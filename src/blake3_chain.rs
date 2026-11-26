//! Unsalted BLAKE3 commit/tree/history binding (`signet-tree` / `signet-parent`).
//!
//! Uses BLAKE3 `DeriveKey` mode with four disjoint contexts (`git-signet 2026-11-24 ...`),
//! streaming blobs directly from `git cat-file --batch` into strictly single-threaded
//! `blake3-servil-core` (`TreeHasher::on_this_core` for blobs `<= 16 KiB`, streaming
//! `convenience::Hasher` for larger blobs) with constant stack memory and zero worker threads.
//!
//! All verification and header emission paths use fresh **memory-only** digest maps so
//! unauthenticated disk bytes never influence verification results or emitted headers.

use crate::git::{Dig, GitRepo, ObjKind, Oid, StoreError, StoreErrorKind, parse_commit_tree_and_parents, parse_git_tree, parse_tag_target};
use crate::id::{decode_lower_hex, to_hex};
use blake3_servil_core::throughput::{TreeHasher, context_key};
use blake3_servil_core::{ContextKey, Mode, convenience, initialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;

pub const CTX_FILE: &str = "git-signet 2026-11-24 file";
pub const CTX_DIR: &str = "git-signet 2026-11-24 directory";
pub const CTX_COMMIT: &str = "git-signet 2026-11-24 commit";
pub const CTX_PLAIN: &str = "git-signet 2026-11-24 plain commit";

pub const HEADER_TREE_PREFIX: &[u8] = b"signet-tree ";
pub const HEADER_PARENT_PREFIX: &[u8] = b"signet-parent ";

const BLOB_STREAM_BUF_LEN: usize = 16_384;
const MAX_TREE_DEPTH: usize = 4_096;

pub struct ContextKeys {
    pub file: ContextKey,
    pub dir: ContextKey,
    pub commit: ContextKey,
    pub plain: ContextKey,
}

impl Default for ContextKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextKeys {
    pub fn new() -> Self {
        initialize();
        Self { file: context_key(CTX_FILE), dir: context_key(CTX_DIR), commit: context_key(CTX_COMMIT), plain: context_key(CTX_PLAIN) }
    }

    #[inline]
    pub fn hash_file(&self, bytes: &[u8]) -> Dig {
        *convenience::hash_with(Mode::DeriveKeyWith(&self.file), bytes).as_bytes()
    }

    #[inline]
    pub fn hash_dir(&self, encoded: &[u8]) -> Dig {
        *convenience::hash_with(Mode::DeriveKeyWith(&self.dir), encoded).as_bytes()
    }

    #[inline]
    pub fn hash_carrying_commit(&self, raw_commit: &[u8]) -> Dig {
        *convenience::hash_with(Mode::DeriveKeyWith(&self.commit), raw_commit).as_bytes()
    }

    #[inline]
    pub fn hash_plain_commit(&self, payload: &[u8]) -> Dig {
        *convenience::hash_with(Mode::DeriveKeyWith(&self.plain), payload).as_bytes()
    }
}

/// Memory-only digest memoization table scoped to one operation.
///
/// Tracks subtree height alongside tree digests so `MAX_TREE_DEPTH` is enforced even when a
/// subtree appears multiple times in a DAG.
pub struct DigestCache {
    blobs: HashMap<Oid, Dig>,
    trees: HashMap<Oid, (Dig, usize)>,
    commits: HashMap<Oid, Dig>,
}

impl DigestCache {
    pub fn memory_only() -> Self {
        Self { blobs: HashMap::new(), trees: HashMap::new(), commits: HashMap::new() }
    }

    pub fn get_blob(&self, oid: &Oid) -> Option<Dig> {
        self.blobs.get(oid).copied()
    }
    pub fn get_tree(&self, oid: &Oid) -> Option<(Dig, usize)> {
        self.trees.get(oid).copied()
    }
    pub fn get_commit(&self, oid: &Oid) -> Option<Dig> {
        self.commits.get(oid).copied()
    }

    pub fn put_blob(&mut self, oid: Oid, dig: Dig) {
        self.blobs.insert(oid, dig);
    }
    pub fn put_tree(&mut self, oid: Oid, dig: Dig, height: usize) {
        self.trees.insert(oid, (dig, height));
    }
    pub fn put_commit(&mut self, oid: Oid, dig: Dig) {
        self.commits.insert(oid, dig);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitClass {
    /// Carries valid `signet-tree blake3` matching `tree` and `signet-parent blake3` matching parent count.
    Carrying { expected_tree: Dig, expected_parents: Vec<Dig> },
    /// No `blake3` signet header lines.
    Plain,
    /// Single `signet-tree` whose `<tree-oid>` != `tree` (leftover from `git commit --amend`): treated as plain.
    Stale,
}

#[derive(Clone, Debug)]
pub struct ParsedCommit {
    pub raw: Vec<u8>,
    pub tree: Oid,
    pub parents: Vec<Oid>,
    pub class: CommitClass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainErrorKind {
    Mismatch,
    Incomplete,
    NotACommit,
    StoreFailure,
}

#[derive(Clone, Debug)]
pub struct ChainError {
    pub kind: ChainErrorKind,
    pub message: String,
}

impl ChainError {
    pub fn mismatch(msg: impl Into<String>) -> Self {
        Self { kind: ChainErrorKind::Mismatch, message: msg.into() }
    }
    pub fn incomplete(msg: impl Into<String>) -> Self {
        Self { kind: ChainErrorKind::Incomplete, message: msg.into() }
    }
    pub fn not_a_commit(msg: impl Into<String>) -> Self {
        Self { kind: ChainErrorKind::NotACommit, message: msg.into() }
    }
    pub fn store(e: StoreError) -> Self {
        match e.kind {
            StoreErrorKind::Missing => Self::incomplete(e.message),
            StoreErrorKind::Failed => Self { kind: ChainErrorKind::StoreFailure, message: e.message },
        }
    }
}

/// Strictly parse a raw commit object's `tree`, `parent`, `signet-tree`, and `signet-parent` headers.
pub fn parse_commit(raw: Vec<u8>) -> Result<ParsedCommit, ChainError> {
    let (tree, parents) = parse_commit_tree_and_parents(&raw).map_err(ChainError::mismatch)?;
    let header_end = raw.windows(2).position(|w| w == b"\n\n").unwrap_or(raw.len());

    let mut tree_claims: Vec<(Oid, Dig)> = Vec::new();
    let mut parent_claims: Vec<Dig> = Vec::new();

    for line in raw[..header_end].split(|&b| b == b'\n') {
        if line.starts_with(b" ") {
            continue;
        }
        if let Some(rest) = line.strip_prefix(HEADER_TREE_PREFIX) {
            let s = std::str::from_utf8(rest).map_err(|_| ChainError::mismatch("non-UTF-8 signet-tree header"))?;
            let parts: Vec<&str> = s.split(' ').collect();
            if parts.first() == Some(&"blake3") {
                if parts.len() != 3 {
                    return Err(ChainError::mismatch(format!("malformed signet-tree blake3 header: {s:?}")));
                }
                let claim_tree = decode_lower_hex::<20>(parts[1]).map_err(|e| ChainError::mismatch(format!("bad signet-tree oid: {e}")))?;
                let claim_dig = decode_lower_hex::<32>(parts[2]).map_err(|e| ChainError::mismatch(format!("bad signet-tree digest: {e}")))?;
                tree_claims.push((claim_tree, claim_dig));
            }
        } else if let Some(rest) = line.strip_prefix(HEADER_PARENT_PREFIX) {
            let s = std::str::from_utf8(rest).map_err(|_| ChainError::mismatch("non-UTF-8 signet-parent header"))?;
            let parts: Vec<&str> = s.split(' ').collect();
            if parts.first() == Some(&"blake3") {
                if parts.len() != 2 {
                    return Err(ChainError::mismatch(format!("malformed signet-parent blake3 header: {s:?}")));
                }
                let claim_dig = decode_lower_hex::<32>(parts[1]).map_err(|e| ChainError::mismatch(format!("bad signet-parent digest: {e}")))?;
                parent_claims.push(claim_dig);
            }
        }
    }

    let class = match tree_claims.as_slice() {
        [] if parent_claims.is_empty() => CommitClass::Plain,
        [] => return Err(ChainError::mismatch("signet-parent blake3 header(s) without signet-tree header")),
        [(claim_tree, claim_dig)] => {
            if *claim_tree != tree {
                CommitClass::Stale
            } else if parent_claims.len() != parents.len() {
                return Err(ChainError::mismatch(format!(
                    "signet-parent count ({}) does not match commit parent count ({})",
                    parent_claims.len(),
                    parents.len()
                )));
            } else {
                CommitClass::Carrying { expected_tree: *claim_dig, expected_parents: parent_claims }
            }
        }
        _ => return Err(ChainError::mismatch("duplicate signet-tree blake3 headers")),
    };

    Ok(ParsedCommit { raw, tree, parents, class })
}

/// Stream a blob directly from `git cat-file --batch` into strictly single-threaded BLAKE3
/// (`DeriveKeyWith(CTX_FILE)`) with a constant 16 KiB stack buffer and zero heap blowup.
pub fn hash_blob_streaming(repo: &mut GitRepo, ctx: &ContextKeys, oid: &Oid, cache: &mut DigestCache) -> Result<Dig, ChainError> {
    if let Some(d) = cache.get_blob(oid) {
        return Ok(d);
    }
    let (kind, size) = repo.begin_stream_object(oid).map_err(ChainError::store)?;
    if kind != ObjKind::Blob {
        repo.reset_batch();
        return Err(ChainError::mismatch(format!("expected blob for {}, got {}", to_hex(oid), kind.as_str())));
    }
    let res = (|| -> Result<Dig, ChainError> {
        let stdout = repo.batch_stdout_mut().ok_or_else(|| ChainError::store(StoreError::failed("no batch stdout")))?;
        let mut buf = [0u8; BLOB_STREAM_BUF_LEN];
        let digest = if size <= u64::try_from(BLOB_STREAM_BUF_LEN).unwrap() {
            let len = usize::try_from(size).unwrap();
            stdout.read_exact(&mut buf[..len]).map_err(|e| ChainError::store(StoreError::failed(format!("blob read: {e}"))))?;
            *TreeHasher::new(Mode::DeriveKeyWith(&ctx.file)).on_this_core().hash(&buf[..len]).as_bytes()
        } else {
            let mut hasher = convenience::Hasher::new(Mode::DeriveKeyWith(&ctx.file), None);
            let mut remaining = size;
            while remaining > 0 {
                let want = usize::try_from(remaining.min(u64::try_from(BLOB_STREAM_BUF_LEN).unwrap())).unwrap();
                stdout.read_exact(&mut buf[..want]).map_err(|e| ChainError::store(StoreError::failed(format!("blob stream read: {e}"))))?;
                hasher.update(&buf[..want]);
                remaining -= u64::try_from(want).unwrap();
            }
            *hasher.finalize().as_bytes()
        };
        let mut nl = [0u8; 1];
        stdout.read_exact(&mut nl).map_err(|e| ChainError::store(StoreError::failed(format!("blob trailing nl: {e}"))))?;
        if nl[0] != b'\n' {
            return Err(ChainError::store(StoreError::failed("cat-file framing error after blob")));
        }
        Ok(digest)
    })();
    if res.is_err() {
        repo.reset_batch();
    }
    let dig = res?;
    cache.put_blob(*oid, dig);
    Ok(dig)
}

/// Compute the BLAKE3 directory digest of tree `root_oid` iteratively (enforcing `MAX_TREE_DEPTH`
/// independently of memoization).
pub fn compute_tree_digest(repo: &mut GitRepo, ctx: &ContextKeys, root_oid: &Oid, cache: &mut DigestCache) -> Result<Dig, ChainError> {
    if let Some((d, _)) = cache.get_tree(root_oid) {
        return Ok(d);
    }
    struct Frame {
        oid: Oid,
        entries: Vec<crate::git::TreeEntry>,
        next_idx: usize,
        encoded: Vec<u8>,
        max_child_height: usize,
    }

    let (kind, raw) = repo.read_object(root_oid).map_err(ChainError::store)?;
    if kind != ObjKind::Tree {
        return Err(ChainError::mismatch(format!("expected tree for {}, got {}", to_hex(root_oid), kind.as_str())));
    }
    let entries = parse_git_tree(&raw).map_err(ChainError::mismatch)?;
    let mut stack = vec![Frame { oid: *root_oid, entries, next_idx: 0, encoded: Vec::new(), max_child_height: 0 }];
    let mut active = HashSet::new();
    active.insert(*root_oid);

    loop {
        let cur_depth = stack.len();
        let top = stack.last_mut().unwrap();
        if top.next_idx < top.entries.len() {
            let e = top.entries[top.next_idx].clone();
            top.next_idx += 1;
            top.encoded.extend_from_slice(&e.mode);
            top.encoded.push(b' ');
            top.encoded.extend_from_slice(&e.name);
            top.encoded.push(0);
            if e.is_gitlink {
                top.encoded.extend_from_slice(&e.oid);
            } else if e.is_dir {
                if let Some((d, child_h)) = cache.get_tree(&e.oid) {
                    if cur_depth + child_h > MAX_TREE_DEPTH {
                        return Err(ChainError::mismatch("git tree cycle or excessive depth"));
                    }
                    top.max_child_height = top.max_child_height.max(child_h);
                    top.encoded.extend_from_slice(&d);
                } else {
                    if cur_depth >= MAX_TREE_DEPTH || !active.insert(e.oid) {
                        return Err(ChainError::mismatch("git tree cycle or excessive depth"));
                    }
                    let (ck, craw) = repo.read_object(&e.oid).map_err(ChainError::store)?;
                    if ck != ObjKind::Tree {
                        return Err(ChainError::mismatch(format!("expected subtree for {}, got {}", to_hex(&e.oid), ck.as_str())));
                    }
                    let centries = parse_git_tree(&craw).map_err(ChainError::mismatch)?;
                    stack.push(Frame { oid: e.oid, entries: centries, next_idx: 0, encoded: Vec::new(), max_child_height: 0 });
                }
            } else {
                let d = hash_blob_streaming(repo, ctx, &e.oid, cache)?;
                top.encoded.extend_from_slice(&d);
            }
        } else {
            let done = stack.pop().unwrap();
            active.remove(&done.oid);
            let dig = ctx.hash_dir(&done.encoded);
            let height = done.max_child_height + 1;
            cache.put_tree(done.oid, dig, height);
            if let Some(parent) = stack.last_mut() {
                parent.max_child_height = parent.max_child_height.max(height);
                parent.encoded.extend_from_slice(&dig);
            } else {
                return Ok(dig);
            }
        }
    }
}

/// Compute the BLAKE3 digest of commit `root_oid` (stopping recursion at carrying commits),
/// optionally recording every commit OID folded into the computed digest.
fn compute_commit_digest_inner(
    repo: &mut GitRepo,
    ctx: &ContextKeys,
    root_oid: &Oid,
    cache: &mut DigestCache,
    mut folded: Option<&mut HashSet<Oid>>,
) -> Result<Dig, ChainError> {
    if let Some(d) = cache.get_commit(root_oid) {
        if let Some(set) = folded.as_deref_mut() {
            set.insert(*root_oid);
        }
        return Ok(d);
    }
    let mut stack: Vec<(Oid, Option<ParsedCommit>)> = vec![(*root_oid, None)];
    let mut active: HashSet<Oid> = HashSet::new();

    while let Some((oid, parsed_opt)) = stack.pop() {
        if cache.get_commit(&oid).is_some() {
            if let Some(set) = folded.as_deref_mut() {
                set.insert(oid);
            }
            continue;
        }
        let parsed = match parsed_opt {
            Some(p) => p,
            None => {
                if !active.insert(oid) {
                    return Err(ChainError::mismatch(format!("commit graph cycle at {}", to_hex(&oid))));
                }
                let (kind, raw) = repo.read_object(&oid).map_err(ChainError::store)?;
                if kind != ObjKind::Commit {
                    return Err(ChainError::mismatch(format!("expected commit for {}, got {}", to_hex(&oid), kind.as_str())));
                }
                let p = parse_commit(raw)?;
                if matches!(p.class, CommitClass::Carrying { .. }) {
                    active.remove(&oid);
                    let d = ctx.hash_carrying_commit(&p.raw);
                    cache.put_commit(oid, d);
                    if let Some(set) = folded.as_deref_mut() {
                        set.insert(oid);
                    }
                    continue;
                }
                let missing_parents: Vec<Oid> = p.parents.iter().copied().filter(|pid| cache.get_commit(pid).is_none()).collect();
                if !missing_parents.is_empty() {
                    stack.push((oid, Some(p)));
                    for pid in missing_parents.into_iter().rev() {
                        stack.push((pid, None));
                    }
                    continue;
                }
                p
            }
        };
        active.remove(&oid);
        let tree_dig = compute_tree_digest(repo, ctx, &parsed.tree, cache)?;
        let parent_count = u32::try_from(parsed.parents.len()).map_err(|_| ChainError::mismatch("too many commit parents"))?;
        let mut payload = Vec::with_capacity(32 + 4 + 32 * parsed.parents.len() + parsed.raw.len());
        payload.extend_from_slice(&tree_dig);
        payload.extend_from_slice(&parent_count.to_le_bytes());
        for pid in &parsed.parents {
            let pd = cache.get_commit(pid).ok_or_else(|| ChainError::mismatch("missing computed parent digest"))?;
            payload.extend_from_slice(&pd);
            if let Some(set) = folded.as_deref_mut() {
                set.insert(*pid);
            }
        }
        payload.extend_from_slice(&parsed.raw);
        let d = ctx.hash_plain_commit(&payload);
        cache.put_commit(oid, d);
        if let Some(set) = folded.as_deref_mut() {
            set.insert(oid);
        }
    }

    cache.get_commit(root_oid).ok_or_else(|| ChainError::mismatch("failed to compute commit digest"))
}

/// Compute the BLAKE3 digest of commit `root_oid` (without recursively re-verifying carrying ancestors).
pub fn compute_commit_digest(repo: &mut GitRepo, ctx: &ContextKeys, root_oid: &Oid, cache: &mut DigestCache) -> Result<Dig, ChainError> {
    compute_commit_digest_inner(repo, ctx, root_oid, cache, None)
}

#[derive(Clone, Debug)]
pub struct VerifyReport {
    pub commit_oid: Oid,
    pub digest: Dig,
    pub carrying_commits: usize,
    pub plain_commits: usize,
    pub tip_carries_lines: bool,
    pub shallow_boundary_hit: bool,
    /// Commits authenticated by verified `signet-parent` BLAKE3 edges starting from a `Carrying` tip
    /// (empty if `tip` itself does not carry `signet-tree` / `signet-parent` headers!).
    pub authenticated_ancestors: HashSet<Oid>,
}

/// Peel up to 64 annotated tag layers (validating declared target kind and rejecting cycles)
/// until reaching a commit object. Returns `ChainErrorKind::NotACommit` if the target is a blob/tree.
pub fn peel_to_commit(repo: &mut GitRepo, start: &Oid) -> Result<Oid, ChainError> {
    let mut cur = *start;
    let mut seen = HashSet::new();
    let mut expected_kind: Option<ObjKind> = None;
    for _ in 0..=64 {
        if !seen.insert(cur) {
            return Err(ChainError::mismatch("tag cycle"));
        }
        let (kind, raw) = repo.read_object(&cur).map_err(ChainError::store)?;
        if let Some(exp) = expected_kind
            && kind != exp
        {
            return Err(ChainError::mismatch(format!("tag target type mismatch: declared {}, actual {}", exp.as_str(), kind.as_str())));
        }
        match kind {
            ObjKind::Commit => return Ok(cur),
            ObjKind::Tag => {
                let (next, decl_kind) = parse_tag_target(&raw).map_err(ChainError::mismatch)?;
                if decl_kind != ObjKind::Commit && decl_kind != ObjKind::Tag {
                    return Err(ChainError::not_a_commit(format!("tag targets {}", decl_kind.as_str())));
                }
                cur = next;
                expected_kind = Some(decl_kind);
            }
            other => return Err(ChainError::not_a_commit(format!("expected commit or tag, got {}", other.as_str()))),
        }
    }
    Err(ChainError::mismatch("tag chain exceeds depth 64"))
}

/// Fully verify every reachable carrying commit and its BLAKE3 tree + parent chain starting at `tip`.
///
/// Uses a fresh memory-only cache and never skips history via unauthenticated prior ref values.
/// - If `allow_shallow` is true and the repository's snapshotted shallow grafts list a commit,
///   verification stops cleanly after verifying that graft commit's own `signet-tree`.
/// - `authenticated_ancestors` contains ONLY commits bound by verified `signet-parent` BLAKE3 edges
///   descending from a `Carrying` tip (never unauthenticated OID reachability from a plain/stale tip).
pub fn verify_commit_chain(
    repo: &mut GitRepo,
    ctx: &ContextKeys,
    tip: &Oid,
    expected_digest: Option<&Dig>,
    allow_shallow: bool,
) -> Result<VerifyReport, ChainError> {
    let grafts: HashSet<Oid> = if allow_shallow { repo.shallow.clone() } else { HashSet::new() };
    let mut cache = DigestCache::memory_only();
    let mut visited: HashSet<Oid> = HashSet::new();
    let mut authenticated: HashSet<Oid> = HashSet::new();
    let mut queue: VecDeque<Oid> = VecDeque::from([*tip]);
    let mut carrying_commits = 0usize;
    let mut plain_commits = 0usize;
    let mut tip_carries_lines = false;
    let mut shallow_boundary_hit = false;

    while let Some(oid) = queue.pop_front() {
        if !visited.insert(oid) {
            continue;
        }
        let (kind, raw) = repo.read_object(&oid).map_err(ChainError::store)?;
        if kind != ObjKind::Commit {
            return Err(ChainError::mismatch(format!("expected commit at {}, got {}", to_hex(&oid), kind.as_str())));
        }
        let parsed = parse_commit(raw)?;
        let is_graft = grafts.contains(&oid);
        if is_graft && !parsed.parents.is_empty() {
            shallow_boundary_hit = true;
        }
        match &parsed.class {
            CommitClass::Carrying { expected_tree, expected_parents } => {
                if oid == *tip {
                    tip_carries_lines = true;
                    authenticated.insert(oid);
                }
                let oid_is_auth = authenticated.contains(&oid);
                carrying_commits += 1;
                let actual_tree = compute_tree_digest(repo, ctx, &parsed.tree, &mut cache)?;
                if actual_tree != *expected_tree {
                    return Err(ChainError::mismatch(format!(
                        "signet-tree mismatch at commit {}: header {}, computed {}",
                        to_hex(&oid),
                        to_hex(expected_tree),
                        to_hex(&actual_tree)
                    )));
                }
                if !is_graft {
                    for (idx, (p_oid, exp_p)) in parsed.parents.iter().zip(expected_parents.iter()).enumerate() {
                        let mut folded = HashSet::new();
                        let actual_p = compute_commit_digest_inner(repo, ctx, p_oid, &mut cache, Some(&mut folded))?;
                        if actual_p != *exp_p {
                            return Err(ChainError::mismatch(format!(
                                "signet-parent #{idx} mismatch at commit {}: header {}, computed {}",
                                to_hex(&oid),
                                to_hex(exp_p),
                                to_hex(&actual_p)
                            )));
                        }
                        if oid_is_auth {
                            authenticated.insert(*p_oid);
                            authenticated.extend(folded);
                        }
                        if !visited.contains(p_oid) {
                            queue.push_back(*p_oid);
                        }
                    }
                }
                cache.put_commit(oid, ctx.hash_carrying_commit(&parsed.raw));
            }
            CommitClass::Plain | CommitClass::Stale => {
                plain_commits += 1;
                if !is_graft {
                    for p_oid in &parsed.parents {
                        if !visited.contains(p_oid) {
                            queue.push_back(*p_oid);
                        }
                    }
                }
            }
        }
    }

    let tip_digest = if let Some(d) = cache.get_commit(tip) {
        d
    } else if expected_digest.is_some() || carrying_commits > 0 {
        compute_commit_digest(repo, ctx, tip, &mut cache)?
    } else {
        [0u8; 32]
    };
    if let Some(exp) = expected_digest
        && tip_digest != *exp
    {
        return Err(ChainError::mismatch(format!("commit {} BLAKE3 digest mismatch: expected {}, got {}", to_hex(tip), to_hex(exp), to_hex(&tip_digest))));
    }

    Ok(VerifyReport {
        commit_oid: *tip,
        digest: tip_digest,
        carrying_commits,
        plain_commits,
        tip_carries_lines,
        shallow_boundary_hit,
        authenticated_ancestors: authenticated,
    })
}

/// Build a commit payload with canonical `signet-tree` and `signet-parent` headers inserted right after
/// `committer` (stripping any stale `signet-*` headers and any `gpgsig` header).
pub fn insert_signet_headers(raw_commit: &[u8], tree_oid: &Oid, tree_dig: &Dig, parent_digs: &[Dig]) -> Result<Vec<u8>, String> {
    let (header_end, has_sep) = match raw_commit.windows(2).position(|w| w == b"\n\n") {
        Some(pos) => (pos, true),
        None => (raw_commit.len(), false),
    };
    let header_bytes = &raw_commit[..header_end];
    let body_bytes = if has_sep { &raw_commit[header_end + 2..] } else { b"" };

    let lines: Vec<&[u8]> = header_bytes.split(|&b| b == b'\n').collect();
    let mut kept: Vec<&[u8]> = Vec::with_capacity(lines.len());
    let mut i = 0usize;
    let mut insert_at: Option<usize> = None;

    while i < lines.len() {
        let line = lines[i];
        if line.starts_with(b"gpgsig ") {
            i += 1;
            while i < lines.len() && lines[i].starts_with(b" ") {
                i += 1;
            }
            continue;
        }
        if line.starts_with(HEADER_TREE_PREFIX) || line.starts_with(HEADER_PARENT_PREFIX) {
            i += 1;
            continue;
        }
        kept.push(line);
        if line.starts_with(b"committer ") {
            insert_at = Some(kept.len());
        }
        i += 1;
    }

    let mut new_lines: Vec<Vec<u8>> = Vec::with_capacity(1 + parent_digs.len());
    new_lines.push(format!("signet-tree blake3 {} {}", to_hex(tree_oid), to_hex(tree_dig)).into_bytes());
    for pd in parent_digs {
        new_lines.push(format!("signet-parent blake3 {}", to_hex(pd)).into_bytes());
    }

    let pos = insert_at.unwrap_or(kept.len());
    let mut out = Vec::with_capacity(raw_commit.len() + 128 * new_lines.len());
    let mut first = true;
    for l in &kept[..pos] {
        if !first {
            out.push(b'\n');
        }
        first = false;
        out.extend_from_slice(l);
    }
    for nl in &new_lines {
        if !first {
            out.push(b'\n');
        }
        first = false;
        out.extend_from_slice(nl);
    }
    for l in &kept[pos..] {
        if !first {
            out.push(b'\n');
        }
        first = false;
        out.extend_from_slice(l);
    }
    if has_sep {
        out.extend_from_slice(b"\n\n");
        out.extend_from_slice(body_bytes);
    }
    Ok(out)
}

/// Attach a `gpgsig` header block (indented continuation lines) right before the blank separator line.
pub fn attach_gpgsig(commit_payload: &[u8], armor: &[u8]) -> Vec<u8> {
    let (header_end, has_sep) = match commit_payload.windows(2).position(|w| w == b"\n\n") {
        Some(pos) => (pos, true),
        None => (commit_payload.len(), false),
    };
    let mut out = Vec::with_capacity(commit_payload.len() + armor.len() + 32);
    out.extend_from_slice(&commit_payload[..header_end]);
    out.extend_from_slice(b"\ngpgsig ");
    let trimmed = armor.strip_suffix(b"\n").unwrap_or(armor);
    for (idx, line) in trimmed.split(|&b| b == b'\n').enumerate() {
        if idx > 0 {
            out.extend_from_slice(b"\n ");
        }
        out.extend_from_slice(line);
    }
    if has_sep {
        out.extend_from_slice(b"\n\n");
        out.extend_from_slice(&commit_payload[header_end + 2..]);
    }
    out
}

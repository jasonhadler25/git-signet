//! Salted whole-snapshot BLINCS imprinting and verification.
//!
//! Streams a uniquely decodable canonical serialization of a Git commit (or annotated tag targeting
//! a commit) PLUS the entire depth-first directory/file tree directly into `signet::Signet::imprint_reader`
//! / `signet::SignetId::verify_reader` under a bounded length-framed BLINCS [`Context`], pulling blobs
//! directly from `git cat-file --batch` with constant memory so multi-gigabyte repositories never buffer in RAM.
//!
//! Wire framing (injective / uniquely decodable, domain-separated via BLINCS `Context`):
//!
//! ```text
//!   Commit snapshot (COMMIT_SNAPSHOT_CTX = "git-signet 2026-11-25 commit-snapshot"):
//!     u64_le(commit_payload.len()) || commit_payload
//!     <tree walk>
//!     b"E"
//!
//!   Tag snapshot (TAG_SNAPSHOT_CTX = "git-signet 2026-11-25 tag-snapshot"):
//!     u64_le(tag_payload.len()) || tag_payload
//!     u64_le(target_commit_raw.len()) || target_commit_raw
//!     <target commit's tree walk>
//!     b"E"
//!
//!   Tree walk (in Git's stored entry order):
//!     dir (040000):     b"D" || mode || b" " || name || b"\0" || <child walk> || b"E"
//!     gitlink (160000): b"G" || mode || b" " || name || b"\0" || <20-byte oid>
//!     blob / symlink:   b"F" || mode || b" " || name || b"\0" || u64_le(blob_len) || <raw blob bytes>
//! ```

use crate::git::{GitRepo, ObjKind, Oid, TreeEntry, parse_commit_tree_and_parents, parse_git_tree, parse_tag_target};
use crate::id::{X509_BEGIN, decode_imprint_armor};
use signet::{Context, Imprint, Randomness, Signet, SignetId, VerifyError};
use std::collections::HashSet;
use std::io::{self, ErrorKind, Read};

pub const COMMIT_SNAPSHOT_CTX: Context<'static> = Context::new(b"git-signet 2026-11-25 commit-snapshot");
pub const TAG_SNAPSHOT_CTX: Context<'static> = Context::new(b"git-signet 2026-11-25 tag-snapshot");
const MAX_TREE_DEPTH: usize = 4_096;

struct TreeFrame {
    oid: Oid,
    entries: Vec<TreeEntry>,
    next_idx: usize,
}

/// Streaming `Read` adapter over a commit (or tag) plus its entire Git tree.
pub struct SnapshotReader<'a> {
    repo: &'a mut GitRepo,
    buf: Vec<u8>,
    pos: usize,
    stack: Vec<TreeFrame>,
    active_dirs: HashSet<Oid>,
    blob_remaining: u64,
    need_blob_nl: bool,
    finished: bool,
}

impl<'a> SnapshotReader<'a> {
    pub fn for_commit(repo: &'a mut GitRepo, commit_payload: &[u8]) -> Result<Self, String> {
        let (tree_oid, _) = parse_commit_tree_and_parents(commit_payload)?;
        let mut buf = Vec::with_capacity(8 + commit_payload.len());
        buf.extend_from_slice(&u64::try_from(commit_payload.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(commit_payload);
        Self::with_root_tree(repo, buf, tree_oid)
    }

    pub fn for_tag(repo: &'a mut GitRepo, tag_payload: &[u8]) -> Result<Self, String> {
        let (target_oid, target_kind) = parse_tag_target(tag_payload)?;
        if target_kind != ObjKind::Commit {
            return Err(format!("annotated tag targets {}, not a commit", target_kind.as_str()));
        }
        let (actual_kind, target_raw) = repo.read_object(&target_oid).map_err(|e| e.message)?;
        if actual_kind != ObjKind::Commit {
            return Err(format!("tag target object is {}, not commit", actual_kind.as_str()));
        }
        let (tree_oid, _) = parse_commit_tree_and_parents(&target_raw)?;
        let mut buf = Vec::with_capacity(16 + tag_payload.len() + target_raw.len());
        buf.extend_from_slice(&u64::try_from(tag_payload.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(tag_payload);
        buf.extend_from_slice(&u64::try_from(target_raw.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(&target_raw);
        Self::with_root_tree(repo, buf, tree_oid)
    }

    fn with_root_tree(repo: &'a mut GitRepo, buf: Vec<u8>, tree_oid: Oid) -> Result<Self, String> {
        let (kind, raw) = repo.read_object(&tree_oid).map_err(|e| e.message)?;
        if kind != ObjKind::Tree {
            return Err(format!("commit tree object is {}, not tree", kind.as_str()));
        }
        let entries = parse_git_tree(&raw)?;
        let mut active_dirs = HashSet::new();
        active_dirs.insert(tree_oid);
        Ok(Self {
            repo,
            buf,
            pos: 0,
            stack: vec![TreeFrame { oid: tree_oid, entries, next_idx: 0 }],
            active_dirs,
            blob_remaining: 0,
            need_blob_nl: false,
            finished: false,
        })
    }

    /// Refill `self.buf` or open the next blob stream. Returns `Ok(true)` if bytes are ready, `Ok(false)` at EOF.
    fn advance(&mut self) -> io::Result<bool> {
        self.buf.clear();
        self.pos = 0;

        if self.need_blob_nl {
            let stdout = self.repo.batch_stdout_mut().ok_or_else(|| io::Error::other("missing batch stdout"))?;
            let mut nl = [0u8; 1];
            if let Err(e) = stdout.read_exact(&mut nl) {
                self.repo.reset_batch();
                return Err(e);
            }
            if nl[0] != b'\n' {
                self.repo.reset_batch();
                return Err(io::Error::new(ErrorKind::InvalidData, "cat-file framing error after blob"));
            }
            self.need_blob_nl = false;
        }

        if let Some(top) = self.stack.last_mut() {
            if top.next_idx < top.entries.len() {
                let entry = top.entries[top.next_idx].clone();
                top.next_idx += 1;
                if entry.is_dir {
                    if self.stack.len() >= MAX_TREE_DEPTH || !self.active_dirs.insert(entry.oid) {
                        return Err(io::Error::new(ErrorKind::InvalidData, "git tree cycle or excessive depth"));
                    }
                    self.buf.push(b'D');
                    self.buf.extend_from_slice(&entry.mode);
                    self.buf.push(b' ');
                    self.buf.extend_from_slice(&entry.name);
                    self.buf.push(0);
                    let (kind, raw) = self.repo.read_object(&entry.oid).map_err(|e| io::Error::other(e.message))?;
                    if kind != ObjKind::Tree {
                        return Err(io::Error::new(ErrorKind::InvalidData, "directory entry does not point to a tree"));
                    }
                    let entries = parse_git_tree(&raw).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
                    self.stack.push(TreeFrame { oid: entry.oid, entries, next_idx: 0 });
                    return Ok(true);
                } else if entry.is_gitlink {
                    self.buf.push(b'G');
                    self.buf.extend_from_slice(&entry.mode);
                    self.buf.push(b' ');
                    self.buf.extend_from_slice(&entry.name);
                    self.buf.push(0);
                    self.buf.extend_from_slice(&entry.oid);
                    return Ok(true);
                } else {
                    let (kind, size) = self.repo.begin_stream_object(&entry.oid).map_err(|e| io::Error::other(e.message))?;
                    if kind != ObjKind::Blob {
                        self.repo.reset_batch();
                        return Err(io::Error::new(ErrorKind::InvalidData, "file entry does not point to a blob"));
                    }
                    self.buf.push(b'F');
                    self.buf.extend_from_slice(&entry.mode);
                    self.buf.push(b' ');
                    self.buf.extend_from_slice(&entry.name);
                    self.buf.push(0);
                    self.buf.extend_from_slice(&size.to_le_bytes());
                    self.blob_remaining = size;
                    self.need_blob_nl = true;
                    return Ok(true);
                }
            } else {
                let done = self.stack.pop().unwrap();
                self.active_dirs.remove(&done.oid);
                self.buf.push(b'E');
                return Ok(true);
            }
        }

        self.finished = true;
        Ok(false)
    }
}

impl Read for SnapshotReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos < self.buf.len() {
                let n = (self.buf.len() - self.pos).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.blob_remaining > 0 {
                let want = usize::try_from(self.blob_remaining.min(u64::try_from(out.len()).unwrap())).unwrap();
                let stdout = self.repo.batch_stdout_mut().ok_or_else(|| io::Error::other("missing batch stdout"))?;
                let n = match stdout.read(&mut out[..want]) {
                    Ok(0) => {
                        self.repo.reset_batch();
                        return Err(io::Error::new(ErrorKind::UnexpectedEof, "truncated blob in cat-file stream"));
                    }
                    Ok(n) => n,
                    Err(e) => {
                        self.repo.reset_batch();
                        return Err(e);
                    }
                };
                self.blob_remaining -= u64::try_from(n).unwrap();
                return Ok(n);
            }
            if self.finished {
                return Ok(0);
            }
            if !self.advance()? {
                return Ok(0);
            }
        }
    }
}

/// Split a raw Git commit object into `(commit_payload_without_gpgsig, armor_bytes)`.
/// Rejects duplicate `gpgsig` headers.
pub fn extract_commit_imprint(raw_commit: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (headers_end, has_sep) = match raw_commit.windows(2).position(|w| w == b"\n\n") {
        Some(pos) => (pos, true),
        None => (raw_commit.len(), false),
    };
    let header_bytes = &raw_commit[..headers_end];
    let body_bytes = if has_sep { &raw_commit[headers_end + 2..] } else { b"" };

    let mut payload_headers: Vec<&[u8]> = Vec::new();
    let mut sig_lines: Option<Vec<&[u8]>> = None;
    let lines: Vec<&[u8]> = header_bytes.split(|&c| c == b'\n').collect();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        if let Some(first) = line.strip_prefix(b"gpgsig ") {
            if sig_lines.is_some() {
                return Err("commit carries duplicate gpgsig headers".into());
            }
            let mut block = vec![first];
            i += 1;
            while i < lines.len() && lines[i].starts_with(b" ") {
                block.push(&lines[i][1..]);
                i += 1;
            }
            sig_lines = Some(block);
            continue;
        }
        payload_headers.push(line);
        i += 1;
    }

    let block = sig_lines.ok_or_else(|| "commit carries no imprint (missing gpgsig header)".to_string())?;
    let mut armor = Vec::new();
    for l in &block {
        armor.extend_from_slice(l);
        armor.push(b'\n');
    }

    let mut payload = Vec::with_capacity(raw_commit.len());
    for (idx, h) in payload_headers.iter().enumerate() {
        if idx > 0 {
            payload.push(b'\n');
        }
        payload.extend_from_slice(h);
    }
    if has_sep {
        payload.extend_from_slice(b"\n\n");
        payload.extend_from_slice(body_bytes);
    }
    Ok((payload, armor))
}

/// Split a raw Git annotated tag object into `(tag_payload_without_armor, armor_bytes)`.
pub fn extract_tag_imprint(raw_tag: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let Some(sep) = raw_tag.windows(2).position(|w| w == b"\n\n") else {
        return Err("annotated tag has no body".into());
    };
    let body_start = sep + 2;
    let body = &raw_tag[body_start..];

    let mut begin_pos: Option<usize> = None;
    let mut off = 0usize;
    while off < body.len() {
        let line_end = body[off..].iter().position(|&c| c == b'\n').map(|p| off + p).unwrap_or(body.len());
        let line = body[off..line_end].strip_suffix(b"\r").unwrap_or(&body[off..line_end]);
        if line == X509_BEGIN {
            if begin_pos.is_some() {
                return Err("annotated tag carries multiple imprint blocks".into());
            }
            begin_pos = Some(body_start + off);
        }
        if line_end == body.len() {
            break;
        }
        off = line_end + 1;
    }

    let sig_start = begin_pos.ok_or_else(|| "annotated tag carries no BLINCS imprint".to_string())?;
    Ok((raw_tag[..sig_start].to_vec(), raw_tag[sig_start..].to_vec()))
}

/// Produce a salted whole-snapshot BLINCS imprint over a Git commit or annotated tag payload.
pub fn imprint_payload(repo: &mut GitRepo, signet: &Signet, rng: &Randomness, payload: &[u8]) -> Result<Imprint, String> {
    let (ctx, reader) = if payload.starts_with(b"tree ") {
        (COMMIT_SNAPSHOT_CTX, SnapshotReader::for_commit(repo, payload)?)
    } else if payload.starts_with(b"object ") {
        (TAG_SNAPSHOT_CTX, SnapshotReader::for_tag(repo, payload)?)
    } else {
        return Err("unsupported Git payload (expected commit or annotated tag)".into());
    };
    signet.imprint_reader(rng, ctx, reader).map_err(|e| format!("snapshot imprint failed: {e}"))
}

/// Verify a salted whole-snapshot BLINCS imprint against `expected_id` (if given, `embedded_id == expected_id`
/// is strictly enforced) and return the verified `SignetId`.
pub fn verify_payload_imprint(repo: &mut GitRepo, payload: &[u8], armor: &[u8], expected_id: Option<&SignetId>) -> Result<SignetId, String> {
    let (embedded_id, imprint) = decode_imprint_armor(armor)?;
    if let Some(exp) = expected_id
        && embedded_id != *exp
    {
        return Err(format!(
            "imprint signet ID mismatch: expected {}, got {}",
            crate::id::format_signet_marker(exp),
            crate::id::format_signet_marker(&embedded_id)
        ));
    }
    let (ctx, reader) = if payload.starts_with(b"tree ") {
        (COMMIT_SNAPSHOT_CTX, SnapshotReader::for_commit(repo, payload)?)
    } else if payload.starts_with(b"object ") {
        (TAG_SNAPSHOT_CTX, SnapshotReader::for_tag(repo, payload)?)
    } else {
        return Err("unsupported Git payload (expected commit or annotated tag)".into());
    };
    match embedded_id.verify_reader(ctx, reader, &imprint) {
        Ok(()) => Ok(embedded_id),
        Err(VerifyError::Invalid) => Err("BLINCS snapshot imprint verification FAILED".into()),
        Err(VerifyError::Io(e)) => Err(format!("snapshot verification I/O error: {e}")),
    }
}

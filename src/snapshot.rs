//! Push-side salted whole-snapshot BLINCS imprinting & verification (`BLINCS-128-7x5`).
//!
//! Instead of imprinting only a 20-byte SHA-1 or an unsalted 32-byte digest, `git-signet`
//! pushes the entire commit (or annotated tag + target commit) AND every reachable tree entry
//! and raw blob byte straight into Signet's single-pass salted `Sink` (`imprint_with` /
//! `verify_with`) under bounded contexts (`COMMIT_SNAPSHOT_CTX` / `TAG_SNAPSHOT_CTX`).
//!
//! Canonical framing (100% unambiguous, length-delimited, raw Git bytes preserved):
//! ```text
//! CommitSnapshot (Context = COMMIT_SNAPSHOT_CTX):
//!   u64_le(len(commit_payload)) || commit_payload || TreeWalk(tree_oid)
//!
//! TagSnapshot (Context = TAG_SNAPSHOT_CTX):
//!   u64_le(len(tag_payload)) || tag_payload || u64_le(len(target_commit_raw)) || target_commit_raw || TreeWalk(tree_oid)
//!
//! TreeWalk(tree_oid):
//!   For each entry in raw Git tree order:
//!     directory (040000):  b"D" || mode || b" " || name || b"\0" || TreeWalk(child_oid) || b"E"
//!     gitlink   (160000):  b"G" || mode || b" " || name || b"\0" || raw_20_byte_oid
//!     blob / symlink:      b"F" || mode || b" " || name || b"\0" || u64_le(blob_len) || <raw blob bytes>
//!   Root closes with b"E".
//! ```

use crate::git::{GitRepo, MAX_TREE_DEPTH, ObjKind, Oid, TreeEntry, parse_commit_tree_and_parents, parse_git_tree, parse_tag_target, split_header_body};
use crate::id::{X509_BEGIN, decode_imprint_armor};
use signet::{Context, Imprint, Randomness, Signet, SignetId, VerifyError};
use std::collections::HashSet;
use std::io::Write;
use std::vec::IntoIter;

pub const COMMIT_SNAPSHOT_CTX: Context<'static> = Context::new(b"git-signet 2026-11-25 commit-snapshot");
pub const TAG_SNAPSHOT_CTX: Context<'static> = Context::new(b"git-signet 2026-11-25 tag-snapshot");
const MAX_SNAPSHOT_ENTRIES: usize = 1_000_000;
const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const _: () = assert!(MAX_SNAPSHOT_BYTES == 17_179_869_184);
const STREAM_BUF_LEN: usize = 16_384;

struct SnapshotBudget {
    entries_seen: usize,
    bytes_emitted: u64,
}

impl SnapshotBudget {
    fn new() -> Self {
        Self { entries_seen: 0, bytes_emitted: 0 }
    }

    fn emit(&mut self, out: &mut impl Write, bytes: &[u8]) -> Result<(), String> {
        let add = u64::try_from(bytes.len()).map_err(|_| "snapshot length overflow".to_string())?;
        self.bytes_emitted = self.bytes_emitted.checked_add(add).ok_or_else(|| "snapshot length overflow".to_string())?;
        if self.bytes_emitted > MAX_SNAPSHOT_BYTES {
            return Err("snapshot exceeds 16 GiB expansion limit".into());
        }
        out.write_all(bytes).map_err(|e| format!("snapshot write: {e}"))
    }

    fn count_entry(&mut self) -> Result<(), String> {
        self.entries_seen += 1;
        if self.entries_seen > MAX_SNAPSHOT_ENTRIES {
            return Err("snapshot exceeds maximum expanded entry limit".into());
        }
        Ok(())
    }
}

struct TreeFrame {
    oid: Oid,
    entries: IntoIter<TreeEntry>,
}

fn push_tree_frame(repo: &mut GitRepo, tree_oid: Oid, stack: &mut Vec<TreeFrame>, active_dirs: &mut HashSet<Oid>) -> Result<(), String> {
    if stack.len() >= MAX_TREE_DEPTH || !active_dirs.insert(tree_oid) {
        return Err("git tree cycle or excessive depth".into());
    }
    let (kind, raw) = repo.read_object(&tree_oid).map_err(|e| e.message)?;
    if kind != ObjKind::Tree {
        return Err(format!("tree object is {}, not tree", kind.as_str()));
    }
    let entries = parse_git_tree(&raw)?;
    stack.push(TreeFrame { oid: tree_oid, entries: entries.into_iter() });
    Ok(())
}

/// Stream the canonical snapshot tree walk starting at `root_tree` straight into `out`.
fn write_tree_walk(repo: &mut GitRepo, root_tree: Oid, out: &mut impl Write, budget: &mut SnapshotBudget) -> Result<(), String> {
    let mut stack: Vec<TreeFrame> = Vec::new();
    let mut active_dirs: HashSet<Oid> = HashSet::new();
    push_tree_frame(repo, root_tree, &mut stack, &mut active_dirs)?;

    let mut header_buf = Vec::with_capacity(128);
    let mut blob_buf = [0u8; STREAM_BUF_LEN];

    while let Some(top) = stack.last_mut() {
        if let Some(entry) = top.entries.next() {
            budget.count_entry()?;
            header_buf.clear();
            if entry.is_dir {
                header_buf.push(b'D');
                entry.write_prefix(&mut header_buf);
                budget.emit(out, &header_buf)?;
                push_tree_frame(repo, entry.oid, &mut stack, &mut active_dirs)?;
            } else if entry.is_gitlink {
                header_buf.push(b'G');
                entry.write_prefix(&mut header_buf);
                header_buf.extend_from_slice(&entry.oid);
                budget.emit(out, &header_buf)?;
            } else {
                header_buf.push(b'F');
                entry.write_prefix(&mut header_buf);
                repo.stream_object(
                    &entry.oid,
                    ObjKind::Blob,
                    |e| e.message,
                    |k| format!("tree entry is {}, expected blob", k.as_str()),
                    |size, reader| {
                        header_buf.extend_from_slice(&size.to_le_bytes());
                        budget.emit(out, &header_buf)?;
                        let mut remaining = size;
                        while remaining > 0 {
                            let want = usize::try_from(remaining.min(u64::try_from(STREAM_BUF_LEN).unwrap())).unwrap();
                            reader.read_exact(&mut blob_buf[..want]).map_err(|e| format!("blob snapshot read: {e}"))?;
                            budget.emit(out, &blob_buf[..want])?;
                            remaining -= u64::try_from(want).unwrap();
                        }
                        Ok(())
                    },
                )?;
            }
        } else {
            let done = stack.pop().unwrap();
            active_dirs.remove(&done.oid);
            budget.emit(out, b"E")?;
        }
    }
    Ok(())
}

/// Push the canonical whole-snapshot byte stream for `kind` (`Commit` or `Tag`) into `out`
/// (accepting both `signet::Sink` and any `std::io::Write` destination).
pub fn write_payload_snapshot(repo: &mut GitRepo, kind: ObjKind, payload: &[u8], out: &mut impl Write) -> Result<(), String> {
    let mut budget = SnapshotBudget::new();
    match kind {
        ObjKind::Commit => {
            let (tree_oid, _) = parse_commit_tree_and_parents(payload)?;
            budget.emit(out, &u64::try_from(payload.len()).unwrap().to_le_bytes())?;
            budget.emit(out, payload)?;
            write_tree_walk(repo, tree_oid, out, &mut budget)
        }
        ObjKind::Tag => {
            let (target_oid, target_kind) = parse_tag_target(payload)?;
            if target_kind != ObjKind::Commit {
                return Err(format!("annotated tag targets {}, not a commit", target_kind.as_str()));
            }
            let (actual_kind, target_raw) = repo.read_object(&target_oid).map_err(|e| e.message)?;
            if actual_kind != ObjKind::Commit {
                return Err(format!("tag target object is {}, not commit", actual_kind.as_str()));
            }
            let (tree_oid, _) = parse_commit_tree_and_parents(&target_raw)?;
            budget.emit(out, &u64::try_from(payload.len()).unwrap().to_le_bytes())?;
            budget.emit(out, payload)?;
            budget.emit(out, &u64::try_from(target_raw.len()).unwrap().to_le_bytes())?;
            budget.emit(out, &target_raw)?;
            write_tree_walk(repo, tree_oid, out, &mut budget)
        }
        other => Err(format!("unsupported Git payload kind {} (expected commit or tag)", other.as_str())),
    }
}

fn context_for_kind(kind: ObjKind) -> Result<Context<'static>, String> {
    match kind {
        ObjKind::Commit => Ok(COMMIT_SNAPSHOT_CTX),
        ObjKind::Tag => Ok(TAG_SNAPSHOT_CTX),
        other => Err(format!("unsupported Git payload kind {} (expected commit or tag)", other.as_str())),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtractedArmor {
    Present { payload: Vec<u8>, armor: Vec<u8> },
    Absent,
    Malformed(String),
}

/// Split a raw Git commit object into `(commit_payload_without_gpgsig, armor_bytes)`.
/// Distinguishes missing `gpgsig` from duplicate/malformed `gpgsig` headers.
pub fn extract_commit_imprint(raw_commit: &[u8]) -> ExtractedArmor {
    let (header_bytes, body_opt) = split_header_body(raw_commit);

    let mut payload_headers: Vec<&[u8]> = Vec::new();
    let mut sig_lines: Option<Vec<&[u8]>> = None;
    let lines: Vec<&[u8]> = header_bytes.split(|&c| c == b'\n').collect();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        if let Some(first) = line.strip_prefix(b"gpgsig ") {
            if sig_lines.is_some() {
                return ExtractedArmor::Malformed("commit carries duplicate gpgsig headers".into());
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

    let Some(block) = sig_lines else {
        return ExtractedArmor::Absent;
    };
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
    if let Some(body) = body_opt {
        payload.extend_from_slice(b"\n\n");
        payload.extend_from_slice(body);
    }
    ExtractedArmor::Present { payload, armor }
}

/// Split a raw Git annotated tag object into `(tag_payload_without_armor, armor_bytes)`.
/// Distinguishes absent armor from duplicate/malformed imprint blocks.
pub fn extract_tag_imprint(raw_tag: &[u8]) -> ExtractedArmor {
    let (header_bytes, Some(body)) = split_header_body(raw_tag) else {
        return ExtractedArmor::Malformed("annotated tag has no body".into());
    };
    let body_start = header_bytes.len() + 2;

    let mut begin_pos: Option<usize> = None;
    let mut off = 0usize;
    while off < body.len() {
        let line_end = body[off..].iter().position(|&c| c == b'\n').map(|p| off + p).unwrap_or(body.len());
        let line = body[off..line_end].strip_suffix(b"\r").unwrap_or(&body[off..line_end]);
        if line == X509_BEGIN {
            if begin_pos.is_some() {
                return ExtractedArmor::Malformed("annotated tag carries multiple imprint blocks".into());
            }
            begin_pos = Some(body_start + off);
        }
        if line_end == body.len() {
            break;
        }
        off = line_end + 1;
    }

    let Some(sig_start) = begin_pos else {
        return ExtractedArmor::Absent;
    };
    ExtractedArmor::Present { payload: raw_tag[..sig_start].to_vec(), armor: raw_tag[sig_start..].to_vec() }
}

/// Produce a salted whole-snapshot BLINCS imprint over an explicitly typed Git commit or annotated tag payload.
pub fn imprint_payload(repo: &mut GitRepo, kind: ObjKind, signet: &Signet, rng: &Randomness, payload: &[u8]) -> Result<Imprint, String> {
    let ctx = context_for_kind(kind)?;
    signet.imprint_with(rng, ctx, |sink| write_payload_snapshot(repo, kind, payload, sink))
}

/// Verify an already-decoded `(SignetId, Imprint)` over an explicitly typed Git commit or annotated
/// tag payload against `expected_id` (if given, `embedded_id == expected_id` is strictly enforced).
pub fn verify_decoded_imprint(
    repo: &mut GitRepo,
    kind: ObjKind,
    payload: &[u8],
    embedded_id: &SignetId,
    imprint: &Imprint,
    expected_id: Option<&SignetId>,
) -> Result<SignetId, String> {
    if let Some(exp) = expected_id
        && embedded_id != exp
    {
        return Err(format!(
            "imprint signet ID mismatch: expected {}, got {}",
            crate::id::format_signet_marker(exp),
            crate::id::format_signet_marker(embedded_id)
        ));
    }
    let ctx = context_for_kind(kind)?;
    match embedded_id.verify_with(ctx, imprint, |sink| write_payload_snapshot(repo, kind, payload, sink)) {
        Ok(()) => Ok(*embedded_id),
        Err(VerifyError::Invalid) => Err("BLINCS snapshot imprint verification FAILED".into()),
        Err(VerifyError::Source(e)) => Err(format!("snapshot verification error: {e}")),
    }
}

/// Decode `BLINCSg2` armor and verify the salted whole-snapshot BLINCS imprint over `payload`.
pub fn verify_payload_imprint(repo: &mut GitRepo, kind: ObjKind, payload: &[u8], armor: &[u8], expected_id: Option<&SignetId>) -> Result<SignetId, String> {
    let (embedded_id, imprint) = decode_imprint_armor(armor)?;
    verify_decoded_imprint(repo, kind, payload, &embedded_id, &imprint, expected_id)
}

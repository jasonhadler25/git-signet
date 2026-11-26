//! Hardened Git subprocess & single `git cat-file --batch-command` object-store interface.
//!
//! Security boundaries:
//! - Rejects non-SHA-1 repositories (`extensions.objectFormat != sha1`).
//! - Passes `--no-replace-objects`, `GIT_NO_REPLACE_OBJECTS=1`, and `GIT_NO_LAZY_FETCH=1`
//!   on every Git invocation so replacement refs or lazy promisor fetches cannot hijack reads.
//! - Owns `cat-file --batch-command` response framing completely (exact body bytes + trailing LF),
//!   automatically resetting and reaping the child process if any read or streaming closure exits
//!   early or encounters an error.
//! - Enforces `MAX_METADATA_OBJECT_BYTES` (64 MiB) before allocating object buffers.

use crate::id::{decode_lower_hex, to_hex};
use std::collections::HashSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

pub type Oid = [u8; 20];
pub type Dig = [u8; 32];

pub const ZERO_OID: Oid = [0u8; 20];
pub const MAX_METADATA_OBJECT_BYTES: usize = 64 << 20;
pub const MAX_TREE_DEPTH: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl ObjKind {
    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        match b {
            b"blob" => Ok(Self::Blob),
            b"tree" => Ok(Self::Tree),
            b"commit" => Ok(Self::Commit),
            b"tag" => Ok(Self::Tag),
            other => Err(format!("unknown git object type {:?}", String::from_utf8_lossy(other))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreErrorKind {
    Missing,
    Failed,
}

#[derive(Clone, Debug)]
pub struct StoreError {
    pub kind: StoreErrorKind,
    pub message: String,
}

impl StoreError {
    pub fn missing(oid: &Oid) -> Self {
        Self { kind: StoreErrorKind::Missing, message: format!("missing git object {}", to_hex(oid)) }
    }

    pub fn failed(msg: impl Into<String>) -> Self {
        Self { kind: StoreErrorKind::Failed, message: msg.into() }
    }
}

/// Strip ASCII/Unicode control and bidirectional formatting characters before printing untrusted strings.
pub fn sanitize_for_tty(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let is_bidi = matches!(ch, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
        if ch.is_control() || is_bidi {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Locate the stock `git` executable (`GIT_SIGNET_REAL_GIT`, `PATH`, or standard system paths).
pub fn resolve_real_git() -> Result<PathBuf, String> {
    if let Ok(explicit) = env::var("GIT_SIGNET_REAL_GIT") {
        let p = PathBuf::from(&explicit);
        if is_executable_file(&p) {
            return Ok(fs::canonicalize(&p).unwrap_or(p));
        }
    }
    if let Some(path_os) = env::var_os("PATH") {
        for dir in env::split_paths(&path_os) {
            let candidate = dir.join("git");
            if is_executable_file(&candidate) {
                return Ok(fs::canonicalize(&candidate).unwrap_or(candidate));
            }
        }
    }
    for fallback in ["/opt/homebrew/bin/git", "/usr/local/bin/git", "/usr/bin/git"] {
        let p = PathBuf::from(fallback);
        if is_executable_file(&p) {
            return Ok(fs::canonicalize(&p).unwrap_or(p));
        }
    }
    Err("could not locate `git` executable on PATH".into())
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

struct BatchProc {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl BatchProc {
    fn spawn(real_git: &Path, git_dir: &Path) -> Result<Self, StoreError> {
        let mut cmd = Command::new(real_git);
        cmd.arg("--no-replace-objects")
            .arg("--git-dir")
            .arg(git_dir)
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .args(["cat-file", "--batch-command"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().map_err(|e| StoreError::failed(format!("spawn git cat-file --batch-command: {e}")))?;
        let stdin = BufWriter::new(child.stdin.take().ok_or_else(|| StoreError::failed("no cat-file stdin"))?);
        let stdout = BufReader::with_capacity(64 * 1024, child.stdout.take().ok_or_else(|| StoreError::failed("no cat-file stdout"))?);
        Ok(Self { child, stdin, stdout })
    }

    fn send_cmd(&mut self, verb: &str, oid: &Oid) -> Result<(ObjKind, u64), StoreError> {
        let hex = to_hex(oid);
        self.stdin.write_all(verb.as_bytes()).map_err(|e| StoreError::failed(format!("cat-file write: {e}")))?;
        self.stdin.write_all(b" ").map_err(|e| StoreError::failed(format!("cat-file write: {e}")))?;
        self.stdin.write_all(hex.as_bytes()).map_err(|e| StoreError::failed(format!("cat-file write: {e}")))?;
        self.stdin.write_all(b"\n").map_err(|e| StoreError::failed(format!("cat-file write: {e}")))?;
        self.stdin.flush().map_err(|e| StoreError::failed(format!("cat-file flush: {e}")))?;
        let line = read_bounded_batch_line(&mut self.stdout)?;
        parse_batch_header(&line, oid)
    }

    fn read_trailing_lf(&mut self) -> Result<(), StoreError> {
        let mut nl = [0u8; 1];
        self.stdout.read_exact(&mut nl).map_err(|e| StoreError::failed(format!("cat-file trailing newline: {e}")))?;
        if nl[0] != b'\n' {
            return Err(StoreError::failed("cat-file framing error: expected trailing newline"));
        }
        Ok(())
    }

    fn shutdown(mut self) {
        drop(self.stdin);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct GitRepo {
    pub real_git: PathBuf,
    pub git_dir: PathBuf,
    pub common_dir: PathBuf,
    pub is_bare: bool,
    pub shallow: HashSet<Oid>,
    batch: Option<BatchProc>,
}

impl GitRepo {
    pub fn open(dir: Option<&Path>) -> Result<Self, String> {
        let real_git = resolve_real_git()?;
        let mut cmd = Command::new(&real_git);
        if let Some(d) = dir {
            cmd.arg("-C").arg(d);
        }
        cmd.arg("--no-replace-objects").env("GIT_NO_REPLACE_OBJECTS", "1").env("GIT_NO_LAZY_FETCH", "1").args([
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
            "--git-common-dir",
            "--is-bare-repository",
            "--show-object-format",
        ]);
        let out = cmd.output().map_err(|e| format!("failed to run git rev-parse: {e}"))?;
        if !out.status.success() {
            return Err(format!("not a git repository: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        let text = String::from_utf8(out.stdout).map_err(|_| "non-UTF-8 git rev-parse output".to_string())?;
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() != 4 {
            return Err(format!("unexpected git rev-parse output ({} lines)", lines.len()));
        }
        let git_dir = PathBuf::from(lines[0]);
        let common_dir = PathBuf::from(lines[1]);
        let is_bare = lines[2] == "true";
        if lines[3] != "sha1" {
            return Err(format!("unsupported git object format {:?}; git-signet requires sha1", lines[3]));
        }

        let mut shallow = HashSet::new();
        let shallow_file = common_dir.join("shallow");
        if shallow_file.exists() {
            let raw = fs::read_to_string(&shallow_file).map_err(|e| format!("read {}: {e}", shallow_file.display()))?;
            for line in raw.lines() {
                let s = line.trim();
                if s.is_empty() {
                    continue;
                }
                let oid = decode_lower_hex::<20>(s).map_err(|e| format!("malformed entry in {}: {e}", shallow_file.display()))?;
                shallow.insert(oid);
            }
        }

        Ok(Self { real_git, git_dir, common_dir, is_bare, shallow, batch: None })
    }

    pub fn cmd(&self) -> Command {
        let mut c = Command::new(&self.real_git);
        c.arg("--no-replace-objects").arg("--git-dir").arg(&self.git_dir).env("GIT_NO_REPLACE_OBJECTS", "1").env("GIT_NO_LAZY_FETCH", "1");
        c
    }

    pub fn run_output<I, S>(&self, args: I) -> Result<Output, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.cmd().args(args).output().map_err(|e| format!("run git: {e}"))
    }

    pub fn rev_parse(&self, rev: &str) -> Result<Oid, String> {
        let out = self.run_output(["rev-parse", "--verify", "--end-of-options", rev])?;
        if !out.status.success() {
            return Err(format!("cannot resolve revision {rev:?}: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        let s = String::from_utf8_lossy(&out.stdout);
        decode_lower_hex::<20>(s.trim()).map_err(|e| format!("bad oid for {rev:?}: {e}"))
    }

    pub fn config_get_checked(&self, key: &str) -> Result<Option<String>, String> {
        let out = self.run_output(["config", "--get", "--", key])?;
        if out.status.success() {
            return Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_owned()));
        }
        if out.status.code() == Some(1) {
            return Ok(None);
        }
        Err(format!("git config --get {key} failed: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }

    pub fn config_get(&self, key: &str) -> Option<String> {
        self.config_get_checked(key).ok().flatten()
    }

    pub fn hash_object_write(&self, kind: ObjKind, bytes: &[u8]) -> Result<Oid, String> {
        let mut child = self
            .cmd()
            .args(["hash-object", "-w", "-t", kind.as_str(), "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn git hash-object: {e}"))?;
        child.stdin.take().unwrap().write_all(bytes).map_err(|e| format!("write git hash-object: {e}"))?;
        let out = child.wait_with_output().map_err(|e| format!("wait git hash-object: {e}"))?;
        if !out.status.success() {
            return Err(format!("git hash-object failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        decode_lower_hex::<20>(String::from_utf8_lossy(&out.stdout).trim())
    }

    pub fn list_remotes(&self) -> Result<Vec<(String, String)>, String> {
        let out = self.run_output(["remote"])?;
        if !out.status.success() {
            return Err(format!("git remote failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        let mut res = Vec::new();
        for name in String::from_utf8_lossy(&out.stdout).lines().map(str::trim).filter(|s| !s.is_empty()) {
            if let Some(url) = self.config_get_checked(&format!("remote.{name}.url"))? {
                res.push((name.to_owned(), url));
            }
        }
        Ok(res)
    }

    pub fn for_each_ref(&self, pattern: Option<&str>) -> Result<Vec<(String, Oid)>, String> {
        let mut args: Vec<OsString> = vec!["for-each-ref".into(), "--format=%(objectname) %(refname)".into()];
        if let Some(p) = pattern {
            args.push(p.into());
        }
        let out = self.run_output(args)?;
        if !out.status.success() {
            return Err(format!("git for-each-ref failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        let mut refs = Vec::new();
        for raw_line in out.stdout.split(|&b| b == b'\n') {
            if raw_line.is_empty() {
                continue;
            }
            let Some(sp) = raw_line.iter().position(|&b| b == b' ') else {
                return Err("malformed git for-each-ref output line".into());
            };
            let hex = std::str::from_utf8(&raw_line[..sp]).map_err(|_| "non-UTF-8 oid in for-each-ref".to_string())?;
            let refname = std::str::from_utf8(&raw_line[sp + 1..]).map_err(|_| "non-UTF-8 refname in for-each-ref".to_string())?;
            let oid = decode_lower_hex::<20>(hex)?;
            refs.push((refname.to_owned(), oid));
        }
        Ok(refs)
    }

    fn take_batch(&mut self) -> Result<BatchProc, StoreError> {
        match self.batch.take() {
            Some(p) => Ok(p),
            None => BatchProc::spawn(&self.real_git, &self.git_dir),
        }
    }

    /// Query `(ObjKind, byte_len)` for `oid` via `info <oid>` without transferring object contents.
    pub fn object_info(&mut self, oid: &Oid) -> Result<(ObjKind, u64), StoreError> {
        let mut proc = self.take_batch()?;
        match proc.send_cmd("info", oid) {
            Ok(info) => {
                self.batch = Some(proc);
                Ok(info)
            }
            Err(e) => {
                if e.kind == StoreErrorKind::Missing {
                    self.batch = Some(proc);
                } else {
                    proc.shutdown();
                }
                Err(e)
            }
        }
    }

    /// Read a complete metadata object (`Commit`, `Tree`, `Tag`, or bounded small `Blob`),
    /// checking `size <= MAX_METADATA_OBJECT_BYTES` BEFORE allocating.
    pub fn read_object(&mut self, oid: &Oid) -> Result<(ObjKind, Vec<u8>), StoreError> {
        let mut proc = self.take_batch()?;
        let res = (|| -> Result<(ObjKind, Vec<u8>), StoreError> {
            let (kind, size) = proc.send_cmd("contents", oid)?;
            let len = usize::try_from(size).map_err(|_| StoreError::failed("object size exceeds usize"))?;
            if len > MAX_METADATA_OBJECT_BYTES {
                return Err(StoreError::failed(format!("{} object {} exceeds 64 MiB limit ({len} bytes)", kind.as_str(), to_hex(oid))));
            }
            let mut buf = vec![0u8; len];
            proc.stdout.read_exact(&mut buf).map_err(|e| StoreError::failed(format!("cat-file body read: {e}")))?;
            proc.read_trailing_lf()?;
            Ok((kind, buf))
        })();
        match res {
            Ok(v) => {
                self.batch = Some(proc);
                Ok(v)
            }
            Err(e) => {
                if e.kind == StoreErrorKind::Missing {
                    self.batch = Some(proc);
                } else {
                    proc.shutdown();
                }
                Err(e)
            }
        }
    }

    /// Stream an object of `expected_kind` to `consumer` with owned response framing.
    ///
    /// Takes ownership of the `cat-file --batch-command` session during the call and restores it
    /// ONLY if `consumer` succeeds, consumes all `size` bytes, and the trailing LF matches; any
    /// error, early exit, or type mismatch kills and reaps the child so streams never desynchronize.
    pub(crate) fn stream_object<T, E>(
        &mut self,
        oid: &Oid,
        expected_kind: ObjKind,
        map_store: impl Fn(StoreError) -> E,
        map_mismatch: impl FnOnce(ObjKind) -> E,
        consumer: impl FnOnce(u64, &mut dyn Read) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut proc = self.take_batch().map_err(&map_store)?;
        let (kind, size) = match proc.send_cmd("contents", oid) {
            Ok(hdr) => hdr,
            Err(e) => {
                if e.kind == StoreErrorKind::Missing {
                    self.batch = Some(proc);
                } else {
                    proc.shutdown();
                }
                return Err(map_store(e));
            }
        };
        if kind != expected_kind {
            proc.shutdown();
            return Err(map_mismatch(kind));
        }
        let (out, remaining) = {
            let mut limited = (&mut proc.stdout).take(size);
            let r = consumer(size, &mut limited);
            (r, limited.limit())
        };
        match out {
            Ok(val) if remaining == 0 => match proc.read_trailing_lf() {
                Ok(()) => {
                    self.batch = Some(proc);
                    Ok(val)
                }
                Err(e) => {
                    proc.shutdown();
                    Err(map_store(e))
                }
            },
            Ok(_) => {
                proc.shutdown();
                Err(map_store(StoreError::failed("cat-file stream left unread bytes")))
            }
            Err(e) => {
                proc.shutdown();
                Err(e)
            }
        }
    }
}

const MAX_BATCH_HEADER_BYTES: usize = 512;

fn read_bounded_batch_line(stdout: &mut BufReader<ChildStdout>) -> Result<String, StoreError> {
    let mut raw = Vec::with_capacity(64);
    let mut limited = stdout.take(u64::try_from(MAX_BATCH_HEADER_BYTES + 1).unwrap());
    let n = limited.read_until(b'\n', &mut raw).map_err(|e| StoreError::failed(format!("cat-file read: {e}")))?;
    if n == 0 {
        return Err(StoreError::failed("unexpected EOF from git cat-file --batch-command"));
    }
    if raw.len() > MAX_BATCH_HEADER_BYTES || !raw.ends_with(b"\n") {
        return Err(StoreError::failed("cat-file header missing LF or exceeds 512 bytes"));
    }
    raw.pop();
    String::from_utf8(raw).map_err(|_| StoreError::failed("non-UTF-8 cat-file header"))
}

fn parse_batch_header(header: &str, oid: &Oid) -> Result<(ObjKind, u64), StoreError> {
    let hex = to_hex(oid);
    if header == format!("{hex} missing") || header == format!("{hex} ambiguous") {
        return Err(StoreError::missing(oid));
    }
    let parts: Vec<&str> = header.split(' ').collect();
    if parts.len() != 3 {
        return Err(StoreError::failed(format!("malformed cat-file header {header:?}")));
    }
    let got_oid = decode_lower_hex::<20>(parts[0]).map_err(|e| StoreError::failed(format!("bad cat-file oid: {e}")))?;
    if got_oid != *oid {
        return Err(StoreError::failed(format!("cat-file oid mismatch: expected {hex}, got {}", parts[0])));
    }
    let kind = ObjKind::from_bytes(parts[1].as_bytes()).map_err(StoreError::failed)?;
    let size = parts[2].parse::<u64>().map_err(|e| StoreError::failed(format!("bad cat-file size: {e}")))?;
    Ok((kind, size))
}

/// Split raw Git commit/tag bytes into `(header_bytes, Some(body_bytes))` when `\n\n` is present,
/// or `(raw, None)` when no header/body separator exists.
pub fn split_header_body(raw: &[u8]) -> (&[u8], Option<&[u8]>) {
    match raw.windows(2).position(|w| w == b"\n\n") {
        Some(pos) => (&raw[..pos], Some(&raw[pos + 2..])),
        None => (raw, None),
    }
}

/// A parsed entry inside a raw Git tree object (`<mode> <name>\0<20-byte-oid>`).
#[derive(Clone, Debug)]
pub struct TreeEntry {
    pub mode: Vec<u8>,
    pub name: Vec<u8>,
    pub oid: Oid,
    pub is_dir: bool,
    pub is_gitlink: bool,
}

impl TreeEntry {
    /// Append canonical Git tree entry prefix `mode || b' ' || name || b'\0'` to `dst`.
    pub fn write_prefix(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.mode);
        dst.push(b' ');
        dst.extend_from_slice(&self.name);
        dst.push(0);
    }
}

/// Strictly parse a raw Git tree object into entries (validating mode octal digits, NUL framing, and 20-byte OID).
pub fn parse_git_tree(raw: &[u8]) -> Result<Vec<TreeEntry>, String> {
    let mut entries = Vec::new();
    let mut off = 0usize;
    while off < raw.len() {
        let Some(sp) = raw[off..].iter().position(|&b| b == b' ') else {
            return Err("malformed git tree: missing space after mode".into());
        };
        let mode = &raw[off..off + sp];
        if mode.is_empty() || !mode.iter().all(|&b| matches!(b, b'0'..=b'7')) {
            return Err(format!("malformed git tree mode {:?}", String::from_utf8_lossy(mode)));
        }
        let mode_val = u32::from_str_radix(std::str::from_utf8(mode).unwrap(), 8).map_err(|_| "git tree mode overflow".to_string())?;
        let name_start = off + sp + 1;
        let Some(nul) = raw[name_start..].iter().position(|&b| b == 0) else {
            return Err("malformed git tree: missing NUL after name".into());
        };
        let name = &raw[name_start..name_start + nul];
        if name.is_empty() {
            return Err("malformed git tree: empty entry name".into());
        }
        let oid_start = name_start + nul + 1;
        if oid_start + 20 > raw.len() {
            return Err("malformed git tree: truncated 20-byte oid".into());
        }
        let oid: Oid = raw[oid_start..oid_start + 20].try_into().unwrap();
        entries.push(TreeEntry { mode: mode.to_vec(), name: name.to_vec(), oid, is_dir: mode_val == 0o040000, is_gitlink: mode_val == 0o160000 });
        off = oid_start + 20;
    }
    Ok(entries)
}

/// Parse the canonical `tree <40-hex>` (first header line) and contiguous `parent <40-hex>`
/// headers of a raw Git commit. Rejects duplicate `tree` lines or out-of-order `parent` lines.
pub fn parse_commit_tree_and_parents(raw: &[u8]) -> Result<(Oid, Vec<Oid>), String> {
    let (header_bytes, _) = split_header_body(raw);
    let mut lines = header_bytes.split(|&b| b == b'\n');
    let first = lines.next().ok_or_else(|| "empty commit header".to_string())?;
    let tree_rest = first.strip_prefix(b"tree ").ok_or_else(|| "commit must begin with tree header".to_string())?;
    let tree_s = std::str::from_utf8(tree_rest).map_err(|_| "non-UTF-8 tree oid".to_string())?;
    let tree = decode_lower_hex::<20>(tree_s)?;

    let mut parents = Vec::new();
    let mut parents_done = false;
    for line in lines {
        if line.starts_with(b"tree ") {
            return Err("commit has duplicate tree headers".into());
        }
        if let Some(rest) = line.strip_prefix(b"parent ") {
            if parents_done {
                return Err("commit has non-contiguous parent header".into());
            }
            let s = std::str::from_utf8(rest).map_err(|_| "non-UTF-8 parent oid".to_string())?;
            parents.push(decode_lower_hex::<20>(s)?);
        } else {
            parents_done = true;
        }
    }
    Ok((tree, parents))
}

/// Parse the `object <40-hex>` and `type <kind>` headers of a raw Git annotated tag.
pub fn parse_tag_target(raw: &[u8]) -> Result<(Oid, ObjKind), String> {
    let (header_bytes, _) = split_header_body(raw);
    let mut target: Option<Oid> = None;
    let mut kind: Option<ObjKind> = None;
    for line in header_bytes.split(|&b| b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"object ") {
            if target.is_some() {
                return Err("tag has duplicate object headers".into());
            }
            let s = std::str::from_utf8(rest).map_err(|_| "non-UTF-8 tag object oid".to_string())?;
            target = Some(decode_lower_hex::<20>(s)?);
        } else if let Some(rest) = line.strip_prefix(b"type ") {
            if kind.is_some() {
                return Err("tag has duplicate type headers".into());
            }
            kind = Some(ObjKind::from_bytes(rest)?);
        }
    }
    Ok((target.ok_or("tag missing object header")?, kind.ok_or("tag missing type header")?))
}

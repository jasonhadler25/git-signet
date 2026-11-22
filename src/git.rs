//! Minimal Git repository interface, ref/remote resolution, hook runner, and installer.

use crate::key::{
    PubKey32, extract_key_from_refname, extract_key_from_remote_url, format_marker,
    parse_openssh_ed25519_pubkey,
};
use crate::verify::{
    extract_commit_ssh_signature, extract_tag_ssh_signature, verify_ssh_signature,
};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjKind {
    Commit,
    Tag,
    Tree,
    Blob,
}

impl ObjKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ObjKind::Commit => "commit",
            ObjKind::Tag => "tag",
            ObjKind::Tree => "tree",
            ObjKind::Blob => "blob",
        }
    }
}

/// Sanitize untrusted ref/remote names before printing to stderr/stdout.
pub fn sanitize_for_tty(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

pub struct GitRepo {
    git_dir: PathBuf,
    git_bin: PathBuf,
}

impl GitRepo {
    pub fn open(cwd: Option<&Path>) -> Result<Self, String> {
        let git_bin = env::var_os("GIT_SIGNET_GIT")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("git"));
        let mut c = Command::new(&git_bin);
        if let Some(d) = cwd {
            c.current_dir(d);
        }
        let out = c
            .args(["--no-replace-objects", "rev-parse", "--path-format=absolute", "--git-dir"])
            .env("GIT_NO_LAZY_FETCH", "1")
            .output()
            .map_err(|e| format!("spawn git rev-parse: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        let gd = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if gd.is_empty() {
            return Err("not a git repository".into());
        }
        Ok(Self {
            git_dir: PathBuf::from(gd),
            git_bin,
        })
    }

    pub fn cmd(&self) -> Command {
        let mut c = Command::new(&self.git_bin);
        c.arg("--no-replace-objects")
            .arg("--git-dir")
            .arg(&self.git_dir)
            .env("GIT_NO_LAZY_FETCH", "1");
        c
    }

    pub fn config_bool(&self, key: &str, default: bool) -> Result<bool, String> {
        let out = self
            .cmd()
            .args(["config", "--type=bool", "--get", key])
            .output()
            .map_err(|e| format!("git config {key}: {e}"))?;
        match out.status.code() {
            Some(0) => Ok(String::from_utf8_lossy(&out.stdout).trim() == "true"),
            Some(1) => Ok(default),
            _ => Err(format!(
                "invalid boolean config {key}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }

    pub fn config_get(&self, key: &str) -> Result<Option<String>, String> {
        let out = self
            .cmd()
            .args(["config", "--get", key])
            .output()
            .map_err(|e| format!("git config {key}: {e}"))?;
        match out.status.code() {
            Some(0) => Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_string())),
            Some(1) => Ok(None),
            _ => Err(format!(
                "git config {key} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }

    pub fn rev_parse(&self, rev: &str) -> Result<String, String> {
        let out = self
            .cmd()
            .args(["rev-parse", "--verify", "--end-of-options", rev])
            .output()
            .map_err(|e| format!("git rev-parse {rev}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "cannot resolve {rev:?}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    pub fn read_object(&self, oid: &str) -> Result<(ObjKind, Vec<u8>), String> {
        let t_out = self
            .cmd()
            .args(["cat-file", "-t", oid])
            .output()
            .map_err(|e| format!("git cat-file -t {oid}: {e}"))?;
        if !t_out.status.success() {
            return Err(format!(
                "missing or unreadable object {oid}: {}",
                String::from_utf8_lossy(&t_out.stderr).trim()
            ));
        }
        let kind = match String::from_utf8_lossy(&t_out.stdout).trim() {
            "commit" => ObjKind::Commit,
            "tag" => ObjKind::Tag,
            "tree" => ObjKind::Tree,
            "blob" => ObjKind::Blob,
            other => return Err(format!("unknown Git object type {other:?}")),
        };
        if matches!(kind, ObjKind::Blob | ObjKind::Tree) {
            return Ok((kind, Vec::new()));
        }
        let raw_out = self
            .cmd()
            .args(["cat-file", kind.as_str(), oid])
            .output()
            .map_err(|e| format!("git cat-file {} {oid}: {e}", kind.as_str()))?;
        if !raw_out.status.success() {
            return Err(format!(
                "failed reading {} {oid}: {}",
                kind.as_str(),
                String::from_utf8_lossy(&raw_out.stderr).trim()
            ));
        }
        Ok((kind, raw_out.stdout))
    }

    /// Return map of `remote_name -> remote_url` from Git config (`remote.<name>.url`).
    pub fn remote_urls(&self) -> Result<HashMap<String, String>, String> {
        let out = self
            .cmd()
            .args(["config", "--get-regexp", r"^remote\..*\.url$"])
            .output()
            .map_err(|e| format!("list remote urls: {e}"))?;
        if out.status.code() == Some(1) {
            return Ok(HashMap::new());
        }
        if !out.status.success() {
            return Err(format!(
                "git config remote.*.url failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let mut map = HashMap::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let Some((k, url)) = line.split_once(' ') else {
                continue;
            };
            if let Some(rest) = k.strip_prefix("remote.")
                && let Some(name) = rest.strip_suffix(".url")
            {
                map.insert(name.to_string(), url.trim().to_string());
            }
        }
        Ok(map)
    }

    /// Map `remote_name -> Option<PubKey32>`, failing closed if any remote URL has a malformed `ed25519-` marker.
    pub fn remote_keys(&self) -> Result<HashMap<String, PubKey32>, String> {
        let urls = self.remote_urls()?;
        let mut keys = HashMap::new();
        for (name, url) in urls {
            if let Some(k) = extract_key_from_remote_url(&url)? {
                keys.insert(name, k);
            }
        }
        Ok(keys)
    }

    /// Determine the required key (if any) for a given refname, combining:
    /// 1. Explicit key embedded in `refname` (`main+ed25519-...`, `v1.0+ed25519-...`)
    /// 2. Key embedded in the corresponding remote's URL (`remote.<r>.url`):
    ///    - `refs/remotes/<r>/*` -> remote `<r>`
    ///    - `refs/heads/<b>` -> tracked `branch.<b>.remote`, OR `origin` during `git clone`
    ///    - `HEAD` (detached or clone) -> `origin` during `git clone`
    ///    - `refs/tags/*` -> during `clone`/`fetch`/`pull`, `origin` (or the unique keyed remote if only one remote exists)
    ///
    /// Fails closed if both refname and remote URL carry keys that disagree!
    pub fn required_key_for_ref(
        &self,
        refname: &str,
        remote_keys: &HashMap<String, PubKey32>,
        is_clone_or_fetch: bool,
    ) -> Result<Option<(PubKey32, String)>, String> {
        let ref_key = extract_key_from_refname(refname)?;
        let mut remote_key: Option<(PubKey32, String)> = None;

        if let Some(rest) = refname.strip_prefix("refs/remotes/") {
            if let Some((rname, _)) = rest.split_once('/')
                && let Some(&k) = remote_keys.get(rname)
            {
                remote_key = Some((k, format!("remote.{rname}.url")));
            }
        } else if let Some(branch) = refname.strip_prefix("refs/heads/") {
            let tracked_remote = self.config_get(&format!("branch.{branch}.remote"))?;
            if let Some(rname) = tracked_remote
                && let Some(&k) = remote_keys.get(&rname)
            {
                remote_key = Some((k, format!("remote.{rname}.url (via branch.{branch}.remote)")));
            } else if is_clone_or_fetch && let Some(&k) = remote_keys.get("origin") {
                remote_key = Some((k, "remote.origin.url (clone/fetch)".into()));
            }
        } else if refname == "HEAD" {
            if is_clone_or_fetch && let Some(&k) = remote_keys.get("origin") {
                remote_key = Some((k, "remote.origin.url (clone/fetch)".into()));
            }
        } else if refname.starts_with("refs/tags/") && is_clone_or_fetch {
            if let Some(&k) = remote_keys.get("origin") {
                remote_key = Some((k, "remote.origin.url (clone/fetch tag)".into()));
            } else if remote_keys.len() == 1
                && let Some((rname, &k)) = remote_keys.iter().next()
            {
                remote_key = Some((k, format!("remote.{rname}.url (fetch tag)")));
            }
        }

        match (ref_key, remote_key) {
            (Some(rk), Some((uk, src))) => {
                if rk != uk {
                    return Err(format!(
                        "CONFLICTING Ed25519 keys for {}: refname requires {}, but {src} requires {}",
                        sanitize_for_tty(refname),
                        format_marker(&rk),
                        format_marker(&uk)
                    ));
                }
                Ok(Some((rk, format!("refname + {src}"))))
            }
            (Some(rk), None) => Ok(Some((rk, "refname".into()))),
            (None, Some(pair)) => Ok(Some(pair)),
            (None, None) => Ok(None),
        }
    }
}

/// Verify a single Git object (`oid`) against `expected_key`:
/// - Commit: verifies `gpgsig` header via `ssh-keygen -Y verify`
/// - Annotated tag: verifies terminal SSH signature block via `ssh-keygen -Y verify`
/// - Tree / Blob: fails closed (cannot carry Git signatures)
pub fn verify_object_signature(
    repo: &GitRepo,
    oid: &str,
    expected_key: &PubKey32,
) -> Result<ObjKind, String> {
    let (kind, raw) = repo.read_object(oid)?;
    match kind {
        ObjKind::Commit => {
            let (payload, sig) = extract_commit_ssh_signature(&raw)?;
            verify_ssh_signature(&payload, &sig, expected_key)?;
            Ok(ObjKind::Commit)
        }
        ObjKind::Tag => {
            let (payload, sig) = extract_tag_ssh_signature(&raw)?;
            verify_ssh_signature(&payload, &sig, expected_key)?;
            Ok(ObjKind::Tag)
        }
        ObjKind::Tree | ObjKind::Blob => Err(format!(
            "object {oid} is a {} and cannot carry a Git signature",
            kind.as_str()
        )),
    }
}

type RefUpdate = (Vec<u8>, Vec<u8>, Vec<u8>);

fn parse_transaction_stdin(mut reader: impl Read) -> Result<Vec<RefUpdate>, String> {
    let mut raw = Vec::new();
    reader
        .read_to_end(&mut raw)
        .map_err(|e| format!("signet: failed reading reference-transaction stdin: {e}"))?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let body = raw
        .strip_suffix(b"\n")
        .ok_or_else(|| "signet: truncated reference-transaction stdin (missing LF)".to_string())?;
    let mut out = Vec::new();
    for line in body.split(|&c| c == b'\n') {
        let sp1 = line
            .iter()
            .position(|&c| c == b' ')
            .ok_or_else(|| "signet: malformed reference-transaction line".to_string())?;
        let rest = &line[sp1 + 1..];
        let sp2 = rest
            .iter()
            .position(|&c| c == b' ')
            .ok_or_else(|| "signet: malformed reference-transaction line".to_string())?;
        let old_tok = &line[..sp1];
        let new_tok = &rest[..sp2];
        let ref_bytes = &rest[sp2 + 1..];
        if old_tok.is_empty() || new_tok.is_empty() || ref_bytes.is_empty() || ref_bytes.contains(&0) {
            return Err("signet: malformed reference-transaction field".into());
        }
        out.push((old_tok.to_vec(), new_tok.to_vec(), ref_bytes.to_vec()));
    }
    Ok(out)
}

/// Run `reference-transaction` hook (`prepared` phase verifies every key-governed ref update!).
pub fn run_reference_transaction_hook(phase: &str) -> Result<(), String> {
    if phase != "prepared" {
        return Ok(());
    }
    let updates = parse_transaction_stdin(std::io::stdin().lock())?;
    if updates.is_empty() {
        return Ok(());
    }

    let repo = match GitRepo::open(None) {
        Ok(r) => r,
        Err(msg) if msg.contains("not a git repository") => return Ok(()),
        Err(msg) => return Err(format!("signet: failed opening repository in hook: {msg}")),
    };
    if repo.config_bool("signet.disabled", false)? {
        return Ok(());
    }

    let remote_keys = repo.remote_keys()?;
    let reflog_action = env::var("GIT_REFLOG_ACTION").unwrap_or_default().to_ascii_lowercase();
    let is_clone_or_fetch = reflog_action.starts_with("clone")
        || reflog_action.starts_with("fetch")
        || reflog_action.starts_with("pull")
        || updates.iter().any(|(_, _, r)| r.starts_with(b"refs/remotes/"));

    for (_old_b, new_b, ref_b) in &updates {
        // Deletions (all-zero OID) or symref updates (`ref:...`)
        if new_b.iter().all(|&b| b == b'0') || new_b.starts_with(b"ref:") {
            continue;
        }
        let Ok(ref_s) = std::str::from_utf8(ref_b) else {
            if ref_b.windows(8).any(|w| w == b"ed25519-") {
                return Err("signet: non-UTF-8 refname containing 'ed25519-' rejected".into());
            }
            continue;
        };
        let Some((expected_key, source)) =
            repo.required_key_for_ref(ref_s, &remote_keys, is_clone_or_fetch)?
        else {
            continue;
        };
        let oid = std::str::from_utf8(new_b)
            .map_err(|_| format!("signet: non-UTF-8 OID for {}", sanitize_for_tty(ref_s)))?;
        verify_object_signature(&repo, oid, &expected_key).map_err(|e| {
            format!(
                "signet: SIGNATURE REJECTED on {} (expected {} from {source}):\n  {e}",
                sanitize_for_tty(ref_s),
                format_marker(&expected_key)
            )
        })?;
    }
    Ok(())
}

/// Audit all refs in the repository (`git refs verify` + `for-each-ref -z` + detached HEAD).
pub fn fsck_all_refs(repo: &GitRepo) -> Result<(usize, usize), String> {
    let rv = repo
        .cmd()
        .args(["refs", "verify"])
        .output()
        .map_err(|e| format!("signet fsck: git refs verify: {e}"))?;
    if !rv.status.success() {
        return Err(format!(
            "signet fsck: ref database verification failed: {}",
            sanitize_for_tty(String::from_utf8_lossy(&rv.stderr).trim())
        ));
    }

    let out = repo
        .cmd()
        .args(["for-each-ref", "--format=%(objectname) %(refname)%00"])
        .output()
        .map_err(|e| format!("signet fsck: for-each-ref: {e}"))?;
    if !out.status.success() || !out.stderr.is_empty() {
        return Err(format!(
            "signet fsck: for-each-ref failed/warned: {}",
            sanitize_for_tty(String::from_utf8_lossy(&out.stderr).trim())
        ));
    }

    let remote_keys = repo.remote_keys()?;
    let mut verified = 0usize;
    let mut unpinned = 0usize;

    for rec in out.stdout.split(|&b| b == 0) {
        if rec.is_empty() || rec == b"\n" {
            continue;
        }
        let rec = rec.strip_prefix(b"\n").unwrap_or(rec);
        let Some(sp) = rec.iter().position(|&b| b == b' ') else {
            return Err("signet fsck: malformed for-each-ref record".into());
        };
        let oid = std::str::from_utf8(&rec[..sp])
            .map_err(|_| "signet fsck: non-UTF-8 OID".to_string())?;
        let ref_b = &rec[sp + 1..];
        let Ok(ref_s) = std::str::from_utf8(ref_b) else {
            if ref_b.windows(8).any(|w| w == b"ed25519-") {
                return Err("signet fsck: non-UTF-8 ref containing 'ed25519-' rejected".into());
            }
            unpinned += 1;
            continue;
        };

        // In fsck, also check tags against origin if origin carries a verifying key
        let check_origin_tags = remote_keys.contains_key("origin");
        match repo.required_key_for_ref(ref_s, &remote_keys, check_origin_tags)? {
            Some((key, source)) => {
                verify_object_signature(repo, oid, &key).map_err(|e| {
                    format!(
                        "signet fsck: FAILED on {} (expected {} from {source}): {e}",
                        sanitize_for_tty(ref_s),
                        format_marker(&key)
                    )
                })?;
                verified += 1;
            }
            None => unpinned += 1,
        }
    }

    Ok((verified, unpinned))
}

/// Detect whether Git supports native `[hook "<name>"]` config (`git hook list`, Git 2.56+).
pub fn supports_native_config_hooks(git_bin: &Path) -> bool {
    let Ok(out) = Command::new(git_bin).args(["hook", "list", "-h"]).output() else {
        return false;
    };
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    combined.contains("usage: git hook list")
}

pub fn posix_single_quote(s: &str) -> String {
    assert!(!s.contains('\0'), "POSIX shell token cannot contain NUL");
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Register `git-signet` via Git 2.56+ native `[hook "signet-reference-transaction"]` config!
/// Coexists natively with `git-buttress`, `git-lfs`, `pre-commit`, `husky`, and `.git/hooks/*`.
pub fn enable_signet(global: bool) -> Result<(), String> {
    let git_bin = env::var_os("GIT_SIGNET_GIT")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("git"));
    if !supports_native_config_hooks(&git_bin) {
        return Err(
            "git-signet auto-enable requires Git 2.56+ native config hooks (`git hook list`); \
             on older Git, invoke `git-signet __hook-reference-transaction \"$@\"` from your reference-transaction hook"
                .into(),
        );
    }
    let self_exe = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| format!("locate git-signet binary: {e}"))?;
    let exe_str = self_exe
        .to_str()
        .ok_or("git-signet executable path is not valid UTF-8")?;
    let cmd_val = format!(
        "{} __hook-reference-transaction",
        posix_single_quote(exe_str)
    );
    let scope = if global { "--global" } else { "--local" };
    if !global {
        let _ = Command::new(&git_bin)
            .args(["config", "--local", "signet.disabled", "false"])
            .output();
    }
    for (k, v, replace) in [
        ("hook.signet-reference-transaction.event", "reference-transaction", true),
        ("hook.signet-reference-transaction.command", cmd_val.as_str(), false),
        ("hook.signet-reference-transaction.enabled", "true", false),
    ] {
        let mut c = Command::new(&git_bin);
        c.args(["config", scope]);
        if replace {
            c.arg("--replace-all");
        }
        let out = c
            .args([k, v])
            .output()
            .map_err(|e| format!("git config {k}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git config {k} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    Ok(())
}

pub fn disable_signet(global: bool) -> Result<(), String> {
    let git_bin = env::var_os("GIT_SIGNET_GIT")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("git"));
    let scope = if global { "--global" } else { "--local" };
    let _ = Command::new(&git_bin)
        .args([
            "config",
            scope,
            "--remove-section",
            "hook.signet-reference-transaction",
        ])
        .output();
    if !global {
        let _ = Command::new(&git_bin)
            .args(["config", "--local", "signet.disabled", "true"])
            .output();
        let _ = Command::new(&git_bin)
            .args([
                "config",
                "--local",
                "hook.signet-reference-transaction.enabled",
                "false",
            ])
            .output();
    }
    Ok(())
}

/// Configure the current repository to automatically SSH-sign commits & annotated tags with `key_path`.
pub fn configure_signing_here(key_path: &Path) -> Result<PubKey32, String> {
    let pub_path = if key_path.extension().and_then(|s| s.to_str()) == Some("pub") {
        key_path.to_path_buf()
    } else {
        PathBuf::from(format!("{}.pub", key_path.display()))
    };
    let pub_text = fs::read_to_string(&pub_path)
        .map_err(|e| format!("read public key {}: {e}", pub_path.display()))?;
    let key = parse_openssh_ed25519_pubkey(&pub_text)?;
    let abs_key = fs::canonicalize(key_path).unwrap_or_else(|_| key_path.to_path_buf());
    let key_str = abs_key
        .to_str()
        .ok_or("signing key path is not valid UTF-8")?;

    let repo = GitRepo::open(None)?;
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", key_str),
        ("commit.gpgsign", "true"),
        ("tag.gpgSign", "true"),
    ] {
        let out = repo
            .cmd()
            .args(["config", "--local", k, v])
            .output()
            .map_err(|e| format!("git config --local {k}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git config --local {k} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    Ok(key)
}

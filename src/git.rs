//! Git repository access, the rule for which refs a verifying key governs, the hook, and setup.
//!
//! The rule, in one place (`governing_key`):
//! - `refs/remotes/<r>/*`: the key in remote `<r>`'s URL, and any key in the ref's own name.
//! - `refs/tags/*`: any key in the tag's own name; and the key of the remote the tag came from,
//!   when that is known (it arrived together with that remote's branches, or the repository is a
//!   bare mirror of a single remote).
//! - `refs/heads/*` and `HEAD` in a repository with a working tree: nothing. Local branches are
//!   the user's own work; `git commit`, `git merge` and `git rebase` are never refused.
//! - `refs/heads/*` and `HEAD` in a bare repository: as for tags (they hold what was fetched or
//!   pushed, not local work).
//!
//! A governed ref must point at a commit signed by the key, or at a tag that is itself signed by
//! the key or names such a commit (`verify_object_signature`).

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

fn git_bin() -> PathBuf {
    env::var_os("GIT_SIGNET_GIT")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("git"))
}

/// The repository's remotes and the verifying keys their URLs carry.
pub struct Remotes {
    pub names: Vec<String>,
    pub keys: HashMap<String, PubKey32>,
}

impl Remotes {
    /// The repository's only remote, if it has exactly one.
    pub fn sole(&self) -> Option<&str> {
        match self.names.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }

    /// The remote whose tracking namespace `refs/remotes/<name>/` holds `refname`
    /// (remote names may contain `/`; the longest matching name wins).
    pub fn of_tracking_ref(&self, refname: &str) -> Option<&str> {
        let rest = refname.strip_prefix("refs/remotes/")?;
        self.names
            .iter()
            .filter(|n| {
                rest.strip_prefix(n.as_str())
                    .is_some_and(|t| t.starts_with('/'))
            })
            .max_by_key(|n| n.len())
            .map(String::as_str)
    }
}

pub struct GitRepo {
    git_dir: PathBuf,
    git_bin: PathBuf,
}

impl GitRepo {
    pub fn open(cwd: Option<&Path>) -> Result<Self, String> {
        let git_bin = git_bin();
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

    pub fn is_bare(&self) -> Result<bool, String> {
        let out = self
            .cmd()
            .args(["rev-parse", "--is-bare-repository"])
            .output()
            .map_err(|e| format!("git rev-parse --is-bare-repository: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim() == "true")
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

    /// The remotes configured for this repository (`remote.<name>.url`) and the keys in their
    /// URLs. A remote whose URLs carry different keys, or a damaged key, is an error.
    pub fn remotes(&self) -> Result<Remotes, String> {
        let out = self
            .cmd()
            .args(["config", "-z", "--get-regexp", r"^remote\..*\.url$"])
            .output()
            .map_err(|e| format!("list remote urls: {e}"))?;
        let mut remotes = Remotes {
            names: Vec::new(),
            keys: HashMap::new(),
        };
        if out.status.code() == Some(1) {
            return Ok(remotes);
        }
        if !out.status.success() {
            return Err(format!(
                "git config remote.*.url failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        // With -z each record is `<key>\n<value>\0`.
        for rec in String::from_utf8_lossy(&out.stdout).split('\0') {
            let Some((k, url)) = rec.split_once('\n') else {
                continue;
            };
            let Some(name) = k.strip_prefix("remote.").and_then(|r| r.strip_suffix(".url")) else {
                continue;
            };
            if !remotes.names.iter().any(|n| n == name) {
                remotes.names.push(name.to_string());
            }
            if let Some(key) = extract_key_from_remote_url(url)?
                && let Some(prev) = remotes.keys.insert(name.to_string(), key)
                && prev != key
            {
                return Err(format!(
                    "remote {} has URLs carrying different ed25519 keys",
                    sanitize_for_tty(name)
                ));
            }
        }
        Ok(remotes)
    }
}

/// The verifying key (and where it was found) that `refname` must satisfy, if any.
///
/// `attributed_remote` is the remote that tags (and, when `include_local_heads`, branches and
/// `HEAD`) are taken to have come from. See the module comment for the rule.
pub fn governing_key(
    refname: &str,
    remotes: &Remotes,
    attributed_remote: Option<&str>,
    include_local_heads: bool,
) -> Result<Option<(PubKey32, String)>, String> {
    let from_remote = |r: &str| {
        remotes
            .keys
            .get(r)
            .map(|k| (*k, format!("remote.{r}.url")))
    };
    let url_key = if refname.starts_with("refs/remotes/") {
        remotes.of_tracking_ref(refname).and_then(from_remote)
    } else if refname.starts_with("refs/tags/") {
        attributed_remote.and_then(from_remote)
    } else if refname.starts_with("refs/heads/") || refname == "HEAD" {
        if !include_local_heads {
            return Ok(None);
        }
        attributed_remote.and_then(from_remote)
    } else {
        return Ok(None);
    };
    match (extract_key_from_refname(refname)?, url_key) {
        (Some(rk), Some((uk, src))) => {
            if rk != uk {
                return Err(format!(
                    "CONFLICTING ed25519 keys for {}: its name requires {}, but {src} requires {}",
                    sanitize_for_tty(refname),
                    format_marker(&rk),
                    format_marker(&uk)
                ));
            }
            Ok(Some((rk, format!("its name and {src}"))))
        }
        (Some(rk), None) => Ok(Some((rk, "its name".into()))),
        (None, url_key) => Ok(url_key),
    }
}

fn verify_commit(raw: &[u8], key: &PubKey32) -> Result<(), String> {
    let (payload, sig) = extract_commit_ssh_signature(raw)?;
    verify_ssh_signature(&payload, &sig, key)
}

/// Check that the object a governed ref points at is vouched for by `expected_key`:
/// - a commit must carry a valid SSH signature by the key;
/// - a tag must carry one itself, or name (through any chain of tags) a commit that does;
/// - trees and blobs are refused.
///
/// Returns a short description of what was found.
pub fn verify_object_signature(
    repo: &GitRepo,
    oid: &str,
    expected_key: &PubKey32,
) -> Result<&'static str, String> {
    let (kind, raw) = repo.read_object(oid)?;
    match kind {
        ObjKind::Commit => {
            verify_commit(&raw, expected_key)?;
            Ok("commit")
        }
        ObjKind::Tag => {
            let tag_err = match extract_tag_ssh_signature(&raw)
                .and_then(|(payload, sig)| verify_ssh_signature(&payload, &sig, expected_key))
            {
                Ok(()) => return Ok("signed tag"),
                Err(e) => e,
            };
            let commit = repo
                .rev_parse(&format!("{oid}^{{commit}}"))
                .map_err(|_| format!("{tag_err}, and the tag does not name a commit"))?;
            let (_, commit_raw) = repo.read_object(&commit)?;
            verify_commit(&commit_raw, expected_key)
                .map_err(|e| format!("{tag_err}; and the commit it names ({commit}): {e}"))?;
            Ok("tag naming a signed commit")
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

/// A deletion (all-zero new value) or a symbolic-ref update: nothing to verify.
fn has_no_object(new_tok: &[u8]) -> bool {
    new_tok.iter().all(|&b| b == b'0') || new_tok.starts_with(b"ref:")
}

/// Git's `reference-transaction` hook.
///
/// `prepared`: verify every governed ref in the transaction; an error aborts the whole
/// transaction before any ref changes. `committed`: remember signing for the user's own
/// key-named branches (see `remember_signing_for_own_branches`). Other phases: nothing.
pub fn run_reference_transaction_hook(phase: &str) -> Result<(), String> {
    if phase != "prepared" && phase != "committed" {
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
    if phase == "committed" {
        remember_signing_for_own_branches(&repo, &updates);
        return Ok(());
    }

    let remotes = repo.remotes()?;
    if remotes.keys.is_empty()
        && !updates
            .iter()
            .any(|(_, _, r)| r.windows(8).any(|w| w == b"ed25519-"))
    {
        return Ok(());
    }
    let bare = repo.is_bare()?;
    // A fetch or clone writes a remote's tags in the same transaction as its branches.
    let txn_remote = updates.iter().find_map(|(_, _, r)| {
        remotes
            .of_tracking_ref(&String::from_utf8_lossy(r))
            .map(str::to_string)
    });
    let attributed = txn_remote.or_else(|| {
        if bare {
            remotes.sole().map(str::to_string)
        } else {
            None
        }
    });

    for (_old_b, new_b, ref_b) in &updates {
        if has_no_object(new_b) {
            continue;
        }
        let ref_s = String::from_utf8_lossy(ref_b);
        let Some((expected_key, source)) =
            governing_key(&ref_s, &remotes, attributed.as_deref(), bare)?
        else {
            continue;
        };
        let oid = std::str::from_utf8(new_b)
            .map_err(|_| format!("signet: non-UTF-8 OID for {}", sanitize_for_tty(&ref_s)))?;
        verify_object_signature(&repo, oid, &expected_key).map_err(|e| {
            format!(
                "signet: SIGNATURE REJECTED on {} (expected {} from {source}):\n  {e}",
                sanitize_for_tty(&ref_s),
                format_marker(&expected_key)
            )
        })?;
    }
    Ok(())
}

/// Audit the repository's refs (`git refs verify` + `for-each-ref`): every remote-tracking ref,
/// every tag (attributed to the repository's only remote, if it has exactly one), and, in a bare
/// repository, every branch. Returns `(verified, not governed by any key)`.
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

    let remotes = repo.remotes()?;
    let bare = repo.is_bare()?;
    let sole = remotes.sole().map(str::to_string);
    let mut verified = 0usize;
    let mut ungoverned = 0usize;

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
        let ref_s = String::from_utf8_lossy(&rec[sp + 1..]);
        match governing_key(&ref_s, &remotes, sole.as_deref(), bare)? {
            Some((key, source)) => {
                verify_object_signature(repo, oid, &key).map_err(|e| {
                    format!(
                        "signet fsck: FAILED on {} (expected {} from {source}): {e}",
                        sanitize_for_tty(&ref_s),
                        format_marker(&key)
                    )
                })?;
                verified += 1;
            }
            None => ungoverned += 1,
        }
    }

    Ok((verified, ungoverned))
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

fn git_config_set(scope_args: &[&str], key: &str, value: &str) -> Result<(), String> {
    let out = Command::new(git_bin())
        .arg("config")
        .args(scope_args)
        .args([key, value])
        .output()
        .map_err(|e| format!("git config {key}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git config {key} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Register `git-signet` via Git 2.56+ native `[hook "signet-reference-transaction"]` config!
/// Coexists natively with `git-buttress`, `git-lfs`, `pre-commit`, `husky`, and `.git/hooks/*`.
pub fn enable_signet(global: bool) -> Result<(), String> {
    if !supports_native_config_hooks(&git_bin()) {
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
        let _ = git_config_set(&["--local"], "signet.disabled", "false");
    }
    git_config_set(
        &[scope, "--replace-all"],
        "hook.signet-reference-transaction.event",
        "reference-transaction",
    )?;
    git_config_set(&[scope], "hook.signet-reference-transaction.command", &cmd_val)?;
    git_config_set(&[scope], "hook.signet-reference-transaction.enabled", "true")
}

pub fn disable_signet(global: bool) -> Result<(), String> {
    let scope = if global { "--global" } else { "--local" };
    let _ = Command::new(git_bin())
        .args([
            "config",
            scope,
            "--remove-section",
            "hook.signet-reference-transaction",
        ])
        .output();
    if !global {
        let _ = git_config_set(&["--local"], "signet.disabled", "true");
        let _ = git_config_set(
            &["--local"],
            "hook.signet-reference-transaction.enabled",
            "false",
        );
    }
    Ok(())
}

/// Where the per-key signing settings written by `adopt_signing_key` live.
fn sign_config_dir() -> Option<PathBuf> {
    let home = env::var_os("HOME").filter(|h| !h.is_empty())?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("git-signet")
            .join("sign"),
    )
}

fn sign_config_file(key: &PubKey32) -> Option<PathBuf> {
    Some(sign_config_dir()?.join(format!("{}.gitconfig", format_marker(key))))
}

/// The four conditional includes that switch signing on wherever a name carries `marker`:
/// the current branch's name (any `/`-separated segment), or any remote's URL.
fn include_conditions(marker: &str) -> [String; 4] {
    [
        format!("includeIf.onbranch:**/*{marker}*.path"),
        format!("includeIf.onbranch:**/*{marker}*/**.path"),
        format!("includeIf.hasconfig:remote.*.url:**/*{marker}*.path"),
        format!("includeIf.hasconfig:remote.*.url:**/*{marker}*/**.path"),
    ]
}

/// Read a signing key's verifying half and settle the path Git should sign with.
/// Accepts the signing key file or its `.pub` file.
fn locate_signing_key(key_path: &Path) -> Result<(PubKey32, String), String> {
    let (signing_path, pub_path) = if key_path.extension().and_then(|s| s.to_str()) == Some("pub") {
        (key_path.with_extension(""), key_path.to_path_buf())
    } else {
        (
            key_path.to_path_buf(),
            PathBuf::from(format!("{}.pub", key_path.display())),
        )
    };
    let pub_text = fs::read_to_string(&pub_path)
        .map_err(|e| format!("read verifying key {}: {e}", pub_path.display()))?;
    let key = parse_openssh_ed25519_pubkey(&pub_text)?;
    // With only the `.pub` file present, ssh-keygen signs through ssh-agent.
    let use_path = if signing_path.is_file() {
        signing_path
    } else {
        pub_path
    };
    let abs = fs::canonicalize(&use_path).unwrap_or(use_path);
    let abs_str = abs
        .to_str()
        .ok_or("signing key path is not valid UTF-8")?
        .to_string();
    Ok((key, abs_str))
}

/// Make plain `git commit` sign with this key wherever a repository, branch or tag name carries
/// its verifying key, on this machine, with no per-repository setup.
///
/// Writes `~/.config/git-signet/sign/<marker>.gitconfig` (`gpg.format = ssh`, `user.signingkey`,
/// `commit.gpgsign = true`) and four `includeIf` entries in the global Git config that include it
/// when the current branch's name or a remote's URL contains the marker. Stock Git then does the
/// signing itself, as it creates each commit. Tags are left alone: a tag is accepted when the
/// commit it names is signed.
pub fn adopt_signing_key(key_path: &Path) -> Result<PubKey32, String> {
    let (key, signing_path) = locate_signing_key(key_path)?;
    let file = sign_config_file(&key).ok_or("HOME is not set")?;
    let dir = file.parent().expect("sign config file has a parent");
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let file_str = file
        .to_str()
        .ok_or("signing config path is not valid UTF-8")?;
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", signing_path.as_str()),
        ("commit.gpgsign", "true"),
    ] {
        git_config_set(&["--file", file_str], k, v)?;
    }
    for cond in include_conditions(&format_marker(&key)) {
        git_config_set(&["--global", "--replace-all"], &cond, file_str)?;
    }
    Ok(key)
}

/// Undo `adopt_signing_key` for the key at `key_path`. The key files are not touched.
pub fn unadopt_signing_key(key_path: &Path) -> Result<PubKey32, String> {
    let (key, _) = locate_signing_key(key_path)?;
    for cond in include_conditions(&format_marker(&key)) {
        let _ = Command::new(git_bin())
            .args(["config", "--global", "--unset-all", &cond])
            .output();
    }
    if let Some(file) = sign_config_file(&key) {
        let _ = fs::remove_file(file);
    }
    Ok(key)
}

/// After a branch whose own name carries a key adopted on this machine is created or moved,
/// record `include.path = <that key's signing settings>` in the repository's config.
///
/// The `onbranch` include that signs commits on such a branch is off while `HEAD` is detached,
/// which is where `git rebase` leaves it when it stops for a conflict; `git rebase --continue`
/// would then try to sign with GnuPG and fail. The recorded include holds in every state.
/// Best effort: any failure leaves things as they were.
fn remember_signing_for_own_branches(repo: &GitRepo, updates: &[RefUpdate]) {
    for (_old_b, new_b, ref_b) in updates {
        if has_no_object(new_b) || !ref_b.starts_with(b"refs/heads/") {
            continue;
        }
        let ref_s = String::from_utf8_lossy(ref_b);
        let Ok(Some(key)) = extract_key_from_refname(&ref_s) else {
            continue;
        };
        let Some(file) = sign_config_file(&key).filter(|f| f.is_file()) else {
            continue; // not a key adopted on this machine
        };
        let Some(file_str) = file.to_str() else {
            continue;
        };
        let already = repo
            .cmd()
            .args(["config", "--local", "--get-all", "include.path"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l == file_str)
            })
            .unwrap_or(true);
        if already {
            continue;
        }
        let added = repo
            .cmd()
            .args(["config", "--local", "--add", "include.path", file_str])
            .output()
            .is_ok_and(|o| o.status.success());
        if added {
            eprintln!(
                "signet: commits in this repository will be signed with {} (branch {} carries that key)",
                format_marker(&key),
                sanitize_for_tty(ref_s.trim_start_matches("refs/heads/"))
            );
        }
    }
}

/// Configure the current repository alone to SSH-sign every commit with `key_path`.
pub fn configure_signing_here(key_path: &Path) -> Result<PubKey32, String> {
    let (key, signing_path) = locate_signing_key(key_path)?;
    let repo = GitRepo::open(None)?;
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", signing_path.as_str()),
        ("commit.gpgsign", "true"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn sanitize_and_parse_transaction_stdin() {
        assert_eq!(sanitize_for_tty("ok\t\x1b[31m\r\n\x7f"), "ok??[31m???");
        let ok = parse_transaction_stdin(Cursor::new(b"aaa bbb refs/heads/main\n")).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].2, b"refs/heads/main");
        assert!(parse_transaction_stdin(Cursor::new(b"")).unwrap().is_empty());
        assert!(parse_transaction_stdin(Cursor::new(b"nospace\n")).is_err());
        assert!(parse_transaction_stdin(Cursor::new(b"one two\n")).is_err());
        assert!(parse_transaction_stdin(Cursor::new(b" bbb refs/heads/m\n")).is_err());
        assert!(parse_transaction_stdin(Cursor::new(b"aaa  refs/heads/m\n")).is_err());
        assert!(parse_transaction_stdin(Cursor::new(b"aaa bbb \n")).is_err());
        assert!(parse_transaction_stdin(Cursor::new(b"aaa bbb refs/\0bad\n")).is_err());
    }
}

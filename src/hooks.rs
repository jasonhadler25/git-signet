//! Git hooks, signet seed management, `gpg.format = x509` BLINCS imprinter/verifier,
//! and unified BLAKE3 + transitive-closure BLINCS verification.

use crate::blake3_chain::{
    ChainError, ChainErrorKind, CommitClass, ContextKeys, DigestCache, attach_gpgsig, compute_commit_digest, compute_tree_digest, insert_signet_headers,
    parse_commit, peel_to_commit, verify_commit_chain,
};
use crate::git::{Dig, GitRepo, MAX_METADATA_OBJECT_BYTES, ObjKind, Oid, WRAPPER_MARKER, ZERO_OID, is_wrapper_script, resolve_real_git, sanitize_for_tty};
use crate::id::{
    decode_imprint_armor, decode_lower_hex, encode_imprint_armor, extract_blake3_pin_from_refname, extract_signet_from_refname, extract_signet_from_remote_url,
    format_signet_marker, parse_signet_marker, to_hex,
};
use crate::snapshot::{ExtractedArmor, extract_commit_imprint, extract_tag_imprint, imprint_payload, verify_payload_imprint};
use signet::{Randomness, SEED_LEN, Signet, SignetId};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const SEED_MAGIC: &[u8; 8] = b"BLINCSs2";
const SEED_FILE_LEN: usize = 8 + SEED_LEN;
const MAX_HOOK_STDIN_BYTES: usize = MAX_METADATA_OBJECT_BYTES;

pub fn config_root() -> Result<PathBuf, String> {
    if let Ok(explicit) = env::var("GIT_SIGNET_CONFIG_DIR")
        && !explicit.is_empty()
    {
        return Ok(PathBuf::from(explicit));
    }
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Ok(PathBuf::from(xdg).join("git-signet"));
    }
    let home = env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".config").join("git-signet"))
}

pub fn signets_dir() -> Result<PathBuf, String> {
    Ok(config_root()?.join("signets"))
}

pub fn gitconfigs_dir() -> Result<PathBuf, String> {
    Ok(config_root()?.join("config"))
}

pub fn randomness_state_dir() -> Result<PathBuf, String> {
    Ok(config_root()?.join("randomness"))
}

fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if !meta.file_type().is_dir() {
            return Err(format!("{} exists and is not a directory", dir.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o022 != 0 {
                return Err(format!("{} must not be group/world-writable", dir.display()));
            }
        }
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| format!("chmod {}: {e}", dir.display()))?;
    }
    Ok(())
}

pub fn ensure_randomness_state() -> Result<PathBuf, String> {
    let root = config_root()?;
    ensure_private_dir(&root)?;
    let dir = root.join("randomness");
    if !dir.exists() {
        Randomness::create(&dir).map_err(|e| format!("create randomness directory {}: {e}", dir.display()))?;
    }
    Ok(dir)
}

fn read_os_seed() -> Result<[u8; SEED_LEN], String> {
    let mut f = File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let meta = f.metadata().map_err(|e| format!("stat /dev/urandom: {e}"))?;
        if !meta.file_type().is_char_device() {
            return Err("/dev/urandom is not a character device".into());
        }
    }
    let mut seed = [0u8; SEED_LEN];
    f.read_exact(&mut seed).map_err(|e| format!("read /dev/urandom: {e}"))?;
    Ok(seed)
}

fn read_bounded_stdin(limit: usize) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut limited = io::stdin().take(u64::try_from(limit + 1).unwrap());
    limited.read_to_end(&mut buf).map_err(|e| format!("read stdin: {e}"))?;
    if buf.len() > limit {
        return Err(format!("stdin exceeds {limit}-byte limit"));
    }
    Ok(buf)
}

/// Generate a fresh BLINCS signet from OS randomness, store its seed at `~/.config/git-signet/signets/<blincs-52>.seed`
/// (or `custom_path` if provided), provision randomness state, and return `(seed_path, SignetId)`.
pub fn generate_signet(custom_path: Option<&Path>) -> Result<(PathBuf, SignetId), String> {
    ensure_randomness_state()?;
    let seed = read_os_seed()?;
    let signet = Signet::from_seed(&seed);
    let id = signet.id();
    let marker = format_signet_marker(&id);

    let path = match custom_path {
        Some(p) => {
            if let Some(parent) = p.parent()
                && !parent.as_os_str().is_empty()
            {
                ensure_private_dir(parent)?;
            }
            p.to_path_buf()
        }
        None => {
            let dir = signets_dir()?;
            ensure_private_dir(&dir)?;
            dir.join(format!("{marker}.seed"))
        }
    };

    let mut raw = [0u8; SEED_FILE_LEN];
    raw[..8].copy_from_slice(SEED_MAGIC);
    raw[8..].copy_from_slice(&seed);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path).map_err(|e| format!("create signet seed {}: {e}", path.display()))?;
    file.write_all(&raw).map_err(|e| format!("write signet seed {}: {e}", path.display()))?;
    file.sync_all().map_err(|e| format!("sync signet seed {}: {e}", path.display()))?;
    Ok((path, id))
}

/// Read a `BLINCSs2` seed file (bounded read) and construct the `Signet`.
pub fn load_signet_from_path(path: &Path) -> Result<Signet, String> {
    let f = File::open(path).map_err(|e| format!("read signet seed {}: {e}", path.display()))?;
    let mut raw = Vec::with_capacity(SEED_FILE_LEN + 1);
    f.take(u64::try_from(SEED_FILE_LEN + 1).unwrap()).read_to_end(&mut raw).map_err(|e| format!("read signet seed {}: {e}", path.display()))?;
    if raw.len() != SEED_FILE_LEN || &raw[..8] != SEED_MAGIC {
        return Err(format!("{} is not a BLINCS signet seed file (expected 40 bytes starting with BLINCSs2)", path.display()));
    }
    let seed: [u8; SEED_LEN] = raw[8..].try_into().unwrap();
    Ok(Signet::from_seed(&seed))
}

/// Resolve a `user.signingkey` specification: either a `blincs-<52>` marker (looked up in `~/.config/git-signet/signets/`)
/// or a direct path to a `.seed` file.
pub fn load_signet_from_spec(spec: &str) -> Result<Signet, String> {
    if let Ok(expected_id) = parse_signet_marker(spec) {
        let path = signets_dir()?.join(format!("{spec}.seed"));
        let signet = load_signet_from_path(&path)?;
        if signet.id() != expected_id {
            return Err(format!("signet seed file {} does not match {spec}", path.display()));
        }
        return Ok(signet);
    }
    load_signet_from_path(Path::new(spec))
}

fn current_exe_str() -> Result<String, String> {
    let exe = env::current_exe().map_err(|e| format!("locate git-signet executable: {e}"))?;
    let canon = fs::canonicalize(&exe).unwrap_or(exe);
    canon.to_str().map(|s| s.to_owned()).ok_or_else(|| "non-UTF-8 executable path".to_string())
}

fn write_signet_gitconfig(id: &SignetId, seed_path: &Path) -> Result<PathBuf, String> {
    let dir = gitconfigs_dir()?;
    ensure_private_dir(&dir)?;
    let marker = format_signet_marker(id);
    let cfg_path = dir.join(format!("{marker}.gitconfig"));
    let tmp_path = dir.join(format!(".{marker}.{}.tmp", std::process::id()));
    let exe = current_exe_str()?;
    let seed_abs = fs::canonicalize(seed_path).unwrap_or_else(|_| seed_path.to_path_buf());
    let seed_str = seed_abs.to_str().ok_or("non-UTF-8 seed path")?;

    // Write via `git config --file` into a fresh 0600 temp file so Git's own config encoder
    // escapes arbitrary path characters (quotes, backslashes, comments, newlines), then rename.
    let _ = fs::remove_file(&tmp_path);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let _ = opts.open(&tmp_path).map_err(|e| format!("create {}: {e}", tmp_path.display()))?;
    let tmp_str = tmp_path.to_str().ok_or("non-UTF-8 temp gitconfig path")?;
    for (k, v) in [("gpg.format", "x509"), ("gpg.x509.program", exe.as_str()), ("user.signingkey", seed_str), ("commit.gpgsign", "true")] {
        let out = global_git_cmd()?.args(["config", "--file", tmp_str, k, v]).output().map_err(|e| format!("git config --file {k}: {e}"))?;
        if !out.status.success() {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("git config --file {k} failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
    }
    fs::rename(&tmp_path, &cfg_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("install {}: {e}", cfg_path.display())
    })?;
    Ok(cfg_path)
}

fn global_git_cmd() -> Result<Command, String> {
    let real_git = resolve_real_git()?;
    let mut cmd = Command::new(real_git);
    cmd.env("GIT_NO_REPLACE_OBJECTS", "1").env("GIT_NO_LAZY_FETCH", "1");
    Ok(cmd)
}

fn git_config_set(global: bool, key: &str, value: &str) -> Result<(), String> {
    let mut cmd = global_git_cmd()?;
    cmd.arg("config");
    if global {
        cmd.arg("--global");
    } else {
        cmd.arg("--local");
    }
    let out = cmd.args([key, value]).output().map_err(|e| format!("git config {key}: {e}"))?;
    if !out.status.success() {
        return Err(format!("git config {key} failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

fn git_config_unset_all(global: bool, key: &str) -> Result<(), String> {
    let mut cmd = global_git_cmd()?;
    cmd.arg("config");
    if global {
        cmd.arg("--global");
    } else {
        cmd.arg("--local");
    }
    let out = cmd.args(["--unset-all", key]).output().map_err(|e| format!("git config --unset-all {key}: {e}"))?;
    // Exit 5 means key was absent, which is fine for idempotent disable/unadopt.
    if !out.status.success() && out.status.code() != Some(5) {
        return Err(format!("git config --unset-all {key} failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

fn include_conditions(marker: &str) -> [String; 4] {
    [
        format!("includeIf.onbranch:**/*{marker}*.path"),
        format!("includeIf.onbranch:**/*{marker}*/**.path"),
        format!("includeIf.hasconfig:remote.*.url:**/*{marker}*.path"),
        format!("includeIf.hasconfig:remote.*.url:**/*{marker}*/**.path"),
    ]
}

/// Adopt a signet seed file so plain `git commit` imprints automatically in repos/branches bound to its `SignetId`.
pub fn adopt_signet(seed_path: &Path) -> Result<SignetId, String> {
    ensure_randomness_state()?;
    let signet = load_signet_from_path(seed_path)?;
    let id = signet.id();
    let marker = format_signet_marker(&id);
    let cfg_path = write_signet_gitconfig(&id, seed_path)?;
    let cfg_str = cfg_path.to_str().ok_or("non-UTF-8 gitconfig path")?;

    for cond in include_conditions(&marker) {
        git_config_set(true, &cond, cfg_str)?;
    }
    Ok(id)
}

pub fn unadopt_signet(seed_path: &Path) -> Result<SignetId, String> {
    let signet = load_signet_from_path(seed_path)?;
    let id = signet.id();
    let marker = format_signet_marker(&id);
    for cond in include_conditions(&marker) {
        git_config_unset_all(true, &cond)?;
    }
    let cfg_path = gitconfigs_dir()?.join(format!("{marker}.gitconfig"));
    let _ = fs::remove_file(cfg_path);
    Ok(id)
}

/// Configure the current repository to imprint every commit with the given signet seed.
pub fn imprint_here(seed_path: &Path) -> Result<SignetId, String> {
    ensure_randomness_state()?;
    let signet = load_signet_from_path(seed_path)?;
    let id = signet.id();
    let cfg_path = write_signet_gitconfig(&id, seed_path)?;
    let cfg_str = cfg_path.to_str().ok_or("non-UTF-8 gitconfig path")?;
    let repo = GitRepo::open(None)?;
    let out = repo.run_output(["config", "--local", "--add", "include.path", cfg_str])?;
    if !out.status.success() {
        return Err(format!("git config --local --add include.path failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(id)
}

fn posix_single_quote(s: &str) -> String {
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

fn supports_native_config_hooks(real_git: &Path) -> bool {
    Command::new(real_git).args(["hook", "list", "-h"]).output().is_ok_and(|o| {
        let txt = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        txt.contains("git hook list")
    })
}

/// Install Git 2.56+ native `[hook]` configuration (no `core.hooksPath` conflict),
/// `gpg.x509.program` (if not set to another tool), and an optional transparent `git` wrapper.
pub fn enable_signet(global: bool, wrapper_dir: Option<&Path>) -> Result<(), String> {
    let real_git = resolve_real_git()?;
    if !supports_native_config_hooks(&real_git) {
        return Err("git-signet enable requires Git 2.56+ native config hooks (`git hook list`); \
             upgrade Git or wire the four hooks (`__hook-post-commit`, `__hook-post-merge`, \
             `__hook-post-rewrite`, `__hook-reference-transaction`) in your hook runner"
            .into());
    }
    let exe = current_exe_str()?;
    let q_exe = posix_single_quote(&exe);
    let hooks = [
        ("signet-post-commit", "post-commit", format!("{q_exe} __hook-post-commit")),
        ("signet-post-merge", "post-merge", format!("{q_exe} __hook-post-merge")),
        ("signet-post-rewrite", "post-rewrite", format!("{q_exe} __hook-post-rewrite")),
        ("signet-reference-transaction", "reference-transaction", format!("{q_exe} __hook-reference-transaction")),
    ];
    for (name, event, cmd_val) in hooks {
        git_config_set(global, &format!("hook.{name}.event"), event)?;
        git_config_set(global, &format!("hook.{name}.command"), &cmd_val)?;
    }
    let existing_x509 = global_git_cmd()
        .ok()
        .and_then(|mut c| c.args(["config", if global { "--global" } else { "--local" }, "--get", "gpg.x509.program"]).output().ok())
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    if existing_x509.as_deref().is_none_or(|p| p == exe || Path::new(p).file_name().and_then(|n| n.to_str()) == Some("git-signet")) {
        git_config_set(global, "gpg.x509.program", &exe)?;
    }
    if let Some(dir) = wrapper_dir {
        install_git_wrapper(dir, &exe)?;
    }
    Ok(())
}

pub fn disable_signet(global: bool, wrapper_dir: Option<&Path>) -> Result<(), String> {
    let exe = current_exe_str()?;
    for name in ["signet-post-commit", "signet-post-merge", "signet-post-rewrite", "signet-reference-transaction"] {
        git_config_unset_all(global, &format!("hook.{name}.event"))?;
        git_config_unset_all(global, &format!("hook.{name}.command"))?;
    }
    let existing_x509 = global_git_cmd()
        .ok()
        .and_then(|mut c| c.args(["config", if global { "--global" } else { "--local" }, "--get", "gpg.x509.program"]).output().ok())
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    if existing_x509.as_deref().is_some_and(|p| p == exe || Path::new(p).file_name().and_then(|n| n.to_str()) == Some("git-signet")) {
        git_config_unset_all(global, "gpg.x509.program")?;
    }
    if let Some(dir) = wrapper_dir {
        let p = dir.join("git");
        if is_wrapper_script(&p) {
            let _ = fs::remove_file(&p);
        }
    }
    Ok(())
}

fn install_git_wrapper(dir: &Path, signet_exe: &str) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let wrapper_path = dir.join("git");
    if wrapper_path.exists() && !is_wrapper_script(&wrapper_path) {
        return Err(format!("refusing to overwrite non-wrapper file {}", wrapper_path.display()));
    }
    let real_git = resolve_real_git()?;
    let marker = std::str::from_utf8(WRAPPER_MARKER).unwrap();
    let q_exe = posix_single_quote(signet_exe);
    let q_real = posix_single_quote(real_git.to_str().ok_or("non-UTF-8 real git path")?);
    let script = format!(
        "#!/bin/sh\n\
         {marker}\n\
         exec {q_exe} __wrap-git {q_real} \"$@\"\n"
    );
    let tmp_path = dir.join(format!(".git-wrapper.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp_path);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o755);
    }
    let mut f = opts.open(&tmp_path).map_err(|e| format!("create {}: {e}", tmp_path.display()))?;
    f.write_all(script.as_bytes()).map_err(|e| format!("write {}: {e}", tmp_path.display()))?;
    drop(f);
    fs::rename(&tmp_path, &wrapper_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("install {}: {e}", wrapper_path.display())
    })?;
    Ok(())
}

/// Transparent `git` wrapper: forwards everything to real `git`, plus appends `git-signet fsck` on `git fsck`.
pub fn run_git_wrapper(real_git_arg: &str, git_args: &[String]) -> Result<i32, String> {
    let real_git = Path::new(real_git_arg);
    let status = Command::new(real_git).args(git_args).status().map_err(|e| format!("exec real git: {e}"))?;
    let code = status.code().unwrap_or(1);
    if code != 0 {
        return Ok(code);
    }
    let (repo_dir, git_dir, subcmd) = parse_git_subcommand(git_args);
    if subcmd == Some("fsck") {
        let mut repo = GitRepo::open_with_git_dir(repo_dir.as_deref(), git_dir.as_deref())?;
        fsck_repo(&mut repo, false)?;
    }
    Ok(0)
}

fn parse_git_subcommand(args: &[String]) -> (Option<PathBuf>, Option<PathBuf>, Option<&str>) {
    let mut repo_dir: Option<PathBuf> = None;
    let mut git_dir: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if let Some(gd) = a.strip_prefix("--git-dir=") {
            git_dir = Some(PathBuf::from(gd));
            i += 1;
            continue;
        }
        match a {
            "-C" => {
                if let Some(d) = args.get(i + 1) {
                    let p = PathBuf::from(d);
                    repo_dir = Some(match repo_dir {
                        Some(prev) if !p.is_absolute() => prev.join(p),
                        _ => p,
                    });
                    i += 2;
                    continue;
                }
                break;
            }
            "--git-dir" => {
                if let Some(gd) = args.get(i + 1) {
                    git_dir = Some(PathBuf::from(gd));
                    i += 2;
                    continue;
                }
                break;
            }
            "-c" | "--work-tree" | "--namespace" | "--config-env" => {
                i += 2;
                continue;
            }
            s if s.starts_with('-') => {
                i += 1;
                continue;
            }
            sub => return (repo_dir, git_dir, Some(sub)),
        }
    }
    (repo_dir, git_dir, None)
}

fn infer_x509_payload_kind(payload: &[u8]) -> Result<ObjKind, String> {
    if payload.starts_with(b"tree ") {
        Ok(ObjKind::Commit)
    } else if payload.starts_with(b"object ") {
        Ok(ObjKind::Tag)
    } else {
        Err("unsupported Git payload (expected commit or annotated tag)".into())
    }
}

/// Handle Git's `gpg.format = x509` invocation (`--status-fd=N -bsau <key>` or `--status-fd=N --verify <sig> -`).
pub fn run_x509_program(args: &[String]) -> Result<i32, String> {
    let mut status_fd: i32 = 2;
    let mut do_sign = false;
    let mut do_verify = false;
    let mut key_spec: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if let Some(fd) = a.strip_prefix("--status-fd=") {
            status_fd = fd.parse::<i32>().map_err(|_| format!("bad --status-fd={fd}"))?;
        } else if a == "--status-fd" {
            i += 1;
            let fd = args.get(i).ok_or("--status-fd requires fd")?;
            status_fd = fd.parse::<i32>().map_err(|_| format!("bad --status-fd {fd}"))?;
        } else if a == "--verify" {
            do_verify = true;
        } else if a == "-u" || a == "--local-user" {
            i += 1;
            key_spec = Some(args.get(i).ok_or("-u requires key")?.clone());
        } else if a == "-bsau" {
            do_sign = true;
            i += 1;
            key_spec = Some(args.get(i).ok_or("-bsau requires key")?.clone());
        } else if a == "-s" || a == "--sign" || a == "-b" || a == "-a" || a == "-bsa" {
            do_sign = true;
        } else if a == "--detach-sign" || a == "--armor" || a == "--keyid-format=long" || a.starts_with("--keyid-format") {
            // Ignored cosmetic gpg flags
        } else {
            positional.push(a.to_owned());
        }
        i += 1;
    }

    if do_sign && do_verify {
        return Err("conflicting x509 sign and verify flags".into());
    }
    if status_fd != 1 && status_fd != 2 {
        return Err(format!("unsupported --status-fd={status_fd} (only 1 or 2 supported)"));
    }

    let write_status = |msg: &str| {
        if status_fd == 1 {
            let _ = io::stdout().write_all(msg.as_bytes());
            let _ = io::stdout().flush();
        } else {
            let _ = io::stderr().write_all(msg.as_bytes());
            let _ = io::stderr().flush();
        }
    };

    if do_sign {
        let spec = key_spec.ok_or("x509 sign invoked without user.signingkey")?;
        let payload = read_bounded_stdin(MAX_HOOK_STDIN_BYTES)?;
        let kind = infer_x509_payload_kind(&payload)?;

        let mut repo = GitRepo::open(None)?;
        let signet = load_signet_from_spec(&spec)?;
        let rng_path = ensure_randomness_state()?;
        let rng = Randomness::initialize(&rng_path).map_err(|e| format!("initialize randomness {}: {e}", rng_path.display()))?;
        let imprint = imprint_payload(&mut repo, kind, &signet, &rng, &payload)?;
        let armor = encode_imprint_armor(&signet.id(), &imprint);

        let id_hex = to_hex(signet.id().as_bytes());
        write_status(&format!("[GNUPG:] SIG_CREATED D 22 10 00 0 {id_hex}\n"));
        io::stdout().write_all(&armor).map_err(|e| format!("write armor: {e}"))?;
        io::stdout().flush().map_err(|e| format!("flush armor: {e}"))?;
        return Ok(0);
    }

    if do_verify {
        let sig_path = positional.first().ok_or("--verify requires imprint file path")?;
        if positional.len() > 2 || (positional.len() == 2 && positional[1] != "-") {
            return Err(format!("unexpected --verify arguments: {positional:?}"));
        }
        let armor = fs::read(sig_path).map_err(|e| format!("read imprint file {sig_path}: {e}"))?;
        let payload = read_bounded_stdin(MAX_HOOK_STDIN_BYTES)?;
        let kind = infer_x509_payload_kind(&payload)?;
        let mut repo = GitRepo::open(None)?;
        match verify_payload_imprint(&mut repo, kind, &payload, &armor, None) {
            Ok(id) => {
                let marker = format_signet_marker(&id);
                let hex = to_hex(id.as_bytes()).to_ascii_uppercase();
                // Report TRUST_UNDEFINED (Git `%G? = U`, exit 0) because stock `git verify-commit`
                // verifies internal snapshot consistency under the embedded SignetId without an
                // external policy pinning the expected SignetId or checking BLAKE3 history.
                write_status("[GNUPG:] NEWSIG\n");
                write_status(&format!("[GNUPG:] GOODSIG {hex} {marker}\n"));
                write_status(&format!("[GNUPG:] VALIDSIG {hex} 2026-11-25 1795564800 0 0 0 0 8 00 {hex}\n"));
                write_status("[GNUPG:] TRUST_UNDEFINED 0 shell\n");
                return Ok(0);
            }
            Err(e) => {
                write_status("[GNUPG:] NEWSIG\n");
                write_status(&format!("[GNUPG:] BADSIG 0000000000000000 git-signet ({})\n", sanitize_for_tty(&e)));
                return Ok(1);
            }
        }
    }

    Err(format!("unsupported x509 invocation: {args:?}"))
}

/// Bind `HEAD` commit with canonical `signet-tree` + `signet-parent` BLAKE3 headers (re-imprinting
/// ONLY when the existing BLINCS imprint verifies cryptographically AND matches this repo's active
/// configured `user.signingkey`). Called from `post-commit`.
pub fn run_post_commit_hook() -> Result<(), String> {
    if env::var("GIT_SIGNET_SKIP_HOOK").as_deref() == Ok("1") {
        return Ok(());
    }
    let mut repo = GitRepo::open(None)?;
    let head_oid = repo.rev_parse("HEAD")?;
    let new_oid = add_blake3_headers_to_commit(&mut repo, &head_oid)?;
    if new_oid == head_oid {
        return Ok(());
    }
    let sym = repo.run_output(["symbolic-ref", "-q", "HEAD"])?;
    let target_ref = if sym.status.success() { String::from_utf8_lossy(&sym.stdout).trim().to_owned() } else { "HEAD".to_owned() };
    let out = repo
        .cmd()
        .env("GIT_SIGNET_SKIP_HOOK", "1")
        .args(["update-ref", "--no-deref", "-m", "git-signet: add BLAKE3 commit headers", &target_ref, &to_hex(&new_oid), &to_hex(&head_oid)])
        .output()
        .map_err(|e| format!("git update-ref: {e}"))?;
    if !out.status.success() {
        return Err(format!("update-ref after adding BLAKE3 headers failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// Handle `post-merge` hook: add BLAKE3 headers ONLY when `HEAD` is a newly created local
/// multi-parent merge commit — NEVER rewriting fast-forwarded merges or imported commits!
pub fn run_post_merge_hook() -> Result<(), String> {
    if env::var("GIT_SIGNET_SKIP_HOOK").as_deref() == Ok("1") {
        return Ok(());
    }
    let mut repo = GitRepo::open(None)?;
    let head_oid = repo.rev_parse("HEAD")?;
    let (kind, raw) = repo.read_object(&head_oid).map_err(|e| e.message)?;
    if kind != ObjKind::Commit {
        return Ok(());
    }
    let parsed = parse_commit(raw).map_err(|e| e.message)?;
    if parsed.parents.len() < 2 {
        return Ok(());
    }
    // Check reflog subject: fast-forward merges record `: Fast-forward` and must NEVER be rewritten.
    let reflog = repo.run_output(["log", "-g", "-1", "--format=%gs", "HEAD"])?;
    if reflog.status.success() {
        let subj = String::from_utf8_lossy(&reflog.stdout);
        if subj.contains("Fast-forward") {
            return Ok(());
        }
    }
    // Also refuse to rewrite a merge commit already reachable from any remote-tracking ref.
    let on_remote = repo.run_output(["for-each-ref", "--contains", &to_hex(&head_oid), "refs/remotes/"])?;
    if on_remote.status.success() && !on_remote.stdout.is_empty() {
        return Ok(());
    }
    run_post_commit_hook()
}

/// Handle `post-rewrite` hook (bounded drain of stdin; ensures `HEAD` carries BLAKE3 headers).
pub fn run_post_rewrite_hook() -> Result<(), String> {
    if env::var("GIT_SIGNET_SKIP_HOOK").as_deref() == Ok("1") {
        return Ok(());
    }
    let _ = read_bounded_stdin(MAX_HOOK_STDIN_BYTES);
    run_post_commit_hook()
}

/// Add `signet-tree` and `signet-parent` BLAKE3 headers to `oid` if missing or stale.
///
/// Always uses a fresh **memory-only** `DigestCache`. If the commit carried a `BLINCSg2` imprint,
/// it is re-imprinted ONLY IF:
/// 1. The existing `BLINCSg2` imprint **cryptographically verifies** against the pre-header commit snapshot, AND
/// 2. This repository's active `user.signingkey` explicitly resolves to that exact `SignetId` (never
///    falling back to global `~/.config/git-signet/signets/` seeds without active repo configuration).
pub fn add_blake3_headers_to_commit(repo: &mut GitRepo, oid: &Oid) -> Result<Oid, String> {
    let (kind, raw) = repo.read_object(oid).map_err(|e| e.message)?;
    if kind != ObjKind::Commit {
        return Ok(*oid);
    }
    let parsed = parse_commit(raw).map_err(|e| e.message)?;
    if matches!(parsed.class, CommitClass::Carrying { .. }) {
        return Ok(*oid);
    }

    let verified_reimprint_signet: Option<Signet> = match extract_commit_imprint(&parsed.raw) {
        ExtractedArmor::Absent => None,
        ExtractedArmor::Malformed(e) => return Err(e),
        ExtractedArmor::Present { payload: orig_payload, armor } => match decode_imprint_armor(&armor) {
            Err(_) => {
                // Non-BLINCS gpgsig (e.g. GPG/SSH): leave untouched rather than stripping another tool's header.
                return Ok(*oid);
            }
            Ok((embedded_id, _)) => {
                // C1 invariant: NEVER acquire a private key based on an unverified embedded ID!
                verify_payload_imprint(repo, ObjKind::Commit, &orig_payload, &armor, Some(&embedded_id))
                    .map_err(|e| format!("refusing to re-imprint commit with unverified BLINCS imprint: {e}"))?;
                let signet = load_active_repo_signet(repo, &embedded_id)?;
                Some(signet)
            }
        },
    };

    let ctx = ContextKeys::new();
    let mut cache = DigestCache::memory_only();

    let tree_dig = compute_tree_digest(repo, &ctx, &parsed.tree, &mut cache).map_err(|e| e.message)?;
    let mut parent_digs = Vec::with_capacity(parsed.parents.len());
    for p in &parsed.parents {
        parent_digs.push(compute_commit_digest(repo, &ctx, p, &mut cache).map_err(|e| e.message)?);
    }

    let payload = insert_signet_headers(&parsed.raw, &parsed.tree, &tree_dig, &parent_digs)?;
    let final_bytes = if let Some(signet) = verified_reimprint_signet {
        let rng_path = ensure_randomness_state()?;
        let rng = Randomness::initialize(&rng_path).map_err(|e| format!("initialize randomness: {e}"))?;
        let imp = imprint_payload(repo, ObjKind::Commit, &signet, &rng, &payload)?;
        let armor = encode_imprint_armor(&signet.id(), &imp);
        attach_gpgsig(&payload, &armor)
    } else {
        payload
    };

    repo.hash_object_write(ObjKind::Commit, &final_bytes)
}

/// Load a private `Signet` ONLY from this repository's active `user.signingkey` configuration,
/// requiring its derived `SignetId` to match `expected_id`. Never falls back to global seed files.
fn load_active_repo_signet(repo: &GitRepo, expected_id: &SignetId) -> Result<Signet, String> {
    let spec = repo
        .config_get_checked("user.signingkey")?
        .ok_or_else(|| format!("refusing to sign with {}: no active user.signingkey configured in this repository", format_signet_marker(expected_id)))?;
    let s = load_signet_from_spec(&spec)?;
    if s.id() != *expected_id {
        return Err(format!("active user.signingkey ({}) does not match commit's signet {}", format_signet_marker(&s.id()), format_signet_marker(expected_id)));
    }
    Ok(s)
}

/// Determine the governing `SignetId` (if any) for `refname` in `repo`:
/// - In a non-bare repo, local `refs/heads/*` and `HEAD` are NEVER governed (local work is never refused).
/// - A `blincs-<52>` in `refname` governs that ref (for remote-tracking refs, tags, and bare-repo refs).
/// - A `blincs-<52>` in `remote.<name>.url` governs `refs/remotes/<name>/*`, tags arriving with that
///   remote (or in a single-remote repo), and in a bare repo its own directory basename or single remote.
/// - Conflicting signet IDs between ref name, remote URL, or bare repo directory name are rejected.
pub fn governing_signet(repo: &GitRepo, refname: &str, batch_remote_id: Option<&SignetId>) -> Result<Option<SignetId>, String> {
    if !repo.is_bare && (refname == "HEAD" || refname.starts_with("refs/heads/")) {
        return Ok(None);
    }

    let ref_id = extract_signet_from_refname(refname)?;

    let remote_id: Option<SignetId> = if let Some(rest) = refname.strip_prefix("refs/remotes/") {
        if let Some((remote_name, _)) = rest.split_once('/') {
            match repo.config_get_checked(&format!("remote.{remote_name}.url"))? {
                Some(url) => extract_signet_from_remote_url(&url)?,
                None => None,
            }
        } else {
            None
        }
    } else if refname.starts_with("refs/tags/") {
        if let Some(bid) = batch_remote_id {
            Some(*bid)
        } else if repo.is_bare {
            bare_repo_signet(repo)?
        } else {
            single_remote_signet(repo)?
        }
    } else if repo.is_bare {
        bare_repo_signet(repo)?
    } else {
        None
    };

    match (ref_id, remote_id) {
        (Some(a), Some(b)) if a != b => Err(format!(
            "conflicting signet IDs for {}: ref carries {}, repository/remote carries {}",
            sanitize_for_tty(refname),
            format_signet_marker(&a),
            format_signet_marker(&b)
        )),
        (Some(a), _) => Ok(Some(a)),
        (None, Some(b)) => Ok(Some(b)),
        (None, None) => Ok(None),
    }
}

fn single_remote_signet(repo: &GitRepo) -> Result<Option<SignetId>, String> {
    let remotes = repo.list_remotes()?;
    if remotes.len() != 1 {
        return Ok(None);
    }
    extract_signet_from_remote_url(&remotes[0].1)
}

fn bare_repo_signet(repo: &GitRepo) -> Result<Option<SignetId>, String> {
    let dir_id = repo.common_dir.to_str().map(extract_signet_from_remote_url).transpose()?.flatten();
    let rem_id = single_remote_signet(repo)?;
    match (dir_id, rem_id) {
        (Some(a), Some(b)) if a != b => {
            Err(format!("conflicting signet IDs between bare repository path ({}) and remote ({})", format_signet_marker(&a), format_signet_marker(&b)))
        }
        (Some(a), _) => Ok(Some(a)),
        (None, Some(b)) => Ok(Some(b)),
        (None, None) => Ok(None),
    }
}

/// Distinct direct authorization evidence separating commit imprints from annotated-tag imprints.
/// Only a directly imprinted `Carrying` commit seeds transitive-closure delegation (SIGNET.md §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectAuth {
    Commit(Oid),
    Tag(Oid),
}

/// Directly verify an object `oid` as carrying a salted whole-snapshot BLINCS imprint under `expected_id`.
/// Returns `Ok(Some(DirectAuth::Commit(c)))` for a verified commit imprint (including via an unimprinted tag),
/// `Ok(Some(DirectAuth::Tag(c)))` for a verified annotated-tag imprint targeting `c`, `Ok(None)` when absent,
/// or `Err` when present armor is malformed, invalid, or signed by a different `SignetId`.
fn verify_direct_imprint(repo: &mut GitRepo, oid: &Oid, expected_id: &SignetId) -> Result<Option<DirectAuth>, String> {
    let (kind, raw) = repo.read_object(oid).map_err(|e| e.message)?;
    match kind {
        ObjKind::Commit => match extract_commit_imprint(&raw) {
            ExtractedArmor::Present { payload, armor } => {
                let _ = verify_payload_imprint(repo, ObjKind::Commit, &payload, &armor, Some(expected_id))?;
                Ok(Some(DirectAuth::Commit(*oid)))
            }
            ExtractedArmor::Absent => Ok(None),
            ExtractedArmor::Malformed(msg) => Err(msg),
        },
        ObjKind::Tag => match extract_tag_imprint(&raw) {
            ExtractedArmor::Present { payload, armor } => {
                let _ = verify_payload_imprint(repo, ObjKind::Tag, &payload, &armor, Some(expected_id))?;
                let commit_oid = peel_to_commit(repo, oid).map_err(|e| e.message)?;
                Ok(Some(DirectAuth::Tag(commit_oid)))
            }
            ExtractedArmor::Malformed(msg) => Err(msg),
            ExtractedArmor::Absent => {
                let commit_oid = peel_to_commit(repo, oid).map_err(|e| e.message)?;
                verify_direct_imprint(repo, &commit_oid, expected_id)
            }
        },
        other => Err(format!("governed ref points to {} (expected commit or tag)", other.as_str())),
    }
}

/// Verify a batch of `(refname, old_oid, new_oid)` updates under BOTH:
/// 1. Full BLAKE3 tree + history verification (`signet-tree` / `signet-parent` + `+blake3-<64>` pins), AND
/// 2. Formal signet transitive-closure authorization (direct salted whole-snapshot BLINCS imprint OR
///    membership in the BLAKE3-verified authenticated ancestor closure of a directly verified carrying
///    commit under `S` surviving in the projected post-transaction ref set).
pub fn verify_ref_batch(repo: &mut GitRepo, updates: &[(String, Oid, Oid)], infer_batch_remote_tags: bool) -> Result<(), String> {
    if updates.is_empty() {
        return Ok(());
    }
    let ctx = ContextKeys::new();

    // Detect if a single marked remote is fetching in this transaction (for tags arriving in the same fetch).
    let batch_remote_id = if infer_batch_remote_tags {
        let mut batch_remote_ids: HashSet<[u8; 32]> = HashSet::new();
        let mut saw_unmarked_remote = false;
        for (refname, _, _) in updates {
            if let Some(rest) = refname.strip_prefix("refs/remotes/")
                && let Some((rname, _)) = rest.split_once('/')
            {
                match repo.config_get_checked(&format!("remote.{rname}.url"))? {
                    Some(url) => match extract_signet_from_remote_url(&url)? {
                        Some(id) => {
                            batch_remote_ids.insert(*id.as_bytes());
                        }
                        None => saw_unmarked_remote = true,
                    },
                    None => saw_unmarked_remote = true,
                }
            }
        }
        if batch_remote_ids.len() == 1 && !saw_unmarked_remote { batch_remote_ids.iter().next().map(SignetId::from_bytes) } else { None }
    } else {
        None
    };

    let mut authorized_ancestors: HashMap<[u8; 32], HashSet<Oid>> = HashMap::new();
    let mut pending_ancestor_checks: Vec<(String, Oid, Oid, SignetId)> = Vec::new();
    let missing_policy = repo.config_get_checked("signet.missing")?.unwrap_or_else(|| "ignore".into());
    let updated_refnames: HashSet<&str> = updates.iter().map(|(r, _, _)| r.as_str()).collect();

    for (refname, _old_oid, oid) in updates {
        if *oid == ZERO_OID {
            continue; // Deletion
        }

        let b3_pin: Option<Dig> = extract_blake3_pin_from_refname(refname)?;
        let gov_id: Option<SignetId> = governing_signet(repo, refname, batch_remote_id.as_ref())?;

        // Local branches in non-bare repos with no `+blake3-` pin skip heavy checks on every transaction.
        if !repo.is_bare && (refname == "HEAD" || refname.starts_with("refs/heads/")) && b3_pin.is_none() && infer_batch_remote_tags {
            continue;
        }

        let commit_oid = match peel_to_commit(repo, oid) {
            Ok(c) => c,
            Err(ChainError { kind: ChainErrorKind::NotACommit, .. }) if gov_id.is_none() && b3_pin.is_none() => continue,
            Err(e) => return Err(format!("ref {} rejected: {}", sanitize_for_tty(refname), e.message)),
        };

        // Full BLAKE3 verification (memory-only cache, never skipping via unauthenticated old_oid!).
        let report = match verify_commit_chain(repo, &ctx, &commit_oid, b3_pin.as_ref(), true) {
            Ok(r) => r,
            Err(ChainError { kind: ChainErrorKind::Incomplete, message }) if gov_id.is_none() && b3_pin.is_none() => {
                // Only ignore incomplete history on plain/unpinned/ungoverned tips; if the tip itself
                // carries `signet-*` claims that cannot be checked, fail closed!
                let tip_is_carrying = repo
                    .read_object(&commit_oid)
                    .ok()
                    .and_then(|(k, r)| if k == ObjKind::Commit { parse_commit(r).ok() } else { None })
                    .is_some_and(|p| matches!(p.class, CommitClass::Carrying { .. }));
                if tip_is_carrying || missing_policy == "error" {
                    return Err(format!("incomplete history on {}: {message}", sanitize_for_tty(refname)));
                }
                if missing_policy == "warn" {
                    eprintln!("git-signet: warning: incomplete history on {}: {message}", sanitize_for_tty(refname));
                }
                continue;
            }
            Err(e) => {
                return Err(format!("BLAKE3 verification failed for {}: {}", sanitize_for_tty(refname), e.message));
            }
        };

        if !report.tip_carries_lines && b3_pin.is_none() && gov_id.is_none() {
            match missing_policy.as_str() {
                "error" => return Err(format!("ref {} has no BLAKE3 signet headers (signet.missing=error)", sanitize_for_tty(refname))),
                "warn" => eprintln!("git-signet: warning: ref {} carries no BLAKE3 headers", sanitize_for_tty(refname)),
                _ => {}
            }
        }

        // Pass 1 for signet-governed refs: check direct salted whole-snapshot BLINCS imprint.
        if let Some(sid) = gov_id {
            match verify_direct_imprint(repo, oid, &sid)? {
                Some(DirectAuth::Commit(_)) => {
                    // Only a directly imprinted CARRYING commit seeds BLAKE3-authenticated closure!
                    if report.tip_carries_lines {
                        authorized_ancestors.entry(*sid.as_bytes()).or_default().extend(report.authenticated_ancestors.iter().copied());
                    }
                }
                Some(DirectAuth::Tag(_)) => {
                    // Directly imprinted annotated tag authorizes THIS tag itself (SIGNET.md §5.2(b)),
                    // never delegating closure authority to arbitrary other refs.
                }
                None => {
                    pending_ancestor_checks.push((refname.clone(), *oid, commit_oid, sid));
                }
            }
        }
    }

    // Pass 2: check pending governed refs against surviving (projected post-transaction) witnesses!
    if !pending_ancestor_checks.is_empty() {
        let needed_ids: HashSet<[u8; 32]> = pending_ancestor_checks.iter().map(|(_, _, _, s)| *s.as_bytes()).collect();
        let existing_refs = repo.for_each_ref(None)?;
        for (eref, eoid) in existing_refs {
            // Skip refs being deleted or replaced in this transaction so a disappearing witness cannot authorize.
            if updated_refnames.contains(eref.as_str()) {
                continue;
            }
            if let Ok(Some(esid)) = governing_signet(repo, &eref, None)
                && needed_ids.contains(esid.as_bytes())
                && let Ok(Some(DirectAuth::Commit(verified_commit))) = verify_direct_imprint(repo, &eoid, &esid)
                && let Ok(rep) = verify_commit_chain(repo, &ctx, &verified_commit, None, true)
                && rep.tip_carries_lines
            {
                authorized_ancestors.entry(*esid.as_bytes()).or_default().extend(rep.authenticated_ancestors.iter().copied());
            }
        }

        for (refname, _, commit_oid, sid) in pending_ancestor_checks {
            let ok = authorized_ancestors.get(sid.as_bytes()).is_some_and(|set| set.contains(&commit_oid));
            if !ok {
                return Err(format!(
                    "ref {} (commit {}) is NOT authorized by signet {}: no valid BLINCS snapshot imprint and not in the BLAKE3-verified transitive closure of any carrying imprinted tip",
                    sanitize_for_tty(&refname),
                    to_hex(&commit_oid),
                    format_signet_marker(&sid)
                ));
            }
        }
    }

    Ok(())
}

/// One parsed byte-exact record from Git's `reference-transaction` hook input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefTxRecord {
    pub refname: String,
    pub old_oid: Oid,
    pub new_oid: Oid,
    pub sym_target: Option<String>,
}

/// Strictly parse byte-exact Git `reference-transaction` lines (`<old> SP <new> SP <refname>\n`).
/// Fails closed on any malformed line or invalid OID instead of silently dropping records.
pub fn parse_reference_transaction_records(raw: &[u8]) -> Result<Vec<RefTxRecord>, String> {
    let mut records = Vec::new();
    for line in raw.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Some(sp1) = line.iter().position(|&b| b == b' ') else {
            return Err("malformed reference-transaction record: missing first ASCII space".into());
        };
        let rest1 = &line[sp1 + 1..];
        let Some(sp2) = rest1.iter().position(|&b| b == b' ') else {
            return Err("malformed reference-transaction record: missing second ASCII space".into());
        };
        let old_b = &line[..sp1];
        let new_b = &rest1[..sp2];
        let ref_b = &rest1[sp2 + 1..];
        if ref_b.is_empty() {
            return Err("malformed reference-transaction record: empty refname".into());
        }
        let refname = std::str::from_utf8(ref_b).map_err(|_| "non-UTF-8 refname in reference-transaction".to_string())?.to_owned();

        let old_oid = if let Some(sym) = old_b.strip_prefix(b"ref:") {
            if sym.is_empty() {
                return Err("malformed symbolic old-value in reference-transaction".into());
            }
            ZERO_OID
        } else {
            let s = std::str::from_utf8(old_b).map_err(|_| "non-UTF-8 old oid in reference-transaction".to_string())?;
            decode_lower_hex::<20>(s).map_err(|e| format!("bad old oid in reference-transaction: {e}"))?
        };

        if let Some(sym) = new_b.strip_prefix(b"ref:") {
            if sym.is_empty() {
                return Err("malformed symbolic new-value in reference-transaction".into());
            }
            let target = std::str::from_utf8(sym).map_err(|_| "non-UTF-8 symbolic target in reference-transaction".to_string())?.to_owned();
            records.push(RefTxRecord { refname, old_oid, new_oid: ZERO_OID, sym_target: Some(target) });
        } else {
            let s = std::str::from_utf8(new_b).map_err(|_| "non-UTF-8 new oid in reference-transaction".to_string())?;
            let new_oid = decode_lower_hex::<20>(s).map_err(|e| format!("bad new oid in reference-transaction: {e}"))?;
            records.push(RefTxRecord { refname, old_oid, new_oid, sym_target: None });
        }
    }
    Ok(records)
}

fn is_allowed_symbolic_update(refname: &str, target: &str) -> Result<bool, String> {
    if extract_blake3_pin_from_refname(refname)?.is_some() {
        return Ok(false);
    }
    if refname == "HEAD" && target.starts_with("refs/heads/") {
        return Ok(true);
    }
    if let Some(rest) = refname.strip_prefix("refs/remotes/")
        && let Some(remote) = rest.strip_suffix("/HEAD")
        && !remote.is_empty()
        && !remote.contains('/')
        && target.starts_with(&format!("refs/remotes/{remote}/"))
    {
        return Ok(true);
    }
    Ok(false)
}

/// Entrypoint for Git's `reference-transaction` hook (`prepared` phase verifies before any ref changes!).
/// Strictly read-only: NEVER mutates repository config.
pub fn run_reference_transaction_hook(phase: &str) -> Result<(), String> {
    if env::var("GIT_SIGNET_SKIP_HOOK").as_deref() == Ok("1") {
        return Ok(());
    }
    let raw = read_bounded_stdin(MAX_HOOK_STDIN_BYTES)?;
    if phase != "prepared" {
        return Ok(());
    }

    let records = parse_reference_transaction_records(&raw)?;
    if records.is_empty() {
        return Ok(());
    }

    let mut updates: Vec<(String, Oid, Oid)> = Vec::with_capacity(records.len());
    for rec in records {
        if let Some(target) = rec.sym_target {
            if !is_allowed_symbolic_update(&rec.refname, &target)? {
                return Err(format!("symbolic ref update refused: {} -> ref:{}", sanitize_for_tty(&rec.refname), sanitize_for_tty(&target)));
            }
            continue;
        }
        updates.push((rec.refname, rec.old_oid, rec.new_oid));
    }
    if updates.is_empty() {
        return Ok(());
    }

    let mut repo = GitRepo::open(None)?;
    verify_ref_batch(&mut repo, &updates, true)
}

/// Check a single revision (BLAKE3 chain + conjunctive `+blake3-` pin/`--expect` + conjunctive
/// governing/explicit `SignetId`).
pub fn check_revision(
    repo: &mut GitRepo,
    rev: &str,
    explicit_signet: Option<&SignetId>,
    expected_digest: Option<&Dig>,
    no_shallow: bool,
) -> Result<String, String> {
    let oid = repo.rev_parse(rev)?;
    let full_ref = if rev == "HEAD" {
        let sym = repo.run_output(["symbolic-ref", "-q", "HEAD"]).ok();
        sym.filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()).unwrap_or_else(|| "HEAD".into())
    } else {
        let sym = repo.run_output(["rev-parse", "--verify", "--symbolic-full-name", "--end-of-options", rev]).ok();
        sym.filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| rev.to_owned())
    };

    // Conjunctive digest expectation: reject if both refname pin and --expect exist and disagree!
    let pin_dig = extract_blake3_pin_from_refname(&full_ref)?;
    let want_dig = match (pin_dig, expected_digest.copied()) {
        (Some(a), Some(b)) if a != b => {
            return Err(format!("conflicting BLAKE3 expectations: refname pins {}, --expect requests {}", to_hex(&a), to_hex(&b)));
        }
        (Some(a), _) => Some(a),
        (None, b) => b,
    };

    // Conjunctive signet expectation: reject if both ref/remote governing signet and --signet exist and disagree!
    let inferred_signet = extract_signet_from_refname(&full_ref)?.or(governing_signet(repo, &full_ref, None)?);
    let effective_signet = match (inferred_signet, explicit_signet.copied()) {
        (Some(a), Some(b)) if a != b => {
            return Err(format!(
                "conflicting signet expectations: ref/remote requires {}, --signet requests {}",
                format_signet_marker(&a),
                format_signet_marker(&b)
            ));
        }
        (Some(a), _) => Some(a),
        (None, b) => b,
    };

    let ctx = ContextKeys::new();
    let commit_oid = peel_to_commit(repo, &oid).map_err(|e| e.message)?;
    let report = verify_commit_chain(repo, &ctx, &commit_oid, want_dig.as_ref(), !no_shallow).map_err(|e| e.message)?;
    let shown_digest = if report.carrying_commits == 0 && want_dig.is_none() {
        let mut cache = DigestCache::memory_only();
        compute_commit_digest(repo, &ctx, &commit_oid, &mut cache).map_err(|e| e.message)?
    } else {
        report.digest
    };

    let mut summary = format!(
        "MATCH {}\n  blake3:  {}\n  commits: {} carrying lines, {} plain{}",
        to_hex(&commit_oid),
        to_hex(&shown_digest),
        report.carrying_commits,
        report.plain_commits,
        if report.shallow_boundary_hit { " (shallow boundary reached)" } else { "" }
    );

    if let Some(sid) = effective_signet {
        match verify_direct_imprint(repo, &oid, &sid)? {
            Some(DirectAuth::Commit(_)) => {
                summary.push_str(&format!("\n  signet:  VERIFIED (direct salted snapshot imprint by {})", format_signet_marker(&sid)));
            }
            Some(DirectAuth::Tag(_)) => {
                summary.push_str(&format!("\n  signet:  VERIFIED (direct salted annotated-tag imprint by {})", format_signet_marker(&sid)));
            }
            None => {
                let mut in_closure = false;
                for (eref, eoid) in repo.for_each_ref(None)? {
                    if let Ok(Some(esid)) = governing_signet(repo, &eref, None)
                        && esid == sid
                        && let Ok(Some(DirectAuth::Commit(vcommit))) = verify_direct_imprint(repo, &eoid, &sid)
                        && let Ok(rep) = verify_commit_chain(repo, &ctx, &vcommit, None, !no_shallow)
                        && rep.tip_carries_lines
                        && rep.authenticated_ancestors.contains(&commit_oid)
                    {
                        in_closure = true;
                        break;
                    }
                }
                if !in_closure {
                    return Err(format!("revision {} is NOT authorized by signet {}", sanitize_for_tty(rev), format_signet_marker(&sid)));
                }
                summary.push_str(&format!("\n  signet:  VERIFIED (in BLAKE3-verified transitive closure of {})", format_signet_marker(&sid)));
            }
        }
    } else {
        let (_, raw_c) = repo.read_object(&commit_oid).map_err(|e| e.message)?;
        match extract_commit_imprint(&raw_c) {
            ExtractedArmor::Present { payload, armor } => {
                if decode_imprint_armor(&armor).is_ok() {
                    let id = verify_payload_imprint(repo, ObjKind::Commit, &payload, &armor, None)?;
                    summary.push_str(&format!("\n  imprint: valid snapshot imprint by {} (ungoverned ref)", format_signet_marker(&id)));
                }
            }
            ExtractedArmor::Malformed(e) => return Err(e),
            ExtractedArmor::Absent => {}
        }
    }

    Ok(summary)
}

/// Verify every ref in `repo` (BLAKE3 chains + BLINCS signet authorization, without cross-remote batch inference).
pub fn fsck_repo(repo: &mut GitRepo, verbose: bool) -> Result<usize, String> {
    let refs: Vec<(String, Oid, Oid)> = repo.for_each_ref(None)?.into_iter().map(|(r, o)| (r, ZERO_OID, o)).collect();
    verify_ref_batch(repo, &refs, false)?;
    if verbose {
        println!("git-signet fsck: {} ref(s) verified cleanly.", refs.len());
    }
    Ok(refs.len())
}

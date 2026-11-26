//! Git hooks, signet seed management, `gpg.format = x509` BLINCS imprinter/verifier,
//! and unified BLAKE3 + transitive-closure BLINCS verification.

use crate::blake3_chain::{
    ChainError, ChainErrorKind, CommitClass, ContextKeys, DigestCache, attach_gpgsig, compute_commit_digest, compute_tree_digest, insert_signet_headers,
    parse_commit, peel_to_commit, verify_commit_chain,
};
use crate::git::{Dig, GitRepo, ObjKind, Oid, WRAPPER_MARKER, ZERO_OID, is_wrapper_script, resolve_real_git, sanitize_for_tty};
use crate::id::{
    decode_imprint_armor, decode_lower_hex, encode_imprint_armor, extract_blake3_pin_from_refname, extract_signet_from_refname, extract_signet_from_remote_url,
    format_signet_marker, parse_signet_marker, to_hex,
};
use crate::snapshot::{extract_commit_imprint, extract_tag_imprint, imprint_payload, verify_payload_imprint};
use signet::{Randomness, SEED_LEN, Signet, SignetId};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const SEED_MAGIC: &[u8; 8] = b"BLINCSs2";
const SEED_FILE_LEN: usize = 8 + SEED_LEN;

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
    if dir.exists() {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
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

/// Read a `BLINCSs2` seed file and construct the `Signet`.
pub fn load_signet_from_path(path: &Path) -> Result<Signet, String> {
    let raw = fs::read(path).map_err(|e| format!("read signet seed {}: {e}", path.display()))?;
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
    let exe = current_exe_str()?;
    let seed_abs = fs::canonicalize(seed_path).unwrap_or_else(|_| seed_path.to_path_buf());
    let seed_str = seed_abs.to_str().ok_or("non-UTF-8 seed path")?;

    // Copy/link or reference the seed path directly as user.signingkey so custom locations also work!
    let content = format!(
        "# Managed by git-signet for {marker}\n\
         [gpg]\n\
         \tformat = x509\n\
         [gpg \"x509\"]\n\
         \tprogram = {exe}\n\
         [user]\n\
         \tsigningkey = {seed_str}\n\
         [commit]\n\
         \tgpgsign = true\n"
    );
    fs::write(&cfg_path, content).map_err(|e| format!("write {}: {e}", cfg_path.display()))?;
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
    let _ = cmd.args(["--unset-all", key]).output();
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
    let out = repo.run_output(["config", "--local", "include.path", cfg_str])?;
    if !out.status.success() {
        return Err(format!("git config --local include.path failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
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
/// `gpg.x509.program` for stock `git verify-commit`/`verify-tag`/`log --show-signature`,
/// and an optional transparent `git` wrapper.
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
    if existing_x509.as_deref().is_none_or(|p| p.contains("git-signet")) {
        git_config_set(global, "gpg.x509.program", &exe)?;
    }
    if let Some(dir) = wrapper_dir {
        install_git_wrapper(dir, &exe)?;
    }
    Ok(())
}

pub fn disable_signet(global: bool, wrapper_dir: Option<&Path>) -> Result<(), String> {
    for name in ["signet-post-commit", "signet-post-merge", "signet-post-rewrite", "signet-reference-transaction"] {
        git_config_unset_all(global, &format!("hook.{name}.event"))?;
        git_config_unset_all(global, &format!("hook.{name}.command"))?;
    }
    let existing_x509 = global_git_cmd()
        .ok()
        .and_then(|mut c| c.args(["config", if global { "--global" } else { "--local" }, "--get", "gpg.x509.program"]).output().ok())
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    if existing_x509.as_deref().is_some_and(|p| p.contains("git-signet")) {
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
    fs::write(&wrapper_path, script).map_err(|e| format!("write {}: {e}", wrapper_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&wrapper_path, fs::Permissions::from_mode(0o755)).map_err(|e| format!("chmod wrapper: {e}"))?;
    }
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
    // Check if the subcommand is `fsck` (skipping leading global options).
    let (repo_dir, subcmd) = parse_git_subcommand(git_args);
    if subcmd == Some("fsck")
        && let Ok(mut repo) = GitRepo::open(repo_dir.as_deref())
    {
        fsck_repo(&mut repo, false)?;
    }
    Ok(0)
}

fn parse_git_subcommand(args: &[String]) -> (Option<PathBuf>, Option<&str>) {
    let mut repo_dir: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-C" => {
                if let Some(d) = args.get(i + 1) {
                    repo_dir = Some(PathBuf::from(d));
                    i += 2;
                    continue;
                }
                break;
            }
            "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env" => {
                i += 2;
                continue;
            }
            s if s.starts_with('-') => {
                i += 1;
                continue;
            }
            sub => return (repo_dir, Some(sub)),
        }
    }
    (repo_dir, None)
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
        } else if a.starts_with('-') && a.contains('s') && a.contains('u') && !a.starts_with("--") {
            // Combined short flags like `-bsau`
            do_sign = true;
            if a.ends_with('u') {
                i += 1;
                key_spec = Some(args.get(i).ok_or("-bsau requires key")?.clone());
            }
        } else if a == "-s" || a == "--sign" || a == "-b" || a == "-a" || a == "-bsa" {
            do_sign = true;
        } else if a == "--detach-sign" || a == "--armor" || a == "--keyid-format=long" || a.starts_with("--keyid-format") {
            // Ignored cosmetic gpg flags
        } else {
            positional.push(a.to_owned());
        }
        i += 1;
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
        let mut payload = Vec::new();
        io::stdin().read_to_end(&mut payload).map_err(|e| format!("read payload from stdin: {e}"))?;

        let mut repo = GitRepo::open(None)?;
        let signet = load_signet_from_spec(&spec)?;
        let rng_path = ensure_randomness_state()?;
        let rng = Randomness::initialize(&rng_path).map_err(|e| format!("initialize randomness {}: {e}", rng_path.display()))?;
        let imprint = imprint_payload(&mut repo, &signet, &rng, &payload)?;
        let armor = encode_imprint_armor(&signet.id(), &imprint);

        let id_hex = to_hex(signet.id().as_bytes());
        write_status(&format!("[GNUPG:] SIG_CREATED D 22 10 00 0 {id_hex}\n"));
        io::stdout().write_all(&armor).map_err(|e| format!("write armor: {e}"))?;
        io::stdout().flush().map_err(|e| format!("flush armor: {e}"))?;
        return Ok(0);
    }

    if do_verify {
        let sig_path = positional.first().ok_or("--verify requires imprint file path")?;
        let armor = fs::read(sig_path).map_err(|e| format!("read imprint file {sig_path}: {e}"))?;
        let mut payload = Vec::new();
        io::stdin().read_to_end(&mut payload).map_err(|e| format!("read payload from stdin: {e}"))?;
        let mut repo = GitRepo::open(None)?;
        match verify_payload_imprint(&mut repo, &payload, &armor, None) {
            Ok(id) => {
                let marker = format_signet_marker(&id);
                let hex = to_hex(id.as_bytes()).to_ascii_uppercase();
                write_status("[GNUPG:] NEWSIG\n");
                write_status(&format!("[GNUPG:] GOODSIG {hex} {marker}\n"));
                write_status(&format!("[GNUPG:] VALIDSIG {hex} 2026-11-24 1795500000 0 0 0 0 8 00 {hex}\n"));
                write_status("[GNUPG:] TRUST_FULLY 0 shell\n");
                return Ok(0);
            }
            Err(e) => {
                write_status("[GNUPG:] NEWSIG\n");
                write_status(&format!("[GNUPG:] BADSIG 0000000000000000 git-signet ({e})\n"));
                return Ok(1);
            }
        }
    }

    Err(format!("unsupported x509 invocation: {args:?}"))
}

/// Bind `HEAD` commit with canonical `signet-tree` + `signet-parent` BLAKE3 headers (re-imprinting with
/// the exact same BLINCS signet if the commit was imprinted!). Called from `post-commit`.
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
    // Update current symbolic branch (or detached HEAD) atomically without firing reference-transaction recursion.
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

/// Handle `post-merge` hook: add BLAKE3 headers (and re-imprint if imprinted) ONLY when `HEAD` is a
/// real multi-parent merge commit (never rewriting fast-forward pulls/merges!).
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
    run_post_commit_hook()
}

/// Handle `post-rewrite` hook (reads `<old-oid> <new-oid>` lines on stdin and ensures `HEAD` carries BLAKE3 headers).
pub fn run_post_rewrite_hook() -> Result<(), String> {
    if env::var("GIT_SIGNET_SKIP_HOOK").as_deref() == Ok("1") {
        return Ok(());
    }
    // Drain stdin cleanly so git never hits EPIPE.
    let mut _drain = Vec::new();
    let _ = io::stdin().read_to_end(&mut _drain);
    run_post_commit_hook()
}

/// Add `signet-tree` and `signet-parent` BLAKE3 headers to `oid` if missing or stale; if the commit
/// carried a `BLINCSg2` imprint, re-imprint the new commit + snapshot under that exact signet.
pub fn add_blake3_headers_to_commit(repo: &mut GitRepo, oid: &Oid) -> Result<Oid, String> {
    let (kind, raw) = repo.read_object(oid).map_err(|e| e.message)?;
    if kind != ObjKind::Commit {
        return Ok(*oid);
    }
    let parsed = parse_commit(raw).map_err(|e| e.message)?;
    if matches!(parsed.class, CommitClass::Carrying { .. }) {
        return Ok(*oid);
    }

    // Check if the commit already carried a gpgsig header.
    let existing_blincs_id: Option<SignetId> = match extract_commit_imprint(&parsed.raw) {
        Ok((_, armor)) => match decode_imprint_armor(&armor) {
            Ok((id, _)) => Some(id),
            Err(_) => {
                // Non-BLINCS gpgsig (e.g. GPG/SSH): leave untouched rather than stripping another tool's header.
                return Ok(*oid);
            }
        },
        Err(_) => None,
    };

    let ctx = ContextKeys::new();
    // Always use memory-only cache when imprinting so disk bytes never influence committed headers.
    let mut cache = if existing_blincs_id.is_some() { DigestCache::memory_only() } else { DigestCache::load_from_git_dir(&repo.common_dir) };

    let tree_dig = compute_tree_digest(repo, &ctx, &parsed.tree, &mut cache).map_err(|e| e.message)?;
    let mut parent_digs = Vec::with_capacity(parsed.parents.len());
    for p in &parsed.parents {
        parent_digs.push(compute_commit_digest(repo, &ctx, p, &mut cache).map_err(|e| e.message)?);
    }
    cache.flush();

    let payload = insert_signet_headers(&parsed.raw, &parsed.tree, &tree_dig, &parent_digs)?;
    let final_bytes = if let Some(expected_id) = existing_blincs_id {
        let signet = load_signet_for_id(repo, &expected_id)?;
        let rng_path = ensure_randomness_state()?;
        let rng = Randomness::initialize(&rng_path).map_err(|e| format!("initialize randomness: {e}"))?;
        let imp = imprint_payload(repo, &signet, &rng, &payload)?;
        let armor = encode_imprint_armor(&signet.id(), &imp);
        attach_gpgsig(&payload, &armor)
    } else {
        payload
    };

    repo.hash_object_write(ObjKind::Commit, &final_bytes)
}

fn load_signet_for_id(repo: &GitRepo, expected_id: &SignetId) -> Result<Signet, String> {
    let marker = format_signet_marker(expected_id);
    // 1. Check user.signingkey in git config first (handles custom seed paths).
    if let Some(spec) = repo.config_get("user.signingkey")
        && let Ok(s) = load_signet_from_spec(&spec)
        && s.id() == *expected_id
    {
        return Ok(s);
    }
    // 2. Fallback to standard ~/.config/git-signet/signets/<blincs-52>.seed.
    load_signet_from_spec(&marker)
}

/// Determine the governing `SignetId` (if any) for `refname` in `repo`, following the exact rules:
/// - In a non-bare repo, local `refs/heads/*` and `HEAD` are NEVER governed (user's local work is never refused).
/// - A `blincs-<52>` in a ref name governs that ref (for remote-tracking refs, tags, and bare-repo branches).
/// - A `blincs-<52>` in a remote's URL governs `refs/remotes/<remote>/*`, tags arriving with that remote,
///   and in a bare single-remote mirror its branches/tags/`HEAD`.
/// - Conflicting signet IDs between ref name and remote URL are rejected (fail closed).
pub fn governing_signet(repo: &GitRepo, refname: &str, batch_remote_id: Option<&SignetId>) -> Result<Option<SignetId>, String> {
    if !repo.is_bare && (refname == "HEAD" || refname.starts_with("refs/heads/")) {
        return Ok(None);
    }

    let ref_id = extract_signet_from_refname(refname)?;

    let remote_id: Option<SignetId> = if let Some(rest) = refname.strip_prefix("refs/remotes/") {
        if let Some((remote_name, _)) = rest.split_once('/') {
            match repo.config_get(&format!("remote.{remote_name}.url")) {
                Some(url) => extract_signet_from_remote_url(&url)?,
                None => None,
            }
        } else {
            None
        }
    } else if refname.starts_with("refs/tags/") {
        if let Some(bid) = batch_remote_id { Some(*bid) } else { single_remote_signet(repo)? }
    } else if repo.is_bare {
        single_remote_signet(repo)?
    } else {
        None
    };

    match (ref_id, remote_id) {
        (Some(a), Some(b)) if a != b => Err(format!(
            "conflicting signet IDs for {}: ref carries {}, remote carries {}",
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

/// Try to directly verify an object `oid` as carrying a salted whole-snapshot BLINCS imprint under `expected_id`.
/// Returns `Ok(Some(commit_oid))` on valid direct imprint (whether on the commit or on an annotated tag targeting it),
/// `Ok(None)` if the object simply carries no imprint, or `Err(msg)` if a present imprint is forged/corrupt/wrong-ID.
fn verify_direct_imprint(repo: &mut GitRepo, oid: &Oid, expected_id: &SignetId) -> Result<Option<Oid>, String> {
    let (kind, raw) = repo.read_object(oid).map_err(|e| e.message)?;
    match kind {
        ObjKind::Commit => match extract_commit_imprint(&raw) {
            Ok((payload, armor)) => {
                let _ = verify_payload_imprint(repo, &payload, &armor, Some(expected_id))?;
                Ok(Some(*oid))
            }
            Err(msg) if msg.contains("missing gpgsig header") => Ok(None),
            Err(msg) => Err(msg),
        },
        ObjKind::Tag => {
            // Check if the annotated tag carries its own imprint first.
            if let Ok((payload, armor)) = extract_tag_imprint(&raw) {
                let _ = verify_payload_imprint(repo, &payload, &armor, Some(expected_id))?;
                let commit_oid = peel_to_commit(repo, oid).map_err(|e| e.message)?;
                return Ok(Some(commit_oid));
            }
            // Otherwise peel through tags to the target commit and check its imprint.
            let commit_oid = peel_to_commit(repo, oid).map_err(|e| e.message)?;
            verify_direct_imprint(repo, &commit_oid, expected_id)
        }
        other => Err(format!("governed ref points to {} (expected commit or tag)", other.as_str())),
    }
}

/// Verify a batch of `(refname, old_oid, new_oid)` updates under BOTH:
/// 1. BLAKE3 tree + history verification (`signet-tree` / `signet-parent` + `+blake3-<64>` pins), AND
/// 2. Formal signet transitive-closure authorization (direct salted whole-snapshot BLINCS imprint OR
///    membership in the BLAKE3-verified ancestor closure of a directly verified imprinted commit under `S`).
pub fn verify_ref_batch(repo: &mut GitRepo, updates: &[(String, Oid, Oid)], strict_tags_only_check: bool) -> Result<(), String> {
    if updates.is_empty() {
        return Ok(());
    }
    let ctx = ContextKeys::new();

    // Detect if any remote-tracking ref in this batch carries a remote signet ID (for tags arriving in the same fetch).
    let mut batch_remote_ids: HashSet<[u8; 32]> = HashSet::new();
    for (refname, _, _) in updates {
        if let Some(rest) = refname.strip_prefix("refs/remotes/")
            && let Some((rname, _)) = rest.split_once('/')
            && let Some(url) = repo.config_get(&format!("remote.{rname}.url"))
            && let Some(id) = extract_signet_from_remote_url(&url)?
        {
            batch_remote_ids.insert(*id.as_bytes());
        }
    }
    let batch_remote_id = if batch_remote_ids.len() == 1 { batch_remote_ids.iter().next().map(SignetId::from_bytes) } else { None };

    // Track verified BLAKE3 ancestor closures per SignetId from directly imprinted commits.
    let mut authorized_ancestors: HashMap<[u8; 32], HashSet<Oid>> = HashMap::new();
    let mut pending_ancestor_checks: Vec<(String, Oid, Oid, SignetId)> = Vec::new();
    let missing_policy = repo.config_get("signet.missing").unwrap_or_else(|| "ignore".into());

    for (refname, old_oid, oid) in updates {
        if *oid == ZERO_OID {
            continue; // Deletion
        }

        // 1. Check optional immutable `+blake3-<64>` digest pin in ref name.
        let b3_pin: Option<Dig> = extract_blake3_pin_from_refname(refname)?;
        // 2. Determine governing SignetId (if any).
        let gov_id: Option<SignetId> = governing_signet(repo, refname, batch_remote_id.as_ref())?;

        // Local branches in non-bare repos with no `+blake3-` pin skip heavy checks on every transaction.
        if !repo.is_bare && (refname == "HEAD" || refname.starts_with("refs/heads/")) && b3_pin.is_none() && !strict_tags_only_check {
            continue;
        }

        // Peel tags to commit (reject blobs/trees on governed or pinned refs).
        let commit_oid = match peel_to_commit(repo, oid) {
            Ok(c) => c,
            Err(e) => {
                if gov_id.is_some() || b3_pin.is_some() {
                    return Err(format!("ref {} rejected: {}", sanitize_for_tty(refname), e.message));
                }
                continue;
            }
        };

        let stop_at = if !strict_tags_only_check && *old_oid != ZERO_OID && b3_pin.is_none() { Some(old_oid) } else { None };

        // Always verify BLAKE3 chain (memory-only cache) on governed, pinned, or carrying commits.
        let report = match verify_commit_chain(repo, &ctx, &commit_oid, b3_pin.as_ref(), true, stop_at) {
            Ok(r) => r,
            Err(ChainError { kind: ChainErrorKind::Incomplete, message }) if gov_id.is_none() && b3_pin.is_none() => {
                if missing_policy == "warn" {
                    eprintln!("git-signet: warning: incomplete history on {}: {message}", sanitize_for_tty(refname));
                } else if missing_policy == "error" {
                    return Err(format!("incomplete history on {}: {message}", sanitize_for_tty(refname)));
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
                Some(_) => {
                    authorized_ancestors.entry(*sid.as_bytes()).or_default().extend(report.ancestors.iter().copied());
                }
                None => {
                    // Defer to Pass 2 (formal transitive-closure ancestor check).
                    pending_ancestor_checks.push((refname.clone(), *oid, commit_oid, sid));
                }
            }
        }
    }

    // Pass 2: for any governed ref without a direct imprint, verify whether its commit lies in the
    // BLAKE3-verified transitive ancestor closure of a directly verified imprinted commit under the same SignetId.
    if !pending_ancestor_checks.is_empty() {
        let needed_ids: HashSet<[u8; 32]> = pending_ancestor_checks.iter().map(|(_, _, _, s)| *s.as_bytes()).collect();
        let existing_refs = repo.for_each_ref(None)?;
        for (eref, eoid) in existing_refs {
            if let Ok(Some(esid)) = governing_signet(repo, &eref, None)
                && needed_ids.contains(esid.as_bytes())
                && let Ok(Some(verified_commit)) = verify_direct_imprint(repo, &eoid, &esid)
                && let Ok(rep) = verify_commit_chain(repo, &ctx, &verified_commit, None, true, None)
            {
                authorized_ancestors.entry(*esid.as_bytes()).or_default().extend(rep.ancestors.iter().copied());
            }
        }

        for (refname, _, commit_oid, sid) in pending_ancestor_checks {
            let ok = authorized_ancestors.get(sid.as_bytes()).is_some_and(|set| set.contains(&commit_oid));
            if !ok {
                return Err(format!(
                    "ref {} (commit {}) is NOT authorized by signet {}: no valid BLINCS snapshot imprint and not in the BLAKE3-verified transitive closure of any imprinted tip",
                    sanitize_for_tty(&refname),
                    to_hex(&commit_oid),
                    format_signet_marker(&sid)
                ));
            }
        }
    }

    Ok(())
}

/// Entrypoint for Git's `reference-transaction` hook (`prepared` phase verifies before any ref changes!).
pub fn run_reference_transaction_hook(phase: &str) -> Result<(), String> {
    if env::var("GIT_SIGNET_SKIP_HOOK").as_deref() == Ok("1") {
        return Ok(());
    }
    let mut stdin_txt = String::new();
    io::stdin().read_to_string(&mut stdin_txt).map_err(|e| format!("read reference-transaction stdin: {e}"))?;
    if phase != "prepared" {
        return Ok(());
    }

    let mut updates: Vec<(String, Oid, Oid)> = Vec::new();
    for line in stdin_txt.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 || parts[1].starts_with("ref:") {
            continue;
        }
        let old_oid = if parts[0].starts_with("ref:") { ZERO_OID } else { decode_lower_hex::<20>(parts[0]).unwrap_or(ZERO_OID) };
        let new_oid = decode_lower_hex::<20>(parts[1]).map_err(|e| format!("bad new oid in reference-transaction: {e}"))?;
        let refname = parts[2].to_owned();
        updates.push((refname, old_oid, new_oid));
    }
    if updates.is_empty() {
        return Ok(());
    }

    let mut repo = GitRepo::open(None)?;

    // If a local branch whose name carries an adopted signet ID is created/updated, wire local `include.path`
    // so detached-HEAD rebases continue imprinting automatically!
    if !repo.is_bare {
        for (refname, _, oid) in &updates {
            if *oid != ZERO_OID
                && let Some(branch) = refname.strip_prefix("refs/heads/")
                && let Ok(Some(sid)) = extract_signet_from_refname(branch)
            {
                let marker = format_signet_marker(&sid);
                let cfg_path = gitconfigs_dir()?.join(format!("{marker}.gitconfig"));
                if cfg_path.is_file() {
                    let cfg_str = cfg_path.to_string_lossy();
                    let cur = repo.config_get("include.path");
                    if cur.as_deref() != Some(cfg_str.as_ref()) {
                        let _ = repo.run_output(["config", "--local", "include.path", &cfg_str]);
                    }
                }
            }
        }
    }

    verify_ref_batch(&mut repo, &updates, false)
}

/// Check a single revision (BLAKE3 chain + optional `+blake3-` pin + governing or explicit `SignetId`).
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

    let pin_dig = extract_blake3_pin_from_refname(&full_ref)?;
    let want_dig = expected_digest.copied().or(pin_dig);

    let effective_signet = match explicit_signet {
        Some(s) => Some(*s),
        None => extract_signet_from_refname(&full_ref)?.or(governing_signet(repo, &full_ref, None)?),
    };

    let ctx = ContextKeys::new();
    let commit_oid = peel_to_commit(repo, &oid).map_err(|e| e.message)?;
    let report = verify_commit_chain(repo, &ctx, &commit_oid, want_dig.as_ref(), !no_shallow, None).map_err(|e| e.message)?;
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
        let verified_direct = verify_direct_imprint(repo, &oid, &sid)?.is_some();
        if verified_direct {
            summary.push_str(&format!("\n  signet:  VERIFIED (direct salted snapshot imprint by {})", format_signet_marker(&sid)));
        } else {
            // Check formal transitive-closure rule against governed refs in this repo.
            let mut in_closure = false;
            for (eref, eoid) in repo.for_each_ref(None)? {
                if let Ok(Some(esid)) = governing_signet(repo, &eref, None)
                    && esid == sid
                    && let Ok(Some(vcommit)) = verify_direct_imprint(repo, &eoid, &sid)
                    && let Ok(rep) = verify_commit_chain(repo, &ctx, &vcommit, None, !no_shallow, None)
                    && rep.ancestors.contains(&commit_oid)
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
    } else if let Ok((payload, armor)) = extract_commit_imprint(&repo.read_object(&commit_oid).map_err(|e| e.message)?.1)
        && let Ok(id) = verify_payload_imprint(repo, &payload, &armor, None)
    {
        summary.push_str(&format!("\n  imprint: valid snapshot imprint by {} (ungoverned ref)", format_signet_marker(&id)));
    }

    Ok(summary)
}

/// Verify every remote-tracking ref, tag, and branch in `repo` (BLAKE3 chains + BLINCS signet authorization).
pub fn fsck_repo(repo: &mut GitRepo, verbose: bool) -> Result<usize, String> {
    let refs: Vec<(String, Oid, Oid)> = repo.for_each_ref(None)?.into_iter().map(|(r, o)| (r, ZERO_OID, o)).collect();
    verify_ref_batch(repo, &refs, true)?;
    if verbose {
        println!("git-signet fsck: {} ref(s) verified cleanly.", refs.len());
    }
    Ok(refs.len())
}

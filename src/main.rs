use git_signet::git::{
    GitRepo, configure_signing_here, disable_signet, enable_signet, fsck_all_refs,
    run_reference_transaction_hook, sanitize_for_tty, verify_object_signature,
};
use git_signet::key::{format_marker, parse_marker, parse_openssh_ed25519_pubkey};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "\
git-signet — Zero-PKI self-certifying Ed25519 signing keys in Git repo, branch, and tag names

USAGE:
  git signet enable [--global | --local]
  git signet disable [--global | --local]
  git signet keygen [--file <path>] [--comment <text>]
  git signet format-key <pubkey.pub>
  git signet sign-here <private-key-path>
  git signet check [<rev>] [--key ed25519-<52-base32>]
  git signet fsck
  git signet version
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let res = match args[0].as_str() {
        "__hook-reference-transaction" => {
            let phase = args.get(1).map(|s| s.as_str()).unwrap_or("");
            run_reference_transaction_hook(phase).map(|()| 0)
        }
        "enable" => cmd_enable(&args[1..]),
        "disable" => cmd_disable(&args[1..]),
        "keygen" => cmd_keygen(&args[1..]),
        "format-key" => cmd_format_key(&args[1..]),
        "sign-here" => cmd_sign_here(&args[1..]),
        "check" | "verify" => cmd_check(&args[1..]),
        "fsck" => cmd_fsck(&args[1..]),
        "-V" | "--version" | "version" => {
            println!("git-signet {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        other => Err(format!("unknown subcommand {other:?}\n\n{USAGE}")),
    };

    match res {
        Ok(0) => ExitCode::SUCCESS,
        Ok(c) if (1..=255).contains(&c) => ExitCode::from(c as u8),
        Ok(_) => ExitCode::from(1),
        Err(msg) => {
            eprintln!("git-signet: error: {msg}");
            ExitCode::from(1)
        }
    }
}

fn cmd_enable(args: &[String]) -> Result<i32, String> {
    let mut global = false;
    let mut local = false;
    for a in args {
        match a.as_str() {
            "--global" => global = true,
            "--local" => local = true,
            other => return Err(format!("unknown option for enable: {other}")),
        }
    }
    if global && local {
        return Err("cannot pass both --global and --local".into());
    }
    if !global && !local {
        global = true;
    }
    enable_signet(global)?;
    let scope = if global { "global" } else { "repository" };
    println!(
        "Configured {scope} native Git hook (`hook.signet-reference-transaction`; `core.hooksPath` untouched)"
    );
    Ok(0)
}

fn cmd_disable(args: &[String]) -> Result<i32, String> {
    let mut global = false;
    let mut local = false;
    for a in args {
        match a.as_str() {
            "--global" => global = true,
            "--local" => local = true,
            other => return Err(format!("unknown option for disable: {other}")),
        }
    }
    if global && local {
        return Err("cannot pass both --global and --local".into());
    }
    if !global && !local {
        global = true;
    }
    disable_signet(global)?;
    println!(
        "Disabled git-signet ({})",
        if global { "global" } else { "local" }
    );
    Ok(0)
}

fn cmd_keygen(args: &[String]) -> Result<i32, String> {
    let mut file: Option<PathBuf> = None;
    let mut comment: String = "git-signet".into();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--file" | "-f" => {
                i += 1;
                file = Some(PathBuf::from(args.get(i).ok_or("--file requires a path")?));
            }
            "--comment" | "-C" => {
                i += 1;
                comment = args.get(i).ok_or("--comment requires text")?.clone();
            }
            other => return Err(format!("unknown option for keygen: {other}")),
        }
        i += 1;
    }
    let key_path = match file {
        Some(p) => p,
        None => {
            let home = env::var("HOME").map_err(|_| "HOME is not set")?;
            PathBuf::from(home).join(".ssh").join("git_signet_ed25519")
        }
    };
    if let Some(parent) = key_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let pub_path = PathBuf::from(format!("{}.pub", key_path.display()));
    if !key_path.exists() {
        let status = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-C", &comment, "-f"])
            .arg(&key_path)
            .status()
            .map_err(|e| format!("run ssh-keygen: {e}"))?;
        if !status.success() {
            return Err("ssh-keygen failed".into());
        }
    }
    let pub_txt = fs::read_to_string(&pub_path)
        .map_err(|e| format!("read {}: {e}", pub_path.display()))?;
    let k = parse_openssh_ed25519_pubkey(&pub_txt)?;
    let marker = format_marker(&k);
    println!("Key file:    {}", key_path.display());
    println!("Signet ID:   {marker}");
    println!("Repo suffix: <repo>.{marker}");
    println!("Branch name: main+{marker}");
    println!("Tag name:    v1.0.0+{marker}");
    Ok(0)
}

fn cmd_format_key(args: &[String]) -> Result<i32, String> {
    if args.len() != 1 {
        return Err("usage: git signet format-key <pubkey.pub>".into());
    }
    let pub_txt = fs::read_to_string(&args[0])
        .map_err(|e| format!("read {}: {e}", args[0]))?;
    let k = parse_openssh_ed25519_pubkey(&pub_txt)?;
    println!("{}", format_marker(&k));
    Ok(0)
}

fn cmd_sign_here(args: &[String]) -> Result<i32, String> {
    if args.len() != 1 {
        return Err("usage: git signet sign-here <private-key-path>".into());
    }
    let k = configure_signing_here(Path::new(&args[0]))?;
    let marker = format_marker(&k);
    println!("Configured local repository to SSH-sign commits and tags with {marker}");
    Ok(0)
}

fn cmd_check(args: &[String]) -> Result<i32, String> {
    let mut rev: Option<&str> = None;
    let mut explicit_key: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                if explicit_key.is_some() {
                    return Err("duplicate --key option".into());
                }
                i += 1;
                explicit_key = Some(args.get(i).ok_or("--key requires ed25519-<52-base32>")?);
            }
            s if s.starts_with('-') => return Err(format!("unknown option for check: {s}")),
            s => {
                if rev.is_some() {
                    return Err(format!("unexpected extra argument: {s:?}"));
                }
                rev = Some(s);
            }
        }
        i += 1;
    }

    let rev_str = rev.unwrap_or("HEAD");
    let repo = GitRepo::open(None)?;
    let oid = repo.rev_parse(rev_str)?;

    // Resolve full ref name if `rev_str` names a branch/tag/HEAD
    let full_ref = if rev_str == "HEAD" {
        let sym = repo.cmd().args(["symbolic-ref", "-q", "HEAD"]).output().ok();
        sym.filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "HEAD".into())
    } else {
        let sym = repo
            .cmd()
            .args([
                "rev-parse",
                "--verify",
                "--symbolic-full-name",
                "--end-of-options",
                rev_str,
            ])
            .output()
            .ok();
        sym.filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| rev_str.to_string())
    };

    let remote_keys = repo.remote_keys()?;
    let inferred = repo.required_key_for_ref(&full_ref, &remote_keys, true)?;

    let (expected_key, source) = match (explicit_key, inferred) {
        (Some(ek_s), Some((ik, isrc))) => {
            let ek = parse_marker(ek_s)?;
            if ek != ik {
                return Err(format!(
                    "--key ({}) disagrees with {} ({isrc})",
                    format_marker(&ek),
                    format_marker(&ik)
                ));
            }
            (ek, format!("--key + {isrc}"))
        }
        (Some(ek_s), None) => (parse_marker(ek_s)?, "--key".into()),
        (None, Some((ik, isrc))) => (ik, isrc),
        (None, None) => {
            return Err(format!(
                "no ed25519 key found in ref {:?} or remote URL (pass --key ed25519-<52-base32>)",
                sanitize_for_tty(&full_ref)
            ));
        }
    };

    let kind = verify_object_signature(&repo, &oid, &expected_key)?;
    println!(
        "GOOD {} {} signed by {} ({source})",
        kind.as_str(),
        oid,
        format_marker(&expected_key)
    );
    Ok(0)
}

fn cmd_fsck(args: &[String]) -> Result<i32, String> {
    if !args.is_empty() {
        return Err(format!("unknown option for fsck: {}", args[0]));
    }
    let repo = GitRepo::open(None)?;
    let (verified, unpinned) = fsck_all_refs(&repo)?;
    println!("signet fsck: {verified} pinned ref(s) verified, {unpinned} unpinned ref(s)");
    Ok(0)
}

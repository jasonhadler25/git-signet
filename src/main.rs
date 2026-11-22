use git_signet::git::{
    GitRepo, adopt_signing_key, configure_signing_here, disable_signet, enable_signet,
    fsck_all_refs, governing_key, run_reference_transaction_hook, sanitize_for_tty,
    unadopt_signing_key, verify_object_signature,
};
use git_signet::key::{format_marker, parse_marker, parse_openssh_ed25519_pubkey};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "\
git-signet — Ed25519 verifying keys carried in Git repository, branch, and tag names

USAGE:
  git signet enable [--global | --local]       check signatures on clone, fetch and pull
  git signet disable [--global | --local]
  git signet keygen [--file <path>] [--comment <text>]
                                               make a signing key and adopt it
  git signet adopt <signing-key>               sign automatically wherever a name carries this key
  git signet unadopt <signing-key>
  git signet format-key <key.pub>              print a key's ed25519-<52-base32> marker
  git signet sign-here <signing-key>           sign every commit in this one repository
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
        "adopt" => cmd_adopt(&args[1..], true),
        "unadopt" => cmd_adopt(&args[1..], false),
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
    parse_openssh_ed25519_pubkey(&pub_txt)?;
    let k = adopt_signing_key(&key_path)?;
    print_adopted(&key_path, &format_marker(&k));
    Ok(0)
}

fn print_adopted(key_path: &Path, marker: &str) {
    println!("Signing key:   {}", key_path.display());
    println!("Verifying key: {marker}");
    println!("Name a repository  <repo>.{marker}");
    println!("or a branch        main+{marker}");
    println!("and plain `git commit` there signs with this key; nothing else to set up.");
}

fn cmd_adopt(args: &[String], adopt: bool) -> Result<i32, String> {
    let [path] = args else {
        return Err("usage: git signet adopt|unadopt <signing-key>".into());
    };
    let path = Path::new(path);
    if adopt {
        let k = adopt_signing_key(path)?;
        print_adopted(path, &format_marker(&k));
    } else {
        let k = unadopt_signing_key(path)?;
        println!("No longer signing automatically with {}", format_marker(&k));
    }
    Ok(0)
}

fn cmd_format_key(args: &[String]) -> Result<i32, String> {
    if args.len() != 1 {
        return Err("usage: git signet format-key <key.pub>".into());
    }
    let pub_txt = fs::read_to_string(&args[0])
        .map_err(|e| format!("read {}: {e}", args[0]))?;
    let k = parse_openssh_ed25519_pubkey(&pub_txt)?;
    println!("{}", format_marker(&k));
    Ok(0)
}

fn cmd_sign_here(args: &[String]) -> Result<i32, String> {
    if args.len() != 1 {
        return Err("usage: git signet sign-here <signing-key>".into());
    }
    let k = configure_signing_here(Path::new(&args[0]))?;
    let marker = format_marker(&k);
    println!("Every commit in this repository will be signed with {marker}");
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

    // An explicit check also looks at local branches: a branch answers to the key of the
    // remote it tracks, or of the repository's only remote.
    let remotes = repo.remotes()?;
    let tracked = match full_ref.strip_prefix("refs/heads/") {
        Some(branch) => repo.config_get(&format!("branch.{branch}.remote"))?,
        None => None,
    };
    let attributed = tracked.or_else(|| remotes.sole().map(str::to_string));
    let inferred = governing_key(&full_ref, &remotes, attributed.as_deref(), true)?;

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
                "no verifying key in the name of {:?} or in its remote's URL (pass --key ed25519-<52-base32>)",
                sanitize_for_tty(&full_ref)
            ));
        }
    };

    let what = verify_object_signature(&repo, &oid, &expected_key)?;
    println!(
        "GOOD {what} {oid}: signed by {} (key from {source})",
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
    println!("signet fsck: {verified} ref(s) verified, {unpinned} ref(s) not governed by a key");
    Ok(0)
}

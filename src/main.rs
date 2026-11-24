use git_signet::blake3_chain::{ContextKeys, DigestCache, compute_commit_digest, peel_to_commit};
use git_signet::git::GitRepo;
use git_signet::hooks::{
    adopt_signet, check_revision, disable_signet, enable_signet, fsck_repo, generate_signet, imprint_here, load_signet_from_path, run_git_wrapper,
    run_post_commit_hook, run_post_merge_hook, run_post_rewrite_hook, run_reference_transaction_hook, run_x509_program, unadopt_signet,
};
use git_signet::id::{decode_lower_hex, format_signet_marker, parse_signet_marker, to_hex};
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
git-signet — BLINCS signet IDs and BLAKE3 tree/history binding for Git (pre-1.0 experimental)

USAGE:
  git signet enable [--global | --local] [--wrapper-dir <dir>]
  git signet disable [--global | --local] [--wrapper-dir <dir>]
  git signet keygen [--file <path>]             generate a BLINCS signet and adopt it
  git signet adopt <seed-file>                  imprint automatically wherever a name carries this signet ID
  git signet unadopt <seed-file>
  git signet format-id <seed-file>              print a signet's blincs-<52-base32> marker
  git signet imprint-here <seed-file>           imprint every commit in this one repository
  git signet id [<rev>]                         print a commit's BLAKE3 digest
  git signet check [<rev>] [--signet blincs-<52>] [--expect <64-hex>] [--no-shallow]
  git signet fsck
  git signet version
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    // Detect direct Git `gpg.format = x509` invocation (`--status-fd=...`, `-bsau`, `--verify`).
    let first = args[0].as_str();
    let res = if first.starts_with("--status-fd") || first == "--verify" || first == "-bsau" || first == "-s" || first == "--sign" {
        run_x509_program(&args)
    } else {
        match first {
            "__hook-post-commit" => run_post_commit_hook().map(|()| 0),
            "__hook-post-merge" => run_post_merge_hook().map(|()| 0),
            "__hook-post-rewrite" => run_post_rewrite_hook().map(|()| 0),
            "__hook-reference-transaction" => {
                let phase = args.get(1).map(|s| s.as_str()).unwrap_or("");
                run_reference_transaction_hook(phase).map(|()| 0)
            }
            "__wrap-git" => {
                let real = args.get(1).map(|s| s.as_str()).unwrap_or("");
                run_git_wrapper(real, &args[2..])
            }
            "enable" => cmd_enable_disable(&args[1..], true),
            "disable" => cmd_enable_disable(&args[1..], false),
            "keygen" => cmd_keygen(&args[1..]),
            "adopt" => cmd_adopt(&args[1..], true),
            "unadopt" => cmd_adopt(&args[1..], false),
            "format-id" => cmd_format_id(&args[1..]),
            "imprint-here" => cmd_imprint_here(&args[1..]),
            "id" => cmd_id(&args[1..]),
            "check" | "verify" => cmd_check(&args[1..]),
            "fsck" => cmd_fsck(&args[1..]),
            "-V" | "--version" | "version" => {
                println!("git-signet {} (pre-1.0 experimental)", env!("CARGO_PKG_VERSION"));
                Ok(0)
            }
            other => Err(format!("unknown subcommand {other:?}\n\n{USAGE}")),
        }
    };

    match res {
        Ok(0) => ExitCode::SUCCESS,
        Ok(c) => ExitCode::from(u8::try_from(c).unwrap_or(1)),
        Err(msg) => {
            eprintln!("git-signet: error: {msg}");
            ExitCode::from(1)
        }
    }
}

fn cmd_enable_disable(args: &[String], enable: bool) -> Result<i32, String> {
    let (mut global, mut local) = (false, false);
    let mut wrapper_dir: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--global" => global = true,
            "--local" => local = true,
            "--wrapper-dir" => {
                i += 1;
                wrapper_dir = Some(PathBuf::from(args.get(i).ok_or("--wrapper-dir requires a directory")?));
            }
            other => return Err(format!("unknown option: {other}")),
        }
        i += 1;
    }
    if global && local {
        return Err("cannot pass both --global and --local".into());
    }
    if !global && !local {
        global = true;
    }
    if enable {
        enable_signet(global, wrapper_dir.as_deref())?;
        let scope = if global { "global" } else { "repository" };
        println!("Configured {scope} native Git hooks (`hook.signet-*`; `core.hooksPath` untouched)");
    } else {
        disable_signet(global, wrapper_dir.as_deref())?;
        println!("Disabled git-signet ({})", if global { "global" } else { "local" });
    }
    Ok(0)
}

fn cmd_keygen(args: &[String]) -> Result<i32, String> {
    let mut file: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--file" | "-f" => {
                i += 1;
                file = Some(PathBuf::from(args.get(i).ok_or("--file requires a path")?));
            }
            other => return Err(format!("unknown option for keygen: {other}")),
        }
        i += 1;
    }
    let (seed_path, id) = generate_signet(file.as_deref())?;
    let _ = adopt_signet(&seed_path)?;
    let marker = format_signet_marker(&id);
    println!("Signet seed: {}", seed_path.display());
    println!("Signet ID:   {marker}");
    println!("Name a repository  <repo>.{marker}");
    println!("or a branch        main+{marker}");
    println!("and plain `git commit` there imprints automatically with this signet.");
    Ok(0)
}

fn cmd_adopt(args: &[String], adopt: bool) -> Result<i32, String> {
    let [path] = args else {
        return Err("usage: git signet adopt|unadopt <seed-file>".into());
    };
    let path = Path::new(path);
    if adopt {
        let id = adopt_signet(path)?;
        println!("Adopted signet {}", format_signet_marker(&id));
    } else {
        let id = unadopt_signet(path)?;
        println!("Unadopted signet {}", format_signet_marker(&id));
    }
    Ok(0)
}

fn cmd_format_id(args: &[String]) -> Result<i32, String> {
    let [path] = args else {
        return Err("usage: git signet format-id <seed-file>".into());
    };
    let signet = load_signet_from_path(Path::new(path))?;
    println!("{}", format_signet_marker(&signet.id()));
    Ok(0)
}

fn cmd_imprint_here(args: &[String]) -> Result<i32, String> {
    let [path] = args else {
        return Err("usage: git signet imprint-here <seed-file>".into());
    };
    let id = imprint_here(Path::new(path))?;
    println!("Every commit in this repository will be imprinted with {}", format_signet_marker(&id));
    Ok(0)
}

fn cmd_id(args: &[String]) -> Result<i32, String> {
    let rev = match args {
        [] => "HEAD",
        [r] => r.as_str(),
        _ => return Err("usage: git signet id [<rev>]".into()),
    };
    let mut repo = GitRepo::open(None)?;
    let oid = repo.rev_parse(rev)?;
    let commit_oid = peel_to_commit(&mut repo, &oid).map_err(|e| e.message)?;
    let ctx = ContextKeys::new();
    let mut cache = DigestCache::memory_only();
    let dig = compute_commit_digest(&mut repo, &ctx, &commit_oid, &mut cache).map_err(|e| e.message)?;
    println!("{}", to_hex(&dig));
    Ok(0)
}

fn cmd_check(args: &[String]) -> Result<i32, String> {
    let mut rev: Option<&str> = None;
    let mut explicit_signet: Option<blincs::SignetId> = None;
    let mut expected_dig: Option<[u8; 32]> = None;
    let mut no_shallow = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--signet" => {
                i += 1;
                let s = args.get(i).ok_or("--signet requires blincs-<52-base32>")?;
                explicit_signet = Some(parse_signet_marker(s)?);
            }
            "--expect" => {
                i += 1;
                let h = args.get(i).ok_or("--expect requires 64-hex BLAKE3 digest")?;
                expected_dig = Some(decode_lower_hex::<32>(h)?);
            }
            "--no-shallow" => no_shallow = true,
            s if s.starts_with('-') => return Err(format!("unknown option for check: {s}")),
            s => {
                if rev.is_some() {
                    return Err(format!("unexpected extra argument {s:?}"));
                }
                rev = Some(s);
            }
        }
        i += 1;
    }
    let mut repo = GitRepo::open(None)?;
    let out = check_revision(&mut repo, rev.unwrap_or("HEAD"), explicit_signet.as_ref(), expected_dig.as_ref(), no_shallow)?;
    println!("{out}");
    Ok(0)
}

fn cmd_fsck(args: &[String]) -> Result<i32, String> {
    if !args.is_empty() {
        return Err("usage: git signet fsck".into());
    }
    let mut repo = GitRepo::open(None)?;
    fsck_repo(&mut repo, true)?;
    Ok(0)
}

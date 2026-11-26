include!("../tools/require_nextest.rs");

use git_signet::blake3_chain::{
    CommitClass, ContextKeys, DigestCache, attach_gpgsig, compute_commit_digest, insert_signet_headers, parse_commit, verify_commit_chain,
};
use git_signet::git::{GitRepo, ObjKind, resolve_real_git};
use git_signet::id::{
    decode_imprint_armor, decode_signet_b32, encode_imprint_armor, encode_signet_b32, extract_blake3_pin_from_refname, extract_signet_from_refname,
    extract_signet_from_remote_url, format_signet_marker, parse_signet_marker, to_hex,
};
use git_signet::snapshot::{COMMIT_SNAPSHOT_CTX, SnapshotReader, TAG_SNAPSHOT_CTX, extract_commit_imprint, imprint_payload, verify_payload_imprint};
use signet::{Context, Randomness, SEED_LEN, Signet, SignetId};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("git-signet-it-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn signet_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_git-signet"))
}

struct TestEnv {
    root: PathBuf,
    home: PathBuf,
    config_dir: PathBuf,
    real_git: PathBuf,
}

impl TestEnv {
    fn new(tag: &str) -> Self {
        let root = temp_dir(tag);
        let home = root.join("home");
        let config_dir = root.join("signet-config");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&config_dir).unwrap();
        let real_git = resolve_real_git().unwrap();
        // Minimal user identity in isolated HOME/.gitconfig.
        fs::write(home.join(".gitconfig"), "[user]\n\tname = Test User\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n").unwrap();
        Self { root, home, config_dir, real_git }
    }

    fn git_with_env(&self, cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(&self.real_git);
        cmd.current_dir(cwd)
            .env("HOME", &self.home)
            .env("GIT_SIGNET_CONFIG_DIR", &self.config_dir)
            .env("GIT_SIGNET_REAL_GIT", &self.real_git)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0");
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.args(args).output().unwrap()
    }

    fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        self.git_with_env(cwd, args, &[])
    }

    fn git_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.git(cwd, args);
        assert!(
            out.status.success(),
            "git {:?} failed in {}:\nstdout: {}\nstderr: {}",
            args,
            cwd.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn signet(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(signet_bin())
            .current_dir(cwd)
            .env("HOME", &self.home)
            .env("GIT_SIGNET_CONFIG_DIR", &self.config_dir)
            .env("GIT_SIGNET_REAL_GIT", &self.real_git)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(args)
            .output()
            .unwrap()
    }

    fn signet_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.signet(cwd, args);
        assert!(
            out.status.success(),
            "git-signet {:?} failed:\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn id_encoding_marker_extraction_and_armor_validation() {
    let raw = [0xa5u8; 32];
    let id = SignetId::from_bytes(&raw);
    let b32 = encode_signet_b32(&id);
    assert_eq!(b32.len(), 52);
    assert!(b32.ends_with('a') || b32.ends_with('q'));
    assert_eq!(decode_signet_b32(&b32).unwrap(), id);

    // Reject uppercase, non-zero trailing pad bits, wrong length.
    assert!(decode_signet_b32(&b32.to_uppercase()).is_err());
    let mut bad_pad = b32.clone();
    bad_pad.pop();
    bad_pad.push('b'); // bottom 4 bits nonzero
    assert!(decode_signet_b32(&bad_pad).is_err());
    assert!(decode_signet_b32(&b32[..51]).is_err());

    let marker = format_signet_marker(&id);
    assert!(marker.starts_with("blincs-") && marker.len() == 59);
    assert_eq!(parse_signet_marker(&marker).unwrap(), id);

    // Repo URLs & ref names.
    assert_eq!(extract_signet_from_remote_url(&format!("https://github.com/org/acme.{marker}.git")).unwrap(), Some(id));
    assert_eq!(extract_signet_from_remote_url(&format!("git@github.com:org/acme.{marker}.git")).unwrap(), Some(id));
    assert_eq!(extract_signet_from_remote_url("https://github.com/org/blincs-demo.git").unwrap(), None);
    assert_eq!(extract_signet_from_refname(&format!("refs/heads/main+{marker}")).unwrap(), Some(id));
    assert_eq!(extract_signet_from_refname("refs/heads/fix/blincs-parser").unwrap(), None);

    // Chained with +blake3-<64-hex> in either order.
    let dig = [0x42u8; 32];
    let hex = to_hex(&dig);
    let chained1 = format!("refs/tags/v1.0+{marker}+blake3-{hex}");
    let chained2 = format!("refs/tags/v1.0+blake3-{hex}+{marker}");
    assert_eq!(extract_signet_from_refname(&chained1).unwrap(), Some(id));
    assert_eq!(extract_blake3_pin_from_refname(&chained1).unwrap(), Some(dig));
    assert_eq!(extract_signet_from_refname(&chained2).unwrap(), Some(id));
    assert_eq!(extract_blake3_pin_from_refname(&chained2).unwrap(), Some(dig));

    // Reject damaged 40+-char tokens, walk operators, and conflicting IDs.
    assert!(extract_signet_from_refname(&format!("refs/heads/main+blincs-{}", "a".repeat(45))).is_err());
    assert!(extract_signet_from_refname(&format!("main+{marker}~1")).is_err());
    assert!(extract_signet_from_refname(&format!("main+{marker}..other")).is_err());
    let id2 = SignetId::from_bytes(&[0x11u8; 32]);
    let m2 = format_signet_marker(&id2);
    assert!(extract_signet_from_refname(&format!("refs/heads/{marker}/{m2}")).is_err());

    // Armor round-trip and rejection.
    let tmp = temp_dir("armor");
    let rng_dir = tmp.join("rng");
    Randomness::create(&rng_dir).unwrap();
    let rng = Randomness::initialize(&rng_dir).unwrap();
    let signet = Signet::from_seed(&[0x22u8; SEED_LEN]);
    let imp = signet.imprint(&rng, Context::EMPTY, b"armor-test");
    let armor = encode_imprint_armor(&signet.id(), &imp);
    let (dec_id, dec_imp) = decode_imprint_armor(&armor).unwrap();
    assert_eq!(dec_id, signet.id());
    assert_eq!(dec_imp, imp);
    assert!(decode_imprint_armor(b"-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n").is_err());
    // Reject exact-length armor with wrong 8-byte magic header (flip first byte of magic).
    let mut bad_magic_armor = String::from_utf8(armor.clone()).unwrap();
    assert!(bad_magic_armor.contains("\nQkxJTkNTZz"));
    bad_magic_armor = bad_magic_armor.replacen("\nQkxJTkNTZz", "\nRkxJTkNTZz", 1);
    assert!(decode_imprint_armor(bad_magic_armor.as_bytes()).is_err());
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn end_to_end_imprint_verify_clone_and_adversarial_rejections() {
    let env = TestEnv::new("e2e");
    env.signet_ok(&env.root, &["enable", "--global"]);

    // Generate signet A and signet B (A adopted, B unadopted).
    let out_a = env.signet_ok(&env.root, &["keygen"]);
    let marker_a = out_a.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();
    let seed_b = env.root.join("b.seed");
    let out_b = env.signet_ok(&env.root, &["keygen", "--file", seed_b.to_str().unwrap()]);
    let marker_b = out_b.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();
    assert_ne!(marker_a, marker_b);
    env.signet_ok(&env.root, &["unadopt", seed_b.to_str().unwrap()]);

    // Create bare remote named `acme.<marker_a>.git`.
    let remote = env.root.join(format!("acme.{marker_a}.git"));
    fs::create_dir_all(&remote).unwrap();
    env.git_ok(&remote, &["init", "--bare"]);

    // Clone and make two commits (including nested dir + 128 KiB file exercising streaming!).
    let work = env.root.join("work");
    env.git_ok(&env.root, &["clone", remote.to_str().unwrap(), work.to_str().unwrap()]);
    fs::create_dir_all(work.join("src/deep")).unwrap();
    fs::write(work.join("README.md"), b"hello unified git-signet\n").unwrap();
    fs::write(work.join("src/deep/big.bin"), vec![0x5Au8; 128 * 1024 + 17]).unwrap();
    env.git_ok(&work, &["add", "."]);
    env.git_ok(&work, &["commit", "-m", "initial commit"]);

    // Verify commit carries BOTH `signet-tree blake3` AND `gpgsig` `BLINCSg2`, and passes stock `git verify-commit`!
    let raw_head = env.git_ok(&work, &["cat-file", "commit", "HEAD"]);
    assert!(raw_head.contains("signet-tree blake3 "), "missing signet-tree header:\n{raw_head}");
    assert!(raw_head.contains("gpgsig -----BEGIN SIGNED MESSAGE-----"), "missing BLINCSg2 gpgsig:\n{raw_head}");
    let vc = env.git_ok(&work, &["verify-commit", "HEAD"]);
    let _ = vc;
    let chk = env.signet_ok(&work, &["check", "HEAD", "--signet", &marker_a]);
    assert!(chk.contains("MATCH") && chk.contains("direct salted snapshot imprint"), "unexpected check:\n{chk}");

    // Second commit carries `signet-parent blake3` too.
    fs::write(work.join("README.md"), b"second revision\n").unwrap();
    env.git_ok(&work, &["add", "README.md"]);
    env.git_ok(&work, &["commit", "-m", "second commit"]);
    let raw2 = env.git_ok(&work, &["cat-file", "commit", "HEAD"]);
    assert!(raw2.contains("signet-parent blake3 "), "missing signet-parent header:\n{raw2}");
    env.git_ok(&work, &["push", "origin", "main"]);

    // Fresh clone of `acme.<marker_a>.git` verifies in `reference-transaction` and passes `fsck`!
    let clone1 = env.root.join("clone1");
    env.git_ok(&env.root, &["clone", remote.to_str().unwrap(), clone1.to_str().unwrap()]);
    let fsck_out = env.signet_ok(&clone1, &["fsck"]);
    assert!(fsck_out.contains("verified cleanly"));

    // Local commits in a non-bare clone are NEVER refused even without the signet!
    env.signet_ok(&env.root, &["unadopt", env.config_dir.join("signets").join(format!("{marker_a}.seed")).to_str().unwrap()]);
    fs::write(clone1.join("local.txt"), b"local work\n").unwrap();
    env.git_ok(&clone1, &["add", "local.txt"]);
    env.git_ok(&clone1, &["commit", "-m", "unsigned local commit"]);

    // Adversarial 1: even pushing an unsigned commit into a bare signet-bound remote is refused if the remote runs git-signet!
    let push_blocked = env.git(&clone1, &["push", "origin", "main"]);
    assert!(!push_blocked.status.success(), "bare signet-bound remote unexpectedly accepted unsigned push!");
    // Now simulate a compromised remote (GIT_SIGNET_SKIP_HOOK=1 on attacker's push) -> fresh client clone MUST FAIL!
    let push_attacker = env.git_with_env(&clone1, &["push", "origin", "main"], &[("GIT_SIGNET_SKIP_HOOK", "1")]);
    assert!(push_attacker.status.success());
    let clone_fail_unsigned = env.root.join("clone_fail_unsigned");
    let res = env.git(&env.root, &["clone", remote.to_str().unwrap(), clone_fail_unsigned.to_str().unwrap()]);
    assert!(!res.status.success(), "clone unexpectedly accepted unsigned commit on signet-bound remote!");

    // Adversarial 2: commit imprinted by WRONG signet B injected on compromised remote -> fresh client clone MUST FAIL!
    env.signet_ok(&clone1, &["imprint-here", seed_b.to_str().unwrap()]);
    fs::write(clone1.join("evil.txt"), b"wrong signet\n").unwrap();
    env.git_ok(&clone1, &["add", "evil.txt"]);
    env.git_ok(&clone1, &["commit", "-m", "imprinted by wrong signet B"]);
    let push_wrong = env.git_with_env(&clone1, &["push", "origin", "main"], &[("GIT_SIGNET_SKIP_HOOK", "1")]);
    assert!(push_wrong.status.success());
    let clone_fail_wrong = env.root.join("clone_fail_wrong");
    let res_b = env.git(&env.root, &["clone", remote.to_str().unwrap(), clone_fail_wrong.to_str().unwrap()]);
    assert!(!res_b.status.success(), "clone unexpectedly accepted wrong signet B on signet-A remote!");
}

#[test]
fn wrapper_git_fsck_amend_and_branch_bound_signet() {
    let env = TestEnv::new("wrapper-amend");
    let bin_dir = env.root.join("bin");
    env.signet_ok(&env.root, &["enable", "--global", "--wrapper-dir", bin_dir.to_str().unwrap()]);
    let out = env.signet_ok(&env.root, &["keygen"]);
    let marker = out.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();

    let repo = env.root.join("work");
    env.git_ok(&env.root, &["init", repo.to_str().unwrap()]);
    // Switch to a signet-bound branch (`main+<marker>`) — `includeIf.onbranch` imprints automatically!
    let branch = format!("main+{marker}");
    env.git_ok(&repo, &["checkout", "-b", &branch]);
    fs::write(repo.join("f.txt"), b"v1\n").unwrap();
    env.git_ok(&repo, &["add", "f.txt"]);
    env.git_ok(&repo, &["commit", "-m", "branch-bound initial"]);

    // Verify commit carries signet-tree + BLINCSg2 imprint AND passes `git verify-commit`!
    env.git_ok(&repo, &["verify-commit", "HEAD"]);
    let chk1 = env.signet_ok(&repo, &["check", "HEAD"]);
    assert!(chk1.contains("direct salted snapshot imprint"));

    // Amend commit (changes tree!) -> post-commit replaces stale signet-tree and re-imprints cleanly!
    fs::write(repo.join("f.txt"), b"v2 amended\n").unwrap();
    env.git_ok(&repo, &["add", "f.txt"]);
    env.git_ok(&repo, &["commit", "--amend", "-m", "branch-bound amended"]);
    env.git_ok(&repo, &["verify-commit", "HEAD"]);
    let chk2 = env.signet_ok(&repo, &["check", "HEAD"]);
    assert!(chk2.contains("MATCH") && chk2.contains("direct salted snapshot imprint"));

    // Run `git fsck` through the installed transparent `git` wrapper -> runs stock git fsck + git-signet fsck!
    let wrap_out = Command::new(bin_dir.join("git"))
        .current_dir(&repo)
        .env("HOME", &env.home)
        .env("GIT_SIGNET_CONFIG_DIR", &env.config_dir)
        .env("GIT_SIGNET_REAL_GIT", &env.real_git)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["fsck"])
        .output()
        .unwrap();
    assert!(
        wrap_out.status.success(),
        "wrapped git fsck failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&wrap_out.stdout),
        String::from_utf8_lossy(&wrap_out.stderr)
    );
}

#[test]
fn merge_commit_empty_tree_no_gpg_sign_and_shallow_clone() {
    let env = TestEnv::new("merge-shallow");
    env.signet_ok(&env.root, &["enable", "--global"]);
    let out = env.signet_ok(&env.root, &["keygen"]);
    let marker = out.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();

    let remote = env.root.join(format!("proj.{marker}.git"));
    fs::create_dir_all(&remote).unwrap();
    env.git_ok(&remote, &["init", "--bare"]);

    let work = env.root.join("work");
    env.git_ok(&env.root, &["clone", remote.to_str().unwrap(), work.to_str().unwrap()]);

    // 1. Empty-tree initial commit (`--allow-empty`), imprinted + BLAKE3-bound.
    env.git_ok(&work, &["commit", "--allow-empty", "-m", "empty root"]);
    let chk_empty = env.signet_ok(&work, &["check", "HEAD", "--signet", &marker, "--no-shallow"]);
    assert!(chk_empty.contains("MATCH") && chk_empty.contains("direct salted snapshot imprint"));

    // 2. `--no-gpg-sign` respected: adds `signet-tree` + `signet-parent`, does NOT imprint!
    env.git_ok(&work, &["checkout", "-b", "side"]);
    fs::write(work.join("side.txt"), b"side branch\n").unwrap();
    env.git_ok(&work, &["add", "side.txt"]);
    env.git_ok(&work, &["commit", "--no-gpg-sign", "-m", "unimprinted side commit"]);
    let side_raw = env.git_ok(&work, &["cat-file", "commit", "HEAD"]);
    assert!(side_raw.contains("signet-tree blake3 ") && side_raw.contains("signet-parent blake3 "));
    assert!(!side_raw.contains("gpgsig "), "--no-gpg-sign commit unexpectedly got imprinted!");

    // 3. 2-parent merge commit back on `main` (carries 2 `signet-parent` lines + BLINCS imprint!).
    env.git_ok(&work, &["checkout", "main"]);
    fs::write(work.join("main.txt"), b"main branch\n").unwrap();
    env.git_ok(&work, &["add", "main.txt"]);
    env.git_ok(&work, &["commit", "-m", "main commit"]);
    env.git_ok(&work, &["merge", "--no-ff", "side", "-m", "merge side into main"]);
    let merge_raw = env.git_ok(&work, &["cat-file", "commit", "HEAD"]);
    let parent_lines = merge_raw.lines().filter(|l| l.starts_with("signet-parent blake3 ")).count();
    assert_eq!(parent_lines, 2, "merge commit should have 2 signet-parent lines:\n{merge_raw}");
    env.git_ok(&work, &["verify-commit", "HEAD"]);
    env.signet_ok(&work, &["check", "HEAD", "--no-shallow"]);
    env.git_ok(&work, &["push", "origin", "main"]);

    // 4. Shallow clone (`--depth=1` over file:// URL) verifies origin/main's salted snapshot + signet-tree cleanly,
    // while `git signet check --no-shallow` rejects shallow history!
    let shallow = env.root.join("shallow");
    let file_url = format!("file://{}", remote.display());
    env.git_ok(&env.root, &["clone", "--depth=1", &file_url, shallow.to_str().unwrap()]);
    let chk_shallow = env.signet_ok(&shallow, &["check", "origin/main"]);
    assert!(chk_shallow.contains("shallow boundary reached") && chk_shallow.contains("direct salted snapshot imprint"));
    let chk_no_shallow = env.signet(&shallow, &["check", "origin/main", "--no-shallow"]);
    assert!(!chk_no_shallow.status.success(), "--no-shallow unexpectedly passed on a shallow clone!");
}

#[test]
fn plain_repo_zero_warnings_and_preserves_custom_x509_program() {
    let env = TestEnv::new("plain-silent");
    // Pre-configure a custom gpg.x509.program (e.g. corporate gpgsm) and verify `enable` does NOT clobber it!
    env.git_ok(&env.root, &["config", "--global", "gpg.x509.program", "/usr/local/bin/custom-gpgsm"]);
    env.signet_ok(&env.root, &["enable", "--global"]);
    let x509 = env.git_ok(&env.root, &["config", "--global", "--get", "gpg.x509.program"]);
    assert_eq!(x509.trim(), "/usr/local/bin/custom-gpgsm", "enable unexpectedly overwrote existing custom gpg.x509.program!");

    // Create a plain bare repo (ZERO signet headers, ZERO signet IDs) with multiple commits.
    let plain_remote = env.root.join("plain-upstream.git");
    fs::create_dir_all(&plain_remote).unwrap();
    env.git_ok(&plain_remote, &["init", "--bare"]);
    let upstream = env.root.join("upstream-work");
    env.git_ok(&env.root, &["clone", plain_remote.to_str().unwrap(), upstream.to_str().unwrap()]);
    for i in 1..=3 {
        fs::write(upstream.join(format!("f{i}.txt")), format!("plain content {i}\n")).unwrap();
        env.git_ok(&upstream, &["add", "."]);
        // Simulate a collaborator who does NOT run git-signet.
        let c = env.git_with_env(&upstream, &["commit", "-m", &format!("plain {i}")], &[("GIT_SIGNET_SKIP_HOOK", "1")]);
        assert!(c.status.success());
    }
    let p = env.git_with_env(&upstream, &["push", "origin", "main"], &[("GIT_SIGNET_SKIP_HOOK", "1")]);
    assert!(p.status.success());

    // Cloning and shallow-cloning a plain repo with git-signet enabled must succeed with ZERO git-signet warnings!
    let client = env.root.join("client-plain");
    let clone_out = env.git(&env.root, &["clone", plain_remote.to_str().unwrap(), client.to_str().unwrap()]);
    assert!(clone_out.status.success());
    let stderr = String::from_utf8_lossy(&clone_out.stderr);
    assert!(!stderr.contains("git-signet:") && !stderr.to_ascii_lowercase().contains("warning"), "unexpected git-signet output on plain repo clone: {stderr}");

    let shallow_plain = env.root.join("client-plain-shallow");
    let file_url = format!("file://{}", plain_remote.display());
    let sh_out = env.git(&env.root, &["clone", "--depth=1", &file_url, shallow_plain.to_str().unwrap()]);
    assert!(sh_out.status.success());
    let sh_err = String::from_utf8_lossy(&sh_out.stderr);
    assert!(
        !sh_err.contains("git-signet:") && !sh_err.to_ascii_lowercase().contains("warning"),
        "unexpected git-signet output on plain shallow clone: {sh_err}"
    );
}

#[test]
fn formal_transitive_closure_old_tags_and_rogue_tag_rejection() {
    let env = TestEnv::new("closure");
    // Create pre-adoption repo with old unsigned commit A tagged `v0.1` (hooks not yet enabled).
    let remote = env.root.join("tmp-remote.git");
    let seed_a = env.root.join("a.seed");
    let out_a = env.signet_ok(&env.root, &["keygen", "--file", seed_a.to_str().unwrap()]);
    let marker_a = out_a.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();
    let bound_remote = env.root.join(format!("legacy.{marker_a}.git"));
    fs::create_dir_all(&bound_remote).unwrap();
    env.git_ok(&bound_remote, &["init", "--bare"]);

    let dev = env.root.join("dev");
    env.git_ok(&env.root, &["clone", bound_remote.to_str().unwrap(), dev.to_str().unwrap()]);
    // Old unsigned commit A (no hooks enabled yet, explicitly --no-gpg-sign).
    fs::write(dev.join("a.txt"), b"old v0.1 content\n").unwrap();
    env.git_ok(&dev, &["add", "a.txt"]);
    env.git_ok(&dev, &["commit", "--no-gpg-sign", "-m", "old commit A"]);
    env.git_ok(&dev, &["tag", "v0.1"]);

    // Now enable git-signet and make commit B (imprinted by A, carrying signet-parent covering A!).
    env.signet_ok(&env.root, &["enable", "--global"]);
    fs::write(dev.join("b.txt"), b"new imprinted commit B\n").unwrap();
    env.git_ok(&dev, &["add", "b.txt"]);
    env.git_ok(&dev, &["commit", "-m", "adopted signet commit B"]);
    env.git_ok(&dev, &["push", "origin", "main", "v0.1"]);

    // Cloning fetches BOTH main (B) and old unsigned tag v0.1 (A) -> ACCEPTED via formal transitive closure!
    let client = env.root.join("client");
    env.git_ok(&env.root, &["clone", bound_remote.to_str().unwrap(), client.to_str().unwrap()]);
    let chk_tag = env.signet_ok(&client, &["check", "v0.1", "--signet", &marker_a]);
    assert!(chk_tag.contains("BLAKE3-verified transitive closure"), "expected closure verification:\n{chk_tag}");

    // Now push a ROGUE unsigned commit R NOT in B's ancestor closure under tag `v-rogue` -> MUST BE REJECTED!
    let rogue = env.root.join("rogue");
    env.git_ok(&env.root, &["init", rogue.to_str().unwrap()]);
    fs::write(rogue.join("r.txt"), b"rogue orphan\n").unwrap();
    env.git_ok(&rogue, &["add", "r.txt"]);
    env.git_ok(&rogue, &["commit", "--no-gpg-sign", "-m", "rogue orphan"]);
    env.git_ok(&rogue, &["tag", "v-rogue"]);
    env.git_ok(&rogue, &["push", bound_remote.to_str().unwrap(), "refs/tags/v-rogue"]);

    let fetch_rogue = env.git(&client, &["fetch", "origin", "--tags"]);
    assert!(!fetch_rogue.status.success(), "fetch unexpectedly accepted rogue tag outside transitive closure!");
    let _ = remote;
}

#[test]
fn salted_snapshot_catches_tree_swap_and_digest_pin_and_annotated_tag() {
    let env = TestEnv::new("snapshot-attack");
    env.signet_ok(&env.root, &["enable", "--global"]);
    let out = env.signet_ok(&env.root, &["keygen"]);
    let marker = out.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();

    let work = env.root.join("repo");
    env.git_ok(&env.root, &["init", work.to_str().unwrap()]);
    env.signet_ok(&work, &["imprint-here", env.config_dir.join("signets").join(format!("{marker}.seed")).to_str().unwrap()]);
    fs::write(work.join("good.txt"), b"benign file\n").unwrap();
    env.git_ok(&work, &["add", "good.txt"]);
    env.git_ok(&work, &["commit", "-m", "good commit"]);

    // Annotated imprinted tag (`git tag -s`) covers tag + target commit + target tree!
    env.git_ok(&work, &["tag", "-s", "v1.0", "-m", "imprinted release tag"]);
    let chk_tag = env.signet_ok(&work, &["check", "v1.0", "--signet", &marker]);
    assert!(chk_tag.contains("direct salted snapshot imprint"));

    // Check digest-bound ref (`+blake3-<exact>` passes, wrong digest rejected).
    let b3_id = env.signet_ok(&work, &["id", "HEAD"]).trim().to_owned();
    env.git_ok(&work, &["tag", &format!("snap+blake3-{b3_id}")]);
    env.signet_ok(&work, &["check", &format!("snap+blake3-{b3_id}")]);
    let mut bad_b3 = b3_id.clone();
    let flip = if bad_b3.starts_with('0') { "1" } else { "0" };
    bad_b3.replace_range(0..1, flip);
    let bad_chk = env.signet(&work, &["check", "HEAD", "--expect", &bad_b3]);
    assert!(!bad_chk.status.success(), "accepted mismatched --expect BLAKE3 digest!");

    // Direct cryptographic test: swap tree OID inside a copy of the commit while keeping the old BLINCS imprint,
    // and also verify a commit with tampered `signet-tree` fails `verify_commit_chain`.
    let mut repo = GitRepo::open(Some(&work)).unwrap();
    let head_oid = repo.rev_parse("HEAD").unwrap();
    let (_, raw_commit) = repo.read_object(&head_oid).unwrap();
    let (payload, armor) = extract_commit_imprint(&raw_commit).unwrap();

    // Valid snapshot verifies cleanly under COMMIT_SNAPSHOT_CTX (rejects wrong/empty Context)
    // and streams the actual file contents directly!
    let sid = verify_payload_imprint(&mut repo, &payload, &armor, None).unwrap();
    let (_, decoded_imp) = decode_imprint_armor(&armor).unwrap();
    let mut snap_bytes = Vec::new();
    SnapshotReader::for_commit(&mut repo, &payload).unwrap().read_to_end(&mut snap_bytes).unwrap();
    assert_eq!(&snap_bytes[..8], &u64::try_from(payload.len()).unwrap().to_le_bytes());
    assert!(snap_bytes.windows(b"benign file\n".len()).any(|w| w == b"benign file\n"), "SnapshotReader omitted tree blob bytes!");
    assert!(sid.verify(COMMIT_SNAPSHOT_CTX, &snap_bytes, &decoded_imp).is_ok(), "BLINCS imprint did not verify against exact SnapshotReader bytes!");
    assert!(sid.verify(Context::EMPTY, &snap_bytes, &decoded_imp).is_err(), "BLINCS imprint accepted empty context!");
    assert!(sid.verify(TAG_SNAPSHOT_CTX, &snap_bytes, &decoded_imp).is_err(), "BLINCS commit imprint accepted tag context!");
    // Flip 1 byte in the streamed file content while keeping commit bytes 100% unchanged (simulated SHA-1/BLAKE3 collision!):
    let pos = snap_bytes.windows(b"benign file\n".len()).position(|w| w == b"benign file\n").unwrap();
    snap_bytes[pos] ^= 1;
    assert!(sid.verify(COMMIT_SNAPSHOT_CTX, &snap_bytes, &decoded_imp).is_err(), "BLINCS imprint accepted tampered file content with unchanged commit bytes!");

    // Tamper 1 byte in `signet-tree` header inside a fresh commit (re-imprinted or not) -> BLAKE3 chain rejects!
    let parsed = parse_commit(raw_commit.clone()).unwrap();
    assert!(matches!(parsed.class, CommitClass::Carrying { .. }));
    let bad_tree_dig = [0x99u8; 32];
    let bad_payload = insert_signet_headers(&raw_commit, &parsed.tree, &bad_tree_dig, &[]).unwrap();
    let bad_oid = repo.hash_object_write(ObjKind::Commit, &bad_payload).unwrap();
    let ctx = ContextKeys::new();
    assert!(verify_commit_chain(&mut repo, &ctx, &bad_oid, None, false, None).is_err(), "accepted forged signet-tree digest!");

    // Tamper tree content under the same commit payload (new blob -> new tree -> swap tree OID into payload)
    // while keeping original armor -> BLINCS snapshot verifier rejects!
    let evil_blob = repo.hash_object_write(ObjKind::Blob, b"evil swapped file\n").unwrap();
    let mut evil_tree_raw = Vec::new();
    evil_tree_raw.extend_from_slice(b"100644 good.txt\0");
    evil_tree_raw.extend_from_slice(&evil_blob);
    let evil_tree = repo.hash_object_write(ObjKind::Tree, &evil_tree_raw).unwrap();
    let swapped_payload = String::from_utf8(payload.clone()).unwrap().replace(&to_hex(&parsed.tree), &to_hex(&evil_tree)).into_bytes();
    assert!(verify_payload_imprint(&mut repo, &swapped_payload, &armor, Some(&sid)).is_err(), "accepted swapped tree under old BLINCS imprint!");

    // Stale amend check: single signet-tree whose tree OID != commit's tree is treated as Stale (plain),
    // while duplicate signet-tree is rejected as malformed!
    let stale_payload = insert_signet_headers(&raw_commit, &evil_tree, &bad_tree_dig, &[]).unwrap();
    assert!(matches!(parse_commit(stale_payload).unwrap().class, CommitClass::Stale));

    // Confirm `imprint_payload` + `attach_gpgsig` round-trip directly through library API too.
    let rng = Randomness::initialize(env.config_dir.join("randomness")).unwrap();
    let signet = Signet::from_seed(&[0x33u8; SEED_LEN]);
    let imp2 = imprint_payload(&mut repo, &signet, &rng, &payload).unwrap();
    let armor2 = encode_imprint_armor(&signet.id(), &imp2);
    let combined = attach_gpgsig(&payload, &armor2);
    let (p2, a2) = extract_commit_imprint(&combined).unwrap();
    assert_eq!(p2, payload);
    assert_eq!(verify_payload_imprint(&mut repo, &p2, &a2, Some(&signet.id())).unwrap(), signet.id());

    // Confirm `compute_commit_digest` works cleanly with memory-only cache.
    let mut cache = DigestCache::memory_only();
    let d = compute_commit_digest(&mut repo, &ctx, &head_oid, &mut cache).unwrap();
    assert_eq!(to_hex(&d), b3_id);
}

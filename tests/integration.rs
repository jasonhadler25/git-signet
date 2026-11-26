include!("../tools/require_nextest.rs");

use git_signet::blake3_chain::{
    CTX_COMMIT, CTX_DIR, CTX_FILE, CTX_PLAIN, CommitClass, ContextKeys, DigestCache, attach_gpgsig, compute_commit_digest, compute_tree_digest,
    hash_blob_streaming, insert_signet_headers, parse_commit, verify_commit_chain,
};
use git_signet::git::{GitRepo, ObjKind, parse_git_tree, resolve_real_git, sanitize_for_tty};
use git_signet::hooks::{
    RefTarget, RefUpdate, add_blake3_headers_to_commit, check_revision, governing_signet, load_signet_from_path, load_signet_from_spec, open_randomness,
    parse_reference_transaction_records, randomness_state_path, verify_ref_batch,
};
use git_signet::id::{
    base64_decode, base64_encode, decode_imprint_armor, decode_lower_hex, decode_signet_b32, encode_imprint_armor, encode_signet_b32,
    extract_blake3_pin_from_refname, extract_signet_from_refname, extract_signet_from_remote_url, format_signet_marker, parse_signet_marker, to_hex,
};
use git_signet::snapshot::{
    COMMIT_SNAPSHOT_CTX, ExtractedArmor, TAG_SNAPSHOT_CTX, extract_commit_imprint, extract_tag_imprint, imprint_payload, verify_payload_imprint,
    write_payload_snapshot,
};
use signet::{Context, Randomness, SEED_LEN, Signet, SignetId};
use std::fs;
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
    let rng_file = tmp.join("salt");
    Randomness::create(&rng_file).unwrap();
    let rng = Randomness::initialize(&rng_file).unwrap();
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
fn git_fsck_amend_and_branch_bound_signet() {
    let env = TestEnv::new("fsck-amend");
    env.signet_ok(&env.root, &["enable", "--global"]);
    let out = env.signet_ok(&env.root, &["keygen"]);
    let marker = out.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();

    let repo = env.root.join("work");
    env.git_ok(&env.root, &["init", repo.to_str().unwrap()]);
    let branch = format!("main+{marker}");
    env.git_ok(&repo, &["checkout", "-b", &branch]);
    fs::write(repo.join("f.txt"), b"v1\n").unwrap();
    env.git_ok(&repo, &["add", "f.txt"]);
    env.git_ok(&repo, &["commit", "-m", "branch-bound initial"]);

    env.git_ok(&repo, &["verify-commit", "HEAD"]);
    let chk1 = env.signet_ok(&repo, &["check", "HEAD"]);
    assert!(chk1.contains("direct salted snapshot imprint"));

    fs::write(repo.join("f.txt"), b"v2 amended\n").unwrap();
    env.git_ok(&repo, &["add", "f.txt"]);
    env.git_ok(&repo, &["commit", "--amend", "-m", "branch-bound amended"]);
    env.git_ok(&repo, &["verify-commit", "HEAD"]);
    let chk2 = env.signet_ok(&repo, &["check", "HEAD"]);
    assert!(chk2.contains("MATCH") && chk2.contains("direct salted snapshot imprint"));

    env.git_ok(&repo, &["fsck"]);
    let fsck_out = env.signet_ok(&repo, &["fsck"]);
    assert!(fsck_out.contains("verified cleanly"));
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
    // Now push a ROGUE unsigned commit R NOT in B's ancestor closure under tag `v-rogue`:
    // 1. Server-side bare-repo enforcement rejects the rogue push directly!
    let rogue_push_blocked = env.git(&rogue, &["push", bound_remote.to_str().unwrap(), "refs/tags/v-rogue"]);
    assert!(!rogue_push_blocked.status.success(), "bare signet-bound remote unexpectedly accepted rogue tag push!");
    // 2. Simulate a compromised remote (GIT_SIGNET_SKIP_HOOK=1) -> client `git fetch` MUST ALSO REJECT!
    let rogue_push_compromised = env.git_with_env(&rogue, &["push", bound_remote.to_str().unwrap(), "refs/tags/v-rogue"], &[("GIT_SIGNET_SKIP_HOOK", "1")]);
    assert!(rogue_push_compromised.status.success());

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
    assert!(chk_tag.contains("direct salted annotated-tag imprint"));

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
    let ExtractedArmor::Present { payload, armor } = extract_commit_imprint(&raw_commit) else {
        panic!("expected commit imprint");
    };

    // Valid snapshot verifies cleanly under COMMIT_SNAPSHOT_CTX (rejects wrong/empty Context)
    // and streams the actual file contents directly!
    let sid = verify_payload_imprint(&mut repo, ObjKind::Commit, &payload, &armor, None).unwrap();
    let (_, decoded_imp) = decode_imprint_armor(&armor).unwrap();
    let mut snap_bytes = Vec::new();
    write_payload_snapshot(&mut repo, ObjKind::Commit, &payload, &mut snap_bytes).unwrap();
    assert_eq!(&snap_bytes[..8], &u64::try_from(payload.len()).unwrap().to_le_bytes());
    assert!(snap_bytes.windows(b"benign file\n".len()).any(|w| w == b"benign file\n"), "snapshot omitted tree blob bytes!");
    assert!(sid.verify(COMMIT_SNAPSHOT_CTX, &snap_bytes, &decoded_imp).is_ok(), "BLINCS imprint did not verify against exact snapshot bytes!");
    assert!(sid.verify(Context::EMPTY, &snap_bytes, &decoded_imp).is_err(), "BLINCS imprint accepted empty context!");
    assert!(sid.verify(TAG_SNAPSHOT_CTX, &snap_bytes, &decoded_imp).is_err(), "BLINCS commit imprint accepted tag context!");
    let pos = snap_bytes.windows(b"benign file\n".len()).position(|w| w == b"benign file\n").unwrap();
    snap_bytes[pos] ^= 1;
    assert!(sid.verify(COMMIT_SNAPSHOT_CTX, &snap_bytes, &decoded_imp).is_err(), "BLINCS imprint accepted tampered file content with unchanged commit bytes!");

    let parsed = parse_commit(raw_commit.clone()).unwrap();
    assert!(matches!(parsed.class, CommitClass::Carrying { .. }));
    let bad_tree_dig = [0x99u8; 32];
    let bad_payload = insert_signet_headers(&raw_commit, &parsed.tree, &bad_tree_dig, &[]).unwrap();
    let bad_oid = repo.hash_object_write(ObjKind::Commit, &bad_payload).unwrap();
    let ctx = ContextKeys::new();
    assert!(verify_commit_chain(&mut repo, &ctx, &bad_oid, None, false, false).is_err(), "accepted forged signet-tree digest!");

    // Tamper tree content under the same commit payload (new blob -> new tree -> swap tree OID into payload)
    // while keeping original armor -> BLINCS snapshot verifier rejects!
    let evil_blob = repo.hash_object_write(ObjKind::Blob, b"evil swapped file\n").unwrap();
    let mut evil_tree_raw = Vec::new();
    evil_tree_raw.extend_from_slice(b"100644 good.txt\0");
    evil_tree_raw.extend_from_slice(&evil_blob);
    let evil_tree = repo.hash_object_write(ObjKind::Tree, &evil_tree_raw).unwrap();
    let swapped_payload = String::from_utf8(payload.clone()).unwrap().replace(&to_hex(&parsed.tree), &to_hex(&evil_tree)).into_bytes();
    assert!(
        verify_payload_imprint(&mut repo, ObjKind::Commit, &swapped_payload, &armor, Some(&sid)).is_err(),
        "accepted swapped tree under old BLINCS imprint!"
    );

    // Stale amend check: single signet-tree whose tree OID != commit's tree is treated as Stale (plain),
    // while duplicate signet-tree is rejected as malformed!
    let stale_payload = insert_signet_headers(&raw_commit, &evil_tree, &bad_tree_dig, &[]).unwrap();
    assert!(matches!(parse_commit(stale_payload).unwrap().class, CommitClass::Stale));

    // Confirm `imprint_payload` + `attach_gpgsig` round-trip directly through library API too.
    let rng = Randomness::initialize(env.config_dir.join("salt")).unwrap();
    let signet = Signet::from_seed(&[0x33u8; SEED_LEN]);
    let imp2 = imprint_payload(&mut repo, ObjKind::Commit, &signet, &rng, &payload).unwrap();
    let armor2 = encode_imprint_armor(&signet.id(), &imp2);
    let combined = attach_gpgsig(&payload, &armor2);
    let ExtractedArmor::Present { payload: p2, armor: a2 } = extract_commit_imprint(&combined) else {
        panic!("expected combined commit imprint");
    };
    assert_eq!(p2, payload);
    assert_eq!(verify_payload_imprint(&mut repo, ObjKind::Commit, &p2, &a2, Some(&signet.id())).unwrap(), signet.id());
    assert!(verify_payload_imprint(&mut repo, ObjKind::Commit, &p2, &a2, Some(&SignetId::from_bytes(&[0x99u8; 32]))).is_err());

    // Confirm `compute_commit_digest` works cleanly with memory-only cache.
    let mut cache = DigestCache::memory_only();
    let d = compute_commit_digest(&mut repo, &ctx, &head_oid, &mut cache).unwrap();
    assert_eq!(to_hex(&d), b3_id);
}

#[test]
fn codec_cache_and_blake3_kats() {
    // 1. Base64 strict round-trip across 0, 1, 2, 3 byte remainders + non-canonical padding rejection.
    for sample in [b"".as_slice(), b"a", b"ab", b"abc", b"abcd", &[0x00, 0xff, 0x55, 0xaa, 0x12]] {
        let enc = base64_encode(sample);
        if sample.is_empty() {
            assert_eq!(enc, "");
            assert!(base64_decode("").is_err());
        } else {
            assert_eq!(base64_decode(&enc).unwrap(), sample);
        }
    }
    assert!(base64_decode("AAA").is_err()); // non-multiple of 4
    assert!(base64_decode("AA==AA==").is_err()); // padding before end
    assert!(base64_decode("AB==").is_err()); // pad==2 non-zero trailing bits (v1 = 1)
    assert!(base64_decode("AAB=").is_err()); // pad==1 non-zero trailing bits (v2 = 1)
    assert!(base64_decode("AA$=").is_err()); // invalid char

    // 2. Armor structural rejections (<3 lines, wrong begin/end, blank line, non-UTF-8).
    assert!(decode_imprint_armor(b"-----BEGIN SIGNED MESSAGE-----\n-----END SIGNED MESSAGE-----\n").is_err());
    assert!(decode_imprint_armor(b"-----BEGIN SIGNED MESSAGE-----\nAAAA\n\n-----END SIGNED MESSAGE-----\n").is_err());
    assert!(decode_imprint_armor(b"-----BEGIN SIGNED MESSAGE-----\n\xff\xff\xff\xff\n-----END SIGNED MESSAGE-----\n").is_err());
    assert!(decode_imprint_armor(b"-----BEGIN SIGNED MESSAGE-----\nAAAA\n-----END WRONG-----\n").is_err());

    // 3. Refname & remote URL edge cases (walk operators, duplicate vs conflicting pins/IDs).
    let id1 = SignetId::from_bytes(&[0x11u8; 32]);
    let id2 = SignetId::from_bytes(&[0x22u8; 32]);
    let m1 = format_signet_marker(&id1);
    let m2 = format_signet_marker(&id2);
    assert_eq!(extract_signet_from_refname(&format!("refs/heads/{m1}.{m1}")).unwrap(), Some(id1));
    assert!(extract_signet_from_refname(&format!("refs/heads/{m1}.{m2}")).is_err());
    assert!(extract_signet_from_refname(&format!("main+{m1}^2")).is_err());
    assert_eq!(extract_signet_from_remote_url(&format!("https://host/org/r.{m1}.git?x=1#frag")).unwrap(), Some(id1));
    assert_eq!(extract_signet_from_remote_url("   ").unwrap(), None);

    let d1 = [0x11u8; 32];
    let d2 = [0x22u8; 32];
    let h1 = to_hex(&d1);
    let h2 = to_hex(&d2);
    assert_eq!(extract_blake3_pin_from_refname(&format!("refs/tags/v1+blake3-{h1}.blake3-{h1}")).unwrap(), Some(d1));
    assert!(extract_blake3_pin_from_refname(&format!("refs/tags/v1+blake3-{h1}+blake3-{h2}")).is_err());
    assert!(extract_blake3_pin_from_refname(&format!("refs/tags/v1+blake3-{}", "a".repeat(45))).is_err());
    assert!(extract_blake3_pin_from_refname(&format!("v1+blake3-{h1}~1")).is_err());
    assert!(extract_blake3_pin_from_refname(&format!("v1+blake3-{h1}^1")).is_err());
    assert!(extract_blake3_pin_from_refname(&format!("v1+blake3-{h1}..HEAD")).is_err());

    // 4. Independent BLAKE3 DeriveKey KATs on ContextKeys (catches zeroed/wrong hashers!).
    let ctx = ContextKeys::new();
    let msg = b"git-signet KAT payload 0123456789";
    let expected = |context: &str| *blake3_servil_core::convenience::hash_with(blake3_servil_core::Mode::DeriveKey(context), msg).as_bytes();
    assert_eq!(ctx.hash_file(msg), expected(CTX_FILE));
    assert_eq!(ctx.hash_dir(msg), expected(CTX_DIR));
    assert_eq!(ctx.hash_carrying_commit(msg), expected(CTX_COMMIT));
    assert_eq!(ctx.hash_plain_commit(msg), expected(CTX_PLAIN));
    assert_ne!(ctx.hash_file(msg), [0u8; 32]);
    assert_ne!(ctx.hash_file(msg), ctx.hash_dir(msg));
    assert_ne!(ctx.hash_carrying_commit(msg), ctx.hash_plain_commit(msg));

    // 5. Memory-only DigestCache starts empty (put_* methods are private to blake3_chain).
    let cache = DigestCache::memory_only();
    assert_eq!(cache.get_blob(&[1u8; 20]), None);
    assert_eq!(cache.get_tree(&[2u8; 20]), None);
    assert_eq!(cache.get_commit(&[3u8; 20]), None);

    // 6. sanitize_for_tty (including bidi override chars) and parse_git_tree edge cases.
    assert_eq!(sanitize_for_tty("refs/heads/\x1b[31mmain\x00\n\u{202E}x"), "refs/heads/?[31mmain???x");
    let mut raw_tree = Vec::new();
    raw_tree.extend_from_slice(b"100755 run.sh\0");
    raw_tree.extend_from_slice(&[0xaa; 20]);
    raw_tree.extend_from_slice(b"160000 sub\0");
    raw_tree.extend_from_slice(&[0xbb; 20]);
    raw_tree.extend_from_slice(b"40000 dir\0");
    raw_tree.extend_from_slice(&[0xcc; 20]);
    let entries = parse_git_tree(&raw_tree).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(!entries[0].is_dir && !entries[0].is_gitlink);
    assert!(entries[1].is_gitlink && !entries[1].is_dir);
    assert!(entries[2].is_dir && !entries[2].is_gitlink);
    assert!(parse_git_tree(b"100644 truncated\0short").is_err());
    assert!(parse_git_tree(b"badentry").is_err());
}

#[test]
fn cli_subcommands_disable_and_missing_policy() {
    let env = TestEnv::new("cli-extra");

    assert!(!env.signet(&env.root, &["enable", "--global", "--local"]).status.success());
    assert!(!env.signet(&env.root, &["check", "--unknown-flag"]).status.success());
    env.signet_ok(&env.root, &["enable", "--global"]);

    let seed_path = env.root.join("k.seed");
    let out = env.signet_ok(&env.root, &["keygen", "--file", seed_path.to_str().unwrap()]);
    let marker = out.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();
    let fmt_id = env.signet_ok(&env.root, &["format-id", seed_path.to_str().unwrap()]);
    assert_eq!(fmt_id.trim(), marker);
    let bad_seed = env.root.join("old.seed");
    let mut old_raw = [0u8; 40];
    old_raw[..8].copy_from_slice(b"BLINCSs1");
    fs::write(&bad_seed, old_raw).unwrap();
    assert!(load_signet_from_path(&bad_seed).is_err());
    assert!(load_signet_from_spec(&format_signet_marker(&SignetId::from_bytes(&[0x99; 32]))).is_err());
    assert!(randomness_state_path().is_ok());

    let work = env.root.join("work");
    env.git_ok(&env.root, &["init", work.to_str().unwrap()]);
    fs::write(work.join("a.txt"), b"hello\n").unwrap();
    env.git_ok(&work, &["add", "a.txt"]);
    env.git_ok(&work, &["commit", "-m", "c1"]);
    let id_default = env.signet_ok(&work, &["id"]).trim().to_owned();
    let id_head = env.signet_ok(&work, &["id", "HEAD"]).trim().to_owned();
    assert_eq!(id_default, id_head);

    let mut repo = GitRepo::open(Some(&work)).unwrap();
    let ctx = ContextKeys::new();
    let mut cache = DigestCache::memory_only();
    let head_oid = repo.rev_parse("HEAD").unwrap();
    let (_, raw_c) = repo.read_object(&head_oid).unwrap();
    let parsed = parse_commit(raw_c).unwrap();
    let tree_dig = compute_tree_digest(&mut repo, &ctx, &parsed.tree, &mut cache).unwrap();
    assert_ne!(tree_dig, [0u8; 32]);
    let (_, tree_raw) = repo.read_object(&parsed.tree).unwrap();
    let blob_oid = parse_git_tree(&tree_raw).unwrap()[0].oid;
    assert_eq!(hash_blob_streaming(&mut repo, &ctx, &blob_oid, &mut cache).unwrap(), ctx.hash_file(b"hello\n"));
    assert_eq!(cache.get_blob(&blob_oid), Some(ctx.hash_file(b"hello\n")));
    assert_eq!(cache.get_tree(&parsed.tree), Some((tree_dig, 1)));

    env.git_ok(&work, &["fsck"]);
    env.signet_ok(&work, &["fsck"]);

    let plain_remote = env.root.join("plain-missing.git");
    fs::create_dir_all(&plain_remote).unwrap();
    env.git_ok(&plain_remote, &["init", "--bare"]);
    let up = env.root.join("up");
    env.git_ok(&env.root, &["clone", plain_remote.to_str().unwrap(), up.to_str().unwrap()]);
    fs::write(up.join("p.txt"), b"plain\n").unwrap();
    env.git_ok(&up, &["add", "p.txt"]);
    assert!(env.git_with_env(&up, &["commit", "-m", "plain"], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());
    assert!(env.git_with_env(&up, &["push", "origin", "main"], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());

    let strict_client = env.root.join("strict-client");
    env.git_ok(&env.root, &["init", strict_client.to_str().unwrap()]);
    env.git_ok(&strict_client, &["remote", "add", "origin", plain_remote.to_str().unwrap()]);
    env.git_ok(&strict_client, &["config", "--local", "signet.missing", "error"]);
    assert!(!env.git(&strict_client, &["fetch", "origin"]).status.success(), "signet.missing=error accepted plain commit!");
    env.git_ok(&strict_client, &["config", "--local", "signet.missing", "warn"]);
    let warn_fetch = env.git(&strict_client, &["fetch", "origin"]);
    assert!(warn_fetch.status.success());
    assert!(String::from_utf8_lossy(&warn_fetch.stderr).contains("warning"));

    env.signet_ok(&env.root, &["disable", "--global"]);
}

#[test]
fn adversarial_headers_conflicts_and_gitlink_snapshot() {
    let env = TestEnv::new("adv-headers");
    env.signet_ok(&env.root, &["enable", "--global"]);
    let out_a = env.signet_ok(&env.root, &["keygen"]);
    let marker_a = out_a.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();
    let id_b = SignetId::from_bytes(&[0x77u8; 32]);
    let marker_b = format_signet_marker(&id_b);

    // 1. Conflicting signet IDs between remote URL (A) and remote-tracking refname (B) rejected by governing_signet!
    let repo_dir = env.root.join("conflict-repo");
    env.git_ok(&env.root, &["init", repo_dir.to_str().unwrap()]);
    env.git_ok(&repo_dir, &["remote", "add", "origin", &format!("https://example.invalid/org/p.{marker_a}.git")]);
    let repo = GitRepo::open(Some(&repo_dir)).unwrap();
    assert!(governing_signet(&repo, &format!("refs/remotes/origin/main+{marker_b}"), None).is_err());
    assert_eq!(governing_signet(&repo, &format!("refs/remotes/origin/main+{marker_a}"), None).unwrap(), Some(parse_signet_marker(&marker_a).unwrap()));

    // 2. Malformed signet headers rejected by parse_commit (`signet-parent` without `signet-tree`, duplicate `signet-tree`, wrong parent count).
    let base_commit = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n";
    let hex64 = "0".repeat(64);
    let parent_only = format!("{}signet-parent blake3 {hex64}\n\nmsg\n", std::str::from_utf8(base_commit).unwrap());
    assert!(parse_commit(parent_only.into_bytes()).is_err());
    let dup_tree = format!(
        "{}signet-tree blake3 4b825dc642cb6eb9a060e54bf8d69288fbee4904 {hex64}\nsignet-tree blake3 4b825dc642cb6eb9a060e54bf8d69288fbee4904 {hex64}\n\nmsg\n",
        std::str::from_utf8(base_commit).unwrap()
    );
    assert!(parse_commit(dup_tree.into_bytes()).is_err());
    let wrong_parent_cnt = format!(
        "{}signet-tree blake3 4b825dc642cb6eb9a060e54bf8d69288fbee4904 {hex64}\nsignet-parent blake3 {hex64}\n\nmsg\n",
        std::str::from_utf8(base_commit).unwrap()
    );
    assert!(parse_commit(wrong_parent_cnt.into_bytes()).is_err());

    // 3. Duplicate gpgsig header & duplicate tag imprint block rejected as Malformed.
    let dup_gpgsig = format!(
        "{}gpgsig -----BEGIN SIGNED MESSAGE-----\n AAAA\ngpgsig -----BEGIN SIGNED MESSAGE-----\n BBBB\n\nmsg\n",
        std::str::from_utf8(base_commit).unwrap()
    );
    assert!(matches!(extract_commit_imprint(dup_gpgsig.as_bytes()), ExtractedArmor::Malformed(_)));
    let dup_tag = b"object 0000000000000000000000000000000000000000\ntype commit\ntag v1\ntagger A <a@b> 1 +0000\n\nhi\n-----BEGIN SIGNED MESSAGE-----\nA\n-----END SIGNED MESSAGE-----\n-----BEGIN SIGNED MESSAGE-----\nB\n-----END SIGNED MESSAGE-----\n";
    assert!(matches!(extract_tag_imprint(dup_tag), ExtractedArmor::Malformed(_)));

    // 4. Tree containing a gitlink (`160000`) hashes cleanly in BOTH compute_tree_digest and write_payload_snapshot!
    let mut repo = GitRepo::open(Some(&repo_dir)).unwrap();
    let blob_oid = repo.hash_object_write(ObjKind::Blob, b"with-gitlink\n").unwrap();
    let gitlink_oid = [0x42u8; 20];
    let mut tree_raw = Vec::new();
    tree_raw.extend_from_slice(b"100644 file.txt\0");
    tree_raw.extend_from_slice(&blob_oid);
    tree_raw.extend_from_slice(b"160000 submod\0");
    tree_raw.extend_from_slice(&gitlink_oid);
    let tree_oid = repo.hash_object_write(ObjKind::Tree, &tree_raw).unwrap();
    let commit_payload = format!("tree {}\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\ngitlink commit\n", to_hex(&tree_oid));
    let mut snap = Vec::new();
    write_payload_snapshot(&mut repo, ObjKind::Commit, commit_payload.as_bytes(), &mut snap).unwrap();
    assert!(snap.windows(b"G160000 submod\0".len()).any(|w| w == b"G160000 submod\0"));
    let ctx = ContextKeys::new();
    let mut cache = DigestCache::memory_only();
    let td = compute_tree_digest(&mut repo, &ctx, &tree_oid, &mut cache).unwrap();
    assert_ne!(td, [0u8; 32]);
}

#[test]
fn astra_security_regressions_c1_c2_h1_h3_h4_h5_m2_m3() {
    let env = TestEnv::new("astra-sec");
    env.signet_ok(&env.root, &["enable", "--global"]);
    let out_a = env.signet_ok(&env.root, &["keygen"]);
    let marker_a = out_a.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();
    let sid_a = parse_signet_marker(&marker_a).unwrap();
    let seed_a_path = env.config_dir.join("signets").join(format!("{marker_a}.seed"));
    let signet_a = load_signet_from_path(&seed_a_path).unwrap();

    // C2: Byte-exact reference-transaction parsing preserves Unicode whitespace inside refnames
    // and fails closed on malformed lines or bad hex OIDs.
    let zero_hex = "0".repeat(40);
    let one_hex = "1".repeat(40);
    let nbsp_ref = "refs/heads/feat\u{00A0}nbsp";
    let raw_tx = format!("{zero_hex} {one_hex} {nbsp_ref}\n");
    let recs = parse_reference_transaction_records(raw_tx.as_bytes()).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].refname, nbsp_ref);
    assert!(parse_reference_transaction_records(b"only-two fields\n").is_err());
    assert!(parse_reference_transaction_records(format!("not-hex {one_hex} refs/heads/a\n").as_bytes()).is_err());
    assert!(parse_reference_transaction_records(format!("{zero_hex} not-hex refs/heads/a\n").as_bytes()).is_err());

    // C1: An unverified / forged BLINCSg2 armor claiming sid_a MUST NOT cause add_blake3_headers_to_commit
    // to sign with local signet A, even when user.signingkey IS configured!
    let repo_dir = env.root.join("c1-repo");
    env.git_ok(&env.root, &["init", repo_dir.to_str().unwrap()]);
    env.signet_ok(&repo_dir, &["imprint-here", seed_a_path.to_str().unwrap()]);
    fs::write(repo_dir.join("x.txt"), b"x\n").unwrap();
    env.git_ok(&repo_dir, &["add", "x.txt"]);
    env.git_ok(&repo_dir, &["commit", "-m", "legit"]);
    // H5: stock `git log -1 --format=%G?` reports `U` (TRUST_UNDEFINED), NOT `G` (TRUST_FULLY), while verify-commit exits 0!
    env.git_ok(&repo_dir, &["verify-commit", "HEAD"]);
    let g_status = env.git_ok(&repo_dir, &["log", "-1", "--format=%G?"]);
    assert_eq!(g_status.trim(), "U", "x509 verifier falsely claimed TRUST_FULLY instead of TRUST_UNDEFINED");

    let mut repo = GitRepo::open(Some(&repo_dir)).unwrap();
    let legit_oid = repo.rev_parse("HEAD").unwrap();
    let (_, legit_raw) = repo.read_object(&legit_oid).unwrap();
    let tree_oid = parse_commit(legit_raw).unwrap().tree;
    let fake_imp = signet::Imprint::from_bytes(&[0x42u8; signet::IMPRINT_LEN]);
    let forged_armor = encode_imprint_armor(&sid_a, &fake_imp);
    let plain_payload = format!("tree {}\nauthor Evil <e@e> 1 +0000\ncommitter Evil <e@e> 1 +0000\n\nforged claim\n", to_hex(&tree_oid));
    let forged_commit = attach_gpgsig(plain_payload.as_bytes(), &forged_armor);
    let forged_oid = repo.hash_object_write(ObjKind::Commit, &forged_commit).unwrap();
    assert!(add_blake3_headers_to_commit(&mut repo, &forged_oid).is_err(), "C1 regression: hook re-imprinted commit with unverified/forged BLINCS armor!");

    // C1 (second half): Even a VALID plain commit imprinted by signet A MUST NOT be re-imprinted
    // in a repository where user.signingkey is NOT configured (no fallback to global signets dir)!
    let other_dir = env.root.join("c1-unconfigured");
    env.git_ok(&env.root, &["init", other_dir.to_str().unwrap()]);
    fs::write(other_dir.join("y.txt"), b"y\n").unwrap();
    env.git_ok(&other_dir, &["add", "y.txt"]);
    assert!(env.git_with_env(&other_dir, &["commit", "-m", "plain"], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());
    let mut repo2 = GitRepo::open(Some(&other_dir)).unwrap();
    let p_oid = repo2.rev_parse("HEAD").unwrap();
    let (_, p_raw) = repo2.read_object(&p_oid).unwrap();
    let rng = Randomness::initialize(env.config_dir.join("salt")).unwrap();
    let valid_imp_on_plain = imprint_payload(&mut repo2, ObjKind::Commit, &signet_a, &rng, &p_raw).unwrap();
    let valid_plain_commit = attach_gpgsig(&p_raw, &encode_imprint_armor(&sid_a, &valid_imp_on_plain));
    let vp_oid = repo2.hash_object_write(ObjKind::Commit, &valid_plain_commit).unwrap();
    assert!(add_blake3_headers_to_commit(&mut repo2, &vp_oid).is_err(), "C1 regression: fell back to global signets/ without active user.signingkey!");

    // H1: A directly imprinted ANNOTATED TAG over an unimprinted plain commit authorizes THAT tag,
    // NEVER seeding transitive-closure delegation for another ref pointing to an ancestor commit!
    let bare_a = env.root.join(format!("bare.{marker_a}.git"));
    fs::create_dir_all(&bare_a).unwrap();
    env.git_ok(&bare_a, &["init", "--bare"]);
    // H3: bare repository named `bare.<marker_a>.git` with ZERO remotes governs its refs!
    let bare_repo_ro = GitRepo::open(Some(&bare_a)).unwrap();
    assert_eq!(governing_signet(&bare_repo_ro, "refs/heads/main", None).unwrap(), Some(sid_a));

    let tag_work = env.root.join("h1-work");
    env.git_ok(&env.root, &["init", tag_work.to_str().unwrap()]);
    fs::write(tag_work.join("a.txt"), b"a\n").unwrap();
    env.git_ok(&tag_work, &["add", "a.txt"]);
    assert!(env.git_with_env(&tag_work, &["commit", "-m", "anc"], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());
    let anc_oid_hex = env.git_ok(&tag_work, &["rev-parse", "HEAD"]).trim().to_owned();
    fs::write(tag_work.join("b.txt"), b"b\n").unwrap();
    env.git_ok(&tag_work, &["add", "b.txt"]);
    assert!(env.git_with_env(&tag_work, &["commit", "-m", "child"], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());
    env.signet_ok(&tag_work, &["imprint-here", seed_a_path.to_str().unwrap()]);
    env.git_ok(&tag_work, &["tag", "-s", "v-tag-only", "-m", "tag imprint"]);
    let mut w_repo = GitRepo::open(Some(&tag_work)).unwrap();
    let tag_oid = w_repo.rev_parse("refs/tags/v-tag-only").unwrap();
    let anc_oid = w_repo.rev_parse(&anc_oid_hex).unwrap();
    let tag_ref = format!("refs/tags/v-tag-only+{marker_a}");
    let anc_ref = format!("refs/tags/anc+{marker_a}");
    assert!(verify_ref_batch(&mut w_repo, &[RefUpdate { refname: tag_ref.clone(), target: RefTarget::Object(tag_oid) }], false).is_ok());
    assert!(
        verify_ref_batch(
            &mut w_repo,
            &[RefUpdate { refname: tag_ref, target: RefTarget::Object(tag_oid) }, RefUpdate { refname: anc_ref.clone(), target: RefTarget::Object(anc_oid) }],
            false
        )
        .is_err(),
        "H1 regression: annotated tag imprint delegated closure authority to unsigned ancestor ref!"
    );

    let mut repo2 = GitRepo::open(Some(&other_dir)).unwrap();
    fs::write(other_dir.join("z.txt"), b"z\n").unwrap();
    env.git_ok(&other_dir, &["add", "z.txt"]);
    assert!(env.git_with_env(&other_dir, &["commit", "-m", "child-plain"], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());
    let c2_oid = repo2.rev_parse("HEAD").unwrap();
    let (_, c2_raw) = repo2.read_object(&c2_oid).unwrap();
    let c2_imp = imprint_payload(&mut repo2, ObjKind::Commit, &signet_a, &rng, &c2_raw).unwrap();
    let c2_signed_plain = attach_gpgsig(&c2_raw, &encode_imprint_armor(&sid_a, &c2_imp));
    let c2_sp_oid = repo2.hash_object_write(ObjKind::Commit, &c2_signed_plain).unwrap();
    let sp_ref = format!("refs/tags/sp+{marker_a}");
    assert!(verify_ref_batch(&mut repo2, &[RefUpdate { refname: sp_ref.clone(), target: RefTarget::Object(c2_sp_oid) }], false).is_ok());
    assert!(
        verify_ref_batch(
            &mut repo2,
            &[RefUpdate { refname: sp_ref, target: RefTarget::Object(c2_sp_oid) }, RefUpdate { refname: anc_ref, target: RefTarget::Object(p_oid) }],
            false
        )
        .is_err(),
        "H1 regression: directly imprinted plain commit (no signet-parent) authorized unsigned parent!"
    );

    // H4: Prepared reference-transaction hook is strictly READ-ONLY (creating a signet-named local branch
    // does NOT write `include.path` into `.git/config`!).
    let ro_dir = env.root.join("h4-ro");
    env.git_ok(&env.root, &["init", ro_dir.to_str().unwrap()]);
    env.git_ok(&ro_dir, &["checkout", "-b", &format!("dev+{marker_a}")]);
    let local_cfg = fs::read_to_string(ro_dir.join(".git/config")).unwrap();
    assert!(!local_cfg.contains("include.path") && !local_cfg.contains("[include]"), "H4 regression: prepared hook mutated .git/config:\n{local_cfg}");

    // H5: check_revision rejects conflicting --expect vs refname `+blake3-` pin AND conflicting --signet vs ref signet!
    // Put a WRONG pin on the tag and pass the ACTUAL head_b3 as --expect so an override bug would falsely succeed!
    let mut repo = GitRepo::open(Some(&repo_dir)).unwrap();
    let head_b3 = env.signet_ok(&repo_dir, &["id", "HEAD"]).trim().to_owned();
    let head_b3_bytes = decode_lower_hex::<32>(&head_b3).unwrap();
    let other_b3 = [0xeeu8; 32];
    let other_sid = SignetId::from_bytes(&[0xeeu8; 32]);
    let bad_pin_tag = format!("badpin+blake3-{}+{marker_a}", to_hex(&other_b3));
    env.git_with_env(&repo_dir, &["tag", &bad_pin_tag], &[("GIT_SIGNET_SKIP_HOOK", "1")]);
    assert!(
        check_revision(&mut repo, &bad_pin_tag, None, Some(&head_b3_bytes), false).is_err(),
        "H5 regression: --expect overrode conflicting refname +blake3- pin!"
    );
    env.git_ok(&repo_dir, &["tag", &format!("pin+blake3-{head_b3}+{marker_a}")]);
    assert!(check_revision(&mut repo, &format!("pin+blake3-{head_b3}+{marker_a}"), None, Some(&other_b3), false).is_err());
    assert!(check_revision(&mut repo, &format!("pin+blake3-{head_b3}+{marker_a}"), Some(&other_sid), None, false).is_err());
    let _ = env.git_with_env(&repo_dir, &["tag", "-d", &bad_pin_tag], &[("GIT_SIGNET_SKIP_HOOK", "1")]);

    // M3: Disappearing witness — deleting the only imprinted ref in the SAME transaction as introducing
    // an unsigned ancestor tag MUST be rejected!
    let m3_dir = env.root.join("m3-witness");
    env.git_ok(&env.root, &["init", m3_dir.to_str().unwrap()]);
    fs::write(m3_dir.join("1.txt"), b"1\n").unwrap();
    env.git_ok(&m3_dir, &["add", "1.txt"]);
    assert!(env.git_with_env(&m3_dir, &["commit", "-m", "old"], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());
    let old_oid_hex = env.git_ok(&m3_dir, &["rev-parse", "HEAD"]).trim().to_owned();
    env.signet_ok(&m3_dir, &["imprint-here", seed_a_path.to_str().unwrap()]);
    fs::write(m3_dir.join("2.txt"), b"2\n").unwrap();
    env.git_ok(&m3_dir, &["add", "2.txt"]);
    env.git_ok(&m3_dir, &["commit", "-m", "carrying imprinted tip"]);
    let tip_oid_hex = env.git_ok(&m3_dir, &["rev-parse", "HEAD"]).trim().to_owned();
    let witness_ref = format!("refs/tags/witness+{marker_a}");
    env.git_ok(&m3_dir, &["update-ref", &witness_ref, &tip_oid_hex]);
    let mut m3_repo = GitRepo::open(Some(&m3_dir)).unwrap();
    let old_oid = m3_repo.rev_parse(&old_oid_hex).unwrap();
    let orphan_tag = format!("refs/tags/old+{marker_a}");
    assert!(verify_ref_batch(&mut m3_repo, &[RefUpdate { refname: orphan_tag.clone(), target: RefTarget::Object(old_oid) }], false).is_ok());
    assert!(
        verify_ref_batch(
            &mut m3_repo,
            &[RefUpdate { refname: witness_ref, target: RefTarget::Delete }, RefUpdate { refname: orphan_tag, target: RefTarget::Object(old_oid) }],
            false
        )
        .is_err(),
        "M3 regression: disappearing witness authorized ref in same transaction!"
    );

    // Explicit `git signet fsck` rejects a forged governed tag once no carrying witness survives.
    let m9_tag = format!("refs/tags/forged+{marker_a}");
    assert!(env.git_with_env(&m3_dir, &["update-ref", &m9_tag, &old_oid_hex], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());
    assert!(env.git_with_env(&m3_dir, &["update-ref", "-d", &format!("refs/tags/witness+{marker_a}")], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());
    let fsck_bad = env.signet(&m3_dir, &["fsck"]);
    assert!(!fsck_bad.status.success(), "git signet fsck failed to reject forged governed tag!");
}

#[test]
fn mutation_hardening_boundaries_and_parsers() {
    let env = TestEnv::new("mut-hardening");
    let dir = env.root.join("repo");
    env.git_ok(&env.root, &["init", dir.to_str().unwrap()]);
    let sid = SignetId::from_bytes(&[0x33u8; 32]);
    let marker = format_signet_marker(&sid);
    let dig_hex = "a".repeat(64);
    let dig_hex2 = "b".repeat(64);

    // id.rs: revision-walk operators rejected individually on signet-bound AND digest-pinned refs
    for bad_ref in [
        format!("refs/heads/main+{marker}^1"),
        format!("refs/heads/main+{marker}~2"),
        format!("refs/heads/a..b+{marker}"),
        format!("refs/tags/v1+blake3-{dig_hex}^1"),
        format!("refs/tags/v1+blake3-{dig_hex}~1"),
        format!("refs/tags/v1..v2+blake3-{dig_hex}"),
    ] {
        assert!(extract_signet_from_refname(&bad_ref).is_err() || extract_blake3_pin_from_refname(&bad_ref).is_err());
    }
    assert!(extract_signet_from_refname(&format!("main+{marker}^1")).is_err());
    assert!(extract_signet_from_refname(&format!("main+{marker}~1")).is_err());
    assert!(extract_signet_from_refname(&format!("a..b+{marker}")).is_err());
    assert!(extract_blake3_pin_from_refname(&format!("v1+blake3-{dig_hex}^1")).is_err());
    assert!(extract_blake3_pin_from_refname(&format!("v1+blake3-{dig_hex}~1")).is_err());
    assert!(extract_blake3_pin_from_refname(&format!("a..b+blake3-{dig_hex}")).is_err());

    // id.rs: boundary matching, identical duplicate markers vs conflicting markers, trailing '+'
    assert_eq!(extract_signet_from_refname(&format!("x{marker}")).unwrap(), None);
    assert_eq!(extract_signet_from_refname(&format!("main+{marker}+{marker}")).unwrap(), Some(sid));
    assert_eq!(extract_blake3_pin_from_refname(&format!("xblake3-{dig_hex}")).unwrap(), None);
    assert_eq!(extract_blake3_pin_from_refname(&format!("v1+blake3-{dig_hex}+")).unwrap(), Some([0xaau8; 32]));
    assert_eq!(extract_blake3_pin_from_refname(&format!("v1+blake3-{dig_hex}+blake3-{dig_hex}")).unwrap(), Some([0xaau8; 32]));
    assert!(extract_blake3_pin_from_refname(&format!("v1+blake3-{dig_hex}+blake3-{dig_hex2}")).is_err());
    assert!(extract_blake3_pin_from_refname("v1+blake3-notenoughhex").unwrap().is_none());

    // id.rs: decode_imprint_armor length boundary (16384 vs 16385), <3 lines, bad header, bad footer
    let over = vec![b'A'; 16_385];
    let over_err = decode_imprint_armor(&over).unwrap_err();
    assert!(over_err.contains("exceeds 16384"), "got: {over_err}");
    let exact = vec![b'A'; 16_384];
    let exact_err = decode_imprint_armor(&exact).unwrap_err();
    assert!(exact_err.contains("SIGNED MESSAGE"), "exact 16384 must pass size guard, got: {exact_err}");
    assert!(decode_imprint_armor(b"-----BEGIN SIGNED MESSAGE-----\n-----END SIGNED MESSAGE-----\n").is_err());
    assert!(decode_imprint_armor(b"-----BEGIN WRONG-----\nAAAA\n-----END SIGNED MESSAGE-----\n").is_err());
    assert!(decode_imprint_armor(b"-----BEGIN SIGNED MESSAGE-----\nAAAA\n-----END WRONG-----\n").is_err());

    // blake3_chain.rs: signet-parent without signet-tree error reason
    let bad_hdr = format!(
        "tree {}\nparent {}\nauthor A <a@a> 1 +0000\ncommitter A <a@a> 1 +0000\nsignet-parent blake3 {}\n\nmsg\n",
        to_hex(&[0x11u8; 20]),
        to_hex(&[0x22u8; 20]),
        dig_hex
    );
    let p_err = parse_commit(bad_hdr.into_bytes()).unwrap_err();
    assert!(p_err.message.contains("without signet-tree"), "got: {}", p_err.message);

    // blake3_chain.rs: insert_signet_headers strips multiline gpgsig, preserves trailing headers, handles no-body commit
    let raw_with_sig =
        format!("tree {}\nauthor A <a@a> 1 +0000\ncommitter A <a@a> 1 +0000\ngpgsig line1\n line2\n line3\nencoding utf-8\n\nbody\n", to_hex(&[0x11u8; 20]));
    let inserted = insert_signet_headers(raw_with_sig.as_bytes(), &[0x11u8; 20], &[0xaa; 32], &[]).unwrap();
    let ins_str = String::from_utf8(inserted).unwrap();
    assert!(!ins_str.contains("gpgsig") && !ins_str.contains("line2") && ins_str.contains("encoding utf-8") && ins_str.ends_with("\n\nbody\n"));
    let no_body = format!("tree {}\nauthor A <a@a> 1 +0000\ncommitter A <a@a> 1 +0000", to_hex(&[0x11u8; 20]));
    let ins_nb = insert_signet_headers(no_body.as_bytes(), &[0x11u8; 20], &[0xaa; 32], &[]).unwrap();
    assert!(!ins_nb.windows(2).any(|w| w == b"\n\n"));

    // blake3_chain.rs & snapshot.rs on a real repo with nested directories + multi-byte blob + plain-on-carrying + forged tag
    fs::create_dir_all(dir.join("sub/deep")).unwrap();
    fs::write(dir.join("sub/deep/data.bin"), b"0123456789abcdefghijklmnopqrstuvwxyz").unwrap();
    fs::write(dir.join("top.txt"), b"top-content\n").unwrap();
    env.git_ok(&dir, &["add", "."]);
    env.git_ok(&dir, &["commit", "-m", "c1"]);
    let c1_hex = env.git_ok(&dir, &["rev-parse", "HEAD"]).trim().to_owned();

    // Carrying commit c2 on top of plain c1, then plain commit c3 on top of carrying c2
    env.signet_ok(&dir, &["enable", "--global"]);
    let out_k = env.signet_ok(&dir, &["keygen"]);
    let marker_k = out_k.lines().find_map(|l| l.strip_prefix("Signet ID:")).unwrap().trim().to_owned();
    let seed_path = env.config_dir.join("signets").join(format!("{marker_k}.seed"));
    env.signet_ok(&dir, &["imprint-here", seed_path.to_str().unwrap()]);
    fs::write(dir.join("top.txt"), b"v2\n").unwrap();
    env.git_ok(&dir, &["add", "top.txt"]);
    env.git_ok(&dir, &["commit", "-m", "c2 carrying"]);
    let c2_hex = env.git_ok(&dir, &["rev-parse", "HEAD"]).trim().to_owned();

    fs::write(dir.join("top.txt"), b"v3\n").unwrap();
    env.git_ok(&dir, &["add", "top.txt"]);
    assert!(env.git_with_env(&dir, &["commit", "-m", "c3 plain"], &[("GIT_SIGNET_SKIP_HOOK", "1")]).status.success());
    let c3_hex = env.git_ok(&dir, &["rev-parse", "HEAD"]).trim().to_owned();

    let mut repo = GitRepo::open(Some(&dir)).unwrap();
    let ctx = ContextKeys::new();
    let c1 = repo.rev_parse(&c1_hex).unwrap();
    let c2 = repo.rev_parse(&c2_hex).unwrap();
    let c3 = repo.rev_parse(&c3_hex).unwrap();

    let rep_c1_skip = verify_commit_chain(&mut repo, &ctx, &c1, None, false, false).unwrap();
    assert_eq!(rep_c1_skip.digest, None);
    let rep_c1_req = verify_commit_chain(&mut repo, &ctx, &c1, None, false, true).unwrap();
    assert!(rep_c1_req.digest.is_some());
    let rep_c3 = verify_commit_chain(&mut repo, &ctx, &c3, None, false, false).unwrap();
    assert_eq!(rep_c3.carrying_commits, 1);
    assert_eq!(rep_c3.plain_commits, 2);
    assert!(!rep_c3.tip_carries_lines);
    assert!(!rep_c3.shallow_boundary_hit);
    assert!(rep_c3.digest.is_some());
    let mut tcache = DigestCache::memory_only();
    let (_, c1_raw) = repo.read_object(&c1).unwrap();
    let c1_tree = parse_commit(c1_raw.clone()).unwrap().tree;
    let d1 = compute_tree_digest(&mut repo, &ctx, &c1_tree, &mut tcache).unwrap();
    let d2 = compute_tree_digest(&mut repo, &ctx, &c1_tree, &mut tcache).unwrap();
    assert_eq!(d1, d2);

    let blob_hex = env.git_ok(&dir, &["rev-parse", "HEAD:top.txt"]).trim().to_owned();
    let forged_tag = format!("object {blob_hex}\ntype commit\ntag bad\ntagger A <a@a> 1 +0000\n\nbad\n");
    let forged_tag_oid = repo.hash_object_write(ObjKind::Tag, forged_tag.as_bytes()).unwrap();
    let peel_err = git_signet::blake3_chain::peel_to_commit(&mut repo, &forged_tag_oid).unwrap_err();
    assert!(peel_err.message.contains("type mismatch"), "got: {}", peel_err.message);

    repo.shallow.insert(c2);
    let rep_sh = verify_commit_chain(&mut repo, &ctx, &c2, None, true, false).unwrap();
    assert!(rep_sh.shallow_boundary_hit);
    repo.shallow.clear();
    repo.shallow.insert(c1);
    let rep_root_sh = verify_commit_chain(&mut repo, &ctx, &c1, None, true, false).unwrap();
    assert!(!rep_root_sh.shallow_boundary_hit);
    repo.shallow.clear();

    // T5: cat-file --batch-command cleanly recovers after a failing Write sink aborts mid-blob!
    struct FailAfter(usize);
    impl std::io::Write for FailAfter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "abort mid-snapshot"));
            }
            let n = buf.len().min(self.0);
            self.0 -= n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut full = Vec::new();
    write_payload_snapshot(&mut repo, ObjKind::Commit, &c1_raw, &mut full).unwrap();
    let needle = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let pos = full.windows(needle.len()).position(|w| w == needle).unwrap();
    assert!(write_payload_snapshot(&mut repo, ObjKind::Commit, &c1_raw, &mut FailAfter(pos + 5)).is_err());
    assert_eq!(repo.read_object(&c1).unwrap().0, ObjKind::Commit);
    let _ = open_randomness;
    // snapshot.rs: extract_tag_imprint edge cases (no body, empty message before armor, duplicate armor blocks)
    assert!(matches!(extract_tag_imprint(b"object 0000\ntype commit\ntag t\n"), ExtractedArmor::Malformed(_)));
    let empty_msg_tag = b"object 0000\ntype commit\ntag t\ntagger A <a@a> 1 +0000\n\n-----BEGIN SIGNED MESSAGE-----\nAAAA\n-----END SIGNED MESSAGE-----\n";
    match extract_tag_imprint(empty_msg_tag) {
        ExtractedArmor::Present { payload, armor } => {
            assert!(payload.ends_with(b"\n\n"));
            assert!(armor.starts_with(b"-----BEGIN SIGNED MESSAGE-----\n"));
        }
        other => panic!("expected Present, got {other:?}"),
    }
    let dup_tag = b"object 0000\ntype commit\ntag t\ntagger A <a@a> 1 +0000\n\nmsg\n-----BEGIN SIGNED MESSAGE-----\nA\n-----BEGIN SIGNED MESSAGE-----\nB\n";
    assert!(matches!(extract_tag_imprint(dup_tag), ExtractedArmor::Malformed(_)));
}

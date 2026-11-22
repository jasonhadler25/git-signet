use git_signet::key::{format_marker, parse_openssh_ed25519_pubkey};
use git_signet::verify::extract_commit_ssh_signature;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static TEST_CTR: AtomicUsize = AtomicUsize::new(0);

struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    git_bin: PathBuf,
    signet_bin: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let id = TEST_CTR.fetch_add(1, Ordering::SeqCst);
        let root = env::temp_dir().join(format!("git-signet-test-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let signet_bin = PathBuf::from(env!("CARGO_BIN_EXE_git-signet"));
        // Use stock system git directly so host wrappers don't leak into test sandbox
        let git_bin = [
            "/opt/homebrew/bin/git",
            "/usr/bin/git",
            "/usr/local/bin/git",
        ]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("git"));
        Self {
            root,
            home,
            git_bin,
            signet_bin,
        }
    }

    fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(&self.git_bin)
            .current_dir(cwd)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_SIGNET_GIT", &self.git_bin)
            .env("GIT_AUTHOR_NAME", "Tester")
            .env("GIT_AUTHOR_EMAIL", "tester@example.com")
            .env("GIT_COMMITTER_NAME", "Tester")
            .env("GIT_COMMITTER_EMAIL", "tester@example.com")
            .env("GIT_EDITOR", "true")
            .args(args)
            .output()
            .unwrap()
    }

    fn signet(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(&self.signet_bin)
            .current_dir(cwd)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_SIGNET_GIT", &self.git_bin)
            .args(args)
            .output()
            .unwrap()
    }

    fn gen_ed25519(&self, name: &str) -> (PathBuf, String) {
        let key = self.root.join(name);
        let out = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen failed: {:?}", out);
        let pub_txt = fs::read_to_string(format!("{}.pub", key.display())).unwrap();
        let pub32 = parse_openssh_ed25519_pubkey(&pub_txt).unwrap();
        (key, format_marker(&pub32))
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn repo_name_key_protects_first_clone_fetch_and_default_branch_hijack() {
    let sb = Sandbox::new();
    let (maya_key, maya_marker) = sb.gen_ed25519("maya_ed25519");
    let (mallory_key, _) = sb.gen_ed25519("mallory_ed25519");

    // 1. Maya creates a bare remote whose repo name embeds her Ed25519 verifying key!
    let remote = sb.root.join(format!("acme-tls.{maya_marker}.git"));
    assert!(sb.git(&sb.root, &["init", "--bare", "-b", "main", remote.to_str().unwrap()]).status.success());

    let maya = sb.root.join("maya");
    fs::create_dir_all(&maya).unwrap();
    assert!(sb.git(&maya, &["init", "-b", "main"]).status.success());
    assert!(sb.signet(&maya, &["sign-here", maya_key.to_str().unwrap()]).status.success());
    fs::write(maya.join("lib.rs"), "pub fn safe() -> u32 { 42 }\n").unwrap();
    assert!(sb.git(&maya, &["add", "lib.rs"]).status.success());
    assert!(sb.git(&maya, &["commit", "-m", "Release 1.0"]).status.success());
    assert!(sb.git(&maya, &["tag", "-s", "v1.0", "-m", "Signed release tag v1.0"]).status.success());
    assert!(sb.git(&maya, &["remote", "add", "origin", remote.to_str().unwrap()]).status.success());
    assert!(sb.git(&maya, &["push", "-u", "origin", "main", "--tags"]).status.success());

    // 2. Enable git-signet globally for Sam (fresh user with ZERO allowed_signers config!)
    assert!(sb.signet(&sb.root, &["enable", "--global"]).status.success());

    // 3. Sam clones the self-certifying URL -> SUCCEEDS automatically!
    let sam = sb.root.join("sam");
    let clone_ok = sb.git(&sb.root, &["clone", remote.to_str().unwrap(), sam.to_str().unwrap()]);
    assert!(
        clone_ok.status.success(),
        "valid signed clone must succeed: stderr={}",
        String::from_utf8_lossy(&clone_ok.stderr)
    );
    assert!(sam.join("lib.rs").is_file());

    // Explicit `git signet check` and `git signet fsck` + independent Python oracle all pass!
    let chk = sb.signet(&sam, &["check", "HEAD"]);
    assert!(chk.status.success(), "check HEAD failed: {:?}", chk);
    let chk_tag = sb.signet(&sam, &["check", "v1.0"]);
    assert!(chk_tag.status.success(), "check v1.0 failed: {:?}", chk_tag);
    let fsck = sb.signet(&sam, &["fsck"]);
    assert!(fsck.status.success(), "fsck failed: {:?}", fsck);
    let py = Command::new("python3")
        .current_dir(&sam)
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("signet-verify.py"))
        .args(["HEAD", &maya_marker])
        .output()
        .unwrap();
    assert!(py.status.success(), "signet-verify.py failed: {:?}", py);

    // 4. ATTACK 1: Compromised host pushes an UNSIGNED commit to `main`!
    let evil_clone = sb.root.join("evil");
    assert!(
        sb.git(
            &sb.root,
            &["-c", "signet.disabled=true", "clone", remote.to_str().unwrap(), evil_clone.to_str().unwrap()]
        )
        .status
        .success()
    );
    fs::write(evil_clone.join("lib.rs"), "pub fn safe() -> u32 { 666 } // backdoor\n").unwrap();
    assert!(
        sb.git(
            &evil_clone,
            &["-c", "signet.disabled=true", "commit", "-am", "Unsigned backdoor"]
        )
        .status
        .success()
    );
    assert!(
        sb.git(&evil_clone, &["-c", "signet.disabled=true", "push", "origin", "main"])
            .status
            .success()
    );

    // Sam's fresh clone MUST ABORT before writing lib.rs!
    let sam_bad1 = sb.root.join("sam-bad1");
    let clone_bad1 = sb.git(&sb.root, &["clone", remote.to_str().unwrap(), sam_bad1.to_str().unwrap()]);
    assert!(!clone_bad1.status.success(), "unsigned commit clone MUST be aborted!");
    assert!(!sam_bad1.join("lib.rs").exists(), "working tree must NOT be written on rejected clone!");

    // Existing Sam's `git fetch` MUST ALSO ABORT!
    let fetch_bad = sb.git(&sam, &["fetch", "origin"]);
    assert!(!fetch_bad.status.success(), "fetch of unsigned commit MUST be aborted!");

    // 5. ATTACK 2: Compromised host signs commit with MALLORY'S Ed25519 key AND hijacks default branch!
    assert!(
        sb.git(&evil_clone, &["-c", "signet.disabled=true", "checkout", "-b", "hijacked"])
            .status
            .success()
    );
    assert!(sb.git(&evil_clone, &["config", "gpg.format", "ssh"]).status.success());
    assert!(
        sb.git(&evil_clone, &["config", "user.signingkey", mallory_key.to_str().unwrap()])
            .status
            .success()
    );
    fs::write(evil_clone.join("lib.rs"), "pub fn safe() -> u32 { 999 } // mallory signed\n").unwrap();
    assert!(
        sb.git(
            &evil_clone,
            &["-c", "signet.disabled=true", "commit", "-S", "-am", "Mallory-signed hijack"]
        )
        .status
        .success()
    );
    assert!(
        sb.git(&evil_clone, &["-c", "signet.disabled=true", "push", "origin", "hijacked"])
            .status
            .success()
    );
    // Point remote HEAD to `hijacked` (default-branch swap attack!)
    assert!(
        sb.git(
            &remote,
            &["-c", "signet.disabled=true", "symbolic-ref", "HEAD", "refs/heads/hijacked"]
        )
        .status
        .success()
    );

    let sam_bad2 = sb.root.join("sam-bad2");
    let clone_bad2 = sb.git(&sb.root, &["clone", remote.to_str().unwrap(), sam_bad2.to_str().unwrap()]);
    assert!(
        !clone_bad2.status.success(),
        "default-branch hijack signed by Mallory MUST be aborted!"
    );
    assert!(
        String::from_utf8_lossy(&clone_bad2.stderr).contains("SIGNATURE REJECTED"),
        "expected SIGNATURE REJECTED, got: {}",
        String::from_utf8_lossy(&clone_bad2.stderr)
    );
}

#[test]
fn branch_and_tag_keys_unsigned_tag_rejection_and_conflict_checks() {
    let sb = Sandbox::new();
    let (maya_key, maya_marker) = sb.gen_ed25519("maya_key");
    let (_, other_marker) = sb.gen_ed25519("other_key");

    // Ordinary repo name (NO repo rename needed!)
    let remote = sb.root.join("ordinary-repo.git");
    let branch = format!("main+{maya_marker}");
    assert!(sb.git(&sb.root, &["init", "--bare", "-b", &branch, remote.to_str().unwrap()]).status.success());

    assert!(sb.signet(&sb.root, &["enable", "--global"]).status.success());

    let repo = sb.root.join("work");
    fs::create_dir_all(&repo).unwrap();
    assert!(sb.git(&repo, &["init", "-b", &branch]).status.success());
    assert!(sb.signet(&repo, &["sign-here", maya_key.to_str().unwrap()]).status.success());
    fs::write(repo.join("hello.txt"), "signed on self-certifying branch\n").unwrap();
    assert!(sb.git(&repo, &["add", "hello.txt"]).status.success());

    // A local commit is never refused, signed or not: local branches are the user's own work.
    // What the key's name promises is checked when the branch is fetched, and on request.
    assert!(sb.git(&repo, &["commit", "--no-gpg-sign", "-m", "Unsigned local work"]).status.success());
    assert!(!sb.signet(&repo, &["check", "HEAD"]).status.success(), "unsigned tip must not check out as signed");
    fs::write(repo.join("hello.txt"), "now signed\n").unwrap();
    assert!(sb.git(&repo, &["commit", "-am", "Signed commit on branch"]).status.success());
    assert!(sb.signet(&repo, &["check", "HEAD"]).status.success());

    // A signed annotated tag whose name carries the key passes.
    let good_tag = format!("v1.0.0+{maya_marker}");
    assert!(sb.git(&repo, &["tag", "-s", &good_tag, "-m", "Signed tag"]).status.success());
    assert!(sb.signet(&repo, &["check", &good_tag]).status.success());

    // So does a plain annotated tag naming a signed commit: the commit carries the signature.
    let plain_tag = format!("v2.0.0+{maya_marker}");
    assert!(sb.git(&repo, &["tag", "-a", "--no-sign", &plain_tag, "-m", "Plain tag"]).status.success());

    // A tag whose name carries the key but which names an unsigned commit is refused.
    assert!(sb.git(&repo, &["checkout", "-q", "--detach"]).status.success());
    assert!(sb.git(&repo, &["commit", "--no-gpg-sign", "--allow-empty", "-m", "unsigned"]).status.success());
    let bad_tag = format!("v3.0.0+{maya_marker}");
    assert!(
        !sb.git(&repo, &["tag", "-a", "--no-sign", &bad_tag, "-m", "x"]).status.success(),
        "a key-named tag on an unsigned commit must be refused"
    );
    assert!(sb.git(&repo, &["checkout", "-q", &branch]).status.success());

    // Push to ordinary remote and verify clone works with `-b main+ed25519-...`
    assert!(sb.git(&repo, &["remote", "add", "origin", remote.to_str().unwrap()]).status.success());
    assert!(sb.git(&repo, &["push", "-u", "origin", &branch, "--tags"]).status.success());

    let cl = sb.root.join("cloned");
    assert!(sb.git(&sb.root, &["clone", "-b", &branch, remote.to_str().unwrap(), cl.to_str().unwrap()]).status.success());
    assert!(sb.signet(&cl, &["fsck"]).status.success());

    // Explicit `--key` disagreeing with refname key MUST fail closed!
    let conflict = sb.signet(&cl, &["check", "HEAD", "--key", &other_marker]);
    assert!(!conflict.status.success(), "conflicting --key must fail closed!");

    // Duplicate gpgsig header MUST fail closed!
    let dup_raw = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
        author A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\
        gpgsig -----BEGIN SSH SIGNATURE-----\n -----END SSH SIGNATURE-----\n\
        gpgsig -----BEGIN SSH SIGNATURE-----\n -----END SSH SIGNATURE-----\n\nmsg\n";
    assert!(extract_commit_ssh_signature(dup_raw).is_err());
}

#[test]
fn composes_cleanly_with_git_buttress_when_installed() {
    // Only run composition check if `git-buttress` binary is discoverable on PATH
    let Some(buttress_bin) = env::var_os("PATH").and_then(|p| {
        env::split_paths(&p)
            .map(|d| d.join("git-buttress"))
            .find(|cand| cand.is_file())
    }) else {
        return;
    };

    let sb = Sandbox::new();
    let (maya_key, maya_marker) = sb.gen_ed25519("maya_combo");
    let (mallory_key, _) = sb.gen_ed25519("mallory_combo");

    // Enable BOTH git-buttress AND git-signet globally in the SAME sandbox HOME!
    assert!(
        Command::new(&buttress_bin)
            .current_dir(&sb.root)
            .env("HOME", &sb.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_BUTTRESS_REAL_GIT", &sb.git_bin)
            .args(["enable", "--global", "--no-wrapper"])
            .status()
            .unwrap()
            .success()
    );
    assert!(sb.signet(&sb.root, &["enable", "--global"]).status.success());

    let remote = sb.root.join(format!("combo.{maya_marker}.git"));
    assert!(sb.git(&sb.root, &["init", "--bare", "-b", "main", remote.to_str().unwrap()]).status.success());

    let maya = sb.root.join("maya");
    fs::create_dir_all(&maya).unwrap();
    assert!(sb.git(&maya, &["init", "-b", "main"]).status.success());
    assert!(sb.signet(&maya, &["sign-here", maya_key.to_str().unwrap()]).status.success());
    fs::write(maya.join("app.rs"), "fn main() {}\n").unwrap();
    assert!(sb.git(&maya, &["add", "app.rs"]).status.success());
    let c = sb.git(&maya, &["commit", "-m", "Both buttressed and signet-signed"]);
    assert!(c.status.success(), "combo commit failed: {:?}", c);

    // Verify commit has BOTH `buttress-tree blake3` AND valid `gpgsig`!
    let raw = String::from_utf8_lossy(&sb.git(&maya, &["cat-file", "-p", "HEAD"]).stdout).to_string();
    assert!(raw.contains("buttress-tree blake3 "), "missing buttress-tree:\n{raw}");
    assert!(raw.contains("gpgsig -----BEGIN SSH SIGNATURE-----"), "missing ssh gpgsig:\n{raw}");

    assert!(sb.git(&maya, &["remote", "add", "origin", remote.to_str().unwrap()]).status.success());
    assert!(sb.git(&maya, &["push", "-u", "origin", "main"]).status.success());

    // Sam clones with BOTH git-buttress and git-signet enabled -> BOTH verify automatically!
    let sam = sb.root.join("sam");
    let cl = sb.git(&sb.root, &["clone", remote.to_str().unwrap(), sam.to_str().unwrap()]);
    assert!(cl.status.success(), "combo clone failed: {:?}", cl);

    // Attack A: Mallory creates a validly-buttressed commit signed by MALLORY'S key -> git-signet blocks!
    let mallory = sb.root.join("mallory");
    assert!(
        sb.git(
            &sb.root,
            &["-c", "signet.disabled=true", "clone", remote.to_str().unwrap(), mallory.to_str().unwrap()]
        )
        .status
        .success()
    );
    assert!(sb.signet(&mallory, &["sign-here", mallory_key.to_str().unwrap()]).status.success());
    fs::write(mallory.join("app.rs"), "fn main() { /* evil */ }\n").unwrap();
    assert!(
        sb.git(&mallory, &["-c", "signet.disabled=true", "commit", "-am", "Mallory buttressed"])
            .status
            .success()
    );
    assert!(
        sb.git(&mallory, &["-c", "signet.disabled=true", "push", "origin", "main"])
            .status
            .success()
    );

    let sam_evil = sb.root.join("sam-evil");
    let blocked = sb.git(&sb.root, &["clone", remote.to_str().unwrap(), sam_evil.to_str().unwrap()]);
    assert!(!blocked.status.success(), "git-signet MUST block Mallory's validly-buttressed commit!");
}

fn head_is_signed(sb: &Sandbox, repo: &Path) -> bool {
    String::from_utf8_lossy(&sb.git(repo, &["cat-file", "commit", "HEAD"]).stdout)
        .contains("gpgsig -----BEGIN SSH SIGNATURE-----")
}

#[test]
fn key_holders_sign_without_setup_and_nobody_elses_commits_are_refused() {
    // Two people on two machines: Maya holds the signing key, Sam does not.
    let m = Sandbox::new();
    let s = Sandbox::new();
    let (maya_key, marker) = m.gen_ed25519("maya_key");
    assert!(m.signet(&m.root, &["adopt", maya_key.to_str().unwrap()]).status.success());
    assert!(m.signet(&m.root, &["enable", "--global"]).status.success());
    assert!(s.signet(&s.root, &["enable", "--global"]).status.success());

    // --- A repository whose name carries the key: Maya types only plain git. ---
    let remote = m.root.join(format!("acme.{marker}.git"));
    assert!(m.git(&m.root, &["init", "--bare", "-b", "main", remote.to_str().unwrap()]).status.success());
    let work = m.root.join("work");
    assert!(m.git(&m.root, &["init", "-b", "main", work.to_str().unwrap()]).status.success());
    assert!(m.git(&work, &["remote", "add", "origin", remote.to_str().unwrap()]).status.success());
    fs::write(work.join("f"), "one\n").unwrap();
    assert!(m.git(&work, &["add", "f"]).status.success());
    assert!(m.git(&work, &["commit", "-m", "one"]).status.success());
    assert!(head_is_signed(&m, &work), "the key holder's plain `git commit` must be signed");
    assert!(m.git(&work, &["tag", "-a", "v1", "-m", "ordinary annotated tag"]).status.success());
    assert!(m.git(&work, &["tag", "light"]).status.success());
    let pushed = m.git(&work, &["push", "-u", "origin", "main", "--tags"]);
    assert!(pushed.status.success(), "push failed: {pushed:?}");

    // --- Sam clones, works, and merges Maya's next commit. Nothing refuses his own commits. ---
    let sam = s.root.join("sam");
    let cloned = s.git(&s.root, &["clone", remote.to_str().unwrap(), sam.to_str().unwrap()]);
    assert!(cloned.status.success(), "clone failed: {cloned:?}");
    fs::write(sam.join("sam.txt"), "sam's work\n").unwrap();
    assert!(s.git(&sam, &["add", "sam.txt"]).status.success());
    let sam_commit = s.git(&sam, &["commit", "-m", "Sam's local work"]);
    assert!(sam_commit.status.success(), "a local commit without the key must succeed: {sam_commit:?}");
    assert!(!head_is_signed(&s, &sam));
    fs::write(work.join("f"), "two\n").unwrap();
    assert!(m.git(&work, &["commit", "-am", "two"]).status.success());
    assert!(m.git(&work, &["push", "origin", "main"]).status.success());
    let pulled = s.git(&sam, &["pull", "--no-rebase", "--no-edit"]);
    assert!(pulled.status.success(), "pull with a local merge must succeed: {pulled:?}");
    assert!(s.signet(&sam, &["fsck"]).status.success());

    // If Sam's unsigned merge is pushed to the keyed repository, everyone's next clone refuses it.
    let _ = s.git(&sam, &["push", "origin", "main"]);
    let later = s.root.join("later");
    let refused = s.git(&s.root, &["clone", remote.to_str().unwrap(), later.to_str().unwrap()]);
    assert!(!refused.status.success(), "an unsigned tip in the keyed repository must be refused");

    // --- A branch whose name carries the key, in a brand-new repository. ---
    let branch = format!("main+{marker}");
    let b = m.root.join("b");
    assert!(m.git(&m.root, &["init", "-b", &branch, b.to_str().unwrap()]).status.success());
    fs::write(b.join("a"), "base\n").unwrap();
    assert!(m.git(&b, &["add", "a"]).status.success());
    assert!(m.git(&b, &["commit", "-m", "base"]).status.success());
    assert!(head_is_signed(&m, &b), "the first commit on an unborn key-named branch must be signed");

    // A rebase that stops for a conflict leaves HEAD detached; continuing must still sign.
    assert!(m.git(&b, &["switch", "-c", "side"]).status.success());
    fs::write(b.join("a"), "side\n").unwrap();
    assert!(m.git(&b, &["commit", "-am", "side"]).status.success());
    assert!(m.git(&b, &["switch", &branch]).status.success());
    fs::write(b.join("a"), "mine\n").unwrap();
    assert!(m.git(&b, &["commit", "-am", "mine"]).status.success());
    assert!(!m.git(&b, &["rebase", "side"]).status.success(), "the rebase should stop on a conflict");
    fs::write(b.join("a"), "resolved\n").unwrap();
    assert!(m.git(&b, &["add", "a"]).status.success());
    let cont = m.git(&b, &["rebase", "--continue"]);
    assert!(cont.status.success(), "rebase --continue failed: {cont:?}");
    assert!(head_is_signed(&m, &b), "the rebased tip must be signed");
    assert!(m.signet(&b, &["check", "HEAD"]).status.success());

    // Sam, without the key, can still commit on a branch of that name; it just is not signed.
    let sb = s.root.join("b");
    assert!(s.git(&s.root, &["init", "-b", &branch, sb.to_str().unwrap()]).status.success());
    fs::write(sb.join("a"), "sam\n").unwrap();
    assert!(s.git(&sb, &["add", "a"]).status.success());
    assert!(s.git(&sb, &["commit", "-m", "sam"]).status.success());
    assert!(!s.signet(&sb, &["check", "HEAD"]).status.success());

    // A repository that merely has `ed25519-` in its name is an ordinary repository.
    let dalek = s.root.join("dalek");
    assert!(s.git(&s.root, &["init", "-b", "main", dalek.to_str().unwrap()]).status.success());
    assert!(s.git(&dalek, &["remote", "add", "origin", "https://example.com/x/ed25519-dalek.git"]).status.success());
    fs::write(dalek.join("a"), "a\n").unwrap();
    assert!(s.git(&dalek, &["add", "a"]).status.success());
    assert!(s.git(&dalek, &["commit", "-m", "a"]).status.success());
    assert!(s.git(&dalek, &["switch", "-c", "fix/ed25519-parsing"]).status.success());
}

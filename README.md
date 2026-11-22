# git-signet

**Self-certifying Ed25519 signing keys embedded right inside Git repository,
branch, and tag names—zero GPG, zero CAs, zero keyservers, zero
`allowed_signers` files.**

`git-signet` is a **zero-dependency** Rust tool (no external crates at all)
built as the natural companion to
[`git-buttress`](https://github.com/jasonhadler25/git-buttress), inspired by
Brian Warner's self-certifying Git capability ideas.

---

## Why?

GPG commit signing fails in practice for a simple reason: even if a maintainer
signs every commit, users cloning the repository have no automatic way to know
*which* key is supposed to sign it, and stock `git clone` / `git pull` never
check signatures anyway.

`git-signet` fixes key distribution by putting the 32-byte Ed25519 verifying
key straight into the string users already copy, paste, clone, or pin in
`Cargo.toml`:

```text
# Option A: embed the key in the repository name (protects every branch from clone #1!)
git clone https://github.com/maya/acme-tls.ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa

# Option B: embed the key in a branch or tag name (no repo rename needed!)
git clone -b main+ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa https://github.com/maya/acme-tls
```

* **Zero new signature format:** Maintainers sign commits and tags with stock
  Git SSH signing (`gpg.format = ssh`, Ed25519)—so GitHub still shows its
  green **Verified** badge, and users without `git-signet` see an ordinary
  Git repo.
* **Automatic enforcement:** Anyone with `git-signet` enabled gets automatic
  Ed25519 signature verification on every `git clone`, `git fetch`, `git pull`,
  and `git signet fsck`. If GitHub is compromised, a maintainer's GitHub token
  is stolen, or a mirror substitutes an unsigned/forged commit—even if the
  attacker renames the default branch—`git clone` **aborts before writing a
  single file to disk**:

```text
$ git clone https://github.com/maya/acme-tls.ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa
Cloning into 'acme-tls.ed25519-74nfu4k2...'...
signet: SIGNATURE REJECTED on refs/remotes/origin/main (expected ed25519-74nfu4k2... from remote.origin.url):
  commit is not signed (missing gpgsig header)
fatal: in 'prepared' phase, update aborted by the reference-transaction hook
```

* **Zero third-party crate dependencies:** `Cargo.toml` has an empty
  `[dependencies]` section—`std` only, delegating cryptographic verification
  to OpenSSH `ssh-keygen -Y verify` over standard Git SSH signatures.

---

## Pairing with `git-buttress`

`git-signet` and [`git-buttress`](https://github.com/jasonhadler25/git-buttress)
stack cleanly via Git 2.56+ native `[hook "..."]` config (neither touches
`core.hooksPath`, so `git-lfs`, `pre-commit`, and `husky` also coexist):

| Threat | Stock Git | `git-buttress` alone | `git-signet` alone | `git-signet` + `git-buttress` |
|---|---|---|---|---|
| Compromised Git host / stolen forge token | Vulnerable | Vulnerable (attacker signs valid BLAKE3) | **Blocked** | **Blocked** |
| SHA-1 / SHA1DC file or history collision | Vulnerable | **Blocked** | Vulnerable (signature covers SHA-1 only) | **Blocked** (Ed25519 signs BLAKE3!) |
| Requires GPG / CA / `allowed_signers` setup | Yes | No | **No** | **No** |

---

## Quickstart

### Build & enable (once per machine, Git 2.56+)

```sh
cargo build --release --locked
cp target/release/git-signet ~/.local/bin/
git signet enable --global
```

### For a maintainer publishing a self-certifying repo or branch

```sh
# 1. Generate (or reuse) an Ed25519 SSH signing key and print your signet suffix:
git signet keygen
# Key file:    ~/.ssh/git_signet_ed25519
# Signet ID:   ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa
# Repo suffix: <repo>.ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa
# Branch name: main+ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa

# 2. Configure the current repo to sign commits & annotated tags automatically:
git signet sign-here ~/.ssh/git_signet_ed25519

# 3. Create your repo with that suffix (or rename/create branch `main+ed25519-...`) and commit normally:
git commit -m "Initial signed release"
git push -u origin HEAD
```

### Explicit checks & independent Python oracle

```sh
git signet check HEAD
git signet fsck
./signet-verify.py HEAD ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa
```

---

## Repository Contents

* [`SIGNET.md`](SIGNET.md) — Crisp specification of the `ed25519-<52-base32>`
  encoding, URL/refname extraction rules, verification semantics, composition
  with `git-buttress`, and honest threat model.
* [`src/`](src/) & [`Cargo.toml`](Cargo.toml) — Zero-dependency Rust
  implementation (`std` only).
* [`signet-verify.py`](signet-verify.py) — Standalone ~55-line Python
  reference verifier using only stock `git` and `ssh-keygen`.
* [`tests/integration.rs`](tests/integration.rs) — End-to-end tests covering
  repo-name keys, branch/tag keys, default-branch hijack attacks, unsigned
  annotated tag attacks, key conflicts, and live composition with
  `git-buttress`.

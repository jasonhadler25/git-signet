# git-signet

**The key that signs a Git repository, carried in the repository's own name.
No GPG, no certificate authority, no keyserver, no `allowed_signers` file.**

A companion to [git-buttress](https://github.com/jasonhadler25/git-buttress),
following Brian Warner's experiment with Git signatures. No crate dependencies.

---

## Why

A maintainer can sign every commit, and it does a user no good: the user has
no way to know which key should have signed, and `git clone` and `git pull`
never look.

git-signet puts the 32-byte Ed25519 verifying key into the name the user
already copies:

```text
# in the repository's name: covers every branch and tag, from the first clone
git clone https://github.com/maya/acme-tls.ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa

# or in a branch's name: no need to rename the repository
git clone -b main+ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa https://github.com/maya/acme-tls
```

To Git, GitHub and Cargo those are ordinary names. With git-signet enabled,
`git clone`, `git fetch` and `git pull` check what arrives against the key in
the name. If the forge is compromised, or a maintainer's forge token is
stolen, or a mirror serves something else, nothing is written:

```text
$ git clone https://github.com/maya/acme-tls.ed25519-74nfu4k2...
Cloning into 'acme-tls.ed25519-74nfu4k2...'...
signet: SIGNATURE REJECTED on refs/remotes/origin/main (expected ed25519-74nfu4k2... from remote.origin.url):
  commit is not signed (missing gpgsig header)
fatal: in 'prepared' phase, update aborted by the reference-transaction hook
```

The signatures are stock Git SSH signatures, so GitHub shows them as
Verified once the key is on the maintainer's account, and a user without git-signet sees an ordinary repository.

---

## Use

Build, and enable checking (once per machine, Git 2.56 or later):

```sh
cargo build --release --locked
cp target/release/git-signet ~/.local/bin/
git signet enable --global
```

To publish under a key, adopt one (once per machine):

```sh
git signet keygen                     # a new key, or:
git signet adopt ~/.ssh/id_ed25519    # the SSH key you already have
# Verifying key: ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa
```

Then give a repository or a branch that name. There is no other step:
wherever a repository or branch name carries a key you have adopted, plain
`git commit`, `git merge` and `git rebase` sign with it. Elsewhere nothing
changes.

To check by hand, or with the short Python script that uses only `git` and
`ssh-keygen`:

```sh
git signet check HEAD
git signet fsck
./signet-verify.py HEAD ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa
```

---

## With git-buttress

| | Stock Git | git-buttress | git-signet | both |
|---|---|---|---|---|
| Compromised forge, stolen forge token | exposed | exposed | **stopped** | **stopped** |
| SHA-1 collision in a file or in history | exposed | **stopped** | exposed | **stopped** |

git-signet alone signs SHA-1 identifiers; git-buttress alone can be rewritten
by anyone who can push. Together the signature covers the BLAKE3 digests.

---

## Limits you should know before relying on it

* Your own commits are never refused, with or without the key. What is
  checked is what you fetch.
* In a repository whose name carries a key, every branch must be signed by
  that key. A bot's branch or a commit from the forge's merge button makes
  clone and fetch fail for everyone running git-signet. A key in a branch's
  name constrains only that branch.
* A signature covers a commit, not the name of the branch or tag it is served
  under: a server can replay an old signed commit, or serve one branch's as
  another.
* Clients that do not run Git's hooks (`jj`, `gix`, Cargo) are not stopped.

[`SIGNET.md`](SIGNET.md) has the exact rules and the rest of the limits.

---

## Contents

* [`SIGNET.md`](SIGNET.md): the specification.
* [`src/`](src/): the implementation, Rust standard library only; signatures
  are checked by OpenSSH's `ssh-keygen -Y verify`.
* [`signet-verify.py`](signet-verify.py): an independent verifier.
* [`tests/integration.rs`](tests/integration.rs): clone, fetch and pull
  against unsigned, wrongly signed and re-pointed branches; signing with no
  setup; a contributor without the key; a rebase that stops and continues;
  git-buttress alongside.

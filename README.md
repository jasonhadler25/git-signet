# git-signet

> **Pre-1.0 — Experimental & Unsupported.** This software is an early prototype under active design. Wire formats, commit headers, context strings, and CLI flags may change incompatibly before 1.0, and no independent human cryptographic audit has been performed. Do not rely on it to protect production repositories or high-stakes assets.

**Install once, keep typing plain `git`, and give your repositories invisible BLAKE3 protection — with optional digest-bound pins and post-quantum self-authenticating names whenever you are ready.**

By default, enabling `git-signet` causes **zero warnings** on ordinary repositories, changes **nothing visible** on GitHub, in `git log`, or in your tag list, asks **nothing** of teammates or downstream users, and adds **no noticeable slowdown**. Stronger, opt-in steps — embedding BLAKE3 digests or post-quantum signet IDs in tag, branch, or repository names — are completely optional and deferred until you choose them.

---

## Why? How Git checks your files today

Every commit ID in Git is a **SHA-1** fingerprint computed from that commit and, through it, every file and history step behind it. Whenever you clone, pull, verify a commit, or pin a version, Git relies on one assumption: *different contents produce a different SHA-1 ID.*

SHA-1 is old and weakened. Today Git uses **SHA1DC**, a variant that detects known collision techniques, so Git is not visibly broken right now. The catch is that cryptographic hashes only ever get weaker — and an attacker who finds a way past SHA1DC does **not** have to publish a paper first.

And even if SHA-1 never broke, stock Git still has a second gap: a maintainer can sign every commit, and it does a user little good if the user has no way to know which key should have signed, and `git clone` and `git pull` never check.

`git-signet` addresses both problems in three progressive layers — starting with zero visible changes and zero friction.

---

## How it works in real life: Maya and Sam

### Layer 1 (Default): Invisible BLAKE3 history binding — zero friction for everyone

Maya maintains `acme-tls`. Two teammates work with her; neither of them installs `git-signet`, and neither ever notices she did.

Maya runs one setup command on her laptop (requires Git 2.56+ for native `[hook]` configuration, leaving `core.hooksPath`, `git-lfs`, `pre-commit`, and `.git/hooks/*` untouched):

```text
$ git signet enable --global
Configured global native Git hooks (`hook.signet-*`; `core.hooksPath` untouched)
```

From that moment on, she keeps typing plain `git` (or using her editor's Git button):

```text
$ git add src/verify.c
$ git commit -m "Release 2.4.0"
[main 9f3c1a2] Release 2.4.0
 1 file changed, 14 insertions(+)

$ git tag -a v2.4.0 -m "Release 2.4.0"
$ git push --follow-tags
```

Look at what changed on GitHub: **nothing.** Commit `9f3c1a2` looks ordinary, tag `v2.4.0` is just `v2.4.0`, and downstream users keep depending on `v2.4.0` without changing a character. When Maya clones or fetches ordinary third-party repositories that have never heard of `git-signet`, it stays **completely silent** and skips hashing plain commit trees, so there are no warnings and no noticeable slowdowns.

Behind the scenes, each commit Maya creates carries hidden `signet-tree` and `signet-parent` headers containing **BLAKE3** digests in a standard Git commit header slot that stock Git already stores, transfers, and ignores. When teammates push plain commits and Maya later commits on top, her commit automatically binds their plain commits into the BLAKE3 chain too:

```text
... ──► [old history] ──► [9f3c1a2 Maya] ──► [a18d0e4 teammate] ──► [c4027b1 Maya]
                            has BLAKE3          plain commit          has BLAKE3
                                                                    (covers all of ←)
```

#### Years later: a silent SHA1DC exploit is uncovered in the wild

One Tuesday morning, an incident report drops:

> *While investigating a supply-chain compromise, responders discovered malicious files and trees in public Git mirrors whose **SHA1DC hashes match the SHA1DC hashes of legitimate objects**. An innocent-looking file had been contributed months earlier, and its malicious twin — sharing the exact same SHA1DC hash — was swapped into mirrors afterward. Forensics show the capability was used privately for at least 18 months before discovery.*

Notice why that last sentence matters: **nobody can assume that a SHA-1 commit ID they wrote down last month — or last year — is safe**, because the attacker may already have planted a twin with the exact same SHA1DC hash.

```text
                    SHA1DC ID      BLAKE3
Maya's real file    83a1d0...      4c91e7...
Mirror's twin file  83a1d0...      9902b1...   ← different!
                    ▲
              stock Git checks only this
```

Sam is an engineer who uses `acme-tls`. With stock Git alone on a poisoned mirror, `git fsck --full` stays completely silent — every SHA1DC hash matches.

Because Maya had `git-signet` enabled when she created `9f3c1a2`:

1. **Against a collision swap (even on a brand-new clone):** Commit `9f3c1a2` baked in the innocent file's **BLAKE3** tree digest when Maya committed it. The attacker swapped the file for its SHA1DC twin on the mirror without rewriting `9f3c1a2`. As soon as Sam clones or pulls:

   ```text
   $ git clone https://mirror.example/acme-tls.git
   Cloning into 'acme-tls'...
   git-signet: error: BLAKE3 verification failed for refs/remotes/origin/main:
     signet-tree mismatch at commit 9f3c1a2...: header a75286bb..., computed 09f13c82...
   fatal: in 'prepared' phase, update aborted by the reference-transaction hook
   ```

   Git aborts the clone before writing a single file to Sam's working tree.

2. **On Sam's existing clone or CI cache:** If a compromised server later serves a poisoned object during `git fetch`/`git pull` or `git fsck`, Sam's verified `signet-tree` and `signet-parent` headers catch it immediately.
3. **Sorting clean backups from poisoned mirrors:** Maya has five mirrors and laptops all reporting `HEAD = 9f3c1a2`. Running `git signet check HEAD --no-shallow` (or `git fsck` with the optional wrapper) immediately separates clean copies (`MATCH`) from poisoned twins.

---

### Layer 2 (Optional): Digest-bound release tags (`+blake3-<64>`)

What if an attacker goes beyond collisions and breaks SHA-1 **second-preimage** resistance — forging a brand-new commit with the exact SHA-1 `9f3c1a2` and stripping its BLAKE3 lines — while Sam is cloning for the very first time?

Whenever Maya wants a downstream dependency pin that survives even that worst case (without needing any keys), she can publish an optional **digest-bound tag** carrying the release's 256-bit BLAKE3 commit digest:

```sh
git tag "v2.4.0+blake3-$(git signet id v2.4.0)"
```

```toml
# Ordinary tag (keeps working for everyone):
acme-tls = { git = "https://github.com/acme/acme-tls", tag = "v2.4.0" }

# Optional digest-bound tag (valid Git tag & SemVer build metadata):
acme-tls = { git = "https://github.com/acme/acme-tls", tag = "v2.4.0+blake3-71e4b908fa2c03d19e5b44a2c8f01d6e3a7792b504c1e8f3a6d902b7e1c45f80" }
```

To stock Git and Cargo it is an ordinary tag name. To any machine running `git-signet`, cloning or fetching that tag enforces the embedded 256-bit BLAKE3 digest automatically.

---

### Layer 3 (Optional): Signet-bound repository and branch names (`.blincs-<52>`, `+blincs-<52>`)

Layer 1 and Layer 2 protect against hash breaks, but anyone who compromises the Git forge or steals a maintainer's forge token can still push a new commit with valid BLAKE3 headers.

When Maya also wants `git clone`, `git fetch`, and `git pull` to reject unauthorized commits automatically — with **no GPG, no certificate authority, no keyservers, and no `allowed_signers` file**, powered by [Signet](https://github.com/jasonhadler25/blincs) (an implementation of BLINCS, a stateless hash-based signature scheme based on BLAKE3 and SPHINCS) — she can opt into a **signet-bound name**.

In cryptography, these objects are commonly called a private signing key, a verifying key, and a signature. Here we call them a **`Signet`**, a **`SignetId`**, and an **`Imprint`**, because a `Signet` is a bearer capability — anyone who holds it can exercise its authority — while a `SignetId` names which signet you mean and verifies its imprints. We borrow this terminology from object-capability security because it makes authority boundaries easier to reason about; if you prefer the conventional names, the mapping is exact.

Maya generates and adopts a signet once on her machine:

```text
$ git signet keygen
Signet seed: ~/.config/git-signet/signets/blincs-74nfu4k2...pswa.seed
Signet ID:   blincs-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa
```

Then she puts that `SignetId` in a repository name or a branch name:

```text
# in the repository name (governs every branch and tag from the first clone):
git clone https://github.com/maya/acme-tls.blincs-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa

# or in a single branch name (no need to rename the repository):
git clone -b main+blincs-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa https://github.com/maya/acme-tls
```

From then on:
- **Zero per-repo setup for Maya:** wherever a repository URL or branch name carries a signet ID she has adopted, plain `git commit`, `git merge`, and `git rebase` automatically imprint with that signet (and elsewhere nothing changes).
- **Salted whole-snapshot imprinting:** every BLINCS imprint streams the commit metadata plus every mode, filename, gitlink, and raw file byte of the entire tree directly into `signet::Signet::imprint_reader` under a bounded domain-separation `Context` with a fresh per-imprint random salt (strictly single-threaded via `blake3-servil-core`, ~1.3 ms for typical repositories). Even a hypothetical unsalted collision break of SHA-1 or BLAKE3 cannot swap a file under an existing imprint, and even a shallow clone (`git clone --depth=1`) verifies the entire checked-out snapshot.
- **Native stock-Git verification:** imprints live in Git's standard `gpgsig` header (`gpg.format = x509`, `BLINCSg2` armor), so `git verify-commit HEAD`, `git verify-tag`, and `git log --show-signature` work out of the box.
- **No history rewriting for existing repos:** when Maya adopts a signet on an existing repository, old unimprinted commits and historical tags like `v2.4.0` keep working automatically via the **formal transitive-closure rule**: once a newer tip commit `T` is directly verified under Maya's `SignetId`, any ancestor commit `C` in `T`'s BLAKE3-verified ancestor closure is accepted too — while any rogue commit or tag outside `T`'s verified ancestry is refused before a single ref moves.
- **Contributors are never blocked locally:** your own local commits on `refs/heads/*` and `HEAD` in a non-bare working repository are never refused, with or without the signet.

---

## Summary of protection layers

| Threat | Stock Git | Layer 1 (default `enable`) | Layer 2 (`+blake3-` tag) | Layer 3 (`.blincs-` name) |
|---|---|---|---|---|
| Zero visible changes / zero collaborator friction | yes | **yes** | opt-in tag name | opt-in repo/branch name |
| SHA-1 / SHA1DC collision swap in files or history | exposed | **stopped** | **stopped** | **stopped** |
| Full SHA-1 second-preimage break on a pinned release | exposed | partial (existing clones) | **stopped** | **stopped** |
| Compromised Git forge / stolen forge token / rogue mirror | exposed | exposed | **stopped** (for pinned tag) | **stopped** (post-quantum) |
| Hypothetical unsalted BLAKE3 collision swap in tip snapshot | n/a | exposed | exposed | **stopped** (salted whole-snapshot) |

---

## Quick Start & Commands

Requires **Git 2.56+** and a Rust toolchain (or prebuilt binary).

```sh
cargo install --path .
git signet enable --global
```

Optional transparent `git` wrapper (install into a directory first on `PATH` so plain `git fsck` also runs `git-signet fsck`):

```sh
git signet enable --global --wrapper-dir ~/.local/bin
```

### Command reference

- `git signet enable [--global | --local] [--wrapper-dir <dir>]` — configure native Git 2.56+ `[hook]` entries (`post-commit`, `post-merge`, `post-rewrite`, `reference-transaction`), `gpg.x509.program` (if unset), and optional `git` wrapper.
- `git signet disable [--global | --local] [--wrapper-dir <dir>]` — cleanly remove hooks, `gpg.x509.program` (if set to `git-signet`), and optional wrapper.
- `git signet keygen [--file <path>]` — generate a new BLINCS signet seed (`0600`) and adopt it.
- `git signet adopt <seed-file>` / `unadopt <seed-file>` — manage automatic imprinting for names carrying that signet ID.
- `git signet format-id <seed-file>` — print a signet's canonical `blincs-<52>` ID.
- `git signet imprint-here <seed-file>` — imprint every commit in the current repository even without a signet-bound name.
- `git signet id [<rev>]` — print a commit's 64-hex BLAKE3 digest.
- `git signet check [<rev>] [--signet blincs-<52>] [--expect <64-hex>] [--no-shallow]` — verify BLAKE3 history, optional digest pin, and BLINCS authorization.
- `git signet fsck` — verify all refs in the repository.

---

## Limits you should know

- **Local commits are never refused** in a non-bare repository; enforcement checks what you fetch, clone, and audit.
- **Repository-wide signet names require every fetched branch/tag** to be authorized under that signet ID (directly or via the BLAKE3-verified transitive closure of an imprinted tip). A bot branch or forge web-UI merge commit on a `.blincs-` repository will fail verification; use a branch-scoped `+blincs-` name if you only want to constrain one branch.
- **No ref-name binding against replay:** a compromised server can serve an *older* genuinely imprinted commit under a signet-bound branch name unless you pin one exact commit with `+blake3-<64>`.
- **Clients that do not run Git's hooks** (for example `gix`, `jj`, or Cargo's built-in Git library) do not invoke `reference-transaction`; run `git signet check` / `git signet fsck` explicitly where hooks do not run.

See [SIGNET.md](SIGNET.md) for the exact specification, [SECURITY.md](SECURITY.md) for the threat model, [QUALITY.md](QUALITY.md) for verification gates and planted-fault controls, and [CONTRIBUTING.md](CONTRIBUTING.md) for development checks.

---

## Authorship & Licensing

This codebase and documentation were written primarily by an AI assistant working at the direction of the repository owner. No independent human cryptographic audit has been performed.

Licensed under `MIT OR Apache-2.0 OR TGPPL-1.0` (see [`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE), [`LICENSE-TGPPL`](LICENSE-TGPPL)), or optionally [`BOSL-1.0`](LICENSE-BOSL.txt).

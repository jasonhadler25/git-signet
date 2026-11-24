# git-signet

> **Pre-1.0 — Experimental & Unsupported.** This software is an early prototype under active design. Wire formats, commit headers, context strings, and CLI flags may change incompatibly before 1.0, and no independent human cryptographic audit has been performed. Do not rely on it to protect production repositories or high-stakes assets.

`git-signet` gives plain Git repositories two things without GPG, keyservers, or modifying stock Git:

1. **Self-authenticating post-quantum repository and branch names** powered by [BLINCS](https://github.com/jasonhadler25/blincs) (a pure-BLAKE3 stateless hash-based signature scheme): embed a 52-character `blincs-<id>` directly in a repository URL, branch name, or tag name so anyone who clones or fetches that name automatically verifies every commit's **salted whole-snapshot imprint** — covering both the commit metadata and every file byte in its tree without pre-hashing — before any ref moves.
2. **BLAKE3 tree and history binding** on every commit (`signet-tree` and `signet-parent` headers), protecting Git repositories from SHA-1 collisions and enabling immutable digest-bound refs (`+blake3-<64-hex>`).

In cryptography, these objects are commonly called a private signing key, a public verifying key, and a signature. Here we call them a **`Signet`**, a **`SignetId`**, and an **`Imprint`**, because a `Signet` is a bearer capability — anyone who holds it can exercise its authority — while a `SignetId` names which signet you mean and verifies its imprints. We borrow this terminology from object-capability security because it makes authority boundaries easier to reason about; if you prefer the conventional names, the mapping is exact.

## Three kinds of Git names

| Name kind | Example | What `git-signet` checks |
|---|---|---|
| **Plain name** | `main`, `https://github.com/org/repo.git` | Verifies any `signet-tree` / `signet-parent` BLAKE3 headers present on fetched commits. |
| **Digest-bound name** | `v1.0+blake3-<64-hex>` | Verifies the full BLAKE3 commit chain and requires the commit's BLAKE3 digest to equal `<64-hex>`. |
| **Signet-bound name** | `acme.blincs-<52>.git`, `main+blincs-<52>` | Verifies the BLAKE3 commit chain AND requires authorization under `blincs-<52>` via direct salted whole-snapshot BLINCS imprint or the BLAKE3-verified transitive ancestor closure of a directly verified imprinted commit. |

## Quick Start

Requires **Git 2.56+** (for native `[hook]` config that coexists cleanly with `core.hooksPath`, `git-lfs`, `pre-commit`, and `.git/hooks/*`).

```sh
cargo install --path .
git signet enable --global
```

Optionally install a transparent `git` wrapper directory first on `PATH` so `git fsck` automatically runs `git-signet fsck` after stock `git fsck`:

```sh
git signet enable --global --wrapper-dir ~/.local/bin
```

### Generate and adopt a signet

```sh
git signet keygen
```

This creates a 40-byte `BLINCSs1` seed file (`0600`) under `~/.config/git-signet/signets/<blincs-52>.seed`, initializes the per-machine BLINCS randomness state file (`~/.config/git-signet/randomness.state`), prints your `blincs-<52>` signet ID, and wires global Git `includeIf` rules.

Now name a repository `acme.blincs-<52>.git` or a branch `main+blincs-<52>` and use plain `git`:

```sh
git commit -m "ship feature"       # imprints whole snapshot with BLINCS + writes signet-tree/signet-parent
git verify-commit HEAD             # stock Git verifies via gpg.x509.program
git signet check HEAD --no-shallow # checks full BLAKE3 history + salted snapshot imprint
git push origin main
```

Anyone with `git-signet enable --global` who runs `git clone https://…/acme.blincs-<52>.git` or `git fetch` has every fetched ref verified in Git's `reference-transaction` (`prepared`) hook **before any local ref updates**. Forged commits, swapped files, wrong signets, and rogue tags are refused before touching `refs/`.

Local commits on `refs/heads/*` and `HEAD` in a non-bare working repository are never refused, so contributors who do not hold the repository's signet can still branch and commit locally.

## Commands

- `git signet enable [--global | --local] [--wrapper-dir <dir>]` — configure Git 2.56+ `[hook]` entries (`post-commit`, `post-merge`, `post-rewrite`, `reference-transaction`), `gpg.x509.program`, and optional `git` wrapper.
- `git signet disable [--global | --local] [--wrapper-dir <dir>]` — remove `git-signet` hooks and wrapper.
- `git signet keygen [--file <path>]` — generate a new BLINCS signet seed and adopt it.
- `git signet adopt <seed-file>` / `unadopt <seed-file>` — manage automatic imprinting for names carrying that signet ID.
- `git signet format-id <seed-file>` — print the canonical `blincs-<52>` signet ID for a seed file.
- `git signet imprint-here <seed-file>` — imprint every commit in the current repository even when its URL/branch does not carry the signet ID.
- `git signet id [<rev>]` — print a commit's 64-hex BLAKE3 digest.
- `git signet check [<rev>] [--signet blincs-<52>] [--expect <64-hex>] [--no-shallow]` — verify BLAKE3 history, optional digest pin, and BLINCS authorization.
- `git signet fsck` — verify all refs in the repository.

## Design & Documentation

- [SIGNET.md](SIGNET.md) — complete wire format, canonical encodings, context strings, salted snapshot framing, and formal transitive-closure rule.
- [SECURITY.md](SECURITY.md) — cryptographic assumptions, threat model, randomness state handling, and non-goals.
- [QUALITY.md](QUALITY.md) — verification gates, zero-tolerance safety counts, planted-fault controls, and bug ledger.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to run the exact-commit landing gate.

## Authorship & Licensing

This codebase and documentation were written primarily by an AI assistant working at the direction of the repository owner. No independent human cryptographic audit has been performed.

Dual-licensed under `MIT OR Apache-2.0`.

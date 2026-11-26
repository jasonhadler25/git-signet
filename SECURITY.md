# Security Policy

> **Pre-1.0 — Experimental & Unsupported.** This software is an early prototype. Formats and interfaces may change incompatibly before 1.0, and **no independent human cryptographic audit has been performed**.

## Cryptographic Properties & Assumptions

`git-signet` relies exclusively on **BLAKE3** (both directly for `signet-tree` / `signet-parent` binding via strictly single-threaded `blake3-servil-core` and inside [Signet](https://github.com/jasonhadler25/blincs)'s `BLINCS-128-7x5` implementation):

1. **Salted whole-snapshot BLINCS imprints (tip commits and imprinted tags):**
   - Every commit or tag imprint streams the object bytes plus every filename, mode, gitlink, and raw file byte of the entire tree directly into `signet::Signet::imprint_reader` / `SignetId::verify_reader` under a bounded length-framed BLINCS `Context` with a fresh per-imprint random salt.
   - Forging a different file or tree under an existing imprint does **not** reduce to finding an unsalted SHA-1 or BLAKE3 collision; it requires breaking BLAKE3's salted second-preimage / target-collision resistance or BLINCS's hash-based security bounds.
   - Even a shallow clone (`git clone --depth=1`) cryptographically verifies the entire checked-out snapshot at `HEAD`.
2. **Unsalted BLAKE3 tree and history binding (`signet-tree`, `signet-parent`, `+blake3-<64>`):**
   - Used where independent parties must derive the same digest without coordinating: history chains, multi-parent merges, digest-bound refs (`+blake3-<64>`), and the transitive ancestor closure rule for historical tags.
   - Replaces Git's SHA-1 object hashes with 256-bit domain-separated BLAKE3 digests while remaining 100% compatible with stock SHA-1 Git servers.

## Operational Security Boundaries

- **Bearer capability (`Signet` seed file):** `~/.config/git-signet/signets/<blincs-52>.seed` (`0600`) is a bearer capability. Anyone who copies those 40 bytes can produce valid imprints for `<blincs-52>`.
- **Per-machine randomness directory (`randomness/`):** `signet::Randomness` mixes OS randomness with a lock-free `0700` seed directory (`~/.config/git-signet/randomness`). Do not clone or replay a VM snapshot containing `randomness/` alongside an active signet seed without reinitializing the directory.
- **Git subprocess hardening:** Every Git invocation forces `--no-replace-objects`, `GIT_NO_REPLACE_OBJECTS=1`, and `GIT_NO_LAZY_FETCH=1`, rejects non-SHA-1 repositories, caps metadata reads at 64 MiB, and never relies on `.git/signet-cache.bin` during verification or imprinting.
- **What `git-signet` does NOT protect against:**
  - Compromised local machines, malicious hooks or binaries in `PATH`, or someone who already stole your `.seed` file.
  - Replay/freeze attacks by a compromised Git host serving an *older* genuinely imprinted commit (use a `+blake3-<64>` digest-bound name when you need to pin one exact commit).
  - Submodule working-tree contents beyond the 20-byte gitlink OID recorded in the parent tree (give the submodule itself a signet-bound or digest-bound URL/ref).

## Reporting Issues

Open an issue on the repository or contact the repository owner directly. Because this is pre-1.0 experimental software, there is no security SLA or bug-bounty program.

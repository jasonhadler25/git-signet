# Security Policy

> **Pre-1.0 — Experimental & Unsupported.** This software is an early prototype. Formats and interfaces may change incompatibly before 1.0, and **no independent human cryptographic audit has been performed**.

## Cryptographic Properties & Assumptions

`git-signet` relies exclusively on **BLAKE3** (both directly for `signet-tree` / `signet-parent` binding via strictly single-threaded `blake3-servil-core` and inside [Signet](https://github.com/jasonhadler25/signet)'s `BLINCS-128-A2` implementation):

1. **Salted whole-snapshot BLINCS imprints (tip commits and imprinted tags):**
   - Every commit or tag imprint pushes the object bytes plus every filename, mode, gitlink, and raw file byte of the entire tree directly into `signet::Signet::imprint_with` / `SignetId::verify_with` under a bounded length-framed BLINCS `Context` with a fresh per-imprint random salt.
   - Forging a different file or tree under an existing imprint does **not** reduce to finding an unsalted SHA-1 or BLAKE3 collision; it requires breaking BLAKE3's salted second-preimage / target-collision resistance or BLINCS's hash-based security bounds.
   - Even a shallow clone (`git clone --depth=1`) cryptographically verifies the entire checked-out snapshot at `HEAD`.
2. **Unsalted BLAKE3 tree and history binding (`signet-tree`, `signet-parent`, `+blake3-<64>`):**
   - Used where independent parties must derive the same digest without coordinating: history chains, multi-parent merges, digest-bound refs (`+blake3-<64>`), and the transitive ancestor closure rule for historical tags.
   - Replaces Git's SHA-1 object hashes with 256-bit domain-separated BLAKE3 digests while remaining 100% compatible with stock SHA-1 Git servers.

## Operational Security Boundaries

- **Bearer capability (`Signet` seed file):** `~/.config/git-signet/signets/<blincs-52>.seed` (`0600`) is a bearer capability. Anyone who copies those 40 bytes can produce valid imprints for `<blincs-52>`.
- **Per-machine randomness state file (`salt`):** `signet::Randomness` mixes OS randomness (`getrandom`), process ID, monotonic clock, and a single private `0600` 32-byte state file (`~/.config/git-signet/salt`) rotated lock-free via atomic `rename`. Do not clone or replay a VM snapshot containing `salt` alongside an active signet seed without reinitializing the state file.
- **Strict local signing boundary:** `post-commit` / `post-merge` / `post-rewrite` hooks never acquire a private signet on the strength of an unverified embedded ID or fall back to global `~/.config/git-signet/signets/` seeds without an active `user.signingkey` configured in the repository. Re-imprinting after adding BLAKE3 headers requires cryptographically verifying the pre-header imprint first, and `post-merge` never rewrites fast-forwarded or remote-reachable commits. The `prepared` `reference-transaction` hook is strictly read-only.
- **Git subprocess hardening:** Object-store commands run through a single `git cat-file --batch-command` session that forces `--no-replace-objects`, `GIT_NO_REPLACE_OBJECTS=1`, and `GIT_NO_LAZY_FETCH=1`, automatically killing and reaping the child on any framing error or early abort. Verification rejects non-SHA-1 repositories, enforces strict `tree` + contiguous `parent` commit header layout, caps metadata reads at 64 MiB before allocation, bounds snapshot expansion (`1,000,000` entries / `16 GiB`) and armor size (`16 KiB`), writes managed gitconfig files via `git config --file` + atomic rename, and uses memory-only digest maps (no unauthenticated disk cache). Stock `git verify-commit` emits `TRUST_UNDEFINED` (`%G? = U`) because embedded-key verification proves snapshot integrity without an external pinned-policy check; use `git signet check` / `git signet fsck` for policy enforcement.
- **What `git-signet` does NOT protect against:**
  - Compromised local machines, malicious hooks or binaries in `PATH`, or someone who already stole your `.seed` file.
  - Replay/freeze attacks by a compromised Git host serving any older authorized target under the same `SignetId` (including historical ancestors in the transitive closure, or ref deletions); use a `+blake3-<64>` digest-bound name when you need to pin one exact commit.
  - Unsigned annotated tag metadata (tag message/tagger/name) when authorized via transitive closure (closure authorizes the target commit only).
  - Submodule working-tree contents beyond the 20-byte gitlink OID recorded in the parent tree (give the submodule itself a signet-bound or digest-bound URL/ref).

## Reporting Issues

Open an issue on the repository or contact the repository owner directly. Because this is pre-1.0 experimental software, there is no security SLA or bug-bounty program.

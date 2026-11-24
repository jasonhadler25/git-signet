# Quality & Verification

`git-signet` follows a fail-closed, zero-`unsafe` build and verification discipline modeled on the companion [`blincs`](https://github.com/jasonhadler25/blincs) crate.

## Landing Gate (`python3 tools/land.py`)

Every commit must pass all gates on a clean working tree:

1. **Formatting:** `cargo fmt -- --check`
2. **Shipped safety counts (`tools/counts.py`):**
   - `unsafe_blocks = 0` (`#![forbid(unsafe_code)]` at crate and manifest level)
   - `debug_asserts = 0` (runtime invariants stay active in release builds)
   - `truncation_allows = 0` (narrowing integer casts denied in `[lints.clippy]`)
   - `drop_impls = 0` (no custom destructors in shipped library code)
3. **Static analysis:** `cargo clippy --all-targets --locked -- -D warnings`
4. **Process-isolated tests:** `cargo nextest run --locked` (enforced by `tools/require_nextest.rs`), running end-to-end against real stock `git` subprocesses, plus `cargo test --doc --locked`.
5. **Planted-fault verification controls (`tools/controls.py`):** copies the tree into a temporary directory, injects 8 targeted security defects one at a time, and requires every defect to fail the test suite:
   - `skip_direct_imprint_check`
   - `skip_signet_tree_compare`
   - `skip_transitive_closure_rejection`
   - `drop_base32_pad_check`
   - `skip_snapshot_tree_walk`
   - `skip_armor_magic_check`
   - `allow_conflicting_signets`
   - `disable_no_shallow_enforcement`

## Bugs Caught by These Checks During Development

1. **Symbolic ref updates in `reference-transaction` (`git init`):** Real-Git integration tests immediately caught `git init` passing `ref:refs/heads/main` (19 chars) as the new-object token in `reference-transaction`; handled cleanly by skipping `ref:` symbolic updates.
2. **Git `includeIf` globbing across `/`:** Real-Git tests caught that `hasconfig:remote.*.url:*<marker>.git` does not match absolute paths with `/` unless prefixed with `**/*`; fixed using the four `**/*<marker>*` / `**/*<marker>*/**` patterns.
3. **Stock `git verify-commit` X.509 status format:** Real-Git tests caught that Git's `gpgsm` parser requires `[GNUPG:] NEWSIG`, a non-zero Unix timestamp in `VALIDSIG`, and `TRUST_FULLY 0 shell` before setting `%G? = G` and exit status `0`.
4. **`git merge` fires `post-merge`, not `post-commit`:** The 2-parent merge integration test caught that non-fast-forward merge commits bypassed `post-commit` and lacked `signet-parent` headers; fixed with `hook.signet-post-merge` (guarded by `parents.len() >= 2` so fast-forward merges/pulls are never rewritten).
5. **Untested zero-commit-change tree blob tampering:** Planted-fault control `skip_snapshot_tree_walk` passed initially because our first tree-swap test altered the commit's `tree` line rather than mutating streamed file bytes under identical commit bytes; fixed by asserting exact `SnapshotReader` file-byte streaming and 1-bit blob-flip rejection in `tests/integration.rs`.
6. **Dead redundant shallow check:** Planted-fault control `disable_no_shallow_enforcement` revealed that `check_revision`'s secondary `if no_shallow && report.shallow_boundary_hit` branch was unreachable because `verify_commit_chain` already refuses missing parents when `allow_shallow = false`; deleted the dead branch and aimed the control at the real enforcement site in `src/blake3_chain.rs`.
7. **Plain-repo fetch slowdown & non-clobbering `gpg.x509.program`:** Auditing zero-friction defaults caught that `verify_commit_chain` previously hashed plain commit trees on ordinary repos without `signet-*` headers, and that `enable` unconditionally overwrote `gpg.x509.program`; fixed both (with `plain_repo_zero_warnings_and_preserves_custom_x509_program` regression test; full `fsck` on a multi-thousand-commit plain monorepo runs in ~0.3s with zero warnings).
8. **`SIGNET.md` §3.3 `signet-parent` format mismatch:** Live dogfooding (`git cat-file commit HEAD` on our very first `git-signet` commit) caught that `SIGNET.md` listed a redundant `<40-hex-parent-oid>` field not emitted by `signet-parent blake3 <64-hex-D_commit>`; aligned `SIGNET.md` to match the wire format.

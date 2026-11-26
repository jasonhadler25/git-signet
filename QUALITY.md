# Quality & Verification

`git-signet` follows a fail-closed, zero-`unsafe` build and verification discipline modeled on the companion [`signet`](https://github.com/jasonhadler25/blincs) crate.

## Landing Gate (`python3 tools/land.py`)

Every commit must pass all gates on a clean working tree:

1. **Supply-chain hashsets:** `cargo fetch --locked` + `python3 tools/cargo_lock_hashsets.py` verifies BLAKE3 + SHA-256 hashsets for every registry crate in `Cargo.lock` before building.
2. **Formatting:** `cargo fmt -- --check`
3. **Shipped safety counts (`tools/counts.py`):**
   - `unsafe_blocks = 0` (`#![forbid(unsafe_code)]` at crate and manifest level)
   - `debug_asserts = 0` (runtime invariants stay active in release builds)
   - `truncation_allows = 0` (narrowing integer casts denied in `[lints.clippy]`)
   - `drop_impls = 0` (no custom destructors in shipped library code)
4. **Static analysis & docs:** `cargo clippy --all-targets --locked -- -D warnings` and `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked`
5. **Process-isolated tests:** `cargo nextest run --locked` (enforced by `tools/require_nextest.rs`), running 13 end-to-end suites against real stock `git` subprocesses, plus `cargo test --doc --locked`.
6. **Planted-fault verification controls (`tools/controls.py`):** copies the tree into a temporary directory, injects **14** targeted security defects one at a time, and requires every defect to compile cleanly and fail tests (`exit 100`, never build errors):
   - `skip_direct_imprint_check`
   - `skip_signet_tree_compare`
   - `skip_transitive_closure_rejection`
   - `drop_base32_pad_check`
   - `skip_snapshot_tree_walk`
   - `skip_armor_magic_check`
   - `allow_conflicting_signets`
   - `disable_no_shallow_enforcement`
   - `drop_snapshot_context`
   - `c1_skip_verify_before_reimprint`
   - `c2_ignore_malformed_ref_tx_line`
   - `h1_tag_imprint_delegates_closure`
   - `h5_allow_conflicting_expect_pin`
   - `h5_skip_expected_signet_id_match`

## Bugs Caught by These Checks During Development

1. **Symbolic ref updates in `reference-transaction` (`git init`):** Real-Git integration tests immediately caught `git init` passing `ref:refs/heads/main` (19 chars) as the new-object token in `reference-transaction`; handled cleanly by skipping `ref:` symbolic updates.
2. **Git `includeIf` globbing across `/`:** Real-Git tests caught that `hasconfig:remote.*.url:*<marker>.git` does not match absolute paths with `/` unless prefixed with `**/*`; fixed using the four `**/*<marker>*` / `**/*<marker>*/**` patterns.
3. **Stock `git verify-commit` X.509 status format:** Real-Git tests caught that Git's `gpgsm` parser requires `[GNUPG:] NEWSIG`, a non-zero Unix timestamp in `VALIDSIG`, and `TRUST_FULLY 0 shell` before setting `%G? = G` and exit status `0`.
4. **`git merge` fires `post-merge`, not `post-commit`:** The 2-parent merge integration test caught that non-fast-forward merge commits bypassed `post-commit` and lacked `signet-parent` headers; fixed with `hook.signet-post-merge` (guarded by `parents.len() >= 2` so fast-forward merges/pulls are never rewritten).
5. **Untested zero-commit-change tree blob tampering:** Planted-fault control `skip_snapshot_tree_walk` passed initially because our first tree-swap test altered the commit's `tree` line rather than mutating streamed file bytes under identical commit bytes; fixed by asserting exact `SnapshotReader` file-byte streaming and 1-bit blob-flip rejection in `tests/integration.rs`.
6. **Dead redundant shallow check:** Planted-fault control `disable_no_shallow_enforcement` revealed that `check_revision`'s secondary `if no_shallow && report.shallow_boundary_hit` branch was unreachable because `verify_commit_chain` already refuses missing parents when `allow_shallow = false`; deleted the dead branch and aimed the control at the real enforcement site in `src/blake3_chain.rs`.
7. **Plain-repo fetch slowdown & non-clobbering `gpg.x509.program`:** Auditing zero-friction defaults caught that `verify_commit_chain` previously hashed plain commit trees on ordinary repos without `signet-*` headers, and that `enable` unconditionally overwrote `gpg.x509.program`; fixed both (with `plain_repo_zero_warnings_and_preserves_custom_x509_program` regression test; full `fsck` on a multi-thousand-commit plain monorepo runs in ~0.3s with zero warnings).
8. **`SIGNET.md` §3.3 `signet-parent` format mismatch:** Live dogfooding (`git cat-file commit HEAD` on our very first `git-signet` commit) caught that `SIGNET.md` listed a redundant `<40-hex-parent-oid>` field not emitted by `signet-parent blake3 <64-hex-D_commit>`; aligned `SIGNET.md` to match the wire format.
9. **Spec-vs-code wire audit on `SIGNET.md` §§3–4 and licenses:** Full doc/comment reread caught `SIGNET.md` describing `BLAKE3_keyed` instead of `BLAKE3_derive_key` (`Mode::DeriveKeyWith`), a stale `TreeWalk` framing description that differed from `src/snapshot.rs`'s NUL-delimited Git-native framing, and missing `LICENSE-*` files referenced by `Cargo.toml`; aligned all three cleanly.
10. **Independent Astra security audit (`C1`, `C2`, `H1`–`H7`, `M1`–`M9`) & release `cargo-mutants` sweep:** Caught hook re-imprinting without verifying the pre-header imprint or checking active repo `user.signingkey` (`C1`), Unicode `split_whitespace()` silently dropping valid ref-transaction lines (`C2`), reachability vs BLAKE3-authenticated ancestry & annotated-tag closure delegation (`H1`), unauthenticated `stop_at` checkpoint skipping (`H2`), bare server directory name governance & config error propagation (`H3`), prepared hook mutating `.git/config` & raw config string interpolation (`H4`/`M6`), bogus `TRUST_FULLY` X.509 status & overriding `--expect`/`--signet` flags (`H5`), carrying-commit missing-object swallowing (`H6`), pre-allocation metadata caps & `SnapshotReader` work bounds (`H7`), unauthenticated disk cache on header emission (`M5`), disappearing post-transaction witnesses (`M3`), and wrapper `fsck` failure swallowing (`M9`). Fixed all of them and guarded each with dedicated negative regression tests and 5 new planted-fault controls. A release-mode `cargo-mutants` sweep over `src/id.rs`, `src/blake3_chain.rs`, and `src/snapshot.rs` (515 mutants) caught 394 viable mutants (90.4% of non-timeout viable mutants; remaining survivors are disjoint-bit `|` vs `^` equivalents and 16 GiB / 1M-entry / 4096-depth DoS ceiling guards), removed a dead cache-height branch, added a compile-time `MAX_SNAPSHOT_BYTES` assert, and closed 24 boundary/parser gaps with dedicated tests.

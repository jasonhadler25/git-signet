# Contributing

Before opening a pull request or landing a commit, run the full landing gate:

```sh
python3 tools/land.py
```

(During development with uncommitted edits, pass `--skip-clean-check`.)

## Conventions

- Keep `#![forbid(unsafe_code)]`, zero `debug_assert!`, zero `cast_possible_truncation` allows, and zero `Drop` impls in `src/`.
- Run tests with `cargo nextest run --locked` (each test runs in its own isolated process).
- Keep dependencies minimal (`signet` and strictly single-threaded `blake3-servil-core` only).
- Follow the project vocabulary: **signet** (`Signet`), **signet ID** (`SignetId`), **imprint** (`Imprint`, noun & verb), **digest-bound name**, **signet-bound name**.

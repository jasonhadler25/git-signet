#!/usr/bin/env python3
"""Exact-commit landing gate for git-signet."""

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(cmd, label):
    print(f"=== {label} ===")
    res = subprocess.run(cmd, cwd=ROOT)
    if res.returncode != 0:
        print(f"FAIL: {label} (exit {res.returncode})", file=sys.stderr)
        sys.exit(res.returncode)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-clean-check", action="store_true")
    ap.add_argument("--skip-controls", action="store_true")
    args = ap.parse_args()

    if not args.skip_clean_check:
        st = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
        if st:
            print("FAIL: working tree is dirty; commit before running exact-commit land gate.", file=sys.stderr)
            print(st, file=sys.stderr)
            sys.exit(1)

    run(["cargo", "fetch", "--locked"], "cargo fetch")
    run([sys.executable, "tools/cargo_lock_hashsets.py"], "Cargo.lock hashsets (BLAKE3 + SHA-256)")
    run(["cargo", "fmt", "--", "--check"], "rustfmt check")
    run([sys.executable, "tools/counts.py"], "shipped safety counts")
    run(["cargo", "clippy", "--all-targets", "--locked", "--", "-D", "warnings"], "clippy (-D warnings)")
    doc_env = os.environ.copy()
    doc_env["RUSTDOCFLAGS"] = "-D warnings"
    print("=== rustdoc (-D warnings) ===")
    res = subprocess.run(["cargo", "doc", "--no-deps", "--locked"], cwd=ROOT, env=doc_env)
    if res.returncode != 0:
        print(f"FAIL: rustdoc (-D warnings) (exit {res.returncode})", file=sys.stderr)
        sys.exit(res.returncode)
    run(["cargo", "nextest", "run", "--locked"], "cargo nextest")
    run(["cargo", "test", "--doc", "--locked"], "doctests")
    if not args.skip_controls:
        run([sys.executable, "tools/controls.py"], "planted-fault controls")

    print("ALL GATES PASSED.")


if __name__ == "__main__":
    main()

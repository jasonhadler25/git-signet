#!/usr/bin/env python3
"""Shipped-code safety counts for git-signet (zero-tolerance invariants)."""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT, "src")

ZERO_PATTERNS = {
    "unsafe_blocks": re.compile(r"\bunsafe\b"),
    "debug_asserts": re.compile(r"\bdebug_assert(?:_eq|_ne)?!"),
    "truncation_allows": re.compile(r"allow\([^)]*cast_possible_truncation"),
    "drop_impls": re.compile(r"\bimpl\b[^{]*\bDrop\b\s+for\b"),
}


def strip_comments_and_strings(src):
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            i += 2
            while i + 1 < n and depth > 0:
                if src[i] == "/" and src[i + 1] == "*":
                    depth += 1
                    i += 2
                elif src[i] == "*" and src[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
        elif c == '"':
            out.append('"')
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            if i < n:
                out.append('"')
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def count_tree(files):
    totals = {k: 0 for k in ZERO_PATTERNS}
    totals["shipped_code_lines"] = 0
    totals["cfg_conditions"] = 0
    for src in files.values():
        cleaned = strip_comments_and_strings(src)
        for line in cleaned.splitlines():
            if line.strip():
                totals["shipped_code_lines"] += 1
        for key, pat in ZERO_PATTERNS.items():
            totals[key] += len(pat.findall(cleaned))
        totals["cfg_conditions"] += len(re.findall(r"#\[cfg\(", cleaned))
    return totals


def main():
    files = {}
    for fname in sorted(os.listdir(SRC_DIR)):
        if fname.endswith(".rs"):
            files[fname] = open(os.path.join(SRC_DIR, fname)).read()
    totals = count_tree(files)
    print("Shipped counts:", ", ".join(f"{k}={v}" for k, v in totals.items()))
    bad = [k for k in ZERO_PATTERNS if totals[k] != 0]
    if bad:
        print(f"FAIL: non-zero forbidden count(s): {bad}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

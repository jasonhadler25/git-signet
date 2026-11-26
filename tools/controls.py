#!/usr/bin/env python3
"""Planted-fault verification controls for git-signet.

Copies the repository to a temporary directory, injects one security defect at a time
into `src/`, runs `cargo nextest run --locked`, and requires every planted defect to
cause a test failure. Never mutates the working tree.
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONTROLS = [
    (
        "skip_direct_imprint_check",
        "src/hooks.rs",
        'Err(msg) if msg.contains("missing gpgsig header") => Ok(None),',
        'Err(msg) if msg.contains("missing gpgsig header") => Ok(Some(*oid)),',
    ),
    (
        "skip_signet_tree_compare",
        "src/blake3_chain.rs",
        "if actual_tree != *expected_tree {",
        "if false && actual_tree != *expected_tree {",
    ),
    (
        "skip_transitive_closure_rejection",
        "src/hooks.rs",
        "let ok = authorized_ancestors.get(sid.as_bytes()).is_some_and(|set| set.contains(&commit_oid));",
        "let ok = true || authorized_ancestors.get(sid.as_bytes()).is_some_and(|set| set.contains(&commit_oid));",
    ),
    (
        "drop_base32_pad_check",
        "src/id.rs",
        "if (buf & 0x0f) != 0 {",
        "if false && (buf & 0x0f) != 0 {",
    ),
    (
        "skip_snapshot_tree_walk",
        "src/snapshot.rs",
        "let entries = parse_git_tree(&raw)?;",
        "let entries = if false { parse_git_tree(&raw)? } else { Vec::new() };",
    ),
    (
        "skip_armor_magic_check",
        "src/id.rs",
        "if raw.len() != ARMOR_RAW_LEN || &raw[..ARMOR_MAGIC.len()] != ARMOR_MAGIC {",
        "if raw.len() != ARMOR_RAW_LEN {",
    ),
    (
        "allow_conflicting_signets",
        "src/id.rs",
        'return Err(format!("conflicting blincs signet IDs in refname {refname:?}"));',
        'let _ = (prev, id);',
    ),
    (
        "disable_no_shallow_enforcement",
        "src/blake3_chain.rs",
        "let grafts = if allow_shallow { load_shallow_grafts(repo) } else { HashSet::new() };",
        "let grafts = if true || allow_shallow { load_shallow_grafts(repo) } else { HashSet::new() };",
    ),
    (
        "drop_snapshot_context",
        "src/snapshot.rs",
        "match embedded_id.verify_reader(ctx, reader, &imprint) {",
        "match embedded_id.verify_reader(Context::EMPTY, reader, &imprint) {",
    ),
]


def main():
    tmp = tempfile.mkdtemp(prefix="git-signet-controls-")
    try:
        work = os.path.join(tmp, "repo")
        shutil.copytree(
            ROOT,
            work,
            ignore=shutil.ignore_patterns(".git", "target"),
        )
        # Share target directory with ROOT's target so incremental builds take ~1s per control.
        target_dir = os.path.join(tmp, "target")
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = target_dir

        # Baseline must pass cleanly first.
        base = subprocess.run(
            ["cargo", "nextest", "run", "--locked", "--no-fail-fast"],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
        )
        if base.returncode != 0:
            print("FAIL: clean baseline did not pass!", file=sys.stderr)
            print(base.stdout, file=sys.stderr)
            print(base.stderr, file=sys.stderr)
            return 1

        caught = 0
        for name, rel_path, old, new in CONTROLS:
            full = os.path.join(work, rel_path)
            orig = open(full).read()
            if orig.count(old) != 1:
                print(
                    f"FAIL: control {name}: pattern appeared {orig.count(old)} times in {rel_path}",
                    file=sys.stderr,
                )
                return 1
            open(full, "w").write(orig.replace(old, new, 1))
            try:
                res = subprocess.run(
                    ["cargo", "nextest", "run", "--locked"],
                    cwd=work,
                    env=env,
                    capture_output=True,
                    text=True,
                )
            finally:
                open(full, "w").write(orig)

            if res.returncode == 0:
                print(f"FAIL: planted fault {name} was NOT caught!", file=sys.stderr)
                return 1
            caught += 1
            print(f"  CAUGHT ({caught}/{len(CONTROLS)}): {name}")

        print(f"PASS: all {caught}/{len(CONTROLS)} planted faults caught.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

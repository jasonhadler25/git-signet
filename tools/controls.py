#!/usr/bin/env python3
"""Planted-fault verification controls for git-signet.

Copies the repository to a temporary directory, injects one security defect at a time
into `src/`, runs `cargo nextest run --locked`, and requires every planted defect to
compile cleanly and cause a test failure (exit code 100, never compile error 101).
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
        "ExtractedArmor::Absent => Ok(None),",
        "ExtractedArmor::Absent => Ok(Some(DirectAuth::Commit(*oid))),",
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
        "let _ = (prev, id);",
    ),
    (
        "disable_no_shallow_enforcement",
        "src/blake3_chain.rs",
        "let grafts: HashSet<Oid> = if allow_shallow { repo.shallow.clone() } else { HashSet::new() };",
        "let grafts: HashSet<Oid> = if true || allow_shallow { repo.shallow.clone() } else { HashSet::new() };",
    ),
    (
        "drop_snapshot_context",
        "src/snapshot.rs",
        "match embedded_id.verify_reader(ctx, &mut reader, &imprint) {",
        "match embedded_id.verify_reader(Context::EMPTY, &mut reader, &imprint) {",
    ),
    (
        "c1_skip_verify_before_reimprint",
        "src/hooks.rs",
        'verify_payload_imprint(repo, ObjKind::Commit, &orig_payload, &armor, Some(&embedded_id))\n                    .map_err(|e| format!("refusing to re-imprint commit with unverified BLINCS imprint: {e}"))?;',
        "let _ = &orig_payload;",
    ),
    (
        "c2_ignore_malformed_ref_tx_line",
        "src/hooks.rs",
        'return Err("malformed reference-transaction record: missing second ASCII space".into());',
        "continue;",
    ),
    (
        "h1_tag_imprint_delegates_closure",
        "src/hooks.rs",
        "                Some(DirectAuth::Tag(_)) => {\n                    // Directly imprinted annotated tag authorizes THIS tag itself (SIGNET.md §5.2(b)),",
        "                Some(DirectAuth::Tag(_)) => {\n                    authorized_ancestors.entry(*sid.as_bytes()).or_default().insert(commit_oid);\n                    if let Ok((_, raw_c)) = repo.read_object(&commit_oid) && let Ok(p) = parse_commit(raw_c) { authorized_ancestors.entry(*sid.as_bytes()).or_default().extend(p.parents); }\n                    // Directly imprinted annotated tag authorizes THIS tag itself (SIGNET.md §5.2(b)),",
    ),
    (
        "h5_allow_conflicting_expect_pin",
        "src/hooks.rs",
        '(Some(a), Some(b)) if a != b => {\n            return Err(format!("conflicting BLAKE3 expectations: refname pins {}, --expect requests {}", to_hex(&a), to_hex(&b)));\n        }',
        "(Some(_), Some(b)) => Some(b),",
    ),
    (
        "h5_skip_expected_signet_id_match",
        "src/snapshot.rs",
        "if let Some(exp) = expected_id\n        && embedded_id != *exp\n    {",
        "if false && let Some(exp) = expected_id && embedded_id != *exp {",
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
        target_dir = os.path.join(tmp, "target")
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = target_dir

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
            if res.returncode != 100 or "failed" not in (res.stdout + res.stderr):
                print(
                    f"FAIL: planted fault {name} exited {res.returncode} (expected 100 test failure, not build error):\n{res.stdout}\n{res.stderr}",
                    file=sys.stderr,
                )
                return 1
            caught += 1
            print(f"  CAUGHT ({caught}/{len(CONTROLS)}): {name}")

        print(f"PASS: all {caught}/{len(CONTROLS)} planted faults caught.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

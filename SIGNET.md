# git-signet Specification (v0.4.0, Pre-1.0)

> **Pre-1.0 — Experimental & Unsupported.** This specification is not yet frozen and may change incompatibly before 1.0.

This document defines every byte format, domain-separation string, name grammar, and verification rule implemented by `git-signet`.

---

## 1. Signet IDs and Digest Pins in Git Names

### 1.1 Signet ID encoding (`blincs-<52>`)
A BLINCS `SignetId` is 32 bytes (256 bits). Its canonical text encoding is:
- Prefix: `blincs-` (7 ASCII bytes)
- Payload: 52 characters of **unpadded lowercase RFC 4648 base32** (`a-z`, `2-7`), encoding 256 bits into `52 × 5 = 260` bits with the **4 trailing padding bits strictly zero** (so the 52nd character is always `a` or `q`).
- Decoders MUST reject uppercase characters, `=`, wrong lengths, non-base32 characters, and non-zero trailing padding bits.

### 1.2 Extracting signet IDs from names
- **Remote URLs:** strip trailing `/`, `?query`, `#fragment`, take the last `/` or `:` path component, strip optional trailing `.git`, and scan for `.blincs-<52>` (or exact `blincs-<52>`).
- **Ref names:** split by `/`, and in each segment scan at start-of-segment, after `.`, or after `+` for `blincs-<52>` delimited by end-of-segment, `.`, or `+`.
- **Fail-closed rules:**
  - If a segment contains `blincs-` followed by `>= 40` non-delimiter characters (or walk operators `~`, `^`, `@`, `:`) that fail strict decoding, reject as malformed (catching typos or truncation).
  - If a ref name contains `^`, `~`, or `..` alongside a signet ID, reject as ambiguous.
  - If two different signet IDs appear in the same ref name, or if a ref's signet ID disagrees with its remote URL's signet ID, reject as conflicting.

### 1.3 Digest-bound names (`+blake3-<64>`)
- A ref name segment may contain `+blake3-<64-lowercase-hex>` (or `.blake3-<64-lowercase-hex>`), naming an exact 32-byte BLAKE3 commit digest.
- `+blake3-<64>` and `+blincs-<52>` may appear in the same ref name in either order.
- Conflicting `+blake3-` digests or malformed 40+-character `blake3-` tokens are rejected.

---

## 2. BLINCS Imprint Armor (`BLINCSg2`)

Imprints are stored in Git's standard `gpgsig` commit header (or appended to annotated tag payloads) using X.509/CMS-compatible PEM framing so stock Git (`gpg.format = x509`) handles insertion and `git verify-commit` / `git verify-tag` natively:

```text
-----BEGIN SIGNED MESSAGE-----
<strict RFC 4648 base64, 64 chars per line>
-----END SIGNED MESSAGE-----
```

The decoded binary payload is **exactly 3,332 bytes**:

| Offset | Length | Contents |
|---|---|---|
| `0` | `8` | ASCII magic `BLINCSg2` |
| `8` | `32` | `SignetId` bytes |
| `40` | `3292` | Raw `BLINCS-128-A2` `Imprint` bytes (`signet::IMPRINT_LEN`) |

Decoders MUST enforce strict base64 (canonical padding bits, no unexpected blank lines) and reject any payload whose length is not 3,332 bytes or whose magic is not `BLINCSg2`.

---

## 3. BLAKE3 Tree and History Binding (`signet-tree`, `signet-parent`)

`git-signet` binds every commit to its tree and parents with **BLAKE3-256** (`derive_key` mode), using four distinct context strings:

| Object role | `blake3::derive_key` context string |
|---|---|
| File blob | `"git-signet 2026-11-24 file"` |
| Tree directory | `"git-signet 2026-11-24 directory"` |
| Commit carrying `signet-*` headers | `"git-signet 2026-11-24 commit"` |
| Plain / stale commit | `"git-signet 2026-11-24 plain commit"` |

### 3.1 File digest
`D_file(blob)` is `BLAKE3_derive_key("git-signet 2026-11-24 file", raw_blob_bytes)` (computed in one strictly single-threaded streaming pass via `blake3-servil-core` with a constant 16 KiB stack buffer).

### 3.2 Directory digest
Given a Git tree object parsed into canonical entries `(mode, name, oid)`:
- Concatenate for each entry in Git tree order:
  - `mode` ASCII bytes (`100644`, `100755`, `120000`, `40000`, `160000`) || `0x20` || `name` raw bytes || `0x00`
  - followed by:
    - for gitlink (`160000`): the 20-byte raw submodule OID;
    - for directory (`40000`): the 32-byte `D_dir(subtree)`;
    - for file/symlink: the 32-byte `D_file(blob)`.
- `D_dir(tree)` is `BLAKE3_derive_key("git-signet 2026-11-24 directory", concatenated_entries)`.
- Cycles and nesting deeper than 4,096 levels are rejected.

### 3.3 Commit headers
A commit carrying BLAKE3 headers includes, directly after the `committer` header line:
- Exactly one `signet-tree blake3 <40-hex-tree-oid> <64-hex-D_dir>` line whose `<40-hex-tree-oid>` equals the commit's `tree` header (carrying the tree OID lets `parse_commit` distinguish a stale `git commit --amend` header from a malformed commit).
- Exactly one `signet-parent blake3 <64-hex-D_commit>` line per `parent` header, in exact parent order.

### 3.4 Commit digest and classification
- **Carrying commit:** has valid `signet-tree` matching `tree` and valid `signet-parent` lines matching every `parent`. Its commit digest is `D_commit(C) = BLAKE3_derive_key("git-signet 2026-11-24 commit", raw_commit_bytes)`.
- **Plain commit:** has zero `signet-tree` and zero `signet-parent` lines. Its commit digest is `D_commit(C) = BLAKE3_derive_key("git-signet 2026-11-24 plain commit", D_dir(tree) || u32_le(parents.len()) || D_commit(p_0) || ... || raw_commit_bytes)`.
- **Stale commit (`git commit --amend` artifact):** has exactly one `signet-tree` whose embedded tree OID differs from the commit's current `tree` OID (and zero malformed lines). Treated as plain during verification and replaced on `post-commit`.
- **Malformed commit:** any duplicate `signet-tree`, mismatched `signet-parent` count/order, bad hex, or non-matching `signet-tree`/`signet-parent` digest is rejected.

Verification and header emission always use a fresh **memory-only** digest map; no unauthenticated disk cache file is read or written.

---

## 4. Salted Whole-Snapshot BLINCS Imprinting

`git-signet` pushes the **entire commit (or annotated tag + target commit) plus a canonical depth-first walk of its entire tree and every file byte** directly into `signet::Signet::imprint_with` and `signet::SignetId::verify_with` under a bounded length-framed BLINCS `Context`. Because BLINCS mixes a fresh per-imprint random salt and the framed `Context` into the streaming message hash, forging a second tree under the same imprint requires breaking salted second-preimage resistance rather than unsalted collision resistance.

### 4.1 Commit snapshot stream
Imprinted and verified with BLINCS `Context = b"git-signet 2026-11-25 commit-snapshot"`, streaming:
```text
u64_le(commit_payload.len()) || commit_payload
|| TreeWalk(commit.tree)
|| b'E'
```
where `commit_payload` is the exact raw commit bytes with the `gpgsig` header removed.

### 4.2 Annotated tag snapshot stream
If an annotated tag targeting a commit (`type commit`) carries its own `BLINCSg2` imprint (e.g. `git tag -s`), it is imprinted and verified with BLINCS `Context = b"git-signet 2026-11-25 tag-snapshot"`, streaming its payload together with its target commit and full target tree as:
```text
u64_le(tag_payload.len()) || tag_payload
|| u64_le(target_commit_raw.len()) || target_commit_raw
|| TreeWalk(target_commit.tree)
|| b'E'
```
where `tag_payload` is the raw tag bytes preceding `-----BEGIN SIGNED MESSAGE-----`. (An unimprinted tag, including nested tags up to depth 64, peels to its target commit and verifies that commit under §5.2.)

### 4.3 Canonical `TreeWalk(tree_oid)` stream
Iterative depth-first traversal in Git's stored entry order (explicit stack, max depth 4,096, cycle rejection):
- For each entry in `tree_oid`:
  - If directory (`40000`): `b'D' || mode || b' ' || name || 0x00 || TreeWalk(entry.oid) || b'E'`
  - If gitlink (`160000`): `b'G' || mode || b' ' || name || 0x00 || oid_20_bytes`
  - If file or symlink (`100644`, `100755`, `120000`): `b'F' || mode || b' ' || name || 0x00 || u64_le(blob_len) || <raw blob bytes streamed directly from git cat-file --batch-command>`
- The root `TreeWalk` is closed by the trailing `b'E'` shown in §4.1 and §4.2.

---

## 5. Governing Signet Rules and Formal Transitive-Closure Rule

### 5.1 Governing signet ID
For a ref update `R -> O`:
1. In a non-bare repository, local `refs/heads/*` and `HEAD` are **never** governed by a signet (so local commits are never refused).
2. A `blincs-<52>` in `R` governs `R` (for remote-tracking refs, tags, and bare-repo branches).
3. A `blincs-<52>` in `remote.<name>.url` governs `refs/remotes/<name>/*`, tags arriving in a single-marked-remote fetch (or single-remote repo), and in a bare repository its own directory basename or single remote governs its branches, tags, and `HEAD`.
4. Conflicting signet IDs between `R`, the remote URL, or a bare repository's own directory basename are rejected.
5. Git `reference-transaction` records are parsed byte-for-byte on ASCII spaces (`0x20`) without splitting non-ASCII whitespace; malformed records and unauthorized symbolic ref updates fail closed, and the `prepared` hook is strictly read-only.

### 5.2 Formal authorization rule
A ref update `R -> O` governed by signet ID `S` is **accepted** if and only if:
1. Its full BLAKE3 commit chain verifies cleanly from `O` down to root commits or `.git/shallow` grafts (when shallow mode is permitted; prior ref values are never skipped as unauthenticated checkpoints), **and**
2. One of the following holds:
   - **(a) Direct commit imprint:** `O` is a commit (or unimprinted tag peeling to a commit `C`) carrying a `BLINCSg2` imprint that verifies `CommitSnapshot(C)` under `S`; or
   - **(b) Direct annotated-tag imprint:** `O` is an annotated tag carrying a `BLINCSg2` imprint that verifies `TagSnapshot(O)` under `S` (authorizing that tag itself, never delegating closure authority to other refs); or
   - **(c) Transitive ancestor closure:** `O` is a commit (or tag peeling to a commit `C`) that lies in the **BLAKE3-authenticated ancestor closure** (traversing only verified `signet-parent` edges) of a directly verified **carrying** commit `T` under `S` that survives in the projected post-transaction ref set (refs deleted or replaced in the same transaction cannot act as witnesses).

Rule (c) lets repositories adopt `git-signet` without rewriting historical commits or old release tags: once a newer carrying tip commit `T` carries `signet-parent` bindings reaching back to `C` and a valid BLINCS imprint under `S`, old tags pointing to `C` verify automatically, while any commit outside `T`'s authenticated ancestor closure is refused. (A directly imprinted plain commit without `signet-parent` headers authorizes only itself, not its unauthenticated ancestors.)

---

## 6. Seed File & Randomness Storage

- Seed files generated by `git signet keygen` are derived via `signet::Signet::generate(&rng)` and stored with mode `0600` at `~/.config/git-signet/signets/<blincs-52>.seed` as **exactly 40 bytes**:
  - `b"BLINCSs2"` (8-byte magic) || 32-byte signet seed.
- Per-machine signing randomness state is stored in the single private `0600` 32-byte file `~/.config/git-signet/salt`, rotated lock-free via sibling temp file and atomic `rename` by `signet::Randomness`.

# git signet

**Draft, 2026-11-22.**

## 1. What it is

Stock Git can sign commits and annotated tags with SSH Ed25519 keys, and
forges like GitHub already display those signatures. What Git lacks is a way
for a user who clones a repository to know *which* public key is supposed to
sign it—without maintaining keyrings, GPG webs of trust, or per-repo
`allowed_signers` files.

`git-signet` puts the 32-byte Ed25519 verifying key directly into an
identifier users already copy, paste, clone, and pin:

1. **a repository name** in the clone URL (`acme-tls.ed25519-<52-base32>`), or
2. **a branch or tag name** (`main+ed25519-<52-base32>`, `v2.4.0+ed25519-<52-base32>`).

Standard Git, GitHub, Cargo, Nix, and CI treat those as ordinary names. Any
client running `git-signet` automatically extracts the public key and verifies
the OpenSSH Git signature on every `clone`, `fetch`, `pull`, `commit`, and
`fsck`—aborting before writing a single file to disk if the signature is
missing, forged, or signed by a different key.

## 2. Key encoding

A verifying key marker has the exact form:

    ed25519-<52-base32>

* The raw key is a 32-byte Ed25519 public key.
* `<52-base32>` is its canonical unpadded lowercase RFC 4648 base32 encoding
  (alphabet `[a-z2-7]`, 52 characters, 260 bits; the 4 trailing padding bits
  MUST be zero, so the 52nd character MUST be `a` or `q`).
* Total marker length: 60 ASCII characters, strictly in `[a-z0-9-]`.

To verify standard OpenSSH Git signatures (`gpg.format = ssh`, namespace
`"git"`), the reader reconstructs the 51-byte OpenSSH public key wire blob:

    00 00 00 0b "ssh-ed25519" 00 00 00 20 || <32-byte raw key>

base64-encodes it, and checks the signature against that single key with
`ssh-keygen -Y verify -n git`.

## 3. Where keys live

### Repository name (in the remote URL)

Extract the final path component of the remote URL (after the last `/` or `:`,
stripping any trailing `/` and optional `.git` suffix). If it contains
`.ed25519-<52-base32>` (or equals `ed25519-<52-base32>`), that key governs:

* every ref under `refs/remotes/<remote>/*`;
* every local branch configured with `branch.<name>.remote = <remote>`;
* on `git clone`, the initial `HEAD`, local branch, and tags fetched from
  `origin`—protecting even a brand-new clone before any file is checked out,
  even if a compromised host renames the default branch.

Example (70 characters; well within GitHub's 100-character repo name limit):

    https://github.com/maya/acme-tls.ed25519-74nfu4k2ulfcryjbwknkyjbdbd7tlna3gfwm3fiomrr5e2t4pswa

### Branch or tag name

If any `/`-separated segment of a refname contains `.ed25519-<52-base32>` or
`+ed25519-<52-base32>` (or equals `ed25519-<52-base32>`), that key governs
that ref—without requiring the repository itself to be renamed.

Markers may be chained with `git-buttress`'s `+blake3-<64-hex>` pin in either
order (for example `v2.4.0+ed25519-<52>+blake3-<64>`).

### Fail-closed parsing rules

* Any malformed `ed25519-` token (wrong length, uppercase, padding `=`,
  non-zero trailing pad bits, invalid delimiter) MUST be rejected as an error.
* Any revision traversal operator (`^`, `~`, `..`) combined with an
  `ed25519-` marker MUST be rejected as ambiguous.
* If both a remote URL and a refname specify keys and those keys differ, the
  reader MUST fail closed with a conflict error.

## 4. What is verified

* **Commits:** Must carry exactly one `gpgsig` header containing a valid
  OpenSSH `-----BEGIN SSH SIGNATURE-----` block signing the commit bytes
  (with `gpgsig` and its continuation lines removed) under namespace `"git"`
  by the required Ed25519 key. Duplicate `gpgsig` headers and non-SSH (GPG)
  signatures are rejected.
* **Annotated tags:** Must end with a single terminal
  `-----BEGIN SSH SIGNATURE-----` block signing the tag bytes preceding the
  signature block under namespace `"git"` by the required Ed25519 key. An
  unsigned annotated tag pointing to a signed commit is rejected.
* **Trees and blobs:** Rejected (cannot carry Git signatures).
* **Isolation:** Readers pass `--no-replace-objects` and `GIT_NO_LAZY_FETCH=1`
  to Git, and never invoke a `gpg.ssh.program` read from untrusted repo-local
  `.git/config`.

## 5. Composing with `git-buttress`

`git-signet` and [`git-buttress`](https://github.com/jasonhadler25/git-buttress)
solve complementary halves of Git's supply-chain problem and compose cleanly:

* **`git-signet`** authenticates *who* signed a ref without GPG, CAs,
  keyservers, or `allowed_signers` files (stopping compromised Git hosts,
  stolen forge tokens, and hostile mirrors).
* **`git-buttress`** replaces Git's SHA-1 Merkle spine with BLAKE3 inside
  commit headers *before* signing (stopping SHA-1 / SHA1DC file and history
  collisions even against a valid commit signature).
* **Together:** On Git 2.56+, both register independent native config hooks
  (`[hook "signet-reference-transaction"]` and `[hook "buttress-*"]`) without
  touching `core.hooksPath`. A single `git clone` verifies both the Ed25519
  signature against the URL/branch key and the entire BLAKE3 tree and history.

## 6. What it does not do

* **Rollback / freeze attacks:** A valid signature proves the holder of the
  key signed that commit at some point—not that it is the newest commit they
  ever signed. A hostile mirror can still replay an older signed commit unless
  pinned to a specific commit/tag digest (e.g., via `git-buttress`
  `+blake3-...` or `--expect`).
* **Key rotation:** Because the key *is* the identifier, rotating keys means
  publishing a new branch or repository name carrying the new key. There is
  deliberately no hidden delegation or revocation server.
* **Non-Git-hook clients:** Clients that fetch without running Git's
  `reference-transaction` hook (such as `jj git fetch`, `gix clone`, or
  GitHub `.tar.gz` downloads) are not blocked automatically; run
  `git signet check` or `git signet fsck` explicitly after fetching.

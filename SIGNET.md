# git signet

**Draft, 2026-11-22.**

## 1. What it is

Stock Git can sign commits and tags with an SSH Ed25519 key. What it lacks is
a way for someone cloning a repository to know which key is supposed to have
signed it, short of keyrings and per-repository `allowed_signers` files.

git signet puts the 32-byte verifying key into a name that users already
copy and paste:

1. the repository's name, in the URL they clone
   (`acme-tls.ed25519-<52-base32>`), or
2. a branch or tag name (`main+ed25519-<52-base32>`).

To Git, a forge, Cargo and Nix these are ordinary names. A client running
git signet reads the key out of the name and checks the signature on what it
fetches, before any ref changes and before any file is written.

## 2. The key in a name

A verifying key is written

    ed25519-<52-base32>

* `<52-base32>` is the 32-byte Ed25519 verifying key in unpadded lowercase
  RFC 4648 base32 (alphabet `a`-`z`, `2`-`7`). 52 characters hold 260 bits;
  the last 4 must be zero, so the 52nd character is `a` or `q`.
* The whole thing is 60 characters from `[a-z0-9-]`.

`ed25519-` begins a key only at the start of a name or after `.` (in a ref
name, also after `+`), and only when exactly 52 base32 characters follow and
then the name ends or continues with `.` (or `+`). Anything else is an
ordinary name: a repository called `ed25519-dalek`, a branch called
`fix/ed25519-parsing`.

Three things are errors, not ordinary names:

* 40 or more letters and digits in a key's place that are not a key (one
  damaged in copying);
* a key followed by `~`, `^`, `@` or `:`, or in a name containing `..`
  (`main+ed25519-…~1` would otherwise look as if it pinned the parent);
* two different keys in one name.

Signatures are OpenSSH signatures in the namespace `git`, the ones
`git commit -S` makes with `gpg.format = ssh`. To check one, a reader builds
the 51-byte OpenSSH key

    00 00 00 0b "ssh-ed25519" 00 00 00 20 || <the 32 bytes>

and runs `ssh-keygen -Y verify -n git` with that as the only allowed signer.

## 3. Where a key can be, and what it governs

**In a repository's name.** The repository name is the last component of a
remote's URL, after the last `/` or `:`, without a trailing `/` or `.git`.
A key there is the key of that remote. It governs:

* every remote-tracking ref of that remote, `refs/remotes/<remote>/*`;
* the tags that arrive in the same clone or fetch as that remote's branches;
* in a bare repository with exactly one remote (a mirror): its tags, its
  branches and `HEAD`.

**In a branch or tag name.** A key in any `/`-separated part of a ref's name
governs that ref: the remote-tracking ref of a branch so named, a tag so
named, and in a bare repository a branch so named. It may sit beside
git-buttress's `+blake3-<64-hex>`, in either order.

**Never a local branch.** In a repository with a working tree, `refs/heads/*`
and `HEAD` are the user's own work. `git commit`, `git merge`, `git rebase`
and `git pull` are never refused, whoever's key the branch or the remote
names.

If a ref is governed by a key in its name and a key in its remote's URL, the
two must be the same key.

## 4. What a governed ref must point at

* **A commit** carrying exactly one `gpgsig` header, an OpenSSH signature by
  the key over the commit without that header.
* **A tag** that carries such a signature itself (over the tag without its
  signature block), or that names, through any chain of tags, a commit that
  does. So lightweight tags, plain annotated tags and signed tags are all
  accepted on a signed commit, and a signed tag is accepted on an unsigned one.
* Anything else is refused: a tree, a blob, a GnuPG signature, a signature by
  another key, no signature.

Only the object the ref points at is checked, not its ancestors.

A reader passes `--no-replace-objects` and `GIT_NO_LAZY_FETCH=1` to Git and
runs the system's `ssh-keygen`, never a `gpg.ssh.program` named by the
repository's own configuration.

`git signet fsck` checks every remote-tracking ref, every tag (against the
key of the repository's only remote, when it has exactly one), and in a bare
repository every branch. `git signet check <rev>` checks one revision,
including a local branch, against the key in its name, the key of the remote
it tracks, or `--key`.

## 5. Signing

The signatures are stock Git's, so stock Git makes them. `git signet adopt
<signing-key>` (or `keygen`, which makes a key first) writes, once per
machine:

* `~/.config/git-signet/sign/<key>.gitconfig`, holding `gpg.format = ssh`,
  `user.signingkey = <signing-key>` and `commit.gpgsign = true`;
* four `includeIf` entries in the global Git configuration that include that
  file when the current branch's name, or any remote's URL, contains the key.

From then on plain `git commit` in such a repository or on such a branch is
signed as Git creates it; so are the commits made by `git merge`,
`git rebase`, `git cherry-pick`, `git revert` and `git am`. Nothing happens
anywhere else, and nothing happens for someone who does not hold the key.

The branch-name condition is off while `HEAD` is detached, which is where a
rebase stops for a conflict. So the first time a branch whose name carries an
adopted key is created or moved, git signet records
`include.path = <that file>` in the repository's own configuration, and says
so. From then on every commit in that repository is signed.

Tags are not signed automatically. Git's setting for that, `tag.gpgSign`,
makes plain `git tag <name>` demand a message. Section 4 accepts a tag on a
signed commit as it is.

## 6. With git-buttress

[git-buttress](https://github.com/jasonhadler25/git-buttress) adds BLAKE3
digests of the files and history to each commit before it is signed. The two
check different things and are installed side by side, each as a Git 2.56
configured hook, neither touching `core.hooksPath`:

* git signet: was this signed by the key in the name? A SHA-1 collision
  defeats it alone, because the signature covers only SHA-1 identifiers.
* git-buttress: do the files and history match the BLAKE3 digests in the
  commit? Someone who can push defeats it alone, by writing new digests.
* Together, the signature covers the digests.

## 7. What it does not do

* **It does not tie a commit to a ref's name.** The signature covers the
  commit, not which branch or tag it belongs under. A server can answer with
  an older signed commit (rollback), or serve one branch's signed commit as
  another branch or as a tag. A digest pinned from elsewhere (git-buttress's
  `--expect` or `+blake3-`) closes this for one revision.
* **In a repository whose name carries a key, every branch must be signed by
  it.** A branch pushed by a bot, or a commit made by a forge's merge button,
  makes clone and fetch fail for everyone running git signet until it is
  gone. A key in a branch's name constrains only that branch.
* **Tags that arrive alone are not checked on arrival.** A fetch that brings
  new tags and moves no branch gives the hook no way to tell them from tags
  made locally. `git signet fsck` checks them.
* **Refs fetched outside a remote's namespace are not checked**:
  `git pull <url>`, `git fetch <remote> <branch>:<local-branch>`.
* **Clients that do not run Git's hooks are not stopped**: `jj git fetch`,
  `gix clone`, Cargo's fetcher, a forge's tarball. Run `git signet fsck`.
* **No key rotation.** The key is the name. A new key is a new name.
* **Not post-quantum.** Ed25519.

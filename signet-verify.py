#!/usr/bin/env python3
"""Standalone reference verifier for git-signet using only stock `git` and `ssh-keygen`."""
import base64, os, subprocess, sys, tempfile

ENV = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}
WIRE_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
SIG_BEGIN = b"-----BEGIN SSH SIGNATURE-----"
SIG_END = b"-----END SSH SIGNATURE-----"

def git(*args):
    return subprocess.run(["git", "--no-replace-objects", *args], stdout=subprocess.PIPE, check=True, env=ENV).stdout

def decode_marker(marker):
    if not marker.startswith("ed25519-"):
        raise ValueError("marker must start with ed25519-")
    b32 = marker[len("ed25519-"):]
    if len(b32) != 52 or any(c not in "abcdefghijklmnopqrstuvwxyz234567" for c in b32):
        raise ValueError("marker must be 52 lowercase RFC 4648 base32 chars")
    if b32[-1] not in ("a", "q"):
        raise ValueError("non-zero trailing base32 pad bits")
    raw = base64.b32decode(b32.upper() + "====")
    assert len(raw) == 32
    return raw

def extract_commit_sig(raw):
    sep = raw.find(b"\n\n")
    hdr, body = (raw[:sep], raw[sep + 2:]) if sep != -1 else (raw, b"")
    lines = hdr.split(b"\n")
    out_h, sig, i = [], None, 0
    while i < len(lines):
        if lines[i].startswith(b"gpgsig "):
            if sig is not None:
                raise ValueError("duplicate gpgsig header")
            blk = [lines[i][7:]]
            i += 1
            while i < len(lines) and lines[i].startswith(b" "):
                blk.append(lines[i][1:])
                i += 1
            sig = b"\n".join(blk) + b"\n"
            continue
        out_h.append(lines[i])
        i += 1
    if sig is None:
        raise ValueError("commit has no gpgsig header")
    payload = b"\n".join(out_h) + (b"\n\n" + body if sep != -1 else b"")
    return payload, sig

def extract_tag_sig(raw):
    sep = raw.find(b"\n\n")
    if sep == -1:
        raise ValueError("tag has no body")
    idx = raw.find(b"\n" + SIG_BEGIN + b"\n", sep)
    if idx == -1:
        raise ValueError("tag has no SSH signature")
    return raw[:idx + 1], raw[idx + 1:]

def good(pub, payload, sig):
    with tempfile.TemporaryDirectory() as td:
        allowed = os.path.join(td, "allowed")
        sigf = os.path.join(td, "sig")
        open(allowed, "w").write(f"git-signet ssh-ed25519 {base64.b64encode(WIRE_PREFIX + pub).decode()}\n")
        open(sigf, "wb").write(sig)
        r = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "git-signet", "-n", "git", "-s", sigf],
            input=payload, capture_output=True
        )
        return r.returncode == 0 and r.stdout.startswith(b'Good "git" signature for git-signet with ED25519 key ')

def signed_by(pub, oid):
    """A commit signed by the key; or a tag signed by it, or naming a commit that is."""
    kind = git("cat-file", "-t", oid).decode().strip()
    raw = git("cat-file", kind, oid)
    try:
        if kind == "commit":
            return good(pub, *extract_commit_sig(raw))
        if kind == "tag" and good(pub, *extract_tag_sig(raw)):
            return True
    except ValueError:
        pass
    if kind != "tag":
        return False
    commit = git("rev-parse", "--verify", "--end-of-options", oid + "^{commit}").decode().strip()
    return signed_by(pub, commit)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: signet-verify.py <rev> <ed25519-52-base32>")
    pub = decode_marker(sys.argv[2])
    oid = git("rev-parse", "--verify", "--end-of-options", sys.argv[1]).decode().strip()
    if not signed_by(pub, oid):
        raise SystemExit(f"NOT signed by {sys.argv[2]}: {oid}")
    print(f"GOOD {oid} signed by {sys.argv[2]}")

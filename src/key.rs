//! Self-certifying Ed25519 key encoding (`ed25519-<52-base32>`) and marker extraction.
//!
//! Encoding follows the exact canonical unpadded lowercase RFC 4648 base32 rules of `hashset`:
//! - Alphabet: `[a-z2-7]` (32 symbols, 5 bits each).
//! - 32-byte Ed25519 verifying key -> 52 characters (260 bits; bottom 4 padding bits MUST be 0,
//!   so the 52nd character MUST be `'a'` (0b00000) or `'q'` (0b10000)).
//! - Total marker length: 60 ASCII characters (`ed25519-` + 52 base32 chars), strictly in `[a-z0-9-]`.

pub type PubKey32 = [u8; 32];

pub const MARKER_PREFIX: &str = "ed25519-";
pub const KEY_B32_LEN: usize = 52;
pub const OPENSSH_ED25519_WIRE_PREFIX: &[u8; 19] = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";

const B32_ALPHA: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const B64_ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode a 32-byte Ed25519 verifying key as canonical 52-char unpadded lowercase RFC 4648 base32.
pub fn encode_base32_key(key: &PubKey32) -> String {
    let mut out = String::with_capacity(KEY_B32_LEN);
    let mut bit_buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in key {
        bit_buf = (bit_buf << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((bit_buf >> bits) & 0x1f) as usize;
            out.push(B32_ALPHA[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((bit_buf << (5 - bits)) & 0x1f) as usize;
        out.push(B32_ALPHA[idx] as char);
    }
    debug_assert_eq!(out.len(), KEY_B32_LEN);
    out
}

/// Strictly decode a canonical 52-char unpadded lowercase RFC 4648 base32 Ed25519 verifying key.
/// Rejects uppercase, padding `=`, wrong length, non-base32 chars, and non-zero trailing pad bits.
pub fn decode_base32_key(s: &str) -> Result<PubKey32, String> {
    let bytes = s.as_bytes();
    if bytes.len() != KEY_B32_LEN {
        return Err(format!(
            "invalid ed25519 base32 key length: expected {KEY_B32_LEN}, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    let mut out_idx = 0usize;
    let mut bit_buf: u32 = 0;
    let mut bits: u32 = 0;
    for &ch in bytes {
        let val = match ch {
            b'a'..=b'z' => (ch - b'a') as u32,
            b'2'..=b'7' => (ch - b'2' + 26) as u32,
            _ => {
                return Err(format!(
                    "non-canonical base32 character {:?} in ed25519 key",
                    ch as char
                ));
            }
        };
        bit_buf = (bit_buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[out_idx] = ((bit_buf >> bits) & 0xff) as u8;
            out_idx += 1;
        }
    }
    debug_assert_eq!(out_idx, 32);
    debug_assert_eq!(bits, 4);
    if (bit_buf & 0x0f) != 0 {
        return Err("non-canonical base32 ed25519 key (non-zero trailing padding bits)".into());
    }
    Ok(out)
}

/// Format as `ed25519-<52-base32>`.
pub fn format_marker(key: &PubKey32) -> String {
    format!("{MARKER_PREFIX}{}", encode_base32_key(key))
}

/// Parse an exact `ed25519-<52-base32>` marker string.
pub fn parse_marker(s: &str) -> Result<PubKey32, String> {
    let rest = s
        .strip_prefix(MARKER_PREFIX)
        .ok_or_else(|| format!("key marker must start with {MARKER_PREFIX:?}"))?;
    decode_base32_key(rest)
}

/// Encode bytes as standard RFC 4648 base64 (with `=` padding).
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHA[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHA[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHA[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode standard RFC 4648 base64 (strict, rejects invalid bytes/padding).
pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return Err("invalid base64 length".into());
    }
    let val = |c: u8| -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 character {:?}", c as char)),
        }
    };
    let mut out = Vec::with_capacity((b.len() / 4) * 3);
    let (chunks, _) = b.as_chunks::<4>();
    for (idx, chunk) in chunks.iter().enumerate() {
        let is_last = (idx + 1) * 4 == b.len();
        let pad = if chunk[2] == b'=' && chunk[3] == b'=' {
            2
        } else if chunk[3] == b'=' {
            1
        } else {
            0
        };
        if pad > 0 && !is_last {
            return Err("unexpected base64 padding before end".into());
        }
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = if pad < 2 { val(chunk[2])? } else { 0 };
        let v3 = if pad == 0 { val(chunk[3])? } else { 0 };
        let n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push(((n >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad == 0 {
            out.push((n & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Parse an OpenSSH `ssh-ed25519 <base64> [comment]` `.pub` line into the raw 32-byte verifying key.
pub fn parse_openssh_ed25519_pubkey(line: &str) -> Result<PubKey32, String> {
    let trimmed = line.trim();
    let mut parts = trimmed.split_whitespace();
    let key_type = parts
        .next()
        .ok_or_else(|| "empty OpenSSH key line".to_string())?;
    if key_type != "ssh-ed25519" {
        return Err(format!(
            "unsupported SSH key type {key_type:?}; git-signet requires ssh-ed25519"
        ));
    }
    let b64 = parts
        .next()
        .ok_or_else(|| "missing base64 key blob in OpenSSH key line".to_string())?;
    let wire = base64_decode(b64)?;
    if wire.len() != 51 || !wire.starts_with(OPENSSH_ED25519_WIRE_PREFIX) {
        return Err(format!(
            "invalid ssh-ed25519 wire blob (expected 51 bytes with ssh-ed25519 header, got {})",
            wire.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&wire[19..51]);
    Ok(key)
}

/// Format a raw 32-byte Ed25519 verifying key as an OpenSSH `allowed_signers` line for principal `principal`.
pub fn format_allowed_signers_line(principal: &str, key: &PubKey32) -> String {
    let mut wire = [0u8; 51];
    wire[..19].copy_from_slice(OPENSSH_ED25519_WIRE_PREFIX);
    wire[19..51].copy_from_slice(key);
    format!("{principal} ssh-ed25519 {}\n", base64_encode(&wire))
}

/// Extract an optional `ed25519-<52>` key from a single name segment (e.g., repo basename or ref segment).
///
/// Accepted forms:
/// - `ed25519-<52>` (whole segment)
/// - `<prefix>.ed25519-<52>` (repo name, branch name, or tag name)
/// - `<prefix>+ed25519-<52>` (branch name or tag name, SemVer-compatible)
///
/// Also supports chaining with `git-buttress`'s `+blake3-<64>` suffix in either order on ref names
/// (e.g., `v1.0+ed25519-<52>+blake3-<64>` or `v1.0+blake3-<64>+ed25519-<52>`).
///
/// Fails closed (`Err`) on any malformed `ed25519-` token or multiple conflicting keys.
pub fn extract_key_from_refname(refname: &str) -> Result<Option<PubKey32>, String> {
    let mut found: Option<PubKey32> = None;
    for seg in refname.split('/') {
        if let Some(k) = extract_key_from_segment(seg, true)? {
            if let Some(prev) = found
                && prev != k
            {
                return Err(format!("conflicting ed25519 keys in refname {refname:?}"));
            }
            found = Some(k);
        }
    }
    if found.is_some()
        && (refname.contains('^') || refname.contains('~') || refname.contains(".."))
    {
        return Err(format!(
            "ambiguous revision walk operator on ed25519-pinned ref {refname:?}"
        ));
    }
    Ok(found)
}

/// Extract an optional `ed25519-<52>` key from a Git remote URL (HTTPS, SSH `git@host:org/repo.git`,
/// `ssh://`, `file://`, or local filesystem path).
///
/// Only the repository basename (final path component with trailing `/` and `.git` stripped) is
/// inspected so arbitrary directory/org names cannot accidentally shadow a repo's verifying key.
pub fn extract_key_from_remote_url(url: &str) -> Result<Option<PubKey32>, String> {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(None);
    }
    // Strip query or fragment if ever present in URL text
    let without_qf = trimmed
        .split_once('#')
        .map(|(a, _)| a)
        .unwrap_or(trimmed);
    let without_qf = without_qf
        .split_once('?')
        .map(|(a, _)| a)
        .unwrap_or(without_qf)
        .trim_end_matches('/');

    // Final component after last `/` or `:` (handles SCP-style `git@github.com:org/repo.git` and `host:repo.git`)
    let last_sep = without_qf.rfind(['/', ':']);
    let basename = match last_sep {
        Some(idx) => &without_qf[idx + 1..],
        None => without_qf,
    };
    let repo_name = basename.strip_suffix(".git").unwrap_or(basename);
    extract_key_from_segment(repo_name, false)
}

fn extract_key_from_segment(seg: &str, allow_plus: bool) -> Result<Option<PubKey32>, String> {
    // `ed25519-` begins a key marker only at the start of the segment or after `.` (or `+` in ref
    // names), and only when exactly 52 base32 characters follow. Anything else containing
    // `ed25519-` (a repository called `ed25519-dalek`, a branch called `fix/ed25519-parsing`) is an
    // ordinary name. A token that is nearly a key (40 or more letters and digits) is rejected as
    // damaged, so that a key mangled in copying fails loudly instead of switching verification off.
    let is_delim = |c: char| c == '.' || (allow_plus && c == '+');
    let is_b32 = |c: char| c.is_ascii_lowercase() || ('2'..='7').contains(&c);
    let mut found: Option<PubKey32> = None;
    let mut search_from = 0usize;
    while let Some(rel) = seg[search_from..].find(MARKER_PREFIX) {
        let pos = search_from + rel;
        search_from = pos + MARKER_PREFIX.len();
        if pos != 0 && !seg[..pos].ends_with(is_delim) {
            continue;
        }
        let after = &seg[search_from..];
        let token = &after[..after
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(after.len())];
        let next = after[token.len()..].chars().next();
        let ends_cleanly = next.is_none_or(is_delim);
        if token.len() == KEY_B32_LEN && token.chars().all(is_b32) {
            if matches!(next, Some('~' | '^' | '@' | ':')) {
                return Err(format!(
                    "ambiguous revision walk operator on ed25519-pinned ref {seg:?}"
                ));
            }
            if !ends_cleanly {
                continue;
            }
            let k = decode_base32_key(token)
                .map_err(|e| format!("invalid ed25519 key marker in {seg:?}: {e}"))?;
            if let Some(prev) = found
                && prev != k
            {
                return Err(format!("conflicting ed25519 keys in {seg:?}"));
            }
            found = Some(k);
        } else if token.len() >= 40 && ends_cleanly {
            return Err(format!(
                "damaged ed25519 key marker in {seg:?}: expected {KEY_B32_LEN} lowercase base32 characters, found {}",
                token.len()
            ));
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_base32_roundtrip_and_strict_rejections() {
        let k = [0xab; 32];
        let b32 = encode_base32_key(&k);
        assert_eq!(b32.len(), 52);
        assert!(b32.ends_with('a') || b32.ends_with('q'));
        assert_eq!(decode_base32_key(&b32).unwrap(), k);

        // Non-zero trailing pad bits (change last char from 'a'/'q' to 'b')
        let mut bad_pad = b32.clone();
        bad_pad.pop();
        bad_pad.push('b');
        assert!(decode_base32_key(&bad_pad).is_err());

        // Uppercase rejected
        assert!(decode_base32_key(&b32.to_uppercase()).is_err());
        // Short/long rejected
        assert!(decode_base32_key(&b32[..51]).is_err());
        assert!(decode_base32_key(&format!("{b32}a")).is_err());
    }

    #[test]
    fn url_and_ref_extraction() {
        let k = [0x42; 32];
        let m = format_marker(&k);

        assert_eq!(
            extract_key_from_remote_url(&format!("https://github.com/maya/acme-tls.{m}.git"))
                .unwrap(),
            Some(k)
        );
        assert_eq!(
            extract_key_from_remote_url(&format!("git@github.com:maya/acme-tls.{m}.git")).unwrap(),
            Some(k)
        );
        assert_eq!(
            extract_key_from_remote_url(&format!("/tmp/repos/acme-tls.{m}")).unwrap(),
            Some(k)
        );
        assert_eq!(
            extract_key_from_remote_url("https://github.com/maya/acme-tls.git").unwrap(),
            None
        );

        // Ref names with + and . and chained with +blake3-
        assert_eq!(
            extract_key_from_refname(&format!("refs/heads/main+{m}")).unwrap(),
            Some(k)
        );
        assert_eq!(
            extract_key_from_refname(&format!(
                "refs/tags/v1.0+{m}+blake3-{}",
                "a".repeat(64)
            ))
            .unwrap(),
            Some(k)
        );
        // Ordinary names that merely contain `ed25519-` are not keys
        for url in [
            "https://github.com/dalek-cryptography/ed25519-dalek.git",
            "https://github.com/maya/acme.ed25519-bad",
            "git@github.com:x/libed25519-donna.git",
        ] {
            assert_eq!(extract_key_from_remote_url(url).unwrap(), None, "{url}");
        }
        assert_eq!(extract_key_from_refname("refs/heads/fix/ed25519-parsing").unwrap(), None);
        assert_eq!(extract_key_from_refname("refs/heads/main+ed25519-short~1").unwrap(), None);
        // A key damaged in copying (one character short, or uppercased) fails loudly
        assert!(extract_key_from_refname(&format!("refs/heads/main+{}", &m[..m.len() - 1])).is_err());
        assert!(extract_key_from_remote_url(&format!("https://h/acme.ed25519-{}", m[8..].to_uppercase())).is_err());
        // Walk syntax rejected
        assert!(extract_key_from_refname(&format!("main+{m}~1")).is_err());
    }
}

//! Self-certifying BLINCS signet IDs (`blincs-<52-base32>`), BLAKE3 digest markers (`+blake3-<64-hex>`),
//! and strict `BLINCSg2` PEM armor for Git `gpg.format = x509` imprints (`BLINCS-48-X`).

use signet::{IMPRINT_LEN, Imprint, SIGNET_ID_LEN, SignetId};

pub const SIGNET_PREFIX: &str = "blincs-";
pub const SIGNET_B32_LEN: usize = 52;
pub const BLAKE3_PREFIX: &str = "blake3-";
pub const BLAKE3_HEX_LEN: usize = 64;

pub const ARMOR_MAGIC: &[u8; 8] = b"BLINCSg2";
pub const ARMOR_RAW_LEN: usize = ARMOR_MAGIC.len() + SIGNET_ID_LEN + IMPRINT_LEN; // 4,030 bytes
const _: () = assert!(ARMOR_RAW_LEN == 4030);
pub const X509_BEGIN: &[u8] = b"-----BEGIN SIGNED MESSAGE-----";
pub const X509_END: &[u8] = b"-----END SIGNED MESSAGE-----";

const B32_ALPHA: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const B64_ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode a 32-byte `SignetId` as canonical 52-char unpadded lowercase RFC 4648 base32 (`[a-z2-7]`).
pub fn encode_signet_b32(id: &SignetId) -> String {
    let mut out = String::with_capacity(SIGNET_B32_LEN);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in id.as_bytes() {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHA[usize::try_from((buf >> bits) & 0x1f).unwrap()] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHA[usize::try_from((buf << (5 - bits)) & 0x1f).unwrap()] as char);
    }
    assert_eq!(out.len(), SIGNET_B32_LEN);
    out
}

/// Strictly decode canonical 52-char unpadded lowercase RFC 4648 base32 into a `SignetId`.
/// Rejects uppercase, `=`, wrong length, non-base32 characters, and non-zero trailing pad bits.
pub fn decode_signet_b32(s: &str) -> Result<SignetId, String> {
    let bytes = s.as_bytes();
    if bytes.len() != SIGNET_B32_LEN {
        return Err(format!("invalid blincs base32 signet ID length: expected {SIGNET_B32_LEN}, got {}", bytes.len()));
    }
    let mut out = [0u8; SIGNET_ID_LEN];
    let (mut idx, mut buf, mut bits) = (0usize, 0u32, 0u32);
    for &ch in bytes {
        let val = match ch {
            b'a'..=b'z' => u32::from(ch - b'a'),
            b'2'..=b'7' => u32::from(ch - b'2' + 26),
            _ => return Err(format!("non-canonical base32 character {:?} in blincs signet ID", ch as char)),
        };
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[idx] = u8::try_from((buf >> bits) & 0xff).unwrap();
            idx += 1;
        }
    }
    assert!(idx == SIGNET_ID_LEN && bits == 4);
    if (buf & 0x0f) != 0 {
        return Err("non-canonical base32 blincs signet ID (non-zero trailing padding bits)".into());
    }
    Ok(SignetId::from_bytes(&out))
}

/// Format a `SignetId` as `blincs-<52-base32>`.
pub fn format_signet_marker(id: &SignetId) -> String {
    format!("{SIGNET_PREFIX}{}", encode_signet_b32(id))
}

/// Parse an exact `blincs-<52-base32>` marker string.
pub fn parse_signet_marker(s: &str) -> Result<SignetId, String> {
    let rest = s.strip_prefix(SIGNET_PREFIX).ok_or_else(|| format!("signet ID marker must start with {SIGNET_PREFIX:?}"))?;
    decode_signet_b32(rest)
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}

pub fn decode_lower_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != 2 * N {
        return Err(format!("expected {} lowercase hex chars, got {}", 2 * N, s.len()));
    }
    let b = s.as_bytes();
    let hex_nibble = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(format!("invalid lowercase hex character {:?}", c as char)),
        }
    };
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = (hex_nibble(b[2 * i])? << 4) | hex_nibble(b[2 * i + 1])?;
    }
    Ok(out)
}

/// Combine two independent expectations: absent + present = present; equal values agree;
/// two distinct present values fail with `on_conflict(&a, &b)`.
pub fn agree<T: Eq>(a: Option<T>, b: Option<T>, on_conflict: impl FnOnce(&T, &T) -> String) -> Result<Option<T>, String> {
    match (a, b) {
        (Some(x), Some(y)) if x != y => Err(on_conflict(&x, &y)),
        (Some(x), _) => Ok(Some(x)),
        (None, y) => Ok(y),
    }
}

fn check_no_walk_ops(refname: &str, kind: &str) -> Result<(), String> {
    if refname.contains('^') || refname.contains('~') || refname.contains("..") {
        return Err(format!("ambiguous revision walk operator on {kind} ref {refname:?}"));
    }
    Ok(())
}

/// Split `seg` on `delims` and parse every token starting with `prefix`, enforcing agreement.
fn scan_prefixed_tokens<T: Eq>(
    seg: &str,
    delims: &[char],
    prefix: &str,
    parse: impl Fn(&str, &str) -> Result<Option<T>, String>,
    conflict_label: &str,
) -> Result<Option<T>, String> {
    let mut found: Option<T> = None;
    for token in seg.split(delims) {
        if let Some(payload) = token.strip_prefix(prefix)
            && let Some(val) = parse(token, payload)?
        {
            found = agree(found, Some(val), |_, _| format!("conflicting {conflict_label} in {seg:?}"))?;
        }
    }
    Ok(found)
}

fn parse_signet_payload(token: &str, payload: &str) -> Result<Option<SignetId>, String> {
    if payload.len() == SIGNET_B32_LEN && payload.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return Ok(Some(decode_signet_b32(payload)?));
    }
    if payload.len() >= 40 || payload.contains(['~', '^', '@', ':']) {
        return Err(format!("malformed blincs signet ID token {token:?}"));
    }
    Ok(None)
}

fn parse_blake3_payload(token: &str, payload: &str) -> Result<Option<[u8; 32]>, String> {
    if payload.len() == BLAKE3_HEX_LEN && payload.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(Some(decode_lower_hex::<32>(payload)?));
    }
    if payload.len() >= 40 || payload.contains(['~', '^', '@', ':']) {
        return Err(format!("malformed blake3 digest pin token {token:?}"));
    }
    Ok(None)
}

/// Extract an optional `blincs-<52-base32>` `SignetId` from a Git ref name.
///
/// Recognized delimiters: start of segment, `.`, or `+`. Fails closed on damaged 40+-char tokens,
/// revision walk operators (`^`, `~`, `..`) on a bound ref, or conflicting signet IDs.
pub fn extract_signet_from_refname(refname: &str) -> Result<Option<SignetId>, String> {
    let mut found: Option<SignetId> = None;
    for seg in refname.split('/') {
        let seg_id = scan_prefixed_tokens(seg, &['.', '+'], SIGNET_PREFIX, parse_signet_payload, "blincs signet IDs")?;
        found = agree(found, seg_id, |_, _| format!("conflicting blincs signet IDs in refname {refname:?}"))?;
    }
    if found.is_some() {
        check_no_walk_ops(refname, "signet-bound")?;
    }
    Ok(found)
}

/// Extract an optional `blincs-<52-base32>` `SignetId` from a Git remote URL (basename only; `.` delimiter, not `+`).
pub fn extract_signet_from_remote_url(url: &str) -> Result<Option<SignetId>, String> {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(None);
    }
    let without_qf = trimmed.split_once('#').map(|(a, _)| a).unwrap_or(trimmed);
    let without_qf = without_qf.split_once('?').map(|(a, _)| a).unwrap_or(without_qf).trim_end_matches('/');
    let basename = without_qf.rsplit(['/', ':']).next().unwrap_or(without_qf);
    let repo_name = basename.strip_suffix(".git").unwrap_or(basename);
    if repo_name.is_empty() {
        return Ok(None);
    }
    scan_prefixed_tokens(repo_name, &['.'], SIGNET_PREFIX, parse_signet_payload, "blincs signet IDs")
}

/// Extract an optional `+blake3-<64-hex>` immutable commit digest pin from a ref name.
pub fn extract_blake3_pin_from_refname(refname: &str) -> Result<Option<[u8; 32]>, String> {
    let mut found: Option<[u8; 32]> = None;
    for seg in refname.split('/') {
        let seg_dig = scan_prefixed_tokens(seg, &['.', '+'], BLAKE3_PREFIX, parse_blake3_payload, "blake3 digest pins")?;
        found = agree(found, seg_dig, |_, _| format!("conflicting blake3 digest pins in refname {refname:?}"))?;
    }
    if found.is_some() {
        check_no_walk_ops(refname, "digest-bound")?;
    }
    Ok(found)
}

pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 { u32::from(chunk[1]) } else { 0 };
        let b2 = if chunk.len() > 2 { u32::from(chunk[2]) } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHA[usize::try_from((n >> 18) & 0x3f).unwrap()] as char);
        out.push(B64_ALPHA[usize::try_from((n >> 12) & 0x3f).unwrap()] as char);
        out.push(if chunk.len() > 1 { B64_ALPHA[usize::try_from((n >> 6) & 0x3f).unwrap()] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64_ALPHA[usize::try_from(n & 0x3f).unwrap()] as char } else { '=' });
    }
    out
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return Err("invalid base64 length".into());
    }
    let val = |c: u8| -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok(u32::from(c - b'A')),
            b'a'..=b'z' => Ok(u32::from(c - b'a' + 26)),
            b'0'..=b'9' => Ok(u32::from(c - b'0' + 52)),
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
        // Reject non-zero unused trailing bits in padded final quantum.
        if (pad == 2 && (v1 & 0x0f) != 0) || (pad == 1 && (v2 & 0x03) != 0) {
            return Err("non-canonical base64 padding bits".into());
        }
        let n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push(u8::try_from((n >> 16) & 0xff).unwrap());
        if pad < 2 {
            out.push(u8::try_from((n >> 8) & 0xff).unwrap());
        }
        if pad == 0 {
            out.push(u8::try_from(n & 0xff).unwrap());
        }
    }
    Ok(out)
}

/// Encode `(SignetId, Imprint)` as Git `gpg.format = x509` PEM armor (`BLINCSg2 || id || imprint`).
pub fn encode_imprint_armor(id: &SignetId, imprint: &Imprint) -> Vec<u8> {
    let mut raw = Vec::with_capacity(ARMOR_RAW_LEN);
    raw.extend_from_slice(ARMOR_MAGIC);
    raw.extend_from_slice(id.as_bytes());
    raw.extend_from_slice(imprint.as_bytes());
    assert_eq!(raw.len(), ARMOR_RAW_LEN);

    let b64 = base64_encode(&raw);
    let mut out = Vec::with_capacity(b64.len() + 256);
    out.extend_from_slice(X509_BEGIN);
    out.push(b'\n');
    for line in b64.as_bytes().chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(X509_END);
    out.push(b'\n');
    out
}

const MAX_ARMOR_BYTES: usize = 16_384;

/// Strictly decode `BLINCSg2` PEM armor into `(SignetId, Imprint)`.
pub fn decode_imprint_armor(armor: &[u8]) -> Result<(SignetId, Imprint), String> {
    if armor.len() > MAX_ARMOR_BYTES {
        return Err(format!("imprint armor exceeds {MAX_ARMOR_BYTES} bytes"));
    }
    let trimmed = armor.strip_suffix(b"\n").unwrap_or(armor);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    let lines: Vec<&[u8]> = trimmed.split(|&c| c == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l)).collect();
    if lines.len() < 3 || lines[0] != X509_BEGIN || lines[lines.len() - 1] != X509_END {
        return Err("imprint armor is not a valid SIGNED MESSAGE block".into());
    }
    let mut b64 = String::new();
    for &line in &lines[1..lines.len() - 1] {
        let s = std::str::from_utf8(line).map_err(|_| "non-UTF-8 byte in imprint armor".to_string())?;
        if s.is_empty() {
            return Err("unexpected blank line in imprint armor".into());
        }
        b64.push_str(s);
    }
    let raw = base64_decode(&b64)?;
    if raw.len() != ARMOR_RAW_LEN || &raw[..ARMOR_MAGIC.len()] != ARMOR_MAGIC {
        return Err(format!("imprint payload is not a valid BLINCSg2 imprint (got {} bytes)", raw.len()));
    }
    let id = SignetId::try_from(&raw[8..8 + SIGNET_ID_LEN]).map_err(|_| "bad signet ID length".to_string())?;
    let imp = Imprint::try_from(&raw[8 + SIGNET_ID_LEN..]).map_err(|_| "bad imprint length".to_string())?;
    Ok((id, imp))
}

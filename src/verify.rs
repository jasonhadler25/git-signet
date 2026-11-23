//! Strict Git commit/tag signature extraction and OpenSSH `ssh-keygen -Y verify` verifier.
//!
//! Security boundaries:
//! - Never reads `gpg.ssh.program` from repo-local `.git/config` during verification (uses system
//!   `ssh-keygen` or explicit `GIT_SIGNET_SSH_KEYGEN` env var).
//! - Uses private mode-`0700` temp dirs and `create_new(true)` mode-`0600` files with RAII cleanup.
//! - Rejects duplicate `gpgsig` headers, trailing bytes after tag signature armor, and unsigned
//!   annotated tags (even if the tagged commit is signed!).

use crate::key::{PubKey32, format_allowed_signers_line};
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const SSH_SIG_BEGIN: &[u8] = b"-----BEGIN SSH SIGNATURE-----";
const SSH_SIG_END: &[u8] = b"-----END SSH SIGNATURE-----";
const PRINCIPAL: &str = "git-signet";

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct PrivateTempDir(PathBuf);

impl PrivateTempDir {
    fn create(prefix: &str) -> Result<Self, String> {
        let base = env::temp_dir();
        let pid = std::process::id();
        for _ in 0..64 {
            let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let p = base.join(format!("{prefix}-{pid}-{n}"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut b = fs::DirBuilder::new();
                b.mode(0o700);
                match b.create(&p) {
                    Ok(()) => return Ok(Self(p)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(format!("create private temp dir: {e}")),
                }
            }
            #[cfg(not(unix))]
            {
                match fs::create_dir(&p) {
                    Ok(()) => return Ok(Self(p)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(format!("create temp dir: {e}")),
                }
            }
        }
        Err("failed to allocate unique private temp directory".into())
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_private_file(path: &PathBuf, bytes: &[u8]) -> Result<(), String> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("create private file: {e}"))?;
    f.write_all(bytes)
        .map_err(|e| format!("write private file: {e}"))?;
    Ok(())
}

/// Split a raw Git commit object into `(signed_payload, ssh_signature_armor)`.
///
/// Exact match to Git's `gpgsig` commit header format:
/// - Header section ends at the first `\n\n` (or EOF if empty body).
/// - `gpgsig <first-line>` followed by zero or more ` <cont-line>` continuation lines.
/// - Duplicate `gpgsig` headers are rejected (fail closed).
pub fn extract_commit_ssh_signature(raw_commit: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (headers_end, has_sep) = match raw_commit.windows(2).position(|w| w == b"\n\n") {
        Some(pos) => (pos, true),
        None => (raw_commit.len(), false),
    };
    let header_bytes = &raw_commit[..headers_end];
    let body_bytes = if has_sep {
        &raw_commit[headers_end + 2..]
    } else {
        b""
    };

    let mut payload_headers: Vec<&[u8]> = Vec::new();
    let mut sig_lines: Option<Vec<&[u8]>> = None;

    let lines: Vec<&[u8]> = header_bytes.split(|&c| c == b'\n').collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(first_sig_line) = line.strip_prefix(b"gpgsig ") {
            if sig_lines.is_some() {
                return Err("commit carries duplicate gpgsig headers".into());
            }
            let mut block = vec![first_sig_line];
            i += 1;
            while i < lines.len() && lines[i].starts_with(b" ") {
                block.push(&lines[i][1..]);
                i += 1;
            }
            sig_lines = Some(block);
            continue;
        }
        payload_headers.push(line);
        i += 1;
    }

    let sig_block = sig_lines.ok_or_else(|| "commit is not signed (missing gpgsig header)".to_string())?;
    let mut sig = Vec::new();
    for l in &sig_block {
        sig.extend_from_slice(l);
        sig.push(b'\n');
    }
    validate_ssh_sig_armor(&sig)?;

    let mut payload = Vec::with_capacity(raw_commit.len());
    for (idx, h) in payload_headers.iter().enumerate() {
        if idx > 0 {
            payload.push(b'\n');
        }
        payload.extend_from_slice(h);
    }
    if has_sep {
        payload.extend_from_slice(b"\n\n");
        payload.extend_from_slice(body_bytes);
    }
    Ok((payload, sig))
}

/// Split a raw Git annotated tag object into `(signed_payload, ssh_signature_armor)`.
///
/// Git signs annotated tags by appending `-----BEGIN SSH SIGNATURE-----...-----END SSH SIGNATURE-----\n`
/// directly at the end of the tag payload. Trailing bytes after the signature end line are rejected.
pub fn extract_tag_ssh_signature(raw_tag: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let Some(sep) = raw_tag.windows(2).position(|w| w == b"\n\n") else {
        return Err("annotated tag has no message/signature body".into());
    };
    let body_start = sep + 2;
    let body = &raw_tag[body_start..];

    // Find the last line starting with SSH_SIG_BEGIN inside the body
    let mut begin_pos: Option<usize> = None;
    let mut off = 0usize;
    while off < body.len() {
        let line_end = body[off..]
            .iter()
            .position(|&c| c == b'\n')
            .map(|p| off + p)
            .unwrap_or(body.len());
        let line = body[off..line_end].strip_suffix(b"\r").unwrap_or(&body[off..line_end]);
        if line == SSH_SIG_BEGIN {
            if begin_pos.is_some() {
                return Err("annotated tag carries multiple SSH signature blocks".into());
            }
            begin_pos = Some(body_start + off);
        }
        if line_end == body.len() {
            break;
        }
        off = line_end + 1;
    }

    let sig_start = begin_pos
        .ok_or_else(|| "annotated tag is not SSH-signed (missing BEGIN SSH SIGNATURE block)".to_string())?;
    let payload = raw_tag[..sig_start].to_vec();
    let sig = raw_tag[sig_start..].to_vec();
    validate_ssh_sig_armor(&sig)?;
    Ok((payload, sig))
}

fn validate_ssh_sig_armor(sig: &[u8]) -> Result<(), String> {
    let trimmed = sig.strip_suffix(b"\n").unwrap_or(sig);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    let mut lines = trimmed.split(|&c| c == b'\n');
    let first = lines
        .next()
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .unwrap_or(b"");
    let last = trimmed
        .rsplit(|&c| c == b'\n')
        .next()
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .unwrap_or(b"");
    if first != SSH_SIG_BEGIN || last != SSH_SIG_END {
        return Err(
            "signature is not a valid OpenSSH signature block (GPG/PGP signatures are not accepted by git-signet; use gpg.format=ssh with an Ed25519 key)".into(),
        );
    }
    Ok(())
}

/// Cryptographically verify `(payload, ssh_sig_armor)` against `expected_key` using `ssh-keygen -Y verify`.
pub fn verify_ssh_signature(
    payload: &[u8],
    ssh_sig_armor: &[u8],
    expected_key: &PubKey32,
) -> Result<(), String> {
    validate_ssh_sig_armor(ssh_sig_armor)?;

    let tmp = PrivateTempDir::create("git-signet-verify")?;
    let allowed_path = tmp.0.join("allowed_signers");
    let sig_path = tmp.0.join("signature.sig");

    let allowed_content = format_allowed_signers_line(PRINCIPAL, expected_key);
    write_private_file(&allowed_path, allowed_content.as_bytes())?;
    write_private_file(&sig_path, ssh_sig_armor)?;

    let ssh_keygen = env::var_os("GIT_SIGNET_SSH_KEYGEN")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ssh-keygen".into());

    let mut cmd = Command::new(&ssh_keygen);
    cmd.args(["-Y", "verify", "-f"])
        .arg(&allowed_path)
        .args(["-I", PRINCIPAL, "-n", "git", "-s"])
        .arg(&sig_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn ssh-keygen for signature verification: {e}"))?;
    let mut stdin = child.stdin.take().unwrap();
    let payload_owned = payload.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&payload_owned));
    let out = child
        .wait_with_output()
        .map_err(|e| format!("failed waiting on ssh-keygen: {e}"))?;
    let write_res = writer.join().map_err(|_| "ssh-keygen stdin writer panicked")?;
    // Ignore BrokenPipe if ssh-keygen exited early on a bad signature; rely on exit status & stdout
    if let Err(e) = write_res
        && e.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(format!("failed writing payload to ssh-keygen: {e}"));
    }

    let stdout_s = String::from_utf8_lossy(&out.stdout);
    let stderr_s = String::from_utf8_lossy(&out.stderr);
    let expected_prefix = format!("Good \"git\" signature for {PRINCIPAL} with ED25519 key ");
    if out.status.success() && stdout_s.starts_with(&expected_prefix) {
        Ok(())
    } else {
        let detail = if !stderr_s.trim().is_empty() {
            stderr_s.trim()
        } else if !stdout_s.trim().is_empty() {
            stdout_s.trim()
        } else {
            "signature verification failed"
        };
        Err(format!("INVALID Ed25519 signature: {detail}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn extract_tag_ssh_signature_and_armor_validation() {
        let header_and_msg = b"object 0123456789abcdef0123456789abcdef01234567\ntype commit\ntag v1.0\ntagger Maya <m@e> 1 +0000\n\nRelease v1.0\n";
        let sig_block = b"-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n";
        let mut raw = Vec::new();
        raw.extend_from_slice(header_and_msg);
        raw.extend_from_slice(sig_block);

        let (payload, sig) = extract_tag_ssh_signature(&raw).unwrap();
        assert_eq!(payload, header_and_msg);
        assert_eq!(sig, sig_block);

        // Also valid without trailing newline after END line
        let mut raw_no_lf = Vec::new();
        raw_no_lf.extend_from_slice(header_and_msg);
        raw_no_lf.extend_from_slice(b"-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----");
        let (p2, s2) = extract_tag_ssh_signature(&raw_no_lf).unwrap();
        assert_eq!(p2, header_and_msg);
        assert!(s2.ends_with(b"-----END SSH SIGNATURE-----"));

        // Reject missing \n\n separator
        assert!(extract_tag_ssh_signature(b"object abc\ntype commit\ntag v1").is_err());
        // Reject missing SSH signature block (e.g. PGP)
        let mut pgp = header_and_msg.to_vec();
        pgp.extend_from_slice(b"-----BEGIN PGP SIGNATURE-----\nXXX\n-----END PGP SIGNATURE-----\n");
        assert!(extract_tag_ssh_signature(&pgp).is_err());
        // Reject duplicate SSH signature blocks
        let mut dup = raw.clone();
        dup.extend_from_slice(sig_block);
        assert!(extract_tag_ssh_signature(&dup).is_err());
        // Reject trailing bytes after END line
        let mut trailing = raw.clone();
        trailing.extend_from_slice(b"extra trailing line\n");
        assert!(extract_tag_ssh_signature(&trailing).is_err());

        // validate_ssh_sig_armor rejects either wrong BEGIN or wrong END independently
        assert!(validate_ssh_sig_armor(b"-----BEGIN SSH SIGNATURE-----\r\nX\r\n-----END SSH SIGNATURE-----\r\n").is_ok());
        assert!(validate_ssh_sig_armor(b"-----BEGIN PGP SIGNATURE-----\nX\n-----END SSH SIGNATURE-----\n").is_err());
        assert!(validate_ssh_sig_armor(b"-----BEGIN SSH SIGNATURE-----\nX\n-----END PGP SIGNATURE-----\n").is_err());
    }

    #[test]
    fn private_temp_dir_mode_and_drop_cleanup() {
        let dir_path = {
            let td = PrivateTempDir::create("git-signet-ut").unwrap();
            let p = td.0.clone();
            assert!(p.is_dir());
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o700);
            p
        };
        assert!(!dir_path.exists(), "PrivateTempDir::drop must remove temp dir");
    }
}

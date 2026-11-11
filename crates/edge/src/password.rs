//! htpasswd-style password hash verification.
//!
//! Supported formats: bcrypt (`$2a$`, `$2b$`, `$2x$`, `$2y$`), Apache `$apr1$`, md5-crypt
//! (`$1$`), sha256-crypt (`$5$`), sha512-crypt (`$6$`), argon2 (`$argon2id$`, `$argon2i$`,
//! `$argon2d$`) and the legacy `{SHA}` (base64 of SHA-1).
//!
//! Every hash is structurally validated before any computation: a recognised prefix with a
//! broken body is [`PasswordError::Malformed`], an unknown prefix is
//! [`PasswordError::Unsupported`]. [`is_supported`] and [`parse_htpasswd`] use that same
//! validation, so a typo in a configured hash fails at startup and not at the first login.
//!
//! Nothing in this module logs or formats a password or a hash.

use std::collections::HashSet;
use std::sync::LazyLock;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha1::{Digest as _, Sha1};
use subtle::ConstantTimeEq;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("unsupported password hash format")]
    Unsupported,
    #[error("malformed password hash: {0}")]
    Malformed(String),
    #[error("htpasswd line {line}: {reason}")]
    File { line: usize, reason: String },
}

fn malformed(why: &'static str) -> PasswordError {
    PasswordError::Malformed(why.to_owned())
}

/// A structurally valid hash, split into the parts needed to verify it.
enum Parsed<'a> {
    /// `legacy_x` marks `$2x$`, the pre-fix sign-extension variant.
    Bcrypt {
        hash: &'a str,
        legacy_x: bool,
    },
    Md5Crypt {
        magic: &'static [u8],
        salt: &'a str,
        digest: &'a str,
    },
    Sha256Crypt {
        hash: &'a str,
        digest: &'a str,
    },
    Sha512Crypt {
        hash: &'a str,
        digest: &'a str,
    },
    Argon2(PasswordHash<'a>),
    Sha1([u8; 20]),
}

const BCRYPT_MIN_COST: u32 = 4;
const BCRYPT_MAX_COST: u32 = 31;

fn is_b64_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'/'
}

fn all_b64(s: &str) -> bool {
    s.bytes().all(is_b64_char)
}

fn parse(hash: &str) -> Result<Parsed<'_>, PasswordError> {
    if let Some(rest) = hash.strip_prefix("{SHA}") {
        let raw = STANDARD
            .decode(rest)
            .map_err(|_| malformed("invalid base64 in {SHA} hash"))?;
        let digest: [u8; 20] = raw
            .try_into()
            .map_err(|_| malformed("{SHA} digest is not 20 bytes"))?;
        return Ok(Parsed::Sha1(digest));
    }
    for (prefix, legacy_x) in [
        ("$2a$", false),
        ("$2b$", false),
        ("$2y$", false),
        ("$2x$", true),
    ] {
        if let Some(rest) = hash.strip_prefix(prefix) {
            return parse_bcrypt(hash, rest, legacy_x);
        }
    }
    if let Some(rest) = hash.strip_prefix("$apr1$") {
        return parse_md5_crypt(b"$apr1$", rest);
    }
    if let Some(rest) = hash.strip_prefix("$1$") {
        return parse_md5_crypt(b"$1$", rest);
    }
    if let Some(rest) = hash.strip_prefix("$5$") {
        let digest = parse_sha2_crypt(rest, 43)?;
        return Ok(Parsed::Sha256Crypt { hash, digest });
    }
    if let Some(rest) = hash.strip_prefix("$6$") {
        let digest = parse_sha2_crypt(rest, 86)?;
        return Ok(Parsed::Sha512Crypt { hash, digest });
    }
    if hash.starts_with("$argon2id$")
        || hash.starts_with("$argon2i$")
        || hash.starts_with("$argon2d$")
    {
        let parsed = PasswordHash::new(hash).map_err(|_| malformed("invalid argon2 hash"))?;
        if parsed.hash.is_none() || parsed.salt.is_none() {
            return Err(malformed("argon2 hash lacks salt or digest"));
        }
        argon2::Params::try_from(&parsed).map_err(|_| malformed("invalid argon2 parameters"))?;
        return Ok(Parsed::Argon2(parsed));
    }
    Err(PasswordError::Unsupported)
}

/// `rest` follows the `$2?$` prefix: `NN$` cost, 22 salt chars, 31 digest chars.
fn parse_bcrypt<'a>(
    hash: &'a str,
    rest: &'a str,
    legacy_x: bool,
) -> Result<Parsed<'a>, PasswordError> {
    let bad = || malformed("invalid bcrypt hash");
    let bytes = rest.as_bytes();
    if bytes.len() != 56 || bytes[2] != b'$' || !all_b64(&rest[3..]) {
        return Err(bad());
    }
    if !bytes[..2].iter().all(u8::is_ascii_digit) {
        return Err(bad());
    }
    let cost: u32 = rest[..2].parse().map_err(|_| bad())?;
    if !(BCRYPT_MIN_COST..=BCRYPT_MAX_COST).contains(&cost) {
        return Err(bad());
    }
    Ok(Parsed::Bcrypt { hash, legacy_x })
}

/// `rest` follows the magic: `salt$digest`, 1 to 8 salt chars and 22 digest chars.
fn parse_md5_crypt<'a>(magic: &'static [u8], rest: &'a str) -> Result<Parsed<'a>, PasswordError> {
    let bad = || malformed("invalid md5-crypt hash");
    let (salt, digest) = rest.split_once('$').ok_or_else(bad)?;
    if salt.is_empty() || salt.len() > 8 || !all_b64(salt) || digest.len() != 22 || !all_b64(digest)
    {
        return Err(bad());
    }
    Ok(Parsed::Md5Crypt {
        magic,
        salt,
        digest,
    })
}

/// `rest` follows the magic: `[rounds=N$]salt$digest`. Returns the digest.
fn parse_sha2_crypt(rest: &str, digest_len: usize) -> Result<&str, PasswordError> {
    let bad = || malformed("invalid sha-crypt hash");
    let rest = match rest.strip_prefix("rounds=") {
        Some(after) => {
            let (rounds, tail) = after.split_once('$').ok_or_else(bad)?;
            if rounds.is_empty() || rounds.len() > 9 || !rounds.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(bad());
            }
            tail
        }
        None => rest,
    };
    let (salt, digest) = rest.split_once('$').ok_or_else(bad)?;
    if salt.is_empty() || salt.len() > 16 || !all_b64(salt) {
        return Err(bad());
    }
    if digest.len() != digest_len || !all_b64(digest) {
        return Err(bad());
    }
    Ok(digest)
}

/// True when `hash` is a format [`verify`] supports and its body is well formed.
pub fn is_supported(hash: &str) -> bool {
    parse(hash).is_ok()
}

/// Constant-time verify of `password` against `hash`.
///
/// Returns `Ok(false)` for a wrong password, `Err(Unsupported)` for an unknown format and
/// `Err(Malformed)` for a recognised prefix with a broken body. bcrypt and argon2 are CPU
/// heavy: call this from `spawn_blocking`.
///
/// `$2x$` hashes were made by a bcrypt with a sign-extension bug that only affects bytes
/// above 0x7f; for those passwords the result is always `false`, for ASCII passwords the
/// algorithm is identical to `$2y$`.
pub fn verify(hash: &str, password: &str) -> Result<bool, PasswordError> {
    let pw = password.as_bytes();
    match parse(hash)? {
        Parsed::Sha1(expected) => {
            let actual = Sha1::digest(pw);
            Ok(actual.as_slice().ct_eq(&expected).into())
        }
        Parsed::Bcrypt { hash, legacy_x } => {
            let hash = if legacy_x {
                if !password.is_ascii() {
                    return Ok(false);
                }
                format!("$2y${}", &hash[4..])
            } else {
                hash.to_owned()
            };
            let out = pwhash::bcrypt::hash_with(hash.as_str(), pw)
                .map_err(|_| malformed("bcrypt hash rejected"))?;
            Ok(tail_eq(&out, &hash, 31))
        }
        Parsed::Md5Crypt {
            magic,
            salt,
            digest,
        } => {
            let actual = md5_crypt(magic, pw, salt.as_bytes());
            Ok(actual.as_bytes().ct_eq(digest.as_bytes()).into())
        }
        #[allow(deprecated)]
        Parsed::Sha256Crypt { hash, digest } => {
            let out = pwhash::sha256_crypt::hash_with(hash, pw)
                .map_err(|_| malformed("sha256-crypt hash rejected"))?;
            Ok(tail_eq(&out, digest, digest.len()))
        }
        #[allow(deprecated)]
        Parsed::Sha512Crypt { hash, digest } => {
            let out = pwhash::sha512_crypt::hash_with(hash, pw)
                .map_err(|_| malformed("sha512-crypt hash rejected"))?;
            Ok(tail_eq(&out, digest, digest.len()))
        }
        Parsed::Argon2(parsed) => match Argon2::default().verify_password(pw, &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(_) => Err(malformed("argon2 hash rejected")),
        },
    }
}

/// Constant-time comparison of the last `n` bytes of `a` and `b`.
fn tail_eq(a: &str, b: &str, n: usize) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() < n || b.len() < n {
        return false;
    }
    a[a.len() - n..].ct_eq(&b[b.len() - n..]).into()
}

/// Parse an htpasswd file body into `(user, hash)` pairs in file order.
///
/// Blank lines and lines starting with `#` are ignored; each other line is split on its
/// first `:`. Errors carry the 1-based line number and never the hash text.
pub fn parse_htpasswd(text: &str) -> Result<Vec<(String, String)>, PasswordError> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fail = |reason: &str| PasswordError::File {
            line: line_no,
            reason: reason.to_owned(),
        };
        let (user, hash) = line
            .split_once(':')
            .ok_or_else(|| fail("missing ':' separator"))?;
        if user.is_empty() {
            return Err(fail("empty user name"));
        }
        if user.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(fail("user name contains whitespace or control characters"));
        }
        if hash.is_empty() {
            return Err(fail("empty hash"));
        }
        match parse(hash) {
            Ok(_) => {}
            Err(PasswordError::Unsupported) => return Err(fail("unsupported hash format")),
            Err(_) => return Err(fail("malformed hash")),
        }
        if !seen.insert(user.to_owned()) {
            return Err(fail("duplicate user"));
        }
        entries.push((user.to_owned(), hash.to_owned()));
    }
    Ok(entries)
}

// --- md5-crypt (`$1$`) and its Apache variant (`$apr1$`) -------------------------------

const CRYPT_ALPHABET: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Byte order of the md5-crypt digest before encoding.
const MD5_CRYPT_ORDER: [usize; 16] = [12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11];

/// md5-crypt digest string (22 chars) for `pass` and `salt` under `magic`.
fn md5_crypt(magic: &[u8], pass: &[u8], salt: &[u8]) -> String {
    let mut buf = Vec::with_capacity(pass.len() * 2 + salt.len() + 64);

    buf.extend_from_slice(pass);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(pass);
    let alt = md5(&buf);

    buf.clear();
    buf.extend_from_slice(pass);
    buf.extend_from_slice(magic);
    buf.extend_from_slice(salt);
    let mut remaining = pass.len();
    while remaining > 0 {
        buf.extend_from_slice(&alt[..remaining.min(16)]);
        remaining = remaining.saturating_sub(16);
    }
    let mut bits = pass.len();
    while bits > 0 {
        buf.push(if bits & 1 == 1 { 0 } else { pass[0] });
        bits >>= 1;
    }
    let mut digest = md5(&buf);

    for round in 0..1000 {
        buf.clear();
        buf.extend_from_slice(if round % 2 == 1 { pass } else { &digest });
        if round % 3 != 0 {
            buf.extend_from_slice(salt);
        }
        if round % 7 != 0 {
            buf.extend_from_slice(pass);
        }
        buf.extend_from_slice(if round % 2 == 1 { &digest } else { pass });
        digest = md5(&buf);
    }

    let mut ordered = [0u8; 16];
    for (dst, &src) in ordered.iter_mut().zip(MD5_CRYPT_ORDER.iter()) {
        *dst = digest[src];
    }
    crypt_b64(&ordered)
}

/// crypt(3) base64: little-endian 6-bit groups over 3-byte blocks.
fn crypt_b64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut v = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            v |= u32::from(b) << (8 * i);
        }
        for _ in 0..chunk.len() + 1 {
            out.push(char::from(CRYPT_ALPHABET[(v & 0x3f) as usize]));
            v >>= 6;
        }
    }
    out
}

// --- MD5 (RFC 1321) --------------------------------------------------------------------

const MD5_SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// `floor(abs(sin(i + 1)) * 2^32)`, as defined by RFC 1321.
static MD5_K: LazyLock<[u32; 64]> = LazyLock::new(|| {
    let mut k = [0u32; 64];
    for (i, v) in k.iter_mut().enumerate() {
        *v = ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32;
    }
    k
});

fn md5(data: &[u8]) -> [u8; 16] {
    let mut state = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let (blocks, rem) = data.as_chunks::<64>();
    for chunk in blocks {
        md5_block(&mut state, chunk);
    }
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let tail_len = if rem.len() < 56 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8);
    tail[tail_len - 8..tail_len].copy_from_slice(&bits.to_le_bytes());
    for chunk in tail[..tail_len].as_chunks::<64>().0 {
        md5_block(&mut state, chunk);
    }
    let mut out = [0u8; 16];
    for (dst, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *dst = word.to_le_bytes();
    }
    out
}

fn md5_block(state: &mut [u32; 4], chunk: &[u8]) {
    let k = &*MD5_K;
    let mut m = [0u32; 16];
    for (word, bytes) in m.iter_mut().zip(chunk.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    let [mut a, mut b, mut c, mut d] = *state;
    for i in 0..64 {
        let (f, g) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let rotated = a
            .wrapping_add(f)
            .wrapping_add(k[i])
            .wrapping_add(m[g])
            .rotate_left(MD5_SHIFTS[i]);
        let next_b = b.wrapping_add(rotated);
        a = d;
        d = c;
        c = b;
        b = next_b;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "pw";
    const UNICODE_PW: &str = "pä🙂ss";

    // Vectors produced offline with htpasswd (-B -C 4/5, -m, -s), openssl passwd, mkpasswd and
    // `openssl kdf` (argon2: m=64 KiB, t=2, p=1, salt "somesalt12345678", password "pw").
    const BCRYPT_PW: &str = "$2y$05$9kShsAtlNCrJt6mzeG3tzu/GJmRia.42/9BNHkIxuCm5s6Bbvz9PS";
    const BCRYPT_UNICODE: &str = "$2y$04$Rd8K97y1JOl4Aovi5oXB4.utjI4ht3FvQb4dsNKAcCnuB/KbqZpHq";
    const BCRYPT_EMPTY: &str = "$2y$04$DqtNo7kdWgNUE039taeDWeq3l52n/XxFg1J0LlcBJqN.oN4MyQQl.";
    const BCRYPT_80_X: &str = "$2y$04$V3buQjBk/5t4FwMkfRip6OmNDFWWxEtMMZbQHDF5WM/Cc.59a8pPG";
    const APR1_PW: &str = "$apr1$xoajiJox$7ZQq5Cq52dHdEWi2OljH80";
    const APR1_PW_2: &str = "$apr1$abcdefgh$5VEbMkemELfbhC5ck.U.z1";
    const APR1_UNICODE: &str = "$apr1$vKC0TvGY$LciJzOVFJf8zGXEZI3qMq/";
    const APR1_40_Y: &str = "$apr1$qppYH.Ty$mPxW6PRPgiBgTiYrenaJz1";
    const MD5_PW: &str = "$1$abcdefgh$IQtUouv7y7Q9dRWkQEPCc.";
    const MD5_EMPTY: &str = "$1$abcdefgh$M55TzYaaccxVGbptZWaxX/";
    const MD5_SHORT_SALT: &str = "$1$a$Slr4opLRbq0iJ7N2AZjfg/";
    const SHA256_PW: &str = "$5$abcdefgh$ijtOJ//yvc/9bq1g0llFn9dB688BwBDRD90DlKKSKE1";
    const SHA256_UNICODE: &str = "$5$abcdefgh$wRGhkcRBKD4fPsaEh9L0gGOiXfJpnRsDQd/6LPbW7y6";
    const SHA256_ROUNDS: &str =
        "$5$rounds=10000$abcdefgh$xmSKbccVzXmdOXRnqXC9PowqSlkM8xjFOGTaRq5MFx6";
    const SHA512_PW: &str = "$6$abcdefgh$KQeXafAQAaOoKTevphVU215RvJdgzyfASRasIOuh12hO8u0r1bGW92ZnTmC9IjsiQ8VPiTXBiZF49dFL1U4wX/";
    const SHA512_UNICODE: &str = "$6$abcdefgh$9zL9xakUqI4TH4bWmtZV9oOnvlN7eMPdWQO.v.P1BzcfbTMAq.ebUhE6IJxz7LlrYDNuECubpdXNOVFYBa.f61";
    const SHA512_ROUNDS: &str = "$6$rounds=2000$abcdefgh$otJG93vNioR1bvMUCsi7FbFDVVoR60pjkn9wO0GEMiVyX1q4RjrwzcWpUXcM.zRaFr6TPTM.oEPL6SQqnzH621";
    const SHA1_PW: &str = "{SHA}GpHWL3ymc5liWkNopqtdSjuqYHM=";
    const ARGON2ID: &str = "$argon2id$v=19$m=64,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$o9++TK5QP+5YLuLn3BKOuPYkAtiyr//yLuowjqqS2p4";
    const ARGON2I: &str = "$argon2i$v=19$m=64,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$fIqExfbSO7IzzC6xL0gTNIonZPqGmlMWA+6h6E1NGtM";
    const ARGON2D: &str = "$argon2d$v=19$m=64,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$+aZl77TFzrUwUPy9gWnKaRMhemotRMTIffyP9bRvPPc";

    fn ok(hash: &str, pw: &str) {
        assert!(verify(hash, pw).expect("verify"), "{hash} should accept");
    }

    fn no(hash: &str, pw: &str) {
        assert!(!verify(hash, pw).expect("verify"), "{hash} should reject");
    }

    #[test]
    fn md5_rfc1321_vectors() {
        let hex = |d: [u8; 16]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            hex(md5(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            hex(md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
        // Padding boundaries: 55, 56 and 64 bytes.
        assert_eq!(hex(md5(&[b'a'; 55])), "ef1772b6dff9a122358552954ad0df65");
        assert_eq!(hex(md5(&[b'a'; 56])), "3b0c8ac703f828b04c6c197006d17218");
        assert_eq!(hex(md5(&[b'a'; 64])), "014842d480b571495a4a0363793f7367");
    }

    #[test]
    fn own_md5_crypt_matches_pwhash() {
        #[allow(deprecated)]
        for (pass, salt) in [
            ("", "abcdefgh"),
            ("pw", "a"),
            ("password", "5pZSV9va"),
            ("exactly-sixteen!", "salt"),
            (
                "a-password-longer-than-sixteen-bytes-for-the-loop",
                "Zz09./xy",
            ),
            ("pä🙂ss", "12345678"),
        ] {
            let theirs = pwhash::md5_crypt::hash_with(format!("$1${salt}$").as_str(), pass)
                .expect("pwhash md5-crypt");
            let ours = format!(
                "$1${salt}${}",
                md5_crypt(b"$1$", pass.as_bytes(), salt.as_bytes())
            );
            assert_eq!(ours, theirs, "pass {pass:?} salt {salt}");
        }
    }

    #[test]
    fn bcrypt_vectors() {
        ok(BCRYPT_PW, PW);
        no(BCRYPT_PW, "pW");
        no(BCRYPT_PW, "");
        ok(BCRYPT_UNICODE, UNICODE_PW);
        no(BCRYPT_UNICODE, "pä🙂s");
        ok(BCRYPT_EMPTY, "");
        no(BCRYPT_EMPTY, " ");
        // bcrypt only looks at the first 72 bytes.
        ok(BCRYPT_80_X, &"x".repeat(80));
        ok(BCRYPT_80_X, &"x".repeat(72));
        no(BCRYPT_80_X, &"x".repeat(71));
    }

    #[test]
    fn bcrypt_variants() {
        for variant in ["2a", "2b", "2x", "2y"] {
            let hash = BCRYPT_PW.replacen("$2y$", &format!("${variant}$"), 1);
            assert!(is_supported(&hash), "{variant}");
            ok(&hash, PW);
            no(&hash, "other");
        }
        // $2x$ cannot be verified for non-ASCII passwords: never a false positive.
        let hash = BCRYPT_UNICODE.replacen("$2y$", "$2x$", 1);
        no(&hash, UNICODE_PW);
    }

    #[test]
    fn bcrypt_round_trip_with_pwhash() {
        let hash = pwhash::bcrypt::hash_with(
            pwhash::bcrypt::BcryptSetup {
                salt: None,
                cost: Some(4),
                variant: Some(pwhash::bcrypt::BcryptVariant::V2b),
            },
            "round trip",
        )
        .expect("hash");
        assert!(hash.starts_with("$2b$04$"));
        ok(&hash, "round trip");
        no(&hash, "round trip!");
    }

    #[test]
    fn apr1_vectors() {
        ok(APR1_PW, PW);
        no(APR1_PW, "pw ");
        ok(APR1_PW_2, PW);
        no(APR1_PW_2, "wp");
        ok(APR1_UNICODE, UNICODE_PW);
        no(APR1_UNICODE, PW);
        ok(APR1_40_Y, &"y".repeat(40));
        no(APR1_40_Y, &"y".repeat(39));
    }

    #[test]
    fn md5_crypt_vectors() {
        ok(MD5_PW, PW);
        no(MD5_PW, "pw2");
        ok(MD5_EMPTY, "");
        no(MD5_EMPTY, PW);
        ok(MD5_SHORT_SALT, PW);
        ok("$1$12345678$OYWcP3UEQ50eVnrC3.L3v/", PW);
        // The same body under the other magic must not verify.
        no("$apr1$abcdefgh$IQtUouv7y7Q9dRWkQEPCc.", PW);
    }

    #[test]
    fn sha2_crypt_vectors() {
        ok(SHA256_PW, PW);
        no(SHA256_PW, "Pw");
        ok(SHA256_UNICODE, UNICODE_PW);
        no(SHA256_UNICODE, PW);
        ok(SHA256_ROUNDS, PW);
        no(SHA256_ROUNDS, "pw1");
        ok(SHA512_PW, PW);
        no(SHA512_PW, "Pw");
        ok(SHA512_UNICODE, UNICODE_PW);
        no(SHA512_UNICODE, "pä🙂s");
        ok(SHA512_ROUNDS, PW);
        no(SHA512_ROUNDS, "");
        ok(
            "$6$abcdefgh$ZJq9WpQ.Trbq8VAZQ28qDnYmkQtppl7hbRvukgOMDzw1sZifz4Ql/Gbz4yshs1YZFNpTc4IB6mg59Xuix1h9J/",
            &"x".repeat(40),
        );
        // Published reference vectors from the sha-crypt specification.
        ok(
            "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
            "Hello world!",
        );
        ok(
            "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
            "Hello world!",
        );
    }

    #[test]
    fn sha1_vectors() {
        ok(SHA1_PW, PW);
        no(SHA1_PW, "pw1");
        no(SHA1_PW, "");
        ok("{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "password");
        let empty = format!("{{SHA}}{}", STANDARD.encode(Sha1::digest(b"")));
        ok(&empty, "");
        no(&empty, "x");
    }

    #[test]
    fn argon2_vectors() {
        for hash in [ARGON2ID, ARGON2I, ARGON2D] {
            ok(hash, PW);
            no(hash, "pw1");
            no(hash, "");
            no(hash, UNICODE_PW);
        }
    }

    #[test]
    fn argon2_round_trip_with_crate() {
        use argon2::PasswordHasher;
        use argon2::password_hash::SaltString;
        use argon2::password_hash::rand_core::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let params = argon2::Params::new(64, 2, 1, None).expect("params");
        let hasher = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let hash = hasher
            .hash_password(UNICODE_PW.as_bytes(), &salt)
            .expect("hash")
            .to_string();
        assert!(is_supported(&hash));
        ok(&hash, UNICODE_PW);
        no(&hash, "nope");
    }

    #[test]
    fn unsupported_formats() {
        for hash in [
            "",
            "plaintext",
            "abJnggxhB/yWI", // DES crypt
            "{SSHA}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$sha1$1000$abc$def",
            "$2$05$9kShsAtlNCrJt6mzeG3tzu/GJmRia.42/9BNHkIxuCm5s6Bbvz9PS",
            "$7$abc",
            "$y$j9T$abc$def",
            "$argon2$abc",
            "$pbkdf2-sha256$1$a$b",
        ] {
            assert!(!is_supported(hash), "{hash}");
            assert!(
                matches!(verify(hash, PW), Err(PasswordError::Unsupported)),
                "{hash}"
            );
        }
    }

    #[test]
    fn truncated_and_broken_hashes_are_malformed() {
        let broken = [
            &BCRYPT_PW[..BCRYPT_PW.len() - 1],
            &BCRYPT_PW[..20],
            "$2y$",
            "$2y$05$",
            "$2y$03$9kShsAtlNCrJt6mzeG3tzu/GJmRia.42/9BNHkIxuCm5s6Bbvz9PS", // cost below 4
            "$2y$32$9kShsAtlNCrJt6mzeG3tzu/GJmRia.42/9BNHkIxuCm5s6Bbvz9PS", // cost above 31
            "$2y$0x$9kShsAtlNCrJt6mzeG3tzu/GJmRia.42/9BNHkIxuCm5s6Bbvz9PS",
            "$2y$05$9kShsAtlNCrJt6mzeG3tzu/GJmRia.42/9BNHkIxuCm5s6Bbvz9P!",
            &APR1_PW[..APR1_PW.len() - 1],
            "$apr1$",
            "$apr1$salt",
            "$apr1$$7ZQq5Cq52dHdEWi2OljH80",
            "$apr1$toolongsalt$7ZQq5Cq52dHdEWi2OljH80",
            &MD5_PW[..MD5_PW.len() - 3],
            "$1$abcdefgh",
            &SHA256_PW[..SHA256_PW.len() - 1],
            &SHA512_PW[..SHA512_PW.len() - 1],
            "$5$",
            "$5$abcdefgh",
            "$5$rounds=$abcdefgh$ijtOJ//yvc/9bq1g0llFn9dB688BwBDRD90DlKKSKE1",
            "$5$rounds=abc$abcdefgh$ijtOJ//yvc/9bq1g0llFn9dB688BwBDRD90DlKKSKE1",
            "$5$rounds=1000",
            "$6$abcdefgh$",
            "{SHA}",
            "{SHA}not base64!",
            "{SHA}AAAA",
            &SHA1_PW[..SHA1_PW.len() - 4],
            &ARGON2ID[..ARGON2ID.len() - 10],
            "$argon2id$",
            "$argon2id$v=19$m=64,t=2,p=1",
            "$argon2id$v=19$m=64,t=2,p=1$c29tZXNhbHQ",
            "$argon2id$v=19$m=0,t=0,p=0$c29tZXNhbHQxMjM0NTY3OA$o9++TK5QP+5YLuLn3BKOuPYkAtiyr//yLuowjqqS2p4",
        ];
        for hash in broken {
            assert!(!is_supported(hash), "{hash}");
            match verify(hash, PW) {
                Err(PasswordError::Malformed(msg)) => {
                    assert!(
                        hash.len() < 8 || !msg.contains(hash),
                        "error leaks the hash"
                    );
                }
                other => panic!("{hash}: {other:?}"),
            }
        }
    }

    #[test]
    fn verify_error_text_never_contains_password() {
        let err = verify("{SHA}broken!", "hunter2-secret").expect_err("malformed");
        assert!(!err.to_string().contains("hunter2-secret"));
        assert!(!err.to_string().contains("broken!"));
    }

    #[test]
    fn supported_hashes_are_supported() {
        for hash in [
            BCRYPT_PW,
            APR1_PW,
            MD5_PW,
            SHA256_PW,
            SHA256_ROUNDS,
            SHA512_PW,
            SHA512_ROUNDS,
            SHA1_PW,
            ARGON2ID,
            ARGON2I,
            ARGON2D,
        ] {
            assert!(is_supported(hash), "{hash}");
        }
    }

    #[test]
    fn htpasswd_parses_in_file_order() {
        let text = format!(
            "# comment\n\nalice:{BCRYPT_PW}\r\nbob:{APR1_PW}\n   \n#bob:{SHA1_PW}\ncarol:{SHA1_PW}"
        );
        let entries = parse_htpasswd(&text).expect("parse");
        assert_eq!(
            entries,
            vec![
                ("alice".to_owned(), BCRYPT_PW.to_owned()),
                ("bob".to_owned(), APR1_PW.to_owned()),
                ("carol".to_owned(), SHA1_PW.to_owned()),
            ]
        );
        assert!(parse_htpasswd("").expect("empty").is_empty());
        assert!(
            parse_htpasswd("# only a comment\n")
                .expect("comment")
                .is_empty()
        );
    }

    #[test]
    fn htpasswd_splits_on_first_colon_only() {
        // `:` cannot appear in a supported hash, so a second colon makes the hash malformed...
        let err = parse_htpasswd(&format!("a:{SHA1_PW}:extra")).expect_err("extra colon");
        assert!(matches!(err, PasswordError::File { line: 1, .. }));
        // ...but a user keeps everything before the first colon and nothing after.
        let entries = parse_htpasswd(&format!("a:{SHA1_PW}")).expect("ok");
        assert_eq!(entries[0].0, "a");
    }

    fn line_of(err: PasswordError) -> (usize, String) {
        match err {
            PasswordError::File { line, reason } => (line, reason),
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn htpasswd_errors_carry_line_numbers_not_hashes() {
        let secret_hash = "$apr1$abcdefgh$SECRETSECRETSECRET";
        let cases: Vec<(String, usize)> = vec![
            ("novalue".to_owned(), 1),
            (format!(":{SHA1_PW}"), 1),
            ("alice:".to_owned(), 1),
            (format!("# c\n\nal ice:{SHA1_PW}"), 3),
            (format!("ali\tce:{SHA1_PW}"), 1),
            (format!("ali\u{7}ce:{SHA1_PW}"), 1),
            (format!("ok:{SHA1_PW}\nbad:plaintext"), 2),
            (format!("ok:{SHA1_PW}\n\nbad:{secret_hash}"), 3),
            (format!("a:{SHA1_PW}\nb:{SHA1_PW}\na:{APR1_PW}"), 3),
        ];
        for (text, want_line) in cases {
            let err = parse_htpasswd(&text).expect_err(&text);
            let shown = err.to_string();
            let (line, reason) = line_of(err);
            assert_eq!(line, want_line, "{text:?}");
            assert!(shown.contains(&format!("line {want_line}")));
            assert!(!shown.contains("plaintext") && !shown.contains("SECRET"));
            assert!(!reason.contains(SHA1_PW));
        }
    }

    #[test]
    fn htpasswd_rejects_user_with_control_chars_and_dupes_case_sensitively() {
        let text = format!("Alice:{SHA1_PW}\nalice:{SHA1_PW}");
        assert_eq!(parse_htpasswd(&text).expect("case differs").len(), 2);
        let (line, reason) = line_of(
            parse_htpasswd(&format!("alice:{SHA1_PW}\nalice:{SHA1_PW}")).expect_err("dupe"),
        );
        assert_eq!((line, reason.as_str()), (2, "duplicate user"));
    }
}

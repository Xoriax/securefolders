use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AppError, AppResult};

type HmacSha256 = Hmac<Sha256>;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// Nonce prefix length for the streaming (STREAM construction) file
/// encryption below: AES-GCM's 12-byte nonce minus the 5 bytes the STREAM
/// construction reserves internally (4-byte big-endian counter + 1-byte
/// "last chunk" flag).
const STREAM_NONCE_LEN: usize = 7;
/// Plaintext bytes per chunk. Bounds peak memory usage for `encrypt_file`/
/// `decrypt_file` regardless of file size — the whole point of streaming.
const STREAM_CHUNK_LEN: usize = 64 * 1024;
/// AES-GCM authentication tag size, appended to every chunk's ciphertext.
const STREAM_TAG_LEN: usize = 16;

/// Argon2id parameters for a given vault. Stored alongside the vault so a
/// future version of the app can change the defaults without breaking
/// existing vaults.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // ~64 MiB / 3 passes: deliberately expensive to slow down offline
        // brute-force of a stolen vault, while staying under ~1s on modern hardware.
        Self {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// A raw encryption key held only in memory. Never serialized, never written
/// to disk, wiped as soon as it is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey(pub [u8; KEY_LEN]);

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

fn random_stream_nonce() -> [u8; STREAM_NONCE_LEN] {
    let mut nonce = [0u8; STREAM_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derives a 256-bit key from the master password using Argon2id.
pub fn derive_key(password: &str, salt: &[u8], params: &Argon2Params) -> AppResult<VaultKey> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| AppError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    Ok(VaultKey(key))
}

/// Encrypts `plaintext` with AES-256-GCM under `key`, using a fresh random
/// nonce. Returns `nonce || ciphertext_with_tag`, self-contained so it can be
/// stored and decrypted without extra bookkeeping.
pub fn encrypt(key: &VaultKey, plaintext: &[u8]) -> AppResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts data produced by [`encrypt`]: splits off the leading nonce, then
/// verifies and decrypts the AES-GCM payload.
pub fn decrypt(key: &VaultKey, data: &[u8]) -> AppResult<Vec<u8>> {
    if data.len() < NONCE_LEN {
        return Err(AppError::Crypto("donnees chiffrees invalides".into()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AppError::WrongPassword)
}

/// Reads up to `len` bytes from `reader` into a freshly allocated buffer,
/// stopping early (with a shorter buffer) at EOF. An empty result means EOF
/// was reached immediately, with nothing read.
fn read_chunk<R: Read>(reader: &mut R, len: usize) -> AppResult<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Encrypts `source` into `dest` in fixed-size chunks (AES-256-GCM under the
/// STREAM construction: a random 7-byte nonce prefix plus an internal
/// per-chunk counter, so chunks can't be reordered, dropped, or truncated
/// without detection). Unlike [`encrypt`], the file is never held in memory
/// in full — only one chunk at a time — so this is safe to use regardless of
/// file size.
///
/// Output layout: `nonce_prefix(7) || chunk_0(≤64KiB+16) || chunk_1 || ...`,
/// where every chunk but the last is exactly `STREAM_CHUNK_LEN` plaintext
/// bytes plus a 16-byte tag.
///
/// `on_progress(bytes_done, bytes_total)` is called after every chunk (both
/// counted in plaintext bytes) so a caller can drive a progress bar; pass
/// `|_, _| {}` to ignore it.
pub fn encrypt_file(
    key: &VaultKey,
    source: &Path,
    dest: &Path,
    mut on_progress: impl FnMut(u64, u64),
) -> AppResult<()> {
    let total_len = std::fs::metadata(source)?.len();
    let nonce_bytes = random_stream_nonce();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let mut encryptor = EncryptorBE32::from_aead(cipher, GenericArray::from_slice(&nonce_bytes));

    let mut input = BufReader::new(File::open(source)?);
    let mut output = BufWriter::new(File::create(dest)?);
    output.write_all(&nonce_bytes)?;

    let mut done: u64 = 0;
    on_progress(done, total_len);

    let mut current = read_chunk(&mut input, STREAM_CHUNK_LEN)?;
    loop {
        let next = read_chunk(&mut input, STREAM_CHUNK_LEN)?;
        if next.is_empty() {
            let chunk_len = current.len() as u64;
            let ciphertext = encryptor
                .encrypt_last(current.as_slice())
                .map_err(|e| AppError::Crypto(e.to_string()))?;
            output.write_all(&ciphertext)?;
            done += chunk_len;
            on_progress(done, total_len);
            break;
        }
        let chunk_len = current.len() as u64;
        let ciphertext = encryptor
            .encrypt_next(current.as_slice())
            .map_err(|e| AppError::Crypto(e.to_string()))?;
        output.write_all(&ciphertext)?;
        done += chunk_len;
        on_progress(done, total_len);
        current = next;
    }
    output.flush()?;
    Ok(())
}

/// Decrypts a file produced by [`encrypt_file`], streaming chunk by chunk.
/// Fails with `WrongPassword` if the key is wrong or any chunk's tag doesn't
/// verify (including a truncated or reordered file, which the STREAM
/// construction's internal counter detects).
///
/// `on_progress(bytes_done, bytes_total)` is called after every chunk (both
/// counted in ciphertext bytes read) so a caller can drive a progress bar.
pub fn decrypt_file(
    key: &VaultKey,
    source: &Path,
    dest: &Path,
    mut on_progress: impl FnMut(u64, u64),
) -> AppResult<()> {
    let total_len = std::fs::metadata(source)?.len();
    let mut input = BufReader::new(File::open(source)?);
    let mut nonce_bytes = [0u8; STREAM_NONCE_LEN];
    input
        .read_exact(&mut nonce_bytes)
        .map_err(|_| AppError::Crypto("fichier chiffre invalide".into()))?;

    let mut done: u64 = STREAM_NONCE_LEN as u64;
    on_progress(done, total_len);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let mut decryptor = DecryptorBE32::from_aead(cipher, GenericArray::from_slice(&nonce_bytes));

    let mut output = BufWriter::new(File::create(dest)?);
    let chunk_ciphertext_len = STREAM_CHUNK_LEN + STREAM_TAG_LEN;

    let mut current = read_chunk(&mut input, chunk_ciphertext_len)?;
    loop {
        let next = read_chunk(&mut input, chunk_ciphertext_len)?;
        if next.is_empty() {
            let read_len = current.len() as u64;
            let plaintext = decryptor
                .decrypt_last(current.as_slice())
                .map_err(|_| AppError::WrongPassword)?;
            output.write_all(&plaintext)?;
            done += read_len;
            on_progress(done, total_len);
            break;
        }
        let read_len = current.len() as u64;
        let plaintext = decryptor
            .decrypt_next(current.as_slice())
            .map_err(|_| AppError::WrongPassword)?;
        output.write_all(&plaintext)?;
        done += read_len;
        on_progress(done, total_len);
        current = next;
    }
    output.flush()?;
    Ok(())
}

/// Computes an HMAC-SHA256 tag over `message`, keyed by `key`. Used to bind
/// security-critical metadata (e.g. whether 2FA is required) to the vault's
/// DEK, so tampering with the metadata file outside the app is detectable
/// instead of silently changing the app's behaviour.
pub fn compute_mac(key: &VaultKey, message: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&key.0).expect("HMAC accepts a key of any size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Verifies a tag produced by [`compute_mac`] in constant time.
pub fn verify_mac(key: &VaultKey, message: &[u8], tag: &[u8]) -> bool {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&key.0).expect("HMAC accepts a key of any size");
    mac.update(message);
    mac.verify_slice(tag).is_ok()
}

// Crockford-style alphabet with ambiguous characters (0/O, 1/I/L, U) removed,
// so a code read off a screenshot or printout is never misread.
const RECOVERY_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";
const RECOVERY_CODE_GROUPS: usize = 4;
const RECOVERY_CODE_GROUP_LEN: usize = 4;

/// Generates a single-use TOTP recovery code, e.g. `"XQ2P-7RTK-4MNC-9VWZ"`
/// (~80 bits of entropy — high enough that hashing with plain SHA-256,
/// rather than a slow KDF, is fine: brute force is infeasible regardless of
/// hash speed).
pub fn generate_recovery_code() -> String {
    let mut rng = rand::rngs::OsRng;
    (0..RECOVERY_CODE_GROUPS)
        .map(|_| {
            (0..RECOVERY_CODE_GROUP_LEN)
                .map(|_| {
                    let idx = (rng.next_u32() as usize) % RECOVERY_CODE_ALPHABET.len();
                    RECOVERY_CODE_ALPHABET[idx] as char
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Strips formatting so a code can be compared regardless of how the user
/// typed it back in (with/without dashes, lowercase, extra spaces).
pub fn normalize_recovery_code(code: &str) -> String {
    code.trim().to_uppercase().chars().filter(|c| !c.is_whitespace() && *c != '-').collect()
}

pub fn hash_recovery_code(code: &str) -> Vec<u8> {
    Sha256::digest(normalize_recovery_code(code).as_bytes()).to_vec()
}

/// Generates a fresh random Data Encryption Key (DEK). The DEK is what
/// actually encrypts vault files; it is itself encrypted with the key
/// derived from the master password (envelope encryption). This means
/// changing the master password only requires re-encrypting the small DEK,
/// not every file in the vault.
pub fn random_dek() -> VaultKey {
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    VaultKey(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal but valid Argon2id parameters, only for tests that need
    // determinism/speed rather than real security margins.
    fn fast_params() -> Argon2Params {
        Argon2Params { memory_kib: 8, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn derive_key_is_deterministic_for_same_input() {
        let salt = random_salt();
        let params = fast_params();
        let k1 = derive_key("correct horse battery staple", &salt, &params).unwrap();
        let k2 = derive_key("correct horse battery staple", &salt, &params).unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn derive_key_differs_for_different_passwords() {
        let salt = random_salt();
        let params = fast_params();
        let k1 = derive_key("password one", &salt, &params).unwrap();
        let k2 = derive_key("password two", &salt, &params).unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn derive_key_differs_for_different_salts() {
        let params = fast_params();
        let k1 = derive_key("same password", &random_salt(), &params).unwrap();
        let k2 = derive_key("same password", &random_salt(), &params).unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = random_dek();
        let plaintext = b"les fichiers secrets";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
        assert_eq!(decrypt(&key, &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn encrypt_uses_a_fresh_nonce_each_call() {
        let key = random_dek();
        let plaintext = b"same message every time";
        let c1 = encrypt(&key, plaintext).unwrap();
        let c2 = encrypt(&key, plaintext).unwrap();
        // Same plaintext, same key, but different random nonces must produce
        // different ciphertext — a repeated nonce under AES-GCM is catastrophic.
        assert_ne!(c1, c2);
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let ciphertext = encrypt(&random_dek(), b"data").unwrap();
        let wrong_key = random_dek();
        assert!(matches!(decrypt(&wrong_key, &ciphertext), Err(AppError::WrongPassword)));
    }

    #[test]
    fn decrypt_fails_when_ciphertext_is_tampered() {
        let key = random_dek();
        let mut ciphertext = encrypt(&key, b"integrity matters").unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        assert!(decrypt(&key, &ciphertext).is_err());
    }

    #[test]
    fn mac_roundtrip_succeeds_and_detects_tampering() {
        let key = random_dek();
        let message = b"totp_enabled=true";
        let tag = compute_mac(&key, message);

        assert!(verify_mac(&key, message, &tag));
        assert!(!verify_mac(&key, b"totp_enabled=false", &tag));

        let other_key = random_dek();
        assert!(!verify_mac(&other_key, message, &tag));
    }

    #[test]
    fn recovery_code_hash_ignores_case_dashes_and_whitespace() {
        let code = generate_recovery_code();
        let hash = hash_recovery_code(&code);
        let messy = format!(" {} ", code.to_lowercase().replace('-', " - "));
        assert_eq!(hash, hash_recovery_code(&messy));
    }

    #[test]
    fn recovery_code_has_expected_shape() {
        let code = generate_recovery_code();
        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), RECOVERY_CODE_GROUPS);
        for group in groups {
            assert_eq!(group.len(), RECOVERY_CODE_GROUP_LEN);
            assert!(group.bytes().all(|b| RECOVERY_CODE_ALPHABET.contains(&b)));
        }
    }

    #[test]
    fn recovery_codes_are_not_all_identical() {
        // Sanity check that generation is actually randomized, not a fixed string.
        let codes: std::collections::HashSet<String> =
            (0..20).map(|_| generate_recovery_code()).collect();
        assert!(codes.len() > 1);
    }

    fn roundtrip_file(key: &VaultKey, plaintext: &[u8]) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("plain.bin");
        let ciphertext_path = dir.path().join("cipher.bin");
        let decrypted_path = dir.path().join("decrypted.bin");

        std::fs::write(&source, plaintext).unwrap();
        encrypt_file(key, &source, &ciphertext_path, |_, _| {}).unwrap();
        decrypt_file(key, &ciphertext_path, &decrypted_path, |_, _| {}).unwrap();
        std::fs::read(&decrypted_path).unwrap()
    }

    #[test]
    fn encrypt_file_roundtrip_for_an_empty_file() {
        let key = random_dek();
        assert_eq!(roundtrip_file(&key, b""), b"");
    }

    #[test]
    fn encrypt_file_roundtrip_smaller_than_one_chunk() {
        let key = random_dek();
        let plaintext = b"un petit fichier tient dans un seul chunk";
        assert_eq!(roundtrip_file(&key, plaintext), plaintext);
    }

    #[test]
    fn encrypt_file_roundtrip_across_multiple_chunks() {
        let key = random_dek();
        // A bit over 2 chunks, and not aligned on a chunk boundary, to
        // exercise the "next vs last chunk" bookkeeping in both functions.
        let plaintext: Vec<u8> = (0..(STREAM_CHUNK_LEN * 2 + 12345))
            .map(|i| (i % 251) as u8)
            .collect();
        assert_eq!(roundtrip_file(&key, &plaintext), plaintext);
    }

    #[test]
    fn encrypt_file_roundtrip_exactly_one_chunk_boundary() {
        let key = random_dek();
        let plaintext = vec![0x42u8; STREAM_CHUNK_LEN];
        assert_eq!(roundtrip_file(&key, &plaintext), plaintext);
    }

    #[test]
    fn decrypt_file_fails_with_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("plain.bin");
        let ciphertext_path = dir.path().join("cipher.bin");
        let decrypted_path = dir.path().join("decrypted.bin");

        std::fs::write(&source, b"des donnees sensibles").unwrap();
        encrypt_file(&random_dek(), &source, &ciphertext_path, |_, _| {}).unwrap();

        let result = decrypt_file(&random_dek(), &ciphertext_path, &decrypted_path, |_, _| {});
        assert!(matches!(result, Err(AppError::WrongPassword)));
    }

    #[test]
    fn decrypt_file_fails_when_a_chunk_is_tampered() {
        let key = random_dek();
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("plain.bin");
        let ciphertext_path = dir.path().join("cipher.bin");
        let decrypted_path = dir.path().join("decrypted.bin");

        std::fs::write(&source, vec![0xAAu8; STREAM_CHUNK_LEN + 500]).unwrap();
        encrypt_file(&key, &source, &ciphertext_path, |_, _| {}).unwrap();

        let mut bytes = std::fs::read(&ciphertext_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&ciphertext_path, &bytes).unwrap();

        assert!(decrypt_file(&key, &ciphertext_path, &decrypted_path, |_, _| {}).is_err());
    }

    #[test]
    fn decrypt_file_fails_when_a_chunk_is_dropped() {
        // The STREAM construction's per-chunk counter must catch reordering
        // or removal of whole chunks, not just single-byte corruption.
        let key = random_dek();
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("plain.bin");
        let ciphertext_path = dir.path().join("cipher.bin");
        let decrypted_path = dir.path().join("decrypted.bin");

        std::fs::write(&source, vec![0x11u8; STREAM_CHUNK_LEN * 3]).unwrap();
        encrypt_file(&key, &source, &ciphertext_path, |_, _| {}).unwrap();

        let mut bytes = std::fs::read(&ciphertext_path).unwrap();
        let chunk_ct_len = STREAM_CHUNK_LEN + STREAM_TAG_LEN;
        // Drop the second chunk entirely (keep nonce + chunk 0 + chunk 2).
        bytes.drain(STREAM_NONCE_LEN + chunk_ct_len..STREAM_NONCE_LEN + 2 * chunk_ct_len);
        std::fs::write(&ciphertext_path, &bytes).unwrap();

        assert!(decrypt_file(&key, &ciphertext_path, &decrypted_path, |_, _| {}).is_err());
    }
}

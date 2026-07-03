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

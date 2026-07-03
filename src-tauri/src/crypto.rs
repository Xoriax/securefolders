use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AppError, AppResult};

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

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{self, Argon2Params, VaultKey};
use crate::error::{AppError, AppResult};

const METADATA_FILE: &str = "vault.json";
const FILES_DIR: &str = "files";
const INDEX_FILE: &str = "vaults_index.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub id: Uuid,
    pub name: String,
    pub size: u64,
    pub added_at: DateTime<Utc>,
}

/// Everything needed to unlock and use a vault, persisted as `vault.json`
/// inside the vault folder. Never contains the password or any derived key
/// in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub id: Uuid,
    pub name: String,
    pub salt: Vec<u8>,
    pub argon2_params: Argon2Params,
    /// The random Data Encryption Key, itself encrypted with the key derived
    /// from the master password (envelope encryption).
    pub dek_encrypted: Vec<u8>,
    pub totp_enabled: bool,
    /// TOTP secret, encrypted with the DEK. `None` unless 2FA is enabled.
    pub totp_secret_encrypted: Option<Vec<u8>>,
    /// HMAC-SHA256 (keyed by the DEK) over the security-critical fields
    /// above. Verified on every unlock so that editing `vault.json` outside
    /// the app — e.g. flipping `totp_enabled` to `false` to strip 2FA —
    /// is detected instead of silently changing the app's behaviour.
    pub integrity_tag: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub files: Vec<FileEntry>,
}

/// Fields covered by `integrity_tag`. Kept separate from `VaultMetadata` so
/// its serialization (and therefore the MAC input) stays stable regardless
/// of unrelated metadata changes (e.g. `files`, `name`).
#[derive(Serialize)]
struct IntegrityFields<'a> {
    id: Uuid,
    totp_enabled: bool,
    totp_secret_encrypted: &'a Option<Vec<u8>>,
}

fn integrity_message(metadata: &VaultMetadata) -> Vec<u8> {
    serde_json::to_vec(&IntegrityFields {
        id: metadata.id,
        totp_enabled: metadata.totp_enabled,
        totp_secret_encrypted: &metadata.totp_secret_encrypted,
    })
    .expect("serializing integrity fields cannot fail")
}

fn seal_integrity(metadata: &mut VaultMetadata, dek: &VaultKey) {
    metadata.integrity_tag = crypto::compute_mac(dek, &integrity_message(metadata));
}

fn verify_integrity(metadata: &VaultMetadata, dek: &VaultKey) -> AppResult<()> {
    if crypto::verify_mac(dek, &integrity_message(metadata), &metadata.integrity_tag) {
        Ok(())
    } else {
        Err(AppError::VaultTampered)
    }
}

/// Lightweight pointer kept in the global index so vaults can live anywhere
/// on disk (per the "Emplacement sur le PC" requirement) while still being
/// listable without scanning the whole filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultIndexEntry {
    pub id: Uuid,
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSummary {
    pub id: Uuid,
    pub name: String,
    pub path: PathBuf,
    pub totp_enabled: bool,
    pub file_count: usize,
    pub created_at: DateTime<Utc>,
}

fn index_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(INDEX_FILE)
}

fn load_index(app_data_dir: &Path) -> AppResult<Vec<VaultIndexEntry>> {
    let path = index_path(app_data_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn save_index(app_data_dir: &Path, entries: &[VaultIndexEntry]) -> AppResult<()> {
    fs::create_dir_all(app_data_dir)?;
    let raw = serde_json::to_string_pretty(entries)?;
    fs::write(index_path(app_data_dir), raw)?;
    Ok(())
}

fn metadata_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(METADATA_FILE)
}

pub fn load_metadata(vault_dir: &Path) -> AppResult<VaultMetadata> {
    let raw = fs::read_to_string(metadata_path(vault_dir))?;
    Ok(serde_json::from_str(&raw)?)
}

fn save_metadata(vault_dir: &Path, metadata: &VaultMetadata) -> AppResult<()> {
    let raw = serde_json::to_string_pretty(metadata)?;
    fs::write(metadata_path(vault_dir), raw)?;
    Ok(())
}

/// Creates a new vault folder at `location/name`, generates its salt and a
/// random DEK wrapped by the password-derived key, and registers it in the
/// global index. Returns the metadata plus the vault's on-disk directory.
pub fn create_vault(
    app_data_dir: &Path,
    name: &str,
    location: &Path,
    password: &str,
) -> AppResult<(VaultMetadata, PathBuf)> {
    let vault_dir = location.join(sanitize_folder_name(name));
    if vault_dir.exists() {
        return Err(AppError::VaultAlreadyExists);
    }
    fs::create_dir_all(vault_dir.join(FILES_DIR))?;

    let salt = crypto::random_salt();
    let params = Argon2Params::default();
    let master_key = crypto::derive_key(password, &salt, &params)?;

    let dek = crypto::random_dek();
    let dek_encrypted = crypto::encrypt(&master_key, &dek.0)?;

    let mut metadata = VaultMetadata {
        id: Uuid::new_v4(),
        name: name.to_string(),
        salt: salt.to_vec(),
        argon2_params: params,
        dek_encrypted,
        totp_enabled: false,
        totp_secret_encrypted: None,
        integrity_tag: Vec::new(),
        created_at: Utc::now(),
        files: Vec::new(),
    };
    seal_integrity(&mut metadata, &dek);
    save_metadata(&vault_dir, &metadata)?;

    let mut index = load_index(app_data_dir)?;
    index.push(VaultIndexEntry {
        id: metadata.id,
        name: metadata.name.clone(),
        path: vault_dir.clone(),
    });
    save_index(app_data_dir, &index)?;

    Ok((metadata, vault_dir))
}

pub fn list_vaults(app_data_dir: &Path) -> AppResult<Vec<VaultSummary>> {
    let index = load_index(app_data_dir)?;
    let mut summaries = Vec::with_capacity(index.len());
    for entry in index {
        // Tolerate a vault folder that was moved or deleted outside the app
        // rather than failing the whole list.
        let Ok(metadata) = load_metadata(&entry.path) else {
            continue;
        };
        summaries.push(VaultSummary {
            id: metadata.id,
            name: metadata.name,
            path: entry.path,
            totp_enabled: metadata.totp_enabled,
            file_count: metadata.files.len(),
            created_at: metadata.created_at,
        });
    }
    Ok(summaries)
}

pub fn find_vault_path(app_data_dir: &Path, vault_id: Uuid) -> AppResult<PathBuf> {
    let index = load_index(app_data_dir)?;
    index
        .into_iter()
        .find(|e| e.id == vault_id)
        .map(|e| e.path)
        .ok_or(AppError::VaultNotFound)
}

/// Deletes a vault's folder (metadata + encrypted files) and removes it from
/// the index. Irreversible — the caller is expected to have already
/// confirmed this with the user.
pub fn delete_vault(app_data_dir: &Path, vault_id: Uuid) -> AppResult<()> {
    let vault_dir = find_vault_path(app_data_dir, vault_id)?;
    if vault_dir.exists() {
        fs::remove_dir_all(&vault_dir)?;
    }
    let mut index = load_index(app_data_dir)?;
    index.retain(|e| e.id != vault_id);
    save_index(app_data_dir, &index)
}

/// Renames a vault. Only the display name changes — the on-disk folder name
/// and the TOTP secret (whose algorithm never depends on the account label)
/// are unaffected.
pub fn rename_vault(app_data_dir: &Path, vault_id: Uuid, new_name: &str) -> AppResult<()> {
    let vault_dir = find_vault_path(app_data_dir, vault_id)?;
    let mut metadata = load_metadata(&vault_dir)?;
    metadata.name = new_name.to_string();
    save_metadata(&vault_dir, &metadata)?;

    let mut index = load_index(app_data_dir)?;
    if let Some(entry) = index.iter_mut().find(|e| e.id == vault_id) {
        entry.name = new_name.to_string();
    }
    save_index(app_data_dir, &index)
}

/// Rotates the master password: verifies `old_password`, then re-wraps the
/// *existing* DEK under a freshly derived key with a new salt. Because files
/// are encrypted with the DEK (not the password-derived key directly), this
/// never touches the encrypted files themselves.
pub fn change_master_password(
    vault_dir: &Path,
    old_password: &str,
    new_password: &str,
) -> AppResult<()> {
    let (metadata, dek) = unlock(vault_dir, old_password)?;
    let mut metadata = metadata;

    let new_salt = crypto::random_salt();
    let new_master_key = crypto::derive_key(new_password, &new_salt, &metadata.argon2_params)?;
    metadata.salt = new_salt.to_vec();
    metadata.dek_encrypted = crypto::encrypt(&new_master_key, &dek.0)?;
    save_metadata(vault_dir, &metadata)
}

/// Derives the master key from the password and unwraps the DEK. Fails with
/// `WrongPassword` if the password is incorrect (AES-GCM auth failure on the
/// wrapped DEK).
pub fn unlock(vault_dir: &Path, password: &str) -> AppResult<(VaultMetadata, VaultKey)> {
    let metadata = load_metadata(vault_dir)?;
    let master_key = crypto::derive_key(password, &metadata.salt, &metadata.argon2_params)?;
    let dek_bytes = crypto::decrypt(&master_key, &metadata.dek_encrypted)?;
    let dek: [u8; crypto::KEY_LEN] = dek_bytes
        .try_into()
        .map_err(|_| AppError::Crypto("taille de cle invalide".into()))?;
    let dek = VaultKey(dek);

    // Must run after the password is known to be correct (constant-time
    // AEAD failure vs. tamper failure would otherwise leak which case
    // occurred) and before the caller trusts `totp_enabled`.
    verify_integrity(&metadata, &dek)?;

    Ok((metadata, dek))
}

pub fn enable_totp(
    vault_dir: &Path,
    dek: &VaultKey,
    secret_base32: &str,
) -> AppResult<()> {
    let mut metadata = load_metadata(vault_dir)?;
    let encrypted_secret = crypto::encrypt(dek, secret_base32.as_bytes())?;
    metadata.totp_enabled = true;
    metadata.totp_secret_encrypted = Some(encrypted_secret);
    seal_integrity(&mut metadata, dek);
    save_metadata(vault_dir, &metadata)
}

pub fn disable_totp(vault_dir: &Path, dek: &VaultKey) -> AppResult<()> {
    let mut metadata = load_metadata(vault_dir)?;
    metadata.totp_enabled = false;
    metadata.totp_secret_encrypted = None;
    seal_integrity(&mut metadata, dek);
    save_metadata(vault_dir, &metadata)
}

pub fn decrypt_totp_secret(metadata: &VaultMetadata, dek: &VaultKey) -> AppResult<String> {
    let encrypted = metadata
        .totp_secret_encrypted
        .as_ref()
        .ok_or(AppError::TotpNotEnabled)?;
    let bytes = crypto::decrypt(dek, encrypted)?;
    String::from_utf8(bytes).map_err(|e| AppError::Crypto(e.to_string()))
}

pub fn add_file(vault_dir: &Path, dek: &VaultKey, source_path: &Path) -> AppResult<FileEntry> {
    let mut metadata = load_metadata(vault_dir)?;

    let name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| AppError::Crypto("nom de fichier invalide".into()))?
        .to_string();
    let plaintext = fs::read(source_path)?;
    let size = plaintext.len() as u64;

    let ciphertext = crypto::encrypt(dek, &plaintext)?;

    let file_id = Uuid::new_v4();
    fs::write(vault_dir.join(FILES_DIR).join(file_id.to_string()), ciphertext)?;

    let entry = FileEntry {
        id: file_id,
        name,
        size,
        added_at: Utc::now(),
    };
    metadata.files.push(entry.clone());
    save_metadata(vault_dir, &metadata)?;

    Ok(entry)
}

pub fn remove_file(vault_dir: &Path, file_id: Uuid) -> AppResult<()> {
    let mut metadata = load_metadata(vault_dir)?;
    let before = metadata.files.len();
    metadata.files.retain(|f| f.id != file_id);
    if metadata.files.len() == before {
        return Err(AppError::FileNotFound);
    }

    let encrypted_path = vault_dir.join(FILES_DIR).join(file_id.to_string());
    if encrypted_path.exists() {
        fs::remove_file(encrypted_path)?;
    }
    save_metadata(vault_dir, &metadata)
}

/// Root of the OS temp directory under which decrypted exports live,
/// namespaced per vault so `wipe_temp_exports` can clear just one vault's
/// files (on lock) or the whole tree (on lock-all / app exit).
fn temp_export_root(vault_id: Uuid) -> PathBuf {
    std::env::temp_dir().join("securefolders-exports").join(vault_id.to_string())
}

/// Decrypts a vault file into a per-vault directory under the OS temp
/// folder — never into a location the user picked — and returns the path to
/// the decrypted copy. This copy is plaintext on disk by necessity (so the
/// OS can open it with the associated application); [`wipe_temp_exports`]
/// removes it again on lock, per the "never leave decrypted files around"
/// requirement. See the README for the SSD/TRIM caveat on how irrecoverable
/// that removal actually is.
pub fn export_file(vault_dir: &Path, dek: &VaultKey, file_id: Uuid) -> AppResult<PathBuf> {
    let metadata = load_metadata(vault_dir)?;
    let entry = metadata
        .files
        .iter()
        .find(|f| f.id == file_id)
        .ok_or(AppError::FileNotFound)?;

    let ciphertext = fs::read(vault_dir.join(FILES_DIR).join(file_id.to_string()))?;
    let plaintext = crypto::decrypt(dek, &ciphertext)?;

    let dest_dir = temp_export_root(metadata.id);
    fs::create_dir_all(&dest_dir)?;
    let dest_path = dest_dir.join(&entry.name);
    fs::write(&dest_path, plaintext)?;
    Ok(dest_path)
}

/// Best-effort cleanup of every decrypted export for a vault. Called on
/// lock; failures are logged by the caller rather than propagated, since a
/// lock action must always succeed from the user's point of view.
pub fn wipe_temp_exports(vault_id: Uuid) -> std::io::Result<()> {
    let dir = temp_export_root(vault_id);
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    Ok(())
}

/// Wipes decrypted exports for every vault at once (used by `lock_all`).
pub fn wipe_all_temp_exports() -> std::io::Result<()> {
    let root = std::env::temp_dir().join("securefolders-exports");
    if root.exists() {
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn sanitize_folder_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            other => other,
        })
        .collect()
}

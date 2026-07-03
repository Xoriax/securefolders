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
    pub created_at: DateTime<Utc>,
    pub files: Vec<FileEntry>,
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

    let metadata = VaultMetadata {
        id: Uuid::new_v4(),
        name: name.to_string(),
        salt: salt.to_vec(),
        argon2_params: params,
        dek_encrypted,
        totp_enabled: false,
        totp_secret_encrypted: None,
        created_at: Utc::now(),
        files: Vec::new(),
    };
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
    Ok((metadata, VaultKey(dek)))
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

/// Decrypts a vault file into `dest_dir` (normally a temp directory managed
/// by the frontend/session, cleaned up on lock or app exit) and returns the
/// path to the decrypted copy.
pub fn export_file(
    vault_dir: &Path,
    dek: &VaultKey,
    file_id: Uuid,
    dest_dir: &Path,
) -> AppResult<PathBuf> {
    let metadata = load_metadata(vault_dir)?;
    let entry = metadata
        .files
        .iter()
        .find(|f| f.id == file_id)
        .ok_or(AppError::FileNotFound)?;

    let ciphertext = fs::read(vault_dir.join(FILES_DIR).join(file_id.to_string()))?;
    let plaintext = crypto::decrypt(dek, &ciphertext)?;

    fs::create_dir_all(dest_dir)?;
    let dest_path = dest_dir.join(&entry.name);
    fs::write(&dest_path, plaintext)?;
    Ok(dest_path)
}

fn sanitize_folder_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            other => other,
        })
        .collect()
}

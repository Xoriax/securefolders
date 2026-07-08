use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::crypto::{self, Argon2Params, VaultKey};
use crate::error::{AppError, AppResult};
use crate::{acl, launcher};

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

/// A single-use TOTP recovery code. Only its SHA-256 hash is ever stored —
/// the plaintext code is shown to the user once, at generation time, and
/// never again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    pub hash: Vec<u8>,
    pub used: bool,
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
    /// Hashes of unused/used single-use recovery codes, generated alongside
    /// the TOTP secret. Lets a user who still knows the master password but
    /// has lost their authenticator device regain access without an
    /// authenticator, instead of being permanently locked out.
    #[serde(default)]
    pub recovery_codes: Vec<RecoveryCode>,
    /// HMAC-SHA256 (keyed by the DEK) over the security-critical fields
    /// above. Verified on every unlock so that editing `vault.json` outside
    /// the app — e.g. flipping `totp_enabled` to `false`, or slipping in an
    /// attacker-known recovery code hash — is detected instead of silently
    /// changing the app's behaviour.
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
    recovery_codes: &'a Vec<RecoveryCode>,
}

fn integrity_message(metadata: &VaultMetadata) -> Vec<u8> {
    serde_json::to_vec(&IntegrityFields {
        id: metadata.id,
        totp_enabled: metadata.totp_enabled,
        totp_secret_encrypted: &metadata.totp_secret_encrypted,
        recovery_codes: &metadata.recovery_codes,
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
    // `create_dir` (not `create_dir_all`) atomically doubles as the
    // existence check: two concurrent creations for the same name/location
    // (e.g. a double-submitted form) race the OS's mkdir instead of a
    // separate exists()-then-create step, so only one can win and the
    // loser gets `AlreadyExists` instead of silently overwriting the
    // winner's vault.json and leaving a duplicate, orphaned entry in the
    // vault index.
    fs::create_dir(&vault_dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            AppError::VaultAlreadyExists
        } else {
            AppError::Io(e)
        }
    })?;
    // Deny-delete, applied before anything else exists under vault_dir so
    // vault.json, files/, and everything added to it later all inherit the
    // protection: Explorer (or any other process running as this user)
    // can no longer delete the vault or its contents, only the app can —
    // see `acl::allow_delete_once` / `allow_full_control_recursive` below.
    acl::protect_from_deletion(&vault_dir)?;
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
        recovery_codes: Vec::new(),
        integrity_tag: Vec::new(),
        created_at: Utc::now(),
        files: Vec::new(),
    };
    seal_integrity(&mut metadata, &dek);
    save_metadata(&vault_dir, &metadata)?;

    // Best-effort: a missing shortcut is a convenience regression, not a
    // reason to fail creating the vault outright.
    if let Err(e) = launcher::create_launcher(&vault_dir) {
        log::warn!("impossible de creer le raccourci de lancement pour {}: {e}", vault_dir.display());
    }

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
        // Overrides the deny-delete protection set by `create_vault` for
        // the whole tree at once, since we're removing all of it anyway.
        acl::allow_full_control_recursive(&vault_dir)?;
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

const RECOVERY_CODE_COUNT: usize = 10;

/// Enables 2FA and (re)generates its recovery codes in one step, since a
/// TOTP secret without a recovery path is a lockout waiting to happen.
/// Returns the plaintext codes — shown to the user exactly once.
pub fn enable_totp(vault_dir: &Path, dek: &VaultKey, secret_base32: &str) -> AppResult<Vec<String>> {
    let mut metadata = load_metadata(vault_dir)?;
    let encrypted_secret = crypto::encrypt(dek, secret_base32.as_bytes())?;
    metadata.totp_enabled = true;
    metadata.totp_secret_encrypted = Some(encrypted_secret);

    let codes = new_recovery_codes();
    metadata.recovery_codes = codes.iter().map(|c| RecoveryCode {
        hash: crypto::hash_recovery_code(c),
        used: false,
    }).collect();

    seal_integrity(&mut metadata, dek);
    save_metadata(vault_dir, &metadata)?;
    Ok(codes)
}

pub fn disable_totp(vault_dir: &Path, dek: &VaultKey) -> AppResult<()> {
    let mut metadata = load_metadata(vault_dir)?;
    metadata.totp_enabled = false;
    metadata.totp_secret_encrypted = None;
    metadata.recovery_codes = Vec::new();
    seal_integrity(&mut metadata, dek);
    save_metadata(vault_dir, &metadata)
}

/// Replaces every recovery code with a fresh set, e.g. after the user has
/// used one and wants a full pool again, or just wants to invalidate
/// codes they no longer trust (old screenshot, etc). Requires an active
/// session — i.e. the vault is already unlocked.
pub fn regenerate_recovery_codes(vault_dir: &Path, dek: &VaultKey) -> AppResult<Vec<String>> {
    let mut metadata = load_metadata(vault_dir)?;
    if !metadata.totp_enabled {
        return Err(AppError::TotpNotEnabled);
    }
    let codes = new_recovery_codes();
    metadata.recovery_codes = codes.iter().map(|c| RecoveryCode {
        hash: crypto::hash_recovery_code(c),
        used: false,
    }).collect();
    seal_integrity(&mut metadata, dek);
    save_metadata(vault_dir, &metadata)?;
    Ok(codes)
}

/// Verifies a recovery code and, if it is valid and unused, consumes it
/// (single use) and completes the unlock. Used as a fallback for
/// `verify_totp` when the user has lost their authenticator device but
/// still knows the master password.
pub fn consume_recovery_code(vault_dir: &Path, dek: &VaultKey, code: &str) -> AppResult<()> {
    let mut metadata = load_metadata(vault_dir)?;
    verify_integrity(&metadata, dek)?;

    let hash = crypto::hash_recovery_code(code);
    let entry = metadata
        .recovery_codes
        .iter_mut()
        .find(|c| !c.used && c.hash == hash)
        .ok_or(AppError::InvalidRecoveryCode)?;
    entry.used = true;

    seal_integrity(&mut metadata, dek);
    save_metadata(vault_dir, &metadata)
}

fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT).map(|_| crypto::generate_recovery_code()).collect()
}

pub fn decrypt_totp_secret(metadata: &VaultMetadata, dek: &VaultKey) -> AppResult<String> {
    let encrypted = metadata
        .totp_secret_encrypted
        .as_ref()
        .ok_or(AppError::TotpNotEnabled)?;
    let bytes = crypto::decrypt(dek, encrypted)?;
    String::from_utf8(bytes).map_err(|e| AppError::Crypto(e.to_string()))
}

/// Encrypts `source_path` into the vault in fixed-size chunks (see
/// `crypto::encrypt_file`) rather than reading it into memory whole, so
/// adding a very large file can't exhaust RAM or crash the app.
pub fn add_file(
    vault_dir: &Path,
    dek: &VaultKey,
    source_path: &Path,
    on_progress: impl FnMut(u64, u64),
) -> AppResult<FileEntry> {
    let mut metadata = load_metadata(vault_dir)?;

    let name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| AppError::Crypto("nom de fichier invalide".into()))?
        .to_string();
    let size = fs::metadata(source_path)?.len();

    let file_id = Uuid::new_v4();
    let dest_path = vault_dir.join(FILES_DIR).join(file_id.to_string());
    crypto::encrypt_file(dek, source_path, &dest_path, on_progress)?;

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

/// Renames a file's display name. The on-disk encrypted blob is named by
/// its UUID, never the file's own name, so this only touches metadata.
pub fn rename_file(vault_dir: &Path, file_id: Uuid, new_name: &str) -> AppResult<()> {
    let mut metadata = load_metadata(vault_dir)?;
    let entry = metadata
        .files
        .iter_mut()
        .find(|f| f.id == file_id)
        .ok_or(AppError::FileNotFound)?;
    entry.name = new_name.to_string();
    save_metadata(vault_dir, &metadata)
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
        // Overrides the deny-delete protection for this one file, inherited
        // from the vault folder — see `acl::protect_from_deletion`.
        acl::allow_delete_once(&encrypted_path)?;
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
pub fn export_file(
    vault_dir: &Path,
    dek: &VaultKey,
    file_id: Uuid,
    on_progress: impl FnMut(u64, u64),
) -> AppResult<PathBuf> {
    let metadata = load_metadata(vault_dir)?;
    let entry = metadata
        .files
        .iter()
        .find(|f| f.id == file_id)
        .ok_or(AppError::FileNotFound)?;

    let dest_dir = temp_export_root(metadata.id);
    fs::create_dir_all(&dest_dir)?;
    let dest_path = dest_dir.join(&entry.name);
    crypto::decrypt_file(
        dek,
        &vault_dir.join(FILES_DIR).join(file_id.to_string()),
        &dest_path,
        on_progress,
    )?;
    Ok(dest_path)
}

/// Decrypts a file straight to a location the user picked via a save
/// dialog, instead of the app-managed temp folder `export_file` uses. The
/// caller owns cleanup of this path — it is not tracked or wiped by
/// `wipe_temp_exports`.
pub fn export_file_to(
    vault_dir: &Path,
    dek: &VaultKey,
    file_id: Uuid,
    destination: &Path,
    on_progress: impl FnMut(u64, u64),
) -> AppResult<()> {
    let metadata = load_metadata(vault_dir)?;
    if !metadata.files.iter().any(|f| f.id == file_id) {
        return Err(AppError::FileNotFound);
    }
    crypto::decrypt_file(
        dek,
        &vault_dir.join(FILES_DIR).join(file_id.to_string()),
        destination,
        on_progress,
    )
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

/// Bundles a vault's metadata and encrypted files into a single .zip for
/// backup or migration to another machine. Nothing is decrypted or
/// re-encrypted here — every file inside is already AES-256-GCM ciphertext,
/// so the archive itself doesn't need (or get) a separate password.
/// The launcher shortcut is deliberately left out: it points at this
/// machine's install path, so restoring it verbatim elsewhere would be
/// wrong. `import_vault_backup` creates a fresh one instead.
pub fn export_vault_backup(vault_dir: &Path, destination: &Path) -> AppResult<()> {
    let file = fs::File::create(destination)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    zip.start_file(METADATA_FILE, options)?;
    zip.write_all(&fs::read(metadata_path(vault_dir))?)?;

    let files_dir = vault_dir.join(FILES_DIR);
    if files_dir.exists() {
        for entry in fs::read_dir(&files_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            zip.start_file(format!("{FILES_DIR}/{}", entry.file_name().to_string_lossy()), options)?;
            zip.write_all(&fs::read(entry.path())?)?;
        }
    }
    zip.finish()?;
    Ok(())
}

/// Restores a vault from a backup created by `export_vault_backup` into a
/// new folder under `destination_parent`. Refuses to import a vault whose
/// id is already known to this machine, to avoid ending up with two index
/// entries for what the app would otherwise treat as the same vault (the
/// exact bug that made `create_vault`'s directory creation atomic).
/// Re-applies the deletion protection and launcher shortcut that were left
/// out of the backup, since both are specific to this machine/install.
pub fn import_vault_backup(
    app_data_dir: &Path,
    backup_zip: &Path,
    destination_parent: &Path,
) -> AppResult<(VaultMetadata, PathBuf)> {
    let file = fs::File::open(backup_zip)?;
    let mut zip = ZipArchive::new(file)?;

    let metadata: VaultMetadata = {
        let mut entry = zip
            .by_name(METADATA_FILE)
            .map_err(|_| AppError::Crypto("archive de sauvegarde invalide (vault.json manquant)".into()))?;
        let mut raw = String::new();
        entry.read_to_string(&mut raw)?;
        serde_json::from_str(&raw)?
    };

    if find_vault_path(app_data_dir, metadata.id).is_ok() {
        return Err(AppError::VaultAlreadyExists);
    }

    let vault_dir = destination_parent.join(sanitize_folder_name(&metadata.name));
    fs::create_dir(&vault_dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            AppError::VaultAlreadyExists
        } else {
            AppError::Io(e)
        }
    })?;
    acl::protect_from_deletion(&vault_dir)?;
    fs::create_dir_all(vault_dir.join(FILES_DIR))?;

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let Some(file_name) = entry.name().strip_prefix(&format!("{FILES_DIR}/")) else {
            continue;
        };
        if file_name.is_empty() {
            continue;
        }
        let file_name = file_name.to_string();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        fs::write(vault_dir.join(FILES_DIR).join(file_name), buf)?;
    }
    save_metadata(&vault_dir, &metadata)?;

    if let Err(e) = launcher::create_launcher(&vault_dir) {
        log::warn!("impossible de creer le raccourci de lancement pour {}: {e}", vault_dir.display());
    }

    let mut index = load_index(app_data_dir)?;
    index.push(VaultIndexEntry {
        id: metadata.id,
        name: metadata.name.clone(),
        path: vault_dir.clone(),
    });
    save_index(app_data_dir, &index)?;

    Ok((metadata, vault_dir))
}

fn sanitize_folder_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    /// Fresh, isolated `(app_data_dir, location)` pair for a test. The
    /// returned `TempDir` must stay in scope for the test's duration — its
    /// `Drop` impl deletes the directory tree.
    fn fresh_dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let app_data_dir = root.path().join("appdata");
        let location = root.path().join("vaults");
        fs::create_dir_all(&app_data_dir).unwrap();
        fs::create_dir_all(&location).unwrap();
        (root, app_data_dir, location)
    }

    #[test]
    fn create_and_unlock_vault_succeeds_with_correct_password() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (metadata, vault_dir) =
            create_vault(&app_data_dir, "Mon Coffre", &location, "correct horse battery").unwrap();
        assert_eq!(metadata.name, "Mon Coffre");
        assert!(!metadata.totp_enabled);

        let (unlocked, _dek) = unlock(&vault_dir, "correct horse battery").unwrap();
        assert_eq!(unlocked.id, metadata.id);
    }

    #[test]
    fn unlock_fails_with_wrong_password() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (_metadata, vault_dir) =
            create_vault(&app_data_dir, "Coffre", &location, "le bon mot de passe").unwrap();
        let result = unlock(&vault_dir, "un mauvais mot de passe");
        assert!(matches!(result, Err(AppError::WrongPassword)));
    }

    #[test]
    fn create_vault_fails_if_folder_already_exists() {
        let (_root, app_data_dir, location) = fresh_dirs();
        create_vault(&app_data_dir, "Doublon", &location, "password123").unwrap();
        let result = create_vault(&app_data_dir, "Doublon", &location, "password123");
        assert!(matches!(result, Err(AppError::VaultAlreadyExists)));
    }

    #[test]
    fn a_freshly_created_vault_cannot_be_deleted_by_bypassing_the_app() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (_metadata, vault_dir) =
            create_vault(&app_data_dir, "Protege", &location, "password123").unwrap();

        // Simulates Explorer (or any other process running as this user)
        // trying to delete the vault directly, instead of going through
        // `delete_vault`'s ACL override.
        assert!(fs::remove_dir_all(&vault_dir).is_err());
        assert!(vault_dir.exists());
    }

    #[test]
    fn enable_totp_generates_recovery_codes_usable_exactly_once() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (_metadata, vault_dir) =
            create_vault(&app_data_dir, "2FA", &location, "password123").unwrap();
        let (_metadata, dek) = unlock(&vault_dir, "password123").unwrap();

        let codes = enable_totp(&vault_dir, &dek, "JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);

        // First use succeeds...
        consume_recovery_code(&vault_dir, &dek, &codes[0]).unwrap();
        // ...but replaying the same code is rejected...
        assert!(matches!(
            consume_recovery_code(&vault_dir, &dek, &codes[0]),
            Err(AppError::InvalidRecoveryCode)
        ));
        // ...and an unrelated code was never valid to begin with.
        assert!(matches!(
            consume_recovery_code(&vault_dir, &dek, "ZZZZ-ZZZZ-ZZZZ-ZZZZ"),
            Err(AppError::InvalidRecoveryCode)
        ));
        // A different, still-unused code from the same batch still works.
        consume_recovery_code(&vault_dir, &dek, &codes[1]).unwrap();
    }

    #[test]
    fn disable_totp_clears_secret_and_recovery_codes() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (_metadata, vault_dir) =
            create_vault(&app_data_dir, "ToggleTwoFa", &location, "password123").unwrap();
        let (_metadata, dek) = unlock(&vault_dir, "password123").unwrap();
        enable_totp(&vault_dir, &dek, "JBSWY3DPEHPK3PXP").unwrap();

        disable_totp(&vault_dir, &dek).unwrap();

        let metadata = load_metadata(&vault_dir).unwrap();
        assert!(!metadata.totp_enabled);
        assert!(metadata.totp_secret_encrypted.is_none());
        assert!(metadata.recovery_codes.is_empty());
    }

    /// Regression test for the fix in v0.2.0: an attacker with brief write
    /// access to the vault folder used to be able to flip `totp_enabled` to
    /// `false` in vault.json and unlock with the password alone, completely
    /// bypassing 2FA. The integrity tag must catch this.
    #[test]
    fn unlock_rejects_a_vault_json_tampered_to_disable_totp() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (_metadata, vault_dir) =
            create_vault(&app_data_dir, "Tamper", &location, "password123").unwrap();
        let (_metadata, dek) = unlock(&vault_dir, "password123").unwrap();
        enable_totp(&vault_dir, &dek, "JBSWY3DPEHPK3PXP").unwrap();

        // Simulate an attacker editing vault.json directly, without knowing
        // the DEK needed to reseal the integrity tag.
        let mut tampered = load_metadata(&vault_dir).unwrap();
        assert!(tampered.totp_enabled);
        tampered.totp_enabled = false;
        save_metadata(&vault_dir, &tampered).unwrap();

        let result = unlock(&vault_dir, "password123");
        assert!(matches!(result, Err(AppError::VaultTampered)));
    }

    /// Same attack, but injecting a recovery code hash the attacker chose
    /// themselves instead of disabling 2FA outright.
    #[test]
    fn unlock_rejects_a_vault_json_with_an_injected_recovery_code() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (_metadata, vault_dir) =
            create_vault(&app_data_dir, "Inject", &location, "password123").unwrap();
        let (_metadata, dek) = unlock(&vault_dir, "password123").unwrap();
        enable_totp(&vault_dir, &dek, "JBSWY3DPEHPK3PXP").unwrap();

        let mut tampered = load_metadata(&vault_dir).unwrap();
        tampered.recovery_codes.push(RecoveryCode {
            hash: crypto::hash_recovery_code("ATTACKER-KNOWN-CODE"),
            used: false,
        });
        save_metadata(&vault_dir, &tampered).unwrap();

        assert!(matches!(unlock(&vault_dir, "password123"), Err(AppError::VaultTampered)));
    }

    #[test]
    fn change_master_password_rotates_access_without_touching_files() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (metadata, vault_dir) =
            create_vault(&app_data_dir, "Rotate", &location, "old-password-123").unwrap();
        let (_metadata, dek_before) = unlock(&vault_dir, "old-password-123").unwrap();

        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"contenu secret").unwrap();
        let entry = add_file(&vault_dir, &dek_before, source.path(), |_, _| {}).unwrap();

        change_master_password(&vault_dir, "old-password-123", "new-password-456").unwrap();

        assert!(matches!(
            unlock(&vault_dir, "old-password-123"),
            Err(AppError::WrongPassword)
        ));
        let (_metadata, dek_after) = unlock(&vault_dir, "new-password-456").unwrap();

        // The DEK — and therefore every file encrypted with it — survives
        // the rotation untouched; only its wrapping changed.
        let exported = export_file(&vault_dir, &dek_after, entry.id, |_, _| {}).unwrap();
        assert_eq!(fs::read(&exported).unwrap(), b"contenu secret");
        let _ = wipe_temp_exports(metadata.id);
    }

    #[test]
    fn rename_and_delete_vault_updates_index_and_disk() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (metadata, vault_dir) =
            create_vault(&app_data_dir, "Avant", &location, "password123").unwrap();

        rename_vault(&app_data_dir, metadata.id, "Apres").unwrap();
        let summaries = list_vaults(&app_data_dir).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "Apres");

        delete_vault(&app_data_dir, metadata.id).unwrap();
        assert!(!vault_dir.exists());
        assert!(list_vaults(&app_data_dir).unwrap().is_empty());
        assert!(matches!(
            find_vault_path(&app_data_dir, metadata.id),
            Err(AppError::VaultNotFound)
        ));
    }

    #[test]
    fn add_export_and_remove_file_round_trip() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (metadata, vault_dir) =
            create_vault(&app_data_dir, "Fichiers", &location, "password123").unwrap();
        let (_metadata, dek) = unlock(&vault_dir, "password123").unwrap();

        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"hello vault").unwrap();
        let entry = add_file(&vault_dir, &dek, source.path(), |_, _| {}).unwrap();

        let exported = export_file(&vault_dir, &dek, entry.id, |_, _| {}).unwrap();
        assert_eq!(fs::read(&exported).unwrap(), b"hello vault");
        let _ = wipe_temp_exports(metadata.id);

        remove_file(&vault_dir, entry.id).unwrap();
        assert!(matches!(
            export_file(&vault_dir, &dek, entry.id, |_, _| {}),
            Err(AppError::FileNotFound)
        ));
    }

    #[test]
    fn rename_file_updates_the_display_name_only() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (_metadata, vault_dir) =
            create_vault(&app_data_dir, "Fichiers", &location, "password123").unwrap();
        let (_metadata, dek) = unlock(&vault_dir, "password123").unwrap();

        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"hello vault").unwrap();
        let entry = add_file(&vault_dir, &dek, source.path(), |_, _| {}).unwrap();

        rename_file(&vault_dir, entry.id, "nouveau-nom.txt").unwrap();
        let files = load_metadata(&vault_dir).unwrap().files;
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "nouveau-nom.txt");
        assert_eq!(files[0].id, entry.id);

        let exported = export_file(&vault_dir, &dek, entry.id, |_, _| {}).unwrap();
        assert_eq!(fs::read(&exported).unwrap(), b"hello vault");

        assert!(matches!(
            rename_file(&vault_dir, Uuid::new_v4(), "x"),
            Err(AppError::FileNotFound)
        ));
    }

    #[test]
    fn export_file_to_decrypts_straight_to_a_chosen_destination() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (_metadata, vault_dir) =
            create_vault(&app_data_dir, "Fichiers", &location, "password123").unwrap();
        let (_metadata, dek) = unlock(&vault_dir, "password123").unwrap();

        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"hello export").unwrap();
        let entry = add_file(&vault_dir, &dek, source.path(), |_, _| {}).unwrap();

        let destination = tempfile::NamedTempFile::new().unwrap().path().to_path_buf();
        export_file_to(&vault_dir, &dek, entry.id, &destination, |_, _| {}).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"hello export");

        assert!(matches!(
            export_file_to(&vault_dir, &dek, Uuid::new_v4(), &destination, |_, _| {}),
            Err(AppError::FileNotFound)
        ));
    }

    #[test]
    fn backup_export_and_import_round_trip_preserves_files_and_unlock() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (metadata, vault_dir) =
            create_vault(&app_data_dir, "Sauvegarde", &location, "password123").unwrap();
        let (_metadata, dek) = unlock(&vault_dir, "password123").unwrap();

        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"contenu sauvegarde").unwrap();
        let entry = add_file(&vault_dir, &dek, source.path(), |_, _| {}).unwrap();

        let backup_dir = tempfile::tempdir().unwrap();
        let zip_path = backup_dir.path().join("backup.zip");
        export_vault_backup(&vault_dir, &zip_path).unwrap();
        assert!(zip_path.exists());

        // Import into a second, independent app_data_dir/location pair, as
        // if this were a different machine.
        let (_other_root, other_app_data_dir, other_location) = fresh_dirs();
        let (restored_metadata, restored_dir) =
            import_vault_backup(&other_app_data_dir, &zip_path, &other_location).unwrap();
        assert_eq!(restored_metadata.id, metadata.id);
        assert_eq!(restored_metadata.name, "Sauvegarde");

        let (_unlocked, restored_dek) = unlock(&restored_dir, "password123").unwrap();
        let restored_export = export_file(&restored_dir, &restored_dek, entry.id, |_, _| {}).unwrap();
        assert_eq!(fs::read(&restored_export).unwrap(), b"contenu sauvegarde");

        let summaries = list_vaults(&other_app_data_dir).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].id, metadata.id);
    }

    #[test]
    fn importing_a_backup_of_an_already_known_vault_is_refused() {
        let (_root, app_data_dir, location) = fresh_dirs();
        let (_metadata, vault_dir) =
            create_vault(&app_data_dir, "Doublon", &location, "password123").unwrap();

        let backup_dir = tempfile::tempdir().unwrap();
        let zip_path = backup_dir.path().join("backup.zip");
        export_vault_backup(&vault_dir, &zip_path).unwrap();

        // Importing into the SAME app_data_dir the vault is already
        // registered in must be refused, not silently create a duplicate
        // index entry for the same id.
        let other_location = tempfile::tempdir().unwrap();
        assert!(matches!(
            import_vault_backup(&app_data_dir, &zip_path, other_location.path()),
            Err(AppError::VaultAlreadyExists)
        ));
    }
}

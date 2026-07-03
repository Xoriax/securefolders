use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::{totp, vault};

fn app_data_dir(app: &AppHandle) -> AppResult<PathBuf> {
    app.path()
        .app_data_dir()
        .map_err(|e| AppError::Crypto(format!("repertoire de donnees introuvable: {e}")))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResult {
    pub requires_totp: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetup {
    pub secret_base32: String,
    pub qr_code_data_url: String,
}

#[tauri::command]
pub fn list_vaults(app: AppHandle) -> AppResult<Vec<vault::VaultSummary>> {
    vault::list_vaults(&app_data_dir(&app)?)
}

#[tauri::command]
pub fn create_vault(
    app: AppHandle,
    name: String,
    location: String,
    password: String,
) -> AppResult<vault::VaultSummary> {
    if password.len() < 8 {
        return Err(AppError::Crypto(
            "le mot de passe maitre doit contenir au moins 8 caracteres".into(),
        ));
    }
    let (metadata, path) = vault::create_vault(&app_data_dir(&app)?, &name, &PathBuf::from(location), &password)?;
    Ok(vault::VaultSummary {
        id: metadata.id,
        name: metadata.name,
        path,
        totp_enabled: metadata.totp_enabled,
        file_count: 0,
        created_at: metadata.created_at,
    })
}

/// Verifies the master password. If the vault has 2FA enabled, the DEK is
/// held in a pending state until `verify_totp` supplies a valid code; the
/// caller must treat `requires_totp: true` as "not yet unlocked".
#[tauri::command]
pub fn unlock_vault(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    password: String,
) -> AppResult<UnlockResult> {
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let (metadata, dek) = vault::unlock(&vault_dir, &password)?;

    if metadata.totp_enabled {
        state.begin_totp_unlock(vault_id, dek);
        Ok(UnlockResult { requires_totp: true })
    } else {
        state.open_session(vault_id, dek);
        Ok(UnlockResult { requires_totp: false })
    }
}

/// Completes login for a vault whose password was already verified and is
/// awaiting its TOTP code (see `unlock_vault`).
#[tauri::command]
pub fn verify_totp(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    code: String,
) -> AppResult<()> {
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let metadata = vault::load_metadata(&vault_dir)?;

    // Peek the pending DEK without consuming it so a wrong code doesn't
    // discard the session and force the user to re-enter their password.
    let dek = state.peek_pending_totp_unlock(vault_id)?;
    let secret = vault::decrypt_totp_secret(&metadata, &dek)?;

    if !totp::verify_code(&secret, &code, &metadata.name)? {
        return Err(AppError::InvalidTotpCode);
    }
    state.complete_totp_unlock(vault_id)
}

#[tauri::command]
pub fn lock_vault(state: State<AppState>, vault_id: Uuid) {
    state.lock_vault(vault_id);
}

/// Locks every unlocked vault at once — used by the settings "lock all"
/// action and by the frontend's global inactivity timer.
#[tauri::command]
pub fn lock_all_vaults(state: State<AppState>) {
    state.lock_all();
}

#[tauri::command]
pub fn setup_totp(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
) -> AppResult<TotpSetup> {
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    // Require an active session so only someone who already unlocked the
    // vault with the master password can enable 2FA on it.
    state.get_active_dek(vault_id)?;
    let metadata = vault::load_metadata(&vault_dir)?;

    let secret_base32 = totp::generate_secret_base32();
    let qr_code_data_url = totp::qr_code_data_url(&secret_base32, &metadata.name)?;
    state.start_totp_setup(vault_id, secret_base32.clone());

    Ok(TotpSetup { secret_base32, qr_code_data_url })
}

#[tauri::command]
pub fn confirm_totp(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    code: String,
) -> AppResult<()> {
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let dek = state.get_active_dek(vault_id)?;
    let secret = state.take_totp_setup(vault_id)?;

    let metadata = vault::load_metadata(&vault_dir)?;
    if !totp::verify_code(&secret, &code, &metadata.name)? {
        // Put it back so the user can retry without re-scanning the QR code.
        state.start_totp_setup(vault_id, secret);
        return Err(AppError::InvalidTotpCode);
    }

    vault::enable_totp(&vault_dir, &dek, &secret)
}

#[tauri::command]
pub fn list_files(app: AppHandle, state: State<AppState>, vault_id: Uuid) -> AppResult<Vec<vault::FileEntry>> {
    state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    Ok(vault::load_metadata(&vault_dir)?.files)
}

#[tauri::command]
pub fn add_file(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    source_path: String,
) -> AppResult<vault::FileEntry> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::add_file(&vault_dir, &dek, &PathBuf::from(source_path))
}

#[tauri::command]
pub fn remove_file(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    file_id: Uuid,
) -> AppResult<()> {
    state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::remove_file(&vault_dir, file_id)
}

/// Decrypts a file to a caller-supplied temporary directory. The frontend is
/// responsible for deleting this plaintext copy once the user is done with
/// it (and on lock/exit) — see the "nettoyage des fichiers temporaires"
/// requirement in the security checklist.
#[tauri::command]
pub fn export_file(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    file_id: Uuid,
    dest_dir: String,
) -> AppResult<String> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let path = vault::export_file(&vault_dir, &dek, file_id, &PathBuf::from(dest_dir))?;
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
pub fn is_vault_unlocked(state: State<AppState>, vault_id: Uuid) -> bool {
    state.is_unlocked(vault_id)
}

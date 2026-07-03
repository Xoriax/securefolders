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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmTotpResult {
    /// Shown to the user exactly once — the app never stores or displays
    /// these again after this response.
    pub recovery_codes: Vec<String>,
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

/// Fallback for `verify_totp` when the user has lost their authenticator
/// device: completes login with a single-use recovery code instead of a
/// TOTP code, generated when 2FA was enabled.
#[tauri::command]
pub fn unlock_with_recovery_code(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    code: String,
) -> AppResult<()> {
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let dek = state.peek_pending_totp_unlock(vault_id)?;
    vault::consume_recovery_code(&vault_dir, &dek, &code)?;
    state.complete_totp_unlock(vault_id)
}

#[tauri::command]
pub fn lock_vault(state: State<AppState>, vault_id: Uuid) {
    state.lock_vault(vault_id);
    if let Err(e) = vault::wipe_temp_exports(vault_id) {
        log::warn!("echec du nettoyage des exports temporaires pour {vault_id}: {e}");
    }
}

/// Locks every unlocked vault at once — used by the settings "lock all"
/// action and by the frontend's global inactivity timer.
#[tauri::command]
pub fn lock_all_vaults(state: State<AppState>) {
    state.lock_all();
    if let Err(e) = vault::wipe_all_temp_exports() {
        log::warn!("echec du nettoyage des exports temporaires: {e}");
    }
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
) -> AppResult<ConfirmTotpResult> {
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let dek = state.get_active_dek(vault_id)?;
    let secret = state.take_totp_setup(vault_id)?;

    let metadata = vault::load_metadata(&vault_dir)?;
    if !totp::verify_code(&secret, &code, &metadata.name)? {
        // Put it back so the user can retry without re-scanning the QR code.
        state.start_totp_setup(vault_id, secret);
        return Err(AppError::InvalidTotpCode);
    }

    let recovery_codes = vault::enable_totp(&vault_dir, &dek, &secret)?;
    Ok(ConfirmTotpResult { recovery_codes })
}

/// Replaces a vault's recovery code pool (e.g. after one was used, or to
/// invalidate an old set). Requires an active session.
#[tauri::command]
pub fn regenerate_recovery_codes(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
) -> AppResult<Vec<String>> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::regenerate_recovery_codes(&vault_dir, &dek)
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

/// Decrypts a file into an app-managed temp directory (never a location the
/// user picks) and returns its path so the frontend can open it with the
/// system's default application. Wiped automatically by `lock_vault` /
/// `lock_all_vaults` — see the "nettoyage des fichiers temporaires"
/// requirement in the security checklist.
#[tauri::command]
pub fn export_file(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    file_id: Uuid,
) -> AppResult<String> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let path = vault::export_file(&vault_dir, &dek, file_id)?;
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
pub fn is_vault_unlocked(state: State<AppState>, vault_id: Uuid) -> bool {
    state.is_unlocked(vault_id)
}

/// Permanently deletes a vault (metadata + encrypted files). Requires an
/// active session so a stolen/borrowed machine can't be used to destroy a
/// vault without first knowing its password (and TOTP code, if enabled).
#[tauri::command]
pub fn delete_vault(app: AppHandle, state: State<AppState>, vault_id: Uuid) -> AppResult<()> {
    state.get_active_dek(vault_id)?;
    vault::delete_vault(&app_data_dir(&app)?, vault_id)?;
    state.lock_vault(vault_id);
    let _ = vault::wipe_temp_exports(vault_id);
    Ok(())
}

#[tauri::command]
pub fn rename_vault(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    new_name: String,
) -> AppResult<()> {
    state.get_active_dek(vault_id)?;
    if new_name.trim().is_empty() {
        return Err(AppError::Crypto("le nom du coffre ne peut pas etre vide".into()));
    }
    vault::rename_vault(&app_data_dir(&app)?, vault_id, new_name.trim())
}

/// Rotates the master password. Re-verifies `old_password` independently of
/// the current session (defense-in-depth against an unattended unlocked
/// vault) before re-wrapping the DEK; the encrypted files themselves are
/// never touched.
#[tauri::command]
pub fn change_master_password(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    old_password: String,
    new_password: String,
) -> AppResult<()> {
    state.get_active_dek(vault_id)?;
    if new_password.len() < 8 {
        return Err(AppError::Crypto(
            "le nouveau mot de passe doit contenir au moins 8 caracteres".into(),
        ));
    }
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::change_master_password(&vault_dir, &old_password, &new_password)
}

#[tauri::command]
pub fn disable_totp(app: AppHandle, state: State<AppState>, vault_id: Uuid) -> AppResult<()> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::disable_totp(&vault_dir, &dek)
}

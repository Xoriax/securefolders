use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::{launcher, settings, totp, vault};

/// How often (at most) a file transfer emits a progress event to the
/// frontend. Chunk-by-chunk would be hundreds of IPC messages per second on
/// a fast disk for no visible UI benefit; this throttles it to something a
/// progress bar can actually use.
const PROGRESS_EMIT_INTERVAL: Duration = Duration::from_millis(100);
const TRANSFER_PROGRESS_EVENT: &str = "vault://transfer-progress";

fn app_data_dir(app: &AppHandle) -> AppResult<PathBuf> {
    app.path()
        .app_data_dir()
        .map_err(|e| AppError::Crypto(format!("repertoire de donnees introuvable: {e}")))
}

/// Passwords cross the IPC boundary as raw bytes (a plain JS array, not a
/// string) so the frontend can wipe its own copy of them right after this
/// call — see `secureBytes.ts`. This decodes them back to a `String` for the
/// existing `&str`-based vault/crypto APIs, wrapped so it's zeroed on drop
/// instead of lingering in freed memory like an ordinary `String` would.
fn password_from_bytes(bytes: Vec<u8>) -> AppResult<zeroize::Zeroizing<String>> {
    String::from_utf8(bytes)
        .map(zeroize::Zeroizing::new)
        .map_err(|_| AppError::Crypto("mot de passe invalide (encodage)".into()))
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

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TransferProgress {
    vault_id: Uuid,
    file_name: String,
    direction: &'static str,
    bytes_done: u64,
    bytes_total: u64,
}

/// Builds a throttled progress callback: forwards to the Tauri event system
/// at most every `PROGRESS_EMIT_INTERVAL`, but always on the final call
/// (`bytes_done == bytes_total`) so the UI reliably reaches 100%.
fn progress_emitter<'a>(
    app: &'a AppHandle,
    vault_id: Uuid,
    file_name: String,
    direction: &'static str,
) -> impl FnMut(u64, u64) + 'a {
    let mut last_emit = Instant::now() - PROGRESS_EMIT_INTERVAL;
    move |bytes_done: u64, bytes_total: u64| {
        let now = Instant::now();
        if bytes_done == bytes_total || now.duration_since(last_emit) >= PROGRESS_EMIT_INTERVAL {
            last_emit = now;
            let _ = app.emit(
                TRANSFER_PROGRESS_EVENT,
                TransferProgress {
                    vault_id,
                    file_name: file_name.clone(),
                    direction,
                    bytes_done,
                    bytes_total,
                },
            );
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FilePreview {
    /// Path to the decrypted temp copy; the frontend loads it via Tauri's
    /// `convertFileSrc`/asset protocol rather than a base64 data URL, so
    /// large images don't have to be inflated ~33% and shipped whole over
    /// the IPC bridge as a command return value.
    Image { path: String },
    Text { content: String, truncated: bool },
    TooLarge,
    Unsupported,
}

/// Files above this size are never decrypted just for a preview — export
/// them instead. Keeps `preview_file` fast and bounds the memory it uses
/// (the whole point of streaming file encryption elsewhere in this app).
const PREVIEW_MAX_BYTES: u64 = 20 * 1024 * 1024;
const PREVIEW_TEXT_MAX_CHARS: usize = 50_000;

fn preview_extension(name: &str) -> String {
    std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase()
}

fn image_mime_type(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        _ => return None,
    })
}

fn is_text_extension(ext: &str) -> bool {
    matches!(
        ext,
        "txt" | "md" | "markdown" | "json" | "csv" | "log" | "xml" | "yaml" | "yml" | "toml"
            | "ini" | "conf" | "rs" | "ts" | "tsx" | "js" | "jsx" | "py" | "html" | "css" | "sh"
    )
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
    password: Vec<u8>,
) -> AppResult<vault::VaultSummary> {
    let password = password_from_bytes(password)?;
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
        created_at: metadata.created_at,
    })
}

/// Verifies the master password. If the vault has 2FA enabled, the DEK is
/// held in a pending state until `verify_totp` supplies a valid code; the
/// caller must treat `requires_totp: true` as "not yet unlocked".
///
/// Rate-limited: repeated wrong passwords lock the vault out for a growing
/// delay (see `AppState::record_failed_attempt`).
#[tauri::command]
pub fn unlock_vault(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    password: Vec<u8>,
) -> AppResult<UnlockResult> {
    state.check_rate_limit(vault_id)?;
    let password = password_from_bytes(password)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let (metadata, dek) = match vault::unlock(&vault_dir, &password) {
        Ok(v) => v,
        Err(e) => {
            state.record_failed_attempt(vault_id);
            return Err(e);
        }
    };

    if metadata.totp_enabled {
        state.begin_totp_unlock(vault_id, dek);
        Ok(UnlockResult { requires_totp: true })
    } else {
        state.record_successful_attempt(vault_id);
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
    state.check_rate_limit(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let metadata = vault::load_metadata(&vault_dir)?;

    // Peek the pending DEK without consuming it so a wrong code doesn't
    // discard the session and force the user to re-enter their password.
    let dek = state.peek_pending_totp_unlock(vault_id)?;
    let secret = vault::decrypt_totp_secret(&metadata, &dek)?;

    if !totp::verify_code(&secret, &code, &metadata.name)? {
        state.record_failed_attempt(vault_id);
        return Err(AppError::InvalidTotpCode);
    }
    state.record_successful_attempt(vault_id);
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
    state.check_rate_limit(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let dek = state.peek_pending_totp_unlock(vault_id)?;
    if let Err(e) = vault::consume_recovery_code(&vault_dir, &dek, &code) {
        state.record_failed_attempt(vault_id);
        return Err(e);
    }
    state.record_successful_attempt(vault_id);
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
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::list_files(&vault_dir, &dek)
}

#[tauri::command]
pub fn add_file(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    source_path: String,
    parent_id: Option<Uuid>,
) -> AppResult<vault::FileEntry> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let source_path = PathBuf::from(source_path);
    let file_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();

    let on_progress = progress_emitter(&app, vault_id, file_name, "import");
    vault::add_file(&vault_dir, &dek, &source_path, parent_id, on_progress)
}

#[tauri::command]
pub fn list_folders(state: State<AppState>, app: AppHandle, vault_id: Uuid) -> AppResult<Vec<vault::Folder>> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::list_folders(&vault_dir, &dek)
}

#[tauri::command]
pub fn create_folder(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    parent_id: Option<Uuid>,
    name: String,
) -> AppResult<vault::Folder> {
    let dek = state.get_active_dek(vault_id)?;
    if name.trim().is_empty() {
        return Err(AppError::Crypto("le nom du dossier ne peut pas etre vide".into()));
    }
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::create_folder(&vault_dir, &dek, parent_id, name.trim())
}

#[tauri::command]
pub fn rename_folder(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    folder_id: Uuid,
    new_name: String,
) -> AppResult<()> {
    let dek = state.get_active_dek(vault_id)?;
    if new_name.trim().is_empty() {
        return Err(AppError::Crypto("le nom du dossier ne peut pas etre vide".into()));
    }
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::rename_folder(&vault_dir, &dek, folder_id, new_name.trim())
}

#[tauri::command]
pub fn delete_folder(app: AppHandle, state: State<AppState>, vault_id: Uuid, folder_id: Uuid) -> AppResult<()> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::delete_folder(&vault_dir, &dek, folder_id)
}

#[tauri::command]
pub fn rename_file(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    file_id: Uuid,
    new_name: String,
) -> AppResult<()> {
    let dek = state.get_active_dek(vault_id)?;
    if new_name.trim().is_empty() {
        return Err(AppError::Crypto("le nom du fichier ne peut pas etre vide".into()));
    }
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::rename_file(&vault_dir, &dek, file_id, new_name.trim())
}

#[tauri::command]
pub fn remove_file(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    file_id: Uuid,
) -> AppResult<()> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::remove_file(&vault_dir, &dek, file_id)
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
    let file_name = vault::list_files(&vault_dir, &dek)?
        .into_iter()
        .find(|f| f.id == file_id)
        .map(|f| f.name)
        .unwrap_or_default();

    let on_progress = progress_emitter(&app, vault_id, file_name, "export");
    let path = vault::export_file(&vault_dir, &dek, file_id, on_progress)?;
    Ok(path.to_string_lossy().to_string())
}

/// Decrypts a file directly to a location the user chose via a save
/// dialog on the frontend, rather than the app-managed temp export folder.
/// Unlike `export_file`, this path is not cleaned up by the app — it is now
/// the user's own file, saved wherever they asked for it.
#[tauri::command]
pub fn export_file_to(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    file_id: Uuid,
    destination: String,
) -> AppResult<()> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let file_name = vault::list_files(&vault_dir, &dek)?
        .into_iter()
        .find(|f| f.id == file_id)
        .map(|f| f.name)
        .unwrap_or_default();

    let on_progress = progress_emitter(&app, vault_id, file_name, "export");
    vault::export_file_to(&vault_dir, &dek, file_id, &PathBuf::from(destination), on_progress)
}

/// Decrypts a small file fully into memory to render an inline preview
/// (image or text) without exporting it. Anything larger than
/// `PREVIEW_MAX_BYTES`, or of an unrecognized type, returns a variant the
/// frontend renders as "export it instead" rather than being decrypted at
/// all.
#[tauri::command]
pub fn preview_file(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    file_id: Uuid,
) -> AppResult<FilePreview> {
    let dek = state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    let files = vault::list_files(&vault_dir, &dek)?;
    let entry = files
        .iter()
        .find(|f| f.id == file_id)
        .ok_or(AppError::FileNotFound)?;

    if entry.size > PREVIEW_MAX_BYTES {
        return Ok(FilePreview::TooLarge);
    }

    let ext = preview_extension(&entry.name);
    let is_image = image_mime_type(&ext).is_some();
    if !is_image && !is_text_extension(&ext) {
        return Ok(FilePreview::Unsupported);
    }

    let exported_path = vault::export_file(&vault_dir, &dek, file_id, |_, _| {})?;

    if is_image {
        return Ok(FilePreview::Image { path: exported_path.to_string_lossy().to_string() });
    }

    let bytes = std::fs::read(&exported_path)?;
    let text = String::from_utf8_lossy(&bytes);
    let truncated = text.chars().count() > PREVIEW_TEXT_MAX_CHARS;
    let content: String = text.chars().take(PREVIEW_TEXT_MAX_CHARS).collect();
    Ok(FilePreview::Text { content, truncated })
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

/// Bundles the vault's metadata and encrypted files into a single .zip the
/// user picked via a save dialog, for backup or migration to another
/// machine. Requires an active session, like the vault's other settings
/// actions.
#[tauri::command]
pub fn export_vault_backup(
    app: AppHandle,
    state: State<AppState>,
    vault_id: Uuid,
    destination: String,
) -> AppResult<()> {
    state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    vault::export_vault_backup(&vault_dir, &PathBuf::from(destination))
}

/// Restores a vault from a .zip created by `export_vault_backup` into a new
/// folder under `destination_parent`. No active session is required —
/// there is nothing to unlock yet.
#[tauri::command]
pub fn import_vault_backup(
    app: AppHandle,
    backup_zip: String,
    destination_parent: String,
) -> AppResult<vault::VaultSummary> {
    let (metadata, path) = vault::import_vault_backup(
        &app_data_dir(&app)?,
        &PathBuf::from(backup_zip),
        &PathBuf::from(destination_parent),
    )?;
    Ok(vault::VaultSummary {
        id: metadata.id,
        name: metadata.name,
        path,
        totp_enabled: metadata.totp_enabled,
        created_at: metadata.created_at,
    })
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
    old_password: Vec<u8>,
    new_password: Vec<u8>,
) -> AppResult<()> {
    state.get_active_dek(vault_id)?;
    let old_password = password_from_bytes(old_password)?;
    let new_password = password_from_bytes(new_password)?;
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

#[tauri::command]
pub fn get_auto_lock_seconds(state: State<AppState>) -> u64 {
    state.auto_lock_timeout().as_secs()
}

/// Changes how long an unlocked vault can sit idle before it auto-locks.
/// Applies immediately to every open session and is persisted so it
/// survives an app restart.
#[tauri::command]
pub fn set_auto_lock_seconds(app: AppHandle, state: State<AppState>, seconds: u64) -> AppResult<()> {
    if seconds < settings::MIN_AUTO_LOCK_SECS || seconds > settings::MAX_AUTO_LOCK_SECS {
        return Err(AppError::Crypto(format!(
            "le delai d'auto-verrouillage doit etre compris entre {} et {} secondes",
            settings::MIN_AUTO_LOCK_SECS,
            settings::MAX_AUTO_LOCK_SECS
        )));
    }
    settings::save_auto_lock_secs(&app_data_dir(&app)?, seconds)?;
    state.set_auto_lock_timeout(Duration::from_secs(seconds));
    Ok(())
}

/// Returns the vault folder path the app was launched with (via a vault's
/// launcher shortcut), if any, so the frontend can jump straight to
/// unlocking that vault. Consumed on first read.
#[tauri::command]
pub fn get_launch_target(state: State<AppState>) -> Option<String> {
    state.take_launch_target()
}

/// (Re)creates a vault's launcher shortcut — used both right after creation
/// and as a settings action for vaults created before this feature existed.
#[tauri::command]
pub fn create_vault_launcher(app: AppHandle, state: State<AppState>, vault_id: Uuid) -> AppResult<()> {
    state.get_active_dek(vault_id)?;
    let vault_dir = vault::find_vault_path(&app_data_dir(&app)?, vault_id)?;
    launcher::create_launcher(&vault_dir)
}

mod acl;
mod commands;
mod crypto;
mod error;
mod launcher;
mod settings;
mod state;
mod totp;
mod vault;

use std::time::Duration;

use tauri::Manager;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            if let Ok(app_data_dir) = app.path().app_data_dir() {
                if let Ok(secs) = settings::load_auto_lock_secs(&app_data_dir) {
                    app.state::<AppState>()
                        .set_auto_lock_timeout(Duration::from_secs(secs));
                }
            }
            // Set when the app is launched via a vault's "Ouvrir avec
            // SecureFolders.lnk" shortcut, which passes the vault folder
            // path as its only argument (see `launcher::create_launcher`).
            if let Some(path) = std::env::args().nth(1) {
                app.state::<AppState>().set_launch_target(path);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_vaults,
            commands::create_vault,
            commands::unlock_vault,
            commands::verify_totp,
            commands::unlock_with_recovery_code,
            commands::regenerate_recovery_codes,
            commands::lock_vault,
            commands::lock_all_vaults,
            commands::setup_totp,
            commands::confirm_totp,
            commands::list_files,
            commands::add_file,
            commands::rename_file,
            commands::remove_file,
            commands::export_file,
            commands::export_file_to,
            commands::preview_file,
            commands::is_vault_unlocked,
            commands::delete_vault,
            commands::rename_vault,
            commands::change_master_password,
            commands::disable_totp,
            commands::get_auto_lock_seconds,
            commands::set_auto_lock_seconds,
            commands::get_launch_target,
            commands::create_vault_launcher,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

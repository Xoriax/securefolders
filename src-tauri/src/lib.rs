mod commands;
mod crypto;
mod error;
mod state;
mod totp;
mod vault;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
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
            commands::remove_file,
            commands::export_file,
            commands::preview_file,
            commands::is_vault_unlocked,
            commands::delete_vault,
            commands::rename_vault,
            commands::change_master_password,
            commands::disable_totp,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

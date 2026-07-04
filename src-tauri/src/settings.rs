use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AppResult;

const SETTINGS_FILE: &str = "settings.json";

pub const DEFAULT_AUTO_LOCK_SECS: u64 = 5 * 60;
pub const MIN_AUTO_LOCK_SECS: u64 = 30;
pub const MAX_AUTO_LOCK_SECS: u64 = 4 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppSettings {
    auto_lock_secs: u64,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self { auto_lock_secs: DEFAULT_AUTO_LOCK_SECS }
    }
}

fn settings_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(SETTINGS_FILE)
}

/// Reads the persisted auto-lock delay, falling back to the default when no
/// settings file has ever been written (fresh install).
pub fn load_auto_lock_secs(app_data_dir: &Path) -> AppResult<u64> {
    let path = settings_path(app_data_dir);
    if !path.exists() {
        return Ok(DEFAULT_AUTO_LOCK_SECS);
    }
    let raw = fs::read_to_string(path)?;
    let settings: AppSettings = serde_json::from_str(&raw)?;
    Ok(settings.auto_lock_secs)
}

pub fn save_auto_lock_secs(app_data_dir: &Path, auto_lock_secs: u64) -> AppResult<()> {
    fs::create_dir_all(app_data_dir)?;
    let raw = serde_json::to_string_pretty(&AppSettings { auto_lock_secs })?;
    fs::write(settings_path(app_data_dir), raw)?;
    Ok(())
}

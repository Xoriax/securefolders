use std::path::Path;

use mslnk::ShellLink;

use crate::error::{AppError, AppResult};

const SHORTCUT_NAME: &str = "Ouvrir avec SecureFolders.lnk";

/// Drops a Windows shortcut inside the vault folder that launches this same
/// app with the vault's path as an argument. Explorer has no way to hand a
/// double-click on an arbitrary folder off to a specific app, so this gives
/// users a concrete "double-click this to open the vault" affordance
/// sitting right next to the encrypted files instead.
pub fn create_launcher(vault_dir: &Path) -> AppResult<()> {
    let exe = std::env::current_exe()?;
    let mut shortcut = ShellLink::new(&exe).map_err(|e| AppError::Crypto(e.to_string()))?;
    shortcut.set_arguments(Some(format!("\"{}\"", vault_dir.display())));
    shortcut
        .create_lnk(vault_dir.join(SHORTCUT_NAME))
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Creating a valid-looking .lnk isn't the same as Windows Explorer
    /// being able to resolve it — the binary format has enough moving parts
    /// that a subtly wrong shell item list would silently produce a
    /// shortcut that looks fine on disk but errors when double-clicked.
    /// This reads it back through the same COM shell interface Explorer
    /// itself uses, rather than trusting our own writer.
    #[test]
    fn create_launcher_produces_a_shortcut_windows_can_resolve() {
        let dir = tempfile::tempdir().unwrap();
        create_launcher(dir.path()).unwrap();
        let lnk_path = dir.path().join(SHORTCUT_NAME);
        assert!(lnk_path.exists());

        let expected_exe = std::env::current_exe().unwrap();
        let script = format!(
            "(New-Object -ComObject WScript.Shell).CreateShortcut('{}').TargetPath",
            lnk_path.display()
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .unwrap();
        let resolved = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
        assert_eq!(resolved, expected_exe.to_string_lossy().to_lowercase());
    }
}

use std::path::Path;
use std::process::Command;

use crate::error::{AppError, AppResult};

/// Windows-only: this project targets Windows exclusively (see the
/// installers and README), so these helpers shell out to `icacls` rather
/// than pulling in a cross-platform ACL abstraction nothing else needs.
fn current_username() -> AppResult<String> {
    std::env::var("USERNAME")
        .map_err(|_| AppError::Crypto("impossible de determiner l'utilisateur Windows courant".into()))
}

fn run_icacls(args: &[&str]) -> AppResult<()> {
    let output = Command::new("icacls").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Crypto(format!("icacls a echoue: {}", stderr.trim())));
    }
    Ok(())
}

/// Denies deleting `path` itself and, via inheritance, anything created
/// inside it afterwards — so Explorer (or any other process running as the
/// same user) can no longer delete the vault folder or its contents.
/// Meant to be applied once, right after the folder is created; the app's
/// own delete operations must call `allow_delete_once` /
/// `allow_full_control_recursive` first to carve out their own exception.
pub fn protect_from_deletion(path: &Path) -> AppResult<()> {
    let user = current_username()?;
    run_icacls(&[&path.to_string_lossy(), "/deny", &format!("{user}:(OI)(CI)(DE,DC)")])
}

/// Grants back delete permission on a single file, as an explicit
/// (non-inherited) ACE — which Windows evaluates before the inherited deny
/// from `protect_from_deletion`, so it wins. Lets the app remove one file
/// the user asked to delete without touching protection on the rest of the
/// vault; once the file is gone the ACE goes with it.
pub fn allow_delete_once(path: &Path) -> AppResult<()> {
    let user = current_username()?;
    run_icacls(&[&path.to_string_lossy(), "/grant", &format!("{user}:(D)")])
}

/// Recursively grants full control back over a protected tree, for the one
/// case where the app needs to remove an entire protected vault folder
/// (deleting the vault itself) rather than a single file inside it.
pub fn allow_full_control_recursive(path: &Path) -> AppResult<()> {
    let user = current_username()?;
    run_icacls(&[
        &path.to_string_lossy(),
        "/grant",
        &format!("{user}:(OI)(CI)F"),
        "/T",
        "/C",
    ])
}

use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::{AppError, AppResult};

const ISSUER: &str = "SecureFolders";
const DIGITS: usize = 6;
const STEP_SECONDS: u64 = 30;
/// Allowed clock skew, in steps of STEP_SECONDS, to tolerate minor drift
/// between the device and the authenticator app.
const SKEW: u8 = 1;

/// Generates a new random TOTP secret, base32-encoded so it can be shown to
/// the user or embedded in an otpauth:// URI.
pub fn generate_secret_base32() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

fn build_totp(secret_base32: &str, account_name: &str) -> AppResult<TOTP> {
    let secret_bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| AppError::Crypto(format!("secret TOTP invalide: {e:?}")))?;

    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW,
        STEP_SECONDS,
        secret_bytes,
        Some(ISSUER.to_string()),
        account_name.to_string(),
    )
    .map_err(|e| AppError::Crypto(e.to_string()))
}

/// Builds a `data:image/png;base64,...` QR code for the given vault's TOTP
/// secret, to be scanned by Google/Microsoft Authenticator or Authy.
pub fn qr_code_data_url(secret_base32: &str, vault_name: &str) -> AppResult<String> {
    let totp = build_totp(secret_base32, vault_name)?;
    let base64_png = totp
        .get_qr_base64()
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    Ok(format!("data:image/png;base64,{base64_png}"))
}

/// Verifies a 6-digit code entered by the user against the current time
/// window (with a small tolerance for clock skew).
pub fn verify_code(secret_base32: &str, code: &str, vault_name: &str) -> AppResult<bool> {
    let totp = build_totp(secret_base32, vault_name)?;
    totp.check_current(code)
        .map_err(|e| AppError::Crypto(e.to_string()))
}

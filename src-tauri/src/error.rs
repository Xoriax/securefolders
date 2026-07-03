use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Vault introuvable")]
    VaultNotFound,
    #[error("Un coffre avec ce nom existe deja")]
    VaultAlreadyExists,
    #[error("Le coffre est verrouille")]
    VaultLocked,
    #[error("Mot de passe incorrect")]
    WrongPassword,
    #[error("Code 2FA invalide")]
    InvalidTotpCode,
    #[error("Le 2FA n'est pas active pour ce coffre")]
    TotpNotEnabled,
    #[error("Fichier introuvable dans le coffre")]
    FileNotFound,
    #[error("Erreur d'entree/sortie: {0}")]
    Io(#[from] std::io::Error),
    #[error("Erreur de (de)serialisation: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Erreur cryptographique: {0}")]
    Crypto(String),
}

// Tauri serializes command errors as strings sent to the frontend; never leak
// internals (e.g. raw crypto library errors) beyond the variant's own message.
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;

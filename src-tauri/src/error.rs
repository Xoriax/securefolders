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
    #[error("Code de recuperation invalide ou deja utilise")]
    InvalidRecoveryCode,
    #[error("Le 2FA n'est pas active pour ce coffre")]
    TotpNotEnabled,
    #[error("Ce coffre semble avoir ete modifie en dehors de l'application. Ouverture refusee par securite.")]
    VaultTampered,
    #[error("Trop de tentatives echouees. Reessayez dans {0} secondes.")]
    TooManyAttempts(u64),
    #[error("Fichier introuvable dans le coffre")]
    FileNotFound,
    #[error("Erreur d'entree/sortie: {0}")]
    Io(#[from] std::io::Error),
    #[error("Erreur de (de)serialisation: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Erreur d'archive de sauvegarde: {0}")]
    Zip(#[from] zip::result::ZipError),
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

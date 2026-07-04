# SecureFolders

[![CI](https://github.com/Xoriax/securefolders/actions/workflows/ci.yml/badge.svg)](https://github.com/Xoriax/securefolders/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Application desktop Windows permettant de créer des coffres de fichiers réellement chiffrés (AES-256-GCM), déverrouillables par mot de passe maître et, en option, par un second facteur TOTP (Google Authenticator, Microsoft Authenticator, Authy). Tout est stocké en local — aucune donnée n'est envoyée sur Internet.

## Stack

- Frontend : React + TypeScript + Vite
- Backend : Rust (Tauri 2)
- Chiffrement : AES-256-GCM en streaming (construction STREAM, blocs de 64 Kio) + Argon2id (dérivation de clé) + enveloppe de clé (DEK aléatoire par coffre, elle-même chiffrée par la clé dérivée du mot de passe)
- 2FA : TOTP (RFC 6238), compatible avec toute application d'authentification standard, avec codes de récupération à usage unique
- UX : barre de progression en temps réel sur l'ajout/export de fichiers, aperçu intégré (images, texte) sans quitter l'application

## Installation

Prérequis :
- Node.js 18+
- Rust (`rustup`) avec la cible MSVC
- Visual Studio Build Tools (workload "Desktop development with C++")
- WebView2 Runtime (préinstallé sur Windows 11)

```bash
npm install
npm run tauri dev     # lancer en mode développement
npm run tauri build   # générer les installeurs .exe et .msi
cd src-tauri && cargo test   # lancer les tests unitaires du backend
```

## Téléchargement

Chaque tag `vX.Y.Z` publie une [release GitHub](https://github.com/Xoriax/securefolders/releases) avec deux installeurs Windows x64 :

- **`SecureFolders_X.Y.Z_x64-setup.exe` (recommandé)** — installeur NSIS, s'installe pour l'utilisateur courant dans `%LOCALAPPDATA%`, **sans droits administrateur**.
- **`SecureFolders_X.Y.Z_x64_en-US.msi`** — installeur MSI/WiX, toujours "par machine" (le bundler Tauri ne propose pas de variante par utilisateur pour le MSI) : nécessite des droits administrateur. À réserver aux déploiements gérés par une équipe IT (GPO, SCCM, etc.) ; pour un usage personnel, préférer le `.exe`.

Vérifiez l'intégrité du fichier téléchargé en comparant son empreinte SHA-256 avec celle publiée sur la page de la release (le binaire n'étant pas signé numériquement, c'est le seul moyen de confirmer qu'il n'a pas été altéré) :

```powershell
Get-FileHash .\SecureFolders_X.Y.Z_x64-setup.exe -Algorithm SHA256
```

## Architecture

```
src/                    Frontend React
  api.ts                Wrapper typé autour des commandes Tauri
  types.ts              Types partagés avec le backend
  components/           Écrans et modales (création, déverrouillage, coffre, paramètres, 2FA)

src-tauri/src/
  crypto.rs             Dérivation de clé (Argon2id), chiffrement/déchiffrement (AES-256-GCM)
  vault.rs               Création/gestion des coffres, métadonnées, fichiers chiffrés
  totp.rs                 Génération de secret, QR code, vérification de code TOTP
  state.rs                Sessions de coffres déverrouillés en mémoire (jamais sur disque), verrouillage auto
  commands.rs             Commandes Tauri exposées au frontend
```

### Commandes Tauri disponibles

`list_vaults`, `create_vault`, `unlock_vault`, `verify_totp`, `unlock_with_recovery_code`, `regenerate_recovery_codes`, `lock_vault`, `lock_all_vaults`, `setup_totp`, `confirm_totp`, `list_files`, `add_file`, `remove_file`, `export_file`, `preview_file`, `is_vault_unlocked`, `delete_vault`, `rename_vault`, `change_master_password`, `disable_totp`, `get_auto_lock_seconds`, `set_auto_lock_seconds`.

### Modèle de chiffrement

1. À la création d'un coffre : génération d'un **salt** aléatoire (16 octets) et d'une **DEK** (Data Encryption Key) aléatoire de 256 bits.
2. Le mot de passe maître + le salt sont passés dans **Argon2id** pour dériver une clé maître.
3. La DEK est chiffrée avec la clé maître (AES-256-GCM) et stockée dans `vault.json` — jamais la clé maître elle-même. Changer le mot de passe ne fait que re-envelopper la DEK sous une nouvelle clé maître : les fichiers ne sont jamais re-chiffrés.
4. Chaque fichier est chiffré **en streaming**, par blocs de 64 Kio (construction STREAM d'AES-256-GCM : un préfixe de nonce aléatoire de 7 octets + un compteur interne par bloc), avec une progression envoyée à l'interface en temps réel. Le fichier entier n'est jamais chargé en mémoire, quelle que soit sa taille, et toute suppression, réordonnancement ou troncature de blocs est détectée.
5. Le secret TOTP (si activé) est chiffré avec la DEK, jamais stocké en clair.
6. À l'activation de la 2FA, 10 **codes de récupération** à usage unique sont générés (~80 bits d'entropie chacun) et affichés une seule fois ; seul leur hash SHA-256 est conservé. Un code valide permet de déverrouiller le coffre avec le mot de passe seul si l'application d'authentification est perdue, sans jamais pouvoir être réutilisé ni retrouvé en clair.
7. Un tag d'intégrité **HMAC-SHA256** (clé = DEK) protège les champs sensibles des métadonnées (`totp_enabled`, secret TOTP chiffré, hashs des codes de récupération). Il est vérifié à chaque déverrouillage : toute modification de `vault.json` en dehors de l'application (par ex. désactiver le flag 2FA à la main, ou injecter un hash de code connu de l'attaquant) fait échouer le déverrouillage au lieu d'être silencieusement acceptée.
8. Aucune clé n'est jamais écrite en clair sur le disque ; les clés déverrouillées ne vivent qu'en RAM et sont effacées (`zeroize`) à la fermeture de session.
9. L'export d'un fichier le déchiffre dans un dossier temporaire géré par l'application (jamais un emplacement choisi par l'utilisateur), ouvert avec l'application par défaut du système. Ce dossier temporaire est supprimé automatiquement au verrouillage du coffre (ou de tous les coffres).
10. L'aperçu (images, texte) réutilise ce même mécanisme d'export temporaire ; les images sont servies via le protocole `asset://` de Tauri plutôt que chargées en mémoire côté interface, et les fichiers de plus de 20 Mo ou de type non reconnu ne sont jamais déchiffrés pour un aperçu — seul l'export l'autorise.
11. Les tentatives de déverrouillage (mot de passe, code TOTP, code de récupération) sont limitées en fréquence : passé 4 essais infructueux, chaque nouvel échec verrouille le coffre un peu plus longtemps (5 s, 10 s, 20 s, ... jusqu'à 5 minutes), remis à zéro dès qu'une tentative aboutit. Ce compteur vit en mémoire, pas sur disque : il protège contre le devinage via l'interface, pas contre un attaquant qui copierait le dossier du coffre pour attaquer Argon2id hors ligne — rien côté application ne peut empêcher cela.

## Limites de sécurité connues

- **Mot de passe perdu = données perdues.** Il n'existe aucune récupération possible, par conception.
- La suppression du dossier temporaire d'export au verrouillage n'est pas garantie irrécupérable sur SSD (limitation physique du TRIM/wear-leveling, pas propre à l'application).
- Si les 10 codes de récupération TOTP sont tous consommés ou perdus (et l'application d'authentification également perdue), le coffre redevient inaccessible ; il faut régénérer les codes depuis un appareil où le coffre est encore déverrouillé, avant d'en arriver là.
- Le binaire n'est pas signé numériquement : Windows SmartScreen affichera un avertissement à l'installation si l'application est distribuée hors du Microsoft Store.

## Feuille de route

- [ ] Signature de code (certificat) pour supprimer l'avertissement SmartScreen
- [ ] Site vitrine avec page de téléchargement

Voir les [issues](https://github.com/Xoriax/securefolders/issues) pour le détail et l'avancement.

## Licence

[MIT](LICENSE)

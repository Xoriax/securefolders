# SecureFolders

[![CI](https://github.com/Xoriax/securefolders/actions/workflows/ci.yml/badge.svg)](https://github.com/Xoriax/securefolders/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Application desktop Windows permettant de créer des coffres de fichiers réellement chiffrés (AES-256-GCM), déverrouillables par mot de passe maître et, en option, par un second facteur TOTP (Google Authenticator, Microsoft Authenticator, Authy). Tout est stocké en local — aucune donnée n'est envoyée sur Internet.

## Stack

- Frontend : React + TypeScript + Vite
- Backend : Rust (Tauri 2)
- Chiffrement : AES-256-GCM (par fichier, nonce aléatoire unique) + Argon2id (dérivation de clé) + enveloppe de clé (DEK aléatoire par coffre, elle-même chiffrée par la clé dérivée du mot de passe)
- 2FA : TOTP (RFC 6238), compatible avec toute application d'authentification standard, avec codes de récupération à usage unique

## Installation

Prérequis :
- Node.js 18+
- Rust (`rustup`) avec la cible MSVC
- Visual Studio Build Tools (workload "Desktop development with C++")
- WebView2 Runtime (préinstallé sur Windows 11)

```bash
npm install
npm run tauri dev     # lancer en mode développement
npm run tauri build   # générer l'installeur .msi/.exe
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

`list_vaults`, `create_vault`, `unlock_vault`, `verify_totp`, `unlock_with_recovery_code`, `regenerate_recovery_codes`, `lock_vault`, `lock_all_vaults`, `setup_totp`, `confirm_totp`, `list_files`, `add_file`, `remove_file`, `export_file`, `is_vault_unlocked`, `delete_vault`, `rename_vault`, `change_master_password`, `disable_totp`.

### Modèle de chiffrement

1. À la création d'un coffre : génération d'un **salt** aléatoire (16 octets) et d'une **DEK** (Data Encryption Key) aléatoire de 256 bits.
2. Le mot de passe maître + le salt sont passés dans **Argon2id** pour dériver une clé maître.
3. La DEK est chiffrée avec la clé maître (AES-256-GCM) et stockée dans `vault.json` — jamais la clé maître elle-même. Changer le mot de passe ne fait que re-envelopper la DEK sous une nouvelle clé maître : les fichiers ne sont jamais re-chiffrés.
4. Chaque fichier ajouté est chiffré individuellement avec la DEK, avec un **nonce** aléatoire de 12 octets généré à chaque chiffrement.
5. Le secret TOTP (si activé) est chiffré avec la DEK, jamais stocké en clair.
6. À l'activation de la 2FA, 10 **codes de récupération** à usage unique sont générés (~80 bits d'entropie chacun) et affichés une seule fois ; seul leur hash SHA-256 est conservé. Un code valide permet de déverrouiller le coffre avec le mot de passe seul si l'application d'authentification est perdue, sans jamais pouvoir être réutilisé ni retrouvé en clair.
7. Un tag d'intégrité **HMAC-SHA256** (clé = DEK) protège les champs sensibles des métadonnées (`totp_enabled`, secret TOTP chiffré, hashs des codes de récupération). Il est vérifié à chaque déverrouillage : toute modification de `vault.json` en dehors de l'application (par ex. désactiver le flag 2FA à la main, ou injecter un hash de code connu de l'attaquant) fait échouer le déverrouillage au lieu d'être silencieusement acceptée.
8. Aucune clé n'est jamais écrite en clair sur le disque ; les clés déverrouillées ne vivent qu'en RAM et sont effacées (`zeroize`) à la fermeture de session.
9. L'export d'un fichier le déchiffre dans un dossier temporaire géré par l'application (jamais un emplacement choisi par l'utilisateur), ouvert avec l'application par défaut du système. Ce dossier temporaire est supprimé automatiquement au verrouillage du coffre (ou de tous les coffres).

## Limites de sécurité connues

- **Mot de passe perdu = données perdues.** Il n'existe aucune récupération possible, par conception.
- L'auto-verrouillage (5 minutes d'inactivité) est actuellement une valeur fixe, pas encore configurable depuis l'interface.
- La suppression du dossier temporaire d'export au verrouillage n'est pas garantie irrécupérable sur SSD (limitation physique du TRIM/wear-leveling, pas propre à l'application).
- Si les 10 codes de récupération TOTP sont tous consommés ou perdus (et l'application d'authentification également perdue), le coffre redevient inaccessible ; il faut régénérer les codes depuis un appareil où le coffre est encore déverrouillé, avant d'en arriver là.
- Le binaire n'est pas signé numériquement : Windows SmartScreen affichera un avertissement à l'installation si l'application est distribuée hors du Microsoft Store.

## Feuille de route

- [ ] Rate-limit / délai croissant après échecs de mot de passe répétés
- [ ] Chiffrement en streaming pour les gros fichiers
- [ ] Timer d'auto-verrouillage configurable depuis les paramètres
- [ ] Tests unitaires (crypto, vault, totp)
- [ ] Icônes et identité visuelle propres au projet

Voir les [issues](https://github.com/Xoriax/securefolders/issues) pour le détail et l'avancement.

## Licence

[MIT](LICENSE)

# SecureFolders

[![CI](https://github.com/Xoriax/securefolders/actions/workflows/ci.yml/badge.svg)](https://github.com/Xoriax/securefolders/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Application desktop Windows permettant de créer des coffres de fichiers réellement chiffrés (AES-256-GCM), déverrouillables par mot de passe maître et, en option, par un second facteur TOTP (Google Authenticator, Microsoft Authenticator, Authy). Tout est stocké en local — aucune donnée n'est envoyée sur Internet.

## Stack

- Frontend : React + TypeScript + Vite
- Backend : Rust (Tauri 2)
- Chiffrement : AES-256-GCM (par fichier, nonce aléatoire unique) + Argon2id (dérivation de clé) + enveloppe de clé (DEK aléatoire par coffre, elle-même chiffrée par la clé dérivée du mot de passe)
- 2FA : TOTP (RFC 6238), compatible avec toute application d'authentification standard

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

`list_vaults`, `create_vault`, `unlock_vault`, `verify_totp`, `lock_vault`, `lock_all_vaults`, `setup_totp`, `confirm_totp`, `list_files`, `add_file`, `remove_file`, `export_file`, `is_vault_unlocked`.

### Modèle de chiffrement

1. À la création d'un coffre : génération d'un **salt** aléatoire (16 octets) et d'une **DEK** (Data Encryption Key) aléatoire de 256 bits.
2. Le mot de passe maître + le salt sont passés dans **Argon2id** pour dériver une clé maître.
3. La DEK est chiffrée avec la clé maître (AES-256-GCM) et stockée dans `vault.json` — jamais la clé maître elle-même.
4. Chaque fichier ajouté est chiffré individuellement avec la DEK, avec un **nonce** aléatoire de 12 octets généré à chaque chiffrement.
5. Le secret TOTP (si activé) est chiffré avec la DEK, jamais stocké en clair.
6. Aucune clé n'est jamais écrite en clair sur le disque ; les clés déverrouillées ne vivent qu'en RAM et sont effacées (`zeroize`) à la fermeture de session.

## Limites de sécurité connues

- **Mot de passe perdu = données perdues.** Il n'existe aucune récupération possible, par conception.
- L'auto-verrouillage (5 minutes d'inactivité) est actuellement une valeur fixe, pas encore configurable depuis l'interface.
- L'export d'un fichier déchiffre une copie en clair sur le disque (dossier choisi par l'utilisateur) ; la suppression de cette copie temporaire n'est pas garantie irrécupérable sur SSD (limitation physique du TRIM/wear-leveling, pas propre à l'application).
- Pas de codes de récupération TOTP : la perte du téléphone associé rend le coffre inaccessible même avec le bon mot de passe, tant que le 2FA n'a pas été désactivé au préalable (fonctionnalité à ajouter).
- Le binaire n'est pas signé numériquement : Windows SmartScreen affichera un avertissement à l'installation si l'application est distribuée hors du Microsoft Store.

## Feuille de route

- [ ] Suppression / renommage d'un coffre, changement du mot de passe maître, désactivation du 2FA
- [ ] Codes de récupération TOTP
- [ ] Chiffrement en streaming pour les gros fichiers
- [ ] Timer d'auto-verrouillage configurable depuis les paramètres
- [ ] Tests unitaires (crypto, vault, totp)
- [ ] Icônes et identité visuelle propres au projet

Voir les [issues](https://github.com/Xoriax/securefolders/issues) pour le détail et l'avancement.

## Licence

[MIT](LICENSE)

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
npm test              # lancer les tests unitaires du frontend
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

`list_vaults`, `create_vault`, `unlock_vault`, `verify_totp`, `unlock_with_recovery_code`, `regenerate_recovery_codes`, `lock_vault`, `lock_all_vaults`, `setup_totp`, `confirm_totp`, `list_files`, `add_file`, `rename_file`, `remove_file`, `export_file`, `export_file_to`, `preview_file`, `is_vault_unlocked`, `delete_vault`, `rename_vault`, `change_master_password`, `disable_totp`, `get_auto_lock_seconds`, `set_auto_lock_seconds`, `get_launch_target`, `create_vault_launcher`, `export_vault_backup`, `import_vault_backup`, `list_folders`, `create_folder`, `rename_folder`, `delete_folder`.

### Modèle de chiffrement

1. À la création d'un coffre : génération d'un **salt** aléatoire (16 octets) et d'une **DEK** (Data Encryption Key) aléatoire de 256 bits.
2. Le mot de passe maître + le salt sont passés dans **Argon2id** pour dériver une clé maître.
3. La DEK est chiffrée avec la clé maître (AES-256-GCM) et stockée dans `vault.json` — jamais la clé maître elle-même. Changer le mot de passe ne fait que re-envelopper la DEK sous une nouvelle clé maître : les fichiers ne sont jamais re-chiffrés.
4. Chaque fichier est chiffré **en streaming**, par blocs de 64 Kio (construction STREAM d'AES-256-GCM : un préfixe de nonce aléatoire de 7 octets + un compteur interne par bloc), avec une progression envoyée à l'interface en temps réel. Le fichier entier n'est jamais chargé en mémoire, quelle que soit sa taille, et toute suppression, réordonnancement ou troncature de blocs est détectée.
5. Le secret TOTP (si activé) est chiffré avec la DEK, jamais stocké en clair.
6. À l'activation de la 2FA, 10 **codes de récupération** à usage unique sont générés (~80 bits d'entropie chacun) et affichés une seule fois ; seul leur hash SHA-256 est conservé. Un code valide permet de déverrouiller le coffre avec le mot de passe seul si l'application d'authentification est perdue, sans jamais pouvoir être réutilisé ni retrouvé en clair.
7. Un tag d'intégrité **HMAC-SHA256** (clé = DEK) protège les champs sensibles des métadonnées (`totp_enabled`, secret TOTP chiffré, hashs des codes de récupération). Il est vérifié à chaque déverrouillage : toute modification de `vault.json` en dehors de l'application (par ex. désactiver le flag 2FA à la main, ou injecter un hash de code connu de l'attaquant) fait échouer le déverrouillage au lieu d'être silencieusement acceptée.
8. Aucune clé n'est jamais écrite en clair sur le disque ; les clés déverrouillées ne vivent qu'en RAM et sont effacées (`zeroize`) à la fermeture de session. Les mots de passe saisis dans l'interface transitent en octets bruts (jamais une chaîne JS) et sont effacés côté frontend juste après l'appel ; côté Rust, ils sont enveloppés dans un `Zeroizing<String>`. Cela réduit la fenêtre d'exposition sans l'éliminer — une chaîne JavaScript est immuable et ne peut, par nature, pas être effacée comme une donnée Rust. La DEK et la clé dérivée du mot de passe maître sont en plus verrouillées en RAM (`VirtualLock`) dès leur création — y compris chaque copie indépendante — pour qu'elles ne puissent pas finir dans le fichier d'échange ou un instantané d'hibernation ; best-effort comme le reste (`VirtualLock` peut échouer sans bloquer le déverrouillage).
9. Exporter un fichier ouvre un dialogue « Enregistrer sous... » et le déchiffre directement à l'emplacement choisi par l'utilisateur.
10. L'aperçu (images, texte) déchiffre dans un dossier temporaire géré par l'application (jamais un emplacement choisi par l'utilisateur) ; les images sont servies via le protocole `asset://` de Tauri plutôt que chargées en mémoire côté interface, et ce dossier temporaire est supprimé automatiquement au verrouillage du coffre (ou de tous les coffres). Les fichiers de plus de 20 Mo ou de type non reconnu ne sont jamais déchiffrés pour un aperçu.
11. Les tentatives de déverrouillage (mot de passe, code TOTP, code de récupération) sont limitées en fréquence : passé 4 essais infructueux, chaque nouvel échec verrouille le coffre un peu plus longtemps (5 s, 10 s, 20 s, ... jusqu'à 5 minutes), remis à zéro dès qu'une tentative aboutit. Ce compteur vit en mémoire, pas sur disque : il protège contre le devinage via l'interface, pas contre un attaquant qui copierait le dossier du coffre pour attaquer Argon2id hors ligne — rien côté application ne peut empêcher cela.
12. Le dossier d'un coffre nouvellement créé refuse la suppression (permission NTFS explicite) depuis l'Explorateur ou tout autre processus externe ; seule l'application peut supprimer un fichier ou le coffre entier, en levant cette permission juste avant sa propre opération de suppression.
13. Chaque coffre reçoit un raccourci Windows (`Ouvrir avec SecureFolders.lnk`) déposé dans son dossier, qui relance l'application directement dessus — Windows n'offrant aucun moyen natif de faire réagir un double-clic sur le dossier lui-même.
14. La sauvegarde d'un coffre regroupe `vault.json` et les fichiers déjà chiffrés dans une seule archive .zip, sans déchiffrement ni chiffrement supplémentaire — l'archive n'a pas besoin de son propre mot de passe puisque son contenu l'est déjà. Le raccourci de lancement et la protection anti-suppression, spécifiques à la machine, ne sont pas inclus ; ils sont recréés à l'import.
15. Tous les coffres se verrouillent automatiquement au réveil d'une mise en veille ou d'une hibernation, en plus du délai d'inactivité habituel. Détecté côté interface via un écart anormalement grand entre deux sondages réguliers — un minuteur JavaScript ne peut pas être mis en pause de cette façon autrement que si le système d'exploitation a réellement suspendu le processus. Cela ne détecte pas un verrouillage manuel de session Windows (Win+L) qui n'endort pas la machine ; ce cas reste couvert par le délai d'inactivité normal.
16. Les dossiers à l'intérieur d'un coffre sont une notion purement organisationnelle (nom, identifiant, dossier parent), chiffrée avec le reste des métadonnées (voir point 18) : ils n'existent pas comme de vrais répertoires sur le disque. Chaque fichier chiffré reste stocké à plat dans `files/`, nommé par son UUID, quelle que soit sa position dans l'arborescence affichée. Supprimer un dossier supprime récursivement tout son contenu, y compris les sous-dossiers imbriqués.
17. La vérification des mises à jour est strictement manuelle (bouton dans les Paramètres) : aucun appel réseau automatique n'a lieu au démarrage ou en arrière-plan. Les binaires publiés sont signés (clé privée conservée uniquement comme secret GitHub Actions) pour que l'application puisse vérifier leur authenticité avant de les installer.
18. Les noms de fichiers, noms de dossiers, tailles, dates d'ajout et la structure des sous-dossiers sont regroupés et chiffrés en un seul bloc AES-256-GCM sous la DEK (`content_encrypted` dans `vault.json`), et non plus stockés en clair. Contrairement au tag d'intégrité HMAC du point 7 (qui protège certains champs contre la modification mais pas contre la lecture), ce bloc protège aussi la confidentialité : un coffre copié ou lu directement, sans le mot de passe, ne révèle plus rien de son contenu — pas même le nombre de fichiers qu'il contient.

## Limites de sécurité connues

- **Mot de passe perdu = données perdues.** Il n'existe aucune récupération possible, par conception.
- La suppression du dossier temporaire d'export au verrouillage n'est pas garantie irrécupérable sur SSD (limitation physique du TRIM/wear-leveling, pas propre à l'application).
- Si les 10 codes de récupération TOTP sont tous consommés ou perdus (et l'application d'authentification également perdue), le coffre redevient inaccessible ; il faut régénérer les codes depuis un appareil où le coffre est encore déverrouillé, avant d'en arriver là.
- Le binaire n'est pas signé numériquement : Windows SmartScreen affichera un avertissement à l'installation si l'application est distribuée hors du Microsoft Store.
- La protection contre la suppression accidentelle (permission NTFS refusant Supprimer) n'est pas une barrière de sécurité : le propriétaire du fichier peut toujours la retirer lui-même (Propriétés > Sécurité, ou `icacls`). Elle vise uniquement à éviter un `Suppr` malheureux dans l'Explorateur, pas à empêcher un utilisateur déterminé ou un administrateur.
- Les coffres créés avant la version 0.9.0 n'ont ni cette protection ni le raccourci de lancement ; le raccourci peut être ajouté après coup depuis les paramètres du coffre, la protection anti-suppression non (elle n'est posée qu'à la création).

## Feuille de route

- [ ] Signature de code (certificat) pour supprimer l'avertissement SmartScreen
- [ ] Site vitrine avec page de téléchargement

Voir les [issues](https://github.com/Xoriax/securefolders/issues) pour le détail et l'avancement.

## Licence

[MIT](LICENSE)

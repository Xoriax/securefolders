# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [0.1.0] - 2026-07-03

### Ajouté
- Scaffold initial Tauri + React + TypeScript + Rust
- Chiffrement des fichiers en AES-256-GCM avec dérivation de clé Argon2id
- Chiffrement en enveloppe (DEK aléatoire par coffre, chiffrée par la clé maître dérivée du mot de passe)
- Double authentification TOTP (RFC 6238) compatible Google Authenticator, Microsoft Authenticator, Authy, avec QR code
- Gestion de coffres : création, déverrouillage, verrouillage, verrouillage automatique après inactivité
- Gestion de fichiers : ajout par glisser-déposer, suppression, export déchiffré
- Interface sombre : accueil, création de coffre, déverrouillage, vue coffre, paramètres
- Documentation (README) et licence MIT

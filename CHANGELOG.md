# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [0.2.0] - 2026-07-03

### Corrige (securite)
- **Faille critique** : le flag `totp_enabled` dans `vault.json` n'etait pas protege contre une modification hors de l'application, permettant de contourner la double authentification en editant le fichier de metadonnees. Corrige par un tag d'integrite HMAC-SHA256 (cle = DEK) verifie a chaque deverrouillage.

### Ajoute
- Suppression et renommage d'un coffre
- Changement du mot de passe maitre (re-enveloppe la DEK, aucun fichier re-chiffre)
- Desactivation de la 2FA
- Export de fichier reecrit : dechiffrement dans un dossier temporaire gere par l'application (jamais un emplacement choisi par l'utilisateur), ouvert avec l'application par defaut du systeme, et nettoye automatiquement au verrouillage
- Rafraichissement automatique de l'interface quand le verrouillage automatique expire pendant que l'utilisateur consulte un coffre
- Modale "Parametres du coffre" (renommer, changer le mot de passe, desactiver la 2FA, supprimer)

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

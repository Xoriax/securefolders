# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [0.8.0] - 2026-07-04

### Ajoute
- Delai d'auto-verrouillage configurable depuis les Parametres (de 30 secondes a 4 heures), applique immediatement a toutes les sessions ouvertes et persiste sur disque pour survivre a un redemarrage de l'application.

### Corrige
- Le sondage periodique de l'interface qui verifie si un coffre est toujours deverrouille (`is_vault_unlocked`, toutes les 10 secondes) reinitialisait par erreur le minuteur d'inactivite a chaque appel, empechant tout verrouillage automatique tant que l'ecran du coffre restait ouvert — quelle que soit la duree reelle d'inactivite de l'utilisateur. Ce sondage est desormais une simple lecture qui n'influence plus le delai.

## [0.7.0] - 2026-07-04

### Ajoute
- Rate-limit progressif sur les tentatives de deverrouillage : 4 essais libres (mot de passe maitre, code TOTP ou code de recuperation confondus, car ils gardent le meme flux de connexion), puis un verrouillage qui double a chaque nouvel echec (5s, 10s, 20s, ... plafonne a 5 minutes). Reinitialise des qu'une tentative aboutit. En memoire uniquement : n'empeche pas un attaquant qui copierait le dossier du coffre pour attaquer Argon2id hors ligne, mais bloque le brute-force via l'interface elle-meme.

### Corrige
- Course critique dans `create_vault` : la verification d'existence du dossier et sa creation etaient deux etapes separees, si bien qu'un double-clic ou une double soumission pouvait laisser deux entrees pointant vers le meme coffre dans l'index (observe concretement : cle React dupliquee dans la liste des coffres). La creation du dossier est desormais atomique (`create_dir` echoue directement si le dossier existe deja), ce qui rend impossible la double insertion.

## [0.6.0] - 2026-07-04

### Ajoute
- Chiffrement/dechiffrement de fichiers en streaming (construction STREAM d'AES-256-GCM, blocs de 64 Kio) : plus aucun fichier n'est charge entierement en RAM, quelle que soit sa taille. Valide manuellement avec un fichier de 50 Mo et par des tests unitaires couvrant les cas limites (fichier vide, plus petit qu'un bloc, exactement un bloc, plusieurs blocs, bloc supprime/reordonne).
- Barre de progression en temps reel sur l'ajout et l'export de fichiers, via des evenements Tauri emis au maximum toutes les 100ms.
- Apercu integre des fichiers (images et texte) sans avoir a les exporter, limite a 20 Mo. Les images sont servies via le protocole `asset://` de Tauri (pas de data URL base64, plus robuste et evite de gonfler le payload IPC).

### Corrige
- Fenetre CSP trop stricte empechant initialement l'affichage des apercus image (contourne par le passage a `asset://` plutot que de relacher la CSP).

## [0.5.0] - 2026-07-03

### Ajoute
- Identite visuelle du projet : logo dossier + cadenas, fond anthracite et liseres or, genere avec Canva puis nettoye (suppression de la marge du canevas, mise en transparence). Remplace les icones par defaut de Tauri pour toutes les plateformes/formats (ICO, ICNS, PNG, Appx) ainsi que le favicon de l'interface web.

## [0.4.0] - 2026-07-03

### Ajoute
- Suite de 25 tests unitaires Rust (crypto, totp, vault), executee en CI a chaque push. Inclut deux tests de regression pour la faille corrigee en 0.2.0 (contournement de la 2FA par modification de `vault.json`).
- Documentation du choix d'installeur dans le README : `.exe` (NSIS, sans droits admin, recommande) vs `.msi` (WiX, toujours par machine, reserve aux deploiements geres) — decouvert en verifiant concretement les artefacts publies par la release v0.3.0, dont l'installation `.msi` silencieuse echouait sans elevation.

## [0.3.0] - 2026-07-03

### Ajoute
- Codes de recuperation TOTP a usage unique : 10 codes generes et affiches une seule fois a l'activation de la 2FA, permettant de deverrouiller un coffre avec le mot de passe seul si l'application d'authentification est perdue. Seuls leurs hashs SHA-256 sont stockes, integres au tag d'integrite HMAC du coffre pour empecher qu'un attaquant en injecte un a lui.
- Ecran de deverrouillage : lien "Application d'authentification perdue ?" basculant vers la saisie d'un code de recuperation a la place du code TOTP.
- Parametres du coffre : bouton "Regenerer les codes de recuperation" (invalide l'ancien lot, en emet un nouveau).
- La desactivation de la 2FA efface egalement les codes de recuperation restants.

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

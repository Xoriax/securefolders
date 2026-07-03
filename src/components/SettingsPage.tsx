import { useState } from "react";
import { api, errorMessage } from "../api";

export function SettingsPage() {
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function lockAll() {
    setError(null);
    setMessage(null);
    try {
      await api.lockAllVaults();
      setMessage("Tous les coffres ont ete verrouilles.");
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <div className="settings-section">
      <div className="page-header">
        <div>
          <h1>Parametres</h1>
          <p>Securite et comportement de l'application</p>
        </div>
      </div>

      <div className="warning-banner">
        Si vous perdez votre mot de passe maitre, les fichiers d'un coffre ne
        pourront jamais etre recuperes. Aucune cle n'est stockee sur le disque
        ni envoyee sur Internet — l'application fonctionne entierement hors
        ligne.
      </div>

      <div className="field">
        <label>Verrouillage automatique</label>
        <p style={{ fontSize: 13, color: "var(--text-dim)", margin: 0 }}>
          Les coffres inactifs sont automatiquement verrouilles apres 5
          minutes.
        </p>
      </div>

      <div className="field">
        <label>Tout verrouiller</label>
        <button className="btn btn-danger" onClick={lockAll}>
          Verrouiller tous les coffres
        </button>
      </div>

      {message && <p style={{ fontSize: 13, color: "var(--success)" }}>{message}</p>}
      {error && <div className="error-text">{error}</div>}
    </div>
  );
}

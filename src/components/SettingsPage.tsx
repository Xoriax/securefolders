import { useEffect, useState } from "react";
import { api, errorMessage } from "../api";

const AUTO_LOCK_OPTIONS = [
  { seconds: 30, label: "30 secondes" },
  { seconds: 60, label: "1 minute" },
  { seconds: 5 * 60, label: "5 minutes" },
  { seconds: 15 * 60, label: "15 minutes" },
  { seconds: 30 * 60, label: "30 minutes" },
  { seconds: 60 * 60, label: "1 heure" },
  { seconds: 4 * 60 * 60, label: "4 heures" },
];

export function SettingsPage() {
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [autoLockSeconds, setAutoLockSeconds] = useState<number | null>(null);

  useEffect(() => {
    api.getAutoLockSeconds().then(setAutoLockSeconds).catch(() => {});
  }, []);

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

  async function changeAutoLock(seconds: number) {
    setError(null);
    setMessage(null);
    const previous = autoLockSeconds;
    setAutoLockSeconds(seconds);
    try {
      await api.setAutoLockSeconds(seconds);
    } catch (err) {
      setAutoLockSeconds(previous);
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
        <p style={{ fontSize: 13, color: "var(--text-dim)", margin: "0 0 8px" }}>
          Delai d'inactivite avant qu'un coffre deverrouille se reverrouille
          automatiquement.
        </p>
        <select
          value={autoLockSeconds ?? ""}
          onChange={(e) => changeAutoLock(Number(e.target.value))}
          disabled={autoLockSeconds === null}
        >
          {autoLockSeconds !== null &&
            !AUTO_LOCK_OPTIONS.some((o) => o.seconds === autoLockSeconds) && (
              <option value={autoLockSeconds}>{autoLockSeconds} secondes</option>
            )}
          {AUTO_LOCK_OPTIONS.map((o) => (
            <option key={o.seconds} value={o.seconds}>
              {o.label}
            </option>
          ))}
        </select>
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

import { useEffect, useState } from "react";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
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
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [availableUpdate, setAvailableUpdate] = useState<Update | null>(null);
  const [installingUpdate, setInstallingUpdate] = useState(false);

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

  async function handleCheckForUpdates() {
    setError(null);
    setMessage(null);
    setAvailableUpdate(null);
    setCheckingUpdate(true);
    try {
      const update = await check();
      if (update) {
        setAvailableUpdate(update);
      } else {
        setMessage("Vous utilisez deja la derniere version.");
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCheckingUpdate(false);
    }
  }

  async function handleInstallUpdate() {
    if (!availableUpdate) return;
    setError(null);
    setInstallingUpdate(true);
    try {
      await availableUpdate.downloadAndInstall();
      await relaunch();
    } catch (err) {
      setError(errorMessage(err));
      setInstallingUpdate(false);
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
        ni envoyee sur Internet. L'application ne se connecte a Internet que
        si vous cliquez vous-meme sur "Verifier les mises a jour" ci-dessous —
        jamais automatiquement, et jamais pour vos coffres ou leur contenu.
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
        <label>Mises a jour</label>
        <p style={{ fontSize: 13, color: "var(--text-dim)", margin: "0 0 8px" }}>
          Verifie manuellement s'il existe une nouvelle version. Aucune
          verification automatique n'a lieu en arriere-plan.
        </p>
        {availableUpdate ? (
          <>
            <p style={{ fontSize: 13, margin: "0 0 8px" }}>
              Version {availableUpdate.version} disponible (actuelle :{" "}
              {availableUpdate.currentVersion}).
            </p>
            <button className="btn btn-primary" onClick={handleInstallUpdate} disabled={installingUpdate}>
              {installingUpdate ? "Installation..." : "Telecharger et installer"}
            </button>
          </>
        ) : (
          <button className="btn" onClick={handleCheckForUpdates} disabled={checkingUpdate}>
            {checkingUpdate ? "Verification..." : "Verifier les mises a jour"}
          </button>
        )}
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

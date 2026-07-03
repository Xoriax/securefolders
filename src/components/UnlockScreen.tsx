import { useState } from "react";
import { api, errorMessage } from "../api";
import type { VaultSummary } from "../types";

interface Props {
  vault: VaultSummary;
  onUnlocked: () => void;
  onCancel: () => void;
}

export function UnlockScreen({ vault, onUnlocked, onCancel }: Props) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needsTotp, setNeedsTotp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submitPassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const result = await api.unlockVault(vault.id, password);
      if (result.requiresTotp) {
        setNeedsTotp(true);
      } else {
        onUnlocked();
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.verifyTotp(vault.id, code);
      onUnlocked();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="unlock-screen">
      <div className="lock-icon">🔒</div>
      <h2 style={{ margin: 0 }}>{vault.name}</h2>
      <p style={{ color: "var(--text-dim)", fontSize: 13, margin: 0 }}>
        {needsTotp
          ? "Entrez le code a 6 chiffres de votre application d'authentification."
          : "Entrez le mot de passe maitre pour deverrouiller ce coffre."}
      </p>

      {!needsTotp ? (
        <form onSubmit={submitPassword}>
          <div className="field">
            <input
              type="password"
              placeholder="Mot de passe maitre"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
            />
          </div>
          {error && <div className="error-text">{error}</div>}
          <div className="modal-actions" style={{ justifyContent: "center" }}>
            <button type="button" className="btn" onClick={onCancel}>
              Retour
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Verification..." : "Deverrouiller"}
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={submitCode}>
          <div className="field">
            <input
              className="code-input"
              type="text"
              inputMode="numeric"
              maxLength={6}
              placeholder="000000"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              autoFocus
            />
          </div>
          {error && <div className="error-text">{error}</div>}
          <div className="modal-actions" style={{ justifyContent: "center" }}>
            <button type="button" className="btn" onClick={onCancel}>
              Retour
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={busy || code.length !== 6}
            >
              {busy ? "Verification..." : "Valider"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

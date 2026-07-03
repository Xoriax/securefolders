import { useState } from "react";
import { api, errorMessage } from "../api";
import type { VaultSummary } from "../types";
import { RecoveryCodesDisplay } from "./RecoveryCodesDisplay";

interface Props {
  vault: VaultSummary;
  onClose: () => void;
  onRenamed: (newName: string) => void;
  onTotpDisabled: () => void;
  onDeleted: () => void;
}

export function VaultSettingsModal({ vault, onClose, onRenamed, onTotpDisabled, onDeleted }: Props) {
  const [newName, setNewName] = useState(vault.name);
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [confirmDeleteName, setConfirmDeleteName] = useState("");
  const [newRecoveryCodes, setNewRecoveryCodes] = useState<string[] | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleRegenerateRecoveryCodes() {
    setError(null);
    setMessage(null);
    setBusy(true);
    try {
      const codes = await api.regenerateRecoveryCodes(vault.id);
      setNewRecoveryCodes(codes);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleRename(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    if (!newName.trim() || newName.trim() === vault.name) return;
    setBusy(true);
    try {
      await api.renameVault(vault.id, newName.trim());
      onRenamed(newName.trim());
      setMessage("Coffre renomme.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    if (newPassword.length < 8) {
      setError("Le nouveau mot de passe doit contenir au moins 8 caracteres.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Les nouveaux mots de passe ne correspondent pas.");
      return;
    }
    setBusy(true);
    try {
      await api.changeMasterPassword(vault.id, oldPassword, newPassword);
      setOldPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setMessage("Mot de passe maitre modifie.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleDisableTotp() {
    setError(null);
    setMessage(null);
    setBusy(true);
    try {
      await api.disableTotp(vault.id);
      onTotpDisabled();
      setMessage("2FA desactivee.");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    setError(null);
    setBusy(true);
    try {
      await api.deleteVault(vault.id);
      onDeleted();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={newRecoveryCodes ? undefined : onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 440 }}>
        <h2>Parametres du coffre</h2>

        {newRecoveryCodes ? (
          <RecoveryCodesDisplay
            codes={newRecoveryCodes}
            onAcknowledge={() => {
              setNewRecoveryCodes(null);
              setMessage("Codes de recuperation regeneres.");
            }}
          />
        ) : (
        <>
        <form onSubmit={handleRename}>
          <div className="field">
            <label>Nom du coffre</label>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                style={{ flex: 1 }}
              />
              <button type="submit" className="btn" disabled={busy}>
                Renommer
              </button>
            </div>
          </div>
        </form>

        <form onSubmit={handleChangePassword}>
          <div className="field">
            <label>Changer le mot de passe maitre</label>
            <input
              type="password"
              placeholder="Mot de passe actuel"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
              style={{ marginBottom: 8 }}
            />
            <input
              type="password"
              placeholder="Nouveau mot de passe"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              style={{ marginBottom: 8 }}
            />
            <input
              type="password"
              placeholder="Confirmer le nouveau mot de passe"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              style={{ marginBottom: 8 }}
            />
          </div>
          <button type="submit" className="btn" disabled={busy}>
            Changer le mot de passe
          </button>
        </form>

        {vault.totpEnabled && (
          <div className="field" style={{ marginTop: 18 }}>
            <label>Double authentification</label>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                className="btn"
                onClick={handleRegenerateRecoveryCodes}
                disabled={busy}
              >
                Regenerer les codes de recuperation
              </button>
              <button type="button" className="btn" onClick={handleDisableTotp} disabled={busy}>
                Desactiver la 2FA
              </button>
            </div>
          </div>
        )}

        {message && <p style={{ fontSize: 13, color: "var(--success)" }}>{message}</p>}
        {error && <div className="error-text">{error}</div>}

        <div className="field" style={{ marginTop: 18, borderTop: "1px solid var(--border)", paddingTop: 18 }}>
          <label style={{ color: "var(--danger)" }}>Zone dangereuse</label>
          <p style={{ fontSize: 12, color: "var(--text-dim)", margin: "0 0 8px" }}>
            Supprime definitivement ce coffre et tous ses fichiers chiffres. Cette
            action est irreversible. Tapez <strong>{vault.name}</strong> pour confirmer.
          </p>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              type="text"
              value={confirmDeleteName}
              onChange={(e) => setConfirmDeleteName(e.target.value)}
              placeholder={vault.name}
              style={{ flex: 1 }}
            />
            <button
              type="button"
              className="btn btn-danger"
              disabled={busy || confirmDeleteName !== vault.name}
              onClick={handleDelete}
            >
              Supprimer
            </button>
          </div>
        </div>

        <div className="modal-actions">
          <button type="button" className="btn" onClick={onClose}>
            Fermer
          </button>
        </div>
        </>
        )}
      </div>
    </div>
  );
}

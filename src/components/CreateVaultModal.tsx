import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, errorMessage } from "../api";
import { encodePassword, wipe } from "../secureBytes";
import type { VaultSummary } from "../types";
import { ModalOverlay } from "./ModalOverlay";

interface Props {
  onClose: () => void;
  onCreated: (vault: VaultSummary, enableTotp: boolean) => void;
}

export function CreateVaultModal({ onClose, onCreated }: Props) {
  const [name, setName] = useState("");
  const [location, setLocation] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [enableTotp, setEnableTotp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function pickLocation() {
    const dir = await open({ directory: true, multiple: false });
    if (typeof dir === "string") setLocation(dir);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!name.trim() || !location) {
      setError("Le nom et l'emplacement sont obligatoires.");
      return;
    }
    if (password.length < 8) {
      setError("Le mot de passe maitre doit contenir au moins 8 caracteres.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Les mots de passe ne correspondent pas.");
      return;
    }

    setBusy(true);
    const bytes = encodePassword(password);
    setPassword("");
    setConfirmPassword("");
    try {
      const vault = await api.createVault(name.trim(), location, bytes);
      if (enableTotp) {
        // A freshly created vault has no 2FA yet, so this always succeeds
        // without a code and opens the session `setup_totp` needs next.
        await api.unlockVault(vault.id, bytes);
      }
      onCreated(vault, enableTotp);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      wipe(bytes);
      setBusy(false);
    }
  }

  return (
    <ModalOverlay onClose={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Creer un coffre securise</h2>
        <div className="warning-banner">
          Si vous perdez votre mot de passe, les fichiers ne pourront pas etre
          recuperes. Il n'existe aucune porte derobee.
        </div>
        <form onSubmit={submit}>
          <div className="field">
            <label>Nom du coffre</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Documents personnels"
              autoFocus
            />
          </div>
          <div className="field">
            <label>Emplacement</label>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                type="text"
                value={location}
                onChange={(e) => setLocation(e.target.value)}
                placeholder="C:\\Users\\..."
                style={{ flex: 1 }}
              />
              <button type="button" className="btn" onClick={pickLocation}>
                Parcourir
              </button>
            </div>
          </div>
          <div className="field">
            <label>Mot de passe maitre</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="field">
            <label>Confirmer le mot de passe</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>
          <label className="checkbox-field">
            <input
              type="checkbox"
              checked={enableTotp}
              onChange={(e) => setEnableTotp(e.target.checked)}
            />
            Activer la double authentification (TOTP)
          </label>

          {error && <div className="error-text">{error}</div>}

          <div className="modal-actions">
            <button type="button" className="btn" onClick={onClose}>
              Annuler
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Creation..." : "Creer le coffre"}
            </button>
          </div>
        </form>
      </div>
    </ModalOverlay>
  );
}

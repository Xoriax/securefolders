import { useEffect, useState } from "react";
import { api, errorMessage } from "../api";
import type { TotpSetup } from "../types";
import { RecoveryCodesDisplay } from "./RecoveryCodesDisplay";

interface Props {
  vaultId: string;
  onClose: () => void;
  onEnabled: () => void;
}

export function TotpSetupModal({ vaultId, onClose, onEnabled }: Props) {
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.setupTotp(vaultId).then(setSetup).catch((err) => setError(errorMessage(err)));
  }, [vaultId]);

  async function confirm(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const result = await api.confirmTotp(vaultId, code);
      setRecoveryCodes(result.recoveryCodes);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={recoveryCodes ? undefined : onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Activer la double authentification</h2>
        {recoveryCodes ? (
          <RecoveryCodesDisplay codes={recoveryCodes} onAcknowledge={onEnabled} />
        ) : !setup ? (
          <p style={{ color: "var(--text-dim)", fontSize: 13 }}>
            {error ?? "Generation du secret..."}
          </p>
        ) : (
          <form onSubmit={confirm}>
            <p style={{ color: "var(--text-dim)", fontSize: 13, marginTop: 0 }}>
              Scannez ce QR code avec Google Authenticator, Microsoft
              Authenticator ou Authy.
            </p>
            <div className="qr-box">
              <img src={setup.qrCodeDataUrl} alt="QR code TOTP" />
            </div>
            <label style={{ fontSize: 12, color: "var(--text-dim)" }}>
              Ou entrez ce code manuellement :
            </label>
            <div className="secret-code">{setup.secretBase32}</div>
            <div className="field">
              <label>Code de verification</label>
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
            <div className="modal-actions">
              <button type="button" className="btn" onClick={onClose}>
                Annuler
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={busy || code.length !== 6}
              >
                {busy ? "Verification..." : "Activer"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

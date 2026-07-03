import { useState } from "react";

interface Props {
  codes: string[];
  onAcknowledge: () => void;
}

export function RecoveryCodesDisplay({ codes, onAcknowledge }: Props) {
  const [confirmed, setConfirmed] = useState(false);

  return (
    <div>
      <div className="warning-banner">
        Notez ces codes de recuperation et rangez-les en lieu sur (gestionnaire
        de mots de passe, papier hors ligne). Chacun ne fonctionne qu'une
        seule fois et permet de deverrouiller ce coffre avec votre mot de
        passe maitre si vous perdez l'acces a votre application
        d'authentification. Ils ne seront plus jamais affiches.
      </div>
      <div className="recovery-codes-grid">
        {codes.map((code) => (
          <code key={code} className="secret-code" style={{ marginBottom: 0 }}>
            {code}
          </code>
        ))}
      </div>
      <label className="checkbox-field" style={{ marginTop: 14 }}>
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
        />
        J'ai sauvegarde ces codes en lieu sur
      </label>
      <div className="modal-actions">
        <button
          type="button"
          className="btn btn-primary"
          disabled={!confirmed}
          onClick={onAcknowledge}
        >
          Continuer
        </button>
      </div>
    </div>
  );
}

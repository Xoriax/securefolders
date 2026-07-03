import { useEffect, useState } from "react";
import { convertFileSrc } from "@tauri-apps/api/core";
import { api, errorMessage } from "../api";
import type { FileEntry, FilePreview } from "../types";

interface Props {
  vaultId: string;
  file: FileEntry;
  onClose: () => void;
}

export function FilePreviewModal({ vaultId, file, onClose }: Props) {
  const [preview, setPreview] = useState<FilePreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .previewFile(vaultId, file.id)
      .then(setPreview)
      .catch((err) => setError(errorMessage(err)));
  }, [vaultId, file.id]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{ width: 560 }}>
        <h2>{file.name}</h2>

        {error && <div className="error-text">{error}</div>}

        {!preview && !error && (
          <p style={{ color: "var(--text-dim)", fontSize: 13 }}>Dechiffrement de l'apercu...</p>
        )}

        {preview?.kind === "image" && (
          <img
            src={convertFileSrc(preview.path)}
            alt={file.name}
            style={{ maxWidth: "100%", maxHeight: 420, borderRadius: 8, display: "block", margin: "0 auto" }}
          />
        )}

        {preview?.kind === "text" && (
          <>
            <pre className="preview-text">{preview.content}</pre>
            {preview.truncated && (
              <p style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 8 }}>
                Apercu tronque — exportez le fichier pour voir le contenu complet.
              </p>
            )}
          </>
        )}

        {preview?.kind === "tooLarge" && (
          <p style={{ color: "var(--text-dim)", fontSize: 13 }}>
            Fichier trop volumineux pour un apercu. Exportez-le pour le consulter.
          </p>
        )}

        {preview?.kind === "unsupported" && (
          <p style={{ color: "var(--text-dim)", fontSize: 13 }}>
            Aucun apercu disponible pour ce type de fichier. Exportez-le pour l'ouvrir.
          </p>
        )}

        <div className="modal-actions">
          <button type="button" className="btn" onClick={onClose}>
            Fermer
          </button>
        </div>
      </div>
    </div>
  );
}

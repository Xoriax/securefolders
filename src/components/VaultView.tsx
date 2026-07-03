import { useCallback, useEffect, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { api, errorMessage } from "../api";
import type { FileEntry, VaultSummary } from "../types";
import { TotpSetupModal } from "./TotpSetupModal";

interface Props {
  vault: VaultSummary;
  onLocked: () => void;
  onVaultUpdated: (vault: VaultSummary) => void;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

export function VaultView({ vault, onLocked, onVaultUpdated }: Props) {
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showTotpSetup, setShowTotpSetup] = useState(false);

  const refresh = useCallback(() => {
    api
      .listFiles(vault.id)
      .then(setFiles)
      .catch((err) => setError(errorMessage(err)));
  }, [vault.id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    const unlisten = getCurrentWebview().onDragDropEvent(async (event) => {
      if (event.payload.type === "over") {
        setDragging(true);
      } else if (event.payload.type === "drop") {
        setDragging(false);
        for (const path of event.payload.paths) {
          try {
            await api.addFile(vault.id, path);
          } catch (err) {
            setError(errorMessage(err));
          }
        }
        refresh();
      } else {
        setDragging(false);
      }
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [vault.id, refresh]);

  async function handleLock() {
    await api.lockVault(vault.id);
    onLocked();
  }

  async function handleRemove(fileId: string) {
    try {
      await api.removeFile(vault.id, fileId);
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function handleExport(fileId: string) {
    const destDir = await open({ directory: true, multiple: false });
    if (typeof destDir !== "string") return;
    try {
      await api.exportFile(vault.id, fileId, destDir);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <div>
      <div className="vault-toolbar">
        <div>
          <h1 style={{ fontSize: 18, margin: 0 }}>{vault.name}</h1>
          <p style={{ color: "var(--text-dim)", fontSize: 12, margin: "4px 0 0" }}>
            {files.length} fichier{files.length !== 1 ? "s" : ""} · {vault.path}
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {!vault.totpEnabled && (
            <button className="btn" onClick={() => setShowTotpSetup(true)}>
              Activer la 2FA
            </button>
          )}
          <button className="btn" onClick={handleLock}>
            Verrouiller
          </button>
        </div>
      </div>

      <div className={`dropzone ${dragging ? "dragging" : ""}`}>
        Glissez-deposez des fichiers ici pour les chiffrer et les ajouter au coffre
      </div>

      {error && <div className="error-text">{error}</div>}

      {files.length === 0 ? (
        <div className="empty-state">Ce coffre ne contient encore aucun fichier.</div>
      ) : (
        <div className="file-list">
          {files.map((file) => (
            <div className="file-row" key={file.id}>
              <div className="file-name">
                <span>📄</span>
                <span>{file.name}</span>
                <span className="file-size">{formatSize(file.size)}</span>
              </div>
              <div className="row-actions">
                <button onClick={() => handleExport(file.id)}>Exporter</button>
                <button onClick={() => handleRemove(file.id)}>Supprimer</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {showTotpSetup && (
        <TotpSetupModal
          vaultId={vault.id}
          onClose={() => setShowTotpSetup(false)}
          onEnabled={() => {
            setShowTotpSetup(false);
            onVaultUpdated({ ...vault, totpEnabled: true });
          }}
        />
      )}
    </div>
  );
}

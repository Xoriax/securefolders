import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import { api, errorMessage } from "../api";
import type { FileEntry, TransferProgress, VaultSummary } from "../types";
import { TotpSetupModal } from "./TotpSetupModal";
import { VaultSettingsModal } from "./VaultSettingsModal";
import { FilePreviewModal } from "./FilePreviewModal";

interface Props {
  vault: VaultSummary;
  onLocked: () => void;
  onDeleted: () => void;
  onVaultUpdated: (vault: VaultSummary) => void;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

type SortKey = "name-asc" | "name-desc" | "date-desc" | "size-desc";

function sortFiles(files: FileEntry[], sortKey: SortKey): FileEntry[] {
  const sorted = [...files];
  switch (sortKey) {
    case "name-asc":
      return sorted.sort((a, b) => a.name.localeCompare(b.name));
    case "name-desc":
      return sorted.sort((a, b) => b.name.localeCompare(a.name));
    case "date-desc":
      return sorted.sort((a, b) => b.addedAt.localeCompare(a.addedAt));
    case "size-desc":
      return sorted.sort((a, b) => b.size - a.size);
  }
}

export function VaultView({ vault, onLocked, onDeleted, onVaultUpdated }: Props) {
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showTotpSetup, setShowTotpSetup] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [previewingFile, setPreviewingFile] = useState<FileEntry | null>(null);
  const [progress, setProgress] = useState<TransferProgress | null>(null);
  const progressClearTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("name-asc");
  const [renamingFileId, setRenamingFileId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");

  const visibleFiles = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    const filtered = query
      ? files.filter((f) => f.name.toLowerCase().includes(query))
      : files;
    return sortFiles(filtered, sortKey);
  }, [files, searchQuery, sortKey]);

  const refresh = useCallback(() => {
    api
      .listFiles(vault.id)
      .then(setFiles)
      .catch((err) => setError(errorMessage(err)));
  }, [vault.id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // The vault auto-locks after inactivity even if the user never touches
  // this screen; poll so the UI notices and drops back to the unlock screen
  // instead of showing a "vault" view backed by a session that no longer exists.
  useEffect(() => {
    const interval = setInterval(async () => {
      const unlocked = await api.isVaultUnlocked(vault.id).catch(() => true);
      if (!unlocked) onLocked();
    }, 10_000);
    return () => clearInterval(interval);
  }, [vault.id, onLocked]);

  useEffect(() => {
    const unlisten = listen<TransferProgress>("vault://transfer-progress", (event) => {
      if (event.payload.vaultId !== vault.id) return;
      setProgress(event.payload);

      if (progressClearTimer.current) clearTimeout(progressClearTimer.current);
      if (event.payload.bytesDone >= event.payload.bytesTotal) {
        // Let the bar sit at 100% briefly instead of vanishing instantly.
        progressClearTimer.current = setTimeout(() => setProgress(null), 500);
      }
    });
    return () => {
      unlisten.then((fn) => fn());
      if (progressClearTimer.current) clearTimeout(progressClearTimer.current);
    };
  }, [vault.id]);

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

  function startRename(file: FileEntry) {
    setRenamingFileId(file.id);
    setRenameValue(file.name);
  }

  async function commitRename(fileId: string) {
    const newName = renameValue.trim();
    setRenamingFileId(null);
    if (!newName) return;
    try {
      await api.renameFile(vault.id, fileId, newName);
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function handleExport(file: FileEntry) {
    setError(null);
    try {
      const destination = await save({ defaultPath: file.name });
      if (!destination) return; // user cancelled the dialog
      await api.exportFileTo(vault.id, file.id, destination);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  const progressPercent = progress
    ? progress.bytesTotal === 0
      ? 100
      : Math.round((progress.bytesDone / progress.bytesTotal) * 100)
    : 0;

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
          <button className="btn" onClick={() => setShowSettings(true)}>
            Parametres
          </button>
          <button className="btn" onClick={handleLock}>
            Verrouiller
          </button>
        </div>
      </div>

      <div className={`dropzone ${dragging ? "dragging" : ""}`}>
        Glissez-deposez des fichiers ici pour les chiffrer et les ajouter au coffre
      </div>

      {progress && (
        <div className="progress-box">
          <div className="progress-box-label">
            <span>
              {progress.direction === "import" ? "Chiffrement" : "Dechiffrement"} de {progress.fileName}
            </span>
            <span>{progressPercent}%</span>
          </div>
          <div className="progress-bar">
            <div className="progress-bar-fill" style={{ width: `${progressPercent}%` }} />
          </div>
        </div>
      )}

      {error && <div className="error-text">{error}</div>}

      {files.length === 0 ? (
        <div className="empty-state">Ce coffre ne contient encore aucun fichier.</div>
      ) : (
        <>
          <div className="file-list-toolbar">
            <input
              type="text"
              placeholder="Rechercher un fichier..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ flex: 1 }}
            />
            <select value={sortKey} onChange={(e) => setSortKey(e.target.value as SortKey)}>
              <option value="name-asc">Nom (A-Z)</option>
              <option value="name-desc">Nom (Z-A)</option>
              <option value="date-desc">Plus recent</option>
              <option value="size-desc">Plus volumineux</option>
            </select>
          </div>

          {visibleFiles.length === 0 ? (
            <div className="empty-state">Aucun fichier ne correspond a la recherche.</div>
          ) : (
            <div className="file-list">
              {visibleFiles.map((file) => (
                <div className="file-row" key={file.id}>
                  <div className="file-name">
                    <span>📄</span>
                    {renamingFileId === file.id ? (
                      <input
                        type="text"
                        autoFocus
                        value={renameValue}
                        onChange={(e) => setRenameValue(e.target.value)}
                        onBlur={() => commitRename(file.id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") commitRename(file.id);
                          if (e.key === "Escape") setRenamingFileId(null);
                        }}
                      />
                    ) : (
                      <span>{file.name}</span>
                    )}
                    <span className="file-size">{formatSize(file.size)}</span>
                  </div>
                  <div className="row-actions">
                    <button onClick={() => setPreviewingFile(file)}>Apercu</button>
                    <button onClick={() => startRename(file)}>Renommer</button>
                    <button onClick={() => handleExport(file)}>Exporter</button>
                    <button onClick={() => handleRemove(file.id)}>Supprimer</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
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

      {showSettings && (
        <VaultSettingsModal
          vault={vault}
          onClose={() => setShowSettings(false)}
          onRenamed={(newName) => onVaultUpdated({ ...vault, name: newName })}
          onTotpDisabled={() => onVaultUpdated({ ...vault, totpEnabled: false })}
          onDeleted={onDeleted}
        />
      )}

      {previewingFile && (
        <FilePreviewModal
          vaultId={vault.id}
          file={previewingFile}
          onClose={() => setPreviewingFile(null)}
        />
      )}
    </div>
  );
}

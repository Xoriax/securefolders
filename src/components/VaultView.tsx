import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import { api, errorMessage } from "../api";
import { breadcrumbPath, formatSize, sortFiles, type SortKey } from "../fileListUtils";
import type { FileEntry, Folder, TransferProgress, VaultSummary } from "../types";
import { TotpSetupModal } from "./TotpSetupModal";
import { VaultSettingsModal } from "./VaultSettingsModal";
import { FilePreviewModal } from "./FilePreviewModal";

interface Props {
  vault: VaultSummary;
  onLocked: () => void;
  onDeleted: () => void;
  onVaultUpdated: (vault: VaultSummary) => void;
}

export function VaultView({ vault, onLocked, onDeleted, onVaultUpdated }: Props) {
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [currentFolderId, setCurrentFolderId] = useState<string | null>(null);
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
  const [renamingFolderId, setRenamingFolderId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [showNewFolder, setShowNewFolder] = useState(false);
  const [newFolderName, setNewFolderName] = useState("");

  const breadcrumb = useMemo(
    () => breadcrumbPath(folders, currentFolderId),
    [folders, currentFolderId],
  );

  const visibleFolders = useMemo(
    () =>
      [...folders]
        .filter((f) => f.parentId === currentFolderId)
        .sort((a, b) => a.name.localeCompare(b.name)),
    [folders, currentFolderId],
  );

  const visibleFiles = useMemo(() => {
    const inFolder = files.filter((f) => f.parentId === currentFolderId);
    const query = searchQuery.trim().toLowerCase();
    const filtered = query
      ? inFolder.filter((f) => f.name.toLowerCase().includes(query))
      : inFolder;
    return sortFiles(filtered, sortKey);
  }, [files, currentFolderId, searchQuery, sortKey]);

  const refresh = useCallback(() => {
    api
      .listFiles(vault.id)
      .then(setFiles)
      .catch((err) => setError(errorMessage(err)));
    api
      .listFolders(vault.id)
      .then(setFolders)
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
            await api.addFile(vault.id, path, currentFolderId);
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
  }, [vault.id, currentFolderId, refresh]);

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

  async function handleCreateFolder(e: React.FormEvent) {
    e.preventDefault();
    const name = newFolderName.trim();
    setShowNewFolder(false);
    setNewFolderName("");
    if (!name) return;
    try {
      await api.createFolder(vault.id, currentFolderId, name);
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  function startFolderRename(folder: Folder) {
    setRenamingFolderId(folder.id);
    setRenameValue(folder.name);
  }

  async function commitFolderRename(folderId: string) {
    const newName = renameValue.trim();
    setRenamingFolderId(null);
    if (!newName) return;
    try {
      await api.renameFolder(vault.id, folderId, newName);
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function handleDeleteFolder(folder: Folder) {
    if (!window.confirm(`Supprimer le dossier "${folder.name}" et tout son contenu ?`)) {
      return;
    }
    try {
      await api.deleteFolder(vault.id, folder.id);
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

      <div className="breadcrumb">
        <button
          className={`breadcrumb-item ${currentFolderId === null ? "active" : ""}`}
          onClick={() => setCurrentFolderId(null)}
        >
          Racine
        </button>
        {breadcrumb.map((folder) => (
          <span key={folder.id}>
            <span className="breadcrumb-sep">/</span>
            <button
              className={`breadcrumb-item ${currentFolderId === folder.id ? "active" : ""}`}
              onClick={() => setCurrentFolderId(folder.id)}
            >
              {folder.name}
            </button>
          </span>
        ))}
        <button className="btn" style={{ marginLeft: "auto" }} onClick={() => setShowNewFolder(true)}>
          + Nouveau dossier
        </button>
      </div>

      {showNewFolder && (
        <form onSubmit={handleCreateFolder} className="field" style={{ display: "flex", gap: 8 }}>
          <input
            type="text"
            autoFocus
            placeholder="Nom du dossier"
            value={newFolderName}
            onChange={(e) => setNewFolderName(e.target.value)}
            style={{ flex: 1 }}
          />
          <button type="submit" className="btn btn-primary">
            Creer
          </button>
          <button type="button" className="btn" onClick={() => setShowNewFolder(false)}>
            Annuler
          </button>
        </form>
      )}

      {visibleFolders.length > 0 && (
        <div className="file-list" style={{ marginBottom: 12 }}>
          {visibleFolders.map((folder) => (
            <div className="file-row" key={folder.id}>
              <div className="file-name">
                <span>📁</span>
                {renamingFolderId === folder.id ? (
                  <input
                    type="text"
                    autoFocus
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    onBlur={() => commitFolderRename(folder.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") commitFolderRename(folder.id);
                      if (e.key === "Escape") setRenamingFolderId(null);
                    }}
                  />
                ) : (
                  <button className="link-button" onClick={() => setCurrentFolderId(folder.id)}>
                    {folder.name}
                  </button>
                )}
              </div>
              <div className="row-actions">
                <button onClick={() => startFolderRename(folder)}>Renommer</button>
                <button onClick={() => handleDeleteFolder(folder)}>Supprimer</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {files.length === 0 && folders.length === 0 ? (
        <div className="empty-state">Ce coffre ne contient encore aucun fichier.</div>
      ) : visibleFiles.length === 0 && visibleFolders.length === 0 ? (
        <div className="empty-state">Ce dossier est vide.</div>
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

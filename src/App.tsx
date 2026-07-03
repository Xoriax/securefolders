import { useEffect, useState } from "react";
import "./App.css";
import { api, errorMessage } from "./api";
import type { VaultSummary } from "./types";
import { CreateVaultModal } from "./components/CreateVaultModal";
import { UnlockScreen } from "./components/UnlockScreen";
import { VaultView } from "./components/VaultView";
import { SettingsPage } from "./components/SettingsPage";
import { TotpSetupModal } from "./components/TotpSetupModal";

type Page = "vaults" | "settings";
type View =
  | { kind: "list" }
  | { kind: "unlock"; vault: VaultSummary }
  | { kind: "vault"; vault: VaultSummary };

function App() {
  const [page, setPage] = useState<Page>("vaults");
  const [vaults, setVaults] = useState<VaultSummary[]>([]);
  const [view, setView] = useState<View>({ kind: "list" });
  const [showCreate, setShowCreate] = useState(false);
  const [pendingTotpVaultId, setPendingTotpVaultId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function refreshVaults() {
    api
      .listVaults()
      .then(setVaults)
      .catch((err) => setError(errorMessage(err)));
  }

  useEffect(() => {
    refreshVaults();
  }, []);

  function openVault(vault: VaultSummary) {
    setView({ kind: "unlock", vault });
  }

  function backToList() {
    setView({ kind: "list" });
    refreshVaults();
  }

  return (
    <div className="app-shell">
      <div className="app-titlebar">
        <div className="brand">
          <span className="dot" />
          SecureFolders
        </div>
        <div className="nav-tabs">
          <button
            className={page === "vaults" ? "active" : ""}
            onClick={() => {
              setPage("vaults");
              setView({ kind: "list" });
            }}
          >
            Coffres
          </button>
          <button
            className={page === "settings" ? "active" : ""}
            onClick={() => setPage("settings")}
          >
            Parametres
          </button>
        </div>
      </div>

      <div className="app-content">
        {page === "settings" ? (
          <SettingsPage />
        ) : view.kind === "unlock" ? (
          <UnlockScreen
            vault={view.vault}
            onCancel={backToList}
            onUnlocked={() => setView({ kind: "vault", vault: view.vault })}
          />
        ) : view.kind === "vault" ? (
          <VaultView
            vault={view.vault}
            onLocked={backToList}
            onVaultUpdated={(updated) =>
              setView({ kind: "vault", vault: updated })
            }
          />
        ) : (
          <>
            <div className="page-header">
              <div>
                <h1>Mes coffres</h1>
                <p>Vos dossiers chiffres, stockes uniquement en local</p>
              </div>
              <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
                + Creer un coffre
              </button>
            </div>

            {error && <div className="error-text">{error}</div>}

            {vaults.length === 0 ? (
              <div className="empty-state">
                Aucun coffre pour le moment. Creez-en un pour commencer a
                proteger vos fichiers.
              </div>
            ) : (
              <div className="vault-grid">
                {vaults.map((vault) => (
                  <button
                    key={vault.id}
                    className="vault-card"
                    onClick={() => openVault(vault)}
                  >
                    <div className="vault-icon">🔒</div>
                    <h3>{vault.name}</h3>
                    <div className="meta">
                      <span>{vault.fileCount} fichier(s)</span>
                      {vault.totpEnabled && <span className="badge">2FA</span>}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {showCreate && (
        <CreateVaultModal
          onClose={() => setShowCreate(false)}
          onCreated={(vault, enableTotp) => {
            setShowCreate(false);
            refreshVaults();
            if (enableTotp) {
              setPendingTotpVaultId(vault.id);
            }
          }}
        />
      )}

      {pendingTotpVaultId && (
        <TotpSetupModal
          vaultId={pendingTotpVaultId}
          onClose={() => setPendingTotpVaultId(null)}
          onEnabled={() => {
            setPendingTotpVaultId(null);
            refreshVaults();
          }}
        />
      )}
    </div>
  );
}

export default App;

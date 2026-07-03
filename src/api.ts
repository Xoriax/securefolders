import { invoke } from "@tauri-apps/api/core";
import type { FileEntry, TotpSetup, UnlockResult, VaultSummary } from "./types";

// Thin typed wrapper around the Tauri commands exposed by src-tauri/src/commands.rs.
// Every call can reject with the French error message produced by AppError on the Rust side.
export const api = {
  listVaults: () => invoke<VaultSummary[]>("list_vaults"),

  createVault: (name: string, location: string, password: string) =>
    invoke<VaultSummary>("create_vault", { name, location, password }),

  unlockVault: (vaultId: string, password: string) =>
    invoke<UnlockResult>("unlock_vault", { vaultId, password }),

  verifyTotp: (vaultId: string, code: string) =>
    invoke<void>("verify_totp", { vaultId, code }),

  lockVault: (vaultId: string) => invoke<void>("lock_vault", { vaultId }),

  lockAllVaults: () => invoke<void>("lock_all_vaults"),

  setupTotp: (vaultId: string) => invoke<TotpSetup>("setup_totp", { vaultId }),

  confirmTotp: (vaultId: string, code: string) =>
    invoke<void>("confirm_totp", { vaultId, code }),

  listFiles: (vaultId: string) => invoke<FileEntry[]>("list_files", { vaultId }),

  addFile: (vaultId: string, sourcePath: string) =>
    invoke<FileEntry>("add_file", { vaultId, sourcePath }),

  removeFile: (vaultId: string, fileId: string) =>
    invoke<void>("remove_file", { vaultId, fileId }),

  exportFile: (vaultId: string, fileId: string, destDir: string) =>
    invoke<string>("export_file", { vaultId, fileId, destDir }),

  isVaultUnlocked: (vaultId: string) =>
    invoke<boolean>("is_vault_unlocked", { vaultId }),
};

export function errorMessage(err: unknown): string {
  return typeof err === "string" ? err : "Une erreur inattendue est survenue.";
}

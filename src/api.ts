import { invoke } from "@tauri-apps/api/core";
import type { ConfirmTotpResult, FileEntry, TotpSetup, UnlockResult, VaultSummary } from "./types";

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

  unlockWithRecoveryCode: (vaultId: string, code: string) =>
    invoke<void>("unlock_with_recovery_code", { vaultId, code }),

  lockVault: (vaultId: string) => invoke<void>("lock_vault", { vaultId }),

  lockAllVaults: () => invoke<void>("lock_all_vaults"),

  setupTotp: (vaultId: string) => invoke<TotpSetup>("setup_totp", { vaultId }),

  confirmTotp: (vaultId: string, code: string) =>
    invoke<ConfirmTotpResult>("confirm_totp", { vaultId, code }),

  regenerateRecoveryCodes: (vaultId: string) =>
    invoke<string[]>("regenerate_recovery_codes", { vaultId }),

  listFiles: (vaultId: string) => invoke<FileEntry[]>("list_files", { vaultId }),

  addFile: (vaultId: string, sourcePath: string) =>
    invoke<FileEntry>("add_file", { vaultId, sourcePath }),

  removeFile: (vaultId: string, fileId: string) =>
    invoke<void>("remove_file", { vaultId, fileId }),

  exportFile: (vaultId: string, fileId: string) =>
    invoke<string>("export_file", { vaultId, fileId }),

  isVaultUnlocked: (vaultId: string) =>
    invoke<boolean>("is_vault_unlocked", { vaultId }),

  deleteVault: (vaultId: string) => invoke<void>("delete_vault", { vaultId }),

  renameVault: (vaultId: string, newName: string) =>
    invoke<void>("rename_vault", { vaultId, newName }),

  changeMasterPassword: (vaultId: string, oldPassword: string, newPassword: string) =>
    invoke<void>("change_master_password", { vaultId, oldPassword, newPassword }),

  disableTotp: (vaultId: string) => invoke<void>("disable_totp", { vaultId }),
};

export function errorMessage(err: unknown): string {
  return typeof err === "string" ? err : "Une erreur inattendue est survenue.";
}

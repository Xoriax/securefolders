import { invoke } from "@tauri-apps/api/core";
import type {
  ConfirmTotpResult,
  FileEntry,
  FilePreview,
  Folder,
  TotpSetup,
  UnlockResult,
  VaultSummary,
} from "./types";

// Thin typed wrapper around the Tauri commands exposed by src-tauri/src/commands.rs.
// Every call can reject with the French error message produced by AppError on the Rust side.
export const api = {
  listVaults: () => invoke<VaultSummary[]>("list_vaults"),

  // Passwords travel as raw bytes (see secureBytes.ts), not JS strings.
  createVault: (name: string, location: string, password: number[]) =>
    invoke<VaultSummary>("create_vault", { name, location, password }),

  unlockVault: (vaultId: string, password: number[]) =>
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

  addFile: (vaultId: string, sourcePath: string, parentId: string | null) =>
    invoke<FileEntry>("add_file", { vaultId, sourcePath, parentId }),

  renameFile: (vaultId: string, fileId: string, newName: string) =>
    invoke<void>("rename_file", { vaultId, fileId, newName }),

  listFolders: (vaultId: string) => invoke<Folder[]>("list_folders", { vaultId }),

  createFolder: (vaultId: string, parentId: string | null, name: string) =>
    invoke<Folder>("create_folder", { vaultId, parentId, name }),

  renameFolder: (vaultId: string, folderId: string, newName: string) =>
    invoke<void>("rename_folder", { vaultId, folderId, newName }),

  deleteFolder: (vaultId: string, folderId: string) =>
    invoke<void>("delete_folder", { vaultId, folderId }),

  removeFile: (vaultId: string, fileId: string) =>
    invoke<void>("remove_file", { vaultId, fileId }),

  exportFile: (vaultId: string, fileId: string) =>
    invoke<string>("export_file", { vaultId, fileId }),

  exportFileTo: (vaultId: string, fileId: string, destination: string) =>
    invoke<void>("export_file_to", { vaultId, fileId, destination }),

  previewFile: (vaultId: string, fileId: string) =>
    invoke<FilePreview>("preview_file", { vaultId, fileId }),

  isVaultUnlocked: (vaultId: string) =>
    invoke<boolean>("is_vault_unlocked", { vaultId }),

  deleteVault: (vaultId: string) => invoke<void>("delete_vault", { vaultId }),

  exportVaultBackup: (vaultId: string, destination: string) =>
    invoke<void>("export_vault_backup", { vaultId, destination }),

  importVaultBackup: (backupZip: string, destinationParent: string) =>
    invoke<VaultSummary>("import_vault_backup", { backupZip, destinationParent }),

  renameVault: (vaultId: string, newName: string) =>
    invoke<void>("rename_vault", { vaultId, newName }),

  changeMasterPassword: (vaultId: string, oldPassword: number[], newPassword: number[]) =>
    invoke<void>("change_master_password", { vaultId, oldPassword, newPassword }),

  disableTotp: (vaultId: string) => invoke<void>("disable_totp", { vaultId }),

  getAutoLockSeconds: () => invoke<number>("get_auto_lock_seconds"),

  setAutoLockSeconds: (seconds: number) =>
    invoke<void>("set_auto_lock_seconds", { seconds }),

  getLaunchTarget: () => invoke<string | null>("get_launch_target"),

  createVaultLauncher: (vaultId: string) =>
    invoke<void>("create_vault_launcher", { vaultId }),
};

export function errorMessage(err: unknown): string {
  return typeof err === "string" ? err : "Une erreur inattendue est survenue.";
}

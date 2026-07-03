export interface FileEntry {
  id: string;
  name: string;
  size: number;
  addedAt: string;
}

export interface VaultSummary {
  id: string;
  name: string;
  path: string;
  totpEnabled: boolean;
  fileCount: number;
  createdAt: string;
}

export interface UnlockResult {
  requiresTotp: boolean;
}

export interface TotpSetup {
  secretBase32: string;
  qrCodeDataUrl: string;
}

export interface ConfirmTotpResult {
  recoveryCodes: string[];
}

export interface TransferProgress {
  vaultId: string;
  fileName: string;
  direction: "import" | "export";
  bytesDone: number;
  bytesTotal: number;
}

export type FilePreview =
  | { kind: "image"; path: string }
  | { kind: "text"; content: string; truncated: boolean }
  | { kind: "tooLarge" }
  | { kind: "unsupported" };

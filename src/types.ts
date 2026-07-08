export interface FileEntry {
  id: string;
  name: string;
  size: number;
  addedAt: string;
  parentId: string | null;
}

export interface Folder {
  id: string;
  name: string;
  parentId: string | null;
}

export interface VaultSummary {
  id: string;
  name: string;
  path: string;
  totpEnabled: boolean;
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

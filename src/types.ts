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

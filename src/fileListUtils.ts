import type { FileEntry } from "./types";

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

export type SortKey = "name-asc" | "name-desc" | "date-desc" | "size-desc";

export function sortFiles(files: FileEntry[], sortKey: SortKey): FileEntry[] {
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

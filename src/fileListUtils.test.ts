import { describe, expect, it } from "vitest";
import { breadcrumbPath, sortFiles } from "./fileListUtils";
import type { FileEntry, Folder } from "./types";

function file(overrides: Partial<FileEntry>): FileEntry {
  return {
    id: "id",
    name: "file.txt",
    size: 0,
    addedAt: "2026-01-01T00:00:00Z",
    parentId: null,
    ...overrides,
  };
}

function folder(overrides: Partial<Folder>): Folder {
  return {
    id: "id",
    name: "folder",
    parentId: null,
    ...overrides,
  };
}

describe("sortFiles", () => {
  const files: FileEntry[] = [
    file({ id: "1", name: "banane.txt", size: 300, addedAt: "2026-01-02T00:00:00Z" }),
    file({ id: "2", name: "abricot.txt", size: 100, addedAt: "2026-01-03T00:00:00Z" }),
    file({ id: "3", name: "cerise.txt", size: 200, addedAt: "2026-01-01T00:00:00Z" }),
  ];

  it("sorts by name ascending", () => {
    expect(sortFiles(files, "name-asc").map((f) => f.name)).toEqual([
      "abricot.txt",
      "banane.txt",
      "cerise.txt",
    ]);
  });

  it("sorts by name descending", () => {
    expect(sortFiles(files, "name-desc").map((f) => f.name)).toEqual([
      "cerise.txt",
      "banane.txt",
      "abricot.txt",
    ]);
  });

  it("sorts by most recently added first", () => {
    expect(sortFiles(files, "date-desc").map((f) => f.id)).toEqual(["2", "1", "3"]);
  });

  it("sorts by largest first", () => {
    expect(sortFiles(files, "size-desc").map((f) => f.id)).toEqual(["1", "3", "2"]);
  });

  it("does not mutate the input array", () => {
    const original = [...files];
    sortFiles(files, "name-asc");
    expect(files).toEqual(original);
  });
});

describe("breadcrumbPath", () => {
  const folders: Folder[] = [
    folder({ id: "root-child", name: "Documents", parentId: null }),
    folder({ id: "nested", name: "Factures", parentId: "root-child" }),
    folder({ id: "unrelated", name: "Photos", parentId: null }),
  ];

  it("is empty at the vault's root", () => {
    expect(breadcrumbPath(folders, null)).toEqual([]);
  });

  it("has one entry for a top-level folder", () => {
    expect(breadcrumbPath(folders, "root-child").map((f) => f.name)).toEqual(["Documents"]);
  });

  it("walks up from a nested folder to the root", () => {
    expect(breadcrumbPath(folders, "nested").map((f) => f.name)).toEqual([
      "Documents",
      "Factures",
    ]);
  });

  it("stops without throwing if a folder id is unknown", () => {
    expect(breadcrumbPath(folders, "does-not-exist")).toEqual([]);
  });
});

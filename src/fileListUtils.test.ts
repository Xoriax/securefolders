import { describe, expect, it } from "vitest";
import { sortFiles } from "./fileListUtils";
import type { FileEntry } from "./types";

function file(overrides: Partial<FileEntry>): FileEntry {
  return {
    id: "id",
    name: "file.txt",
    size: 0,
    addedAt: "2026-01-01T00:00:00Z",
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

import { describe, expect, it } from "vitest";
import { encodePassword, wipe } from "./secureBytes";

describe("encodePassword", () => {
  it("round-trips a plain ASCII password to UTF-8 byte values", () => {
    expect(encodePassword("abc123")).toEqual([97, 98, 99, 49, 50, 51]);
  });

  it("encodes multi-byte UTF-8 characters correctly", () => {
    // "é" is 2 bytes in UTF-8 (0xC3 0xA9), not 1
    expect(encodePassword("é")).toEqual([0xc3, 0xa9]);
  });

  it("encodes an empty password as an empty array", () => {
    expect(encodePassword("")).toEqual([]);
  });
});

describe("wipe", () => {
  it("overwrites every element of the array with zero", () => {
    const bytes = encodePassword("secret");
    expect(bytes.some((b) => b !== 0)).toBe(true);
    wipe(bytes);
    expect(bytes.every((b) => b === 0)).toBe(true);
  });

  it("preserves the array's length", () => {
    const bytes = encodePassword("secret");
    const originalLength = bytes.length;
    wipe(bytes);
    expect(bytes).toHaveLength(originalLength);
  });
});

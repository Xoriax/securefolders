import { describe, expect, it } from "vitest";
import { wasLikelySuspended } from "./suspendDetector";

describe("wasLikelySuspended", () => {
  it("is false for a normal polling gap", () => {
    expect(wasLikelySuspended(10_000)).toBe(false);
  });

  it("is false for minor jitter above the expected interval", () => {
    expect(wasLikelySuspended(15_000)).toBe(false);
  });

  it("is true for a gap consistent with sleep/hibernate", () => {
    expect(wasLikelySuspended(5 * 60_000)).toBe(true);
  });

  it("is false exactly at the threshold and true just past it", () => {
    expect(wasLikelySuspended(60_000)).toBe(false);
    expect(wasLikelySuspended(60_001)).toBe(true);
  });
});

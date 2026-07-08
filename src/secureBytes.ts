const encoder = new TextEncoder();

/**
 * Encodes a password to raw bytes for the IPC call, as a plain number
 * array rather than a Uint8Array — Tauri's invoke() serializes arguments
 * with JSON.stringify, which turns a Uint8Array into an object of numeric
 * keys instead of a JSON array, so the Rust side (expecting `Vec<u8>`)
 * would fail to deserialize it.
 */
export function encodePassword(value: string): number[] {
  return Array.from(encoder.encode(value));
}

/**
 * Best-effort: overwrites a byte array in place immediately after it's
 * been sent, so our own copy of the password's bytes doesn't sit reachable
 * for the rest of the component's lifetime. JS strings are immutable and
 * can't be wiped this way — this narrows the window a copy is reachable
 * in our own variables, it does not guarantee the JS engine's memory is
 * actually cleared.
 */
export function wipe(bytes: number[]): void {
  bytes.fill(0);
}

/**
 * A gap this much larger than the polling interval can only happen if the
 * OS actually suspended the process (sleep/hibernate) -- ordinary timer
 * jitter or a minimized/backgrounded window clamps JS timers to at most a
 * few seconds, never tens of seconds.
 *
 * This is a heuristic, not a real "session locked" or "system suspended"
 * event: detecting those directly would mean hooking the raw Win32 message
 * loop (WM_WTSSESSION_CHANGE / WM_POWERBROADCAST) from native code, which
 * Tauri does not expose. This catches the sleep/hibernate case the
 * inactivity timer alone misses -- a laptop closed mid-session stays
 * "unlocked" until the configured delay elapses after it's reopened, even
 * though real time has moved on much further than that -- without needing
 * any native Windows integration.
 */
export const SUSPEND_GAP_THRESHOLD_MS = 60_000;

export function wasLikelySuspended(elapsedMs: number): boolean {
  return elapsedMs > SUSPEND_GAP_THRESHOLD_MS;
}

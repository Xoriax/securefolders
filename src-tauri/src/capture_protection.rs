use tauri::{AppHandle, Manager, WebviewWindow};
use windows::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE};

use crate::state::AppState;

const MAIN_WINDOW_LABEL: &str = "main";

/// Excludes (or restores) the main window from screen capture: screenshot
/// tools, screen recorders, and remote-desktop/screen-sharing sessions show
/// it blacked out or skip it entirely, while it stays fully visible to the
/// user on their own physical screen. Best-effort like the other memory/OS
/// mitigations — a failure here is logged and otherwise ignored rather than
/// blocking lock/unlock.
fn set_excluded_from_capture(window: &WebviewWindow, excluded: bool) {
    let Ok(hwnd) = window.hwnd() else {
        log::warn!("impossible d'obtenir le handle de fenetre pour la protection anti-capture");
        return;
    };
    let affinity = if excluded { WDA_EXCLUDEFROMCAPTURE } else { WDA_NONE };
    if let Err(e) = unsafe { SetWindowDisplayAffinity(hwnd, affinity) } {
        log::warn!("SetWindowDisplayAffinity a echoue: {e}");
    }
}

/// Re-applies the capture exclusion to match the current session state:
/// excluded as soon as at least one vault is unlocked, restored the moment
/// every vault is locked again (manually, by auto-lock, or by the sleep
/// detector). Called after every command that can change that state, since
/// there is no single choke point all of them already go through.
pub fn sync(app: &AppHandle, state: &AppState) {
    let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) else {
        return;
    };
    set_excluded_from_capture(&window, state.any_session_open());
}

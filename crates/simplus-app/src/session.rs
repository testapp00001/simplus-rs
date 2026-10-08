//! Detects whether the user's desktop session is locked (Win+L), so the vault can lock too.

/// `true` while the Windows session is locked. Always `false` on other platforms.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn is_session_locked() -> bool {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTS_SESSIONSTATE_LOCK, WTSFreeMemory, WTSINFOEXW,
        WTSQuerySessionInformationW, WTSSessionInfoEx,
    };

    let mut buffer: windows_sys::core::PWSTR = std::ptr::null_mut();
    let mut bytes: u32 = 0;
    // SAFETY: WTSQuerySessionInformationW allocates `buffer` and reports its size in `bytes`;
    // we only read it when the call succeeded and the buffer is large enough, then free it with
    // WTSFreeMemory as the API requires.
    unsafe {
        if WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buffer,
            &mut bytes,
        ) == 0
            || buffer.is_null()
        {
            return false;
        }
        let locked = if bytes as usize >= std::mem::size_of::<WTSINFOEXW>() {
            let info = &*(buffer as *const WTSINFOEXW);
            info.Level == 1 && info.Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_LOCK as i32
        } else {
            false
        };
        WTSFreeMemory(buffer.cast());
        locked
    }
}

#[cfg(not(windows))]
pub fn is_session_locked() -> bool {
    false
}

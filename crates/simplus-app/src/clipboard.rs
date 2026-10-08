//! Clipboard access for secrets: excluded from Windows clipboard history/cloud sync and
//! cleared automatically after a delay, but only if it still holds what we copied.

use std::cell::RefCell;
use std::time::Duration;

use sha2::{Digest, Sha256};

fn digest(text: &str) -> Vec<u8> {
    Sha256::digest(text.as_bytes()).to_vec()
}

#[derive(Default)]
pub struct SecretClipboard {
    // Kept alive: on Linux the copied text is served by this clipboard instance.
    inner: RefCell<Option<arboard::Clipboard>>,
}

impl SecretClipboard {
    /// Copies `text`. With `clear_after`, the text is treated as a secret.
    pub fn copy(&self, text: &str, clear_after: Option<Duration>) -> anyhow::Result<()> {
        let mut slot = self.inner.borrow_mut();
        if slot.is_none() {
            *slot = Some(arboard::Clipboard::new()?);
        }
        let clipboard = slot.as_mut().expect("initialised above");
        set_text(clipboard, text, clear_after.is_some())?;

        if let Some(delay) = clear_after.filter(|d| !d.is_zero()) {
            // Only a hash crosses into the timer thread, never the secret itself.
            let expected = digest(text);
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                if let Ok(mut clipboard) = arboard::Clipboard::new()
                    && clipboard.get_text().is_ok_and(|current| digest(&current) == expected)
                {
                    let _ = clipboard.clear();
                }
            });
        }
        Ok(())
    }
}

#[cfg(windows)]
fn set_text(clipboard: &mut arboard::Clipboard, text: &str, secret: bool) -> Result<(), arboard::Error> {
    use arboard::SetExtWindows as _;
    if secret {
        clipboard.set().exclude_from_history().exclude_from_cloud().text(text)
    } else {
        clipboard.set_text(text)
    }
}

#[cfg(not(windows))]
fn set_text(clipboard: &mut arboard::Clipboard, text: &str, _secret: bool) -> Result<(), arboard::Error> {
    clipboard.set_text(text)
}

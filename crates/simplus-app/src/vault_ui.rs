//! Connects the `VaultState` Slint global to [`simplus_vault_core::Vault`].
//!
//! Fast operations (listing, saving, notes) run on the UI thread. Argon2id work (create,
//! unlock, password changes, recovery, backups) runs on a background thread and reports back
//! through the Slint event loop, so the window never freezes.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local, Utc};
use simplus_vault_core::generator::{self, PassphraseOptions, PasswordOptions};
use simplus_vault_core::import_export::{self, ImportSummary};
use simplus_vault_core::totp::Totp;
use simplus_vault_core::{CustomField, KdfParams, Record, RecoveryKey, SecureNote, Vault, VaultError};
use simplus_vault_sync::{self as vsync, Account, LoginChange, SyncError, SyncReport, VaultAccess as _};
use slint::{ComponentHandle as _, Model as _, ModelRc, SharedString, Timer, TimerMode, VecModel};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::clipboard::SecretClipboard;
use crate::{
    AppSettings, DeviceRow, FieldRow, GeneratorOptions, HistoryRow, MainWindow, NoteRow, RecordDetail,
    RecordRow, Strength, VaultPanel, VaultScreen, VaultState,
};

/// Minimum length enforced for new vault passwords.
const MIN_PASSWORD_LEN: usize = 8;
/// Secure notes re-lock after this much inactivity (or sooner if the vault auto-lock is shorter).
const NOTES_IDLE_LIMIT: Duration = Duration::from_secs(120);
const STATUS_DURATION: Duration = Duration::from_secs(4);
/// Delay between a local change and the automatic sync that uploads it.
const SYNC_DEBOUNCE: Duration = Duration::from_secs(3);
/// Background sync interval while the vault is unlocked.
const SYNC_INTERVAL: Duration = Duration::from_secs(300);

thread_local! {
    static CONTROLLER: RefCell<Option<Rc<VaultController>>> = const { RefCell::new(None) };
}

fn with_controller(f: impl FnOnce(&Rc<VaultController>)) {
    let controller = CONTROLLER.with(|c| c.borrow().clone());
    if let Some(controller) = controller {
        f(&controller);
    }
}

type Secret = Zeroizing<String>;

fn secret(s: &SharedString) -> Secret {
    Zeroizing::new(s.to_string())
}

pub struct VaultController {
    ui: slint::Weak<MainWindow>,
    path: PathBuf,
    vault: Arc<Mutex<Option<Vault>>>,
    records: RefCell<Vec<Record>>,
    search: RefCell<String>,
    totp: RefCell<Option<Totp>>,
    last_activity: RefCell<Instant>,
    rows: Rc<VecModel<RecordRow>>,
    notes: Rc<VecModel<NoteRow>>,
    fields: Rc<VecModel<FieldRow>>,
    clipboard: SecretClipboard,
    status_timer: Timer,
    sync_timer: Timer,
    timers: RefCell<Vec<Timer>>,
}

/// Builds a callback closure that records user activity before running `$body`.
macro_rules! handler {
    ($c:expr, |$this:ident $(, $arg:ident)*| $body:expr) => {{
        let $this = $c.clone();
        move |$($arg),*| {
            $this.touch();
            $body
        }
    }};
}

impl VaultController {
    pub fn install(ui: &MainWindow, path: PathBuf) -> Rc<Self> {
        let controller = Rc::new(Self {
            ui: ui.as_weak(),
            path,
            vault: Arc::default(),
            records: RefCell::default(),
            search: RefCell::default(),
            totp: RefCell::default(),
            last_activity: RefCell::new(Instant::now()),
            rows: Rc::new(VecModel::default()),
            notes: Rc::new(VecModel::default()),
            fields: Rc::new(VecModel::default()),
            clipboard: SecretClipboard::default(),
            status_timer: Timer::default(),
            sync_timer: Timer::default(),
            timers: RefCell::default(),
        });
        let state = ui.global::<VaultState<'_>>();
        state.set_records(ModelRc::from(controller.rows.clone()));
        state.set_notes(ModelRc::from(controller.notes.clone()));
        state.set_edit_fields(ModelRc::from(controller.fields.clone()));
        state.set_default_device_name(default_device_name().into());

        controller.connect(&state);
        controller.start_timers();
        controller.open_existing();
        CONTROLLER.with(|c| *c.borrow_mut() = Some(controller.clone()));
        controller
    }

    fn connect(self: &Rc<Self>, state: &VaultState<'_>) {
        state.on_activity(handler!(self, |_c| ()));

        state.on_create_vault(handler!(self, |c, a, b, x, y| c.create_vault(
            secret(&a),
            secret(&b),
            secret(&x),
            secret(&y)
        )));
        state.on_recovery_kit_done(handler!(self, |c| c.recovery_kit_done()));
        state.on_copy_recovery_key(handler!(self, |c| c.copy_recovery_key()));
        state.on_save_recovery_key(handler!(self, |c| c.save_recovery_key()));
        state.on_unlock(handler!(self, |c, pw| c.unlock(secret(&pw))));
        state.on_show_recover(handler!(self, |c| c.show_screen(VaultScreen::Recover)));
        state.on_cancel_recover(handler!(self, |c| c.show_screen(VaultScreen::Locked)));
        state.on_recover(handler!(self, |c, key, a, b, x, y| c.recover(
            secret(&key),
            secret(&a),
            secret(&b),
            secret(&x),
            secret(&y)
        )));
        state.on_lock(handler!(self, |c| c.lock(None)));

        state.on_search(handler!(self, |c, text| {
            *c.search.borrow_mut() = text.to_string();
            c.apply_filter();
        }));
        state.on_set_favorites_only(handler!(self, |c, on| {
            c.with_state(|s| s.set_favorites_only(on));
            c.apply_filter();
        }));
        state.on_select_record(handler!(self, |c, id| c.select_record(&id)));
        state.on_new_record(handler!(self, |c| c.new_record()));
        state.on_edit_record(handler!(self, |c| c.edit_record()));
        state.on_cancel_edit(handler!(self, |c| c.with_state(|s| {
            s.set_error(SharedString::new());
            s.set_panel(VaultPanel::Detail);
        })));
        state.on_save_record(handler!(self, |c, detail| c.save_record(&detail)));
        state.on_delete_record(handler!(self, |c, id| c.delete_record(&id)));
        state.on_toggle_favorite(handler!(self, |c, id| c.toggle_favorite(&id)));
        state.on_copy(handler!(self, |c, value, is_secret| c.copy(&value, is_secret)));
        state.on_copy_totp(handler!(self, |c| {
            let code = c.totp.borrow().as_ref().map(|t| t.current().code);
            if let Some(code) = code {
                c.copy(&code, true);
            }
        }));
        state.on_add_field(handler!(self, |c| c.fields.push(FieldRow::default())));
        state.on_remove_field(handler!(self, |c, index| {
            if (index as usize) < c.fields.row_count() {
                c.fields.remove(index as usize);
            }
        }));
        state.on_update_field(handler!(self, |c, index, row| {
            if (index as usize) < c.fields.row_count() {
                c.fields.set_row_data(index as usize, row);
            }
        }));
        state.on_strength(|password| strength(&password));
        let c = self.clone();
        state.on_generate(move |options| c.generate(&options));

        state.on_unlock_notes(handler!(self, |c, pw| c.unlock_notes(secret(&pw))));
        state.on_lock_notes(handler!(self, |c| c.lock_notes(None)));
        state.on_save_note(handler!(self, |c, note| c.save_note(&note)));
        state.on_delete_note(handler!(self, |c, id| c.delete_note(&id)));

        state.on_open_settings(handler!(self, |c| c.with_state(|s| {
            s.set_error(SharedString::new());
            s.set_panel(VaultPanel::Settings);
        })));
        state.on_close_settings(handler!(self, |c| c.with_state(|s| {
            s.set_error(SharedString::new());
            s.set_panel(VaultPanel::Detail);
        })));
        state.on_change_master_password(handler!(self, |c, cur, new, confirm| c.change_password(
            false,
            secret(&cur),
            secret(&new),
            secret(&confirm)
        )));
        state.on_change_notes_password(handler!(self, |c, cur, new, confirm| c.change_password(
            true,
            secret(&cur),
            secret(&new),
            secret(&confirm)
        )));
        state.on_rotate_recovery_key(handler!(self, |c| c.rotate_recovery_key()));
        state.on_import_file(handler!(self, |c| c.import_file()));
        state.on_restore_backup(handler!(self, |c, pw| c.restore_backup(secret(&pw))));
        state.on_export_backup(handler!(self, |c, pw, confirm| c.export_backup(secret(&pw), secret(&confirm))));
        state.on_export_csv(handler!(self, |c| c.export_csv()));

        state.on_sync_setup(handler!(self, |c, url, email, device, password, invite, create| c.sync_setup(
            url.to_string(),
            email.to_string(),
            device.to_string(),
            secret(&password),
            invite.to_string(),
            create
        )));
        state.on_sync_now(handler!(self, |c| c.sync_now()));
        state.on_sync_sign_in_again(handler!(self, |c, password| c.sync_sign_in_again(secret(&password))));
        state
            .on_sync_finish_recovery(handler!(self, |c, password| c.sync_finish_recovery(secret(&password))));
        state.on_sync_sign_out(handler!(self, |c| c.sync_sign_out()));
        state.on_sync_load_devices(handler!(self, |c| c.sync_load_devices()));
        state.on_sync_revoke_device(handler!(self, |c, id| c.sync_revoke_device(&id)));
        state.on_show_download(handler!(self, |c| c.show_screen(VaultScreen::Download)));
        state.on_cancel_download(handler!(self, |c| c.show_screen(VaultScreen::Create)));
        state.on_download_vault(handler!(self, |c, url, email, device, password| c.download_vault(
            url.to_string(),
            email.to_string(),
            device.to_string(),
            secret(&password)
        )));
    }

    fn start_timers(self: &Rc<Self>) {
        let totp_timer = Timer::default();
        let c = self.clone();
        totp_timer.start(TimerMode::Repeated, Duration::from_secs(1), move || c.refresh_totp());

        let lock_timer = Timer::default();
        let c = self.clone();
        lock_timer.start(TimerMode::Repeated, Duration::from_secs(3), move || c.check_auto_lock());

        let sync_timer = Timer::default();
        let c = self.clone();
        sync_timer.start(TimerMode::Repeated, SYNC_INTERVAL, move || c.sync_now());

        self.timers.borrow_mut().extend([totp_timer, lock_timer, sync_timer]);
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    fn with_state(&self, f: impl FnOnce(&VaultState<'_>)) {
        if let Some(ui) = self.ui.upgrade() {
            f(&ui.global::<VaultState<'_>>());
        }
    }

    fn settings(&self) -> (i32, i32) {
        self.ui.upgrade().map_or((5, 30), |ui| {
            let s = ui.global::<AppSettings<'_>>();
            (s.get_auto_lock_minutes(), s.get_clipboard_clear_seconds())
        })
    }

    fn touch(&self) {
        *self.last_activity.borrow_mut() = Instant::now();
    }

    fn vault(&self) -> MutexGuard<'_, Option<Vault>> {
        self.vault.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` on the open vault, turning errors into a status message.
    fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> Result<T, VaultError>) -> Option<T> {
        let result = match self.vault().as_mut() {
            Some(vault) => f(vault),
            None => Err(VaultError::NotFound),
        };
        result.map_err(|e| self.status(&describe(&e), true)).ok()
    }

    fn status(&self, message: &str, is_error: bool) {
        self.with_state(|s| {
            s.set_status(message.into());
            s.set_status_is_error(is_error);
        });
        let ui = self.ui.clone();
        self.status_timer.start(TimerMode::SingleShot, STATUS_DURATION, move || {
            if let Some(ui) = ui.upgrade() {
                ui.global::<VaultState<'_>>().set_status(SharedString::new());
            }
        });
    }

    fn error(&self, message: &str) {
        self.with_state(|s| s.set_error(message.into()));
    }

    fn show_screen(&self, screen: VaultScreen) {
        self.with_state(|s| {
            s.set_error(SharedString::new());
            s.set_screen(screen);
        });
    }

    /// Runs slow vault work off the UI thread; `done` runs back on the UI thread.
    fn background<T, W, D>(&self, work: W, done: D)
    where
        T: Send + 'static,
        W: FnOnce(&mut Option<Vault>) -> T + Send + 'static,
        D: FnOnce(&Rc<VaultController>, T) + Send + 'static,
    {
        self.with_state(|s| {
            s.set_busy(true);
            s.set_error(SharedString::new());
        });
        let vault = self.vault.clone();
        std::thread::spawn(move || {
            let result = {
                let mut guard = vault.lock().unwrap_or_else(|e| e.into_inner());
                work(&mut guard)
            };
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(|c| {
                    c.with_state(|s| s.set_busy(false));
                    done(c, result);
                })
            });
        });
    }

    fn validate_new_password(&self, password: &str, confirm: &str, what: &str) -> bool {
        let message = if password != confirm {
            format!("The {what} passwords do not match.")
        } else if password.chars().count() < MIN_PASSWORD_LEN {
            format!("The {what} password must have at least {MIN_PASSWORD_LEN} characters.")
        } else {
            return true;
        };
        self.error(&message);
        false
    }

    // ---------------------------------------------------------------------------------------
    // Setup, unlock and recovery
    // ---------------------------------------------------------------------------------------

    fn open_existing(&self) {
        if !Vault::exists(&self.path) {
            self.show_screen(VaultScreen::Create);
            return;
        }
        match Vault::open(&self.path) {
            Ok(vault) => *self.vault() = Some(vault),
            Err(e) => self.error(&format!("Cannot open the vault at {}: {e}", self.path.display())),
        }
        self.with_state(|s| s.set_screen(VaultScreen::Locked));
    }

    fn create_vault(&self, master: Secret, master_confirm: Secret, notes: Secret, notes_confirm: Secret) {
        if !self.validate_new_password(&master, &master_confirm, "master")
            || !self.validate_new_password(&notes, &notes_confirm, "secure notes")
        {
            return;
        }
        if *master == *notes {
            self.error("The secure notes password must be different from the master password.");
            return;
        }
        let path = self.path.clone();
        self.background(
            move |slot| {
                let (vault, recovery) = Vault::create(&path, &master, &notes, KdfParams::RECOMMENDED)?;
                *slot = Some(vault);
                Ok::<_, VaultError>(recovery.display())
            },
            |c, result| match result {
                Ok(key) => c.with_state(|s| {
                    s.set_recovery_key(key.as_str().into());
                    s.set_recovery_key_is_new_vault(true);
                    s.set_screen(VaultScreen::RecoveryKit);
                }),
                Err(e) => c.error(&describe(&e)),
            },
        );
    }

    fn recovery_kit_done(&self) {
        let mut new_vault = true;
        self.with_state(|s| {
            new_vault = s.get_recovery_key_is_new_vault();
            s.set_recovery_key(SharedString::new());
            s.set_screen(VaultScreen::Unlocked);
            s.set_panel(if new_vault { VaultPanel::Detail } else { VaultPanel::Settings });
        });
        if new_vault {
            self.refresh_records();
        }
    }

    fn recovery_key_text(&self) -> Secret {
        let mut key = Secret::default();
        self.with_state(|s| key = Zeroizing::new(s.get_recovery_key().to_string()));
        key
    }

    fn copy_recovery_key(&self) {
        let key = self.recovery_key_text();
        self.copy(&key, true);
    }

    fn save_recovery_key(&self) {
        let key = self.recovery_key_text();
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save recovery key")
            .set_file_name("simplus-recovery-key.txt")
            .add_filter("Text", &["txt"])
            .save_file()
        else {
            return;
        };
        let contents = Zeroizing::new(format!(
            "SIMPLUS PASSWORD VAULT - RECOVERY KEY\n\
             Created: {}\n\n\
             {}\n\n\
             This key resets both the master password and the secure notes password.\n\
             Keep it offline and private. Anyone with this key and your vault file can read it.\n",
            Local::now().format("%Y-%m-%d %H:%M"),
            key.as_str()
        ));
        match std::fs::write(&path, contents.as_bytes()) {
            Ok(()) => self.status(&format!("Recovery key saved to {}", path.display()), false),
            Err(e) => self.status(&format!("Could not save the file: {e}"), true),
        }
    }

    fn unlock(&self, password: Secret) {
        if password.is_empty() {
            return;
        }
        self.background(
            move |slot| match slot.as_mut() {
                Some(vault) => vault.unlock(&password),
                None => Err(VaultError::NotFound),
            },
            |c, result| match result {
                Ok(()) => {
                    c.with_state(|s| {
                        s.set_screen(VaultScreen::Unlocked);
                        s.set_panel(VaultPanel::Detail);
                    });
                    c.refresh_records();
                    c.refresh_sync_state();
                    c.sync_now();
                }
                Err(e) => c.error(&describe(&e)),
            },
        );
    }

    fn recover(
        &self,
        key: Secret,
        master: Secret,
        master_confirm: Secret,
        notes: Secret,
        notes_confirm: Secret,
    ) {
        let recovery_key = match RecoveryKey::parse(&key) {
            Ok(k) => k,
            Err(e) => return self.error(&describe(&e)),
        };
        if !self.validate_new_password(&master, &master_confirm, "master")
            || !self.validate_new_password(&notes, &notes_confirm, "secure notes")
        {
            return;
        }
        let path = self.path.clone();
        self.sync_job(
            true,
            move |slot| {
                let vault = Vault::recover(&path, &recovery_key, &master, &notes)?;
                let synced = vault.is_sync_enabled()?;
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(vault);
                if !synced {
                    return Ok(None);
                }
                // Reset the server login too; if the server is unreachable, remember to do it later.
                match vsync::recover_account(slot, &master) {
                    Ok(()) => Ok(None),
                    Err(e) => {
                        slot.with_vault(|v| Ok(v.set_recovery_pending(true)?))?;
                        Ok(Some(e))
                    }
                }
            },
            |c, result| match result {
                Ok(server_error) => {
                    c.with_state(|s| {
                        s.set_screen(VaultScreen::Unlocked);
                        s.set_panel(VaultPanel::Detail);
                    });
                    c.refresh_records();
                    c.refresh_sync_state();
                    match server_error {
                        None => {
                            c.status("Passwords reset. Consider creating a new recovery key in Vault settings.", false);
                            c.sync_now();
                        }
                        Some(e) => c.status(
                            &format!("Passwords reset here, but the sync server could not be updated ({e}). Finish it in Vault settings."),
                            true,
                        ),
                    }
                }
                Err(e) => c.error(&sync_message(&e)),
            },
        );
    }

    /// Locks the vault and wipes every decrypted value from the UI.
    fn lock(&self, reason: Option<&str>) {
        if let Some(vault) = self.vault().as_mut() {
            vault.lock();
        }
        self.records.borrow_mut().clear();
        *self.totp.borrow_mut() = None;
        self.rows.set_vec(Vec::new());
        self.notes.set_vec(Vec::new());
        self.fields.set_vec(Vec::new());
        self.with_state(|s| {
            s.set_detail(RecordDetail::default());
            s.set_selected_id(SharedString::new());
            s.set_notes_unlocked(false);
            s.set_editing_note_id(SharedString::new());
            s.set_totp_code(SharedString::new());
            s.set_record_total(0);
            s.set_panel(VaultPanel::Detail);
            s.set_error(SharedString::new());
            s.set_screen(VaultScreen::Locked);
        });
        if let Some(reason) = reason {
            self.status(reason, false);
        }
    }

    fn check_auto_lock(&self) {
        let mut unlocked = false;
        let mut notes_unlocked = false;
        let mut busy = false;
        self.with_state(|s| {
            unlocked = s.get_screen() == VaultScreen::Unlocked;
            notes_unlocked = s.get_notes_unlocked();
            busy = s.get_busy();
        });
        if !unlocked || busy {
            return;
        }
        if crate::session::is_session_locked() {
            self.lock(Some("Vault locked because the computer was locked."));
            return;
        }
        let (minutes, _) = self.settings();
        if minutes <= 0 {
            return;
        }
        let idle = self.last_activity.borrow().elapsed();
        let limit = Duration::from_secs(minutes as u64 * 60);
        if idle >= limit {
            self.lock(Some("Vault locked after inactivity."));
        } else if notes_unlocked && idle >= limit.min(NOTES_IDLE_LIMIT) {
            self.lock_notes(Some("Secure notes locked after inactivity."));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Records
    // ---------------------------------------------------------------------------------------

    fn refresh_records(&self) {
        let records = self.with_vault(|v| v.list_records()).unwrap_or_default();
        *self.records.borrow_mut() = records;
        self.apply_filter();
    }

    fn apply_filter(&self) {
        let mut favorites_only = false;
        self.with_state(|s| favorites_only = s.get_favorites_only());
        let query = self.search.borrow().clone();
        let records = self.records.borrow();
        let rows: Vec<RecordRow> = records
            .iter()
            .filter(|r| r.matches(&query) && (!favorites_only || r.favorite))
            .map(record_row)
            .collect();
        self.rows.set_vec(rows);
        self.with_state(|s| s.set_record_total(records.len() as i32));
    }

    fn find_record(&self, id: &str) -> Option<Record> {
        let id = Uuid::parse_str(id).ok()?;
        self.records.borrow().iter().find(|r| r.id == id).cloned()
    }

    fn select_record(&self, id: &str) {
        let Some(record) = self.find_record(id) else { return };
        self.with_state(|s| {
            s.set_selected_id(id.into());
            s.set_panel(VaultPanel::Detail);
            s.set_error(SharedString::new());
        });
        self.show_detail(&record);
    }

    fn show_detail(&self, record: &Record) {
        let totp = record.totp.as_deref().filter(|t| !t.is_empty()).map(Totp::parse);
        let totp_error = match &totp {
            Some(Err(e)) => e.to_string(),
            _ => String::new(),
        };
        *self.totp.borrow_mut() = totp.and_then(Result::ok);
        let note_count = self.with_vault(|v| v.note_count(record.id)).unwrap_or(0);
        self.with_state(|s| {
            s.set_detail(record_detail(record));
            s.set_totp_error(totp_error.into());
            s.set_note_count(note_count as i32);
            s.set_editing_note_id(SharedString::new());
        });
        self.refresh_totp();
        self.load_notes();
    }

    fn refresh_totp(&self) {
        let code = self.totp.borrow().as_ref().map(Totp::current);
        if let Some(code) = code {
            self.with_state(|s| {
                s.set_totp_code(format_code(&code.code).into());
                s.set_totp_remaining(code.remaining_secs as i32);
                s.set_totp_period(code.period as i32);
            });
        }
    }

    fn new_record(&self) {
        *self.totp.borrow_mut() = None;
        self.fields.set_vec(Vec::new());
        self.with_state(|s| {
            s.set_selected_id(SharedString::new());
            s.set_detail(RecordDetail::default());
            s.set_error(SharedString::new());
            s.set_panel(VaultPanel::Edit);
        });
    }

    fn edit_record(&self) {
        self.with_state(|s| {
            let fields: Vec<FieldRow> = s.get_detail().fields.iter().collect();
            self.fields.set_vec(fields);
            s.set_error(SharedString::new());
            s.set_panel(VaultPanel::Edit);
        });
    }

    fn save_record(&self, detail: &RecordDetail) {
        let mut record = if detail.id.is_empty() {
            Record::new("")
        } else {
            match self.find_record(&detail.id) {
                Some(r) => r,
                None => return self.error("This item no longer exists."),
            }
        };
        let fields: Vec<FieldRow> = self.fields.iter().collect();
        if let Err(message) = apply_detail(&mut record, detail, &fields) {
            return self.error(&message);
        }
        match self.vault().as_mut().map(|v| v.save_record(&mut record)) {
            Some(Ok(())) => {}
            Some(Err(e)) => return self.error(&describe(&e)),
            None => return self.error("The vault is not open."),
        }
        self.refresh_records();
        self.select_record(&record.id.to_string());
        self.status("Saved.", false);
        self.schedule_sync();
    }

    fn delete_record(&self, id: &str) {
        let Ok(uuid) = Uuid::parse_str(id) else { return };
        if self.with_vault(|v| v.delete_record(uuid)).is_some() {
            *self.totp.borrow_mut() = None;
            self.with_state(|s| {
                s.set_selected_id(SharedString::new());
                s.set_detail(RecordDetail::default());
            });
            self.refresh_records();
            self.status("Item deleted.", false);
            self.schedule_sync();
        }
    }

    fn toggle_favorite(&self, id: &str) {
        let Some(mut record) = self.find_record(id) else { return };
        record.favorite = !record.favorite;
        if self.with_vault(|v| v.save_record(&mut record)).is_some() {
            self.refresh_records();
            self.select_record(id);
            self.schedule_sync();
        }
    }

    fn copy(&self, value: &str, is_secret: bool) {
        if value.is_empty() {
            return;
        }
        let (_, clear_secs) = self.settings();
        let clear_after = (is_secret && clear_secs > 0).then(|| Duration::from_secs(clear_secs as u64));
        match self.clipboard.copy(value, clear_after) {
            Ok(()) if clear_after.is_some() => {
                self.status(&format!("Copied. The clipboard will be cleared in {clear_secs} s."), false)
            }
            Ok(()) => self.status("Copied.", false),
            Err(e) => self.status(&format!("Could not access the clipboard: {e}"), true),
        }
    }

    fn generate(&self, options: &GeneratorOptions) -> SharedString {
        let result = if options.passphrase {
            generator::generate_passphrase(&PassphraseOptions {
                words: options.words.max(0) as usize,
                separator: options.separator.to_string(),
                capitalize: options.capitalize,
                include_number: options.include_number,
            })
        } else {
            generator::generate_password(&PasswordOptions {
                length: options.length.max(0) as usize,
                lowercase: options.lowercase,
                uppercase: options.uppercase,
                digits: options.digits,
                symbols: options.symbols,
                exclude_ambiguous: options.exclude_ambiguous,
            })
        };
        match result {
            Ok(value) => value.as_str().into(),
            Err(e) => {
                self.status(&e.to_string(), true);
                SharedString::new()
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Secure notes
    // ---------------------------------------------------------------------------------------

    fn selected_record_id(&self) -> Option<Uuid> {
        let mut id = SharedString::new();
        self.with_state(|s| id = s.get_selected_id());
        Uuid::parse_str(&id).ok()
    }

    fn unlock_notes(&self, password: Secret) {
        if password.is_empty() {
            return;
        }
        self.background(
            move |slot| match slot.as_mut() {
                Some(vault) => vault.unlock_notes(&password),
                None => Err(VaultError::NotFound),
            },
            |c, result| match result {
                Ok(()) => {
                    c.with_state(|s| s.set_notes_unlocked(true));
                    c.load_notes();
                }
                Err(e) => c.error(&describe(&e)),
            },
        );
    }

    fn lock_notes(&self, reason: Option<&str>) {
        if let Some(vault) = self.vault().as_mut() {
            vault.lock_notes();
        }
        self.notes.set_vec(Vec::new());
        self.with_state(|s| {
            s.set_notes_unlocked(false);
            s.set_editing_note_id(SharedString::new());
        });
        if let Some(reason) = reason {
            self.status(reason, false);
        }
    }

    fn load_notes(&self) {
        let Some(record_id) = self.selected_record_id() else {
            self.notes.set_vec(Vec::new());
            return;
        };
        let unlocked = self.vault().as_ref().is_some_and(Vault::notes_unlocked);
        if !unlocked {
            self.notes.set_vec(Vec::new());
            return;
        }
        let notes = self.with_vault(|v| v.list_notes(record_id)).unwrap_or_default();
        let count = notes.len();
        self.notes.set_vec(notes.iter().map(note_row).collect::<Vec<_>>());
        self.with_state(|s| s.set_note_count(count as i32));
    }

    fn save_note(&self, row: &NoteRow) {
        let Some(record_id) = self.selected_record_id() else { return };
        let title = match row.title.trim() {
            "" => "Note".to_owned(),
            t => t.to_owned(),
        };
        let result = self.with_vault(|v| {
            let mut note = match Uuid::parse_str(&row.id) {
                Ok(id) => v
                    .list_notes(record_id)?
                    .into_iter()
                    .find(|n| n.id == id)
                    .ok_or(VaultError::ItemNotFound(id))?,
                Err(_) => SecureNote::new(record_id, "", ""),
            };
            note.title = title;
            note.body = row.body.to_string();
            v.save_note(&mut note)
        });
        if result.is_some() {
            self.with_state(|s| s.set_editing_note_id(SharedString::new()));
            self.load_notes();
            self.status("Note saved.", false);
            self.schedule_sync();
        }
    }

    fn delete_note(&self, id: &str) {
        let Ok(uuid) = Uuid::parse_str(id) else { return };
        if self.with_vault(|v| v.delete_note(uuid)).is_some() {
            self.load_notes();
            self.status("Note deleted.", false);
            self.schedule_sync();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Vault settings
    // ---------------------------------------------------------------------------------------

    fn change_password(&self, notes: bool, current: Secret, new: Secret, confirm: Secret) {
        let what = if notes { "secure notes" } else { "master" };
        if !self.validate_new_password(&new, &confirm, what) {
            return;
        }
        self.sync_job(
            true,
            move |slot| {
                with_published_keys(slot, |v| {
                    if notes {
                        v.change_notes_password(&current, &new)?;
                        return Ok((None, ()));
                    }
                    // A synced vault also moves its server login to the new password.
                    let current_auth = v.is_sync_enabled()?.then(|| v.auth_key(&current)).transpose()?;
                    v.change_master_password(&current, &new)?;
                    let login = match current_auth {
                        Some(current) => Some(LoginChange {
                            current_auth_key: Zeroizing::new(current.expose().to_vec()),
                            new_auth_key: Zeroizing::new(v.auth_key(&new)?.expose().to_vec()),
                        }),
                        None => None,
                    };
                    Ok((login, ()))
                })
            },
            move |c, result| match result {
                Ok(()) => c.status(&format!("The {what} password was changed."), false),
                Err(e) => c.error(&sync_message(&e)),
            },
        );
    }

    fn rotate_recovery_key(&self) {
        self.sync_job(
            true,
            |slot| with_published_keys(slot, |v| Ok((None, v.rotate_recovery_key()?.display()))),
            |c, result| match result {
                Ok(key) => c.with_state(|s| {
                    s.set_recovery_key(key.as_str().into());
                    s.set_recovery_key_is_new_vault(false);
                    s.set_screen(VaultScreen::RecoveryKit);
                }),
                Err(e) => c.error(&sync_message(&e)),
            },
        );
    }

    fn report_import(&self, summary: ImportSummary, skipped: usize) {
        self.refresh_records();
        let mut message =
            format!("Imported {} item(s) and {} secure note(s).", summary.records, summary.notes);
        if skipped > 0 {
            message.push_str(&format!(" {skipped} entry(ies) could not be imported."));
        }
        self.status(&message, false);
        self.schedule_sync();
    }

    fn import_file(&self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Import passwords")
            .add_filter("Password exports", &["csv", "json"])
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return;
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => Zeroizing::new(text),
            Err(e) => return self.error(&format!("Cannot read {}: {e}", path.display())),
        };
        let parsed = match import_export::parse_auto(&text) {
            Ok(parsed) => parsed,
            Err(e) => return self.error(&describe(&e)),
        };
        let skipped = parsed.skipped;
        match self.vault().as_mut().map(|v| v.import(parsed)) {
            Some(Ok(summary)) => {
                self.error("");
                self.report_import(summary, skipped);
            }
            Some(Err(e)) => self.error(&describe(&e)),
            None => self.error("The vault is not open."),
        }
    }

    fn restore_backup(&self, password: Secret) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Restore Simplus backup")
            .add_filter("Simplus backup", &["simplusvault"])
            .pick_file()
        else {
            return;
        };
        self.background(
            move |slot| -> Result<(ImportSummary, usize), VaultError> {
                let text = Zeroizing::new(std::fs::read_to_string(&path)?);
                let parsed = import_export::read_encrypted_backup(&text, &password)?;
                let vault = slot.as_mut().ok_or(VaultError::NotFound)?;
                Ok((vault.import(parsed)?, 0))
            },
            |c, result| match result {
                Ok((summary, skipped)) => c.report_import(summary, skipped),
                Err(VaultError::WrongPassword) => c.error("Wrong backup password."),
                Err(e) => c.error(&describe(&e)),
            },
        );
    }

    fn export_backup(&self, password: Secret, confirm: Secret) {
        if *password != *confirm {
            return self.error("The backup passwords do not match.");
        }
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export encrypted backup")
            .set_file_name(format!("simplus-backup-{}.simplusvault", Local::now().format("%Y%m%d")))
            .add_filter("Simplus backup", &["simplusvault"])
            .save_file()
        else {
            return;
        };
        self.background(
            move |slot| -> Result<PathBuf, VaultError> {
                let vault = slot.as_ref().ok_or(VaultError::NotFound)?;
                let backup = vault.export_encrypted(&password, vault.kdf_params())?;
                std::fs::write(&path, backup)?;
                Ok(path)
            },
            |c, result| match result {
                Ok(path) => c.status(&format!("Backup saved to {}", path.display()), false),
                Err(e) => c.error(&describe(&e)),
            },
        );
    }

    fn export_csv(&self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export unencrypted CSV")
            .set_file_name("simplus-export.csv")
            .add_filter("CSV", &["csv"])
            .save_file()
        else {
            return;
        };
        let Some(csv) = self.with_vault(|v| v.export_csv()) else { return };
        match std::fs::write(&path, csv.as_bytes()) {
            Ok(()) => self.status("CSV exported. Delete the file once you no longer need it.", false),
            Err(e) => self.error(&format!("Cannot write {}: {e}", path.display())),
        }
    }
}

impl VaultController {
    // ---------------------------------------------------------------------------------------
    // Sync
    // ---------------------------------------------------------------------------------------

    /// Runs sync work on a background thread. The work receives the shared vault and locks it
    /// only for local steps, so the UI stays responsive during network calls. With
    /// `blocking`, forms show their busy state while it runs.
    fn sync_job<T, W, D>(&self, blocking: bool, work: W, done: D)
    where
        T: Send + 'static,
        W: FnOnce(&Mutex<Option<Vault>>) -> Result<T, SyncError> + Send + 'static,
        D: FnOnce(&Rc<VaultController>, Result<T, SyncError>) + Send + 'static,
    {
        self.with_state(|s| {
            s.set_sync_busy(true);
            if blocking {
                s.set_busy(true);
                s.set_error(SharedString::new());
            }
        });
        let vault = self.vault.clone();
        std::thread::spawn(move || {
            let result = work(&vault);
            let _ = slint::invoke_from_event_loop(move || {
                with_controller(|c| {
                    c.with_state(|s| {
                        s.set_sync_busy(false);
                        if blocking {
                            s.set_busy(false);
                        }
                    });
                    done(c, result);
                })
            });
        });
    }

    /// Copies the vault's sync configuration into the UI.
    fn refresh_sync_state(&self) {
        let info = self.vault().as_ref().map(|v| {
            (
                v.is_sync_enabled().unwrap_or(false),
                v.sync_settings().ok().flatten(),
                v.last_sync().ok().flatten(),
                v.recovery_pending().unwrap_or(false),
            )
        });
        let (enabled, settings, last, pending) = info.unwrap_or((false, None, None, false));
        self.with_state(|s| {
            s.set_sync_enabled(enabled && !s.get_sync_signed_out());
            s.set_sync_recovery_pending(pending);
            if let Some(settings) = &settings {
                s.set_sync_server(settings.server_url.as_str().into());
                s.set_sync_email(settings.email.as_str().into());
            }
            let status = last.map_or_else(
                || "Not synced yet".to_owned(),
                |t| format!("Last synced {}", format_sync_time(t)),
            );
            s.set_sync_status(status.into());
            s.set_sync_status_is_error(false);
        });
    }

    fn sync_now(&self) {
        let mut ready = false;
        self.with_state(|s| {
            ready = s.get_screen() == VaultScreen::Unlocked
                && s.get_sync_enabled()
                && !s.get_sync_busy()
                && !s.get_sync_signed_out();
        });
        if ready {
            self.sync_job(false, vsync::sync, |c, result| c.after_sync(result));
        }
    }

    /// Syncs shortly after a local change (several quick edits share one sync).
    fn schedule_sync(&self) {
        let mut enabled = false;
        self.with_state(|s| enabled = s.get_sync_enabled());
        if enabled {
            self.sync_timer.start(TimerMode::SingleShot, SYNC_DEBOUNCE, || with_controller(|c| c.sync_now()));
        }
    }

    fn after_sync(&self, result: Result<SyncReport, SyncError>) {
        match result {
            Ok(report) => {
                if report.pulled > 0 || report.conflicts > 0 {
                    self.refresh_after_remote_change();
                }
                self.refresh_sync_state();
                if report.conflicts > 0 {
                    self.status(
                        &format!(
                            "Sync: {} item(s) were edited on two devices; both versions were kept.",
                            report.conflicts
                        ),
                        false,
                    );
                } else if report.keys_updated {
                    self.status(
                        "A password was changed on another device. Use the new one next time you unlock.",
                        false,
                    );
                }
            }
            Err(e) if e.is_unauthorized() => self.with_state(|s| {
                s.set_sync_signed_out(true);
                s.set_sync_enabled(false);
                s.set_sync_status("Signed out by the sync server".into());
                s.set_sync_status_is_error(true);
            }),
            Err(e) => self.with_state(|s| {
                s.set_sync_status(format!("Sync failed: {}", sync_message(&e)).into());
                s.set_sync_status_is_error(true);
            }),
        }
    }

    /// Reloads the list after a sync changed items, keeping the user's place.
    fn refresh_after_remote_change(&self) {
        self.refresh_records();
        let (mut panel, mut selected, mut editing_note) = (VaultPanel::Detail, SharedString::new(), false);
        self.with_state(|s| {
            panel = s.get_panel();
            selected = s.get_selected_id();
            editing_note = !s.get_editing_note_id().is_empty();
        });
        if panel != VaultPanel::Detail || selected.is_empty() || editing_note {
            return;
        }
        match self.find_record(&selected) {
            Some(record) => self.show_detail(&record),
            None => self.with_state(|s| {
                s.set_selected_id(SharedString::new());
                s.set_detail(RecordDetail::default());
            }),
        }
    }

    fn sync_setup(
        &self,
        url: String,
        email: String,
        device: String,
        password: Secret,
        invite: String,
        create: bool,
    ) {
        if email.trim().is_empty() || device.trim().is_empty() {
            return self.error("Enter an email and a name for this device.");
        }
        self.sync_job(
            true,
            move |slot| {
                let account = Account { server_url: &url, email: &email, device_name: &device };
                if create {
                    vsync::create_account(slot, &account, &password, Some(&invite))?;
                } else {
                    vsync::sign_in(slot, &account, &password)?;
                }
                vsync::sync(slot)
            },
            |c, result| {
                c.with_state(|s| s.set_sync_signed_out(false));
                c.refresh_sync_state();
                match result {
                    Ok(report) => {
                        c.after_sync(Ok(report));
                        c.status("Sync is on for this vault.", false);
                    }
                    Err(e) => c.error(&sync_message(&e)),
                }
            },
        );
    }

    fn current_account(&self) -> Option<(String, String, String)> {
        let settings = self.vault().as_ref().and_then(|v| v.sync_settings().ok().flatten())?;
        Some((settings.server_url, settings.email, settings.device_name))
    }

    fn sync_sign_in_again(&self, password: Secret) {
        let Some((url, email, device)) = self.current_account() else { return };
        self.sync_job(
            true,
            move |slot| {
                vsync::sign_in(
                    slot,
                    &Account { server_url: &url, email: &email, device_name: &device },
                    &password,
                )?;
                vsync::sync(slot)
            },
            |c, result| match result {
                Ok(report) => {
                    c.with_state(|s| s.set_sync_signed_out(false));
                    c.after_sync(Ok(report));
                    c.status("Signed in again.", false);
                }
                Err(e) => c.error(&sync_message(&e)),
            },
        );
    }

    fn sync_finish_recovery(&self, password: Secret) {
        self.sync_job(
            true,
            move |slot| {
                vsync::recover_account(slot, &password)?;
                vsync::sync(slot)
            },
            |c, result| match result {
                Ok(report) => {
                    c.with_state(|s| s.set_sync_signed_out(false));
                    c.after_sync(Ok(report));
                    c.status("The sync server now uses your new password.", false);
                }
                Err(e) => c.error(&sync_message(&e)),
            },
        );
    }

    fn sync_sign_out(&self) {
        self.sync_job(true, vsync::sign_out, |c, result| {
            c.with_state(|s| {
                s.set_sync_signed_out(false);
                s.set_sync_devices(ModelRc::default());
            });
            c.refresh_sync_state();
            match result {
                Ok(()) => c.status("Sync is off on this device. Your vault stays here.", false),
                Err(e) => c.error(&sync_message(&e)),
            }
        });
    }

    fn show_devices(&self, result: Result<Vec<simplus_vault_proto::DeviceSession>, SyncError>) {
        match result {
            Ok(devices) => {
                let rows: Vec<DeviceRow> = devices
                    .into_iter()
                    .map(|d| DeviceRow {
                        id: d.id.to_string().into(),
                        name: d.name.into(),
                        last_seen: DateTime::from_timestamp(d.last_seen, 0)
                            .map(format_sync_time)
                            .unwrap_or_default()
                            .into(),
                        current: d.current,
                    })
                    .collect();
                self.with_state(|s| s.set_sync_devices(ModelRc::new(VecModel::from(rows))));
            }
            Err(e) => self.after_sync(Err(e)),
        }
    }

    fn sync_load_devices(&self) {
        self.sync_job(false, vsync::devices, |c, result| c.show_devices(result));
    }

    fn sync_revoke_device(&self, id: &str) {
        let Ok(id) = Uuid::parse_str(id) else { return };
        self.sync_job(
            false,
            move |slot| {
                vsync::revoke_device(slot, id)?;
                vsync::devices(slot)
            },
            |c, result| c.show_devices(result),
        );
    }

    /// New device: builds the local vault from a sync account, then downloads the items.
    fn download_vault(&self, url: String, email: String, device: String, password: Secret) {
        if Vault::exists(&self.path) {
            return self.error("A vault already exists on this device.");
        }
        let path = self.path.clone();
        self.sync_job(
            true,
            move |slot| {
                let account = Account { server_url: &url, email: &email, device_name: &device };
                let vault = vsync::download_vault(&path, &account, &password)?;
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(vault);
                Ok(vsync::sync(slot).err())
            },
            |c, result| match result {
                Ok(sync_error) => {
                    c.with_state(|s| {
                        s.set_screen(VaultScreen::Unlocked);
                        s.set_panel(VaultPanel::Detail);
                    });
                    c.refresh_records();
                    c.refresh_sync_state();
                    match sync_error {
                        None => c.status("Vault downloaded and in sync.", false),
                        Some(e) => c.after_sync(Err(e)),
                    }
                }
                Err(e) => c.error(&sync_message(&e)),
            },
        );
    }
}

/// Applies a local key change and, on a synced vault, publishes the new key bundle. If the
/// server cannot be updated the local change is undone, so devices never disagree on keys.
fn with_published_keys<T>(
    slot: &Mutex<Option<Vault>>,
    change: impl FnOnce(&mut Vault) -> Result<(Option<LoginChange>, T), VaultError>,
) -> Result<T, SyncError> {
    let (snapshot, synced, login, value) = slot.with_vault(|v| {
        let synced = v.is_sync_enabled()?;
        let snapshot = v.key_bundle()?;
        let (login, value) = change(v)?;
        Ok((snapshot, synced, login, value))
    })?;
    if synced && let Err(e) = vsync::publish_keys(slot, login) {
        slot.with_vault(|v| Ok(v.apply_key_bundle(&snapshot)?))?;
        return Err(e);
    }
    Ok(value)
}

fn sync_message(error: &SyncError) -> String {
    match error {
        SyncError::Vault(e) => describe(e),
        other => {
            let mut text = other.to_string();
            if let Some(first) = text.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            if !text.ends_with('.') {
                text.push('.');
            }
            text
        }
    }
}

fn format_sync_time(t: DateTime<Utc>) -> String {
    let local = t.with_timezone(&Local);
    if local.date_naive() == Local::now().date_naive() {
        local.format("%H:%M").to_string()
    } else {
        local.format("%Y-%m-%d %H:%M").to_string()
    }
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "This computer".to_owned())
}

// -------------------------------------------------------------------------------------------
// Conversions between vault types and Slint structs
// -------------------------------------------------------------------------------------------

fn describe(error: &VaultError) -> String {
    match error {
        VaultError::WrongPassword => "Wrong master password.".into(),
        VaultError::WrongNotesPassword => "Wrong secure notes password.".into(),
        VaultError::WrongRecoveryKey => "That recovery key is not correct.".into(),
        VaultError::NotesLocked => "Unlock secure notes first.".into(),
        VaultError::Locked => "The vault is locked.".into(),
        other => {
            let mut text = other.to_string();
            if let Some(first) = text.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            if !text.ends_with('.') {
                text.push('.');
            }
            text
        }
    }
}

fn strength(password: &str) -> Strength {
    if password.is_empty() {
        return Strength::default();
    }
    let s = generator::strength(password, &[]);
    Strength {
        score: s.score as i32,
        label: s.label.into(),
        crack_time: format!("cracked in ~{}", s.crack_time).into(),
        warning: s.warning.unwrap_or_default().into(),
    }
}

fn format_time(t: DateTime<Utc>) -> SharedString {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string().into()
}

/// "123456" → "123 456" for readability.
fn format_code(code: &str) -> String {
    let mid = code.len() / 2;
    format!("{} {}", &code[..mid], &code[mid..])
}

fn host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

fn record_row(record: &Record) -> RecordRow {
    let subtitle = if !record.username.is_empty() {
        record.username.clone()
    } else {
        record.urls.first().map(|u| host(u).to_owned()).unwrap_or_else(|| record.folder.clone())
    };
    RecordRow {
        id: record.id.to_string().into(),
        title: record.title.as_str().into(),
        subtitle: subtitle.into(),
        favorite: record.favorite,
        has_totp: record.totp.as_deref().is_some_and(|t| !t.is_empty()),
    }
}

fn record_detail(record: &Record) -> RecordDetail {
    let fields: Vec<FieldRow> = record
        .custom_fields
        .iter()
        .map(|f| FieldRow { name: f.name.as_str().into(), value: f.value.as_str().into(), hidden: f.hidden })
        .collect();
    let history: Vec<HistoryRow> = record
        .password_history
        .iter()
        .map(|h| HistoryRow {
            password: h.password.as_str().into(),
            changed: format!("Changed {}", format_time(h.changed_at)).into(),
        })
        .collect();
    let urls: Vec<SharedString> = record.urls.iter().map(|u| u.as_str().into()).collect();
    RecordDetail {
        id: record.id.to_string().into(),
        title: record.title.as_str().into(),
        username: record.username.as_str().into(),
        password: record.password.as_str().into(),
        urls: record.urls.join("\n").into(),
        url_list: ModelRc::new(VecModel::from(urls)),
        folder: record.folder.as_str().into(),
        tags: record.tags.join(", ").into(),
        favorite: record.favorite,
        totp: record.totp.clone().unwrap_or_default().into(),
        fields: ModelRc::new(VecModel::from(fields)),
        history: ModelRc::new(VecModel::from(history)),
        created: format_time(record.created_at),
        updated: format_time(record.updated_at),
    }
}

fn note_row(note: &SecureNote) -> NoteRow {
    NoteRow {
        id: note.id.to_string().into(),
        title: note.title.as_str().into(),
        body: note.body.as_str().into(),
        updated: format_time(note.updated_at),
    }
}

/// Copies the editor's values into `record`, validating the TOTP secret.
fn apply_detail(record: &mut Record, detail: &RecordDetail, fields: &[FieldRow]) -> Result<(), String> {
    let title = detail.title.trim();
    if title.is_empty() {
        return Err("A title is required.".into());
    }
    let totp = detail.totp.trim();
    if !totp.is_empty() {
        Totp::parse(totp).map_err(|e| format!("Two-factor secret: {e}."))?;
    }
    record.title = title.to_owned();
    record.username = detail.username.trim().to_owned();
    record.password = detail.password.to_string();
    record.urls = detail.urls.lines().map(str::trim).filter(|u| !u.is_empty()).map(str::to_owned).collect();
    record.folder = detail.folder.trim().to_owned();
    record.tags =
        detail.tags.split(',').map(str::trim).filter(|t| !t.is_empty()).map(str::to_owned).collect();
    record.favorite = detail.favorite;
    record.totp = (!totp.is_empty()).then(|| totp.to_owned());
    record.custom_fields = fields
        .iter()
        .filter(|f| !f.name.trim().is_empty() || !f.value.is_empty())
        .map(|f| CustomField { name: f.name.trim().to_owned(), value: f.value.to_string(), hidden: f.hidden })
        .collect();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(title: &str) -> RecordDetail {
        RecordDetail { title: title.into(), ..Default::default() }
    }

    #[test]
    fn apply_detail_normalises_input() {
        let mut record = Record::new("old");
        let mut d = detail("  GitHub ");
        d.username = " octocat ".into();
        d.password = " keep spaces ".into();
        d.urls = "https://github.com\n\n  https://gist.github.com  \n".into();
        d.tags = "work, , dev ".into();
        d.totp = " JBSWY3DPEHPK3PXP ".into();
        let fields =
            [FieldRow { name: "PIN".into(), value: "1234".into(), hidden: true }, FieldRow::default()];
        apply_detail(&mut record, &d, &fields).unwrap();
        assert_eq!(record.title, "GitHub");
        assert_eq!(record.username, "octocat");
        assert_eq!(record.password, " keep spaces ", "passwords are never trimmed");
        assert_eq!(record.urls, ["https://github.com", "https://gist.github.com"]);
        assert_eq!(record.tags, ["work", "dev"]);
        assert_eq!(record.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(record.custom_fields.len(), 1, "empty rows are dropped");
    }

    #[test]
    fn apply_detail_rejects_bad_input() {
        let mut record = Record::new("x");
        assert!(apply_detail(&mut record, &detail("  "), &[]).is_err());
        let mut d = detail("Site");
        d.totp = "not a secret!".into();
        assert!(apply_detail(&mut record, &d, &[]).unwrap_err().starts_with("Two-factor"));
        assert_eq!(record.title, "x", "record untouched on error");
    }

    #[test]
    fn detail_round_trip() {
        let mut record = Record::new("Mail");
        record.username = "me".into();
        record.urls = vec!["https://mail.example".into()];
        record.custom_fields.push(CustomField { name: "a".into(), value: "b".into(), hidden: false });
        let d = record_detail(&record);
        assert_eq!(d.url_list.row_count(), 1);
        let fields: Vec<FieldRow> = d.fields.iter().collect();
        let mut copy = Record::new("other");
        apply_detail(&mut copy, &d, &fields).unwrap();
        assert_eq!(copy.title, record.title);
        assert_eq!(copy.username, record.username);
        assert_eq!(copy.urls, record.urls);
        assert_eq!(copy.custom_fields, record.custom_fields);
    }

    #[test]
    fn row_subtitle_falls_back_to_host() {
        let mut record = Record::new("Site");
        record.urls = vec!["https://example.com/login".into()];
        assert_eq!(record_row(&record).subtitle, "example.com");
        record.username = "bob".into();
        assert_eq!(record_row(&record).subtitle, "bob");
    }

    #[test]
    fn misc_formatting() {
        assert_eq!(format_code("123456"), "123 456");
        assert_eq!(format_code("12345678"), "1234 5678");
        assert_eq!(describe(&VaultError::Invalid("a title is required".into())), "A title is required.");
        assert_eq!(strength("").score, 0);
    }
}

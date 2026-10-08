//! Real vaults on several "devices" syncing through an in-process server.

use std::path::PathBuf;
use std::sync::Mutex;

use simplus_crypto::KdfParams;
use simplus_sync_server::{AppState, Config};
use simplus_vault_core::{Record, RecoveryKey, SecureNote, Vault, VaultError};
use simplus_vault_sync::{
    Account, LoginChange, SyncError, create_account, devices, download_vault, publish_keys, recover_account,
    revoke_device, sign_in, sign_out, sync,
};
use zeroize::Zeroizing;

const FAST: KdfParams = KdfParams { m_cost_kib: 64, t_cost: 1, p_cost: 1 };
const MP1: &str = "master password 1";
const MP2: &str = "notes password 2";
const EMAIL: &str = "user@example.com";

struct Server {
    url: String,
    _runtime: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let config = Config { database: dir.path().join("sync.db"), ..Config::default() };
    let state = AppState::open(config).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    runtime.spawn(simplus_sync_server::serve(state, listener, std::future::pending()));
    Server { url, _runtime: runtime, _dir: dir }
}

struct Device {
    dir: tempfile::TempDir,
    vault: Mutex<Vault>,
}

impl Device {
    fn path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("vault.db")
    }

    fn v(&self) -> std::sync::MutexGuard<'_, Vault> {
        self.vault.lock().unwrap()
    }
}

fn account<'a>(server: &'a Server, name: &'a str) -> Account<'a> {
    Account { server_url: &server.url, email: EMAIL, device_name: name }
}

/// First device: a local vault with some content, then "Set up sync".
fn first_device(server: &Server) -> (Device, RecoveryKey) {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, recovery) = Vault::create(&Device::path(&dir), MP1, MP2, FAST).unwrap();
    vault.unlock_notes(MP2).unwrap();
    let mut record = Record::new("GitHub");
    record.password = "hunter2".into();
    vault.save_record(&mut record).unwrap();
    vault.save_note(&mut SecureNote::new(record.id, "Codes", "1111")).unwrap();
    let device = Device { dir, vault: Mutex::new(vault) };
    create_account(&device.vault, &account(server, "Desktop"), MP1, None).unwrap();
    let report = sync(&device.vault).unwrap();
    assert_eq!(report.pushed, 2);
    (device, recovery)
}

fn new_device(server: &Server, name: &str) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let vault = download_vault(&Device::path(&dir), &account(server, name), MP1).unwrap();
    let device = Device { dir, vault: Mutex::new(vault) };
    sync(&device.vault).unwrap();
    device
}

fn titles(device: &Device) -> Vec<String> {
    device.v().list_records().unwrap().into_iter().map(|r| r.title.clone()).collect()
}

#[test]
fn new_device_downloads_everything() {
    let s = server();
    let (a, _) = first_device(&s);
    let b = new_device(&s, "Laptop");
    assert_eq!(titles(&b), ["GitHub"]);
    let id = b.v().list_records().unwrap()[0].id;
    assert_eq!(b.v().list_records().unwrap()[0].password, "hunter2");
    b.v().unlock_notes(MP2).unwrap();
    assert_eq!(b.v().list_notes(id).unwrap()[0].body, "1111");
    assert_eq!(b.v().id(), a.v().id());

    // Wrong password on another new device: nothing is created.
    let dir = tempfile::tempdir().unwrap();
    let err = download_vault(&Device::path(&dir), &account(&s, "Bad"), "nope").unwrap_err();
    assert!(err.is_invalid_credentials(), "{err:?}");
    assert!(!Device::path(&dir).exists());
}

#[test]
fn edits_flow_both_ways_with_conflict_copies() {
    let s = server();
    let (a, _) = first_device(&s);
    let b = new_device(&s, "Laptop");
    let id = a.v().list_records().unwrap()[0].id;

    // Plain edit A -> B.
    {
        let mut r = a.v().get_record(id).unwrap();
        r.username = "octocat".into();
        a.v().save_record(&mut r).unwrap();
    }
    sync(&a.vault).unwrap();
    sync(&b.vault).unwrap();
    assert_eq!(b.v().get_record(id).unwrap().username, "octocat");

    // Concurrent edits: B syncs second and keeps its version as a conflict copy.
    for (device, password) in [(&a, "from a"), (&b, "from b")] {
        let mut r = device.v().get_record(id).unwrap();
        r.password = password.into();
        device.v().save_record(&mut r).unwrap();
    }
    sync(&a.vault).unwrap();
    let report = sync(&b.vault).unwrap();
    assert_eq!(report.conflicts, 1);
    sync(&a.vault).unwrap();
    for device in [&a, &b] {
        assert_eq!(titles(device), ["GitHub", "GitHub (conflict copy)"]);
        assert_eq!(device.v().get_record(id).unwrap().password, "from a");
    }

    // Deletion propagates.
    b.v().delete_record(id).unwrap();
    sync(&b.vault).unwrap();
    sync(&a.vault).unwrap();
    assert_eq!(titles(&a), ["GitHub (conflict copy)"]);
}

#[test]
fn master_password_change_signs_out_other_devices() {
    let s = server();
    let (a, _) = first_device(&s);
    let b = new_device(&s, "Laptop");

    {
        let mut v = a.v();
        let current = Zeroizing::new(v.auth_key(MP1).unwrap().expose().to_vec());
        v.change_master_password(MP1, "brand new master").unwrap();
        let new = Zeroizing::new(v.auth_key("brand new master").unwrap().expose().to_vec());
        drop(v);
        publish_keys(&a.vault, Some(LoginChange { current_auth_key: current, new_auth_key: new })).unwrap();
    }
    sync(&a.vault).unwrap();

    let err = sync(&b.vault).unwrap_err();
    assert!(err.is_unauthorized(), "{err:?}");
    // B still unlocks with the old password until it signs in again...
    assert!(sign_in(&b.vault, &account(&s, "Laptop"), MP1).unwrap_err().is_invalid_credentials());
    sign_in(&b.vault, &account(&s, "Laptop"), "brand new master").unwrap();
    // ...after which its local master password is the new one too.
    b.v().lock();
    assert!(matches!(b.v().unlock(MP1), Err(VaultError::WrongPassword)));
    b.v().unlock("brand new master").unwrap();
    sync(&b.vault).unwrap();

    // Re-signing in reused the device id: still exactly two devices.
    assert_eq!(devices(&a.vault).unwrap().len(), 2);
}

#[test]
fn notes_password_change_propagates_without_sign_out() {
    let s = server();
    let (a, _) = first_device(&s);
    let b = new_device(&s, "Laptop");
    a.v().change_notes_password(MP2, "new notes pw").unwrap();
    publish_keys(&a.vault, None).unwrap();

    let report = sync(&b.vault).unwrap();
    assert!(report.keys_updated);
    assert!(matches!(b.v().unlock_notes(MP2), Err(VaultError::WrongNotesPassword)));
    b.v().unlock_notes("new notes pw").unwrap();
}

#[test]
fn recovery_key_resets_server_login() {
    let s = server();
    let (a, recovery) = first_device(&s);
    let b = new_device(&s, "Laptop");

    // A forgot the password: local reset with the recovery key, then the server login.
    let path = Device::path(&a.dir);
    let recovered = {
        drop(a.vault);
        Vault::recover(&path, &recovery, "recovered master", "recovered notes").unwrap()
    };
    let a = Device { dir: a.dir, vault: Mutex::new(recovered) };
    recover_account(&a.vault, "recovered master").unwrap();
    sync(&a.vault).unwrap();

    assert!(sync(&b.vault).unwrap_err().is_unauthorized());
    sign_in(&b.vault, &account(&s, "Laptop"), "recovered master").unwrap();
    sync(&b.vault).unwrap();
    b.v().lock();
    b.v().unlock("recovered master").unwrap();
    b.v().unlock_notes("recovered notes").unwrap();
}

#[test]
fn devices_revoke_and_sign_out() {
    let s = server();
    let (a, _) = first_device(&s);
    let b = new_device(&s, "Laptop");
    let list = devices(&a.vault).unwrap();
    assert_eq!(list.len(), 2);
    let laptop = list.iter().find(|d| d.name == "Laptop").unwrap();
    revoke_device(&a.vault, laptop.id).unwrap();
    assert!(sync(&b.vault).unwrap_err().is_unauthorized());

    sign_out(&a.vault).unwrap();
    assert!(matches!(sync(&a.vault), Err(SyncError::NotSignedIn)));
    // Signing back in resumes without re-uploading anything.
    sign_in(&a.vault, &account(&s, "Desktop"), MP1).unwrap();
    assert_eq!(sync(&a.vault).unwrap().pushed, 0);
}

#[test]
fn account_rules() {
    let s = server();
    let (_a, _) = first_device(&s);
    // A second vault cannot take the same email...
    let dir = tempfile::tempdir().unwrap();
    let (other, _) = Vault::create(&Device::path(&dir), MP1, MP2, FAST).unwrap();
    let other = Mutex::new(other);
    let err = create_account(&other, &account(&s, "Other"), MP1, None).unwrap_err();
    assert!(matches!(err, SyncError::Server { status: 409, .. }), "{err:?}");
    // ...nor sign in to an account holding a different vault.
    assert!(matches!(sign_in(&other, &account(&s, "Other"), MP1), Err(SyncError::DifferentVault)));
    // Plain http to a remote host is refused before any request.
    let remote = Account { server_url: "http://sync.example.com", email: EMAIL, device_name: "X" };
    assert!(matches!(create_account(&other, &remote, MP1, None), Err(SyncError::InsecureUrl)));
}

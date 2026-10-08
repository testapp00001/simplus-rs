use std::collections::BTreeMap;

use simplus_crypto::KdfParams;
use simplus_vault_proto::RemoteItem;
use uuid::Uuid;

use super::*;
use crate::RecoveryKey;

const FAST: KdfParams = KdfParams { m_cost_kib: 64, t_cost: 1, p_cost: 1 };
const MP1: &str = "master password";
const MP2: &str = "notes password";

/// Minimal in-memory stand-in for the sync server's item feed.
#[derive(Default)]
struct FakeServer {
    items: BTreeMap<Uuid, RemoteItem>,
    seq: i64,
}

impl FakeServer {
    /// Pushes pending changes; returns how many were rejected as conflicts.
    fn push(&mut self, vault: &mut Vault) -> usize {
        let mut conflicts = 0;
        for change in vault.pending_changes().unwrap() {
            let item = change.item;
            let current = self.items.get(&item.id).map_or(0, |i| i.seq);
            if current != item.base_seq {
                conflicts += 1;
                continue;
            }
            self.seq += 1;
            self.items.insert(
                item.id,
                RemoteItem {
                    id: item.id,
                    kind: item.kind,
                    parent_id: item.parent_id,
                    seq: self.seq,
                    deleted: item.deleted,
                    updated_at: item.updated_at,
                    blob: item.blob,
                },
            );
            vault.mark_pushed(item.id, change.revision, self.seq).unwrap();
        }
        conflicts
    }

    fn pull(&self, vault: &mut Vault) -> ApplyReport {
        let cursor = vault.sync_cursor().unwrap();
        let mut items: Vec<_> = self.items.values().filter(|i| i.seq > cursor).cloned().collect();
        items.sort_by_key(|i| i.seq);
        let report = vault.apply_remote(&items).unwrap();
        vault.set_sync_cursor(self.seq).unwrap();
        report
    }

    /// Same loop as the real client: pull, push, repeat while there are conflicts.
    fn sync(&mut self, vault: &mut Vault) -> ApplyReport {
        let mut total = ApplyReport::default();
        for _ in 0..3 {
            let report = self.pull(vault);
            total.applied += report.applied;
            total.conflicts += report.conflicts;
            total.rejected += report.rejected;
            if self.push(vault) == 0 {
                break;
            }
        }
        total
    }
}

struct Device {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    vault: Vault,
}

fn device_a() -> (Device, RecoveryKey) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (vault, recovery) = Vault::create(&path, MP1, MP2, FAST).unwrap();
    (Device { _dir: dir, path, vault }, recovery)
}

fn device_from(other: &Vault) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let vault = Vault::create_from_bundle(&path, &other.key_bundle().unwrap(), MP1).unwrap();
    Device { _dir: dir, path, vault }
}

fn record(vault: &mut Vault, title: &str, password: &str) -> Record {
    let mut r = Record::new(title);
    r.password = password.into();
    vault.save_record(&mut r).unwrap();
    r
}

fn titles(vault: &Vault) -> Vec<String> {
    vault.list_records().unwrap().into_iter().map(|r| r.title.clone()).collect()
}

#[test]
fn dirty_tracking() {
    let (mut a, _) = device_a();
    let mut r = record(&mut a.vault, "Mail", "pw");
    let pending = a.vault.pending_changes().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].item.base_seq, 0);

    a.vault.mark_pushed(r.id, pending[0].revision, 5).unwrap();
    assert!(a.vault.pending_changes().unwrap().is_empty());

    r.password = "pw2".into();
    a.vault.save_record(&mut r).unwrap();
    let pending = a.vault.pending_changes().unwrap();
    assert_eq!(pending[0].item.base_seq, 5, "edits are based on the last pushed seq");

    // An edit made while a push was in flight keeps the item dirty.
    let in_flight = pending[0].revision;
    r.password = "pw3".into();
    a.vault.save_record(&mut r).unwrap();
    a.vault.mark_pushed(r.id, in_flight, 6).unwrap();
    let pending = a.vault.pending_changes().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].item.base_seq, 6);

    // Deleting something the server never saw needs no push.
    let local_only = record(&mut a.vault, "Scratch", "x");
    a.vault.delete_record(local_only.id).unwrap();
    assert!(a.vault.pending_changes().unwrap().iter().all(|c| c.item.id != local_only.id));
}

#[test]
fn two_devices_converge() {
    let (mut a, _) = device_a();
    let mut server = FakeServer::default();
    a.vault.unlock_notes(MP2).unwrap();
    let r = record(&mut a.vault, "Bank", "pw");
    a.vault.save_note(&mut SecureNote::new(r.id, "PIN", "1234")).unwrap();
    server.sync(&mut a.vault);

    let mut b = device_from(&a.vault);
    let report = server.sync(&mut b.vault);
    assert_eq!(report.applied, 2);
    assert_eq!(titles(&b.vault), ["Bank"]);
    assert_eq!(b.vault.note_count(r.id).unwrap(), 1);
    b.vault.unlock_notes(MP2).unwrap();
    assert_eq!(b.vault.list_notes(r.id).unwrap()[0].body, "1234");

    // B edits, A receives.
    let mut on_b = b.vault.get_record(r.id).unwrap();
    on_b.password = "changed on b".into();
    b.vault.save_record(&mut on_b).unwrap();
    server.sync(&mut b.vault);
    server.sync(&mut a.vault);
    assert_eq!(a.vault.get_record(r.id).unwrap().password, "changed on b");
    assert!(a.vault.pending_changes().unwrap().is_empty());

    // Deletions propagate, including the record's notes.
    a.vault.delete_record(r.id).unwrap();
    server.sync(&mut a.vault);
    server.sync(&mut b.vault);
    assert!(b.vault.list_records().unwrap().is_empty());
    assert_eq!(b.vault.note_count(r.id).unwrap(), 0);
}

#[test]
fn concurrent_edits_keep_a_conflict_copy() {
    let (mut a, _) = device_a();
    let mut server = FakeServer::default();
    let r = record(&mut a.vault, "Shop", "original");
    server.sync(&mut a.vault);
    let mut b = device_from(&a.vault);
    server.sync(&mut b.vault);

    let mut on_a = a.vault.get_record(r.id).unwrap();
    on_a.password = "from a".into();
    a.vault.save_record(&mut on_a).unwrap();
    let mut on_b = b.vault.get_record(r.id).unwrap();
    on_b.password = "from b".into();
    b.vault.save_record(&mut on_b).unwrap();

    server.sync(&mut a.vault); // A wins the race to the server.
    let report = server.sync(&mut b.vault);
    assert_eq!(report.conflicts, 1);
    server.sync(&mut a.vault);

    for vault in [&a.vault, &b.vault] {
        let records = vault.list_records().unwrap();
        assert_eq!(titles(vault), ["Shop", "Shop (conflict copy)"]);
        assert_eq!(records[0].password, "from a");
        assert_eq!(records[1].password, "from b");
    }
}

#[test]
fn identical_concurrent_edits_do_not_conflict() {
    let (mut a, _) = device_a();
    let mut server = FakeServer::default();
    let r = record(&mut a.vault, "Same", "x");
    server.sync(&mut a.vault);
    let mut b = device_from(&a.vault);
    server.sync(&mut b.vault);

    for vault in [&mut a.vault, &mut b.vault] {
        let mut rec = vault.get_record(r.id).unwrap();
        rec.username = "same edit".into();
        vault.save_record(&mut rec).unwrap();
    }
    server.sync(&mut a.vault);
    assert_eq!(server.sync(&mut b.vault).conflicts, 0);
    assert_eq!(titles(&b.vault), ["Same"]);
}

#[test]
fn edits_beat_deletes() {
    let (mut a, _) = device_a();
    let mut server = FakeServer::default();
    let r1 = record(&mut a.vault, "One", "x");
    let r2 = record(&mut a.vault, "Two", "x");
    server.sync(&mut a.vault);
    let mut b = device_from(&a.vault);
    server.sync(&mut b.vault);

    // r1: A deletes, B edits. r2: A edits, B deletes.
    a.vault.delete_record(r1.id).unwrap();
    let mut two = a.vault.get_record(r2.id).unwrap();
    two.username = "edited on a".into();
    a.vault.save_record(&mut two).unwrap();
    let mut one = b.vault.get_record(r1.id).unwrap();
    one.username = "edited on b".into();
    b.vault.save_record(&mut one).unwrap();
    b.vault.delete_record(r2.id).unwrap();

    server.sync(&mut a.vault);
    server.sync(&mut b.vault);
    server.sync(&mut a.vault);

    for vault in [&a.vault, &b.vault] {
        assert_eq!(titles(vault), ["One", "Two"]);
        assert_eq!(vault.get_record(r1.id).unwrap().username, "edited on b");
        assert_eq!(vault.get_record(r2.id).unwrap().username, "edited on a");
    }
}

#[test]
fn note_conflict_while_notes_locked_is_resolved_on_unlock() {
    let (mut a, _) = device_a();
    let mut server = FakeServer::default();
    a.vault.unlock_notes(MP2).unwrap();
    let r = record(&mut a.vault, "Server", "x");
    let mut note = SecureNote::new(r.id, "Keys", "v1");
    a.vault.save_note(&mut note).unwrap();
    server.sync(&mut a.vault);
    let mut b = device_from(&a.vault);
    b.vault.unlock_notes(MP2).unwrap();
    server.sync(&mut b.vault);

    note.body = "edited on a".into();
    a.vault.save_note(&mut note).unwrap();
    let mut on_b = b.vault.list_notes(r.id).unwrap().remove(0);
    on_b.body = "edited on b".into();
    b.vault.save_note(&mut on_b).unwrap();
    b.vault.lock_notes();

    server.sync(&mut a.vault);
    let report = server.sync(&mut b.vault);
    assert_eq!(report.conflicts, 1);
    assert_eq!(b.vault.note_count(r.id).unwrap(), 1, "copy waits for the notes key");

    b.vault.unlock_notes(MP2).unwrap();
    let notes = b.vault.list_notes(r.id).unwrap();
    let bodies: Vec<_> = notes.iter().map(|n| (n.title.as_str(), n.body.as_str())).collect();
    assert_eq!(bodies, [("Keys", "edited on a"), ("Keys (conflict copy)", "edited on b")]);
    server.sync(&mut b.vault);
    server.sync(&mut a.vault);
    assert_eq!(a.vault.list_notes(r.id).unwrap().len(), 2);
}

#[test]
fn unreadable_remote_items_are_rejected() {
    let (mut a, _) = device_a();
    let bogus = RemoteItem {
        id: Uuid::now_v7(),
        kind: WireKind::Record,
        parent_id: None,
        seq: 1,
        deleted: false,
        updated_at: 0,
        blob: Some(vec![1; 80]),
    };
    let orphan_note = RemoteItem { id: Uuid::now_v7(), kind: WireKind::Note, seq: 2, ..bogus.clone() };
    let report = a.vault.apply_remote(&[bogus, orphan_note]).unwrap();
    assert_eq!(report.rejected, 2);
    assert!(a.vault.list_records().unwrap().is_empty(), "listing still works");
}

#[test]
fn password_change_propagates_through_the_bundle() {
    let (mut a, _) = device_a();
    let mut b = device_from(&a.vault);
    a.vault.change_master_password(MP1, "new master").unwrap();
    b.vault.apply_key_bundle(&a.vault.key_bundle().unwrap()).unwrap();
    b.vault.lock();
    assert!(matches!(b.vault.unlock(MP1), Err(VaultError::WrongPassword)));
    b.vault.unlock("new master").unwrap();
    assert_eq!(b.vault.kdf_info().unwrap(), a.vault.kdf_info().unwrap());
}

#[test]
fn substituted_bundle_is_detected_and_undone() {
    let (mut a, _) = device_a();
    // An attacker's vault with its own keys, presented under our vault id.
    let (attacker, _) = device_a();
    let mut forged = attacker.vault.key_bundle().unwrap();
    forged.vault_id = a.vault.id();

    a.vault.apply_key_bundle(&forged).unwrap();
    a.vault.lock();
    assert!(matches!(a.vault.unlock(MP1), Err(VaultError::KeyMismatch)));
    // The original slots are back, so the real password works again.
    a.vault.unlock(MP1).unwrap();

    let mut other_vault = forged.clone();
    other_vault.vault_id = Uuid::now_v7();
    assert!(matches!(a.vault.apply_key_bundle(&other_vault), Err(VaultError::KeyMismatch)));
}

#[test]
fn auth_keys_agree_across_devices() {
    let (a, _) = device_a();
    let kdf = a.vault.kdf_info().unwrap();
    assert_eq!(a.vault.auth_key(MP1).unwrap().expose(), auth_key_from_kdf(MP1, &kdf).unwrap().expose());
    assert!(matches!(a.vault.auth_key("wrong"), Err(VaultError::WrongPassword)));
    assert_ne!(a.vault.auth_key(MP1).unwrap().expose(), a.vault.key_proof().unwrap().expose());

    let b = device_from(&a.vault);
    assert_eq!(b.vault.key_proof().unwrap().expose(), a.vault.key_proof().unwrap().expose());
}

#[test]
fn create_from_bundle_checks_password_first() {
    let (a, _) = device_a();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.db");
    let bundle = a.vault.key_bundle().unwrap();
    assert!(matches!(Vault::create_from_bundle(&path, &bundle, "nope"), Err(VaultError::WrongPassword)));
    assert!(!path.exists());
    let b = Vault::create_from_bundle(&path, &bundle, MP1).unwrap();
    assert_eq!(b.id(), a.vault.id());
    assert!(matches!(Vault::create_from_bundle(&path, &bundle, MP1), Err(VaultError::AlreadyExists)));
}

#[test]
fn recovery_still_works_on_a_synced_device() {
    let (a, recovery) = device_a();
    let Device { _dir, path, vault } = device_from(&a.vault);
    drop(vault);
    let mut recovered = Vault::recover(&path, &recovery, "fresh master", "fresh notes").unwrap();
    recovered.unlock_notes("fresh notes").unwrap();
}

#[test]
fn sync_settings_and_token() {
    let (mut a, _) = device_a();
    record(&mut a.vault, "x", "y");
    let settings = SyncSettings {
        server_url: "https://sync.example.com".into(),
        email: "me@example.com".into(),
        device_id: Uuid::now_v7(),
        device_name: "Laptop".into(),
    };
    a.vault.enable_sync(&settings, "token-1", 3).unwrap();
    assert!(a.vault.is_sync_enabled().unwrap());
    assert_eq!(a.vault.sync_settings().unwrap(), Some(settings.clone()));
    assert_eq!(a.vault.synced_keys_version().unwrap(), 3);
    assert_eq!(a.vault.sync_token().unwrap().unwrap().as_str(), "token-1");

    // Push everything, then sign out and back in to the same account: nothing is re-uploaded.
    let mut server = FakeServer::default();
    server.sync(&mut a.vault);
    a.vault.disable_sync().unwrap();
    assert!(!a.vault.is_sync_enabled().unwrap());
    a.vault.enable_sync(&settings, "token-2", 3).unwrap();
    assert!(a.vault.pending_changes().unwrap().is_empty());

    // A different account starts over.
    let other = SyncSettings { email: "other@example.com".into(), ..settings };
    a.vault.enable_sync(&other, "token-3", 1).unwrap();
    assert_eq!(a.vault.pending_changes().unwrap().len(), 1);
    assert_eq!(a.vault.sync_cursor().unwrap(), 0);

    a.vault.lock();
    assert!(matches!(a.vault.sync_token(), Err(VaultError::Locked)));
}

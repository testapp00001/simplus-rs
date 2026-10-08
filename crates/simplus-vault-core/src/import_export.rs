//! Importing from other password managers and exporting backups.
//!
//! Imports are **additive**: every imported entry gets a fresh id, so importing never
//! overwrites existing records. Free-text notes from other managers become secure notes, which
//! means the notes password must be entered before importing them.

use chrono::Utc;
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use simplus_crypto::{KdfParams, KeySlot, SecretKey, open as open_sealed, seal};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::store::{self, ItemKind};
use crate::vault::{data_error, encrypt_item};
use crate::{CustomField, Record, Result, SecureNote, Vault, VaultError};

const EXPORT_FORMAT: &str = "simplus-vault-export";
const EXPORT_VERSION: u32 = 1;
const CTX_EXPORT_KEY: &[u8] = b"simplus/export/data-key";
const AAD_EXPORT_PAYLOAD: &[u8] = b"simplus/export/payload/v1";
const DEFAULT_NOTE_TITLE: &str = "Notes";

/// One entry ready to be imported: a record plus the bodies of its secure notes.
#[derive(Clone, Debug)]
pub struct ImportedItem {
    pub record: Record,
    /// `(title, body)` pairs that become secure notes.
    pub notes: Vec<(String, Zeroizing<String>)>,
}

/// Parsed import data plus how many source entries could not be used.
#[derive(Debug, Default)]
pub struct ParsedImport {
    pub items: Vec<ImportedItem>,
    pub skipped: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub records: usize,
    pub notes: usize,
}

fn import_error(msg: impl Into<String>) -> VaultError {
    VaultError::Import(msg.into())
}

fn non_empty(s: Option<&str>) -> Option<String> {
    s.map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned)
}

/// `https://www.example.com/login` → `example.com`.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?.split(':').next()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

fn finish_title(record: &mut Record) {
    if record.title.trim().is_empty() {
        record.title = record
            .urls
            .first()
            .and_then(|u| host_of(u))
            .or_else(|| non_empty(Some(&record.username)))
            .unwrap_or_else(|| "Untitled".into());
    }
}

// ---------------------------------------------------------------------------------------------
// CSV (Chrome/Edge, Firefox, Bitwarden CSV, KeePassXC and generic)
// ---------------------------------------------------------------------------------------------

/// Which CSV column feeds which field. Built automatically by [`CsvMapping::detect`] and
/// adjustable in the UI.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CsvMapping {
    pub title: Option<usize>,
    pub username: Option<usize>,
    pub password: Option<usize>,
    pub url: Option<usize>,
    pub notes: Option<usize>,
    pub totp: Option<usize>,
    pub folder: Option<usize>,
    pub favorite: Option<usize>,
    /// Bitwarden-style custom fields: one `name: value` per line.
    pub fields: Option<usize>,
}

impl CsvMapping {
    /// Maps columns by their header names, covering the export formats of common managers.
    pub fn detect(headers: &[String]) -> Self {
        let find = |aliases: &[&str]| {
            headers.iter().position(|h| {
                let h = h.trim().trim_start_matches('\u{feff}').to_lowercase();
                aliases.contains(&h.as_str())
            })
        };
        Self {
            title: find(&["title", "name", "account", "site", "entry"]),
            username: find(&["username", "login_username", "user", "user name", "login", "email", "e-mail"]),
            password: find(&["password", "login_password", "pass"]),
            url: find(&["url", "login_uri", "uri", "website", "web site", "origin"]),
            notes: find(&["notes", "note", "extra", "comments", "comment"]),
            totp: find(&["totp", "login_totp", "otp", "otpauth", "one-time password"]),
            folder: find(&["folder", "group", "category", "grouping"]),
            favorite: find(&["favorite", "favourite"]),
            fields: find(&["fields"]),
        }
    }

    /// A mapping is usable once it knows where passwords or usernames are.
    pub fn is_usable(&self) -> bool {
        self.password.is_some() || self.username.is_some()
    }
}

fn csv_reader(data: &str) -> csv::Reader<&[u8]> {
    csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(data.trim_start_matches('\u{feff}').as_bytes())
}

/// The header row of a CSV export, for showing a column-mapping UI.
pub fn csv_headers(data: &str) -> Result<Vec<String>> {
    let mut reader = csv_reader(data);
    let headers = reader.headers().map_err(|e| import_error(format!("cannot read CSV header: {e}")))?;
    Ok(headers.iter().map(str::to_owned).collect())
}

fn clean_folder(folder: &str) -> String {
    // KeePass exports the root group as "Root" and nested groups as "Root/Work".
    let folder = folder.trim();
    let folder = folder.strip_prefix("Root/").unwrap_or(folder);
    if folder == "Root" { String::new() } else { folder.to_owned() }
}

pub fn parse_csv(data: &str, mapping: &CsvMapping) -> Result<ParsedImport> {
    if !mapping.is_usable() {
        return Err(import_error("could not find a username or password column"));
    }
    let mut reader = csv_reader(data);
    let mut parsed = ParsedImport::default();
    for row in reader.records() {
        let row = row.map_err(|e| import_error(format!("invalid CSV: {e}")))?;
        let get = |col: Option<usize>| col.and_then(|i| row.get(i)).map(str::trim).unwrap_or("");

        let mut record = Record::new(get(mapping.title));
        record.username = get(mapping.username).to_owned();
        record.password = get(mapping.password).to_owned();
        if let Some(url) = non_empty(Some(get(mapping.url))) {
            record.urls.push(url);
        }
        record.totp = non_empty(Some(get(mapping.totp)));
        record.folder = clean_folder(get(mapping.folder));
        record.favorite = matches!(get(mapping.favorite).to_lowercase().as_str(), "1" | "true" | "yes");
        for line in get(mapping.fields).lines() {
            if let Some((name, value)) = line.split_once(':') {
                record.custom_fields.push(CustomField {
                    name: name.trim().to_owned(),
                    value: value.trim().to_owned(),
                    hidden: false,
                });
            }
        }
        let notes = non_empty(Some(get(mapping.notes)));

        if record.title.is_empty()
            && record.username.is_empty()
            && record.password.is_empty()
            && record.urls.is_empty()
            && notes.is_none()
        {
            parsed.skipped += 1;
            continue;
        }
        finish_title(&mut record);
        let notes =
            notes.map(|n| vec![(DEFAULT_NOTE_TITLE.to_owned(), Zeroizing::new(n))]).unwrap_or_default();
        parsed.items.push(ImportedItem { record, notes });
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------------------------
// Bitwarden JSON
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct BwExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Deserialize)]
struct BwFolder {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct BwItem {
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(rename = "folderId", default)]
    folder_id: Option<String>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
    #[serde(default)]
    login: Option<BwLogin>,
}

#[derive(Deserialize)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type", default)]
    kind: u8,
}

#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

const BW_LOGIN: u8 = 1;
const BW_SECURE_NOTE: u8 = 2;
const BW_FIELD_HIDDEN: u8 = 1;

/// Parses an **unencrypted** Bitwarden JSON export. Logins and secure notes are imported;
/// cards and identities are counted as skipped.
pub fn parse_bitwarden_json(data: &str) -> Result<ParsedImport> {
    let export: BwExport =
        serde_json::from_str(data).map_err(|e| import_error(format!("not a Bitwarden JSON export: {e}")))?;
    if export.encrypted {
        return Err(import_error(
            "encrypted Bitwarden exports are not supported; export as unencrypted JSON",
        ));
    }
    let mut parsed = ParsedImport::default();
    for item in export.items {
        if item.kind != BW_LOGIN && item.kind != BW_SECURE_NOTE {
            parsed.skipped += 1;
            continue;
        }
        let mut record = Record::new(item.name.unwrap_or_default());
        record.favorite = item.favorite;
        record.folder = item
            .folder_id
            .and_then(|id| export.folders.iter().find(|f| f.id == id))
            .map(|f| f.name.clone())
            .unwrap_or_default();
        if let Some(login) = item.login {
            record.username = login.username.unwrap_or_default();
            record.password = login.password.unwrap_or_default();
            record.totp = non_empty(login.totp.as_deref());
            record.urls = login
                .uris
                .unwrap_or_default()
                .into_iter()
                .filter_map(|u| non_empty(u.uri.as_deref()))
                .collect();
        }
        for field in item.fields.unwrap_or_default() {
            record.custom_fields.push(CustomField {
                name: field.name.unwrap_or_default(),
                value: field.value.unwrap_or_default(),
                hidden: field.kind == BW_FIELD_HIDDEN,
            });
        }
        finish_title(&mut record);
        let notes = non_empty(item.notes.as_deref())
            .map(|n| vec![(DEFAULT_NOTE_TITLE.to_owned(), Zeroizing::new(n))])
            .unwrap_or_default();
        parsed.items.push(ImportedItem { record, notes });
    }
    Ok(parsed)
}

/// Detects the format (Bitwarden JSON or any supported CSV) and parses it.
pub fn parse_auto(data: &str) -> Result<ParsedImport> {
    let trimmed = data.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') {
        if trimmed.contains(&format!("\"{EXPORT_FORMAT}\"")) {
            return Err(import_error(
                "this is a Simplus backup; use “Restore backup” and enter its password",
            ));
        }
        return parse_bitwarden_json(trimmed);
    }
    let mapping = CsvMapping::detect(&csv_headers(trimmed)?);
    parse_csv(trimmed, &mapping)
}

// ---------------------------------------------------------------------------------------------
// Encrypted backup (.simplusvault)
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ExportEnvelope {
    format: String,
    version: u32,
    /// Base64 key slot wrapping the payload key under the export password.
    slot: String,
    /// Base64 XChaCha20-Poly1305 ciphertext of [`ExportPayload`].
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct ExportPayload {
    exported_at: chrono::DateTime<Utc>,
    records: Vec<Record>,
    notes: Vec<SecureNote>,
}

/// Decrypts a `.simplusvault` backup into importable items.
pub fn read_encrypted_backup(text: &str, password: &str) -> Result<ParsedImport> {
    let envelope: ExportEnvelope =
        serde_json::from_str(text).map_err(|_| import_error("not a Simplus backup file"))?;
    if envelope.format != EXPORT_FORMAT {
        return Err(import_error("not a Simplus backup file"));
    }
    if envelope.version != EXPORT_VERSION {
        return Err(import_error(format!("unsupported backup version {}", envelope.version)));
    }
    let decode = |s: &str| BASE64.decode(s.as_bytes()).map_err(|_| VaultError::Corrupted);
    let slot = KeySlot::from_bytes(&decode(&envelope.slot)?).map_err(data_error)?;
    let key = slot.open_password(password.as_bytes(), CTX_EXPORT_KEY).map_err(|e| match e {
        simplus_crypto::CryptoError::Decrypt => VaultError::WrongPassword,
        other => data_error(other),
    })?;
    let plain = open_sealed(&key, &decode(&envelope.payload)?, AAD_EXPORT_PAYLOAD).map_err(data_error)?;
    let payload: ExportPayload = serde_json::from_slice(&plain).map_err(|_| VaultError::Corrupted)?;

    let mut items = Vec::with_capacity(payload.records.len());
    for record in payload.records {
        let notes = payload
            .notes
            .iter()
            .filter(|n| n.record_id == record.id)
            .map(|n| (n.title.clone(), Zeroizing::new(n.body.clone())))
            .collect();
        items.push(ImportedItem { record, notes });
    }
    Ok(ParsedImport { items, skipped: 0 })
}

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

impl Vault {
    /// Adds parsed items to the vault in one transaction. Requires the notes password when any
    /// item carries notes; nothing is written if that check fails.
    pub fn import(&mut self, parsed: ParsedImport) -> Result<ImportSummary> {
        let vault_key = self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        let has_notes = parsed.items.iter().any(|i| !i.notes.is_empty());
        let notes_key = match (&self.notes_key, has_notes) {
            (Some(key), _) => Some(key),
            (None, true) => return Err(VaultError::NotesLocked),
            (None, false) => None,
        };

        let now = Utc::now();
        let tx = self.conn.transaction()?;
        let mut summary = ImportSummary::default();
        for item in parsed.items {
            let mut record = item.record;
            record.id = Uuid::now_v7();
            record.updated_at = now;
            finish_title(&mut record);
            let blob = encrypt_item(vault_key, ItemKind::Record, record.id, None, &record)?;
            store::put_item(&tx, ItemKind::Record, record.id, None, 1, now.timestamp_millis(), &blob)?;
            summary.records += 1;

            for (title, body) in item.notes {
                let key = notes_key.expect("checked above");
                let note = SecureNote::new(record.id, title, body.as_str());
                let blob = encrypt_item(key, ItemKind::Note, note.id, Some(record.id), &note)?;
                store::put_item(
                    &tx,
                    ItemKind::Note,
                    note.id,
                    Some(record.id),
                    1,
                    now.timestamp_millis(),
                    &blob,
                )?;
                summary.notes += 1;
            }
        }
        tx.commit()?;
        Ok(summary)
    }

    /// Full encrypted backup (records and secure notes) protected by `password`.
    /// Requires the vault and notes to be unlocked so nothing is silently left out.
    pub fn export_encrypted(&self, password: &str, params: KdfParams) -> Result<String> {
        if password.is_empty() {
            return Err(VaultError::EmptyPassword);
        }
        self.require_notes_key()?;
        let records = self.list_records()?;
        let mut notes = Vec::new();
        for record in &records {
            notes.extend(self.list_notes(record.id)?);
        }
        let payload = ExportPayload { exported_at: Utc::now(), records, notes };
        let plain =
            Zeroizing::new(serde_json::to_vec(&payload).map_err(|e| VaultError::Invalid(e.to_string()))?);

        let key = SecretKey::generate().map_err(VaultError::Crypto)?;
        let slot = KeySlot::seal_password(password.as_bytes(), params, &key, CTX_EXPORT_KEY)
            .map_err(VaultError::Crypto)?;
        let sealed = seal(&key, &plain, AAD_EXPORT_PAYLOAD).map_err(VaultError::Crypto)?;
        let envelope = ExportEnvelope {
            format: EXPORT_FORMAT.into(),
            version: EXPORT_VERSION,
            slot: BASE64.encode(&slot.to_bytes()),
            payload: BASE64.encode(&sealed),
        };
        serde_json::to_string_pretty(&envelope).map_err(|e| VaultError::Invalid(e.to_string()))
    }

    /// **Unencrypted** CSV export (title, username, password, url, totp, folder, notes).
    /// Notes are included only while they are unlocked. The UI must warn before using this.
    pub fn export_csv(&self) -> Result<Zeroizing<String>> {
        let records = self.list_records()?;
        let mut out = Zeroizing::new(String::from("title,username,password,url,totp,folder,notes\n"));
        for record in &records {
            let notes = if self.notes_unlocked() {
                self.list_notes(record.id)?
                    .iter()
                    .map(|n| format!("{}: {}", n.title, n.body))
                    .collect::<Vec<_>>()
                    .join("\n\n")
            } else {
                String::new()
            };
            let cells = [
                record.title.as_str(),
                record.username.as_str(),
                record.password.as_str(),
                record.urls.first().map_or("", String::as_str),
                record.totp.as_deref().unwrap_or(""),
                record.folder.as_str(),
                notes.as_str(),
            ];
            let line: Vec<String> = cells.iter().map(|c| csv_cell(c)).collect();
            out.push_str(&line.join(","));
            out.push('\n');
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_cost_kib: 64, t_cost: 1, p_cost: 1 };

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = Vault::create(&dir.path().join("v.db"), "master pw", "notes pw", FAST).unwrap();
        (dir, vault)
    }

    #[test]
    fn chrome_csv() {
        let data = "name,url,username,password,note\n\
                    github.com,https://github.com/login,octocat,hunter2,\n\
                    ,https://www.example.com/a,bob,pw,\"line1\nline2\"\n";
        let parsed = parse_auto(data).unwrap();
        assert_eq!(parsed.items.len(), 2);
        let first = &parsed.items[0];
        assert_eq!((first.record.title.as_str(), first.record.username.as_str()), ("github.com", "octocat"));
        assert!(first.notes.is_empty());
        let second = &parsed.items[1];
        assert_eq!(second.record.title, "example.com", "title falls back to the URL host");
        assert_eq!(second.notes[0].1.as_str(), "line1\nline2");
    }

    #[test]
    fn firefox_csv() {
        let data = "\u{feff}\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
                    \"https://accounts.example.org:8443\",\"alice\",\"s3cret\",,\"https://accounts.example.org\",\"{x}\",\"1\",\"2\",\"3\"\n";
        let parsed = parse_auto(data).unwrap();
        assert_eq!(parsed.items[0].record.title, "accounts.example.org");
        assert_eq!(parsed.items[0].record.password, "s3cret");
    }

    #[test]
    fn keepassxc_csv() {
        let data = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
                    \"Root/Work\",\"VPN\",\"me\",\"pw\",\"\",\"\",\"otpauth://totp/x?secret=JBSWY3DP\",\"0\",\"\",\"\"\n\
                    \"Root\",\"\",\"\",\"\",\"\",\"\",\"\",\"0\",\"\",\"\"\n";
        let parsed = parse_auto(data).unwrap();
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.skipped, 1, "empty rows are skipped");
        let r = &parsed.items[0].record;
        assert_eq!((r.folder.as_str(), r.title.as_str()), ("Work", "VPN"));
        assert!(r.totp.as_deref().unwrap().starts_with("otpauth://"));
    }

    #[test]
    fn bitwarden_csv() {
        let data = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                    Social,1,login,Twitter,,\"PIN: 1234\nQuestion: blue\",0,https://twitter.com,me,pw,\n";
        let r = &parse_auto(data).unwrap().items[0].record;
        assert!(r.favorite);
        assert_eq!(r.folder, "Social");
        assert_eq!(r.custom_fields.len(), 2);
        assert_eq!(r.custom_fields[1].value, "blue");
    }

    #[test]
    fn unusable_csv_is_rejected() {
        assert!(matches!(parse_auto("a,b\n1,2\n"), Err(VaultError::Import(_))));
    }

    #[test]
    fn bitwarden_json() {
        let data = r#"{
          "encrypted": false,
          "folders": [{"id": "f1", "name": "Banking"}],
          "items": [
            {"id":"1","type":1,"name":"Bank","folderId":"f1","favorite":true,"notes":"PIN hint",
             "fields":[{"name":"Card","value":"4111","type":1}],
             "login":{"uris":[{"uri":"https://bank.example"}],"username":"me","password":"pw","totp":null}},
            {"id":"2","type":2,"name":"Wifi","notes":"psk=abc","secureNote":{"type":0}},
            {"id":"3","type":3,"name":"Visa","card":{}}
          ]
        }"#;
        let parsed = parse_auto(data).unwrap();
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.skipped, 1);
        let bank = &parsed.items[0];
        assert_eq!(bank.record.folder, "Banking");
        assert!(bank.record.custom_fields[0].hidden);
        assert_eq!(bank.notes[0].1.as_str(), "PIN hint");
        assert_eq!(parsed.items[1].notes[0].1.as_str(), "psk=abc");

        assert!(parse_bitwarden_json(r#"{"encrypted": true, "items": []}"#).is_err());
    }

    #[test]
    fn import_requires_notes_key_when_notes_present() {
        let (_dir, mut vault) = vault();
        let parsed = parse_auto("name,username,password,note\nA,u,p,secret note\n").unwrap();
        assert!(matches!(vault.import(parsed), Err(VaultError::NotesLocked)));
        assert!(vault.list_records().unwrap().is_empty(), "nothing written");

        vault.unlock_notes("notes pw").unwrap();
        let parsed = parse_auto("name,username,password,note\nA,u,p,secret note\nB,u2,p2,\n").unwrap();
        let summary = vault.import(parsed).unwrap();
        assert_eq!(summary, ImportSummary { records: 2, notes: 1 });
        let a = vault.list_records().unwrap().into_iter().find(|r| r.title == "A").unwrap();
        assert_eq!(vault.list_notes(a.id).unwrap()[0].body, "secret note");
    }

    #[test]
    fn encrypted_backup_round_trip() {
        let (_dir, mut vault) = vault();
        vault.unlock_notes("notes pw").unwrap();
        let mut r = Record::new("Mail");
        r.password = "pw".into();
        vault.save_record(&mut r).unwrap();
        vault.save_note(&mut SecureNote::new(r.id, "codes", "1-2-3")).unwrap();

        let backup = vault.export_encrypted("backup pw", FAST).unwrap();
        assert!(!backup.contains("1-2-3") && !backup.contains("Mail"));
        assert!(matches!(read_encrypted_backup(&backup, "nope"), Err(VaultError::WrongPassword)));

        let parsed = read_encrypted_backup(&backup, "backup pw").unwrap();
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].notes[0].1.as_str(), "1-2-3");

        let (_dir2, mut other) = self::vault();
        other.unlock_notes("notes pw").unwrap();
        assert_eq!(other.import(parsed).unwrap(), ImportSummary { records: 1, notes: 1 });
        let restored = &other.list_records().unwrap()[0];
        assert_eq!(restored.password, "pw");
        assert_ne!(restored.id, r.id, "imports never reuse ids");

        assert!(matches!(parse_auto(&backup), Err(VaultError::Import(_))), "auto-detect points to restore");
    }

    #[test]
    fn export_requires_notes_unlocked() {
        let (_dir, vault) = vault();
        assert!(matches!(vault.export_encrypted("pw", FAST), Err(VaultError::NotesLocked)));
    }

    #[test]
    fn csv_export_escapes_and_round_trips() {
        let (_dir, mut vault) = vault();
        let mut r = Record::new("Comma, \"quoted\"");
        r.username = "me".into();
        r.password = "p,w".into();
        vault.save_record(&mut r).unwrap();
        let csv = vault.export_csv().unwrap();
        let parsed = parse_auto(&csv).unwrap();
        assert_eq!(parsed.items[0].record.title, "Comma, \"quoted\"");
        assert_eq!(parsed.items[0].record.password, "p,w");
    }

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("https://user@www.a.com:8080/x?y").as_deref(), Some("a.com"));
        assert_eq!(host_of("b.org/path").as_deref(), Some("b.org"));
        assert_eq!(host_of("").as_deref(), None);
    }
}

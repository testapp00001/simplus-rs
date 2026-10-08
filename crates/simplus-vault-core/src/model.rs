use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// How many previous passwords are kept per record.
pub const MAX_PASSWORD_HISTORY: usize = 20;

/// A login entry. Everything in it is encrypted with the vault key.
///
/// Secret fields are wiped from memory when the record is dropped.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub urls: Vec<String>,
    /// Folder name; empty when the record is not in a folder.
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// `otpauth://totp/...` URI or a bare base32 secret.
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// Previous passwords, newest first. Maintained by the vault on save.
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Record {
    pub fn new(title: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            title: title.into(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            folder: String::new(),
            tags: Vec::new(),
            favorite: false,
            totp: None,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Case-insensitive match against title, username, URLs, folder and tags.
    pub fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return true;
        }
        let hit = |s: &str| s.to_lowercase().contains(&query);
        hit(&self.title)
            || hit(&self.username)
            || hit(&self.folder)
            || self.urls.iter().any(|u| hit(u))
            || self.tags.iter().any(|t| hit(t))
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.totp.zeroize();
        for field in &mut self.custom_fields {
            field.value.zeroize();
        }
        for entry in &mut self.password_history {
            entry.password.zeroize();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    /// Masked in the UI like a password.
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: DateTime<Utc>,
}

/// A secure note attached to a record, encrypted with the notes key (second password).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureNote {
    pub id: Uuid,
    pub record_id: Uuid,
    pub title: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SecureNote {
    pub fn new(record_id: Uuid, title: impl Into<String>, body: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            record_id,
            title: title.into(),
            body: body.into(),
            created_at: now,
            updated_at: now,
        }
    }
}

impl Drop for SecureNote {
    fn drop(&mut self) {
        self.title.zeroize();
        self.body.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_matches_relevant_fields() {
        let mut r = Record::new("GitHub");
        r.username = "octocat".into();
        r.urls.push("https://github.com/login".into());
        r.tags.push("Work".into());
        for q in ["git", "OCTO", "github.com", "work", "  "] {
            assert!(r.matches(q), "{q}");
        }
        assert!(!r.matches("gitlab"));
        r.password = "secret-term".into();
        assert!(!r.matches("secret"), "passwords are never searched");
    }

    #[test]
    fn old_json_without_optional_fields_still_parses() {
        let json = r#"{"id":"0190a5e4-0000-7000-8000-000000000000","title":"x",
            "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let r: Record = serde_json::from_str(json).unwrap();
        assert!(r.urls.is_empty() && r.totp.is_none());
    }
}

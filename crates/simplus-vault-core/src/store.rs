//! SQLite persistence for the vault: a key/value `meta` table and one encrypted row per item.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension as _, params};
use simplus_core::db::{self, rusqlite};
use uuid::Uuid;

use crate::{Result, VaultError};

const MIGRATIONS: &[&str] = &[
    "
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value BLOB NOT NULL
    );
    CREATE TABLE items (
        id         TEXT PRIMARY KEY,
        kind       INTEGER NOT NULL,
        parent_id  TEXT,
        revision   INTEGER NOT NULL,
        deleted    INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL,
        blob       BLOB
    );
    CREATE INDEX items_parent ON items (parent_id) WHERE parent_id IS NOT NULL;
",
    "
    -- Sync support: the server sequence number last seen for each item, and whether the
    -- item has local changes that still need to be pushed.
    ALTER TABLE items ADD COLUMN server_seq INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE items ADD COLUMN dirty INTEGER NOT NULL DEFAULT 1;
    CREATE INDEX items_dirty ON items (dirty) WHERE dirty = 1;
    -- Local versions of notes that lost a sync conflict while the notes key was locked.
    CREATE TABLE pending_conflicts (
        id        TEXT PRIMARY KEY,
        parent_id TEXT,
        blob      BLOB NOT NULL
    );
",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ItemKind {
    Record = 1,
    Note = 2,
}

impl ItemKind {
    fn from_i64(value: i64) -> rusqlite::Result<Self> {
        match value {
            1 => Ok(Self::Record),
            2 => Ok(Self::Note),
            other => Err(rusqlite::Error::IntegralValueOutOfRange(1, other)),
        }
    }
}

/// Every column of an item row, including sync state and tombstones.
pub(crate) struct FullRow {
    pub id: Uuid,
    pub kind: ItemKind,
    pub parent_id: Option<Uuid>,
    pub revision: i64,
    pub deleted: bool,
    pub dirty: bool,
    pub server_seq: i64,
    pub updated_at: i64,
    pub blob: Option<Vec<u8>>,
}

/// One row of the `items` table. `blob` is `None` for tombstones.
pub(crate) struct ItemRow {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub blob: Option<Vec<u8>>,
}

pub(crate) fn open(path: &Path) -> Result<Connection> {
    let mut conn = db::open(path)?;
    db::migrate(&mut conn, "vault", MIGRATIONS)?;
    Ok(conn)
}

pub(crate) fn get_meta(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    Ok(conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
}

pub(crate) fn require_meta(conn: &Connection, key: &str) -> Result<Vec<u8>> {
    get_meta(conn, key)?.ok_or(VaultError::Corrupted)
}

pub(crate) fn set_meta(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub(crate) fn delete_meta(conn: &Connection, key: &str) -> Result<()> {
    conn.execute("DELETE FROM meta WHERE key = ?1", [key])?;
    Ok(())
}

fn parse_uuid(s: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&s)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<ItemRow> {
    Ok(ItemRow {
        id: parse_uuid(row.get(0)?)?,
        parent_id: row.get::<_, Option<String>>(1)?.map(parse_uuid).transpose()?,
        blob: row.get(2)?,
    })
}

/// A live (non-deleted) item of the given kind.
pub(crate) fn get_item(conn: &Connection, kind: ItemKind, id: Uuid) -> Result<Option<ItemRow>> {
    Ok(conn
        .query_row(
            "SELECT id, parent_id, blob FROM items WHERE id = ?1 AND kind = ?2 AND deleted = 0",
            params![id.to_string(), kind as i64],
            row_to_item,
        )
        .optional()?)
}

/// Current revision of an item, including tombstones (0 if it never existed).
pub(crate) fn revision(conn: &Connection, id: Uuid) -> Result<i64> {
    Ok(conn
        .query_row("SELECT revision FROM items WHERE id = ?1", [id.to_string()], |r| r.get(0))
        .optional()?
        .unwrap_or(0))
}

pub(crate) fn list_items(conn: &Connection, kind: ItemKind, parent: Option<Uuid>) -> Result<Vec<ItemRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, parent_id, blob FROM items
         WHERE kind = ?1 AND deleted = 0 AND (?2 IS NULL OR parent_id = ?2)",
    )?;
    let rows = stmt.query_map(params![kind as i64, parent.map(|p| p.to_string())], row_to_item)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub(crate) fn count_children(conn: &Connection, parent: Uuid) -> Result<usize> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM items WHERE parent_id = ?1 AND deleted = 0",
        [parent.to_string()],
        |r| r.get(0),
    )?;
    Ok(n as usize)
}

pub(crate) fn put_item(
    conn: &Connection,
    kind: ItemKind,
    id: Uuid,
    parent_id: Option<Uuid>,
    revision: i64,
    updated_at_ms: i64,
    blob: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT INTO items (id, kind, parent_id, revision, deleted, updated_at, blob, dirty)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, 1)
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, parent_id = excluded.parent_id,
             revision = excluded.revision, deleted = 0, updated_at = excluded.updated_at,
             blob = excluded.blob, dirty = 1",
        params![id.to_string(), kind as i64, parent_id.map(|p| p.to_string()), revision, updated_at_ms, blob],
    )?;
    Ok(())
}

/// Replaces an item with a tombstone (kept so a future sync can propagate the deletion).
pub(crate) fn tombstone(conn: &Connection, id: Uuid, updated_at_ms: i64) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE items SET deleted = 1, blob = NULL, revision = revision + 1, updated_at = ?2, dirty = 1
         WHERE id = ?1 AND deleted = 0",
        params![id.to_string(), updated_at_ms],
    )? > 0)
}

// -----------------------------------------------------------------------------------------
// Sync support
// -----------------------------------------------------------------------------------------

const FULL_COLUMNS: &str = "id, kind, parent_id, revision, deleted, dirty, server_seq, updated_at, blob";

fn row_to_full(row: &rusqlite::Row<'_>) -> rusqlite::Result<FullRow> {
    Ok(FullRow {
        id: parse_uuid(row.get(0)?)?,
        kind: ItemKind::from_i64(row.get(1)?)?,
        parent_id: row.get::<_, Option<String>>(2)?.map(parse_uuid).transpose()?,
        revision: row.get(3)?,
        deleted: row.get(4)?,
        dirty: row.get(5)?,
        server_seq: row.get(6)?,
        updated_at: row.get(7)?,
        blob: row.get(8)?,
    })
}

/// Any row with this id, live or tombstone, of any kind.
pub(crate) fn get_full(conn: &Connection, id: Uuid) -> Result<Option<FullRow>> {
    Ok(conn
        .query_row(&format!("SELECT {FULL_COLUMNS} FROM items WHERE id = ?1"), [id.to_string()], row_to_full)
        .optional()?)
}

/// Rows with local changes that have not been pushed yet.
pub(crate) fn dirty_rows(conn: &Connection) -> Result<Vec<FullRow>> {
    let mut stmt =
        conn.prepare(&format!("SELECT {FULL_COLUMNS} FROM items WHERE dirty = 1 ORDER BY kind, id"))?;
    let rows = stmt.query_map([], row_to_full)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Deletions of items the server never saw need no push.
pub(crate) fn clear_unpushed_tombstones(conn: &Connection) -> Result<()> {
    conn.execute("UPDATE items SET dirty = 0 WHERE dirty = 1 AND deleted = 1 AND server_seq = 0", [])?;
    Ok(())
}

/// Records that `revision` of an item was accepted by the server as `seq`. If the item was
/// edited again in the meantime it stays dirty, now based on the new seq.
pub(crate) fn mark_pushed(conn: &Connection, id: Uuid, revision: i64, seq: i64) -> Result<()> {
    conn.execute(
        "UPDATE items SET server_seq = ?2, dirty = CASE WHEN revision = ?3 THEN 0 ELSE dirty END
         WHERE id = ?1",
        params![id.to_string(), seq, revision],
    )?;
    Ok(())
}

/// Moves an item's base to `seq` without touching its content or dirty flag.
pub(crate) fn set_server_seq(conn: &Connection, id: Uuid, seq: i64) -> Result<()> {
    conn.execute("UPDATE items SET server_seq = ?2 WHERE id = ?1", params![id.to_string(), seq])?;
    Ok(())
}

/// Stores the server's version of an item as the clean local state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn put_remote(
    conn: &Connection,
    kind: ItemKind,
    id: Uuid,
    parent_id: Option<Uuid>,
    seq: i64,
    deleted: bool,
    updated_at_ms: i64,
    blob: Option<&[u8]>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO items (id, kind, parent_id, revision, deleted, updated_at, blob, dirty, server_seq)
         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 0, ?7)
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, parent_id = excluded.parent_id,
             revision = revision + 1, deleted = excluded.deleted, updated_at = excluded.updated_at,
             blob = excluded.blob, dirty = 0, server_seq = excluded.server_seq",
        params![
            id.to_string(),
            kind as i64,
            parent_id.map(|p| p.to_string()),
            deleted,
            updated_at_ms,
            blob,
            seq
        ],
    )?;
    Ok(())
}

/// Forgets which server state each item corresponds to, so everything is uploaded again
/// (used when sync is enabled against a new account).
pub(crate) fn reset_sync_state(conn: &Connection) -> Result<()> {
    conn.execute("UPDATE items SET server_seq = 0, dirty = 1", [])?;
    conn.execute("DELETE FROM pending_conflicts", [])?;
    Ok(())
}

pub(crate) fn stash_conflict(
    conn: &Connection,
    id: Uuid,
    parent_id: Option<Uuid>,
    blob: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT INTO pending_conflicts (id, parent_id, blob) VALUES (?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET parent_id = excluded.parent_id, blob = excluded.blob",
        params![id.to_string(), parent_id.map(|p| p.to_string()), blob],
    )?;
    Ok(())
}

/// Stashed note conflicts as `ItemRow`s (id, parent, sealed blob).
pub(crate) fn stashed_conflicts(conn: &Connection) -> Result<Vec<ItemRow>> {
    let mut stmt = conn.prepare("SELECT id, parent_id, blob FROM pending_conflicts")?;
    let rows = stmt.query_map([], row_to_item)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub(crate) fn remove_stashed_conflict(conn: &Connection, id: Uuid) -> Result<()> {
    conn.execute("DELETE FROM pending_conflicts WHERE id = ?1", [id.to_string()])?;
    Ok(())
}

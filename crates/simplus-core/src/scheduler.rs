//! Persistent schedules (cron or fixed interval) that start jobs through the [`JobManager`].
//!
//! Modules register a handler per *job kind* (e.g. `"s3.sync"`); a schedule stores the kind
//! plus an opaque `job_ref` (e.g. the sync job id) that is handed back to the handler.
//!
//! Missed runs (the app was closed or the credential store was locked) are caught up once: a
//! schedule whose `next_run` is in the past is simply due, and after it runs the next
//! occurrence is computed from *now*.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::{DateTime, Local, TimeZone, Utc};
use rusqlite::{Connection, OptionalExtension as _, Row, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db;
use crate::jobs::{JobContext, JobManager, JobState};

/// Shortest allowed interval, to protect remote servers from accidental hammering.
pub const MIN_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScheduleError {
    #[error("invalid cron expression: {0}")]
    InvalidCron(String),
    #[error("interval must be at least {MIN_INTERVAL_SECS} seconds")]
    IntervalTooShort,
    #[error("schedule has no future occurrence")]
    NoNextOccurrence,
}

/// When a schedule fires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScheduleSpec {
    /// Every `every_secs` seconds, measured from the previous run.
    Interval { every_secs: u64 },
    /// Standard cron expression (5 fields, optional leading seconds), in the user's local time.
    Cron { expr: String },
}

impl ScheduleSpec {
    pub fn validate(&self) -> Result<(), ScheduleError> {
        match self {
            Self::Interval { every_secs } if *every_secs < MIN_INTERVAL_SECS => {
                Err(ScheduleError::IntervalTooShort)
            }
            Self::Interval { .. } => Ok(()),
            Self::Cron { expr } => parse_cron(expr).map(|_| ()),
        }
    }

    /// Next occurrence strictly after `after`, evaluating cron expressions in local time.
    pub fn next_after(&self, after: DateTime<Utc>) -> Result<DateTime<Utc>, ScheduleError> {
        self.next_after_in(after, &Local)
    }

    /// Like [`Self::next_after`] with an explicit time zone for cron evaluation.
    pub fn next_after_in<Tz: TimeZone>(
        &self,
        after: DateTime<Utc>,
        tz: &Tz,
    ) -> Result<DateTime<Utc>, ScheduleError> {
        match self {
            Self::Interval { every_secs } => {
                let secs = i64::try_from(*every_secs).map_err(|_| ScheduleError::NoNextOccurrence)?;
                after
                    .checked_add_signed(chrono::Duration::seconds(secs))
                    .ok_or(ScheduleError::NoNextOccurrence)
            }
            Self::Cron { expr } => parse_cron(expr)?
                .find_next_occurrence(&after.with_timezone(tz), false)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| ScheduleError::NoNextOccurrence),
        }
    }

    /// Human-readable description for the UI.
    pub fn describe(&self) -> String {
        match self {
            Self::Interval { every_secs } => match every_secs {
                s if s % 86_400 == 0 => format!("Every {} day(s)", s / 86_400),
                s if s % 3_600 == 0 => format!("Every {} hour(s)", s / 3_600),
                s if s % 60 == 0 => format!("Every {} minute(s)", s / 60),
                s => format!("Every {s} seconds"),
            },
            Self::Cron { expr } => parse_cron(expr).map_or_else(|e| e.to_string(), |c| c.describe()),
        }
    }
}

fn parse_cron(expr: &str) -> Result<croner::Cron, ScheduleError> {
    croner::Cron::from_str(expr).map_err(|e| ScheduleError::InvalidCron(e.to_string()))
}

/// A stored schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleEntry {
    pub id: String,
    pub name: String,
    /// Which registered handler runs this schedule, e.g. `"s3.sync"`.
    pub job_kind: String,
    /// Opaque reference passed to the handler, e.g. a sync job id.
    pub job_ref: String,
    pub spec: ScheduleSpec,
    pub enabled: bool,
    pub next_run: Option<DateTime<Utc>>,
    pub last_run: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
}

const MIGRATIONS: &[&str] = &["CREATE TABLE schedules (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        job_kind    TEXT NOT NULL,
        job_ref     TEXT NOT NULL,
        spec        TEXT NOT NULL,
        enabled     INTEGER NOT NULL DEFAULT 1,
        next_run    INTEGER,
        last_run    INTEGER,
        last_status TEXT
    );
    CREATE INDEX schedules_next_run ON schedules (enabled, next_run);"];

/// SQLite-backed schedule persistence.
pub struct ScheduleStore {
    conn: Mutex<Connection>,
}

impl ScheduleStore {
    pub fn new(mut conn: Connection) -> anyhow::Result<Self> {
        db::migrate(&mut conn, "core.scheduler", MIGRATIONS)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("schedule store poisoned")
    }

    /// Validates and stores a new schedule, computing its first run from `now`.
    pub fn create(
        &self,
        name: &str,
        job_kind: &str,
        job_ref: &str,
        spec: ScheduleSpec,
        now: DateTime<Utc>,
    ) -> anyhow::Result<ScheduleEntry> {
        spec.validate()?;
        let entry = ScheduleEntry {
            id: Uuid::now_v7().to_string(),
            name: name.to_owned(),
            job_kind: job_kind.to_owned(),
            job_ref: job_ref.to_owned(),
            next_run: Some(spec.next_after(now)?),
            spec,
            enabled: true,
            last_run: None,
            last_status: None,
        };
        self.conn().execute(
            "INSERT INTO schedules (id, name, job_kind, job_ref, spec, enabled, next_run)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
            params![
                entry.id,
                entry.name,
                entry.job_kind,
                entry.job_ref,
                serde_json::to_string(&entry.spec)?,
                entry.next_run.map(|t| t.timestamp()),
            ],
        )?;
        Ok(entry)
    }

    pub fn get(&self, id: &str) -> anyhow::Result<Option<ScheduleEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("{SELECT} WHERE id = ?1"))?;
        stmt.query_row([id], from_row).optional()?.transpose()
    }

    pub fn list(&self) -> anyhow::Result<Vec<ScheduleEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("{SELECT} ORDER BY name"))?;
        let rows = stmt.query_map([], from_row)?;
        rows.map(|r| r?).collect()
    }

    /// Enabled schedules whose next run is at or before `now`.
    pub fn due(&self, now: DateTime<Utc>) -> anyhow::Result<Vec<ScheduleEntry>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare(&format!("{SELECT} WHERE enabled = 1 AND next_run <= ?1 ORDER BY next_run"))?;
        let rows = stmt.query_map([now.timestamp()], from_row)?;
        rows.map(|r| r?).collect()
    }

    pub fn remove(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.conn().execute("DELETE FROM schedules WHERE id = ?1", [id])? > 0)
    }

    /// Enables or disables a schedule. Re-enabling computes the next run from `now` so a long
    /// disabled schedule does not fire immediately.
    pub fn set_enabled(&self, id: &str, enabled: bool, now: DateTime<Utc>) -> anyhow::Result<()> {
        let entry = self.get(id)?.ok_or_else(|| anyhow::anyhow!("unknown schedule {id}"))?;
        let next = if enabled { Some(entry.spec.next_after(now)?.timestamp()) } else { None };
        self.conn().execute(
            "UPDATE schedules SET enabled = ?2, next_run = ?3 WHERE id = ?1",
            params![id, enabled, next],
        )?;
        Ok(())
    }

    fn record_start(&self, id: &str, ran_at: DateTime<Utc>, next_run: DateTime<Utc>) -> anyhow::Result<()> {
        self.conn().execute(
            "UPDATE schedules SET last_run = ?2, next_run = ?3 WHERE id = ?1",
            params![id, ran_at.timestamp(), next_run.timestamp()],
        )?;
        Ok(())
    }

    fn record_status(&self, id: &str, status: &str) -> anyhow::Result<()> {
        self.conn().execute("UPDATE schedules SET last_status = ?2 WHERE id = ?1", params![id, status])?;
        Ok(())
    }
}

const SELECT: &str =
    "SELECT id, name, job_kind, job_ref, spec, enabled, next_run, last_run, last_status FROM schedules";

fn from_row(row: &Row<'_>) -> rusqlite::Result<anyhow::Result<ScheduleEntry>> {
    let ts = |secs: Option<i64>| secs.and_then(|s| DateTime::from_timestamp(s, 0));
    let spec = match serde_json::from_str(&row.get::<_, String>(4)?) {
        Ok(spec) => spec,
        Err(e) => return Ok(Err(e.into())),
    };
    Ok(Ok(ScheduleEntry {
        id: row.get(0)?,
        name: row.get(1)?,
        job_kind: row.get(2)?,
        job_ref: row.get(3)?,
        spec,
        enabled: row.get(5)?,
        next_run: ts(row.get(6)?),
        last_run: ts(row.get(7)?),
        last_status: row.get(8)?,
    }))
}

pub type JobFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;
type Handler = Arc<dyn Fn(String, JobContext) -> JobFuture + Send + Sync>;

/// Status strings written to `last_status`.
pub fn status_label(state: &JobState) -> String {
    match state {
        JobState::Running => "running".into(),
        JobState::Succeeded => "succeeded".into(),
        JobState::Cancelled => "cancelled".into(),
        JobState::Failed(e) => format!("failed: {e}"),
    }
}

/// Starts due schedules as jobs.
pub struct Scheduler {
    store: Arc<ScheduleStore>,
    jobs: JobManager,
    handlers: RwLock<HashMap<String, Handler>>,
    paused: AtomicBool,
    active: Arc<Mutex<HashSet<String>>>,
}

impl Scheduler {
    pub fn new(store: Arc<ScheduleStore>, jobs: JobManager) -> Arc<Self> {
        Arc::new(Self {
            store,
            jobs,
            handlers: RwLock::default(),
            paused: AtomicBool::new(false),
            active: Arc::default(),
        })
    }

    pub fn store(&self) -> &Arc<ScheduleStore> {
        &self.store
    }

    /// Registers the code that runs schedules of `kind`. `job_ref` is passed through verbatim.
    pub fn register_handler<F>(&self, kind: impl Into<String>, handler: F)
    where
        F: Fn(String, JobContext) -> JobFuture + Send + Sync + 'static,
    {
        self.handlers.write().expect("handlers poisoned").insert(kind.into(), Arc::new(handler));
    }

    /// While paused (e.g. the credential store is locked) nothing starts; due schedules stay
    /// due and run on the first tick after resuming.
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Starts every due schedule and returns one watcher per started job, resolving to the
    /// job's final state once its status has been recorded.
    pub fn tick(&self, now: DateTime<Utc>) -> anyhow::Result<Vec<JoinHandle<JobState>>> {
        if self.is_paused() {
            return Ok(Vec::new());
        }
        let mut started = Vec::new();
        for entry in self.store.due(now)? {
            let Some(handler) =
                self.handlers.read().expect("handlers poisoned").get(&entry.job_kind).cloned()
            else {
                // The module or plugin providing this kind is not loaded; keep it due.
                tracing::debug!(schedule = %entry.id, kind = %entry.job_kind, "no handler registered");
                continue;
            };
            let next = entry.spec.next_after(now)?;
            self.store.record_start(&entry.id, now, next)?;

            if !self.active.lock().expect("active set poisoned").insert(entry.id.clone()) {
                self.store.record_status(&entry.id, "skipped: previous run still in progress")?;
                continue;
            }

            tracing::info!(schedule = %entry.id, name = %entry.name, "starting scheduled job");
            let job_ref = entry.job_ref.clone();
            let handle = self.jobs.spawn(entry.name.clone(), move |ctx| handler(job_ref, ctx));
            let (store, active, id) = (self.store.clone(), self.active.clone(), entry.id);
            started.push(tokio::spawn(async move {
                let state = handle.wait().await;
                if let Err(e) = store.record_status(&id, &status_label(&state)) {
                    tracing::warn!(schedule = %id, "cannot record schedule status: {e:#}");
                }
                active.lock().expect("active set poisoned").remove(&id);
                state
            }));
        }
        Ok(started)
    }

    /// Runs [`Self::tick`] every `period` until `shutdown` is cancelled.
    pub fn run(self: Arc<Self>, period: Duration, shutdown: CancellationToken) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        if let Err(e) = self.tick(Utc::now()) {
                            tracing::error!("scheduler tick failed: {e:#}");
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn setup() -> (Arc<Scheduler>, Arc<ScheduleStore>) {
        let store = Arc::new(ScheduleStore::new(db::open_in_memory().unwrap()).unwrap());
        let scheduler = Scheduler::new(store.clone(), JobManager::new(tokio::runtime::Handle::current()));
        (scheduler, store)
    }

    #[test]
    fn spec_validation() {
        assert_eq!(ScheduleSpec::Interval { every_secs: 5 }.validate(), Err(ScheduleError::IntervalTooShort));
        assert!(ScheduleSpec::Cron { expr: "not a cron".into() }.validate().is_err());
        assert!(ScheduleSpec::Cron { expr: "*/15 * * * *".into() }.validate().is_ok());
    }

    #[test]
    fn cron_is_evaluated_in_the_given_time_zone() {
        let spec = ScheduleSpec::Cron { expr: "0 3 * * *".into() };
        let after = t("2026-01-01T05:00:00Z");
        assert_eq!(spec.next_after_in(after, &Utc).unwrap(), t("2026-01-02T03:00:00Z"));
        // 03:00 at UTC+7 is 20:00 UTC the previous day.
        let ict = FixedOffset::east_opt(7 * 3600).unwrap();
        assert_eq!(spec.next_after_in(after, &ict).unwrap(), t("2026-01-01T20:00:00Z"));
    }

    #[test]
    fn interval_description() {
        assert_eq!(ScheduleSpec::Interval { every_secs: 7200 }.describe(), "Every 2 hour(s)");
    }

    #[test]
    fn spec_serialises_with_type_tag() {
        let json = serde_json::to_string(&ScheduleSpec::Interval { every_secs: 60 }).unwrap();
        assert_eq!(json, r#"{"type":"interval","every_secs":60}"#);
    }

    #[tokio::test]
    async fn runs_when_due_and_records_status() {
        let (scheduler, store) = setup();
        scheduler.register_handler("test.ok", |job_ref, _| {
            Box::pin(async move {
                assert_eq!(job_ref, "job-1");
                Ok(())
            })
        });
        let t0 = t("2026-01-01T00:00:00Z");
        let entry = store
            .create("Nightly", "test.ok", "job-1", ScheduleSpec::Interval { every_secs: 60 }, t0)
            .unwrap();
        assert_eq!(entry.next_run, Some(t("2026-01-01T00:01:00Z")));

        assert!(scheduler.tick(t0).unwrap().is_empty(), "not due yet");

        let t1 = t("2026-01-01T00:05:00Z"); // several runs missed -> caught up once
        let watchers = scheduler.tick(t1).unwrap();
        assert_eq!(watchers.len(), 1);
        for w in watchers {
            assert_eq!(w.await.unwrap(), JobState::Succeeded);
        }
        let stored = store.get(&entry.id).unwrap().unwrap();
        assert_eq!(stored.last_run, Some(t1));
        assert_eq!(stored.next_run, Some(t("2026-01-01T00:06:00Z")));
        assert_eq!(stored.last_status.as_deref(), Some("succeeded"));
        assert!(scheduler.tick(t1).unwrap().is_empty(), "already advanced");
    }

    #[tokio::test]
    async fn failures_are_recorded() {
        let (scheduler, store) = setup();
        scheduler
            .register_handler("test.fail", |_, _| Box::pin(async { anyhow::bail!("server unreachable") }));
        let t0 = t("2026-01-01T00:00:00Z");
        let e = store.create("Sync", "test.fail", "", ScheduleSpec::Interval { every_secs: 60 }, t0).unwrap();
        for w in scheduler.tick(t("2026-01-01T00:02:00Z")).unwrap() {
            w.await.unwrap();
        }
        assert_eq!(
            store.get(&e.id).unwrap().unwrap().last_status.as_deref(),
            Some("failed: server unreachable")
        );
    }

    #[tokio::test]
    async fn paused_or_unhandled_schedules_stay_due() {
        let (scheduler, store) = setup();
        let t0 = t("2026-01-01T00:00:00Z");
        let later = t("2026-01-01T01:00:00Z");
        store.create("Sync", "test.ok", "", ScheduleSpec::Interval { every_secs: 60 }, t0).unwrap();

        assert!(scheduler.tick(later).unwrap().is_empty(), "no handler yet");
        scheduler.register_handler("test.ok", |_, _| Box::pin(async { Ok(()) }));
        scheduler.set_paused(true);
        assert!(scheduler.tick(later).unwrap().is_empty(), "paused");
        scheduler.set_paused(false);
        assert_eq!(scheduler.tick(later).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn overlapping_runs_are_skipped() {
        let (scheduler, store) = setup();
        scheduler.register_handler("test.slow", |_, _| Box::pin(std::future::pending()));
        let t0 = t("2026-01-01T00:00:00Z");
        let e = store.create("Slow", "test.slow", "", ScheduleSpec::Interval { every_secs: 60 }, t0).unwrap();

        assert_eq!(scheduler.tick(t("2026-01-01T00:01:00Z")).unwrap().len(), 1);
        assert!(scheduler.tick(t("2026-01-01T00:02:00Z")).unwrap().is_empty());
        let stored = store.get(&e.id).unwrap().unwrap();
        assert_eq!(stored.last_status.as_deref(), Some("skipped: previous run still in progress"));
        assert_eq!(stored.next_run, Some(t("2026-01-01T00:03:00Z")));
    }

    #[tokio::test]
    async fn disable_and_reenable() {
        let (scheduler, store) = setup();
        scheduler.register_handler("test.ok", |_, _| Box::pin(async { Ok(()) }));
        let t0 = t("2026-01-01T00:00:00Z");
        let e = store.create("S", "test.ok", "", ScheduleSpec::Interval { every_secs: 60 }, t0).unwrap();
        store.set_enabled(&e.id, false, t0).unwrap();
        assert!(scheduler.tick(t("2026-01-02T00:00:00Z")).unwrap().is_empty());

        let t1 = t("2026-01-03T00:00:00Z");
        store.set_enabled(&e.id, true, t1).unwrap();
        assert_eq!(store.get(&e.id).unwrap().unwrap().next_run, Some(t("2026-01-03T00:01:00Z")));
        assert!(store.remove(&e.id).unwrap());
        assert!(store.list().unwrap().is_empty());
    }
}

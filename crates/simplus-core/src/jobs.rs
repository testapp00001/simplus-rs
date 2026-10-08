//! Background jobs with progress reporting and cancellation.
//!
//! Anything long-running (a sync, a large upload, a scheduled task) runs as a job so the UI can
//! show it in the Tasks panel, report progress and let the user cancel it.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use tokio::runtime::Handle;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub type JobId = Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobState {
    Running,
    Succeeded,
    Failed(String),
    Cancelled,
}

impl JobState {
    pub fn is_finished(&self) -> bool {
        !matches!(self, Self::Running)
    }
}

/// Point-in-time view of a job, broadcast to subscribers on every change.
#[derive(Clone, Debug)]
pub struct JobSnapshot {
    pub id: JobId,
    pub name: String,
    pub state: JobState,
    /// Completion fraction in `0.0..=1.0`, if the job reports one.
    pub progress: Option<f32>,
    pub message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

struct Entry {
    snapshot: JobSnapshot,
    cancel: CancellationToken,
}

struct Inner {
    runtime: Handle,
    jobs: Mutex<HashMap<JobId, Entry>>,
    events: broadcast::Sender<JobSnapshot>,
}

impl Inner {
    fn update(&self, id: JobId, f: impl FnOnce(&mut JobSnapshot)) {
        let snapshot = {
            let mut jobs = self.jobs.lock().expect("job table poisoned");
            let Some(entry) = jobs.get_mut(&id) else {
                return;
            };
            f(&mut entry.snapshot);
            entry.snapshot.clone()
        };
        // No subscribers is fine.
        let _ = self.events.send(snapshot);
    }
}

/// Handed to every job: lets it report progress and observe cancellation.
#[derive(Clone)]
pub struct JobContext {
    id: JobId,
    cancel: CancellationToken,
    inner: Arc<Inner>,
}

impl JobContext {
    pub fn id(&self) -> JobId {
        self.id
    }

    /// Reports progress (`fraction` is clamped to `0.0..=1.0`) and a status line.
    pub fn progress(&self, fraction: f32, message: impl Into<String>) {
        let message = message.into();
        self.inner.update(self.id, |s| {
            s.progress = Some(fraction.clamp(0.0, 1.0));
            s.message = Some(message);
        });
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Token for cooperative cancellation inside the job (e.g. between file transfers).
    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancel
    }
}

/// A spawned job. Dropping the handle does not cancel the job.
pub struct JobHandle {
    pub id: JobId,
    join: JoinHandle<JobState>,
}

impl JobHandle {
    /// Waits for the job to finish and returns its final state.
    pub async fn wait(self) -> JobState {
        self.join.await.unwrap_or_else(|e| JobState::Failed(format!("job panicked: {e}")))
    }
}

/// Spawns, tracks and cancels jobs on a tokio runtime. Cheap to clone.
#[derive(Clone)]
pub struct JobManager {
    inner: Arc<Inner>,
}

impl JobManager {
    pub fn new(runtime: Handle) -> Self {
        let (events, _) = broadcast::channel(256);
        Self { inner: Arc::new(Inner { runtime, jobs: Mutex::default(), events }) }
    }

    /// Starts a job. The future is dropped as soon as the job is cancelled; long-running work
    /// should additionally check [`JobContext::is_cancelled`] at safe points.
    pub fn spawn<F, Fut>(&self, name: impl Into<String>, job: F) -> JobHandle
    where
        F: FnOnce(JobContext) -> Fut,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let id = Uuid::now_v7();
        let cancel = CancellationToken::new();
        let snapshot = JobSnapshot {
            id,
            name: name.into(),
            state: JobState::Running,
            progress: None,
            message: None,
            started_at: Utc::now(),
            finished_at: None,
        };
        self.inner
            .jobs
            .lock()
            .expect("job table poisoned")
            .insert(id, Entry { snapshot: snapshot.clone(), cancel: cancel.clone() });
        let _ = self.inner.events.send(snapshot);

        let ctx = JobContext { id, cancel: cancel.clone(), inner: self.inner.clone() };
        let fut = job(ctx);
        let inner = self.inner.clone();
        let join = self.inner.runtime.spawn(async move {
            let state = tokio::select! {
                biased;
                _ = cancel.cancelled() => JobState::Cancelled,
                result = fut => match result {
                    Ok(()) => JobState::Succeeded,
                    Err(e) => JobState::Failed(format!("{e:#}")),
                },
            };
            inner.update(id, |s| {
                s.state = state.clone();
                s.finished_at = Some(Utc::now());
                if state == JobState::Succeeded {
                    s.progress = Some(1.0);
                }
            });
            state
        });
        JobHandle { id, join }
    }

    /// Requests cancellation. Returns `false` if the job is unknown or already finished.
    pub fn cancel(&self, id: JobId) -> bool {
        let jobs = self.inner.jobs.lock().expect("job table poisoned");
        match jobs.get(&id) {
            Some(entry) if !entry.snapshot.state.is_finished() => {
                entry.cancel.cancel();
                true
            }
            _ => false,
        }
    }

    pub fn snapshot(&self, id: JobId) -> Option<JobSnapshot> {
        self.inner.jobs.lock().expect("job table poisoned").get(&id).map(|e| e.snapshot.clone())
    }

    /// All known jobs, newest first.
    pub fn list(&self) -> Vec<JobSnapshot> {
        let mut all: Vec<_> = self
            .inner
            .jobs
            .lock()
            .expect("job table poisoned")
            .values()
            .map(|e| e.snapshot.clone())
            .collect();
        all.sort_by(|a, b| b.started_at.cmp(&a.started_at).then(b.id.cmp(&a.id)));
        all
    }

    /// Removes finished jobs from the list.
    pub fn clear_finished(&self) {
        self.inner.jobs.lock().expect("job table poisoned").retain(|_, e| !e.snapshot.state.is_finished());
    }

    /// Receives a snapshot every time any job changes.
    pub fn subscribe(&self) -> broadcast::Receiver<JobSnapshot> {
        self.inner.events.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> JobManager {
        JobManager::new(Handle::current())
    }

    #[tokio::test]
    async fn success_and_progress() {
        let jobs = manager();
        let mut events = jobs.subscribe();
        let handle = jobs.spawn("copy", |ctx| async move {
            ctx.progress(0.5, "halfway");
            Ok(())
        });
        let id = handle.id;
        assert_eq!(handle.wait().await, JobState::Succeeded);

        let snap = jobs.snapshot(id).unwrap();
        assert_eq!(snap.progress, Some(1.0));
        assert_eq!(snap.message.as_deref(), Some("halfway"));
        assert!(snap.finished_at.is_some());

        let seen: Vec<_> = std::iter::from_fn(|| events.try_recv().ok()).collect();
        assert_eq!(seen.first().unwrap().state, JobState::Running);
        assert!(seen.iter().any(|s| s.progress == Some(0.5)));
        assert_eq!(seen.last().unwrap().state, JobState::Succeeded);
    }

    #[tokio::test]
    async fn failure_keeps_error_chain() {
        let jobs = manager();
        let handle =
            jobs.spawn("broken", |_| async { Err(anyhow::anyhow!("disk full").context("upload failed")) });
        assert_eq!(handle.wait().await, JobState::Failed("upload failed: disk full".into()));
    }

    #[tokio::test]
    async fn cancel_stops_a_pending_job() {
        let jobs = manager();
        let handle = jobs.spawn("forever", |_| std::future::pending());
        assert!(jobs.cancel(handle.id));
        let id = handle.id;
        assert_eq!(handle.wait().await, JobState::Cancelled);
        assert!(!jobs.cancel(id), "finished jobs cannot be cancelled");
    }

    #[tokio::test]
    async fn clear_finished_keeps_running_jobs() {
        let jobs = manager();
        jobs.spawn("done", |_| async { Ok(()) }).wait().await;
        let running = jobs.spawn("running", |_| std::future::pending());
        jobs.clear_finished();
        let list = jobs.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, running.id);
    }
}

//! Shared services used by the Simplus shell, official modules and (through the plugin host)
//! community plugins: filesystem locations, configuration, SQLite storage with migrations,
//! logging, background jobs and scheduling.

pub mod config;
pub mod db;
pub mod jobs;
pub mod logging;
pub mod paths;
pub mod scheduler;

pub use config::AppConfig;
pub use jobs::{JobContext, JobHandle, JobId, JobManager, JobSnapshot, JobState};
pub use paths::AppPaths;
pub use scheduler::{ScheduleEntry, ScheduleSpec, ScheduleStore, Scheduler};

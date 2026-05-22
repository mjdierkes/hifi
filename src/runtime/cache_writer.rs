//! Runtime boundary for best-effort cache writes.
//!
//! The cache layer decides what should be persisted; this module decides how to
//! schedule that blocking filesystem work without stalling fetch/scan progress.

#[cfg(not(test))]
use std::{
    sync::{
        mpsc::{sync_channel, SyncSender, TrySendError},
        OnceLock,
    },
    thread,
};

#[cfg(not(test))]
const CACHE_WRITE_QUEUE: usize = 1024;

#[cfg(not(test))]
type Job = Box<dyn FnOnce() + Send + 'static>;

pub fn defer(write: impl FnOnce() + Send + 'static) {
    #[cfg(test)]
    {
        write();
    }
    #[cfg(not(test))]
    match worker().try_send(Box::new(write)) {
        Ok(()) => {}
        Err(TrySendError::Full(job)) => defer_overflow(job),
        Err(TrySendError::Disconnected(job)) => job(),
    }
}

#[cfg(not(test))]
fn worker() -> &'static SyncSender<Job> {
    static WORKER: OnceLock<SyncSender<Job>> = OnceLock::new();
    WORKER.get_or_init(|| {
        let (tx, rx) = sync_channel::<Job>(CACHE_WRITE_QUEUE);
        thread::Builder::new()
            .name("hifi-cache-writer".to_string())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    job();
                }
            })
            .expect("cache writer thread");
        tx
    })
}

#[cfg(not(test))]
fn defer_overflow(job: Job) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn_blocking(job);
    } else {
        job();
    }
}

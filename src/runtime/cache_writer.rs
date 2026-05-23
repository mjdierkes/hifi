//! Runtime boundary for best-effort cache writes.
//!
//! The cache layer decides what should be persisted; this module decides how to
//! schedule that blocking filesystem work without stalling fetch/scan progress.

#[cfg(not(test))]
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{sync_channel, SyncSender, TrySendError},
        OnceLock,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(not(test))]
const CACHE_WRITE_QUEUE: usize = 1024;

#[cfg(not(test))]
type Job = Box<dyn FnOnce() + Send + 'static>;

#[cfg(not(test))]
static PENDING: AtomicUsize = AtomicUsize::new(0);

pub fn defer(write: impl FnOnce() + Send + 'static) {
    #[cfg(test)]
    {
        write();
    }
    #[cfg(not(test))]
    {
        PENDING.fetch_add(1, Ordering::SeqCst);
        let job: Job = Box::new(move || {
            write();
            PENDING.fetch_sub(1, Ordering::SeqCst);
        });
        match worker().try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(job)) => defer_overflow(job),
            Err(TrySendError::Disconnected(job)) => {
                job();
            }
        }
    }
}

pub fn flush(timeout: std::time::Duration) {
    #[cfg(test)]
    {
        let _ = timeout;
    }
    #[cfg(not(test))]
    {
        let deadline = Instant::now() + timeout;
        while PENDING.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
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

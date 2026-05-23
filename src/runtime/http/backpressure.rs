use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Shared load signal used to tune HTTP/2 flow-control generosity.
pub struct Backpressure {
    inflight: AtomicUsize,
    capacity: AtomicUsize,
}

impl Backpressure {
    pub fn new(capacity: usize) -> Self {
        Self {
            inflight: AtomicUsize::new(0),
            capacity: AtomicUsize::new(capacity.max(1)),
        }
    }

    pub fn enter(self: &Arc<Self>) -> InflightGuard {
        self.inflight.fetch_add(1, Ordering::Relaxed);
        InflightGuard(self.clone())
    }

    pub fn set_capacity(&self, capacity: usize) {
        self.capacity.store(capacity.max(1), Ordering::Relaxed);
    }

    pub(crate) fn generosity(&self) -> f32 {
        let cap = self.capacity.load(Ordering::Relaxed).max(1) as f32;
        let inflight = self.inflight.load(Ordering::Relaxed) as f32;
        let pressure = (inflight / cap).clamp(0.0, 1.5);
        (1.0 - pressure * 0.5).clamp(0.25, 1.0)
    }
}

impl Default for Backpressure {
    fn default() -> Self {
        Self::new(256)
    }
}

pub struct InflightGuard(Arc<Backpressure>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backpressure_generosity_shrinks_under_load() {
        let bp = Arc::new(Backpressure::new(4));
        let full = bp.generosity();
        let _g1 = bp.enter();
        let _g2 = bp.enter();
        let _g3 = bp.enter();
        let _g4 = bp.enter();
        let loaded = bp.generosity();
        assert!(loaded < full);
        assert!(loaded >= 0.25);
    }
}

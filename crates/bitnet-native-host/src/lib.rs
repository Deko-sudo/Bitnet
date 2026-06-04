// bitnet-native-host
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Simple sliding-window rate limiter: max N messages per second.
/// Tracks seconds elapsed since this limiter was constructed (via `start`).
pub struct RateLimiter {
    start: Instant,
    window_start: AtomicU64, // seconds since `start` when current window opened
    count: AtomicU64,
    max_per_sec: u64,
}

impl RateLimiter {
    pub fn new(max_per_sec: u64) -> Self {
        Self {
            start: Instant::now(),
            window_start: AtomicU64::new(0),
            count: AtomicU64::new(0),
            max_per_sec,
        }
    }

    pub fn check(&self) -> bool {
        let now_sec = self.start.elapsed().as_secs();
        let stored = self.window_start.load(Ordering::Relaxed);
        if now_sec != stored {
            self.window_start.store(now_sec, Ordering::Relaxed);
            self.count.store(1, Ordering::Relaxed);
            return true;
        }
        let current = self.count.fetch_add(1, Ordering::Relaxed);
        current < self.max_per_sec
    }
}

pub fn init() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_blocks_overflow() {
        // Bug C-001 regression: Instant::now().elapsed() always returned 0,
        // so the limiter never blocked anything. The fix captures start in
        // new() and uses self.start.elapsed() instead.
        let rl = RateLimiter::new(3);
        assert!(rl.check(), "1st request must pass");
        assert!(rl.check(), "2nd request must pass");
        assert!(rl.check(), "3rd request must pass");
        assert!(!rl.check(), "4th request in same second must be blocked");
        assert!(!rl.check(), "5th request in same second must be blocked");
    }

    #[test]
    fn test_rate_limiter_max_one() {
        let rl = RateLimiter::new(1);
        assert!(rl.check());
        assert!(!rl.check());
    }
}

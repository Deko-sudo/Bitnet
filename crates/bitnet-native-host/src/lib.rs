// bitnet-native-host
//
// Rate limiter hardened against TOCTOU/data-race [BITNET-M1]:
// replaces lock-free AtomicU64 with a plain Mutex<RateState>. The
// critical section is just a few integer ops, so the lock overhead
// is negligible. Memory ordering on a Mutex is well-defined and the
// state is now race-free by construction.
use std::sync::Mutex;
use std::time::Instant;

struct RateState {
    window_start: u64, // seconds since `start` when current window opened
    count: u64,
}

/// Sliding-window rate limiter: max N messages per second.
pub struct RateLimiter {
    start: Instant,
    state: Mutex<RateState>,
    max_per_sec: u64,
}

impl RateLimiter {
    pub fn new(max_per_sec: u64) -> Self {
        Self {
            start: Instant::now(),
            state: Mutex::new(RateState {
                window_start: 0,
                count: 0,
            }),
            max_per_sec,
        }
    }

    pub fn check(&self) -> bool {
        let now_sec = self.start.elapsed().as_secs();
        let mut s = self.state.lock().expect("RateLimiter mutex poisoned");
        if now_sec != s.window_start {
            s.window_start = now_sec;
            s.count = 1;
            return true;
        }
        s.count += 1;
        s.count <= self.max_per_sec
    }
}

pub fn init() {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

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

    /// [BITNET-M1] Regression test for the data race that allowed N*M
    /// messages to slip through when M threads called `check()`
    /// simultaneously. After the fix (Mutex-backed state), the limit
    /// holds even with concurrent callers.
    #[test]
    fn test_rate_limiter_concurrent_caps_at_max() {
        let rl = Arc::new(RateLimiter::new(50));
        let mut handles = vec![];
        for _ in 0..16 {
            let rl = Arc::clone(&rl);
            handles.push(thread::spawn(move || {
                let mut allowed = 0u64;
                for _ in 0..100 {
                    if rl.check() {
                        allowed += 1;
                    }
                }
                allowed
            }));
        }
        let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        // All 16 threads run within the same wall-clock second, so
        // the limiter must never admit more than 50 calls in total.
        assert!(
            total <= 50,
            "rate limiter let through {total} calls in one second (max=50)"
        );
    }
}

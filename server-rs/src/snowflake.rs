use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Verdant epoch: 2025-01-01T00:00:00Z (same as TypeScript implementation).
const VERDANT_EPOCH_MS: u64 = 1_735_689_600_000;

/// Generates unique Snowflake IDs.
///
/// Layout (64 bits):
///   - 42 bits: milliseconds since Verdant epoch (~139 years)
///   - 10 bits: worker ID (0–1023)
///   - 12 bits: sequence (0–4095 per ms per worker)
pub struct SnowflakeGenerator {
    worker_id: u64,
    state: AtomicU64, // packed: upper 42 = last_ms, lower 12 = sequence
}

impl SnowflakeGenerator {
    pub fn new(worker_id: u16) -> Self {
        assert!(worker_id < 1024, "worker_id must be 0–1023");
        Self {
            worker_id: worker_id as u64,
            state: AtomicU64::new(0),
        }
    }

    /// Generate the next Snowflake ID.
    pub fn next_id(&self) -> i64 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock went backwards")
            .as_millis() as u64;
        let timestamp = now_ms.saturating_sub(VERDANT_EPOCH_MS);

        loop {
            let prev = self.state.load(Ordering::Relaxed);
            let prev_ts = prev >> 12;
            let seq = if prev_ts == timestamp {
                (prev & 0xFFF) + 1
            } else {
                0
            };

            if seq > 4095 {
                // Exhausted sequence for this ms — spin until next ms.
                std::hint::spin_loop();
                continue;
            }

            let new_state = (timestamp << 12) | seq;
            if self
                .state
                .compare_exchange_weak(prev, new_state, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let id = (timestamp << 22) | (self.worker_id << 12) | seq;
                return id as i64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_ascending() {
        let sf = SnowflakeGenerator::new(0);
        let mut prev = 0i64;
        for _ in 0..1000 {
            let id = sf.next_id();
            assert!(id > prev, "IDs must be ascending");
            prev = id;
        }
    }

    #[test]
    fn id_is_positive() {
        let sf = SnowflakeGenerator::new(1);
        let id = sf.next_id();
        assert!(id > 0);
    }
}

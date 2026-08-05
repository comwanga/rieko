use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::sink::{Alert, AlertError, AlertSink};

/// Wraps another sink and suppresses repeats of the same alert within a
/// cooldown window. This is the D9 alert-fatigue guard: a bot that repeats
/// gets muted, and a muted bot fails silently during the incident it exists
/// to surface.
pub struct DedupingSink<S> {
    inner: S,
    cooldown: Duration,
    last_sent: HashMap<String, Instant>,
    sent_count: u64,
}

impl<S> DedupingSink<S> {
    pub fn new(inner: S, cooldown: Duration) -> Self {
        Self {
            inner,
            cooldown,
            last_sent: HashMap::new(),
            sent_count: 0,
        }
    }

    pub fn sent_count(&self) -> u64 {
        self.sent_count
    }
}

impl<S: AlertSink> AlertSink for DedupingSink<S> {
    fn send(&mut self, alert: &Alert) -> Result<(), AlertError> {
        if let Some(last) = self.last_sent.get(&alert.dedup_key) {
            if last.elapsed() < self.cooldown {
                // Deduped. Do not forward; treat as success.
                return Ok(());
            }
        }
        self.inner.send(alert)?;
        self.last_sent
            .insert(alert.dedup_key.clone(), Instant::now());
        self.sent_count += 1;
        Ok(())
    }
}

/// Alias matching the ADR terminology.
pub type AlertCooldown<S> = DedupingSink<S>;

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    struct RecordingSink {
        sent: RefCell<Vec<String>>,
    }

    impl AlertSink for RecordingSink {
        fn send(&mut self, alert: &Alert) -> Result<(), AlertError> {
            self.sent.borrow_mut().push(alert.dedup_key.clone());
            Ok(())
        }
    }

    fn alert(key: &str) -> Alert {
        Alert {
            dedup_key: key.into(),
            severity: rieko_findings::Severity::Warning,
            title: "t".into(),
            message: "m".into(),
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn deduplicates_within_cooldown() {
        let inner = RecordingSink {
            sent: RefCell::new(Vec::new()),
        };
        let mut sink = DedupingSink::new(inner, Duration::from_secs(60));
        sink.send(&alert("a|1")).unwrap();
        sink.send(&alert("a|1")).unwrap();
        sink.send(&alert("a|1")).unwrap();
        sink.send(&alert("b|2")).unwrap();
        assert_eq!(sink.sent_count(), 2);
    }

    #[test]
    fn re_sends_after_cooldown() {
        let inner = RecordingSink {
            sent: RefCell::new(Vec::new()),
        };
        let mut sink = DedupingSink::new(inner, Duration::from_millis(1));
        sink.send(&alert("a|1")).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        sink.send(&alert("a|1")).unwrap();
        assert_eq!(sink.sent_count(), 2);
    }
}

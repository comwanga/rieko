pub mod dedup;
pub mod sink;
pub mod state;
pub mod telegram;

pub use dedup::{AlertCooldown, DedupingSink, PersistentAlertCooldown, PersistentDedupingSink};
pub use sink::{Alert, AlertError, AlertSink};
pub use state::{AlertState, AlertStateStore, DeliveryOutcome, DeliveryStatus};
pub use telegram::TelegramSink;

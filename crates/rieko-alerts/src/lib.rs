pub mod dedup;
pub mod sink;
pub mod telegram;

pub use dedup::{AlertCooldown, DedupingSink};
pub use sink::{Alert, AlertError, AlertSink};
pub use telegram::TelegramSink;

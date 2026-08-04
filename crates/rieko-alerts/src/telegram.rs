use crate::sink::{Alert, AlertError, AlertSink};

/// Telegram bot sink. Configure via `RIEKO_TELEGRAM_TOKEN` and
/// `RIEKO_TELEGRAM_CHAT_ID`. Unconfigured, it refuses loudly rather than
/// silently dropping alerts.
pub struct TelegramSink {
    token: String,
    chat_id: String,
    client: reqwest::blocking::Client,
}

impl TelegramSink {
    pub fn from_env() -> Result<Self, AlertError> {
        let token = std::env::var("RIEKO_TELEGRAM_TOKEN")
            .map_err(|_| AlertError::Sink("RIEKO_TELEGRAM_TOKEN not set".into()))?;
        let chat_id = std::env::var("RIEKO_TELEGRAM_CHAT_ID")
            .map_err(|_| AlertError::Sink("RIEKO_TELEGRAM_CHAT_ID not set".into()))?;
        Ok(Self {
            token,
            chat_id,
            client: reqwest::blocking::Client::new(),
        })
    }

    pub fn new(token: impl Into<String>, chat_id: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            chat_id: chat_id.into(),
            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn is_configured() -> bool {
        std::env::var("RIEKO_TELEGRAM_TOKEN").is_ok()
            && std::env::var("RIEKO_TELEGRAM_CHAT_ID").is_ok()
    }
}

impl AlertSink for TelegramSink {
    fn send(&mut self, alert: &Alert) -> Result<(), AlertError> {
        let emoji = match alert.severity {
            rieko_findings::Severity::Critical => "🚨",
            rieko_findings::Severity::Warning => "⚠️",
            rieko_findings::Severity::Info => "ℹ️",
        };
        let text = format!(
            "{emoji} *{title}*\n\n{message}\n\n`{key}`",
            title = alert.title,
            message = alert.message,
            key = alert.dedup_key,
        );
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        let resp = self
            .client
            .post(url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown",
            }))
            .send()?;
        let status = resp.status();
        if !status.is_success() {
            return Err(AlertError::Sink(format!("telegram returned {status}")));
        }
        Ok(())
    }
}

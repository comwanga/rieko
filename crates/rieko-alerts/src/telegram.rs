use std::time::Duration;

use crate::sink::{Alert, AlertError, AlertSink};
use crate::state::DeliveryOutcome;

/// Default Telegram Bot API base URL. Overridable for tests / self-hosted
/// proxies via [`TelegramSink::with_endpoint`].
pub const TELEGRAM_API_BASE: &str = "https://api.telegram.org";
/// Telegram rejects messages over 4096 UTF-16 code units. We truncate well
/// below that so Markdown markup can never push a message over the wire limit.
pub const MAX_MESSAGE_UTF16: usize = 4000;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_ATTEMPTS: u32 = 3;
const DEFAULT_BASE_BACKOFF: Duration = Duration::from_millis(500);

/// A bounded retry policy. `base_backoff` doubles per attempt, and there is
/// always a finite `max_attempts` — Telegram can never block the loop
/// indefinitely (RIEKO-AUDIT-013).
#[derive(Debug, Clone, Copy)]
struct RetryPolicy {
    max_attempts: u32,
    base_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            base_backoff: DEFAULT_BASE_BACKOFF,
        }
    }
}

/// Telegram bot sink. Configure via `RIEKO_TELEGRAM_TOKEN` and
/// `RIEKO_TELEGRAM_CHAT_ID`. Unconfigured, it refuses loudly rather than
/// silently dropping alerts.
///
/// Hardening (RIEKO-AUDIT-013): every request runs under a finite timeout with
/// a bounded retry/backoff policy; untrusted fields are escaped for Telegram's
/// Markdown parse mode and the message is truncated within Telegram limits; the
/// bot token never appears in any error or log (secrets are redacted); a
/// delivery failure never blocks or invalidates detection/persistence (callers
/// persist first).
pub struct TelegramSink {
    token: String,
    chat_id: String,
    endpoint: String,
    client: reqwest::blocking::Client,
    retry: RetryPolicy,
}

impl TelegramSink {
    pub fn from_env() -> Result<Self, AlertError> {
        let token = std::env::var("RIEKO_TELEGRAM_TOKEN")
            .map_err(|_| AlertError::Sink("RIEKO_TELEGRAM_TOKEN not set".into()))?;
        let chat_id = std::env::var("RIEKO_TELEGRAM_CHAT_ID")
            .map_err(|_| AlertError::Sink("RIEKO_TELEGRAM_CHAT_ID not set".into()))?;
        Ok(Self::new(token, chat_id))
    }

    pub fn new(token: impl Into<String>, chat_id: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            chat_id: chat_id.into(),
            endpoint: TELEGRAM_API_BASE.to_string(),
            client: Self::build_client(DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT),
            retry: RetryPolicy::default(),
        }
    }

    pub fn is_configured() -> bool {
        std::env::var("RIEKO_TELEGRAM_TOKEN").is_ok()
            && std::env::var("RIEKO_TELEGRAM_CHAT_ID").is_ok()
    }

    /// Override the API base URL (used by tests against a local HTTP server).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Override connection/request timeouts (used by tests to keep them fast).
    pub fn with_timeouts(mut self, connect: Duration, request: Duration) -> Self {
        self.client = Self::build_client(connect, request);
        self
    }

    /// Override the bounded retry policy (used by tests to disable backoff).
    pub fn with_retry(mut self, max_attempts: u32, base_backoff: Duration) -> Self {
        self.retry = RetryPolicy {
            max_attempts: max_attempts.max(1),
            base_backoff,
        };
        self
    }

    fn build_client(connect: Duration, request: Duration) -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .connect_timeout(connect)
            .timeout(request)
            .build()
            .expect("reqwest client builder is infallible with fixed config")
    }

    /// One attempt. Retryable failures are transport problems (incl. timeout)
    /// and HTTP 5xx; client errors (4xx) and malformed responses are permanent.
    fn send_once(&self, url: &str, payload: &serde_json::Value) -> Result<(), AttemptOutcome> {
        let resp = self.client.post(url).json(payload).send().map_err(|e| {
            AttemptOutcome::Retry(format!(
                "telegram transport error: {}",
                sanitize(&e, &self.token)
            ))
        })?;
        let status = resp.status();
        if status.is_server_error() {
            return Err(AttemptOutcome::Retry(format!("telegram returned {status}")));
        }
        if !status.is_success() {
            return Err(AttemptOutcome::Permanent(format!(
                "telegram returned {status}"
            )));
        }
        // Telegram answers 200 with `{"ok": true}`; anything else is malformed.
        match resp.json::<serde_json::Value>() {
            Ok(body) if body.get("ok").and_then(serde_json::Value::as_bool) == Some(true) => Ok(()),
            Ok(_) => Err(AttemptOutcome::Permanent(
                "telegram responded without ok=true".into(),
            )),
            Err(_) => Err(AttemptOutcome::Permanent(
                "telegram returned a non-JSON response".into(),
            )),
        }
    }

    fn send_with_retry(&self, url: &str, payload: &serde_json::Value) -> Result<(), AlertError> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.send_once(url, payload) {
                Ok(()) => return Ok(()),
                Err(AttemptOutcome::Permanent(msg)) => {
                    return Err(AlertError::Sink(msg));
                }
                Err(AttemptOutcome::Retry(msg)) if attempt >= self.retry.max_attempts => {
                    return Err(AlertError::Sink(format!(
                        "{msg} (after {attempt} attempts)"
                    )));
                }
                Err(AttemptOutcome::Retry(_)) => {
                    let delay = self.retry.base_backoff * (1u32 << (attempt - 1)).min(1 << 30);
                    std::thread::sleep(delay);
                }
            }
        }
    }

    fn build_text(&self, alert: &Alert) -> String {
        let emoji = match alert.severity {
            rieko_findings::Severity::Critical => "🚨",
            rieko_findings::Severity::Warning => "⚠️",
            rieko_findings::Severity::Info => "ℹ️",
        };
        let text = format!(
            "{emoji} *{title}*\n\n{message}\n\n`{key}`",
            title = escape_markdown(&alert.title),
            message = escape_markdown(&alert.message),
            key = escape_markdown(&alert.dedup_key),
        );
        truncate_utf16(&text, MAX_MESSAGE_UTF16)
    }
}

impl AlertSink for TelegramSink {
    fn send(&mut self, alert: &Alert) -> Result<DeliveryOutcome, AlertError> {
        let text = self.build_text(alert);
        let url = format!("{}/bot{}/sendMessage", self.endpoint, self.token);
        let payload = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
        });
        self.send_with_retry(&url, &payload)
            .map(|()| DeliveryOutcome::Delivered)
    }
}

/// Never let a transport error echo the token or the request URL back into
/// logs. reqwest error messages can include the URL, which contains the bot
/// token, so they are replaced with a generic description (RIEKO-AUDIT-013).
fn sanitize(e: &reqwest::Error, _secret: &str) -> String {
    // Deliberately ignore the underlying message: it can embed the URL.
    if e.is_timeout() {
        "request timed out".into()
    } else if e.is_connect() {
        "connection failed".into()
    } else if e.is_request() {
        "request construction failed".into()
    } else {
        "unreachable or protocol error".into()
    }
}

/// Escape the characters that can restructure Telegram MarkdownV1 output so
/// untrusted fields (title, message, dedup key) cannot break the message
/// format or forge links (RIEKO-AUDIT-013).
fn escape_markdown(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

/// Truncate to a maximum number of UTF-16 code units (Telegram's limit is
/// measured in UTF-16 units, not bytes or chars), appending `…` when cut.
fn truncate_utf16(s: &str, max_units: usize) -> String {
    let total: usize = s.chars().map(|c| c.len_utf16()).sum();
    if total <= max_units {
        return s.to_string();
    }
    // Reserve one unit for the ellipsis; truncate the rest by whole chars.
    let target = max_units.saturating_sub(1);
    let mut out = String::new();
    let mut units = 0usize;
    for ch in s.chars() {
        let u = ch.len_utf16();
        if units + u > target {
            break;
        }
        out.push(ch);
        units += u;
    }
    if units > 0 {
        out.push('…');
    }
    out
}

enum AttemptOutcome {
    Retry(String),
    Permanent(String),
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    use rieko_findings::Severity;

    use super::*;

    fn alert(title: &str, message: &str) -> Alert {
        Alert {
            dedup_key: "det|v1|Warning|node|c1".into(),
            severity: Severity::Warning,
            title: title.into(),
            message: message.into(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// A minimal local HTTP server that answers up to `max_accepts` requests
    /// with `status`/`body`. `behavior` lets tests produce timeouts (never
    /// respond) or malformed bodies.
    fn serve_once(
        status: &'static str,
        body: &'static str,
        behavior: &'static str,
        max_accepts: usize,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..max_accepts {
                let (mut stream, _) = match listener.accept() {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                if behavior == "timeout" {
                    // Accept but never respond; the client's timeout must fire.
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn successful_delivery_parses_ok_true() {
        let endpoint = serve_once(
            "200 OK",
            r#"{"ok":true,"result":{"message_id":1}}"#,
            "respond",
            4,
        );
        let mut sink = TelegramSink::new("secret-token", "chat-1")
            .with_endpoint(endpoint)
            .with_timeouts(Duration::from_millis(500), Duration::from_secs(2))
            .with_retry(2, Duration::ZERO);
        sink.send(&alert("t", "m")).unwrap();
    }

    #[test]
    fn http_500_is_retried_then_fails() {
        let endpoint = serve_once("500 Internal Server Error", r#"{"ok":false}"#, "respond", 4);
        let mut sink = TelegramSink::new("secret-token", "chat-1")
            .with_endpoint(endpoint)
            .with_timeouts(Duration::from_millis(500), Duration::from_secs(2))
            .with_retry(2, Duration::ZERO);
        let err = sink.send(&alert("t", "m")).unwrap_err().to_string();
        assert!(err.contains("500"), "got {err}");
        assert!(err.contains("after 2 attempts"), "got {err}");
    }

    #[test]
    fn http_400_is_a_permanent_failure() {
        let endpoint = serve_once(
            "400 Bad Request",
            r#"{"ok":false,"description":"bad"}"#,
            "respond",
            2,
        );
        let mut sink = TelegramSink::new("secret-token", "chat-1")
            .with_endpoint(endpoint)
            .with_timeouts(Duration::from_millis(500), Duration::from_secs(2))
            .with_retry(2, Duration::ZERO);
        let err = sink.send(&alert("t", "m")).unwrap_err().to_string();
        assert!(err.contains("400"), "got {err}");
        // A 4xx must not be retried: only one attempt.
        assert!(!err.contains("after 2 attempts"), "got {err}");
    }

    #[test]
    fn malformed_response_is_rejected() {
        let endpoint = serve_once("200 OK", r#"this is not json"#, "respond", 4);
        let mut sink = TelegramSink::new("secret-token", "chat-1")
            .with_endpoint(endpoint)
            .with_timeouts(Duration::from_millis(500), Duration::from_secs(2))
            .with_retry(1, Duration::ZERO);
        let err = sink.send(&alert("t", "m")).unwrap_err().to_string();
        assert!(
            err.contains("non-JSON") || err.contains("ok=true"),
            "got {err}"
        );
    }

    #[test]
    fn timeout_does_not_block_forever() {
        let endpoint = serve_once("200 OK", "", "timeout", 4);
        let mut sink = TelegramSink::new("secret-token", "chat-1")
            .with_endpoint(endpoint)
            .with_timeouts(Duration::from_millis(30), Duration::from_millis(30))
            .with_retry(1, Duration::ZERO);
        let start = std::time::Instant::now();
        let err = sink.send(&alert("t", "m")).unwrap_err().to_string();
        assert!(err.contains("timed out"), "got {err}");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout must be bounded"
        );
    }

    #[test]
    fn transport_error_redacts_the_token() {
        // Point at a port nothing listens on: connection refused.
        let endpoint = "http://127.0.0.1:1";
        let mut sink = TelegramSink::new("SECRET-BOT-TOKEN", "chat-1")
            .with_endpoint(endpoint)
            .with_timeouts(Duration::from_millis(200), Duration::from_millis(200))
            .with_retry(1, Duration::ZERO);
        let err = sink.send(&alert("t", "m")).unwrap_err().to_string();
        assert!(
            !err.contains("SECRET-BOT-TOKEN"),
            "the token must never leak, got: {err}"
        );
        assert!(!err.contains("/bot"), "the URL must never leak, got: {err}");
    }

    #[test]
    fn markdown_metacharacters_are_escaped() {
        let title = "*bold* and _under_ and `code` and [a](b)";
        let message = "foo *bar* `baz` (x) [y]";
        let sink = TelegramSink::new("secret-token", "chat-1")
            .with_endpoint("http://127.0.0.1:1")
            .with_retry(1, Duration::ZERO);
        let text = sink.build_text(&alert(title, message));
        assert!(!text.contains("*bold*"), "raw asterisks must be escaped");
        assert!(text.contains("\\*bold\\*"), "asterisk must be escaped");
        assert!(text.contains("\\_under\\_"), "underscore must be escaped");
        assert!(text.contains("\\`code\\`"), "backtick must be escaped");
        assert!(
            text.contains("\\[a\\]\\(b\\)"),
            "link chars must be escaped"
        );
        // No unescaped markdown metacharacters inside the untrusted fields.
        assert!(!text.contains("`code`"), "raw backticks must be escaped");
        assert!(!text.contains("*bold*"), "raw asterisks must be escaped");
        assert!(
            text.contains("\\`baz\\`"),
            "backtick inside message must be escaped"
        );
    }

    #[test]
    fn oversized_message_is_truncated() {
        let sink = TelegramSink::new("secret-token", "chat-1");
        let message = "x".repeat(10_000);
        let text = sink.build_text(&alert("t", &message));
        let units: usize = text.chars().map(|c| c.len_utf16()).sum();
        assert!(
            units <= MAX_MESSAGE_UTF16,
            "text is {units} UTF-16 units, over limit"
        );
        assert!(
            text.ends_with('…'),
            "truncated text should end with ellipsis"
        );
    }

    #[test]
    fn non_ascii_text_is_truncated_by_utf16_units_not_chars() {
        let sink = TelegramSink::new("secret-token", "chat-1");
        // Each emoji is two UTF-16 units; 5000 of them must be cut hard.
        let message = "🚨".repeat(5000);
        let text = sink.build_text(&alert("t", &message));
        let units: usize = text.chars().map(|c| c.len_utf16()).sum();
        assert!(
            units <= MAX_MESSAGE_UTF16,
            "text is {units} UTF-16 units, over limit"
        );
    }

    #[test]
    fn escape_and_truncate_are_pure_and_deterministic() {
        let a = escape_markdown("a * b ` c [ d ] ( e )");
        let b = escape_markdown("a * b ` c [ d ] ( e )");
        assert_eq!(a, b);
        assert_eq!(truncate_utf16("short", 100), "short");
    }
}

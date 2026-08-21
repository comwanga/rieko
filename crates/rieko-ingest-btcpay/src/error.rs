use thiserror::Error;

#[derive(Debug, Error)]
pub enum BtcPayError {
    #[error("invalid webhook signature")]
    InvalidSignature,

    #[error("missing signature header '{0}'")]
    MissingSignatureHeader(String),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("malformed payload: {0}")]
    MalformedPayload(String),

    #[error("Greenfield API error (status {status}): {message}")]
    Api { status: u16, message: String },

    #[error("event channel closed")]
    ChannelClosed,

    #[error("invalid configuration: {0}")]
    Config(String),
}

impl From<BtcPayError> for rieko_domain::IngestionError {
    fn from(err: BtcPayError) -> Self {
        match err {
            BtcPayError::InvalidSignature | BtcPayError::MissingSignatureHeader(_) => {
                rieko_domain::IngestionError::Authentication(err.to_string())
            }
            BtcPayError::Http(e) => rieko_domain::IngestionError::Connection(e.to_string()),
            BtcPayError::Json(e) => rieko_domain::IngestionError::Normalization(e.to_string()),
            BtcPayError::MalformedPayload(msg) => rieko_domain::IngestionError::Normalization(msg),
            BtcPayError::Api { status, message } => {
                if status == 401 || status == 403 {
                    rieko_domain::IngestionError::Authentication(message)
                } else {
                    rieko_domain::IngestionError::Connection(format!("status {status}: {message}"))
                }
            }
            BtcPayError::ChannelClosed => rieko_domain::IngestionError::Closed,
            BtcPayError::Config(msg) => rieko_domain::IngestionError::Other(msg),
        }
    }
}

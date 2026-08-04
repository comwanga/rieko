pub mod client;
pub mod prompt;

pub use client::{ExplainRequest, LlmClient, LlmError, NullClient, OpenAiCompatibleClient};
pub use prompt::build_explanation_prompt;

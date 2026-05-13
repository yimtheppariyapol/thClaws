//! ChatGPT/Codex OAuth token representation — ported from themion's
//! `crates/themion-core/src/auth.rs`.
//!
//! Used by the `chatgpt-codex` provider to authenticate against
//! `chatgpt.com/backend-api/codex` with a ChatGPT subscription. The
//! provider auto-refreshes tokens via [`is_expired`] checks; the
//! [`crate::codex_auth_store`] module persists them on disk.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CodexAuth {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix epoch seconds — when the access_token expires.
    pub expires_at: i64,
    /// `chatgpt_account_id` extracted from the access_token JWT.
    /// Required on every API request via the `chatgpt-account-id` header.
    pub account_id: String,
}

impl CodexAuth {
    /// Returns `true` if the access_token is past its expiry minus `skew_secs`.
    /// Callers pass a non-zero skew (e.g. 60s) so we refresh slightly early
    /// rather than at the exact deadline.
    pub fn is_expired(&self, skew_secs: i64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.expires_at - skew_secs <= now
    }
}

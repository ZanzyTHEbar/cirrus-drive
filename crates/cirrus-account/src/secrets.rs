//! Platform credential stores share the same bounded, zeroizing account payload.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::Store;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(crate) use macos::Store;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountData {
    pub instance: String,
    pub issuer: String,
    pub client_id: String,
    pub token_endpoint: String,
    pub subject: String,
    pub ca_pem: Option<String>,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    pub refresh_in_progress: bool,
    pub selected_space: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_space_verified: Option<String>,
}

// Static diagnostics only: no framework descriptions or query/payload contents.
// Kept independent of the account engine so the physical native boundary can
// be typechecked without substituting an AccountError or networking/SQL code.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(crate) struct CredentialError {
    pub(crate) message: &'static str,
    pub(crate) retryable: bool,
}

#[cfg(target_os = "macos")]
impl CredentialError {
    pub(crate) fn invalid(message: &'static str) -> Self {
        Self {
            message,
            retryable: false,
        }
    }

    pub(crate) fn unavailable(message: &'static str) -> Self {
        Self {
            message,
            retryable: true,
        }
    }
}

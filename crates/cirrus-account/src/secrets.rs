//! Platform credential stores share the same bounded, zeroizing account payload.

use serde::{Deserialize, Serialize, de::IgnoredAny};
use sha2::{Digest, Sha256};
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
}

pub(crate) enum StoredAccount {
    Current(AccountData),
    Legacy(LegacyAccount),
}

pub(crate) struct LegacyAccount {
    issuer: String,
    subject: String,
    fingerprint: [u8; 32],
}

// The previous writer always serialized selected_space, including null. Recover
// only that layout and only its identity; never recover or use its tokens.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPayload {
    instance: String,
    issuer: String,
    subject: String,
    refresh_in_progress: bool,
    #[serde(rename = "client_id")]
    _client_id: IgnoredAny,
    #[serde(rename = "token_endpoint")]
    _token_endpoint: IgnoredAny,
    #[serde(rename = "ca_pem")]
    _ca_pem: Option<IgnoredAny>,
    #[serde(rename = "access_token")]
    _access_token: IgnoredAny,
    #[serde(rename = "refresh_token")]
    _refresh_token: IgnoredAny,
    #[serde(rename = "expires_at")]
    _expires_at: u64,
    #[serde(rename = "selected_space")]
    _selected_space: IgnoredAny,
    #[serde(rename = "selected_space_verified")]
    _selected_space_verified: Option<IgnoredAny>,
}

impl StoredAccount {
    pub(crate) fn decode(secret: &[u8], instance: &str) -> Result<Self, &'static str> {
        if let Ok(account) = serde_json::from_slice::<AccountData>(secret) {
            if account.instance != instance {
                return Err("account secret does not match instance");
            }
            return Ok(Self::Current(account));
        }
        let legacy: LegacyPayload =
            serde_json::from_slice(secret).map_err(|_| "account secret is invalid")?;
        if legacy.instance != instance {
            return Err("account secret does not match instance");
        }
        if legacy.issuer.is_empty() || legacy.subject.is_empty() || legacy.refresh_in_progress {
            return Err("account secret is invalid");
        }
        Ok(Self::Legacy(LegacyAccount {
            issuer: legacy.issuer,
            subject: legacy.subject,
            fingerprint: Sha256::digest(secret).into(),
        }))
    }

    pub(crate) fn current(self) -> Result<AccountData, &'static str> {
        match self {
            Self::Current(account) => Ok(account),
            Self::Legacy(_) => Err("account secret is invalid"),
        }
    }

    pub(crate) fn verify_identity(&self, issuer: &str, subject: &str) -> Result<(), &'static str> {
        let (old_issuer, old_subject) = match self {
            Self::Current(old) => (&old.issuer, &old.subject),
            Self::Legacy(old) => (&old.issuer, &old.subject),
        };
        if old_issuer != issuer || old_subject != subject {
            return Err(
                "connected identity differs from the saved account; existing account was preserved",
            );
        }
        Ok(())
    }

    pub(crate) fn check_save(
        existing: Option<&Self>,
        account: &AccountData,
        replace: Option<&LegacyAccount>,
    ) -> Result<(), &'static str> {
        match (existing, replace) {
            (None, None) => Ok(()),
            (Some(current @ Self::Current(_)), None) => {
                current.verify_identity(&account.issuer, &account.subject)
            }
            (Some(Self::Legacy(_)), None) => Err("account secret is invalid"),
            (Some(stored @ Self::Legacy(old)), Some(expected))
                if old.fingerprint == expected.fingerprint =>
            {
                stored.verify_identity(&account.issuer, &account.subject)
            }
            (_, Some(_)) => Err("account secret changed during sign-in; retry the operation"),
        }
    }
}

#[cfg(test)]
#[test]
fn legacy_credentials_require_fresh_sign_in_by_the_same_principal() {
    let instance = "https://instance.invalid/";
    let current = serde_json::json!({
        "instance": instance,
        "issuer": "https://issuer.invalid/",
        "client_id": "fixture",
        "token_endpoint": "https://issuer.invalid/token",
        "subject": "fixture",
        "ca_pem": null,
        "access_token": "disposable-access",
        "refresh_token": "disposable-refresh",
        "expires_at": 0,
        "refresh_in_progress": false,
    });
    let mut fresh = serde_json::from_value::<AccountData>(current.clone()).unwrap();
    fresh.access_token = "fresh-access".into();
    for field in ["selected_space", "selected_space_verified"] {
        let mut removed_field = current.clone();
        removed_field[field] = serde_json::Value::Null;
        assert!(serde_json::from_value::<AccountData>(removed_field).is_err());
    }
    let mut legacy = current;
    legacy["selected_space"] = serde_json::Value::Null;
    let read = |payload: &serde_json::Value| {
        StoredAccount::decode(&serde_json::to_vec(payload).unwrap(), instance)
    };
    assert!(read(&legacy).unwrap().current().is_err());
    let observed = read(&legacy).unwrap();
    let StoredAccount::Legacy(previous) = &observed else {
        panic!("the previous release's payload must admit explicit sign-in");
    };
    assert!(StoredAccount::check_save(Some(&observed), &fresh, None).is_err());
    assert!(StoredAccount::check_save(Some(&observed), &fresh, Some(previous)).is_ok());
    fresh.subject = "other-principal".into();
    assert!(StoredAccount::check_save(Some(&observed), &fresh, Some(previous)).is_err());
    fresh.subject = "fixture".into();

    legacy["selected_space"] = "old-space".into();
    legacy["selected_space_verified"] = "old-space".into();
    let changed = read(&legacy).unwrap();
    assert!(StoredAccount::check_save(Some(&changed), &fresh, Some(previous)).is_err());
    let changed = StoredAccount::Current(fresh.clone());
    assert!(StoredAccount::check_save(Some(&changed), &fresh, Some(previous)).is_err());
    assert!(StoredAccount::check_save(None, &fresh, Some(previous)).is_err());

    legacy["refresh_in_progress"] = true.into();
    assert!(read(&legacy).is_err());
    legacy["refresh_in_progress"] = false.into();
    legacy["instance"] = "https://other-instance.invalid/".into();
    assert!(read(&legacy).is_err());
    legacy["instance"] = instance.into();
    legacy["subject"] = "".into();
    assert!(read(&legacy).is_err());
    assert!(StoredAccount::decode(b"damaged credential", instance).is_err());
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

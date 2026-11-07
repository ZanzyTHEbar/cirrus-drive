use secret_service::{EncryptionType, blocking::SecretService};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::AccountError;

fn unavailable(message: &'static str) -> AccountError {
    if crate::executor::is_automatic() {
        AccountError::retryable_read(message)
    } else {
        AccountError::new(message)
    }
}

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

pub(crate) struct Store {
    service: SecretService<'static>,
}

impl Store {
    pub fn open(connection: &zbus::blocking::Connection) -> Result<Self, AccountError> {
        let service = SecretService::connect_with_existing(EncryptionType::Dh, connection.clone())
            .map_err(|_| unavailable("Secret Service is unavailable"))?;
        let store = Self { service };
        let collection = store
            .service
            .get_default_collection()
            .map_err(|_| unavailable("default Secret Service collection is unavailable"))?;
        if collection
            .is_locked()
            .map_err(|_| unavailable("cannot inspect Secret Service collection"))?
        {
            return Err(unavailable(
                "Secret Service collection is locked; unlock it and retry",
            ));
        }
        drop(collection);
        Ok(store)
    }

    pub fn check_account(&self, instance: &str) -> Result<(), AccountError> {
        let collection = self
            .service
            .get_default_collection()
            .map_err(|_| unavailable("default Secret Service collection is unavailable"))?;
        let items = collection
            .search_items(attributes(instance))
            .map_err(|_| unavailable("cannot search Secret Service"))?;
        if items.len() > 1 {
            return Err(AccountError::new(
                "multiple matching account secrets require manual resolution",
            ));
        }
        if let Some(item) = items.first()
            && item
                .is_locked()
                .map_err(|_| unavailable("cannot inspect account secret"))?
        {
            return Err(unavailable("account secret is locked; unlock it and retry"));
        }
        if let Some(item) = items.first() {
            let mut actual = item
                .get_attributes()
                .map_err(|_| unavailable("cannot inspect account secret attributes"))?;
            // GNOME Keyring adds the standard generic schema to items it creates.
            if actual.get("xdg:schema").map(String::as_str)
                == Some("org.freedesktop.Secret.Generic")
            {
                actual.remove("xdg:schema");
            }
            let expected: HashMap<String, String> = attributes(instance)
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect();
            if actual != expected {
                return Err(AccountError::new(
                    "matching account secret has unexpected attributes",
                ));
            }
        }
        Ok(())
    }

    pub fn load(&self, instance: &str) -> Result<AccountData, AccountError> {
        self.check_account(instance)?;
        let collection = self
            .service
            .get_default_collection()
            .map_err(|_| unavailable("default Secret Service collection is unavailable"))?;
        let items = collection
            .search_items(attributes(instance))
            .map_err(|_| unavailable("cannot search Secret Service"))?;
        let item = items
            .first()
            .ok_or_else(|| unavailable("account is not connected"))?;
        let secret = Zeroizing::new(
            item.get_secret()
                .map_err(|_| unavailable("cannot read account secret"))?,
        );
        if secret.len() > 131_072 {
            return Err(AccountError::new("account secret exceeds the size limit"));
        }
        let account: AccountData = serde_json::from_slice(&secret)
            .map_err(|_| AccountError::new("account secret is invalid"))?;
        if account.instance != instance {
            return Err(AccountError::new("account secret does not match instance"));
        }
        Ok(account)
    }

    pub fn load_existing_account(
        &self,
        instance: &str,
    ) -> Result<Option<AccountData>, AccountError> {
        self.check_account(instance)?;
        let collection = self
            .service
            .get_default_collection()
            .map_err(|_| AccountError::new("default Secret Service collection is unavailable"))?;
        if !collection
            .search_items(attributes(instance))
            .map_err(|_| AccountError::new("cannot search Secret Service"))?
            .is_empty()
        {
            return self.load(instance).map(Some);
        }
        Ok(None)
    }

    pub fn save(&self, account: &AccountData) -> Result<(), AccountError> {
        self.check_account(&account.instance)?;
        let collection = self
            .service
            .get_default_collection()
            .map_err(|_| AccountError::new("default Secret Service collection is unavailable"))?;
        let items = collection
            .search_items(attributes(&account.instance))
            .map_err(|_| AccountError::new("cannot search Secret Service"))?;
        let data = Zeroizing::new(
            serde_json::to_vec(account)
                .map_err(|_| AccountError::new("cannot encode account secret"))?,
        );
        if data.len() > 131_072 {
            return Err(AccountError::new("account secret exceeds the size limit"));
        }
        if let Some(item) = items.first() {
            item.set_secret(&data, "application/json")
                .map_err(|_| AccountError::new("cannot save account secret"))?;
        } else {
            collection
                .create_item(
                    "Cirrus Drive account",
                    attributes(&account.instance),
                    &data,
                    false,
                    "application/json",
                )
                .map_err(|_| AccountError::new("cannot save account secret"))?;
        }
        Ok(())
    }
}

fn attributes(instance: &str) -> HashMap<&str, &str> {
    HashMap::from([("application", "cirrus-drive"), ("instance", instance)])
}

use secret_service::{
    EncryptionType,
    blocking::{Collection, Item, SecretService},
};
use std::collections::HashMap;
use zeroize::Zeroizing;

use super::AccountData;
use crate::AccountError;
use crate::ownership::credentials::Context;

fn unavailable(message: &'static str) -> AccountError {
    if crate::executor::is_automatic() {
        AccountError::retryable_read(message)
    } else {
        AccountError::new(message)
    }
}

pub(crate) struct Store {
    service: SecretService<'static>,
}

struct Existing<'a> {
    item: Item<'a>,
    account: AccountData,
}

impl Store {
    pub fn open(context: &Context) -> Result<Self, AccountError> {
        let connection = context.connection();
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

    pub fn load(&self, instance: &str) -> Result<AccountData, AccountError> {
        self.load_existing_account(instance)?
            .ok_or_else(|| unavailable("account is not connected"))
    }

    pub fn load_existing_account(
        &self,
        instance: &str,
    ) -> Result<Option<AccountData>, AccountError> {
        let collection = self
            .service
            .get_default_collection()
            .map_err(|_| unavailable("default Secret Service collection is unavailable"))?;
        Ok(existing(&collection, instance)?.map(|item| item.account))
    }

    pub fn save(&self, account: &AccountData) -> Result<(), AccountError> {
        let collection = self
            .service
            .get_default_collection()
            .map_err(|_| AccountError::new("default Secret Service collection is unavailable"))?;
        let existing = existing(&collection, &account.instance)?;
        if existing.as_ref().is_some_and(|item| {
            item.account.issuer != account.issuer || item.account.subject != account.subject
        }) {
            return Err(AccountError::new(
                "connected identity differs from the saved account; existing account was preserved",
            ));
        }
        let data = Zeroizing::new(
            serde_json::to_vec(account)
                .map_err(|_| AccountError::new("cannot encode account secret"))?,
        );
        if data.len() > 131_072 {
            return Err(AccountError::new("account secret exceeds the size limit"));
        }
        if let Some(existing) = existing {
            existing
                .item
                .set_secret(&data, "application/json")
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

fn existing<'a>(
    collection: &'a Collection<'_>,
    instance: &str,
) -> Result<Option<Existing<'a>>, AccountError> {
    if collection
        .is_locked()
        .map_err(|_| unavailable("cannot inspect Secret Service collection"))?
    {
        return Err(unavailable(
            "Secret Service collection is locked; unlock it and retry",
        ));
    }
    let mut items = collection
        .search_items(attributes(instance))
        .map_err(|_| unavailable("cannot search Secret Service"))?;
    if items.len() > 1 {
        return Err(AccountError::new(
            "multiple matching account secrets require manual resolution",
        ));
    }
    let Some(item) = items.pop() else {
        return Ok(None);
    };
    if item
        .is_locked()
        .map_err(|_| unavailable("cannot inspect account secret"))?
    {
        return Err(unavailable("account secret is locked; unlock it and retry"));
    }
    let mut actual = item
        .get_attributes()
        .map_err(|_| unavailable("cannot inspect account secret attributes"))?;
    // GNOME Keyring adds the standard generic schema to items it creates.
    if actual.get("xdg:schema").map(String::as_str) == Some("org.freedesktop.Secret.Generic") {
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
    Ok(Some(Existing { item, account }))
}

fn attributes(instance: &str) -> HashMap<&str, &str> {
    HashMap::from([("application", "cirrus-drive"), ("instance", instance)])
}

#[cfg(test)]
mod acceptance {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    #[ignore = "requires an explicitly guarded disposable Secret Service"]
    fn refuses_corrupt_secret_without_overwriting() {
        assert!(
            cfg!(feature = "fault-injection"),
            "credential acceptance requires fault-injection routing"
        );
        use std::os::unix::fs::FileTypeExt;
        let pinned = |name: &str| std::env::var(name).expect("explicit private fixture identity");
        let process_start = |pid: u32| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .unwrap()
                .rsplit_once(") ")
                .unwrap()
                .1
                .split_whitespace()
                .nth(19)
                .unwrap()
                .to_owned()
        };
        let runtime = std::path::PathBuf::from(
            std::env::var_os("CIRRUS_TEST_CREDENTIAL_RUNTIME").expect("explicit private runtime"),
        );
        let job = runtime.parent().unwrap();
        let scratch = std::path::Path::new("/workspaces/.ubuntu-disposable-scratch");
        assert_eq!(job.parent(), Some(scratch));
        assert_eq!(runtime, job.join("r"));
        assert_eq!(
            std::env::var_os("CIRRUS_TEST_USER_BUS_DIR").as_deref(),
            Some(runtime.as_os_str())
        );
        for directory in [scratch, job, runtime.as_path()] {
            assert_eq!(std::fs::canonicalize(directory).unwrap(), directory);
            let metadata = std::fs::symlink_metadata(directory).unwrap();
            assert!(metadata.file_type().is_dir());
            assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
            assert_eq!(metadata.mode() & 0o7777, 0o700);
            assert_eq!(metadata.dev(), std::fs::metadata(scratch).unwrap().dev());
        }
        let socket = std::fs::symlink_metadata(runtime.join("bus")).unwrap();
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(
            socket.dev(),
            pinned("CIRRUS_TEST_BUS_DEVICE").parse::<u64>().unwrap()
        );
        assert_eq!(
            socket.ino(),
            pinned("CIRRUS_TEST_BUS_INODE").parse::<u64>().unwrap()
        );
        let bus_pid = pinned("CIRRUS_TEST_BUS_PID").parse::<u32>().unwrap();
        assert_eq!(process_start(bus_pid), pinned("CIRRUS_TEST_BUS_START"));
        assert_eq!(
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
            Some(runtime.as_os_str())
        );
        assert_eq!(
            std::env::var_os("HOME").as_deref(),
            Some(job.join("home").as_os_str())
        );
        assert_eq!(
            std::env::var_os("XDG_STATE_HOME").as_deref(),
            Some(job.join("state").as_os_str())
        );
        let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap();
        assert_eq!(std::env::var("DBUS_STARTER_ADDRESS").unwrap(), address);
        assert_eq!(address, pinned("CIRRUS_TEST_PINNED_BUS_ADDRESS"));
        let (socket_address, address_guid) = address.split_once(",guid=").unwrap();
        assert_eq!(
            socket_address,
            format!("unix:path={}/bus", runtime.display())
        );
        assert_eq!(
            address_guid.len(),
            32,
            "private address must include its emitted GUID"
        );
        assert!(address_guid.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let container = std::path::PathBuf::from(
            std::env::var_os("CIRRUS_TEST_CREDENTIAL_CONTAINER")
                .expect("explicit private container"),
        );
        assert_eq!(container, job.join("credential-container"));
        let metadata = std::fs::symlink_metadata(&container).unwrap();
        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        let root = crate::StorageRoot::open_container(&container).unwrap();
        let identity = root.identity();
        let accounts =
            crate::Accounts::with_storage(crate::RuntimeDir::open(&runtime).unwrap(), root);
        assert_eq!(accounts.storage_root().unwrap().identity(), identity);
        let guard = accounts.begin_operation().unwrap();
        let context = guard.credential_context().unwrap();
        let bus = zbus::blocking::Proxy::new(
            context.connection(),
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .unwrap();
        let actual_id: String = bus.call("GetId", &()).unwrap();
        assert_eq!(actual_id, pinned("CIRRUS_TEST_BUS_ID"));
        let actual_pid: u32 = bus
            .call("GetConnectionUnixProcessID", &("org.freedesktop.DBus",))
            .unwrap();
        assert_eq!(actual_pid, bus_pid);
        assert_eq!(process_start(actual_pid), pinned("CIRRUS_TEST_BUS_START"));
        let owner: String = bus
            .call("GetNameOwner", &("org.freedesktop.secrets",))
            .unwrap();
        assert_eq!(owner, pinned("CIRRUS_TEST_KEYRING_OWNER"));
        let keyring_pid: u32 = bus
            .call("GetConnectionUnixProcessID", &(owner.as_str(),))
            .unwrap();
        assert_eq!(
            keyring_pid,
            pinned("CIRRUS_TEST_KEYRING_PID").parse::<u32>().unwrap()
        );
        assert_eq!(
            process_start(keyring_pid),
            pinned("CIRRUS_TEST_KEYRING_START")
        );
        eprintln!("ACTUAL_CONTEXT_PRIVATE_BUS_VERIFIED_BEFORE_STORE");
        let store = Store::open(guard.credential_context().unwrap()).unwrap();
        let mut account = AccountData {
            instance: "https://credential-acceptance.invalid/".into(),
            issuer: "https://identity-acceptance.invalid/".into(),
            client_id: "fixture".into(),
            token_endpoint: "https://identity-acceptance.invalid/token".into(),
            subject: "fixture".into(),
            ca_pem: None,
            access_token: "disposable-access".into(),
            refresh_token: "disposable-refresh".into(),
            expires_at: 0,
            refresh_in_progress: false,
            selected_space: None,
            selected_space_verified: None,
        };
        store.save(&account).unwrap();
        account.access_token = "rotated-disposable-access".into();
        store.save(&account).unwrap();
        assert!(store.load(&account.instance).unwrap() == account);
        let collection = store.service.get_default_collection().unwrap();
        let mut items = collection
            .search_items(attributes(&account.instance))
            .unwrap();
        assert_eq!(items.len(), 1);
        let item = items.pop().unwrap();
        item.set_secret(b"damaged credential", "application/json")
            .unwrap();

        assert!(store.save(&account).is_err());
        assert_eq!(item.get_secret().unwrap(), b"damaged credential");
    }
}

//! Foreground user daemon and private local client.

mod application;
mod local;
mod release;
mod scheduler;
mod worker_wire;

use std::io;

use cirrus_client::{AccountReply, AccountRequest, account as account_request};

pub use cirrus_account::{
    CleanCacheStatus, JournalEntry, JournalPage, JournalState, JournalSummary,
    NamespaceStorageReservation, SqlStorageReservation, StorageLimits, StorageLimitsView,
    StorageStatus, StorageUsage, SyncPhase, SyncStatus,
};
use cirrus_runtime::RuntimeDir;

pub use cirrus_api::{
    DirectoryEntry, MountInfo, MountState, ReleaseStatus, RetainedPage, RetainedPin, RetainedPinCopy,
    RetainedPinCopyEntry, RetainedPinFile, RetainedStaged,
};

/// The user-scoped daemon's application boundary.
#[derive(Debug, Default)]
pub struct Daemon;

impl Daemon {
    /// Creates a daemon without starting a process or accessing user data.
    pub fn new() -> Self {
        Self
    }

    /// Canonicalizes an instance URL without accessing the network.
    ///
    /// # Errors
    /// Returns an error if the URL is unsafe or invalid.
    pub fn canonical_instance(instance: &str) -> io::Result<String> {
        cirrus_account::Accounts::canonical_instance(instance).map_err(io::Error::other)
    }

    /// Runs the foreground status service until a local client requests shutdown.
    ///
    /// The caller must arrange a process umask of 077 before calling this method.
    /// The private runtime directory is trusted against other processes of the same UID.
    /// An owner marker identifies this application's socket namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if exclusive ownership, socket permissions or serving fails.
    pub fn run(&self, runtime: &RuntimeDir) -> io::Result<()> {
        local::serve(runtime, true, None)
    }

    /// Runs diagnostics without automatic transfers or startup account access.
    /// Explicit commands remain available; persistent activations are not removed.
    ///
    /// # Errors
    /// Returns an error if the private local service cannot be safely established.
    pub fn run_without_automatic_sync(&self, runtime: &RuntimeDir) -> io::Result<()> {
        local::serve(runtime, false, None)
    }

    /// Runs the resident with an installed Linux user-release root.
    #[doc(hidden)]
    pub fn run_managed(
        &self, runtime: &RuntimeDir, root: &std::path::Path, automatic: bool,
    ) -> io::Result<()> {
        local::serve(runtime, automatic, Some(root))
    }

    /// Prepares the default State store without starting the resident or opening credentials.
    ///
    /// The caller must stop and unmount all older writers first. The runtime
    /// guard only proves that there is no resident in the supplied runtime.
    pub fn prepare_state_after_stopping_writers(runtime: &RuntimeDir) -> io::Result<()> {
        let _runtime = local::acquire_runtime_guard(runtime)?;
        cirrus_account::StorageRoot::prepare_default_state(runtime).map_err(io::Error::other)
    }

    /// Runs an authenticated CLI or UI from the selected user-release set.
    #[doc(hidden)]
    pub fn launch_client(
        root: &std::path::Path,
        role: &str,
        bootstrap: &std::path::Path,
        args: &[std::ffi::OsString],
    ) -> io::Result<()> {
        release::launch_client(root, role, bootstrap, args)
    }

    /// Queries a running daemon; never starts one.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint, peer or response cannot be verified.
    pub fn status(&self, runtime: &RuntimeDir) -> io::Result<&'static str> {
        cirrus_client::status(runtime)
            .map(|status| status.description())
            .map_err(Into::into)
    }

    /// Observes this resident's Linux release and worker identities.
    pub fn release_status(&self, runtime: &RuntimeDir) -> io::Result<ReleaseStatus> {
        cirrus_client::release(runtime, cirrus_api::ReleaseRequest::Status).map_err(Into::into)
    }

    /// Requests a running daemon to stop and clean up its socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint, peer or response cannot be verified.
    pub fn stop(&self, runtime: &RuntimeDir) -> io::Result<()> {
        cirrus_client::stop(runtime).map_err(Into::into)
    }

    /// Reports shared local clean-cache payload usage without accessing the server or keyring.
    ///
    /// # Errors
    /// Returns an error if the daemon or cache cannot be inspected.
    pub fn clean_cache_status(&self, runtime: &RuntimeDir) -> io::Result<CleanCacheStatus> {
        match account_request(runtime, AccountRequest::CleanCacheStatus)? {
            AccountReply::CleanCacheStatus(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Observes shared account-owner storage without credentials or network access.
    ///
    /// # Errors
    /// Returns an error if the daemon, paths or local storage cannot be inspected.
    pub fn storage_status(&self, runtime: &RuntimeDir) -> io::Result<StorageStatus> {
        match account_request(runtime, AccountRequest::StorageStatus)? {
            AccountReply::StorageStatus(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Reads shared local allocation-pressure limits without credentials/network.
    ///
    /// # Errors
    /// Returns an error for unavailable daemon or invalid/unsafe configuration.
    pub fn storage_limits(&self, runtime: &RuntimeDir) -> io::Result<StorageLimitsView> {
        self.storage_limits_request(runtime, AccountRequest::StorageLimits)
    }

    /// Sets user-chosen shared limits, or disables them without deleting data.
    ///
    /// # Errors
    /// Returns an error for invalid limits, unsafe configuration or failed persistence.
    pub fn configure_storage_limits(
        &self,
        runtime: &RuntimeDir,
        limits: Option<StorageLimits>,
    ) -> io::Result<StorageLimitsView> {
        self.storage_limits_request(runtime, AccountRequest::SetStorageLimits { limits })
    }

    /// Releases a token-matched inactive store or namespace allowance, never data.
    ///
    /// # Errors
    /// Returns an error for an active owner, changed token or unsafe record.
    pub fn release_storage_reservation(
        &self,
        runtime: &RuntimeDir,
        store: String,
        token: String,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::ReleaseStorageReservation {
                store: store.parse().map_err(io::Error::other)?,
                token,
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    fn storage_limits_request(
        &self,
        runtime: &RuntimeDir,
        request: AccountRequest,
    ) -> io::Result<StorageLimitsView> {
        match account_request(runtime, request)? {
            AccountReply::StorageLimits(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Requests browser account connection in the daemon.
    ///
    /// # Errors
    /// Returns an error if the daemon or account operation fails.
    pub fn connect(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        ca_pem: Option<String>,
    ) -> io::Result<()> {
        self.connect_with_attempt(runtime, instance, ca_pem, &Self::sign_in_attempt()?)
    }

    /// Generates an opaque identifier for a sign-in attempt.
    ///
    /// # Errors
    /// Returns an error if system randomness is unavailable.
    pub fn sign_in_attempt() -> io::Result<String> {
        cirrus_client::sign_in_attempt()
    }

    /// Connects an account with a cancelable attempt identifier.
    ///
    /// # Errors
    /// Returns an error if the daemon or account operation fails.
    pub fn connect_with_attempt(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        ca_pem: Option<String>,
        attempt: &str,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::Connect {
                instance: instance.to_owned(),
                ca_pem,
                attempt: attempt.to_owned(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Requests cancellation before the attempt starts exchanging its authorization code.
    ///
    /// # Errors
    /// Returns an error if the attempt is no longer active or is finishing.
    pub fn cancel_connect(&self, runtime: &RuntimeDir, attempt: &str) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::CancelConnect {
                attempt: attempt.to_owned(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Lists authenticated Spaces through the daemon.
    ///
    /// # Errors
    /// Returns an error if the daemon or account operation fails.
    pub fn spaces(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
    ) -> io::Result<Vec<(String, String)>> {
        match account_request(
            runtime,
            AccountRequest::Spaces {
                instance: instance.to_owned(),
            },
        )? {
            AccountReply::Spaces(value) => Ok(value
                .into_iter()
                .map(|space| (space.id, space.name))
                .collect()),
            _ => Err(unexpected_reply()),
        }
    }

    /// Lists a directory in the requested, freshly verified Space via the daemon.
    ///
    /// # Errors
    /// Returns an error for unverified access, incomplete listings or daemon failures.
    pub fn directory_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: Vec<String>,
    ) -> io::Result<Vec<DirectoryEntry>> {
        match account_request(
            runtime,
            AccountRequest::DirectorySpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.into(),
            },
        )? {
            AccountReply::Entries(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Inspects one previously mounted Space's saved namespace without credentials.
    /// This is local metadata, not a refreshed remote observation or content read.
    ///
    /// # Errors
    /// Returns an error for unavailable metadata, changed identity or daemon failure.
    pub fn offline_directory(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: Vec<String>,
    ) -> io::Result<Vec<DirectoryEntry>> {
        match account_request(
            runtime,
            AccountRequest::OfflineDirectory {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.into(),
            },
        )? {
            AccountReply::Entries(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Stages a local file in an explicitly verified Space.
    ///
    /// # Errors
    /// Returns an error if Space verification or staging fails.
    pub fn stage_file_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: Vec<String>,
        source: &str,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::StageFileSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.into(),
                source: source.into(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Imports a local file using saved Space and parent metadata, without authenticating.
    ///
    /// # Errors
    /// Returns an error for missing retained evidence, unsafe imports or daemon failures.
    pub fn stage_file_offline_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: Vec<String>,
        source: &str,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::StageFileOfflineSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.into(),
                source: source.into(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Evicts clean cached ranges for a Space path without removing pins or edits.
    ///
    /// # Errors
    /// Returns an error if the account, path or cache cannot be validated.
    pub fn evict_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: Vec<String>,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::EvictSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.into(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Lists a bounded account or Space journal page, newest first.
    ///
    /// # Errors
    /// Returns an error if the journal cannot be read.
    pub fn journal(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: Option<&str>,
        before: Option<i64>,
    ) -> io::Result<JournalPage> {
        match account_request(
            runtime,
            AccountRequest::Journal {
                instance: instance.to_owned(),
                space: space.map(str::to_owned),
                before,
            },
        )? {
            AccountReply::Journal(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Requests best-effort synchronization of staged files.
    ///
    /// # Errors
    /// Returns an error when operations remain pending, conflicted or uncertain.
    pub fn sync_pending(&self, runtime: &RuntimeDir, instance: &str) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::Sync {
                instance: instance.to_owned(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Requests best-effort synchronization of one listed Space.
    ///
    /// # Errors
    /// Returns an error if the Space is unlisted or has unresolved operations.
    pub fn sync_space(&self, runtime: &RuntimeDir, instance: &str, space: &str) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::SyncSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Requests bounded-output, local-only status for one immutable Space ID.
    ///
    /// # Errors
    /// Returns an error for invalid input, unsupported state or IPC failure.
    pub fn sync_status(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
    ) -> io::Result<SyncStatus> {
        match account_request(
            runtime,
            AccountRequest::SyncStatus {
                instance: instance.to_owned(),
                space: space.to_owned(),
            },
        )? {
            AccountReply::SyncStatus(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Acknowledges an inspected conflict or uncertain entry, retaining its local copy.
    ///
    /// # Errors
    /// Returns an error if the entry cannot be acknowledged.
    pub fn acknowledge(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        staged: &str,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::Acknowledge {
                instance: instance.to_owned(),
                staged: staged.to_owned(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Pins a path in an explicitly verified Space.
    ///
    /// # Errors
    /// Returns an error if Space verification or pinning fails.
    pub fn pin_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: Vec<String>,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::PinSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.into(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Removes a pin in an explicitly verified Space.
    ///
    /// # Errors
    /// Returns an error if Space verification or unpinning fails.
    pub fn unpin_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: Vec<String>,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::UnpinSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.into(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Lists locally retained pins in the named Space without checking the server.
    ///
    /// # Errors
    /// Returns an error if local identity or pin listing is unavailable.
    pub fn pins_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
    ) -> io::Result<Vec<(String, String)>> {
        match account_request(
            runtime,
            AccountRequest::PinsSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
            },
        )? {
            AccountReply::Pins(value) => Ok(value
                .into_iter()
                .map(|pin| (pin.path.clone(), pin.status(false).to_owned()))
                .collect()),
            _ => Err(unexpected_reply()),
        }
    }

    /// Compares pins with the server in a freshly verified Space.
    ///
    /// # Errors
    /// Returns an error if Space verification or pin listing fails.
    pub fn pins_space_check_remote(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
    ) -> io::Result<Vec<(String, String)>> {
        match account_request(
            runtime,
            AccountRequest::PinsSpaceCheckRemote {
                instance: instance.to_owned(),
                space: space.to_owned(),
            },
        )? {
            AccountReply::Pins(value) => Ok(value
                .into_iter()
                .map(|pin| (pin.path.clone(), pin.status(true).to_owned()))
                .collect()),
            _ => Err(unexpected_reply()),
        }
    }

    /// Lists journal-referenced retained staged copies without account credentials.
    ///
    /// # Errors
    /// Returns an error if the daemon or local state cannot be read.
    pub fn retained_staged(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        offset: u32,
    ) -> io::Result<RetainedPage<RetainedStaged>> {
        match account_request(
            runtime,
            AccountRequest::RetainedStaged {
                instance: instance.to_owned(),
                offset,
            },
        )? {
            AccountReply::RetainedStaged(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Exports one journal-referenced staged copy to a new local path.
    ///
    /// # Errors
    /// Returns an error when validation or output fails; partial output may remain.
    pub fn export_staged(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        id: i64,
        selector: &str,
        destination: &str,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::ExportStaged {
                instance: instance.to_owned(),
                id,
                selector: selector.to_owned(),
                destination: destination.into(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Parses one page of pin roots for interactive clients.
    ///
    /// # Errors
    /// Returns an error if the daemon returns invalid metadata.
    pub fn recovery_pins(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        offset: u32,
    ) -> io::Result<RetainedPage<RetainedPin>> {
        match account_request(
            runtime,
            AccountRequest::RetainedPins {
                instance: instance.to_owned(),
                offset,
            },
        )? {
            AccountReply::RetainedPins(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Parses one page of pinned files for interactive clients.
    ///
    /// # Errors
    /// Returns an error if the daemon returns invalid metadata.
    pub fn recovery_files(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        root: Vec<String>,
        offset: u32,
    ) -> io::Result<RetainedPage<RetainedPinFile>> {
        match account_request(
            runtime,
            AccountRequest::RetainedFiles {
                instance: instance.to_owned(),
                offset,
                space: space.to_owned(),
                root: root.into(),
            },
        )? {
            AccountReply::RetainedFiles(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Lists typed retained pin captures for the recovery controls.
    ///
    /// # Errors
    /// Returns an error for unavailable or malformed retained metadata.
    pub fn recovery_pin_copies(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        offset: u32,
    ) -> io::Result<RetainedPage<RetainedPinCopy>> {
        match account_request(
            runtime,
            AccountRequest::PinCopies {
                instance: instance.to_owned(),
                offset,
            },
        )? {
            AccountReply::PinCopies(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Lists captured directory identities and selectable files for recovery.
    ///
    /// # Errors
    /// Returns an error for unavailable or malformed retained metadata.
    pub fn recovery_pin_copy_entries(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        id: i64,
        offset: u32,
    ) -> io::Result<RetainedPage<RetainedPinCopyEntry>> {
        match account_request(
            runtime,
            AccountRequest::PinCopyEntries {
                instance: instance.to_owned(),
                offset,
                space: space.to_owned(),
                id,
            },
        )? {
            AccountReply::PinCopyEntries(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Exports one selected file from an immutable pin copy.
    ///
    /// # Errors
    /// Returns an error if source validation or exclusive output creation fails.
    pub fn export_pin_copy(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        source: (i64, Vec<String>),
        selector: &str,
        destination: &str,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::ExportPinCopy {
                instance: instance.to_owned(),
                space: space.to_owned(),
                id: source.0,
                path: source.1.into(),
                selector: selector.to_owned(),
                destination: destination.into(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Removes only an explicitly identified retained pin copy, never active pins.
    ///
    /// # Errors
    /// Returns an error for invalid identity or unavailable retained state.
    pub fn remove_pin_copy(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        id: i64,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::RemovePinCopy {
                instance: instance.to_owned(),
                space: space.to_owned(),
                id,
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Exports one retained, possibly stale file version to a new local path.
    ///
    /// # Errors
    /// Returns an error if validation or export fails; a partial destination may remain.
    pub fn export_retained(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        source: (Vec<String>, Vec<String>),
        selector: &str,
        destination: &str,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::ExportRetained {
                instance: instance.to_owned(),
                space: space.to_owned(),
                root: source.0.into(),
                path: source.1.into(),
                selector: selector.to_owned(),
                destination: destination.into(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Mounts an explicitly verified Space at an existing private directory.
    ///
    /// # Errors
    /// Returns an error if the Space, mountpoint or daemon cannot be verified.
    pub fn mount_space_at(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: &str,
    ) -> io::Result<()> {
        self.mount_space(runtime, instance, space, Some(path))
            .map(|_| ())
    }

    /// Mounts a Space at a custom path, or creates its default path under HOME.
    ///
    /// # Errors
    /// Returns an error if the Space, path, or daemon cannot be verified.
    pub fn mount_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: Option<&str>,
    ) -> io::Result<String> {
        match account_request(
            runtime,
            AccountRequest::MountSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.map(Into::into),
            },
        )? {
            AccountReply::Mounted(value) => Ok(value.path),
            _ => Err(unexpected_reply()),
        }
    }

    /// Mounts saved local Space data read-only, with automatic work disabled.
    ///
    /// # Errors
    /// Refuses missing retained ownership/activation, unsafe mount state or enabled automatic work.
    pub fn mount_offline_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: &str,
    ) -> io::Result<String> {
        match account_request(
            runtime,
            AccountRequest::OfflineMountSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.into(),
            },
        )? {
            AccountReply::Mounted(value) => Ok(value.path),
            _ => Err(unexpected_reply()),
        }
    }

    /// Mounts retained files for explicit local editing without credentials.
    ///
    /// # Errors
    /// Requires retained bindings and safe mount ownership.
    pub fn mount_writable_offline_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: &str,
    ) -> io::Result<String> {
        match account_request(
            runtime,
            AccountRequest::WritableOfflineMountSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.into(),
            },
        )? {
            AccountReply::Mounted(value) => Ok(value.path),
            _ => Err(unexpected_reply()),
        }
    }

    /// Unmounts one Space owned by the daemon without affecting other mounts.
    ///
    /// # Errors
    /// Returns an error if the Space is not mounted or unmounting fails.
    pub fn unmount_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
    ) -> io::Result<()> {
        account_request(
            runtime,
            AccountRequest::UnmountSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
            },
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    /// Lists live mounts and verified owner records requiring recovery.
    ///
    /// # Errors
    /// Returns an error when owner records are unsafe or ambiguous.
    pub fn mounts(&self, runtime: &RuntimeDir) -> io::Result<Vec<MountInfo>> {
        match account_request(runtime, AccountRequest::Mounts)? {
            AccountReply::Mounts(value) => Ok(value),
            _ => Err(unexpected_reply()),
        }
    }

    /// Recovers a stale recorded mount at the explicitly supplied path.
    ///
    /// # Errors
    /// Returns an error if the mount record, identity or unmount cannot be verified.
    pub fn recover_mount(&self, runtime: &RuntimeDir, path: &str) -> io::Result<()> {
        account_request(runtime, AccountRequest::RecoverMount { path: path.into() })
            .map(|_| ())
            .map_err(Into::into)
    }
}

fn unexpected_reply() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unexpected typed daemon reply")
}

//! Foreground user daemon and private local client.

mod local;
mod scheduler;

use std::io::{self, Read};

pub use cirrus_account::{
    CleanCacheStatus, JournalEntry, JournalPage, JournalState, JournalSummary,
    NamespaceStorageReservation, SqlStorageReservation, StorageLimits, StorageLimitsView,
    StorageStatus, StorageUsage, SyncPhase, SyncStatus, WriteTurnOutcome,
};
use cirrus_runtime::RuntimeDir;
use serde::{Deserialize, Serialize};

/// A validated immediate child of a selected Space directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// Original UTF-8 child name.
    pub name: String,
    /// Whether the child is a directory.
    pub directory: bool,
    /// File size, absent for directories.
    pub size: Option<u64>,
}

/// State of a mount owned by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MountState {
    /// The daemon owns an active FUSE mount.
    Mounted,
    /// A stale mount needs explicit recovery.
    RecoveryRequired,
}

/// Identifies one mount and its Space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    /// Canonical account URL.
    pub instance: String,
    /// Stable Space ID.
    pub space_id: String,
    /// Space display label, currently the ID if a name is unavailable.
    pub space_name: String,
    /// Absolute mount path.
    pub path: String,
    /// Current lifecycle state.
    pub state: MountState,
    /// Local-only read-only mode for a live mount; unknown after a crash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_read_only: Option<bool>,
    /// Explicit local-only file editing mode; unknown on stale crash records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_writable: Option<bool>,
}

/// A journal-referenced immutable dirty snapshot, not a remote-content assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedStaged {
    /// Journal row ID.
    pub id: i64,
    /// Space containing the operation.
    pub space: String,
    /// Original Space path.
    pub path: Vec<String>,
    /// Journal state, not a claim about remote content.
    pub state: String,
    /// Private staging filename.
    pub staged_file: String,
    /// Current file size, absent if the file cannot be inspected safely.
    pub size: Option<u64>,
    /// Current content digest, absent if unavailable.
    pub sha256: Option<String>,
    /// Selector binding the journal entry and immutable byte-interpretation root.
    pub selector: Option<String>,
    /// Explanation of the digest's limitations.
    pub integrity: String,
    /// The copy is local and may be stale.
    pub status: String,
}

/// A pin root in an explicitly named Space.
#[derive(Debug, Clone)]
pub struct RetainedPin {
    /// Space ID.
    pub space: String,
    /// Pin root components.
    pub root: Vec<String>,
}

/// A retained file from an explicitly named pin, not necessarily current remotely.
#[derive(Debug, Clone)]
pub struct RetainedPinFile {
    /// Space path components.
    pub path: Vec<String>,
    /// Opaque version selector.
    pub selector: String,
    /// Stored length when valid metadata is available.
    pub size: Option<u64>,
}

/// An immutable displaced pin capture, independent of namespace paths.
#[derive(Debug, Clone, Deserialize)]
pub struct RetainedPinCopy {
    /// Stable local capture ID, independent of any active path.
    pub id: i64,
    /// Original immutable Space ID.
    pub space: String,
    /// Original captured logical root, not a live namespace binding.
    pub root: Vec<String>,
    /// Replacement target path at capture admission.
    pub displaced_path: Vec<String>,
    /// Resource ID from the separate replacement-admission proof.
    pub target_id: String,
    /// Strong ETag from the separate replacement-admission proof.
    pub target_etag: String,
}

/// A directory identity or exportable file version in a retained pin capture.
#[derive(Debug, Clone, Deserialize)]
pub struct RetainedPinCopyEntry {
    /// Captured entry kind: directory metadata or file version.
    pub kind: String,
    /// Original path within the capture.
    pub path: Vec<String>,
    /// Captured directory ID, absent for the explicit Space-root sentinel.
    pub id: Option<String>,
    /// Exact file version/chunk selector, absent for directories.
    pub selector: Option<String>,
    /// File length, absent for directory metadata.
    pub size: Option<u64>,
}

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

    /// Describes this build's capabilities, not the status of a running process.
    pub fn scaffold_status(&self) -> &'static str {
        "daemon account, Space and experimental staged-write file mounts available"
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
        local::serve(runtime, true)
    }

    /// Runs diagnostics without automatic transfers or startup account access.
    /// Explicit commands remain available; persistent activations are not removed.
    ///
    /// # Errors
    /// Returns an error if the private local service cannot be safely established.
    pub fn run_without_automatic_sync(&self, runtime: &RuntimeDir) -> io::Result<()> {
        local::serve(runtime, false)
    }

    /// Queries a running daemon; never starts one.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint, peer or response cannot be verified.
    pub fn status(&self, runtime: &RuntimeDir) -> io::Result<&'static str> {
        local::request(runtime, local::Request::Status)
    }

    /// Requests a running daemon to stop and clean up its socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint, peer or response cannot be verified.
    pub fn stop(&self, runtime: &RuntimeDir) -> io::Result<()> {
        local::request(runtime, local::Request::Stop).map(|_| ())
    }

    /// Reports shared local clean-cache payload usage without accessing the server or keyring.
    ///
    /// # Errors
    /// Returns an error if the daemon or cache cannot be inspected.
    pub fn clean_cache_status(&self, runtime: &RuntimeDir) -> io::Result<CleanCacheStatus> {
        let rows = local::account_request(runtime, local::AccountRequest::CleanCacheStatus)?;
        match rows.as_slice() {
            [(kind, value)] if kind == "clean-cache" => {
                serde_json::from_str(value).map_err(io::Error::other)
            }
            _ => Err(io::Error::other("invalid clean cache status response")),
        }
    }

    /// Observes shared account-owner storage without credentials or network access.
    ///
    /// # Errors
    /// Returns an error if the daemon, paths or local storage cannot be inspected.
    pub fn storage_status(&self, runtime: &RuntimeDir) -> io::Result<StorageStatus> {
        let rows = local::account_request(runtime, local::AccountRequest::StorageStatus)?;
        match rows.as_slice() {
            [(kind, value)] if kind == "storage" => {
                serde_json::from_str(value).map_err(io::Error::other)
            }
            _ => Err(io::Error::other("invalid storage status response")),
        }
    }

    /// Reads shared local allocation-pressure limits without credentials/network.
    ///
    /// # Errors
    /// Returns an error for unavailable daemon or invalid/unsafe configuration.
    pub fn storage_limits(&self, runtime: &RuntimeDir) -> io::Result<StorageLimitsView> {
        self.storage_limits_request(runtime, local::AccountRequest::StorageLimits)
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
        self.storage_limits_request(runtime, local::AccountRequest::SetStorageLimits { limits })
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
        let rows = local::account_request(
            runtime,
            local::AccountRequest::ReleaseStorageReservation { store, token },
        )?;
        match rows.as_slice() {
            [(kind, value)] if kind == "storage-reservation-released" && value == "{}" => Ok(()),
            _ => Err(io::Error::other(
                "invalid storage reservation release response",
            )),
        }
    }

    fn storage_limits_request(
        &self,
        runtime: &RuntimeDir,
        request: local::AccountRequest,
    ) -> io::Result<StorageLimitsView> {
        let rows = local::account_request(runtime, request)?;
        match rows.as_slice() {
            [(kind, value)] if kind == "storage-limits" => {
                serde_json::from_str(value).map_err(io::Error::other)
            }
            _ => Err(io::Error::other("invalid storage limits response")),
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
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
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
        local::account_request(
            runtime,
            local::AccountRequest::Connect {
                instance: instance.to_owned(),
                ca_pem,
                attempt: attempt.to_owned(),
            },
        )
        .map(|_| ())
    }

    /// Requests cancellation before the attempt starts exchanging its authorization code.
    ///
    /// # Errors
    /// Returns an error if the attempt is no longer active or is finishing.
    pub fn cancel_connect(&self, runtime: &RuntimeDir, attempt: &str) -> io::Result<()> {
        local::cancel_connect(runtime, attempt)
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
        local::account_request(
            runtime,
            local::AccountRequest::Spaces {
                instance: instance.to_owned(),
            },
        )
    }

    /// Selects a freshly verified Space through the daemon.
    ///
    /// # Errors
    /// Returns an error if the daemon or account operation fails.
    pub fn select_space(&self, runtime: &RuntimeDir, instance: &str, id: &str) -> io::Result<()> {
        local::account_request(
            runtime,
            local::AccountRequest::SelectSpace {
                instance: instance.to_owned(),
                id: id.to_owned(),
            },
        )
        .map(|_| ())
    }

    /// Lists a directory in the selected Space via the daemon.
    ///
    /// # Errors
    /// Returns an error for invalid paths, incomplete listings or daemon failures.
    pub fn directory(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        path: Vec<String>,
    ) -> io::Result<Vec<DirectoryEntry>> {
        local::directory_request(runtime, instance, path)
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
        local::offline_directory_request(runtime, instance, space, path)
    }

    /// Stages a local file without modifying the remote Space.
    ///
    /// # Errors
    /// Returns an error if the source or durable state cannot be verified.
    pub fn stage_file(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        path: Vec<String>,
        source: &str,
    ) -> io::Result<()> {
        local::account_request(
            runtime,
            local::AccountRequest::StageFile {
                instance: instance.to_owned(),
                path,
                source: source.to_owned(),
            },
        )
        .map(|_| ())
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
        local::account_request(
            runtime,
            local::AccountRequest::StageFileSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path,
                source: source.to_owned(),
            },
        )
        .map(|_| ())
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
        local::account_request(
            runtime,
            local::AccountRequest::EvictSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path,
            },
        )
        .map(|_| ())
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
        local::journal_request(runtime, instance, space, before)
    }

    /// Requests best-effort synchronization of staged files.
    ///
    /// # Errors
    /// Returns an error when operations remain pending, conflicted or uncertain.
    pub fn sync_pending(&self, runtime: &RuntimeDir, instance: &str) -> io::Result<()> {
        local::account_request(
            runtime,
            local::AccountRequest::Sync {
                instance: instance.to_owned(),
            },
        )
        .map(|_| ())
    }

    /// Requests best-effort synchronization of one listed Space.
    ///
    /// # Errors
    /// Returns an error if the Space is unlisted or has unresolved operations.
    pub fn sync_space(&self, runtime: &RuntimeDir, instance: &str, space: &str) -> io::Result<()> {
        local::account_request(
            runtime,
            local::AccountRequest::SyncSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
            },
        )
        .map(|_| ())
    }

    /// Runs one explicit Space write-transfer turn, releasing ownership on return.
    ///
    /// # Errors
    /// Returns an error for account, storage or IPC failure.
    pub fn write_turn(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
    ) -> io::Result<WriteTurnOutcome> {
        local::write_turn_request(runtime, instance, space)
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
        local::sync_status_request(runtime, instance, space)
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
        local::account_request(
            runtime,
            local::AccountRequest::Acknowledge {
                instance: instance.to_owned(),
                staged: staged.to_owned(),
            },
        )
        .map(|_| ())
    }

    /// Pins a file or directory tree for experimental offline use.
    ///
    /// # Errors
    /// Returns an error if the pin cannot be verified and stored.
    pub fn pin(&self, runtime: &RuntimeDir, instance: &str, path: Vec<String>) -> io::Result<()> {
        local::account_request(
            runtime,
            local::AccountRequest::Pin {
                instance: instance.to_owned(),
                path,
            },
        )
        .map(|_| ())
    }

    /// Removes a previously requested pin.
    ///
    /// # Errors
    /// Returns an error if the account or offline state is unavailable.
    pub fn unpin(&self, runtime: &RuntimeDir, instance: &str, path: Vec<String>) -> io::Result<()> {
        local::account_request(
            runtime,
            local::AccountRequest::Unpin {
                instance: instance.to_owned(),
                path,
            },
        )
        .map(|_| ())
    }

    /// Lists pin paths and their observed availability status.
    ///
    /// # Errors
    /// Returns an error if the account or offline state is unavailable.
    pub fn pins(&self, runtime: &RuntimeDir, instance: &str) -> io::Result<Vec<(String, String)>> {
        local::account_request(
            runtime,
            local::AccountRequest::Pins {
                instance: instance.to_owned(),
            },
        )
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
        local::account_request(
            runtime,
            local::AccountRequest::PinSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path,
            },
        )
        .map(|_| ())
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
        local::account_request(
            runtime,
            local::AccountRequest::UnpinSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path,
            },
        )
        .map(|_| ())
    }

    /// Lists pins in an explicitly verified Space.
    ///
    /// # Errors
    /// Returns an error if Space verification or pin listing fails.
    pub fn pins_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
    ) -> io::Result<Vec<(String, String)>> {
        local::account_request(
            runtime,
            local::AccountRequest::PinsSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
            },
        )
    }

    /// Lists a page of retained pin roots, without connecting to the server.
    ///
    /// # Errors
    /// Returns an error if the daemon or local state is unavailable.
    pub fn retained_pins(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        offset: u32,
    ) -> io::Result<Vec<(String, String)>> {
        local::account_request(
            runtime,
            local::AccountRequest::RetainedPins {
                instance: instance.to_owned(),
                offset,
            },
        )
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
    ) -> io::Result<Vec<RetainedStaged>> {
        local::account_request(
            runtime,
            local::AccountRequest::RetainedStaged {
                instance: instance.to_owned(),
                offset,
            },
        )?
        .into_iter()
        .map(|(_, value)| serde_json::from_str(&value).map_err(io::Error::other))
        .collect()
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
        local::account_request(
            runtime,
            local::AccountRequest::ExportStaged {
                instance: instance.to_owned(),
                id,
                selector: selector.to_owned(),
                destination: destination.to_owned(),
            },
        )
        .map(|_| ())
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
    ) -> io::Result<Vec<RetainedPin>> {
        self.retained_pins(runtime, instance, offset)?
            .into_iter()
            .map(|(space, root)| {
                Ok(RetainedPin {
                    space,
                    root: serde_json::from_str(&root).map_err(io::Error::other)?,
                })
            })
            .collect()
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
    ) -> io::Result<Vec<RetainedPinFile>> {
        self.retained_files(runtime, instance, space, root, offset)?
            .into_iter()
            .map(|(path, value)| {
                let (selector, metadata) = value
                    .split_once('\n')
                    .ok_or_else(|| io::Error::other("invalid retained version"))?;
                let version: serde_json::Value =
                    serde_json::from_str(metadata).map_err(io::Error::other)?;
                Ok(RetainedPinFile {
                    path: serde_json::from_str(&path).map_err(io::Error::other)?,
                    selector: selector.to_owned(),
                    size: version.get("size").and_then(serde_json::Value::as_u64),
                })
            })
            .collect()
    }

    /// Lists retained file metadata; each value is a selector, newline, and
    /// stored version JSON. The selector does not assert integrity.
    ///
    /// # Errors
    /// Returns an error if the daemon or local state is unavailable.
    pub fn retained_files(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        root: Vec<String>,
        offset: u32,
    ) -> io::Result<Vec<(String, String)>> {
        local::account_request(
            runtime,
            local::AccountRequest::RetainedFiles {
                instance: instance.to_owned(),
                space: space.to_owned(),
                root,
                offset,
            },
        )
    }

    /// Lists independent immutable displaced-pin copy IDs and capture metadata.
    ///
    /// # Errors
    /// Returns an error if local retained state or the service is unavailable.
    pub fn pin_copies(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        offset: u32,
    ) -> io::Result<Vec<(String, String)>> {
        local::account_request(
            runtime,
            local::AccountRequest::PinCopies {
                instance: instance.to_owned(),
                offset,
            },
        )
    }

    /// Lists directories and selected file versions in one retained pin copy.
    ///
    /// # Errors
    /// Returns an error for invalid selection or unavailable retained metadata.
    pub fn pin_copy_entries(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        id: i64,
        offset: u32,
    ) -> io::Result<Vec<(String, String)>> {
        local::account_request(
            runtime,
            local::AccountRequest::PinCopyEntries {
                instance: instance.to_owned(),
                space: space.to_owned(),
                id,
                offset,
            },
        )
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
    ) -> io::Result<Vec<RetainedPinCopy>> {
        self.pin_copies(runtime, instance, offset)?
            .into_iter()
            .map(|(_, value)| serde_json::from_str(&value).map_err(io::Error::other))
            .collect()
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
    ) -> io::Result<Vec<RetainedPinCopyEntry>> {
        self.pin_copy_entries(runtime, instance, space, id, offset)?
            .into_iter()
            .map(|(_, value)| serde_json::from_str(&value).map_err(io::Error::other))
            .collect()
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
        local::account_request(
            runtime,
            local::AccountRequest::ExportPinCopy {
                instance: instance.to_owned(),
                space: space.to_owned(),
                id: source.0,
                path: source.1,
                selector: selector.to_owned(),
                destination: destination.to_owned(),
            },
        )
        .map(|_| ())
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
        local::account_request(
            runtime,
            local::AccountRequest::RemovePinCopy {
                instance: instance.to_owned(),
                space: space.to_owned(),
                id,
            },
        )
        .map(|_| ())
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
        local::account_request(
            runtime,
            local::AccountRequest::ExportRetained {
                instance: instance.to_owned(),
                space: space.to_owned(),
                root: source.0,
                path: source.1,
                selector: selector.to_owned(),
                destination: destination.to_owned(),
            },
        )
        .map(|_| ())
    }

    /// Mounts the selected Space at an existing empty private directory.
    ///
    /// # Errors
    /// Returns an error if the mount, account or daemon is unavailable.
    pub fn mount(&self, runtime: &RuntimeDir, instance: &str, path: &str) -> io::Result<()> {
        local::mount_request(
            runtime,
            local::AccountRequest::Mount {
                instance: instance.to_owned(),
                path: path.to_owned(),
            },
        )
        .map(|_| ())
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
        let rows = local::account_request(
            runtime,
            local::AccountRequest::MountSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.map(str::to_owned),
            },
        )?;
        match rows.as_slice() {
            [(id, path)] if id == space => Ok(path.clone()),
            _ => Err(io::Error::other("invalid mount response")),
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
        let rows = local::account_request(
            runtime,
            local::AccountRequest::OfflineMountSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.to_owned(),
            },
        )?;
        match rows.as_slice() {
            [(id, path)] if id == space => Ok(path.clone()),
            _ => Err(io::Error::other("invalid offline mount response")),
        }
    }

    /// Mounts retained files for explicit local editing without credentials.
    ///
    /// # Errors
    /// Requires automatic work disabled, retained bindings and safe mount ownership.
    pub fn mount_writable_offline_space(
        &self,
        runtime: &RuntimeDir,
        instance: &str,
        space: &str,
        path: &str,
    ) -> io::Result<String> {
        let rows = local::account_request(
            runtime,
            local::AccountRequest::WritableOfflineMountSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.to_owned(),
            },
        )?;
        match rows.as_slice() {
            [(id, path)] if id == space => Ok(path.clone()),
            _ => Err(io::Error::other("invalid offline mount response")),
        }
    }

    /// Unmounts the Space owned by the daemon.
    ///
    /// # Errors
    /// Returns an error if no mount is owned or unmounting fails.
    pub fn unmount(&self, runtime: &RuntimeDir) -> io::Result<()> {
        local::mount_request(runtime, local::AccountRequest::Unmount).map(|_| ())
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
        local::mount_request(
            runtime,
            local::AccountRequest::UnmountSpace {
                instance: instance.to_owned(),
                space: space.to_owned(),
            },
        )
        .map(|_| ())
    }

    /// Returns the daemon's current mountpoint, if any.
    ///
    /// # Errors
    /// Returns an error if the daemon or mount state is unavailable.
    pub fn mount_status(&self, runtime: &RuntimeDir) -> io::Result<Option<String>> {
        local::mount_request(runtime, local::AccountRequest::MountStatus)
    }

    /// Lists live mounts and verified owner records requiring recovery.
    ///
    /// # Errors
    /// Returns an error when owner records are unsafe or ambiguous.
    pub fn mounts(&self, runtime: &RuntimeDir) -> io::Result<Vec<MountInfo>> {
        local::account_request(runtime, local::AccountRequest::Mounts)?
            .into_iter()
            .map(|(_, value)| serde_json::from_str(&value).map_err(io::Error::other))
            .collect()
    }

    /// Recovers a stale recorded mount at the explicitly supplied path.
    ///
    /// # Errors
    /// Returns an error if the mount record, identity or unmount cannot be verified.
    pub fn recover_mount(&self, runtime: &RuntimeDir, path: &str) -> io::Result<()> {
        local::mount_request(
            runtime,
            local::AccountRequest::RecoverMount {
                path: path.to_owned(),
            },
        )
        .map(|_| ())
    }
}

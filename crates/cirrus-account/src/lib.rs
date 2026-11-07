//! Browser-based OpenID account connection and read-only Space discovery.

mod browser;
mod cache;
mod callback;
mod dav;
mod executor;
mod http;
mod offline;
mod ownership;
mod recovery;
mod secrets;
mod storage;
mod sync;
mod upload;

pub use storage::{
    NamespaceStorageReservation, SqlStorageReservation, StorageLimits, StorageLimitsView,
    StorageStatus, StorageUsage,
};

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cirrus_discovery::{Configuration, Discovery};
use cirrus_runtime::RuntimeDir;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreTokenType,
};
use openidconnect::{
    AccessTokenHash, AuthType, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use url::Url;

pub use browser::{Browser, PortalBrowser};
pub use dav::Entry;
mod directory;
pub use directory::DirectorySnapshot;
use secrets::{AccountData, Store};
pub use sync::{ForegroundPriority, SyncPhase, SyncStatus};
pub use upload::WriteTurnOutcome;

/// One locally durable change to an immutable dirty extent map.
#[derive(Clone, Copy, Debug)]
pub enum DirtyMutation<'a> {
    /// Capture only the exact original content metadata, without downloading bytes.
    Preserve,
    /// Persist only the supplied bytes at a checked logical offset.
    Write { offset: u64, bytes: &'a [u8] },
    /// Change EOF; truncated original bytes never reappear on extension.
    Resize(u64),
}

/// A directory identity captured when a local operation was journaled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectoryIdentity {
    /// A directory observed on the server.
    Remote(String),
    /// A locally created directory identified by its journal operation.
    Pending(i64),
}

impl DirectoryIdentity {
    /// Converts a mounted directory's resource ID to a durable identity.
    ///
    /// # Errors
    /// Returns an error if the ID is malformed or reserved for another resource type.
    pub fn from_resource_id(id: &str) -> Result<Self, AccountError> {
        if let Some(value) = id.strip_prefix("cirrus-dir:") {
            let id = value
                .parse::<i64>()
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| AccountError::new("invalid local directory identity"))?;
            Ok(Self::Pending(id))
        } else if dav::valid_remote_id(id) {
            Ok(Self::Remote(id.to_owned()))
        } else {
            Err(AccountError::new("invalid remote directory identity"))
        }
    }
}

/// Parent identities captured on both sides of a local rename.
#[derive(Clone, Copy, Debug)]
pub struct RenameParents<'a> {
    /// The source path's ancestor identities.
    pub source: &'a [DirectoryIdentity],
    /// The destination path's ancestor identities.
    pub destination: &'a [DirectoryIdentity],
}

#[cfg(feature = "fault-injection")]
fn wait_test_window(variable: &str) -> Result<(), AccountError> {
    if let Some(marker) = std::env::var_os(variable) {
        let marker = std::path::Path::new(&marker);
        if marker.is_file() {
            std::fs::write(marker.with_extension("waiting"), b"waiting")
                .map_err(|_| AccountError::new("cannot mark test window"))?;
            for _ in 0..1500 {
                if !marker.exists() {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            return Err(AccountError::new("test window timed out"));
        }
    }
    Ok(())
}

/// A discovered Space; this does not imply that it is mounted or offline-ready.
#[derive(Debug, Clone)]
pub struct Space {
    id: String,
    name: String,
}

/// Stored clean-range payload usage across all accounts and Spaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanCacheStatus {
    /// Bytes in cached range bodies, excluding SQLite overhead and other local data.
    pub bytes: u64,
    /// Number of stored clean ranges.
    pub ranges: u64,
    /// Maximum total range-body bytes.
    pub byte_limit: u64,
    /// Maximum number of stored clean ranges.
    pub range_limit: u64,
}

/// One locally recorded operation and its current observed state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    /// Monotonic local journal ID.
    pub id: i64,
    /// Space-relative path as displayed to the user.
    pub path: String,
    /// Stable Space ID.
    pub space: String,
    /// Locally recorded operation type.
    pub operation: String,
    /// Staging filename or namespace operation token.
    pub token: String,
    /// Locally observed state, not a guarantee of current remote content.
    pub state: JournalState,
    /// Diagnostic recorded with this operation, if any.
    pub detail: Option<String>,
}

/// Locally recorded operation state, optionally annotated with current upload activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalState {
    /// Waiting for synchronization.
    Pending,
    /// This daemon still considers the write active after reading the journal snapshot.
    Uploading,
    /// A conflict requires inspection.
    Conflict,
    /// An outcome is uncertain or an operation is still in progress.
    UncertainOrInProgress,
    /// Historically confirmed, without a guarantee about current remote state.
    Synced,
    /// Locally acknowledged or superseded.
    Resolved,
}

impl JournalEntry {
    /// Formats the local state, Space, token and diagnostic for display.
    pub fn status(&self) -> String {
        let state = match self.state {
            JournalState::Pending => "pending",
            JournalState::Uploading => "uploading",
            JournalState::Conflict => "conflict",
            JournalState::UncertainOrInProgress => "uncertain or operation in progress",
            JournalState::Synced => "synced",
            JournalState::Resolved => "resolved",
        };
        format!(
            "{state} (Space {}, {} {}){}",
            self.space,
            if self.operation == "write" {
                "staged file"
            } else {
                self.operation.as_str()
            },
            self.token,
            self.detail
                .as_ref()
                .map_or_else(String::new, |value| format!(": {value}"))
        )
    }
}

/// A bounded page of journal entries in descending journal-ID order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalPage {
    /// Counts for the requested account or Space at the same local database snapshot.
    pub summary: JournalSummary,
    /// Entries in this page.
    pub entries: Vec<JournalEntry>,
    /// Exclusive cursor for an older page, if one exists.
    pub next_before: Option<i64>,
}

/// Journal counts for the requested scope; uncertain includes operations in progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalSummary {
    /// Operations waiting to run.
    pub pending: u64,
    /// Operations requiring conflict inspection.
    pub conflict: u64,
    /// Uncertain outcomes or operations currently in progress.
    pub uncertain_or_in_progress: u64,
    /// Historically confirmed operations, not a current remote-state guarantee.
    pub synced: u64,
    /// Locally acknowledged or superseded operations.
    pub resolved: u64,
}

/// A mount's account and Space binding, verified online or from retained activation.
#[derive(Clone)]
pub struct MountBinding {
    instance: String,
    space: String,
    name: Option<String>,
    issuer: String,
    subject: String,
    offline: bool,
    offline_writable: bool,
}

/// One complete cached-session observation and its exact local confirmations.
pub struct MountDirectoryRefresh {
    /// Validated directory, including retained local overlays.
    pub entries: DirectorySnapshot,
    /// Staged versions that match a durably confirmed remote version.
    pub files: Vec<(FileVersion, FileVersion)>,
    /// Local directories that match their confirmed remote identities.
    pub directories: Vec<(Vec<String>, String, Entry)>,
}

impl MountBinding {
    /// Whether this mount serves retained local state without credentials.
    pub fn is_offline(&self) -> bool {
        self.offline
    }
    /// Whether explicitly authorized local edits and file creation are enabled.
    pub fn is_offline_writable(&self) -> bool {
        self.offline_writable
    }
    /// Returns the canonical account instance URL.
    pub fn instance(&self) -> &str {
        &self.instance
    }
    /// Returns the verified Space ID.
    pub fn space_id(&self) -> &str {
        &self.space
    }
    /// Returns the uniquely named Space label, if verified online.
    pub fn unique_name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

/// Metadata captured for one experimental read-only open.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileVersion {
    instance: String,
    space: String,
    path: Vec<String>,
    id: String,
    etag: String,
    size: u64,
    checksums: Vec<String>,
}

#[derive(PartialEq, Eq)]
struct PinTree {
    is_dir: bool,
    directories: Vec<(Vec<String>, String)>,
    files: Vec<FileVersion>,
}

impl FileVersion {
    /// Length recorded at open.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether two snapshots refer to the same resource in the same Space.
    pub fn same_resource(&self, other: &Self) -> bool {
        self.instance == other.instance && self.space == other.space && self.id == other.id
    }

    /// Stable server file identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Strong ETag recorded at open.
    pub fn etag(&self) -> &str {
        &self.etag
    }

    /// Server-provided checksums, not yet independently verified.
    pub fn checksums(&self) -> &[String] {
        &self.checksums
    }
}

impl Space {
    /// Stable server identifier for the Space.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Server-provided display name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Account access with serialized credential changes and bounded concurrent reads.
pub struct Accounts {
    runtime: RuntimeDir,
    pending: Mutex<HashMap<String, AccountData>>,
    operation: Mutex<()>,
    pending_guard: Mutex<Option<ownership::Guard>>,
    cancelled: Arc<AtomicBool>,
    read_session: Mutex<Option<ReadSession>>,
    session_ready: Condvar,
    reads_in_flight: Mutex<usize>,
    read_available: Condvar,
    metadata_generation: AtomicU64,
    clean_cache_generation: AtomicU64,
    clean_cache_update: Mutex<()>,
    sync_staging: RwLock<bool>,
    read_ahead_active: AtomicBool,
    active_writes: Mutex<HashSet<i64>>,
    background_admission: Arc<sync::BackgroundAdmission>,
    automatic_active: Arc<AtomicBool>,
}

/// Cancellation fence for one browser sign-in attempt.
#[derive(Debug, Default)]
pub struct SignIn {
    phase: Mutex<SignInPhase>,
    cancelled: AtomicBool,
}

#[derive(Debug, Default)]
enum SignInPhase {
    #[default]
    Pending,
    Finishing,
    Cancelled,
}

impl SignIn {
    /// Cancels the attempt before token exchange starts.
    pub fn cancel(&self) -> Result<(), AccountError> {
        let mut phase = self
            .phase
            .lock()
            .map_err(|_| AccountError::new("sign-in state unavailable"))?;
        match *phase {
            SignInPhase::Pending | SignInPhase::Cancelled => {
                *phase = SignInPhase::Cancelled;
                self.cancelled.store(true, Ordering::Release);
                Ok(())
            }
            SignInPhase::Finishing => Err(AccountError::new(
                "sign-in is finishing; wait for its result",
            )),
        }
    }

    fn check(&self) -> Result<(), AccountError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(AccountError::new("sign-in cancelled; you can try again"))
        } else {
            Ok(())
        }
    }

    fn begin_exchange(&self) -> Result<(), AccountError> {
        let mut phase = self
            .phase
            .lock()
            .map_err(|_| AccountError::new("sign-in state unavailable"))?;
        if matches!(*phase, SignInPhase::Cancelled) {
            return Err(AccountError::new("sign-in cancelled; you can try again"));
        }
        *phase = SignInPhase::Finishing;
        Ok(())
    }
}

#[derive(Clone)]
struct ReadSession {
    base: Url,
    account: AccountData,
    client: reqwest::blocking::Client,
}

fn bound_space<'a>(
    session: &'a ReadSession,
    binding: Option<&'a MountBinding>,
) -> Result<&'a str, AccountError> {
    if let Some(binding) = binding {
        if binding.offline {
            return Err(AccountError::new(
                "offline mount is read-only and cannot authenticate",
            ));
        }
        if binding.instance != session.base.as_str()
            || binding.issuer != session.account.issuer
            || binding.subject != session.account.subject
        {
            return Err(AccountError::new("mounted account identity changed"));
        }
        return Ok(&binding.space);
    }
    session
        .account
        .selected_space
        .as_deref()
        .ok_or_else(|| AccountError::new("no Space is selected"))
}

struct ReadPermit<'a>(&'a Accounts);

impl Drop for ReadPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0.reads_in_flight.lock() {
            *active -= 1;
            self.0.read_available.notify_one();
        }
    }
}

// Keep ownership until every rotated credential has been persisted.
struct Operation<'a> {
    accounts: &'a Accounts,
    lock: Option<MutexGuard<'a, ()>>,
    guard: Option<ownership::Guard>,
}

/// A remotely verified tree move holding account ownership until it is committed.
pub struct PreparedRemoteTree<'a> {
    // Drain identity-checked local staging before releasing account ownership.
    _staging: Option<SyncStaging<'a>>,
    _guard: Option<Operation<'a>>,
    _offline_owner: Option<rustix::fd::OwnedFd>,
    _sync_owner: Option<rustix::fd::OwnedFd>,
    offline: Option<MountBinding>,
    cancelled: Arc<AtomicBool>,
    instance: String,
    space: String,
    source: &'a [String],
    destination: &'a [String],
    entry: Entry,
    target: Option<Entry>,
    local_target: Option<&'a str>,
    parents: RenameParents<'a>,
    open_versions: &'a [FileVersion],
    open_directories: &'a [(Vec<String>, String)],
    relocated: Vec<FileVersion>,
}

impl PreparedRemoteTree<'_> {
    /// Atomically journals the prepared tree move and returns rebased open versions.
    ///
    /// # Errors
    /// Returns an error if the durable journal no longer permits the move.
    pub fn commit(self) -> Result<Vec<FileVersion>, AccountError> {
        let _turn = self
            .offline
            .as_ref()
            .map(|_| ownership::local_state_turn(Arc::clone(&self.cancelled)))
            .transpose()?;
        let mut attempts = 0;
        loop {
            let result = offline::queue_tree_move(offline::TreeMoveRequest {
                instance: &self.instance,
                space: &self.space,
                source: self.source,
                destination: self.destination,
                entry: &self.entry,
                target: self.target.as_ref(),
                local_target: self.local_target,
                parents: self.parents,
                open_versions: self.open_versions,
                open_directories: self.open_directories,
                offline: self.offline.as_ref(),
            });
            if self.offline.is_some()
                && attempts < 7
                && result
                    .as_ref()
                    .is_err_and(|error| error.is_metadata_changed())
            {
                attempts += 1;
                continue;
            }
            result?;
            break;
        }
        Ok(self.relocated)
    }
}

/// A verified empty-directory move holding account ownership until it is committed.
pub struct PreparedEmptyDirectory<'a> {
    // Close staging admission and wait for its local readers before releasing
    // the original exclusive account guard (field drop order matters).
    _staging: SyncStaging<'a>,
    _guard: Operation<'a>,
    instance: String,
    space: String,
    source: &'a [String],
    destination: &'a [String],
    base: (&'a str, &'a str),
    parents: RenameParents<'a>,
}

impl PreparedEmptyDirectory<'_> {
    /// Atomically journals the prepared empty-directory move.
    ///
    /// # Errors
    /// Returns an error if the durable journal no longer permits the move.
    pub fn commit(self) -> Result<i64, AccountError> {
        offline::queue_empty_directory_move(
            &self.instance,
            &self.space,
            self.source,
            self.destination,
            self.base,
            self.parents.source,
            self.parents.destination,
        )
    }
}

// The account ownership guard stays held while this window is open. Readers
// finish their local journal transactions before the guard can be released.
struct SyncStaging<'a>(&'a Accounts);

struct LocalOperation<'a> {
    _sync_window: Option<RwLockReadGuard<'a, bool>>,
    _operation: Option<OwnedLocalOperation<'a>>,
}

/// A verified file rename holding account identity stable until it is committed.
pub struct PreparedFileRename<'a> {
    _guard: Option<OwnedLocalOperation<'a>>,
    _offline_owner: Option<rustix::fd::OwnedFd>,
    source: &'a FileVersion,
    destination: &'a [String],
    target: Option<(&'a str, &'a str)>,
    pending_target: Option<&'a FileVersion>,
    parents: RenameParents<'a>,
    offline: Option<MountBinding>,
    cancelled: Arc<AtomicBool>,
}

impl PreparedFileRename<'_> {
    /// Atomically journals the prepared file rename.
    ///
    /// # Errors
    /// Returns an error if either staged version or its parents changed.
    pub fn commit(self) -> Result<(FileVersion, Option<FileVersion>), AccountError> {
        let _state_turn = self
            .offline
            .as_ref()
            .map(|_| ownership::local_state_turn(Arc::clone(&self.cancelled)))
            .transpose()?;
        let mut retries = 0;
        loop {
            let result = if let Some(target) = self.pending_target {
                offline::replace_pending_write(
                    self.source,
                    target,
                    self.parents.source,
                    self.parents.destination,
                    self.offline.as_ref(),
                )
            } else {
                offline::rename_staged_write(
                    self.source,
                    self.destination,
                    self.target,
                    self.parents.source,
                    self.parents.destination,
                    self.offline.as_ref(),
                )
                .map(|version| (version, None))
            };
            // Both paths reject a stale database-wide reservation plan before
            // any mutation. Replan with the SAME prepared versions/parents:
            // each fresh transaction revalidates them, never rebasing a changed
            // source/target. Other errors (including unknown commit) never retry.
            if retries < 7
                && result
                    .as_ref()
                    .is_err_and(|error| error.is_metadata_changed())
            {
                retries += 1;
                continue;
            }
            return result;
        }
    }
}

struct OwnedLocalOperation<'a> {
    _shared: Option<ownership::Guard>,
    _exclusive: Option<Operation<'a>>,
}

struct ActiveWrite<'a> {
    accounts: &'a Accounts,
    id: i64,
}

enum ConflictCopyOutcome {
    ParentChanged,
    Recorded,
}

impl Drop for ActiveWrite<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.accounts.active_writes.lock() {
            active.remove(&self.id);
        }
    }
}

impl Drop for SyncStaging<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0.sync_staging.write() {
            *active = false;
        }
    }
}

impl Operation<'_> {
    fn connection(&self) -> Result<&zbus::blocking::Connection, AccountError> {
        self.guard
            .as_ref()
            .map(ownership::Guard::connection)
            .ok_or_else(|| AccountError::new("account ownership is unavailable"))
    }
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if self.accounts.has_pending_credentials().unwrap_or(true)
            && let Ok(mut retained) = self.accounts.pending_guard.lock()
        {
            *retained = self.guard.take();
        }
        drop(self.guard.take());
        // Pair the operation release with session waiters so they cannot miss it.
        let session = self.accounts.read_session.lock();
        drop(self.lock.take());
        self.accounts.session_ready.notify_all();
        drop(session);
    }
}

impl fmt::Debug for Accounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accounts").finish_non_exhaustive()
    }
}

impl Accounts {
    /// Creates an account boundary without accessing the keyring or network.
    pub fn new(runtime: RuntimeDir) -> Self {
        Self {
            runtime,
            pending: Mutex::new(HashMap::new()),
            operation: Mutex::new(()),
            pending_guard: Mutex::new(None),
            cancelled: Arc::new(AtomicBool::new(false)),
            read_session: Mutex::new(None),
            session_ready: Condvar::new(),
            reads_in_flight: Mutex::new(0),
            read_available: Condvar::new(),
            metadata_generation: AtomicU64::new(0),
            clean_cache_generation: AtomicU64::new(0),
            clean_cache_update: Mutex::new(()),
            sync_staging: RwLock::new(false),
            read_ahead_active: AtomicBool::new(false),
            active_writes: Mutex::new(HashSet::new()),
            background_admission: Arc::new(sync::BackgroundAdmission::default()),
            automatic_active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Canonicalizes an instance URL without accessing the network.
    ///
    /// # Errors
    /// Returns an error if the instance URL is unsafe or invalid.
    pub fn canonical_instance(instance: &str) -> Result<String, AccountError> {
        http::instance_and_ca(instance, None).map(|(base, _)| base.to_string())
    }

    /// Returns the generation of locally invalidated mount metadata.
    pub fn metadata_generation(&self) -> u64 {
        self.metadata_generation.load(Ordering::Acquire)
    }

    /// Invalidates in-memory mount metadata after an external account operation.
    pub fn invalidate_mount_metadata(&self) {
        self.metadata_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Returns the generation of explicit clean-cache evictions.
    pub fn clean_cache_generation(&self) -> u64 {
        self.clean_cache_generation.load(Ordering::Acquire)
    }

    /// Reports local clean-cache payload usage without accessing an account or server.
    ///
    /// # Errors
    /// Returns an error if the cache cannot be safely inspected.
    pub fn clean_cache_status(&self) -> Result<CleanCacheStatus, AccountError> {
        cache::status()
    }

    /// Observes all local stores without credentials, network or account-operation ownership.
    ///
    /// # Errors
    /// Returns an error for unsafe paths, unavailable metadata/SQLite, overflow or scan limits.
    pub fn storage_status(&self) -> Result<StorageStatus, AccountError> {
        storage::status()
    }

    /// Reads shared opt-in allocation-pressure policy without credentials/network.
    ///
    /// # Errors
    /// Returns an error for invalid or unsafe private configuration.
    pub fn storage_limits(&self) -> Result<StorageLimitsView, AccountError> {
        storage::limits::view()
    }

    /// Persists user-chosen limits, or disables them, without deleting protected data.
    ///
    /// # Errors
    /// Returns an error for invalid bytes, unsafe paths or failed persistence.
    pub fn configure_storage_limits(
        &self,
        limits: Option<StorageLimits>,
    ) -> Result<StorageLimitsView, AccountError> {
        storage::limits::set(limits)
    }

    /// Releases an inspected inactive store or namespace allowance, never data.
    ///
    /// # Errors
    /// Returns an error for an active owner, changed token or unsafe record.
    pub fn release_storage_reservation(
        &self,
        store: &str,
        token: &str,
    ) -> Result<(), AccountError> {
        storage::sql_reservation::release(store, token)
    }

    /// Reserves the single bounded background read-ahead slot.
    pub fn reserve_read_ahead(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire)
            && self
                .read_ahead_active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    /// Releases a previously reserved read-ahead slot.
    pub fn release_read_ahead(&self) {
        self.read_ahead_active.store(false, Ordering::Release);
    }

    /// Evicts clean ranges under a Space path without touching pins or staged edits.
    ///
    /// # Errors
    /// Returns an error if the account, path or cache cannot be validated.
    pub fn evict_space(
        &self,
        instance: &str,
        space: &str,
        path: &[String],
    ) -> Result<(), AccountError> {
        if space.is_empty()
            || space.contains('/')
            || space.chars().any(char::is_control)
            || path.len() > 128
            || path.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid Space path"));
        }
        let session = self.read_session(instance)?;
        let _guard = self
            .clean_cache_update
            .lock()
            .map_err(|_| AccountError::new("cache is unavailable"))?;
        cache::evict(&session, space, path)?;
        self.clean_cache_generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Connects one account using a browser, PKCE and an encrypted Secret Service item.
    ///
    /// The browser receives a one-time authorization URL and must not log it.
    /// This operation holds the user-scoped account guard through keyring persistence.
    ///
    /// # Errors
    /// Returns an error for discovery, keyring, browser, callback, token or identity failures.
    pub fn connect(
        &self,
        instance: &str,
        ca_pem: Option<&[u8]>,
        browser: &impl Browser,
        attempt: &SignIn,
    ) -> Result<(), AccountError> {
        let _guard = self.begin_operation()?;
        self.clear_read_session()?;
        let store = Store::open(_guard.connection()?)?;
        let (base, ca) = http::instance_and_ca(instance, ca_pem)?;
        self.persist_pending(&store, base.as_str())?;
        // Check the destination before opening a browser; never replace ambiguous items.
        // Refuse to overwrite a matching item unless its contents are ours.
        let mut existing = store.load_existing_account(base.as_str())?;
        if let Some(account) = &existing {
            offline::bind_identity(base.as_str(), &account.issuer, &account.subject)?;
        }
        let discovery = match ca_pem {
            Some(pem) => Discovery::with_additional_ca(pem),
            None => Discovery::new(),
        }
        .map_err(|_| AccountError::new("cannot create discovery client"))?;
        let config = discovery
            .discover(base.as_str())
            .map_err(|_| AccountError::new("OpenCloud desktop discovery failed"))?;
        self.check_cancelled()?;
        attempt.check()?;
        let transport = http::Transport::new(ca_pem, config.issuer())?;
        let provider = CoreProviderMetadata::discover(
            &IssuerUrl::new(config.issuer().to_owned())
                .map_err(|_| AccountError::new("invalid issuer"))?,
            &|request| transport.call(request),
        )
        .map_err(|_| {
            AccountError::new("cannot validate OpenID provider metadata or signing keys")
        })?;
        verify_provider(&config, &provider)?;
        self.check_cancelled()?;
        attempt.check()?;
        let listener = callback::Listener::bind()?;
        let redirect = RedirectUrl::new(listener.redirect_uri())
            .map_err(|_| AccountError::new("cannot prepare loopback redirect"))?;
        let client = CoreClient::from_provider_metadata(
            provider,
            ClientId::new(config.client_id().to_owned()),
            None,
        )
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_uri(redirect);
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut authorization = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in config
            .scopes()
            .iter()
            .filter(|scope| scope.as_str() != "openid")
        {
            authorization = authorization.add_scope(Scope::new(scope.clone()));
        }
        let (url, state, nonce) = authorization.url();
        attempt.check()?;
        browser
            .open(url.as_str())
            .map_err(|_| AccountError::new("desktop browser could not open authorization"))?;
        let code = listener.wait(
            state.secret(),
            config.issuer(),
            config.callback_issuer_required(),
            &self.cancelled,
            &attempt.cancelled,
        )?;
        self.check_cancelled()?;
        attempt.begin_exchange()?;
        if let Some(account) = existing.as_mut() {
            let was_in_progress = account.refresh_in_progress;
            account.refresh_in_progress = true;
            if store.save(account).is_err() {
                account.refresh_in_progress = was_in_progress;
                self.save_refresh(&store, account)?;
                return Err(AccountError::new(
                    "cannot prepare account reconnection in keyring",
                ));
            }
        }
        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| AccountError::new("token endpoint unavailable"))?
            .set_pkce_verifier(verifier)
            .request(&|request| transport.call(request))
            .map_err(|_| AccountError::new("authorization code exchange failed"))?;
        if token.token_type() != &CoreTokenType::Bearer {
            return Err(AccountError::new(
                "provider returned an unsupported token type",
            ));
        }
        let identity_token = token
            .id_token()
            .ok_or_else(|| AccountError::new("provider did not return an ID token"))?;
        let id_verifier = client.id_token_verifier();
        let claims = identity_token.claims(&id_verifier, &nonce).map_err(|_| {
            AccountError::new("ID token signature, issuer, audience, expiry or nonce is invalid")
        })?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                token.access_token(),
                identity_token
                    .signing_alg()
                    .map_err(|_| AccountError::new("invalid ID token algorithm"))?,
                identity_token
                    .signing_key(&id_verifier)
                    .map_err(|_| AccountError::new("invalid ID token key"))?,
            )
            .map_err(|_| AccountError::new("invalid access token hash"))?;
            if &actual != expected {
                return Err(AccountError::new(
                    "access token does not match the ID token",
                ));
            }
        }
        let refresh = token
            .refresh_token()
            .ok_or_else(|| AccountError::new("provider did not return a refresh token"))?;
        let expiry = expiry(token.expires_in())?;
        if let Some(account) = &existing
            && (account.issuer != config.issuer() || account.subject != claims.subject().as_str())
        {
            return Err(AccountError::new(
                "connected identity differs from the saved account; existing account was preserved",
            ));
        }
        let account = AccountData {
            instance: base.to_string(),
            issuer: config.issuer().to_owned(),
            client_id: config.client_id().to_owned(),
            token_endpoint: config.token_endpoint().to_owned(),
            subject: claims.subject().as_str().to_owned(),
            ca_pem: ca,
            access_token: token.access_token().secret().to_owned(),
            refresh_token: refresh.secret().to_owned(),
            expires_at: expiry,
            refresh_in_progress: false,
            selected_space: existing
                .as_ref()
                .and_then(|account| account.selected_space.clone()),
            selected_space_verified: existing
                .as_ref()
                .and_then(|account| account.selected_space_verified.clone()),
        };
        offline::bind_identity(base.as_str(), &account.issuer, &account.subject)?;
        self.save_refresh(&store, &account)?;
        Ok(())
    }

    /// Lists Spaces using the saved account, refreshing its token when required.
    ///
    /// # Errors
    /// Returns an error for missing or locked secrets, refresh failures, or incomplete listings.
    pub fn spaces(&self, instance: &str) -> Result<Vec<Space>, AccountError> {
        let _guard = self.begin_operation()?;
        self.clear_read_session()?;
        let store = Store::open(_guard.connection()?)?;
        let (base, _) = http::instance_and_ca(instance, None)?;
        self.persist_pending(&store, base.as_str())?;
        let mut account = store.load(base.as_str())?;
        let client = http::client(account.ca_pem.as_deref().map(str::as_bytes))?;
        self.refresh_if_needed(&mut account, &store, &client)?;
        self.account_spaces(&base, &mut account, &store, &client)
    }

    /// Selects a Space only after it appears in a fresh authenticated listing.
    ///
    /// # Errors
    /// Returns an error if the account, listing or requested Space cannot be verified.
    pub fn select_space(&self, instance: &str, id: &str) -> Result<(), AccountError> {
        let _guard = self.begin_operation()?;
        self.clear_read_session()?;
        let store = Store::open(_guard.connection()?)?;
        let (base, _) = http::instance_and_ca(instance, None)?;
        self.persist_pending(&store, base.as_str())?;
        let mut account = store.load(base.as_str())?;
        let client = http::client(account.ca_pem.as_deref().map(str::as_bytes))?;
        self.refresh_if_needed(&mut account, &store, &client)?;
        let spaces = self.account_spaces(&base, &mut account, &store, &client)?;
        if !spaces.iter().any(|space| space.id == id) {
            return Err(AccountError::new(
                "selected Space is not in the authenticated listing",
            ));
        }
        self.check_cancelled()?;
        account.selected_space = Some(id.to_owned());
        account.selected_space_verified = Some(id.to_owned());
        store.save(&account)
    }

    /// Checks the selected Space against the current user-scoped listing before mounting.
    ///
    /// A previously verified selection remains usable offline when the server cannot be
    /// reached. Protocol, authentication and permission failures are never treated as offline.
    ///
    /// # Errors
    /// Returns an error for an unverified selection or a failed online access check.
    pub fn check_mount_access(&self, instance: &str) -> Result<MountBinding, AccountError> {
        let session = self.read_session(instance)?;
        let selected = session
            .account
            .selected_space
            .as_deref()
            .ok_or_else(|| AccountError::new("no Space is selected"))?;
        let (listing, offline_allowed) = match list_spaces(
            &session.base,
            &session.account.access_token,
            &session.client,
            &self.cancelled,
        ) {
            Err(error) if error.unauthorized => (self.spaces(instance), false),
            result => (result, true),
        };
        match listing {
            Ok(spaces) if spaces.iter().any(|space| space.id == selected) => {}
            Ok(_) => {
                return Err(AccountError::new(
                    "selected Space is no longer in the signed-in user's listing; select an accessible Space",
                ));
            }
            Err(error) if offline_allowed && error.network => {}
            Err(error) => return Err(error),
        };
        Ok(MountBinding {
            instance: session.base.to_string(),
            space: selected.to_owned(),
            name: None,
            issuer: session.account.issuer.clone(),
            subject: session.account.subject.clone(),
            offline: false,
            offline_writable: false,
        })
    }

    /// Verifies and binds an explicitly requested Space without changing selection.
    ///
    /// # Errors
    /// Returns an error unless a fresh authenticated listing contains the Space.
    pub fn bind_space(&self, instance: &str, id: &str) -> Result<MountBinding, AccountError> {
        let session = self.read_session(instance)?;
        let spaces = self.read_with_refresh(&session, |current| {
            list_spaces(
                &current.base,
                &current.account.access_token,
                &current.client,
                &self.cancelled,
            )
        })?;
        let found = spaces.iter().find(|space| space.id == id).ok_or_else(|| {
            AccountError::new("requested Space is not in the authenticated listing")
        })?;
        let name = (spaces
            .iter()
            .filter(|space| space.name == found.name)
            .count()
            == 1)
            .then(|| found.name.clone());
        Ok(MountBinding {
            instance: session.base.to_string(),
            space: id.to_owned(),
            name,
            issuer: session.account.issuer.clone(),
            subject: session.account.subject.clone(),
            offline: false,
            offline_writable: false,
        })
    }

    /// Lists one directory in the selected Space without hydrating file contents.
    ///
    /// # Errors
    /// Returns an error when the account, selected Space or complete DAV listing is invalid.
    pub fn directory(&self, instance: &str, path: &[String]) -> Result<Vec<Entry>, AccountError> {
        self.directory_inner(instance, None, path, None)?.collect()
    }

    /// Inspects saved metadata and local entries in a previously mounted Space.
    /// Never authenticates, fetches content or asserts current remote state.
    ///
    /// # Errors
    /// Returns an error for invalid input, unavailable metadata or changed local identity.
    pub fn offline_directory(
        &self,
        instance: &str,
        space: &str,
        path: &[String],
    ) -> Result<Vec<Entry>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        if space.is_empty()
            || space.chars().any(char::is_control)
            || path.len() > 128
            || path.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid offline Space path"));
        }
        offline::offline_directory(base.as_str(), space, path, None)?.collect()
    }

    /// Binds a read-only local mount to a previously verified retained Space.
    /// No current credentials or remote authorization are asserted.
    ///
    /// # Errors
    /// Refuses missing/mismatched persisted identity, activation or root metadata.
    pub fn bind_offline_space(
        &self,
        instance: &str,
        space: &str,
    ) -> Result<MountBinding, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid offline Space"));
        }
        let (issuer, subject) = offline::mount_identity(base.as_str(), space)?;
        offline::offline_directory(base.as_str(), space, &[], Some((&issuer, &subject)))?;
        Ok(MountBinding {
            instance: base.to_string(),
            space: space.to_owned(),
            name: None,
            issuer,
            subject,
            offline: true,
            offline_writable: false,
        })
    }

    /// Binds explicit local editing to the original retained account and Space.
    /// No keyring access, remote authorization or identity adoption is performed.
    ///
    /// # Errors
    /// Refuses competing account ownership or missing/mismatched saved bindings.
    pub fn bind_writable_offline_space(
        &self,
        instance: &str,
        space: &str,
    ) -> Result<MountBinding, AccountError> {
        let _owner = ownership::acquire_offline(&self.runtime)?;
        self.check_cancelled()?;
        let mut binding = self.bind_offline_space(instance, space)?;
        binding.offline_writable = true;
        Ok(binding)
    }

    fn verify_offline_mount(&self, binding: &MountBinding) -> Result<(), AccountError> {
        if offline::mount_identity(&binding.instance, &binding.space)?
            != (binding.issuer.clone(), binding.subject.clone())
        {
            return Err(AccountError::new("offline mount identity changed"));
        }
        Ok(())
    }

    /// Lists a directory within the Space bound to a mount.
    ///
    /// # Errors
    /// Returns an error if the binding or directory cannot be verified.
    pub fn mount_directory(
        &self,
        instance: &str,
        space: &MountBinding,
        path: &[String],
        parent_id: &str,
    ) -> Result<DirectorySnapshot, AccountError> {
        if space.offline {
            if instance != space.instance {
                return Err(AccountError::new("offline mount instance changed"));
            }
            return offline::offline_directory(
                instance,
                &space.space,
                path,
                Some((&space.issuer, &space.subject)),
            );
        }
        self.directory_inner(instance, Some(space), path, Some(parent_id))
    }

    /// Observes one mounted directory without keyring access, token refresh or retries.
    /// A missing/expiring cached session or saturated foreground reads skips work.
    ///
    /// # Errors
    /// Returns an error for an invalid/failed observation; no offline fallback is published.
    pub fn refresh_mount_directory(
        &self,
        binding: &MountBinding,
        path: &[String],
        parent_id: &str,
        alive: &AtomicBool,
        staged: (&[FileVersion], &[(Vec<String>, String)]),
    ) -> Result<Option<MountDirectoryRefresh>, AccountError> {
        if binding.offline {
            return Ok(None);
        }
        let available = || alive.load(Ordering::Acquire) && !self.background_yield_requested();
        if !available() {
            return Ok(None);
        }
        let mut reads = self
            .reads_in_flight
            .lock()
            .map_err(|_| AccountError::new("read state is unavailable"))?;
        // Leave a slot for demand reads; never queue behind their network work.
        if *reads >= 3 {
            return Ok(None);
        }
        *reads += 1;
        drop(reads);
        let _permit = ReadPermit(self);
        let session = self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?
            .clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AccountError::new("system clock is invalid"))?
            .as_secs();
        let Some(session) = session.filter(|s| {
            s.base.as_str() == binding.instance()
                && !s.account.refresh_in_progress
                && s.account.expires_at > now.saturating_add(30)
        }) else {
            return Ok(None);
        };
        let space = bound_space(&session, Some(binding))?;
        offline::verify_identity(
            session.base.as_str(),
            &session.account.issuer,
            &session.account.subject,
        )?;
        let (remote, fenced) = offline::tree_remote_path(session.base.as_str(), space, path)?;
        if fenced || offline::local_directory(session.base.as_str(), space, path)? {
            return Ok(None);
        }
        let observation = offline::begin_snapshot()?;
        let observed = dav::directory_snapshot_timed(
            &session.base,
            space,
            &remote,
            &session.account.access_token,
            &session.client,
            Duration::from_secs(2),
        );
        if observed.as_ref().is_err_and(|error| error.unauthorized) {
            let mut cached = self
                .read_session
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            if cached.as_ref().is_some_and(|current| {
                current.base == session.base && current.account == session.account
            }) {
                *cached = None;
            }
        }
        let mut entries = observed?;
        if !available() {
            return Ok(None);
        }
        // A foreground credential operation may have invalidated/replaced the
        // cached session during DAV. Never publish that superseded observation.
        if self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?
            .as_ref()
            .is_none_or(|current| {
                current.base != session.base || current.account != session.account
            })
        {
            return Ok(None);
        }
        offline::verify_identity(
            session.base.as_str(),
            &session.account.issuer,
            &session.account.subject,
        )?;
        if !parent_id.is_empty() && !entries.matches_parent(parent_id)? {
            return Err(AccountError::new("directory parent identity changed"));
        }
        if !offline::save_directory_snapshot(
            observation,
            session.base.as_str(),
            space,
            path,
            &entries,
        )? {
            return Ok(None);
        }
        offline::apply_staged_entries(session.base.as_str(), space, path, &mut entries)?;
        let files = self.confirmed_mount_versions_in(&session, binding, staged.0, &entries)?;
        let directories =
            self.confirmed_mount_directories_in(&session, binding, staged.1, &entries)?;
        Ok(Some(MountDirectoryRefresh {
            entries,
            files,
            directories,
        }))
    }

    /// Matches open staged versions to the exact remote versions confirmed by sync.
    ///
    /// # Errors
    /// Returns an error if the binding or local journal cannot be checked.
    pub fn confirmed_mount_versions(
        &self,
        binding: &MountBinding,
        versions: &[FileVersion],
        entries: &DirectorySnapshot,
    ) -> Result<Vec<(FileVersion, FileVersion)>, AccountError> {
        if binding.offline {
            if !binding.offline_writable {
                return Ok(Vec::new());
            }
            self.verify_offline_mount(binding)?;
            return self.confirmed_mount_versions_local(binding, versions, entries);
        }
        let session = self.read_session(binding.instance())?;
        self.confirmed_mount_versions_in(&session, binding, versions, entries)
    }

    fn confirmed_mount_versions_in(
        &self,
        session: &ReadSession,
        binding: &MountBinding,
        versions: &[FileVersion],
        entries: &DirectorySnapshot,
    ) -> Result<Vec<(FileVersion, FileVersion)>, AccountError> {
        bound_space(session, Some(binding))?;
        self.confirmed_mount_versions_local(binding, versions, entries)
    }

    // Local confirmation is not a fresh remote binding. Only an exact synced
    // staged head and its recorded identity may advance an open version.
    fn confirmed_mount_versions_local(
        &self,
        binding: &MountBinding,
        versions: &[FileVersion],
        entries: &DirectorySnapshot,
    ) -> Result<Vec<(FileVersion, FileVersion)>, AccountError> {
        let mut confirmed = Vec::new();
        for staged in versions {
            if staged.instance != binding.instance || staged.space != binding.space {
                return Err(AccountError::new(
                    "file version does not match mounted Space",
                ));
            }
            let Some((id, etag)) = offline::confirmed_write(staged)? else {
                continue;
            };
            let Some(name) = staged.path.last() else {
                continue;
            };
            if let Some(entry) = entries.get(name)?.filter(|entry| {
                !entry.is_directory()
                    && entry.id() == id
                    && entry.etag() == Some(etag.as_str())
                    && entry.size() == Some(staged.size)
            }) {
                confirmed.push((
                    staged.clone(),
                    FileVersion {
                        instance: staged.instance.clone(),
                        space: staged.space.clone(),
                        path: staged.path.clone(),
                        id,
                        etag,
                        size: staged.size,
                        checksums: entry.checksums().to_vec(),
                    },
                ));
            }
        }
        Ok(confirmed)
    }

    /// Matches locally created directories to their confirmed remote identities.
    ///
    /// # Errors
    /// Returns an error if the mounted account or journal cannot be checked.
    pub fn confirmed_mount_directories(
        &self,
        binding: &MountBinding,
        directories: &[(Vec<String>, String)],
        entries: &DirectorySnapshot,
    ) -> Result<Vec<(Vec<String>, String, Entry)>, AccountError> {
        if binding.offline {
            if !binding.offline_writable {
                return Ok(Vec::new());
            }
            self.verify_offline_mount(binding)?;
            return self.confirmed_mount_directories_local(binding, directories, entries);
        }
        let session = self.read_session(binding.instance())?;
        self.confirmed_mount_directories_in(&session, binding, directories, entries)
    }

    fn confirmed_mount_directories_in(
        &self,
        session: &ReadSession,
        binding: &MountBinding,
        directories: &[(Vec<String>, String)],
        entries: &DirectorySnapshot,
    ) -> Result<Vec<(Vec<String>, String, Entry)>, AccountError> {
        bound_space(session, Some(binding))?;
        self.confirmed_mount_directories_local(binding, directories, entries)
    }

    fn confirmed_mount_directories_local(
        &self,
        binding: &MountBinding,
        directories: &[(Vec<String>, String)],
        entries: &DirectorySnapshot,
    ) -> Result<Vec<(Vec<String>, String, Entry)>, AccountError> {
        let mut confirmed = Vec::new();
        for (path, resource) in directories {
            let Some(id) = resource
                .strip_prefix("cirrus-dir:")
                .and_then(|value| value.parse::<i64>().ok())
            else {
                return Err(AccountError::new("invalid local directory identity"));
            };
            let Some(confirmed_directory) = offline::confirmed_directory(&binding.instance, id)?
            else {
                continue;
            };
            if confirmed_directory.space != binding.space || confirmed_directory.path != *path {
                continue;
            }
            if let Some(name) = path.last()
                && let Some(entry) = entries
                    .get(name)?
                    .filter(|entry| entry.is_directory() && entry.id() == confirmed_directory.id)
            {
                confirmed.push((path.clone(), resource.clone(), entry.clone()));
            }
        }
        Ok(confirmed)
    }

    fn directory_inner(
        &self,
        instance: &str,
        expected_space: Option<&MountBinding>,
        path: &[String],
        parent_id: Option<&str>,
    ) -> Result<DirectorySnapshot, AccountError> {
        let _permit = self.read_permit()?;
        let session = self.read_session(instance)?;
        let space = bound_space(&session, expected_space)?;
        let observation = offline::begin_snapshot()?;
        let (remote_path, move_fenced) =
            offline::tree_remote_path(session.base.as_str(), space, path)?;
        let mut entries = if offline::local_directory(session.base.as_str(), space, path)? {
            DirectorySnapshot::empty()?
        } else if move_fenced {
            offline::directory_snapshot(session.base.as_str(), space, path)?
                .ok_or_else(|| AccountError::new("directory rename requires attention"))?
        } else {
            match self.read_with_refresh(&session, |current| {
                dav::directory_snapshot(
                    &current.base,
                    space,
                    &remote_path,
                    &current.account.access_token,
                    &current.client,
                )
            }) {
                Ok(entries) => {
                    if let Some(id) = parent_id
                        && !id.is_empty()
                        && !id.starts_with("cirrus-dir:")
                        && !entries.matches_parent(id)?
                    {
                        return Err(AccountError::new("directory parent identity changed"));
                    }
                    // CLI publication is required rather than best-effort.
                    // Queue behind local readers only after DAV, before SQL
                    // planning; retain the original observation's CAS fence.
                    let _state_turn = if expected_space.is_none() {
                        Some(ownership::local_state_turn(Arc::clone(&self.cancelled))?)
                    } else {
                        None
                    };
                    let _state_phase = if _state_turn.is_some() {
                        Some(ownership::admit_local_state_turn()?)
                    } else {
                        None
                    };
                    let saved = offline::save_directory_snapshot(
                        observation,
                        session.base.as_str(),
                        space,
                        path,
                        &entries,
                    );
                    #[cfg(feature = "fault-injection")]
                    if expected_space.is_none()
                        && saved.as_ref().is_err_and(|error| error.storage_busy)
                        && let Some(marker) =
                            std::env::var_os("CIRRUS_TEST_CLI_SNAPSHOT_BLOCKED_MARKER")
                    {
                        let _ = std::fs::write(marker, b"refused");
                    }
                    // Mounted readers may race each other for optional
                    // offline-copy publication. Keep the complete online
                    // result, with parent identity checked above; staging's
                    // own State admission/CAS still decides any local write.
                    // Explicit CLI publication still refuses peer ownership.
                    if matches!(saved, Ok(false))
                        && !offline::directory_copy_compatible(
                            session.base.as_str(),
                            space,
                            path,
                            &entries,
                            &session.account.issuer,
                            &session.account.subject,
                        )?
                    {
                        return Err(AccountError::new(
                            "directory metadata changed concurrently; retry",
                        ));
                    }
                    if let Err(error) = saved
                        && !(expected_space.is_some()
                            && error.storage_busy
                            && offline::directory_copy_compatible(
                                session.base.as_str(),
                                space,
                                path,
                                &entries,
                                &session.account.issuer,
                                &session.account.subject,
                            )?)
                    {
                        return Err(error);
                    }
                    entries
                }
                Err(error) if error.network => {
                    let saved = offline::directory_snapshot(session.base.as_str(), space, path)?;
                    #[cfg(feature = "fault-injection")]
                    if std::env::var_os("CIRRUS_TEST_BLOCKER_TRACE").is_some() {
                        eprintln!(
                            "cirrus lab directory fallback: path={path:?} remote={remote_path:?} bound_raw={}",
                            saved.is_some()
                        );
                    }
                    if let Some(saved) = saved {
                        saved
                    } else if expected_space.is_some() {
                        // A queued MOVE's destination exists in the projected
                        // ancestor view, not the raw remote parent. Reuse its
                        // exact identity/copy proof, never an orphan fallback.
                        return offline::offline_directory(
                            session.base.as_str(),
                            space,
                            path,
                            Some((&session.account.issuer, &session.account.subject)),
                        );
                    } else {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        };
        offline::apply_staged_entries(session.base.as_str(), space, path, &mut entries)?;
        Ok(entries)
    }

    /// Captures a fresh identity and strong ETag for an experimental read-only open.
    ///
    /// # Errors
    /// Returns an error if the file, account, identity or strong validator cannot be verified.
    pub fn open_file(
        &self,
        instance: &str,
        path: &[String],
        id: &str,
    ) -> Result<FileVersion, AccountError> {
        self.open_file_inner(instance, None, path, id, true)
    }

    /// Opens a file within the Space bound to a mount.
    ///
    /// # Errors
    /// Returns an error if the binding or file version cannot be verified.
    pub fn mount_open_file(
        &self,
        instance: &str,
        space: &MountBinding,
        path: &[String],
        id: &str,
    ) -> Result<FileVersion, AccountError> {
        if space.offline {
            let (name, parent) = path
                .split_last()
                .ok_or_else(|| AccountError::new("invalid file path"))?;
            let entries = self.mount_directory(instance, space, parent, "")?;
            let entry = entries
                .get(name)?
                .filter(|entry| !entry.is_directory() && entry.id() == id)
                .ok_or_else(|| AccountError::new("offline file identity changed"))?;
            return Ok(FileVersion {
                instance: instance.to_owned(),
                space: space.space.clone(),
                path: path.to_vec(),
                id: id.to_owned(),
                etag: entry
                    .etag()
                    .ok_or_else(|| AccountError::new("offline file version unavailable"))?
                    .to_owned(),
                size: entry
                    .size()
                    .ok_or_else(|| AccountError::new("offline file size unavailable"))?,
                checksums: entry.checksums().to_vec(),
            });
        }
        self.open_file_inner(instance, Some(space), path, id, true)
    }

    fn open_file_inner(
        &self,
        instance: &str,
        expected_space: Option<&MountBinding>,
        path: &[String],
        id: &str,
        allow_offline: bool,
    ) -> Result<FileVersion, AccountError> {
        let (name, _) = path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid file path"))?;
        let _permit = self.read_permit()?;
        let session = self.read_session(instance)?;
        let space = bound_space(&session, expected_space)?;
        if id.starts_with("cirrus-staged:") {
            if !offline::publication::spaces(session.base.as_str(), Some(space))?.is_empty() {
                let _guard = self.begin_local_operation(&session, true)?;
                let operation = id
                    .strip_prefix("cirrus-staged:")
                    .and_then(|id| id.parse::<i64>().ok())
                    .ok_or_else(|| AccountError::new("invalid staged identity"))?;
                offline::publication::recover(
                    session.base.as_str(),
                    space,
                    path,
                    operation,
                    None,
                    true,
                )?;
            }
            return offline::staged_version(session.base.as_str(), space, path, id)?
                .map(|(version, _)| version)
                .ok_or_else(|| AccountError::new("staged file is unavailable"));
        }
        let (remote_path, move_fenced) =
            offline::tree_remote_path(session.base.as_str(), space, path)?;
        if move_fenced {
            return offline::version(
                session.base.as_str(),
                space,
                path,
                id,
                expected_space.map(|_| {
                    (
                        session.account.issuer.as_str(),
                        session.account.subject.as_str(),
                    )
                }),
            )?
            .ok_or_else(|| AccountError::new("directory rename requires attention"));
        }
        let (_, remote_parent) = remote_path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid file path"))?;
        let entries = match self.read_with_refresh(&session, |current| {
            dav::directory_snapshot(
                &current.base,
                space,
                remote_parent,
                &current.account.access_token,
                &current.client,
            )
        }) {
            Ok(entries) => entries,
            Err(error) if error.network && allow_offline => {
                if let Some(version) = offline::version(
                    session.base.as_str(),
                    space,
                    path,
                    id,
                    expected_space.map(|_| {
                        (
                            session.account.issuer.as_str(),
                            session.account.subject.as_str(),
                        )
                    }),
                )? {
                    return Ok(version);
                }
                let (name, parent) = path
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid file path"))?;
                let saved = offline::directory_snapshot(session.base.as_str(), space, parent)?;
                let saved = if saved.is_none() && expected_space.is_some() {
                    Some(offline::offline_directory(
                        session.base.as_str(),
                        space,
                        parent,
                        Some((&session.account.issuer, &session.account.subject)),
                    )?)
                } else {
                    saved
                };
                if let Some(entries) = saved
                    && let Some(entry) = entries
                        .get(name)?
                        .filter(|entry| entry.id() == id && !entry.is_directory())
                    && let (Some(etag), Some(size)) = (entry.etag(), entry.size())
                {
                    let version = FileVersion {
                        instance: session.base.to_string(),
                        space: space.to_owned(),
                        path: path.to_vec(),
                        id: id.to_owned(),
                        etag: etag.to_owned(),
                        size,
                        checksums: entry.checksums().to_vec(),
                    };
                    let origin = self.moved_cache_version(
                        &version,
                        &session.account.issuer,
                        &session.account.subject,
                    )?;
                    if cache::contains(&session, &version).unwrap_or(false)
                        || origin.as_ref().is_some_and(|origin| {
                            cache::contains(&session, origin).unwrap_or(false)
                        })
                    {
                        return Ok(version);
                    }
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let entry = entries
            .get(name)?
            .filter(|entry| entry.id() == id && !entry.is_directory())
            .ok_or_else(|| AccountError::new("file identity changed or is unavailable"))?;
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_FILE_METADATA_TRACE").is_some() {
            eprintln!("cirrus lab indexed file-open lookup");
        }
        Ok(FileVersion {
            instance: session.base.to_string(),
            space: space.to_owned(),
            path: path.to_vec(),
            id: id.to_owned(),
            etag: entry
                .etag()
                .ok_or_else(|| AccountError::new("file lacks a strong ETag"))?
                .to_owned(),
            size: entry
                .size()
                .ok_or_else(|| AccountError::new("file size is unavailable"))?,
            checksums: entry.checksums().to_vec(),
        })
    }

    fn online_directory(
        &self,
        instance: &str,
        binding: Option<&MountBinding>,
        path: &[String],
        save: bool,
        pin_root: &[String],
    ) -> Result<DirectorySnapshot, AccountError> {
        let _permit = self.read_permit()?;
        let session = self.read_session(instance)?;
        let space = bound_space(&session, binding)?;
        let snapshot = if save {
            Some(offline::begin_pin_snapshot(
                session.base.as_str(),
                space,
                pin_root,
            )?)
        } else {
            None
        };
        let entries = self.read_with_refresh(&session, |current| {
            dav::directory_snapshot(
                &current.base,
                space,
                path,
                &current.account.access_token,
                &current.client,
            )
        })?;
        if let Some(snapshot) = snapshot {
            offline::save_pin_snapshot(
                snapshot,
                session.base.as_str(),
                space,
                pin_root,
                path,
                &entries,
            )?;
        }
        Ok(entries)
    }

    /// Pins one file or a bounded directory tree for experimental offline use.
    ///
    /// # Errors
    /// Returns an error if traversal, validation, checksum verification or durable storage fails.
    pub fn pin(&self, instance: &str, root: &[String]) -> Result<(), AccountError> {
        self.pin_inner(instance, None, root)
    }

    /// Pins a path in an explicitly verified Space without changing selection.
    ///
    /// # Errors
    /// Returns an error if the Space, traversal or durable pin cannot be verified.
    pub fn pin_space(
        &self,
        instance: &str,
        space: &str,
        root: &[String],
    ) -> Result<(), AccountError> {
        let binding = self.bind_space(instance, space)?;
        self.pin_inner(instance, Some(&binding), root)
    }

    fn pin_inner(
        &self,
        instance: &str,
        binding: Option<&MountBinding>,
        root: &[String],
    ) -> Result<(), AccountError> {
        if root.len() > 128
            || root.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid Space path"));
        }
        let session = self.read_session(instance)?;
        let space = bound_space(&session, binding)?.to_owned();
        let instance = session.base.to_string();
        offline::check_pin_path(&instance, &space, root)?;
        let local_state = offline::current_pin_local_state()?;
        let mut retries = 0;
        loop {
            let result = self
                .collect_pin_files(&instance, binding, root, true)
                .and_then(|tree| {
                    offline::replace_pin(
                        (&instance, &space),
                        root,
                        &tree,
                        (retries != 0).then_some(&local_state),
                        |version, offset, length| {
                            self.read_range_online(version, binding, offset, length)
                                .map(|(bytes, _metadata)| bytes)
                        },
                        |version| {
                            if self.open_file_inner(
                                &version.instance,
                                binding,
                                &version.path,
                                &version.id,
                                false,
                            )? != *version
                            {
                                return Err(AccountError::new("file representation changed"));
                            }
                            Ok(())
                        },
                        || {
                            if self.collect_pin_files(&instance, binding, root, false)? != tree {
                                return Err(AccountError::new(
                                    "pin tree changed during verification",
                                ));
                            }
                            Ok(())
                        },
                    )
                });
            match result {
                Err(error) if error.message == offline::PIN_SNAPSHOT_INTERRUPTED && retries < 2 => {
                    if offline::current_pin_local_state()? != local_state {
                        return Err(error);
                    }
                    retries += 1;
                }
                result => return result,
            }
        }
    }

    fn collect_pin_files(
        &self,
        instance: &str,
        binding: Option<&MountBinding>,
        root: &[String],
        save: bool,
    ) -> Result<PinTree, AccountError> {
        let mut files = Vec::new();
        let mut directories = Vec::new();
        let mut directory_versions = Vec::new();
        let is_dir;
        // Save every ancestor needed to reach a nested pin after restart,
        // including when pinning without first mounting the Space.
        for depth in 0..root.len().saturating_sub(1) {
            let entries = self.online_directory(instance, binding, &root[..depth], save, root)?;
            if !entries
                .get(&root[depth])?
                .is_some_and(|entry| entry.is_directory())
            {
                return Err(AccountError::new("pin ancestor is unavailable"));
            }
        }
        if let Some((name, parent)) = root.split_last() {
            let entries = self.online_directory(instance, binding, parent, save, root)?;
            let entry = entries
                .get(name)?
                .ok_or_else(|| AccountError::new("pin path not found"))?;
            if entry.is_directory() {
                is_dir = true;
                directory_versions.push((root.to_vec(), entry.id().to_owned()));
                directories.push(root.to_vec());
            } else {
                is_dir = false;
                files.push(self.open_file_inner(instance, binding, root, entry.id(), false)?);
            }
        } else {
            is_dir = true;
            directory_versions.push((Vec::new(), String::new()));
            directories.push(Vec::new());
        }
        let mut visited = 0usize;
        while let Some(path) = directories.pop() {
            let entries = self.online_directory(instance, binding, &path, save, root)?;
            let mut after = 0;
            loop {
                let page = entries.page(after)?;
                if page.is_empty() {
                    break;
                }
                #[cfg(feature = "fault-injection")]
                if std::env::var_os("CIRRUS_TEST_FILE_METADATA_TRACE").is_some() {
                    eprintln!("cirrus lab pin listing page: rows={}", page.len());
                }
                for (cookie, entry) in page {
                    after = cookie;
                    visited += 1;
                    if visited > 4096 || path.len() >= 128 {
                        return Err(AccountError::new("pin tree exceeds the limit"));
                    }
                    let mut child = path.clone();
                    child.push(entry.name().to_owned());
                    if entry.is_directory() {
                        directory_versions.push((child.clone(), entry.id().to_owned()));
                        directories.push(child);
                    } else {
                        files.push(self.open_file_inner(
                            instance,
                            binding,
                            &child,
                            entry.id(),
                            false,
                        )?);
                    }
                }
            }
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        directory_versions.sort();
        Ok(PinTree {
            is_dir,
            directories: directory_versions,
            files,
        })
    }

    /// Removes a pin and its stored chunks.
    ///
    /// # Errors
    /// Returns an error if account selection or durable storage is unavailable.
    pub fn unpin(&self, instance: &str, root: &[String]) -> Result<(), AccountError> {
        self.unpin_inner(instance, None, root)
    }

    /// Removes only the named local pin, without credentials or network access.
    ///
    /// # Errors
    /// Returns an error for invalid input, missing local identity or durable storage failure.
    pub fn unpin_space(
        &self,
        instance: &str,
        space: &str,
        root: &[String],
    ) -> Result<(), AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid Space ID"));
        }
        offline::unpin(base.as_str(), space, root)
    }

    fn unpin_inner(
        &self,
        instance: &str,
        binding: Option<&MountBinding>,
        root: &[String],
    ) -> Result<(), AccountError> {
        let session = self.read_session(instance)?;
        let space = bound_space(&session, binding)?;
        offline::unpin(session.base.as_str(), space, root)
    }

    /// Durably stages a local file and records an observed base version when available.
    ///
    /// # Errors
    /// Returns an error if the path, source, account or durable state is unsafe.
    pub fn stage_file(
        &self,
        instance: &str,
        path: &[String],
        source: &std::path::Path,
    ) -> Result<(), AccountError> {
        self.stage_file_inner(instance, None, path, source)
    }

    /// Stages a local file in an explicitly verified Space without changing selection.
    ///
    /// # Errors
    /// Returns an error if the Space, source or durable state cannot be verified.
    pub fn stage_file_space(
        &self,
        instance: &str,
        space: &str,
        path: &[String],
        source: &std::path::Path,
    ) -> Result<(), AccountError> {
        let binding = self.bind_space(instance, space)?;
        self.stage_file_inner(instance, Some(&binding), path, source)
    }

    fn stage_file_inner(
        &self,
        instance: &str,
        binding: Option<&MountBinding>,
        path: &[String],
        source: &std::path::Path,
    ) -> Result<(), AccountError> {
        if path.is_empty()
            || path.len() > 128
            || path.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid Space path"));
        }
        let (base, _) = http::instance_and_ca(instance, None)?;
        let guard = self.begin_operation()?;
        let store = Store::open(guard.connection()?)?;
        self.persist_pending(&store, base.as_str())?;
        let account = store.load(base.as_str())?;
        offline::bind_identity(base.as_str(), &account.issuer, &account.subject)?;
        let space = if let Some(binding) = binding {
            if binding.instance != base.as_str()
                || binding.issuer != account.issuer
                || binding.subject != account.subject
            {
                return Err(AccountError::new("account identity changed"));
            }
            binding.space.as_str()
        } else {
            account
                .selected_space
                .as_deref()
                .ok_or_else(|| AccountError::new("no Space is selected"))?
        };
        let observation = offline::begin_snapshot().ok();
        let (remote_path, uncertain) = offline::tree_remote_path(base.as_str(), space, path)?;
        if uncertain {
            return Err(AccountError::new("directory rename requires attention"));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|v| v.as_secs());
        if !account.refresh_in_progress
            && now.is_some_and(|now| account.expires_at > now.saturating_add(30))
            && let Ok(client) = http::client(account.ca_pem.as_deref().map(str::as_bytes))
        {
            for depth in 0..path.len().saturating_sub(1) {
                let logical = &path[..depth];
                if offline::local_directory(base.as_str(), space, logical)? {
                    continue;
                }
                let (remote, fenced) = offline::tree_remote_path(base.as_str(), space, logical)?;
                if fenced {
                    return Err(AccountError::new("directory rename requires attention"));
                }
                let observation = offline::begin_snapshot()?;
                if let Ok(entries) =
                    dav::directory_snapshot(&base, space, &remote, &account.access_token, &client)
                {
                    let _ = offline::save_directory_snapshot(
                        observation,
                        base.as_str(),
                        space,
                        logical,
                        &entries,
                    )?;
                }
            }
        }
        let parents = offline::observed_parent_identities(base.as_str(), space, path)?;
        let entries = if !account.refresh_in_progress
            && now.is_some_and(|now| account.expires_at > now.saturating_add(30))
            && let Ok(client) = http::client(account.ca_pem.as_deref().map(str::as_bytes))
            && let Some((name, parent)) = remote_path.split_last()
            && let Ok(entries) =
                dav::directory_snapshot(&base, space, parent, &account.access_token, &client)
        {
            if let (Some(observation), Some((_, logical_parent))) = (observation, path.split_last())
            {
                let _ = offline::save_directory_snapshot(
                    observation,
                    base.as_str(),
                    space,
                    logical_parent,
                    &entries,
                );
            }
            entries.get(name)?
        } else {
            None
        };
        offline::stage_file(
            base.as_str(),
            space,
            path,
            source,
            entries.as_ref(),
            &parents,
        )?;
        Ok(())
    }

    /// Publishes an extent-map mutation after payload and directory durability.
    ///
    /// # Errors
    /// Returns an error on stale identity, quota, invalid range or local storage failure.
    pub fn stage_mount_mutation(
        &self,
        instance: &str,
        expected_space: &MountBinding,
        path: &[String],
        mutation: DirtyMutation<'_>,
        base: Option<&FileVersion>,
        parents: &[DirectoryIdentity],
    ) -> Result<FileVersion, AccountError> {
        if path.is_empty()
            || path.len() > 128
            || path.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid Space path"));
        }
        let _priority = self.request_foreground();
        if expected_space.offline {
            if !expected_space.offline_writable || instance != expected_space.instance {
                return Err(AccountError::new("offline mount writes unavailable"));
            }
            let _owner = ownership::acquire_offline(&self.runtime)?;
            #[cfg(feature = "fault-injection")]
            if std::env::var("CIRRUS_TEST_OFFLINE_WRITE_OWNED_SPACE")
                .ok()
                .as_deref()
                == Some(expected_space.space.as_str())
            {
                wait_test_window("CIRRUS_TEST_OFFLINE_WRITE_OWNED_WINDOW")?;
            }
            self.check_cancelled()?;
            self.verify_offline_mount(expected_space)?;
            if base.is_some_and(|version| {
                version.instance != instance
                    || version.space != expected_space.space
                    || version.path != path
            }) {
                return Err(AccountError::new(
                    "file version does not match mounted path",
                ));
            }
            let _state_turn = ownership::local_state_turn(Arc::clone(&self.cancelled))?;
            return offline::stage_offline_mutation(expected_space, path, mutation, base, parents);
        }
        let session = self.read_session(instance)?;
        let space = bound_space(&session, Some(expected_space))?;
        if base.is_some_and(|version| {
            version.instance != session.base.as_str()
                || version.space != space
                || version.path != path
        }) {
            return Err(AccountError::new(
                "file version does not match mounted path",
            ));
        }
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_WRITE_SYNC_WINDOW")?;
        let _guard = self.begin_local_operation(&session, true)?;
        let _state_turn = ownership::local_state_turn(Arc::clone(&self.cancelled))?;
        let (_, uncertain) = offline::tree_remote_path(session.base.as_str(), space, path)?;
        if uncertain && !base.is_some_and(|version| version.id.starts_with("cirrus-staged:")) {
            return Err(AccountError::new("directory rename requires attention"));
        }
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_WRITE_TREE_WINDOW")?;
        offline::stage_mutation(expected_space, path, mutation, base, parents)
    }

    /// Verifies a pending staged-file rename before its journal transaction.
    ///
    /// A remote source is retained until its destination is confirmed at sync.
    ///
    /// # Errors
    /// Returns an error when metadata, the journal or either path has changed.
    pub fn prepare_file_rename<'a>(
        &'a self,
        instance: &str,
        expected_space: &MountBinding,
        source: &'a FileVersion,
        destination: &'a [String],
        expected_target: Option<(&'a str, &'a str)>,
        observed_target: Option<(&'a str, &'a str)>,
        pending_target: Option<&'a FileVersion>,
        parents: RenameParents<'a>,
    ) -> Result<PreparedFileRename<'a>, AccountError> {
        if destination.is_empty()
            || destination.len() > 128
            || destination.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid Space path"));
        }
        if expected_space.offline {
            if !expected_space.offline_writable
                || instance != expected_space.instance
                || source.instance != instance
                || source.space != expected_space.space
                || pending_target.is_some_and(|target| {
                    target.instance != instance
                        || target.space != expected_space.space
                        || target.path != destination
                })
            {
                return Err(AccountError::new("offline rename binding changed"));
            }
            let owner = ownership::acquire_offline(&self.runtime)?;
            self.check_cancelled()?;
            self.verify_offline_mount(expected_space)?;
            // Preserve only already verified local ranges. Missing originals
            // remain unavailable; no credential lookup, DAV or hydration.
            for version in std::iter::once(source).chain(pending_target) {
                let (_, name) = offline::staged_version(
                    &version.instance,
                    &version.space,
                    &version.path,
                    &version.id,
                )?
                .filter(|(current, _)| current == version)
                .ok_or_else(|| AccountError::new("rename snapshot changed"))?;
                offline::overlay::Overlay::load(&name)?.retain_available(
                    |base, offset, length| {
                        self.read_offline_range(expected_space, base, offset, length)
                            .ok()
                    },
                )?;
            }
            return Ok(PreparedFileRename {
                _guard: None,
                _offline_owner: Some(owner),
                source,
                destination,
                target: observed_target.or(expected_target),
                pending_target,
                parents,
                offline: Some(expected_space.clone()),
                cancelled: Arc::clone(&self.cancelled),
            });
        }
        let session = self.read_session(instance)?;
        let space = bound_space(&session, Some(expected_space))?;
        if source.instance != session.base.as_str() || source.space != space {
            return Err(AccountError::new(
                "file version does not match mounted Space",
            ));
        }
        if pending_target.is_some_and(|target| {
            target.instance != session.base.as_str()
                || target.space != space
                || target.path != destination
        }) {
            return Err(AccountError::new(
                "replacement target does not match mounted path",
            ));
        }
        let (source_name, source_parent) = source
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid source path"))?;
        let (target_name, target_parent) = destination
            .split_last()
            .ok_or_else(|| AccountError::new("invalid target path"))?;
        let guard = self.begin_shared_staging_operation(&session)?;
        let source_base = offline::staged_source_base(source)?;
        for version in std::iter::once(source).chain(pending_target) {
            let (_, name) = offline::staged_version(
                &version.instance,
                &version.space,
                &version.path,
                &version.id,
            )?
            .filter(|(current, _)| current == version)
            .ok_or_else(|| AccountError::new("rename snapshot changed"))?;
            offline::overlay::Overlay::load(&name)?.retain_available(|base, offset, length| {
                cache::read(&session, base, offset, length)
                    .ok()
                    .flatten()
                    .or_else(|| offline::read(base, offset, length).ok())
            })?;
        }
        let directory = |path: &[String]| -> Result<DirectorySnapshot, AccountError> {
            let observation = offline::begin_snapshot()?;
            #[cfg(feature = "fault-injection")]
            wait_test_window("CIRRUS_TEST_FILE_RENAME_PREP_WINDOW")?;
            if offline::local_directory(session.base.as_str(), space, path)? {
                return DirectorySnapshot::empty();
            }
            let (remote_path, uncertain) =
                offline::tree_remote_path(session.base.as_str(), space, path)?;
            if uncertain {
                return Err(AccountError::new("directory rename requires attention"));
            }
            match dav::directory_snapshot(
                &session.base,
                space,
                &remote_path,
                &session.account.access_token,
                &session.client,
            ) {
                Ok(entries) => {
                    if !offline::save_directory_snapshot(
                        observation,
                        session.base.as_str(),
                        space,
                        path,
                        &entries,
                    )? {
                        return Err(AccountError::new(
                            "directory metadata changed concurrently; retry",
                        ));
                    }
                    Ok(entries)
                }
                Err(error) if error.network => {
                    offline::directory_snapshot(session.base.as_str(), space, path)?.ok_or(error)
                }
                Err(error) => Err(error),
            }
        };
        let source_entries = directory(source_parent)?;
        let current_source = source_entries.get(source_name)?;
        if !match (current_source.as_ref(), source_base.as_ref()) {
            (None, None) => true,
            (Some(entry), Some((id, etag))) => {
                !entry.is_directory() && entry.id() == id && entry.etag() == Some(etag)
            }
            _ => false,
        } {
            return Err(AccountError::new(
                "rename source differs from its observed base",
            ));
        }
        let target_entries = if source_parent == target_parent {
            source_entries
        } else {
            directory(target_parent)?
        };
        let target = target_entries.get(target_name)?;
        if pending_target.is_none()
            && !match (target.as_ref(), expected_target) {
                (None, None) => true,
                (Some(entry), Some((id, etag))) => {
                    !entry.is_directory() && entry.id() == id && entry.etag() == Some(etag)
                }
                _ => false,
            }
        {
            return Err(AccountError::new("rename target changed"));
        }
        if source_base
            .as_ref()
            .is_some_and(|(id, _)| target.is_some_and(|entry| entry.id() == id))
        {
            return Err(AccountError::new(
                "rename paths identify the same remote resource",
            ));
        }
        if let Some(pending_target) = pending_target
            && let Some((id, etag)) = observed_target
        {
            let base = offline::staged_source_base(pending_target)?;
            if !base
                .as_ref()
                .is_some_and(|(base_id, base_etag)| base_id == id && base_etag == etag)
            {
                return Err(AccountError::new("rename target changed"));
            }
        }
        Ok(PreparedFileRename {
            _guard: Some(guard),
            _offline_owner: None,
            source,
            destination,
            target: observed_target.or(expected_target),
            pending_target,
            parents,
            offline: None,
            cancelled: Arc::clone(&self.cancelled),
        })
    }

    /// Relocates a wholly local pending directory tree in one journal transaction.
    ///
    /// # Errors
    /// Returns an error if either path or any unresolved operation is incompatible.
    /// A remote target carries its strong ETag; a pending local target has none.
    /// Reusing a remote target is supported only by explicit writable offline mounts.
    pub fn rename_local_directory(
        &self,
        instance: &str,
        expected_space: &MountBinding,
        source: &[String],
        destination: &[String],
        resource: &str,
        target: Option<(&str, Option<&str>)>,
        open_versions: &[FileVersion],
        parents: RenameParents<'_>,
    ) -> Result<Vec<FileVersion>, AccountError> {
        if destination.is_empty()
            || destination.len() > 128
            || destination.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid Space path"));
        }
        if expected_space.offline {
            if !expected_space.offline_writable || instance != expected_space.instance {
                return Err(AccountError::new("offline directory rename unavailable"));
            }
            let _owner = ownership::acquire_offline(&self.runtime)?;
            self.check_cancelled()?;
            self.verify_offline_mount(expected_space)?;
            let _turn = ownership::local_state_turn(Arc::clone(&self.cancelled))?;
            let mut relocated = Vec::with_capacity(open_versions.len());
            for version in open_versions {
                if version.instance != instance
                    || version.space != expected_space.space
                    || !version.path.starts_with(source)
                {
                    return Err(AccountError::new("open tree file binding changed"));
                }
                let mut next = version.clone();
                next.path = destination.to_vec();
                next.path.extend_from_slice(&version.path[source.len()..]);
                relocated.push(next);
            }
            offline::rename_local_directory(
                (instance, &expected_space.space),
                source,
                destination,
                resource,
                target,
                parents,
                Some((expected_space, open_versions)),
            )?;
            return Ok(relocated);
        }
        let session = self.read_session(instance)?;
        let space = bound_space(&session, Some(expected_space))?;
        let _guard = self.begin_local_operation(&session, false)?;
        let mut relocated = Vec::with_capacity(open_versions.len());
        for version in open_versions {
            if version.instance != session.base.as_str()
                || version.space != space
                || !version.path.starts_with(source)
                || !version.id.starts_with("cirrus-staged:")
                || offline::staged_version(
                    &version.instance,
                    &version.space,
                    &version.path,
                    &version.id,
                )?
                .is_none_or(|(current, _)| current != *version)
            {
                return Err(AccountError::new(
                    "open file changed during directory rename",
                ));
            }
            let mut next = version.clone();
            next.path = destination.to_vec();
            next.path.extend_from_slice(&version.path[source.len()..]);
            relocated.push(next);
        }
        offline::rename_local_directory(
            (session.base.as_str(), space),
            source,
            destination,
            resource,
            target,
            parents,
            None,
        )?;
        Ok(relocated)
    }

    /// Verifies a remote directory move before its journal transaction.
    ///
    /// # Errors
    /// Returns an error if observed paths, open versions or durable state are incompatible.
    pub fn prepare_remote_tree<'a>(
        &'a self,
        instance: &str,
        expected_space: &MountBinding,
        source: (&'a [String], &str, &str),
        destination: &'a [String],
        target: Option<(&str, &str)>,
        local_target: Option<&'a str>,
        open_versions: &'a [FileVersion],
        parents: RenameParents<'a>,
        open_directories: &'a [(Vec<String>, String)],
    ) -> Result<PreparedRemoteTree<'a>, AccountError> {
        let (source_path, source_id, source_etag) = source;
        if source_path.is_empty()
            || destination.is_empty()
            || destination.len() > 128
            || destination.starts_with(source_path)
            || source_path.starts_with(destination)
            || destination.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid Space path"));
        }
        if expected_space.offline {
            if !expected_space.offline_writable || instance != expected_space.instance {
                return Err(AccountError::new("offline directory rename unavailable"));
            }
            let owner = ownership::acquire_offline(&self.runtime)?;
            self.check_cancelled()?;
            self.verify_offline_mount(expected_space)?;
            let (name, parent) = source_path
                .split_last()
                .ok_or_else(|| AccountError::new("invalid tree source"))?;
            let entry = offline::offline_directory(
                instance,
                &expected_space.space,
                parent,
                Some((&expected_space.issuer, &expected_space.subject)),
            )?
            .get(name)?
            .filter(|entry| {
                entry.is_directory() && entry.id() == source_id && entry.etag() == Some(source_etag)
            })
            .ok_or_else(|| AccountError::new("offline directory source changed"))?;
            let mut relocated = Vec::with_capacity(open_versions.len());
            for version in open_versions {
                if version.instance != instance
                    || version.space != expected_space.space
                    || !version.path.starts_with(source_path)
                {
                    return Err(AccountError::new("open tree file binding changed"));
                }
                let mut next = version.clone();
                next.path = destination.to_vec();
                next.path
                    .extend_from_slice(&version.path[source_path.len()..]);
                relocated.push(next);
            }
            let target_entry = if let Some((id, etag)) = target {
                let (name, parent) = destination
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid tree destination"))?;
                Some(
                    offline::offline_directory(
                        instance,
                        &expected_space.space,
                        parent,
                        Some((&expected_space.issuer, &expected_space.subject)),
                    )?
                    .get(name)?
                    .filter(|entry| {
                        entry.is_directory() && entry.id() == id && entry.etag() == Some(etag)
                    })
                    .ok_or_else(|| AccountError::new("offline directory target changed"))?,
                )
            } else {
                None
            };
            return Ok(PreparedRemoteTree {
                _staging: None,
                _guard: None,
                _offline_owner: Some(owner),
                // Exclude admitted sync preflights as well as uncertain MOVEs.
                _sync_owner: Some(ownership::acquire_sync(&self.runtime)?),
                offline: Some(expected_space.clone()),
                cancelled: Arc::clone(&self.cancelled),
                instance: instance.to_owned(),
                space: expected_space.space.clone(),
                source: source_path,
                destination,
                entry,
                target: target_entry,
                local_target,
                parents,
                open_versions,
                open_directories,
                relocated,
            });
        }
        let session = self.read_session(instance)?;
        let space = bound_space(&session, Some(expected_space))?;
        let guard = self.begin_owned_local_operation(&session)?;
        // As for empty-directory preparation, keep exclusive cross-process
        // ownership but allow this daemon's local staging during DAV work.
        *self
            .sync_staging
            .write()
            .map_err(|_| AccountError::new("account state is unavailable"))? = true;
        let staging = SyncStaging(self);
        let (mapped_source, _) =
            offline::tree_remote_path(session.base.as_str(), space, source_path)?;
        let (mapped_destination, _) =
            offline::tree_remote_path(session.base.as_str(), space, destination)?;
        if mapped_source != source_path || mapped_destination != destination {
            return Err(AccountError::new("path has unresolved operations"));
        }
        let directory = |path: &[String]| -> Result<DirectorySnapshot, AccountError> {
            self.check_cancelled()?;
            let observation = offline::begin_snapshot()?;
            if offline::local_directory(session.base.as_str(), space, path)? {
                return DirectorySnapshot::empty();
            }
            let (remote, uncertain) =
                offline::tree_remote_path(session.base.as_str(), space, path)?;
            if uncertain {
                return Err(AccountError::new("directory rename requires attention"));
            }
            match dav::directory_snapshot(
                &session.base,
                space,
                &remote,
                &session.account.access_token,
                &session.client,
            ) {
                Ok(entries) => {
                    if !offline::save_directory_snapshot(
                        observation,
                        session.base.as_str(),
                        space,
                        path,
                        &entries,
                    )? {
                        return Err(AccountError::new(
                            "directory metadata changed concurrently; retry",
                        ));
                    }
                    Ok(entries)
                }
                Err(error) if error.network => {
                    offline::directory_snapshot(session.base.as_str(), space, path)?.ok_or(error)
                }
                Err(error) => Err(error),
            }
        };
        let (name, parent) = source_path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid Space path"))?;
        let entry = directory(parent)?
            .get(name)?
            .filter(|entry| {
                entry.is_directory() && entry.id() == source_id && entry.etag() == Some(source_etag)
            })
            .ok_or_else(|| AccountError::new("directory rename source changed"))?;
        // Save the root listing for offline traversal before publishing the mapping.
        directory(source_path)?;
        let (name, parent) = destination
            .split_last()
            .ok_or_else(|| AccountError::new("invalid Space path"))?;
        let target_entry = directory(parent)?.get(name)?;
        if !match (target_entry.as_ref(), target) {
            (None, None) => true,
            (Some(entry), Some((id, etag))) => {
                entry.is_directory() && entry.id() == id && entry.etag() == Some(etag)
            }
            _ => false,
        } {
            return Err(AccountError::new("rename target changed"));
        }
        if target_entry.is_some() && !directory(destination)?.is_empty()? {
            return Err(AccountError::new("directory is not empty"));
        }
        let mut relocated = Vec::with_capacity(open_versions.len());
        for version in open_versions {
            if version.instance != session.base.as_str()
                || version.space != space
                || !version.path.starts_with(source_path)
            {
                return Err(AccountError::new(
                    "open file changed during directory rename",
                ));
            }
            let current = if version.id.starts_with("cirrus-staged:") {
                offline::staged_version(
                    &version.instance,
                    &version.space,
                    &version.path,
                    &version.id,
                )?
                .map(|(v, _)| v)
            } else {
                let (name, parent) = version
                    .path
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid file path"))?;
                let entry = directory(parent)?
                    .get(name)?
                    .filter(|entry| entry.id() == version.id && !entry.is_directory());
                entry.and_then(|entry| {
                    Some(FileVersion {
                        instance: session.base.to_string(),
                        space: space.to_owned(),
                        path: version.path.clone(),
                        id: entry.id().to_owned(),
                        etag: entry.etag()?.to_owned(),
                        size: entry.size()?,
                        checksums: entry.checksums().to_vec(),
                    })
                })
            };
            if current.as_ref() != Some(version) {
                return Err(AccountError::new(
                    "open file changed during directory rename",
                ));
            }
            let mut next = version.clone();
            next.path = destination.to_vec();
            next.path
                .extend_from_slice(&version.path[source_path.len()..]);
            relocated.push(next);
        }
        Ok(PreparedRemoteTree {
            _staging: Some(staging),
            _guard: Some(guard),
            _offline_owner: None,
            _sync_owner: None,
            offline: None,
            cancelled: Arc::clone(&self.cancelled),
            instance: session.base.to_string(),
            space: space.to_owned(),
            source: source_path,
            destination,
            entry,
            target: target_entry,
            local_target,
            parents,
            open_versions,
            open_directories,
            relocated,
        })
    }

    /// Verifies an empty remote directory move before its journal transaction.
    ///
    /// # Errors
    /// Returns an error if the observed paths or durable journal cannot be validated.
    pub fn prepare_empty_directory<'a>(
        &'a self,
        instance: &str,
        expected_space: &MountBinding,
        source: &'a [String],
        destination: &'a [String],
        base: (&'a str, &'a str),
        parents: RenameParents<'a>,
    ) -> Result<PreparedEmptyDirectory<'a>, AccountError> {
        if source.is_empty()
            || destination.is_empty()
            || destination.len() > 128
            || destination.starts_with(source)
            || destination.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid Space path"));
        }
        let session = self.read_session(instance)?;
        let space = bound_space(&session, Some(expected_space))?;
        let guard = self.begin_owned_local_operation(&session)?;
        // Keep the same cross-process credential/namespace ownership as before,
        // but admit this daemon's identity-checked local staging while DAV is
        // in flight, just as during sync. Other account operations and peer
        // writers still cannot acquire this exclusive account owner.
        *self
            .sync_staging
            .write()
            .map_err(|_| AccountError::new("account state is unavailable"))? = true;
        let staging = SyncStaging(self);
        let (mapped_source, _) = offline::tree_remote_path(session.base.as_str(), space, source)?;
        let (mapped_destination, _) =
            offline::tree_remote_path(session.base.as_str(), space, destination)?;
        if mapped_source != source || mapped_destination != destination {
            return Err(AccountError::new("path has unresolved operations"));
        }
        let directory = |path: &[String]| -> Result<DirectorySnapshot, AccountError> {
            self.check_cancelled()?;
            let observation = offline::begin_snapshot()?;
            if offline::local_directory(session.base.as_str(), space, path)? {
                return DirectorySnapshot::empty();
            }
            match dav::directory_snapshot(
                &session.base,
                space,
                path,
                &session.account.access_token,
                &session.client,
            ) {
                Ok(entries) => {
                    if !offline::save_directory_snapshot(
                        observation,
                        session.base.as_str(),
                        space,
                        path,
                        &entries,
                    )? {
                        return Err(AccountError::new(
                            "directory metadata changed concurrently; retry",
                        ));
                    }
                    Ok(entries)
                }
                Err(error) if error.network => {
                    offline::directory_snapshot(session.base.as_str(), space, path)?.ok_or(error)
                }
                Err(error) => Err(error),
            }
        };
        let (name, parent) = source
            .split_last()
            .ok_or_else(|| AccountError::new("invalid Space path"))?;
        if !directory(parent)?.get(name)?.is_some_and(|entry| {
            entry.is_directory() && entry.id() == base.0 && entry.etag() == Some(base.1)
        }) {
            return Err(AccountError::new("directory rename source changed"));
        }
        if !directory(source)?.is_empty()? {
            return Err(AccountError::new("directory is not empty"));
        }
        let (name, parent) = destination
            .split_last()
            .ok_or_else(|| AccountError::new("invalid Space path"))?;
        if directory(parent)?.get(name)?.is_some() {
            return Err(AccountError::new("rename target changed"));
        }
        Ok(PreparedEmptyDirectory {
            _staging: staging,
            _guard: guard,
            instance: session.base.to_string(),
            space: space.to_owned(),
            source,
            destination,
            base,
            parents,
        })
    }

    /// Checks whether unresolved operations exist inside a selected directory.
    ///
    /// # Errors
    /// Returns an error if the account or journal is unavailable.
    pub fn has_unresolved_subtree(
        &self,
        instance: &str,
        expected_space: &MountBinding,
        path: &[String],
    ) -> Result<bool, AccountError> {
        let session = self.read_session(instance)?;
        let space = bound_space(&session, Some(expected_space))?;
        offline::any_unresolved_beneath(session.base.as_str(), space, path)
    }

    /// Queues a bounded local namespace operation and returns its journal ID.
    ///
    /// # Errors
    /// Returns an error for invalid paths, unsupported kinds or unresolved operations.
    pub fn stage_namespace(
        &self,
        instance: &str,
        expected_space: &MountBinding,
        path: &[String],
        kind: &str,
        base: Option<(&str, &str)>,
        parents: &[DirectoryIdentity],
    ) -> Result<i64, AccountError> {
        if path.is_empty()
            || path.len() > 128
            || path.iter().any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
        {
            return Err(AccountError::new("invalid Space path"));
        }
        if !matches!(
            (kind, base),
            ("mkdir", None) | ("unlink" | "rmdir", Some(_))
        ) {
            return Err(AccountError::new("invalid namespace operation"));
        }
        if expected_space.offline {
            let _priority = self.request_foreground();
            if !expected_space.offline_writable
                || instance != expected_space.instance
                || !matches!(kind, "mkdir" | "rmdir")
            {
                return Err(AccountError::new("offline namespace operation unavailable"));
            }
            let _owner = ownership::acquire_offline(&self.runtime)?;
            self.check_cancelled()?;
            self.verify_offline_mount(expected_space)?;
            let _state_turn = ownership::local_state_turn(Arc::clone(&self.cancelled))?;
            return offline::queue_namespace(
                instance,
                &expected_space.space,
                path,
                kind,
                base,
                parents,
                Some(expected_space),
            );
        }
        let session = self.read_session(instance)?;
        let space = bound_space(&session, Some(expected_space))?;
        let _guard = self.begin_local_operation(&session, false)?;
        let (_, uncertain) = offline::tree_remote_path(session.base.as_str(), space, path)?;
        if uncertain {
            return Err(AccountError::new("directory rename requires attention"));
        }
        offline::queue_namespace(
            session.base.as_str(),
            space,
            path,
            kind,
            base,
            parents,
            None,
        )
    }

    /// Removes a pending local entry while retaining any staged file snapshots.
    ///
    /// # Errors
    /// Returns an error if the entry has changed or has unresolved descendants.
    pub fn remove_staged(
        &self,
        instance: &str,
        expected_space: &MountBinding,
        path: &[String],
        resource: &str,
        detached: bool,
        parents: &[DirectoryIdentity],
    ) -> Result<(), AccountError> {
        let session = self.read_session(instance)?;
        let space = bound_space(&session, Some(expected_space))?;
        let _guard = self.begin_local_operation(&session, false)?;
        offline::remove_staged(
            (session.base.as_str(), space),
            path,
            resource,
            detached,
            parents,
            None,
        )
    }

    /// Unlinks an exact offline file while retaining its staged snapshot/history.
    ///
    /// # Errors
    /// Refuses changed identity, namespace, parents, version or storage admission.
    pub fn remove_offline_file(
        &self,
        binding: &MountBinding,
        version: &FileVersion,
        detached: bool,
        parents: &[DirectoryIdentity],
    ) -> Result<(), AccountError> {
        if !binding.offline
            || !binding.offline_writable
            || version.instance != binding.instance
            || version.space != binding.space
        {
            return Err(AccountError::new("offline unlink binding changed"));
        }
        let _priority = self.request_foreground();
        let _owner = ownership::acquire_offline(&self.runtime)?;
        self.check_cancelled()?;
        self.verify_offline_mount(binding)?;
        let _state_turn = ownership::local_state_turn(Arc::clone(&self.cancelled))?;
        offline::remove_staged(
            (&version.instance, &version.space),
            &version.path,
            &version.id,
            detached,
            parents,
            Some((binding, version)),
        )
    }

    /// Publishes a local-only extent mutation to an unlinked open file.
    ///
    /// # Errors
    /// Returns an error if the exact detached snapshot cannot be updated durably.
    pub fn stage_detached_mutation(
        &self,
        binding: &MountBinding,
        version: &FileVersion,
        mutation: DirtyMutation<'_>,
    ) -> Result<FileVersion, AccountError> {
        if binding.offline {
            if !binding.offline_writable
                || version.instance != binding.instance
                || version.space != binding.space
            {
                return Err(AccountError::new("offline detached binding changed"));
            }
            let _priority = self.request_foreground();
            let _owner = ownership::acquire_offline(&self.runtime)?;
            self.check_cancelled()?;
            if !offline::verify_offline_detached(binding, version)? {
                return Err(AccountError::new("offline detached version changed"));
            }
            let _state_turn = ownership::local_state_turn(Arc::clone(&self.cancelled))?;
            return offline::stage_detached_mutation(version, mutation, Some(binding));
        }
        let session = self.read_session(&version.instance)?;
        if bound_space(&session, Some(binding))? != version.space {
            return Err(AccountError::new(
                "file version does not match mounted Space",
            ));
        }
        let _guard = self.begin_local_operation(&session, true)?;
        offline::stage_detached_mutation(version, mutation, None)
    }

    /// Lists locally staged operations; none are uploaded automatically.
    ///
    /// # Errors
    /// Returns an error if the instance or durable state cannot be read.
    pub fn journal(
        &self,
        instance: &str,
        space: Option<&str>,
        before: Option<i64>,
    ) -> Result<JournalPage, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        if space.is_some_and(|id| id.is_empty() || id.chars().any(char::is_control)) {
            return Err(AccountError::new("invalid Space ID"));
        }
        if before == Some(0) {
            return Err(AccountError::new("invalid journal cursor"));
        }
        let mut page = offline::journal(base.as_str(), space, before)?;
        // Do not hold the upload-state lock while SQLite scans retained history.
        // Another daemon's active upload remains conservatively ambiguous.
        let active = self
            .active_writes
            .lock()
            .map_err(|_| AccountError::new("upload status is unavailable"))?;
        for entry in &mut page.entries {
            if entry.state == JournalState::UncertainOrInProgress && active.contains(&entry.id) {
                entry.state = JournalState::Uploading;
            }
        }
        Ok(page)
    }

    /// Lists a page of retained pin roots without accessing credentials or the network.
    ///
    /// # Errors
    /// Returns an error if the instance or local database cannot be read.
    pub fn retained_pins(
        &self,
        instance: &str,
        offset: u32,
    ) -> Result<Vec<(String, String)>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        recovery::list(base.as_str(), None, offset)
    }

    /// Lists immutable displaced pin copies by independent local ID.
    ///
    /// # Errors
    /// Returns an error for invalid input or unavailable retained metadata.
    pub fn pin_copies(
        &self,
        instance: &str,
        offset: u32,
    ) -> Result<Vec<(String, String)>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        recovery::pin_copies(base.as_str(), offset)
    }

    /// Lists captured directories and exact file versions in one retained copy.
    ///
    /// # Errors
    /// Returns an error for invalid identity, copy ID or retained metadata.
    pub fn pin_copy_entries(
        &self,
        instance: &str,
        space: &str,
        id: i64,
        offset: u32,
    ) -> Result<Vec<(String, String)>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        recovery::pin_copy_entries(base.as_str(), space, id, offset)
    }

    /// Exports one retained copy's selected file without credentials or network.
    ///
    /// # Errors
    /// Returns an error for invalid selection, damaged bytes or unsafe output.
    pub fn export_pin_copy(
        &self,
        instance: &str,
        space: &str,
        id: i64,
        path: &[String],
        selector: &str,
        destination: &std::path::Path,
    ) -> Result<(), AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        recovery::export_pin_copy(base.as_str(), space, id, path, selector, destination)
    }

    /// Removes only one explicitly identified immutable retained pin copy.
    ///
    /// # Errors
    /// Returns an error for invalid identity, missing copy or storage failure.
    pub fn remove_pin_copy(
        &self,
        instance: &str,
        space: &str,
        id: i64,
    ) -> Result<(), AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        recovery::remove_pin_copy(base.as_str(), space, id)
    }

    /// Lists journal-referenced immutable roots without scanning logical file content.
    ///
    /// # Errors
    /// Returns an error if local journal metadata cannot be read.
    pub fn retained_staged(
        &self,
        instance: &str,
        offset: u32,
    ) -> Result<Vec<(String, String)>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        recovery::staged_list(base.as_str(), offset)
    }

    /// Exports a selected journal-referenced staged copy without network access.
    ///
    /// # Errors
    /// Returns an error if selection, source validation or output fails. A partial output may remain.
    pub fn export_staged(
        &self,
        instance: &str,
        id: i64,
        selector: &str,
        destination: &std::path::Path,
    ) -> Result<(), AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        recovery::staged_export(base.as_str(), id, selector, destination)
    }

    /// Lists retained file metadata for one pin. Each value is a selector,
    /// newline, and the stored version JSON; the selector is not validation.
    ///
    /// # Errors
    /// Returns an error if the instance, path or local database is invalid.
    pub fn retained_files(
        &self,
        instance: &str,
        space: &str,
        root: &[String],
        offset: u32,
    ) -> Result<Vec<(String, String)>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        recovery::list(base.as_str(), Some((space, root)), offset)
    }

    /// Exports a retained, possibly stale, version to a new local file.
    ///
    /// # Errors
    /// Returns an error for invalid retained data or an unsafe destination. After
    /// creation, an error means the destination may contain partial data.
    pub fn export_retained(
        &self,
        instance: &str,
        space: &str,
        source: (&[String], &[String]),
        selector: &str,
        destination: &std::path::Path,
    ) -> Result<(), AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        recovery::export(
            base.as_str(),
            space,
            source.0,
            source.1,
            selector,
            destination,
        )
    }

    /// Uploads pending staged writes using best-effort ETag conflict detection.
    ///
    /// # Errors
    /// Returns an error when operations remain pending, conflict, or have an uncertain outcome.
    pub fn sync_pending(&self, instance: &str) -> Result<(), AccountError> {
        self.sync_pending_in(instance, None, executor::Mode::Manual)
            .map(|_| ())
    }

    /// Synchronizes one Space after checking the current authenticated Space listing.
    ///
    /// # Errors
    /// Returns an error if the Space is not listed or its operations need attention.
    pub fn sync_space(&self, instance: &str, space: &str) -> Result<(), AccountError> {
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid Space ID"));
        }
        self.sync_pending_in(instance, Some(space), executor::Mode::Manual)
            .map(|_| ())
    }

    /// Runs one write-transfer turn in a freshly authenticated, explicitly named Space.
    ///
    /// Admits at most one pending PUT or one durable GET-only continuation. Read-back
    /// uses at most eight HTTP requests (at most 1 MiB) with five-second admission
    /// and a 15-second request timeout, not a hard five-second wall-clock deadline.
    /// Authentication, listing and journal/parent preflight are not time-bounded.
    /// Namespace work and conflict-copy creation require ordinary explicit sync.
    /// Ownership is released on every return. This does not enable a scheduler.
    ///
    /// # Errors
    /// Returns an error for invalid input, account ownership, authentication or storage.
    pub fn write_turn(
        &self,
        instance: &str,
        space: &str,
    ) -> Result<WriteTurnOutcome, AccountError> {
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid Space ID"));
        }
        match self.sync_pending_in(instance, Some(space), executor::Mode::Write) {
            Err(error) if error.network => Ok(WriteTurnOutcome::Retry),
            result => result,
        }
    }

    fn sync_pending_in(
        &self,
        instance: &str,
        requested_space: Option<&str>,
        mode: executor::Mode,
    ) -> Result<WriteTurnOutcome, AccountError> {
        let _sync_guard = ownership::acquire_sync(&self.runtime)?;
        let mut session = self.read_session(instance)?;
        let result = self.sync_pending_once(&mut session, requested_space, mode);
        if mode != executor::Mode::Automatic
            || !result
                .as_ref()
                .is_err_and(|error| error.unauthorized && !error.upload_uncertain)
        {
            return result;
        }
        // Only read APIs emit unauthorized errors. Mutations return statuses
        // under durable uncertain claims, never this refresh/retry signal.
        // The failed turn has drained local staging and released shared account
        // ownership before refresh takes the exclusive credential bus name
        // with shared principal flock; never upgrade a live sync guard or
        // recursively enter account preparation.
        self.check_cancelled()?;
        executor::preflight_checkpoint()?;
        offline::database()?.execute("DELETE FROM sync_reads WHERE operation_id IN (SELECT id FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2))", rusqlite::params![session.base.as_str(),requested_space])
            .map_err(|_| AccountError::new("cannot invalidate rejected sync preflight"))?;
        session = self.refresh_rejected_session(&session)?;
        self.check_cancelled()?;
        executor::preflight_checkpoint()?;
        // One renewed turn only. A second 401 is Attention, not an endless
        // rotating refresh loop. Receipts select read-only continuation first;
        // uncertain mutations without receipts remain ineligible for replay.
        self.sync_pending_once(&mut session, requested_space, mode)
    }

    fn sync_pending_once(
        &self,
        session: &mut ReadSession,
        requested_space: Option<&str>,
        mode: executor::Mode,
    ) -> Result<WriteTurnOutcome, AccountError> {
        let bounded = mode != executor::Mode::Manual;
        let guard = self.begin_operation()?;
        self.clear_read_session()?;
        let store = Store::open(guard.connection()?)?;
        self.persist_pending(&store, session.base.as_str())?;
        session.account = store.load(session.base.as_str())?;
        if mode == executor::Mode::Automatic {
            offline::verify_identity(
                session.base.as_str(),
                &session.account.issuer,
                &session.account.subject,
            )
            .map_err(|mut error| {
                error.retryable_read = true;
                error
            })?;
        } else {
            offline::bind_identity(
                session.base.as_str(),
                &session.account.issuer,
                &session.account.subject,
            )?;
        }
        if mode == executor::Mode::Automatic {
            sync::check_identity(
                session,
                requested_space
                    .ok_or_else(|| AccountError::new("automatic sync requires a Space"))?,
            )
            .map_err(|mut error| {
                error.retryable_read = true;
                error
            })?;
        }
        if mode != executor::Mode::Automatic
            && session.account.selected_space.is_some()
            && session.account.selected_space != session.account.selected_space_verified
        {
            return Err(AccountError::new(
                "reselect your Space from the signed-in user's listing before accessing it",
            ));
        }
        if mode == executor::Mode::Manual
            && let Some(space) = requested_space
            && !offline::publication::spaces(session.base.as_str(), Some(space))?.is_empty()
        {
            return Err(AccountError::new(
                "local publication requires recovery; Space fenced; reopen the file before syncing",
            ));
        }
        session.client = http::client(session.account.ca_pem.as_deref().map(str::as_bytes))?;
        self.refresh_if_needed(&mut session.account, &store, &session.client)?;
        let spaces = if mode == executor::Mode::Automatic {
            Vec::new()
        } else {
            self.account_spaces(&session.base, &mut session.account, &store, &session.client)?
        };
        if mode != executor::Mode::Automatic
            && requested_space.is_some_and(|id| !spaces.iter().any(|space| space.id == id))
        {
            return Err(AccountError::new(
                "requested Space is not in the signed-in user's listing; local copies retained",
            ));
        }
        guard
            .guard
            .as_ref()
            .ok_or_else(|| AccountError::new("account ownership is unavailable"))?
            .downgrade()?;
        // flock downgrade is not atomic. Re-read credentials under the shared
        // lock before permitting either local journal writes or remote mutation.
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_SYNC_DOWNGRADE_WINDOW")?;
        if store.load(session.base.as_str())? != session.account {
            return Err(AccountError::new(
                "account changed while starting sync; retry",
            ));
        }
        *self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))? =
            Some(session.clone());
        self.session_ready.notify_all();
        *self
            .sync_staging
            .write()
            .map_err(|_| AccountError::new("account state is unavailable"))? = true;
        let _staging_window = SyncStaging(self);
        if mode == executor::Mode::Automatic {
            // Same-principal refresh is serialized by the exclusive bus owner;
            // shared principal ownership also permits retained local staging.
            let spaces = list_spaces(
                &session.base,
                &session.account.access_token,
                &session.client,
                &self.cancelled,
            )?;
            if requested_space.is_none_or(|id| !spaces.iter().any(|space| space.id == id)) {
                return Err(AccountError::retryable_read(
                    "activated Space absent from authenticated listing; local copies retained",
                ));
            }
            return self.automatic_turn(
                session,
                requested_space
                    .ok_or_else(|| AccountError::new("automatic sync requires a Space"))?,
            );
        }
        if mode == executor::Mode::Manual {
            self.resume_mutations(session, requested_space)?;
        }
        let allowed = |id: &str| spaces.iter().any(|space| space.id == id);
        let in_scope = |id: &str| requested_space.is_none_or(|requested| requested == id);
        let check = |id: &str| {
            if allowed(id) {
                Ok(())
            } else {
                Err(AccountError::new(
                    "pending operations include a Space not in the signed-in user's listing; local copies retained",
                ))
            }
        };
        let mut unlisted = HashSet::new();
        let preflight_through = offline::journal_high_water(session.base.as_str())?;
        let mut after = 0;
        loop {
            self.check_cancelled()?;
            let page = offline::tree_move_page(
                session.base.as_str(),
                requested_space,
                after,
                preflight_through,
            )?;
            let Some(last) = page.last() else { break };
            after = last.id;
            for operation in page {
                if in_scope(&operation.space) && !allowed(&operation.space) {
                    unlisted.insert(operation.space);
                }
            }
        }
        let mut after = 0;
        loop {
            self.check_cancelled()?;
            let page = offline::pending_writes(
                session.base.as_str(),
                requested_space,
                after,
                preflight_through,
            )?;
            let Some(last) = page.last() else { break };
            after = last.id;
            for operation in page {
                if in_scope(&operation.space) && !allowed(&operation.space) {
                    unlisted.insert(operation.space);
                }
            }
        }
        for mkdir in [true, false] {
            let mut after = (0, 0);
            loop {
                self.check_cancelled()?;
                let page = offline::pending_namespace(
                    session.base.as_str(),
                    requested_space,
                    mkdir,
                    after,
                    preflight_through,
                )?;
                let Some(last) = page.last() else { break };
                after = (if mkdir { last.path.len() } else { 0 }, last.id);
                for operation in page {
                    if in_scope(&operation.space) && !allowed(&operation.space) {
                        unlisted.insert(operation.space);
                    }
                }
            }
        }
        let invalid_journal =
            offline::invalid_journal_spaces(session.base.as_str(), requested_space)?;
        let local_publications =
            offline::publication::spaces(session.base.as_str(), requested_space)?;
        let mut blocked = unlisted.clone();
        blocked.extend(local_publications.iter().cloned());
        blocked.extend(invalid_journal.iter().cloned());
        blocked.extend(offline::unsettled_mkdir_spaces(
            session.base.as_str(),
            requested_space,
        )?);
        blocked.extend(offline::tree_blocked_spaces(
            session.base.as_str(),
            requested_space,
        )?);
        blocked.extend(offline::parent_conflict_spaces(
            session.base.as_str(),
            requested_space,
        )?);
        blocked.retain(|space| in_scope(space));
        let mut rejected_upload = false;
        let mut uncertain_upload = false;
        let mut deferred_upload = false;
        let mut namespace_attention = false;
        let mut conflict_copy_attention = false;
        // A continuation is executable only after a durably recorded successful
        // PUT response. Ordinary uncertain writes are deliberately absent here.
        let mut verification_after = 0;
        loop {
            let page = offline::upload_verifications(
                session.base.as_str(),
                requested_space,
                verification_after,
            )?;
            let Some(last) = page.last() else { break };
            verification_after = last.operation.id;
            for mut verification in page {
                if blocked.contains(&verification.operation.space) {
                    continue;
                }
                if !allowed(&verification.operation.space) {
                    unlisted.insert(verification.operation.space.clone());
                    blocked.insert(verification.operation.space.clone());
                    continue;
                }
                {
                    let mut active = self
                        .active_writes
                        .lock()
                        .map_err(|_| AccountError::new("upload status is unavailable"))?;
                    if !active.insert(verification.operation.id) {
                        return Err(AccountError::new("write is already being synchronized"));
                    }
                }
                let _active = ActiveWrite {
                    accounts: self,
                    id: verification.operation.id,
                };
                let outcome = self.advance_upload(session, &mut verification, bounded)?;
                if bounded {
                    return Ok(outcome);
                }
                if outcome == WriteTurnOutcome::Attention {
                    blocked.insert(verification.operation.space.clone());
                    uncertain_upload = true;
                }
                if outcome == WriteTurnOutcome::Retry {
                    blocked.insert(verification.operation.space.clone());
                    deferred_upload = true;
                }
            }
        }
        if bounded && !blocked.is_empty() {
            return Ok(WriteTurnOutcome::Attention);
        }
        if bounded && offline::write_turn_dependencies(session.base.as_str(), requested_space)? {
            return Ok(WriteTurnOutcome::Dependencies);
        }
        let trees_through = offline::journal_high_water(session.base.as_str())?;
        let mkdir_through = offline::journal_high_water(session.base.as_str())?;
        let mut after = (0, 0);
        loop {
            if bounded {
                break;
            }
            self.check_cancelled()?;
            let page = offline::pending_namespace(
                session.base.as_str(),
                requested_space,
                true,
                after,
                mkdir_through,
            )?;
            let Some(last) = page.last() else { break };
            after = (last.path.len(), last.id);
            for operation in page {
                if !in_scope(&operation.space) || blocked.contains(&operation.space) {
                    continue;
                }
                check(&operation.space)?;
                if !offline::tree_destination_contains(
                    session.base.as_str(),
                    &operation.space,
                    &operation.path,
                    trees_through,
                )? {
                    self.sync_mkdir_or_fence_space(session, &operation, &mut blocked)?;
                }
            }
        }
        let mut after = 0;
        loop {
            if bounded {
                break;
            }
            self.check_cancelled()?;
            let page = offline::tree_move_page(
                session.base.as_str(),
                requested_space,
                after,
                trees_through,
            )?;
            let Some(last) = page.last() else { break };
            after = last.id;
            for tree in page {
                if !in_scope(&tree.space) || blocked.contains(&tree.space) {
                    continue;
                }
                check(&tree.space)?;
                if let Err(error) = self.sync_tree_move(session, &tree) {
                    if offline::tree_blocked_spaces(session.base.as_str(), Some(&tree.space))?
                        .contains(&tree.space)
                    {
                        blocked.insert(tree.space.clone());
                    } else {
                        return Err(error);
                    }
                }
            }
        }
        let mkdir_through = offline::journal_high_water(session.base.as_str())?;
        let mut after = (0, 0);
        loop {
            if bounded {
                break;
            }
            self.check_cancelled()?;
            let page = offline::pending_namespace(
                session.base.as_str(),
                requested_space,
                true,
                after,
                mkdir_through,
            )?;
            let Some(last) = page.last() else { break };
            after = (last.path.len(), last.id);
            for operation in page {
                if !in_scope(&operation.space) || blocked.contains(&operation.space) {
                    continue;
                }
                check(&operation.space)?;
                self.sync_mkdir_or_fence_space(session, &operation, &mut blocked)?;
            }
        }
        // Bound this pass even when mounted writers append journal entries while
        // network I/O is in flight. Newly appended writes remain for a later pass.
        let writes_through = offline::journal_high_water(session.base.as_str())?;
        let mut after = 0;
        let mut attempted = false;
        'writes: loop {
            self.check_cancelled()?;
            let page = offline::pending_writes(
                session.base.as_str(),
                requested_space,
                after,
                writes_through,
            )?;
            let Some(last) = page.last() else { break };
            after = last.id;
            for operation in page {
                if !in_scope(&operation.space) || blocked.contains(&operation.space) {
                    continue;
                }
                check(&operation.space)?;
                if offline::tree_destination_contains(
                    session.base.as_str(),
                    &operation.space,
                    &operation.path,
                    i64::MAX,
                )? {
                    continue;
                }
                if bounded && attempted {
                    break 'writes;
                }
                attempted = true;
                self.check_cancelled()?;
                {
                    let mut active = self
                        .active_writes
                        .lock()
                        .map_err(|_| AccountError::new("upload status is unavailable"))?;
                    if !active.insert(operation.id) {
                        return Err(AccountError::new("write is already being synchronized"));
                    }
                }
                let _active = ActiveWrite {
                    accounts: self,
                    id: operation.id,
                };
                let (name, parent) = operation
                    .path
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid pending path"))?;
                if !self.verify_parent_identities(
                    session,
                    &operation.space,
                    &operation.path,
                    &operation.parents,
                )? {
                    offline::set_write_state(
                        session.base.as_str(),
                        &operation,
                        "pending",
                        "conflict",
                        Some(offline::PARENT_WRITE_CONFLICT),
                    )?;
                    blocked.insert(operation.space.clone());
                    continue;
                }
                let data = offline::StagedSnapshot::open(&operation.staged)?;
                if !self.prepare_dirty_snapshot(session, &data, bounded)?
                    || !self.protect_dirty_bases(
                        session,
                        &operation.space,
                        &operation.path,
                        bounded,
                    )?
                {
                    return Ok(WriteTurnOutcome::Yielded);
                }
                let entries = self.sync_directory_snapshot(session, &operation.space, parent)?;
                let current = entries.get(name)?;
                let matches = match (&operation.base_id, &operation.base_etag, current) {
                    (Some(id), Some(etag), Some(entry)) => {
                        !entry.is_directory()
                            && entry.id() == id
                            && entry.etag() == Some(etag.as_str())
                    }
                    (None, None, None) => true,
                    _ => false,
                };
                if !matches {
                    if bounded {
                        return Ok(WriteTurnOutcome::Dependencies);
                    }
                    self.sync_conflict_copy_or_fence_space(
                        session,
                        &operation,
                        &data,
                        &entries,
                        &mut blocked,
                        &mut conflict_copy_attention,
                    )?;
                    continue;
                }
                let body = reqwest::blocking::Body::sized(data.stream()?, data.len());
                let digest = if bounded {
                    let Some(digest) = data.digest_step("before-put")? else {
                        return Ok(WriteTurnOutcome::Yielded);
                    };
                    digest
                } else {
                    data.digest()?
                };
                if !self.protect_dirty_bases(session, &operation.space, &operation.path, bounded)? {
                    return Ok(WriteTurnOutcome::Yielded);
                }
                self.verify_incoming_file_source(session, &operation)?;
                offline::set_write_state(
                    session.base.as_str(),
                    &operation,
                    "pending",
                    "uncertain",
                    Some("upload started; outcome not yet confirmed"),
                )?;
                let status = match dav::put_file(
                    &session.base,
                    &operation.space,
                    &operation.path,
                    &session.account.access_token,
                    &session.client,
                    body,
                    operation.base_etag.as_deref(),
                ) {
                    Ok(status) => status,
                    Err(error) if error.upload_uncertain => {
                        blocked.insert(operation.space.clone());
                        uncertain_upload = true;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if status == reqwest::StatusCode::PRECONDITION_FAILED
                    || status == reqwest::StatusCode::CONFLICT
                {
                    offline::set_write_state(
                        session.base.as_str(),
                        &operation,
                        "uncertain",
                        "pending",
                        Some("remote rejected the precondition; local copy retained"),
                    )?;
                    if bounded {
                        return Ok(WriteTurnOutcome::Dependencies);
                    }
                    let entries =
                        self.sync_directory_snapshot(session, &operation.space, parent)?;
                    self.sync_conflict_copy_or_fence_space(
                        session,
                        &operation,
                        &data,
                        &entries,
                        &mut blocked,
                        &mut conflict_copy_attention,
                    )?;
                    continue;
                }
                if !matches!(status.as_u16(), 200 | 201 | 204) {
                    if status.is_client_error()
                        && status != reqwest::StatusCode::UNAUTHORIZED
                        && status != reqwest::StatusCode::REQUEST_TIMEOUT
                        && status != reqwest::StatusCode::TOO_MANY_REQUESTS
                    {
                        offline::set_write_state(
                            session.base.as_str(),
                            &operation,
                            "uncertain",
                            "pending",
                            Some("server rejected upload"),
                        )?;
                        blocked.insert(operation.space.clone());
                        rejected_upload = true;
                        continue;
                    }
                    offline::set_write_state(
                        session.base.as_str(),
                        &operation,
                        "uncertain",
                        "uncertain",
                        Some("server did not confirm upload; outcome remains uncertain"),
                    )?;
                    blocked.insert(operation.space.clone());
                    uncertain_upload = true;
                    continue;
                }
                // Verify the original descriptor before recording receipt. If it
                // changed in flight, keep the ambiguous operation fenced forever.
                if let Err(error) = data.verify() {
                    offline::set_write_state(
                        session.base.as_str(),
                        &operation,
                        "uncertain",
                        "uncertain",
                        Some(error.message),
                    )?;
                    blocked.insert(operation.space.clone());
                    uncertain_upload = true;
                    continue;
                }
                let mut verification = offline::UploadVerification::record(
                    session.base.as_str(),
                    &operation,
                    digest,
                    data.len(),
                )?;
                let outcome = self.advance_upload(session, &mut verification, bounded)?;
                if bounded {
                    return Ok(outcome);
                }
                if outcome == WriteTurnOutcome::Attention {
                    blocked.insert(operation.space.clone());
                    uncertain_upload = true;
                }
                if outcome == WriteTurnOutcome::Retry {
                    blocked.insert(operation.space.clone());
                    deferred_upload = true;
                }
            }
        }
        if bounded {
            return if !blocked.is_empty() || rejected_upload || uncertain_upload {
                Ok(WriteTurnOutcome::Attention)
            } else {
                offline::write_turn_remaining(session.base.as_str(), requested_space)
            };
        }
        let namespace_through = offline::journal_high_water(session.base.as_str())?;
        let mut after = (0, 0);
        loop {
            self.check_cancelled()?;
            let page = offline::pending_namespace(
                session.base.as_str(),
                requested_space,
                false,
                after,
                namespace_through,
            )?;
            let Some(last) = page.last() else { break };
            after = (0, last.id);
            for mut operation in page {
                if !in_scope(&operation.space) || blocked.contains(&operation.space) {
                    continue;
                }
                check(&operation.space)?;
                if operation.kind == "rmdir" {
                    let Some(current) = offline::pending_rmdir_base(
                        session.base.as_str(),
                        &operation.space,
                        &operation.path,
                    )?
                    else {
                        return Err(AccountError::new("parent removal changed concurrently"));
                    };
                    if !operation.same_rmdir_identity(&current) {
                        return Err(AccountError::new("parent removal changed concurrently"));
                    }
                    operation = current;
                }
                if let Err(error) = self.sync_namespace(session, &operation) {
                    self.check_cancelled()?;
                    if offline::namespace_needs_attention(session.base.as_str(), &operation)? {
                        blocked.insert(operation.space.clone());
                        namespace_attention = true;
                    } else {
                        return Err(error);
                    }
                }
            }
        }
        // Wait for local writes admitted during sync before reporting completion.
        drop(_staging_window);
        if deferred_upload {
            return Err(AccountError::retryable_read(
                "successful uploads await safe read-back retry; local copies retained",
            ));
        }
        if uncertain_upload {
            return Err(AccountError::new(
                "upload outcome is uncertain; its Space was fenced for this run; other eligible operations may have synced",
            ));
        }
        if conflict_copy_attention {
            return Err(AccountError::new(
                "conflict-copy upload requires attention; other eligible operations may have synced",
            ));
        }
        if namespace_attention {
            return Err(AccountError::new(
                "namespace conflict or uncertain outcome requires attention; other eligible operations may have synced",
            ));
        }
        if !unlisted.is_empty() {
            return Err(AccountError::new(
                "pending operations include a Space not in the signed-in user's listing; local copies retained; other eligible operations may have synced",
            ));
        }
        if !local_publications.is_empty() {
            return Err(AccountError::new(
                "local publication requires recovery; affected Spaces fenced; reopen the file; other eligible operations may have synced",
            ));
        }
        if !invalid_journal.is_empty() {
            return Err(AccountError::new(
                "invalid journal entries require attention; affected Spaces were fenced and local copies retained; other eligible operations may have synced",
            ));
        }
        if rejected_upload {
            return Err(AccountError::new(
                "server rejected an upload; its Space remains pending; other eligible operations may have synced",
            ));
        }
        if !blocked.is_empty() {
            return Err(AccountError::new(
                "directory conflict or uncertain outcome requires attention; other eligible operations may have synced",
            ));
        }
        if offline::has_unresolved(session.base.as_str(), requested_space)? {
            return Err(AccountError::new(
                "pending, conflict or uncertain operations require attention; local copies retained",
            ));
        }
        sync::manual_idle(session.base.as_str(), requested_space)?;
        Ok(WriteTurnOutcome::Idle)
    }

    fn sync_mkdir_or_fence_space(
        &self,
        session: &ReadSession,
        operation: &offline::NamespaceOperation,
        blocked: &mut HashSet<String>,
    ) -> Result<(), AccountError> {
        if let Err(error) = self.sync_namespace(session, operation) {
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_NAMESPACE_TRACE").is_some() {
                eprintln!(
                    "cirrus lab namespace failure: id={} kind={} path={:?} error={error}",
                    operation.id, operation.kind, operation.path
                );
            }
            if offline::unsettled_mkdir_spaces(session.base.as_str(), Some(&operation.space))?
                .contains(&operation.space)
            {
                blocked.insert(operation.space.clone());
            } else {
                return Err(error);
            }
        }
        Ok(())
    }

    fn sync_conflict_copy_or_fence_space(
        &self,
        session: &ReadSession,
        operation: &offline::PendingWrite,
        data: &offline::StagedSnapshot,
        entries: &DirectorySnapshot,
        blocked: &mut HashSet<String>,
        attention: &mut bool,
    ) -> Result<(), AccountError> {
        match self.save_conflict_copy(session, operation, data, entries) {
            Ok(ConflictCopyOutcome::ParentChanged) => {
                blocked.insert(operation.space.clone());
            }
            Ok(ConflictCopyOutcome::Recorded) => {}
            Err(error) => {
                self.check_cancelled()?;
                if offline::write_needs_attention(session.base.as_str(), operation)? {
                    blocked.insert(operation.space.clone());
                    *attention = true;
                } else {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn sync_tree_move(
        &self,
        session: &ReadSession,
        operation: &offline::TreeMove,
    ) -> Result<(), AccountError> {
        self.check_cancelled()?;
        let bounded = executor::active();
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_TREE_PREFLIGHT_WINDOW")?;
        if !self.protect_dirty_bases(session, &operation.space, &operation.source, bounded)?
            || !self.protect_dirty_bases(
                session,
                &operation.space,
                &operation.destination,
                bounded,
            )?
        {
            return Err(AccountError::yielded());
        }
        if !self.verify_parent_identities(
            session,
            &operation.space,
            &operation.source,
            &operation.parents,
        )? || !self.verify_parent_identities(
            session,
            &operation.space,
            &operation.destination,
            &operation.destination_parents,
        )? {
            offline::set_tree_state(
                session.base.as_str(),
                operation,
                "pending",
                "conflict",
                Some("directory parent identity changed; no MOVE sent"),
            )?;
            return Err(AccountError::new(
                "directory parent identity changed; local data retained",
            ));
        }
        let (source_name, source_parent) = operation
            .source
            .split_last()
            .ok_or_else(|| AccountError::new("invalid directory source"))?;
        let (target_name, target_parent) = operation
            .destination
            .split_last()
            .ok_or_else(|| AccountError::new("invalid directory destination"))?;
        let source_entries =
            self.sync_directory_snapshot(session, &operation.space, source_parent)?;
        let source = source_entries.get(source_name)?;
        let source_matches = source.is_some_and(|entry| {
            entry.is_directory()
                && entry.id() == operation.entry.id()
                && entry.etag() == operation.entry.etag()
        });
        let target_entries = if source_parent == target_parent {
            source_entries.clone()
        } else {
            self.sync_directory_snapshot(session, &operation.space, target_parent)?
        };
        let target = target_entries.get(target_name)?;
        let target_matches = match (target.as_ref(), operation.target.as_ref()) {
            (None, None) => true,
            (Some(entry), Some((id, etag))) => {
                entry.is_directory() && entry.id() == id && entry.etag() == Some(etag)
            }
            _ => false,
        };
        if !source_matches
            || !target_matches
            || (target.is_some()
                && !self
                    .sync_directory_snapshot(session, &operation.space, &operation.destination)?
                    .is_empty()?)
        {
            offline::set_tree_state(
                session.base.as_str(),
                operation,
                "pending",
                "conflict",
                Some("remote directory source or destination changed; no MOVE sent"),
            )?;
            return Err(AccountError::new(
                "directory rename conflict requires attention",
            ));
        }
        if operation.offline {
            use sha2::{Digest, Sha256};
            let mut after = None;
            loop {
                self.check_cancelled()?;
                let page =
                    offline::tree_proof_page(session.base.as_str(), operation, after.as_deref())?;
                let Some(last) = page.last() else {
                    break;
                };
                after = Some(last.0.clone());
                for (_, proof) in page {
                    let mut path = operation.source.clone();
                    path.extend(proof.path);
                    let fresh = self.sync_directory_snapshot(session, &operation.space, &path)?;
                    if fresh.remote_parent()? != (proof.id, proof.etag)
                        || format!("{:x}", Sha256::digest(fresh.json()?.as_bytes())) != proof.digest
                    {
                        offline::set_tree_state(
                            session.base.as_str(),
                            operation,
                            "pending",
                            "conflict",
                            Some("offline source subtree changed; no MOVE sent"),
                        )?;
                        return Err(AccountError::new(
                            "offline directory subtree conflict requires attention",
                        ));
                    }
                }
            }
        }
        if !self.protect_dirty_bases(session, &operation.space, &operation.source, bounded)?
            || !self.protect_dirty_bases(
                session,
                &operation.space,
                &operation.destination,
                bounded,
            )?
        {
            return Err(AccountError::yielded());
        }
        if executor::active() {
            executor::admit(self)?;
        }
        if operation.offline && operation.target.is_some() {
            offline::tree_target_proof(session.base.as_str(), operation)?;
            // Never restore these last-moment guards from scheduler read
            // checkpoints. Source If-Match does not condition the target.
            let fresh_parent = self.fresh_tree_destination(session, operation, target_parent)?;
            let fresh_target = fresh_parent.get(target_name)?;
            let expected = operation
                .target
                .as_ref()
                .ok_or_else(|| AccountError::new("replacement target unavailable"))?;
            let matches = fresh_parent.remote_parent()?.0 == target_entries.remote_parent()?.0
                && fresh_target.is_some_and(|entry| {
                    entry.is_directory()
                        && entry.id() == expected.0
                        && entry.etag() == Some(expected.1.as_str())
                });
            let empty = if matches {
                let fresh =
                    self.fresh_tree_destination(session, operation, &operation.destination)?;
                fresh.remote_parent()? == *expected && fresh.is_empty()?
            } else {
                false
            };
            if !empty {
                offline::set_tree_state(
                    session.base.as_str(),
                    operation,
                    "pending",
                    "conflict",
                    Some("replacement target changed or is not empty; no MOVE sent"),
                )?;
                return Err(AccountError::new(
                    "directory replacement conflict requires attention",
                ));
            }
        }
        offline::set_tree_state(
            session.base.as_str(),
            operation,
            "pending",
            "uncertain",
            Some("directory MOVE started; outcome not yet confirmed"),
        )?;
        let status = dav::move_directory(
            &session.base,
            &operation.space,
            (&operation.source, &operation.destination),
            &session.account.access_token,
            &session.client,
            operation
                .entry
                .etag()
                .ok_or_else(|| AccountError::new("directory lacks a strong ETag"))?,
            operation.target.is_some(),
        )?;
        if !matches!(status.as_u16(), 200 | 201 | 204) {
            if status.is_client_error()
                && status != reqwest::StatusCode::UNAUTHORIZED
                && status != reqwest::StatusCode::REQUEST_TIMEOUT
                && status != reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                offline::set_tree_state(
                    session.base.as_str(),
                    operation,
                    "uncertain",
                    "conflict",
                    Some("server rejected directory MOVE"),
                )?;
            }
            return Err(AccountError::new("directory MOVE failed or is uncertain"));
        }
        if executor::tree_receipt(operation)? {
            return Err(AccountError::yielded());
        }
        let source_after =
            self.sync_directory_snapshot(session, &operation.space, source_parent)?;
        let target_after = if source_parent == target_parent {
            source_after.clone()
        } else {
            self.sync_directory_snapshot(session, &operation.space, target_parent)?
        };
        if source_after.get(source_name)?.is_some()
            || !target_after
                .get(target_name)?
                .is_some_and(|entry| entry.is_directory() && entry.id() == operation.entry.id())
        {
            return Err(AccountError::new(
                "directory MOVE outcome could not be verified",
            ));
        }
        if !self.verify_parent_identities(
            session,
            &operation.space,
            &operation.source,
            &operation.parents,
        )? || !self.verify_parent_identities(
            session,
            &operation.space,
            &operation.destination,
            &operation.destination_parents,
        )? {
            return Err(AccountError::new(
                "directory parent identity changed after MOVE; outcome remains uncertain",
            ));
        }
        if operation.offline
            && operation.target.is_some()
            && !self.verify_replaced_tree(session, operation)?
        {
            return Err(AccountError::new(
                "replacement MOVE structure could not be verified",
            ));
        }
        offline::set_tree_state(
            session.base.as_str(),
            operation,
            "uncertain",
            "synced",
            None,
        )
    }

    fn fresh_tree_destination(
        &self,
        session: &ReadSession,
        operation: &offline::TreeMove,
        path: &[String],
    ) -> Result<DirectorySnapshot, AccountError> {
        self.check_cancelled()?;
        if executor::active() {
            executor::admit(self)?;
        }
        dav::directory_snapshot_once(
            &session.base,
            &operation.space,
            path,
            &session.account.access_token,
            &session.client,
        )
    }

    fn verify_replaced_tree(
        &self,
        session: &ReadSession,
        operation: &offline::TreeMove,
    ) -> Result<bool, AccountError> {
        use sha2::{Digest, Sha256};
        offline::tree_target_proof(session.base.as_str(), operation)?;
        let mut after = None;
        loop {
            let page =
                offline::tree_proof_page(session.base.as_str(), operation, after.as_deref())?;
            let Some(last) = page.last() else {
                break;
            };
            after = Some(last.0.clone());
            for (_, proof) in page {
                let mut path = operation.destination.clone();
                path.extend(proof.path);
                let fresh = self.sync_directory_snapshot(session, &operation.space, &path)?;
                if fresh.remote_parent()? != (proof.id, proof.etag)
                    || format!("{:x}", Sha256::digest(fresh.json()?.as_bytes())) != proof.digest
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn sync_namespace(
        &self,
        session: &ReadSession,
        operation: &offline::NamespaceOperation,
    ) -> Result<(), AccountError> {
        self.check_cancelled()?;
        // A rename source may depend on a verified write outside the tree.
        // That edge alone does not prove its relocated source exists remotely.
        // Gate on the durable MOVE ancestry, independently of dispatcher order.
        if offline::tree_destination_contains(
            session.base.as_str(),
            &operation.space,
            &operation.path,
            i64::MAX,
        )? {
            return Err(AccountError::yielded());
        }
        if !self.protect_dirty_bases(session, &operation.space, &operation.path, false)? {
            return Err(AccountError::yielded());
        }
        if !self.verify_parent_identities(
            session,
            &operation.space,
            &operation.path,
            &operation.parents,
        )? {
            offline::set_namespace_state(
                session.base.as_str(),
                operation,
                "pending",
                "conflict",
                Some("parent identity changed; no mutation sent"),
            )?;
            return Err(AccountError::new(
                "parent identity changed; local data retained",
            ));
        }
        if self.reuse_local_directory_target(session, operation)? {
            return Ok(());
        }
        let (name, parent) = operation
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid namespace path"))?;
        let entries = self.sync_directory_snapshot(session, &operation.space, parent)?;
        let current = entries.get(name)?;
        let mkdir = operation.kind == "mkdir";
        if let Some(dependency) = operation.dependency
            && operation.kind == "move-dir-source"
        {
            let Some(destination) =
                offline::confirmed_directory(session.base.as_str(), dependency)?
            else {
                offline::set_namespace_state(
                    session.base.as_str(),
                    operation,
                    "pending",
                    "conflict",
                    Some("directory destination not confirmed; source retained"),
                )?;
                return Err(AccountError::new(
                    "directory destination is not confirmed; source retained",
                ));
            };
            let (destination_name, destination_parent) = destination
                .path
                .split_last()
                .ok_or_else(|| AccountError::new("invalid directory destination"))?;
            let confirmed = destination.space == operation.space
                && self.verify_parent_identities(
                    session,
                    &destination.space,
                    &destination.path,
                    &destination.parents,
                )?
                && self
                    .sync_directory_snapshot(session, &destination.space, destination_parent)?
                    .get(destination_name)?
                    .is_some_and(|entry| entry.is_directory() && entry.id() == destination.id);
            if !confirmed {
                offline::set_namespace_state(
                    session.base.as_str(),
                    operation,
                    "pending",
                    "conflict",
                    Some("directory destination changed; source retained"),
                )?;
                return Err(AccountError::new(
                    "directory destination changed; source retained",
                ));
            }
        } else if let Some(dependency) = operation.dependency {
            let Some(destination) =
                offline::confirmed_destination(session.base.as_str(), dependency)?
            else {
                offline::set_namespace_state(
                    session.base.as_str(),
                    operation,
                    "pending",
                    "conflict",
                    Some("rename destination not confirmed; remote source retained"),
                )?;
                return Err(AccountError::new(
                    "rename destination is not confirmed; source retained",
                ));
            };
            #[cfg(feature = "fault-injection")]
            wait_test_window("CIRRUS_TEST_RENAME_CONFIRM_WINDOW")?;
            let data = offline::StagedSnapshot::open(&destination.staged)?;
            let verified = if destination.space == operation.space
                && self.verify_parent_identities(
                    session,
                    &destination.space,
                    &destination.path,
                    &destination.parents,
                )? {
                self.verify_upload(session, &destination.space, &destination.path, &data)
                    .and_then(|version| {
                        if version.id == destination.file_id && version.etag == destination.etag {
                            Ok(())
                        } else {
                            Err(AccountError::new("rename destination identity changed"))
                        }
                    })
            } else {
                Err(AccountError::new(
                    "rename destination parent or Space changed",
                ))
            };
            if let Err(error) = verified {
                if !error.network {
                    offline::set_namespace_state(
                        session.base.as_str(),
                        operation,
                        "pending",
                        "conflict",
                        Some("rename destination could not be verified; remote source retained"),
                    )?;
                }
                return Err(error);
            }
        }
        if !mkdir && current.is_none() {
            return offline::set_namespace_state(
                session.base.as_str(),
                operation,
                "pending",
                "synced",
                Some("target already absent"),
            );
        }
        let matches = if mkdir {
            current.is_none()
        } else {
            current.is_some_and(|entry| {
                entry.is_directory()
                    == matches!(operation.kind.as_str(), "rmdir" | "move-dir-source")
                    && Some(entry.id()) == operation.base_id.as_deref()
                    && entry.etag() == operation.base_etag.as_deref()
                    && operation.base_etag.is_some()
            })
        };
        if !matches {
            offline::set_namespace_state(
                session.base.as_str(),
                operation,
                "pending",
                "conflict",
                Some("remote namespace target differs; no mutation sent"),
            )?;
            return Err(AccountError::new("namespace conflict requires attention"));
        }
        if !mkdir
            && offline::unresolved_beneath(
                session.base.as_str(),
                &operation.space,
                &operation.path,
            )?
        {
            return Err(AccountError::new("local pending data prevents deletion"));
        }
        if matches!(operation.kind.as_str(), "rmdir" | "move-dir-source") {
            let children =
                self.sync_directory_snapshot(session, &operation.space, &operation.path)?;
            let (id, etag) = children.remote_parent()?;
            if Some(id.as_str()) != operation.base_id.as_deref()
                || Some(etag.as_str()) != operation.base_etag.as_deref()
                || !children.is_empty()?
            {
                offline::set_namespace_state(
                    session.base.as_str(),
                    operation,
                    "pending",
                    "conflict",
                    Some("remote directory version changed or is not empty; no mutation sent"),
                )?;
                return Err(AccountError::new("directory is not empty"));
            }
        }
        let parent_rebase = if !mkdir && !parent.is_empty() {
            if let Some(pending) =
                offline::pending_rmdir_base(session.base.as_str(), &operation.space, parent)?
            {
                let parent_id = pending
                    .base_id
                    .as_deref()
                    .ok_or_else(|| AccountError::new("invalid parent removal"))?;
                let parent_etag = pending
                    .base_etag
                    .as_deref()
                    .ok_or_else(|| AccountError::new("invalid parent removal"))?;
                let (parent_name, grandparent) = parent
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid parent path"))?;
                let matches = self
                    .sync_directory_snapshot(session, &operation.space, grandparent)?
                    .get(parent_name)?
                    .is_some_and(|entry| {
                        entry.is_directory()
                            && entry.id() == parent_id
                            && entry.etag() == Some(parent_etag)
                    });
                if matches { Some(pending) } else { None }
            } else {
                None
            }
        } else {
            None
        };
        if !self.protect_dirty_bases(session, &operation.space, &operation.path, false)? {
            return Err(AccountError::yielded());
        }
        offline::set_namespace_state(
            session.base.as_str(),
            operation,
            "pending",
            "uncertain",
            Some("namespace request started; outcome not yet confirmed"),
        )?;
        let status = dav::namespace_request(
            &session.base,
            &operation.space,
            &operation.path,
            &session.account.access_token,
            &session.client,
            mkdir,
            operation.base_etag.as_deref(),
        )?;
        if !matches!(status.as_u16(), 200 | 201 | 204)
            && !(!mkdir && status == reqwest::StatusCode::NOT_FOUND)
        {
            if status.is_client_error()
                && status != reqwest::StatusCode::UNAUTHORIZED
                && status != reqwest::StatusCode::REQUEST_TIMEOUT
                && status != reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                offline::set_namespace_state(
                    session.base.as_str(),
                    operation,
                    "uncertain",
                    "conflict",
                    Some("server rejected namespace request"),
                )?;
            }
            return Err(AccountError::new(
                "namespace request failed or is uncertain",
            ));
        }
        // Successful response evidence must survive any later local/read
        // failure. The already durable uncertain claim prevents replay even
        // if this uncapped receipt transaction itself fails.
        executor::namespace_receipt(operation, parent_rebase.as_ref())?;
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_NAMESPACE_RECEIPT_WINDOW")?;
        let after = self.sync_directory_snapshot(session, &operation.space, parent)?;
        let present = after.get(name)?;
        if (mkdir && !present.as_ref().is_some_and(Entry::is_directory))
            || (!mkdir && present.is_some())
        {
            return Err(AccountError::new("namespace outcome could not be verified"));
        }
        if !self.verify_parent_identities(
            session,
            &operation.space,
            &operation.path,
            &operation.parents,
        )? {
            return Err(AccountError::new(
                "parent identity changed after namespace mutation; outcome remains uncertain",
            ));
        }
        let rebase = if let Some(pending) = parent_rebase.as_ref() {
            let parent_id = pending
                .base_id
                .as_deref()
                .ok_or_else(|| AccountError::new("invalid parent removal"))?;
            let (parent_name, grandparent) = parent
                .split_last()
                .ok_or_else(|| AccountError::new("invalid parent path"))?;
            self.sync_directory_snapshot(session, &operation.space, grandparent)?
                .get(parent_name)?
                .filter(|entry| entry.is_directory() && entry.id() == parent_id)
                .and_then(|entry| entry.etag().map(str::to_owned))
                .map(|etag| (pending, etag))
        } else {
            None
        };
        let confirmation = if mkdir {
            present.map(|entry| format!("confirmed-directory:{}", entry.id()))
        } else {
            None
        };
        offline::confirm_namespace(
            session.base.as_str(),
            operation,
            confirmation.as_deref(),
            rebase
                .as_ref()
                .map(|(parent, etag)| (*parent, etag.as_str())),
        )?;
        executor::retire(operation.id)
    }

    fn reuse_local_directory_target(
        &self,
        session: &ReadSession,
        operation: &offline::NamespaceOperation,
    ) -> Result<bool, AccountError> {
        if !operation.reuses_directory() {
            return Ok(false);
        }
        let instance = session.base.as_str();
        let target = offline::local_directory_target(instance, operation)?;
        let (name, parent) = operation
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid directory binding path"))?;
        let observed_parent = self.sync_directory_snapshot(session, &operation.space, parent)?;
        let fresh = |path: &[String]| -> Result<DirectorySnapshot, AccountError> {
            self.check_cancelled()?;
            if executor::active() {
                executor::admit(self)?;
            }
            dav::directory_snapshot_once(
                &session.base,
                &operation.space,
                path,
                &session.account.access_token,
                &session.client,
            )
        };
        let parent_now = fresh(parent)?;
        let mut matches = parent_now.remote_parent()?.0 == observed_parent.remote_parent()?.0
            && parent_now.get(name)?.is_some_and(|entry| {
                entry.is_directory()
                    && entry.id() == target.id
                    && entry.etag() == Some(target.etag.as_str())
            });
        if matches {
            let children = fresh(&operation.path)?;
            matches = children.remote_parent()? == (target.id.clone(), target.etag.clone())
                && children.is_empty()?;
        }
        if !matches {
            offline::set_namespace_state(
                instance,
                operation,
                "pending",
                "conflict",
                Some("empty directory target changed; no child mutation authorized"),
            )?;
            return Err(AccountError::new(
                "directory target binding conflict requires attention",
            ));
        }
        offline::confirm_local_directory_target(instance, operation, &target).map_err(
            |mut error| {
                error.retryable_read = true;
                error
            },
        )?;
        Ok(true)
    }

    /// Acknowledges an inspected conflict or uncertain outcome without deleting its local copy.
    ///
    /// # Errors
    /// Returns an error if no matching unresolved entry exists or the journal cannot be updated.
    pub fn acknowledge(&self, instance: &str, staged: &str) -> Result<(), AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        let _guard = self.begin_operation()?;
        offline::acknowledge(base.as_str(), staged)
    }

    fn sync_directory_snapshot(
        &self,
        session: &ReadSession,
        space: &str,
        path: &[String],
    ) -> Result<DirectorySnapshot, AccountError> {
        if executor::active() {
            return executor::directory(self, session, space, path);
        }
        for attempt in 0..3 {
            self.check_cancelled()?;
            let observation = offline::begin_snapshot()?;
            match dav::directory_snapshot(
                &session.base,
                space,
                path,
                &session.account.access_token,
                &session.client,
            ) {
                Err(error) if error.network && attempt < 2 => {
                    std::thread::sleep(Duration::from_millis(100 << attempt))
                }
                Ok(entries) => {
                    let saved = offline::save_directory_snapshot(
                        observation,
                        session.base.as_str(),
                        space,
                        path,
                        &entries,
                    );
                    if matches!(saved, Ok(false))
                        && !offline::directory_copy_compatible(
                            session.base.as_str(),
                            space,
                            path,
                            &entries,
                            &session.account.issuer,
                            &session.account.subject,
                        )?
                    {
                        return Err(AccountError::retryable_read(
                            "directory metadata changed concurrently; retry",
                        ));
                    }
                    if let Err(error) = saved {
                        // This complete online snapshot already passed DAV
                        // validation. A competing State lease may skip its
                        // optional offline copy (as a stale observation can),
                        // never its parent/ETag checks or a sync_reads gate.
                        if !error.storage_busy
                            || !offline::directory_copy_compatible(
                                session.base.as_str(),
                                space,
                                path,
                                &entries,
                                &session.account.issuer,
                                &session.account.subject,
                            )?
                        {
                            return Err(error);
                        }
                        #[cfg(feature = "fault-injection")]
                        if std::env::var_os("CIRRUS_TEST_NAMESPACE_TRACE").is_some() {
                            eprintln!(
                                "cirrus lab manual snapshot cache skipped: State lease busy path={path:?}"
                            );
                        }
                    }
                    return Ok(entries);
                }
                Err(error) => return Err(error),
            }
        }
        Err(AccountError::new("directory request failed"))
    }

    fn verify_parent_identities(
        &self,
        session: &ReadSession,
        space: &str,
        path: &[String],
        parents: &[DirectoryIdentity],
    ) -> Result<bool, AccountError> {
        if path.is_empty() || parents.len() != path.len() - 1 {
            return Err(AccountError::new("invalid parent identity chain"));
        }
        for (index, parent) in parents.iter().enumerate() {
            let expected = match parent {
                DirectoryIdentity::Remote(id) if dav::valid_remote_id(id) => id.clone(),
                DirectoryIdentity::Pending(id) => {
                    let confirmed = offline::confirmed_directory(session.base.as_str(), *id)?
                        .ok_or_else(|| {
                            AccountError::new("parent directory creation is not confirmed")
                        })?;
                    if confirmed.space != space
                        || confirmed.path != path[..=index]
                        || !dav::valid_remote_id(&confirmed.id)
                    {
                        return Ok(false);
                    }
                    confirmed.id
                }
                _ => return Err(AccountError::new("invalid parent identity chain")),
            };
            let entries = self.sync_directory_snapshot(session, space, &path[..index])?;
            if !entries
                .get(&path[index])?
                .is_some_and(|entry| entry.is_directory() && entry.id() == expected)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn save_conflict_copy(
        &self,
        session: &ReadSession,
        operation: &offline::PendingWrite,
        data: &offline::StagedSnapshot,
        entries: &DirectorySnapshot,
    ) -> Result<ConflictCopyOutcome, AccountError> {
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_CONFLICT_PARENT_WINDOW")?;
        if !self.verify_parent_identities(
            session,
            &operation.space,
            &operation.path,
            &operation.parents,
        )? {
            offline::set_write_state(
                session.base.as_str(),
                operation,
                "pending",
                "conflict",
                Some(offline::PARENT_WRITE_CONFLICT),
            )?;
            return Ok(ConflictCopyOutcome::ParentChanged);
        }
        let (name, parent) = operation
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid pending path"))?;
        let mut random = [0u8; 16];
        let mut filled = 0;
        while filled < random.len() {
            let count = rustix::rand::getrandom(
                &mut random[filled..],
                rustix::rand::GetRandomFlags::empty(),
            )
            .map_err(|_| AccountError::new("cannot generate conflict name"))?;
            if count == 0 {
                return Err(AccountError::new("cannot generate conflict name"));
            }
            filled += count;
        }
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let (stem, ext) = match name.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => (stem, format!(".{ext}")),
            _ => (name.as_str(), String::new()),
        };
        let candidate = format!("{stem} (conflict {suffix}){ext}");
        if candidate.len() > 255 || entries.get(&candidate)?.is_some() {
            offline::set_write_state(
                session.base.as_str(),
                operation,
                "pending",
                "conflict",
                Some("cannot create conflict copy; local copy retained"),
            )?;
            return Ok(ConflictCopyOutcome::Recorded);
        }
        let mut path = parent.to_vec();
        path.push(candidate);
        let source_digest = data.digest()?;
        let body = reqwest::blocking::Body::sized(data.stream()?, data.len());
        offline::set_write_state(
            session.base.as_str(),
            operation,
            "pending",
            "uncertain",
            Some(&format!(
                "conflict-copy upload /{} started; outcome not yet confirmed",
                path.join("/")
            )),
        )?;
        let status = dav::put_file(
            &session.base,
            &operation.space,
            &path,
            &session.account.access_token,
            &session.client,
            body,
            None,
        )?;
        if !matches!(status.as_u16(), 200 | 201 | 204) {
            if status.is_client_error()
                && status != reqwest::StatusCode::UNAUTHORIZED
                && status != reqwest::StatusCode::REQUEST_TIMEOUT
                && status != reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                offline::set_write_state(
                    session.base.as_str(),
                    operation,
                    "uncertain",
                    "conflict",
                    Some("conflict-copy upload rejected; local copy retained"),
                )?;
            }
            return Err(AccountError::new(
                "conflict-copy upload failed or is uncertain; local copy retained",
            ));
        }
        self.verify_upload(session, &operation.space, &path, data)?;
        if data.digest()? != source_digest {
            return Err(AccountError::new(
                "conflict-copy source changed; outcome remains uncertain",
            ));
        }
        if !self.verify_parent_identities(
            session,
            &operation.space,
            &operation.path,
            &operation.parents,
        )? {
            return Err(AccountError::new(
                "parent identity changed after conflict-copy upload; outcome remains uncertain",
            ));
        }
        offline::set_write_state(
            session.base.as_str(),
            operation,
            "uncertain",
            "conflict",
            Some(&format!(
                "conflict copy /{}; local copy retained",
                path.join("/")
            )),
        )?;
        Ok(ConflictCopyOutcome::Recorded)
    }

    fn verify_upload(
        &self,
        session: &ReadSession,
        space: &str,
        path: &[String],
        data: &offline::StagedSnapshot,
    ) -> Result<FileVersion, AccountError> {
        let (name, parent) = path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid upload path"))?;
        let entries = self.sync_directory_snapshot(session, space, parent)?;
        let entry = entries
            .get(name)?
            .filter(|entry| !entry.is_directory() && entry.size() == Some(data.len()))
            .ok_or_else(|| {
                AccountError::new("upload could not be verified; local copy retained")
            })?;
        let version = FileVersion {
            instance: session.base.to_string(),
            space: space.to_owned(),
            path: path.to_vec(),
            id: entry.id().to_owned(),
            etag: entry
                .etag()
                .ok_or_else(|| AccountError::new("uploaded file lacks a strong ETag"))?
                .to_owned(),
            size: data.len(),
            checksums: entry.checksums().to_vec(),
        };
        let mut offset = 0u64;
        while offset < data.len() {
            self.check_cancelled()?;
            let length = (data.len() - offset).min(131_072) as u32;
            let bytes = dav::read_range(
                &session.base,
                &version,
                offset,
                offset + u64::from(length) - 1,
                &session.account.access_token,
                &session.client,
            )?;
            if bytes != data.range(offset, length)? {
                return Err(AccountError::new(
                    "uploaded content could not be verified; local copy retained",
                ));
            }
            offset += u64::from(length);
        }
        let after = self.sync_directory_snapshot(session, space, parent)?;
        if !after.get(name)?.is_some_and(|entry| {
            entry.id() == version.id
                && entry.etag() == Some(version.etag.as_str())
                && entry.size() == Some(version.size)
        }) {
            return Err(AccountError::new(
                "uploaded file changed during verification; local copy retained",
            ));
        }
        data.verify()?;
        Ok(version)
    }

    /// Lists the selected Space's pinned paths.
    ///
    /// # Errors
    /// Returns an error if account selection or durable storage is unavailable.
    pub fn pins(&self, instance: &str) -> Result<Vec<(String, String)>, AccountError> {
        self.pins_inner(instance, None)
    }

    /// Inspects one Space's locally retained pins, without credentials or network access.
    ///
    /// # Errors
    /// Returns an error for invalid input, missing local identity or durable storage failure.
    pub fn pins_space(
        &self,
        instance: &str,
        space: &str,
    ) -> Result<Vec<(String, String)>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid Space ID"));
        }
        Ok(offline::pins(base.as_str(), space, true)?
            .into_iter()
            .map(|pin| {
                let status = if !pin.complete {
                    "incomplete (local state; remote not checked)"
                } else if !pin.metadata_matches {
                    "stale (local metadata; remote not checked)"
                } else {
                    "available offline (local state; remote not checked)"
                };
                (format!("/{}", pin.path.join("/")), status.to_owned())
            })
            .collect())
    }

    fn pins_inner(
        &self,
        instance: &str,
        binding: Option<&MountBinding>,
    ) -> Result<Vec<(String, String)>, AccountError> {
        let session = self.read_session(instance)?;
        let space = bound_space(&session, binding)?;
        let mut output = Vec::new();
        for offline::Pin {
            path,
            tree,
            complete,
            metadata_matches,
        } in offline::pins(session.base.as_str(), space, true)?
        {
            let status = if !complete {
                "incomplete"
            } else if !metadata_matches {
                "stale"
            } else {
                match self.collect_pin_files(session.base.as_str(), binding, &path, true) {
                    Ok(current) if current == tree => "available offline",
                    Ok(_) => "stale",
                    Err(error) if error.network => "available offline",
                    Err(error)
                        if error
                            .message
                            .starts_with("offline metadata changed during pinning") =>
                    {
                        "unknown"
                    }
                    Err(_) => "stale",
                }
            };
            output.push((format!("/{}", path.join("/")), status.to_owned()));
        }
        Ok(output)
    }

    /// Revalidates a snapshot before serving an experimental cached range.
    ///
    /// # Errors
    /// Returns an error if the resource or representation is no longer observed.
    pub fn verify_file(
        &self,
        binding: &MountBinding,
        version: &FileVersion,
    ) -> Result<(), AccountError> {
        if binding.offline {
            if offline::verify_offline_detached(binding, version)? {
                return Ok(());
            }
            let current =
                self.mount_open_file(&version.instance, binding, &version.path, &version.id)?;
            return if current == *version {
                Ok(())
            } else {
                Err(AccountError::new("offline file representation changed"))
            };
        }
        if version.id.starts_with("cirrus-staged:") {
            // Flush may be triggered by a fork child's close-on-exec while sync
            // owns the account and awaits that child's HTTP bridge. It must not
            // reload credentials, acquire account ownership or attempt recovery.
            if version.instance != binding.instance || version.space != binding.space {
                return Err(AccountError::new("staged file binding changed"));
            }
            offline::verify_identity(&binding.instance, &binding.issuer, &binding.subject)?;
            let current = offline::staged_version(
                &version.instance,
                &version.space,
                &version.path,
                &version.id,
            )?;
            if current.is_none_or(|(current, _)| current != *version) {
                return Err(AccountError::new("file representation changed"));
            }
            return Ok(());
        }
        let current =
            self.mount_open_file(&version.instance, binding, &version.path, &version.id)?;
        if current != *version {
            return Err(AccountError::new("file representation changed"));
        }
        Ok(())
    }

    /// Fetches one bounded range, publishing only a fully validated response.
    ///
    /// # Errors
    /// Returns an error when the version, range, response or account cannot be verified.
    pub fn read_range(
        &self,
        binding: &MountBinding,
        version: &FileVersion,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, AccountError> {
        if length == 0
            || length > 131_072
            || offset
                .checked_add(u64::from(length))
                .is_none_or(|end| end > version.size)
        {
            return Err(AccountError::new("invalid file range"));
        }
        let cache_generation = self.clean_cache_generation();
        if binding.offline {
            self.verify_file(binding, version)?;
            let bytes = self.read_offline_range(binding, version, offset, length)?;
            self.verify_offline_mount(binding)?;
            return Ok(bytes);
        }
        let session = self.read_session(&version.instance)?;
        if bound_space(&session, Some(binding))? != version.space {
            return Err(AccountError::new(
                "file version does not match mounted Space",
            ));
        }
        if version.id.starts_with("cirrus-staged:") {
            let (current, staged) = offline::staged_version(
                &version.instance,
                &version.space,
                &version.path,
                &version.id,
            )?
            .ok_or_else(|| AccountError::new("staged file is unavailable"))?;
            if &current != version {
                return Err(AccountError::new("staged file changed"));
            }
            let snapshot = offline::StagedSnapshot::open(&staged)?;
            if snapshot.len() != version.size {
                return Err(AccountError::new("staged file changed"));
            }
            return snapshot.range_with(offset, length, |base, offset, length| {
                self.read_range(binding, base, offset, length)
            });
        }
        let (_, move_fenced) =
            offline::tree_remote_path(&version.instance, &version.space, &version.path)?;
        if move_fenced {
            return offline::read(version, offset, length);
        }
        let disk_generation = cache::generation().ok();
        if let Ok(Some(bytes)) = cache::read(&session, version, offset, length) {
            self.verify_file(binding, version)?;
            return Ok(bytes);
        }
        if let Some(origin) =
            self.moved_cache_version(version, &session.account.issuer, &session.account.subject)?
            && let Some(bytes) = cache::read(&session, &origin, offset, length)?
        {
            self.verify_file(binding, version)?;
            return Ok(bytes);
        }
        match self.read_range_online(version, Some(binding), offset, length) {
            Ok((bytes, _validated_metadata)) => {
                // Clean caching is an optimization: failures never invalidate a verified read.
                // Keep its actual validation scratch owner/allowance alive
                // through best-effort persistence; don't release paid headroom
                // between verification and the cache's admission decision.
                if let Ok(_guard) = self.clean_cache_update.lock()
                    && cache_generation == self.clean_cache_generation()
                    && let Some(generation) = disk_generation
                {
                    let _ = cache::store(&session, version, offset, &bytes, generation);
                }
                Ok(bytes)
            }
            Err(error) if error.network => {
                offline::read(version, offset, length).map_err(|_| error)
            }
            Err(error) => Err(error),
        }
    }

    // A queued MOVE does not rewrite the separate clean-cache database. Alias
    // only its proven original path, with every other FileVersion field exact.
    fn moved_cache_version(
        &self,
        version: &FileVersion,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<FileVersion>, AccountError> {
        if !offline::tree_destination_contains(
            &version.instance,
            &version.space,
            &version.path,
            i64::MAX,
        )? {
            return Ok(None);
        }
        let (name, parent) = version
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid moved file path"))?;
        let entries = offline::offline_directory(
            &version.instance,
            &version.space,
            parent,
            Some((issuer, subject)),
        )?;
        if !entries.get(name)?.is_some_and(|entry| {
            !entry.is_directory()
                && entry.id() == version.id
                && entry.etag() == Some(version.etag.as_str())
                && entry.size() == Some(version.size)
                && entry.checksums() == version.checksums
        }) {
            return Err(AccountError::new("moved cache version changed"));
        }
        let (path, fenced) =
            offline::tree_remote_path(&version.instance, &version.space, &version.path)?;
        if fenced {
            return Ok(None);
        }
        let mut origin = version.clone();
        origin.path = path;
        Ok(Some(origin))
    }

    fn read_offline_range(
        &self,
        binding: &MountBinding,
        version: &FileVersion,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, AccountError> {
        self.verify_offline_mount(binding)?;
        if version.instance != binding.instance || version.space != binding.space {
            return Err(AccountError::new("offline file binding changed"));
        }
        if version.id.starts_with("cirrus-staged:") {
            let (current, staged) = offline::staged_version(
                &version.instance,
                &version.space,
                &version.path,
                &version.id,
            )?
            .ok_or_else(|| AccountError::new("offline staged file unavailable"))?;
            if current != *version {
                return Err(AccountError::new("offline staged version changed"));
            }
            return offline::StagedSnapshot::open(&staged)?.range_with(
                offset,
                length,
                |base, offset, length| {
                    self.read_original_local_range(
                        &binding.issuer,
                        &binding.subject,
                        base,
                        offset,
                        length,
                    )?
                    .ok_or_else(|| {
                        AccountError::new("exact original content base is unavailable locally")
                    })
                },
            );
        }
        if let Some(bytes) = cache::read_identity(
            &binding.issuer,
            &binding.subject,
            version,
            offset,
            length,
            false,
        )? {
            return Ok(bytes);
        }
        if let Some(origin) =
            self.moved_cache_version(version, &binding.issuer, &binding.subject)?
            && let Some(bytes) = cache::read_identity(
                &binding.issuer,
                &binding.subject,
                &origin,
                offset,
                length,
                false,
            )?
        {
            return Ok(bytes);
        }
        if let Some(bytes) = offline::confirmed_local_range(version, offset, length)? {
            return Ok(bytes);
        }
        if let Some(bytes) = offline::read_moved_local(version, offset, length)? {
            return Ok(bytes);
        }
        offline::read(version, offset, length)
    }

    // Only immutable overlay bases use this route. A projected staged head is
    // not evidence against already verified original bytes, nor permission to
    // fetch a newer remote representation at its pathname.
    fn read_original_local_range(
        &self,
        issuer: &str,
        subject: &str,
        version: &FileVersion,
        offset: u64,
        length: u32,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        offline::verify_identity(&version.instance, issuer, subject)?;
        let original = offline::tree_content_base(version)?;
        for candidate in original
            .iter()
            .filter(|original| *original != version)
            .chain(std::iter::once(version))
        {
            if let Some(bytes) =
                cache::read_identity(issuer, subject, candidate, offset, length, false)?
            {
                return Ok(Some(bytes));
            }
            if let Some(bytes) = offline::confirmed_local_range(candidate, offset, length)? {
                return Ok(Some(bytes));
            }
            if let Some(bytes) = offline::read_moved_local(candidate, offset, length)? {
                return Ok(Some(bytes));
            }
            if let Ok(bytes) = offline::read(candidate, offset, length) {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    fn read_range_online(
        &self,
        version: &FileVersion,
        binding: Option<&MountBinding>,
        offset: u64,
        length: u32,
    ) -> Result<(Vec<u8>, DirectorySnapshot), AccountError> {
        if length == 0 || length > 131_072 || offset >= version.size {
            return Err(AccountError::new("invalid file range"));
        }
        let end = offset
            .checked_add(u64::from(length) - 1)
            .filter(|end| *end < version.size)
            .ok_or_else(|| AccountError::new("invalid file range"))?;
        let _permit = self.read_permit()?;
        let session = self.read_session(&version.instance)?;
        if bound_space(&session, binding)? != version.space {
            return Err(AccountError::new("file version does not match Space"));
        }
        self.read_with_refresh(&session, |current| {
            let (remote_path, move_fenced) =
                offline::tree_remote_path(current.base.as_str(), &version.space, &version.path)?;
            if move_fenced {
                return Err(AccountError::new("directory rename requires attention"));
            }
            let (name, parent) = remote_path
                .split_last()
                .ok_or_else(|| AccountError::new("invalid file path"))?;
            let verify = || {
                let entries = dav::directory_snapshot(
                    &current.base,
                    &version.space,
                    parent,
                    &current.account.access_token,
                    &current.client,
                )?;
                if entries.get(name)?.is_some_and(|entry| {
                    !entry.is_directory()
                        && entry.id() == version.id
                        && entry.etag() == Some(version.etag.as_str())
                        && entry.size() == Some(version.size)
                        && entry.checksums() == version.checksums
                }) {
                    #[cfg(feature = "fault-injection")]
                    if std::env::var_os("CIRRUS_TEST_FILE_METADATA_TRACE").is_some() {
                        eprintln!("cirrus lab indexed range-version lookup");
                    }
                    Ok(entries)
                } else {
                    Err(AccountError::new("file representation changed"))
                }
            };
            drop(verify()?);
            let mut remote_version = version.clone();
            remote_version.path = remote_path.clone();
            let bytes = dav::read_range(
                &current.base,
                &remote_version,
                offset,
                end,
                &current.account.access_token,
                &current.client,
            )?;
            self.check_cancelled()?;
            let validated_metadata = verify()?;
            Ok((bytes, validated_metadata))
        })
    }

    fn read_with_refresh<T>(
        &self,
        session: &ReadSession,
        mut read: impl FnMut(&ReadSession) -> Result<T, AccountError>,
    ) -> Result<T, AccountError> {
        let result = match read(session) {
            Err(error) if error.unauthorized => {
                let renewed = self.refresh_rejected_session(session)?;
                read(&renewed).map_err(|mut error| {
                    // A confirmed 401 must not become an offline-cache fallback.
                    error.network = false;
                    error
                })
            }
            result => result,
        };
        if result.as_ref().is_err_and(|error| !error.network) {
            self.invalidate_mount_metadata();
        }
        result
    }

    fn refresh_rejected_session(
        &self,
        rejected: &ReadSession,
    ) -> Result<ReadSession, AccountError> {
        let guard = if executor::is_automatic() {
            // Yield/back off instead of waiting behind a foreground account
            // owner at this newly released turn boundary.
            executor::preflight_checkpoint()?;
            self.begin_operation()?
        } else {
            let lock = self
                .operation
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            self.operation_with_lock(lock)?
        };
        self.clear_read_session()?;
        let store = Store::open(guard.connection()?)?;
        self.persist_pending(&store, rejected.base.as_str())?;
        let mut account = store.load(rejected.base.as_str())?;
        if account.issuer != rejected.account.issuer
            || account.subject != rejected.account.subject
            || account.selected_space != rejected.account.selected_space
            || account.selected_space != account.selected_space_verified
        {
            return Err(AccountError::new(
                "account or selected Space changed; retry the operation",
            ));
        }
        let client = http::client(account.ca_pem.as_deref().map(str::as_bytes))?;
        if account.access_token == rejected.account.access_token {
            account.expires_at = 0;
        }
        self.check_cancelled()?;
        executor::preflight_checkpoint()?;
        self.refresh_if_needed(&mut account, &store, &client)?;
        self.check_cancelled()?;
        let session = ReadSession {
            base: rejected.base.clone(),
            account,
            client,
        };
        *self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))? =
            Some(session.clone());
        Ok(session)
    }

    fn persist_pending(&self, store: &Store, instance: &str) -> Result<(), AccountError> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?;
        if let Some(account) = pending.get(instance) {
            store.save(account).map_err(|_| {
                AccountError::new("account credentials are awaiting keyring persistence")
            })?;
            pending.remove(instance);
        }
        Ok(())
    }

    fn begin_local_operation(
        &self,
        session: &ReadSession,
        allow_shared_staging: bool,
    ) -> Result<LocalOperation<'_>, AccountError> {
        let active = self
            .sync_staging
            .read()
            .map_err(|_| AccountError::new("account state is unavailable"))?;
        if *active {
            let cached = self
                .read_session
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            let current = cached
                .as_ref()
                .ok_or_else(|| AccountError::new("account session is unavailable"))?;
            if current.base != session.base
                || current.account.issuer != session.account.issuer
                || current.account.subject != session.account.subject
            {
                return Err(AccountError::new("mounted account identity changed"));
            }
            Ok(LocalOperation {
                _sync_window: Some(active),
                _operation: None,
            })
        } else {
            drop(active);
            Ok(LocalOperation {
                _sync_window: None,
                _operation: Some(if allow_shared_staging {
                    self.begin_shared_staging_operation(session)?
                } else {
                    OwnedLocalOperation {
                        _shared: None,
                        _exclusive: Some(self.begin_owned_local_operation(session)?),
                    }
                }),
            })
        }
    }

    fn begin_owned_local_operation(
        &self,
        session: &ReadSession,
    ) -> Result<Operation<'_>, AccountError> {
        let operation = self.begin_operation()?;
        let store = Store::open(operation.connection()?)?;
        self.persist_pending(&store, session.base.as_str())?;
        let account = store.load(session.base.as_str())?;
        offline::bind_identity(session.base.as_str(), &account.issuer, &account.subject)?;
        if account.issuer != session.account.issuer || account.subject != session.account.subject {
            return Err(AccountError::new("mounted account identity changed"));
        }
        Ok(operation)
    }

    fn begin_shared_staging_operation(
        &self,
        session: &ReadSession,
    ) -> Result<OwnedLocalOperation<'_>, AccountError> {
        let (shared, exclusive) = if self.has_pending_credentials()? {
            (None, Some(self.begin_owned_local_operation(session)?))
        } else {
            (Some(ownership::acquire_shared(&self.runtime)?), None)
        };
        let connection = match (&shared, &exclusive) {
            (Some(guard), None) => guard.connection(),
            (None, Some(operation)) => operation.connection()?,
            _ => return Err(AccountError::new("account ownership is unavailable")),
        };
        let store = Store::open(connection)?;
        let account = store.load(session.base.as_str())?;
        offline::bind_identity(session.base.as_str(), &account.issuer, &account.subject)?;
        if account.issuer != session.account.issuer || account.subject != session.account.subject {
            return Err(AccountError::new("mounted account identity changed"));
        }
        Ok(OwnedLocalOperation {
            _shared: shared,
            _exclusive: exclusive,
        })
    }

    fn begin_operation(&self) -> Result<Operation<'_>, AccountError> {
        if self.automatic_active.load(Ordering::Acquire) && !executor::is_automatic() {
            return self.wait_for_automatic_turn();
        }
        let lock = self.operation.try_lock().map_err(|_| {
            AccountError::retryable_read("another account operation is in progress")
        })?;
        self.operation_with_lock(lock)
    }

    fn operation_with_lock<'a>(
        &'a self,
        lock: MutexGuard<'a, ()>,
    ) -> Result<Operation<'a>, AccountError> {
        let mut retained = self
            .pending_guard
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?;
        if let Some(guard) = retained.as_mut() {
            guard.reconnect()?;
        }
        let guard = match retained.take() {
            Some(guard) => guard,
            None => ownership::acquire(&self.runtime)?,
        };
        Ok(Operation {
            accounts: self,
            lock: Some(lock),
            guard: Some(guard),
        })
    }

    fn clear_read_session(&self) -> Result<(), AccountError> {
        *self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))? = None;
        Ok(())
    }

    fn read_permit(&self) -> Result<ReadPermit<'_>, AccountError> {
        let mut active = self
            .reads_in_flight
            .lock()
            .map_err(|_| AccountError::new("read state is unavailable"))?;
        while *active >= 4 {
            let (next, timed) = self
                .read_available
                .wait_timeout(active, Duration::from_secs(15))
                .map_err(|_| AccountError::new("read state is unavailable"))?;
            active = next;
            self.check_cancelled()?;
            if timed.timed_out() && *active >= 4 {
                return Err(AccountError::new("read capacity is unavailable"));
            }
        }
        self.check_cancelled()?;
        *active += 1;
        Ok(ReadPermit(self))
    }

    fn read_session(&self, instance: &str) -> Result<ReadSession, AccountError> {
        self.check_cancelled()?;
        let (base, _) = http::instance_and_ca(instance, None)?;
        let usable = |session: &ReadSession| -> bool {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs());
            session.base == base
                && !session.account.refresh_in_progress
                && now.is_some_and(|now| session.account.expires_at > now.saturating_add(30))
        };
        let lock = loop {
            let cached = self
                .read_session
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            if let Some(session) = cached.as_ref().filter(|session| usable(session)) {
                let session = session.clone();
                drop(cached);
                offline::verify_identity(
                    session.base.as_str(),
                    &session.account.issuer,
                    &session.account.subject,
                )?;
                return Ok(session);
            }
            match self.operation.try_lock() {
                Ok(lock) => {
                    drop(cached);
                    break lock;
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    let (cached, _) = self
                        .session_ready
                        .wait_timeout(cached, Duration::from_secs(1))
                        .map_err(|_| AccountError::new("account state is unavailable"))?;
                    drop(cached);
                    self.check_cancelled()?;
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(AccountError::new("account state is unavailable"));
                }
            }
        };
        let guard = self.operation_with_lock(lock)?;
        let cached = self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?
            .as_ref()
            .filter(|session| usable(session))
            .cloned();
        if let Some(session) = cached {
            offline::verify_identity(
                session.base.as_str(),
                &session.account.issuer,
                &session.account.subject,
            )?;
            return Ok(session);
        }
        let store = Store::open(guard.connection()?)?;
        self.persist_pending(&store, base.as_str())?;
        let mut account = store.load(base.as_str())?;
        if executor::is_automatic() {
            offline::verify_identity(base.as_str(), &account.issuer, &account.subject).map_err(
                |mut error| {
                    error.retryable_read = true;
                    error
                },
            )?;
        } else {
            offline::bind_identity(base.as_str(), &account.issuer, &account.subject)?;
        }
        if account.selected_space.is_some()
            && account.selected_space != account.selected_space_verified
        {
            return Err(AccountError::new(
                "reselect your Space from the signed-in user's listing before accessing it",
            ));
        }
        let client = http::client(account.ca_pem.as_deref().map(str::as_bytes))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AccountError::new("system clock is invalid"))?
            .as_secs();
        // Probe before fencing a rotating refresh token, so an offline read
        // does not leave an otherwise valid account fenced after a lost refresh.
        let offline = !account.refresh_in_progress
            && account.expires_at <= now.saturating_add(30)
            && account.selected_space.as_deref().is_some_and(|space| {
                dav::directory_snapshot(&base, space, &[], &account.access_token, &client)
                    .is_err_and(|error| error.network)
            });
        if !offline {
            self.refresh_if_needed(&mut account, &store, &client)?;
        }
        self.check_cancelled()?;
        let session = ReadSession {
            base,
            account,
            client,
        };
        *self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))? =
            Some(session.clone());
        Ok(session)
    }

    /// Requests cancellation of pending browser and subsequent network work.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Allows new work after a cancelled operation has finished.
    pub fn reset_cancel(&self) {
        self.cancelled.store(false, Ordering::Release);
    }

    /// Reports whether rotated credentials are still awaiting secure persistence.
    ///
    /// # Errors
    /// Returns an error if the account state is unavailable.
    pub fn has_pending_credentials(&self) -> Result<bool, AccountError> {
        Ok(!self
            .pending
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?
            .is_empty())
    }

    fn check_cancelled(&self) -> Result<(), AccountError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(AccountError::new(
                "account operation cancelled by daemon shutdown",
            ));
        }
        Ok(())
    }

    fn save_refresh(&self, store: &Store, account: &AccountData) -> Result<(), AccountError> {
        if store.save(account).is_err() {
            self.pending
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?
                .insert(account.instance.clone(), account.clone());
            return Err(AccountError::new(
                "account credentials are awaiting keyring persistence",
            ));
        }
        Ok(())
    }
}

fn verify_provider(
    config: &Configuration,
    provider: &CoreProviderMetadata,
) -> Result<(), AccountError> {
    if provider.issuer().as_str() != config.issuer()
        || provider.authorization_endpoint().as_str() != config.authorization_endpoint()
        || provider.token_endpoint().map(|url| url.as_str()) != Some(config.token_endpoint())
        || provider.jwks_uri().as_str() != config.jwks_uri()
    {
        return Err(AccountError::new(
            "OpenID provider metadata changed during discovery",
        ));
    }
    Ok(())
}

fn expiry(duration: Option<Duration>) -> Result<u64, AccountError> {
    let seconds = duration
        .ok_or_else(|| AccountError::new("provider omitted token expiry"))?
        .as_secs();
    if seconds == 0 {
        return Err(AccountError::new("provider returned an expired token"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AccountError::new("system clock is invalid"))?
        .as_secs();
    now.checked_add(seconds)
        .ok_or_else(|| AccountError::new("token expiry is invalid"))
}

impl Accounts {
    fn account_spaces(
        &self,
        base: &Url,
        account: &mut AccountData,
        store: &Store,
        client: &reqwest::blocking::Client,
    ) -> Result<Vec<Space>, AccountError> {
        let result = list_spaces(base, &account.access_token, client, &self.cancelled);
        if !result.as_ref().is_err_and(|error| error.unauthorized) {
            return result;
        }
        // The caller holds the account guard, so only one process can rotate this token.
        account.expires_at = 0;
        self.refresh_if_needed(account, store, client)?;
        list_spaces(base, &account.access_token, client, &self.cancelled)
    }

    fn refresh_if_needed(
        &self,
        account: &mut AccountData,
        store: &Store,
        client: &reqwest::blocking::Client,
    ) -> Result<(), AccountError> {
        if account.refresh_in_progress {
            return Err(AccountError::new(
                "previous token refresh was interrupted; reconnect the account",
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AccountError::new("system clock is invalid"))?
            .as_secs();
        if account.expires_at > now.saturating_add(30) {
            return Ok(());
        }
        if executor::is_automatic() {
            // Do not strand a rotating-token fence merely because the service
            // started offline. A real HTTP challenge may require refresh; a
            // failed read must yield before any refresh-token request/marker.
            let base = Url::parse(&account.instance)
                .map_err(|_| AccountError::new("stored instance is invalid"))?;
            match list_spaces(&base, &account.access_token, client, &self.cancelled) {
                Ok(_) => {}
                Err(error) if error.unauthorized => {}
                Err(error) => return Err(error),
            }
        }
        let issuer = Url::parse(&account.issuer)
            .map_err(|_| AccountError::new("stored issuer is invalid"))?;
        let token = Url::parse(&account.token_endpoint)
            .map_err(|_| AccountError::new("stored token endpoint is invalid"))?;
        if issuer.scheme() != "https"
            || token.origin() != issuer.origin()
            || token.scheme() != "https"
            || token.username() != ""
            || token.password().is_some()
            || token.fragment().is_some()
        {
            return Err(AccountError::new("stored token endpoint is untrusted"));
        }
        let transport = http::Transport::from_client(client.clone(), issuer);
        let oauth = oauth2::basic::BasicClient::new(ClientId::new(account.client_id.clone()))
            .set_auth_type(AuthType::RequestBody)
            .set_token_uri(
                openidconnect::TokenUrl::new(account.token_endpoint.clone())
                    .map_err(|_| AccountError::new("stored token endpoint is invalid"))?,
            );
        // Persist the fence before sending a potentially rotating refresh token.
        // A lost response or dead daemon must not lead another process to reuse it.
        account.refresh_in_progress = true;
        if store.save(account).is_err() {
            account.refresh_in_progress = false;
            self.save_refresh(store, account)?;
            return Err(AccountError::new("cannot prepare token refresh in keyring"));
        }
        let response = oauth
            .exchange_refresh_token(&openidconnect::RefreshToken::new(
                account.refresh_token.clone(),
            ))
            .request(&|request| transport.call(request))
            .map_err(|_| AccountError::new("token refresh failed; reconnect the account"))?;
        account.refresh_in_progress = false;
        if let Some(token) = response.refresh_token() {
            account.refresh_token = token.secret().to_owned();
        }
        let valid_expiry = expiry(response.expires_in());
        if response.token_type() != &CoreTokenType::Bearer || valid_expiry.is_err() {
            account.expires_at = 0;
            self.save_refresh(store, account)?;
            return Err(AccountError::new(
                "refresh returned an unusable access token; retry or reconnect",
            ));
        }
        account.access_token = response.access_token().secret().to_owned();
        account.expires_at = valid_expiry?;
        self.save_refresh(store, account)
    }
}

#[derive(Deserialize)]
struct SpacePage {
    value: Vec<SpaceRow>,
    #[serde(rename = "@odata.nextLink")]
    next: Option<String>,
}
#[derive(Deserialize)]
struct SpaceRow {
    id: String,
    name: String,
    #[serde(default)]
    root: Option<SpaceRoot>,
}

#[derive(Deserialize)]
struct SpaceRoot {
    #[serde(default)]
    deleted: Option<serde::de::IgnoredAny>,
}

fn list_spaces(
    base: &Url,
    access_token: &str,
    client: &reqwest::blocking::Client,
    cancelled: &AtomicBool,
) -> Result<Vec<Space>, AccountError> {
    let mut url = base
        .join("/graph/v1.0/me/drives")
        .map_err(|_| AccountError::new("invalid OpenCloud instance"))?;
    let mut spaces: Vec<Space> = Vec::new();
    for page in 0..32 {
        executor::preflight_checkpoint()?;
        if cancelled.load(Ordering::Acquire) {
            return Err(AccountError::new(
                "account operation cancelled by daemon shutdown",
            ));
        }
        let response = http::space_page(client, &url, access_token, page, cancelled)?;
        let page: SpacePage = http::json(response)?;
        for row in page.value {
            // OpenCloud retains trashed drives in Graph listings. Presence of
            // an ID is not live Space membership/dispatch authority.
            if row.root.is_some_and(|root| root.deleted.is_some()) {
                continue;
            }
            if row.id.is_empty()
                || row.name.is_empty()
                || row.id.chars().any(char::is_control)
                || row.name.chars().any(char::is_control)
                || spaces.iter().any(|space| space.id == row.id)
            {
                return Err(AccountError::new("Space listing contains invalid fields"));
            }
            spaces.push(Space {
                id: row.id,
                name: row.name,
            });
            if spaces.len() > 1024 {
                return Err(AccountError::new("Space listing exceeds the limit"));
            }
        }
        let Some(next) = page.next else {
            return Ok(spaces);
        };
        url = url
            .join(&next)
            .map_err(|_| AccountError::new("invalid Space pagination link"))?;
        if url.scheme() != "https"
            || url.origin() != base.origin()
            || url.path() != "/graph/v1.0/me/drives"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(AccountError::new("untrusted Space pagination link"));
        }
    }
    Err(AccountError::new("Space listing exceeds the page limit"))
}

/// A safe-to-display account failure; token values and response bodies are omitted.
#[derive(Debug)]
pub struct AccountError {
    message: &'static str,
    network: bool,
    upload_uncertain: bool,
    unauthorized: bool,
    dav_properties: Option<(u16, Vec<&'static str>)>,
    yielded: bool,
    retryable_read: bool,
    storage_busy: bool,
}
impl AccountError {
    /// Whether a namespace create found an existing entry or unresolved target.
    pub fn is_entry_exists(&self) -> bool {
        self.message == "namespace target already exists"
    }

    /// Whether local staging or offline storage exhausted its capacity.
    pub fn is_staging_full(&self) -> bool {
        matches!(
            self.message,
            "staging capacity exhausted"
                | "local storage capacity exhausted"
                | "configured storage pressure limit reached"
                | "configured storage pressure changed after allocation; candidate retained"
        )
    }

    /// Whether account coordination or an unresolved operation is busy.
    pub fn is_operation_busy(&self) -> bool {
        matches!(
            self.message,
            "another account operation is in progress"
                | "path has unresolved operations"
                | "rename target has unresolved operations"
                | "rename would displace or split a pin"
        )
    }

    /// Whether a directory removal encountered locally staged descendants.
    pub fn is_directory_not_empty(&self) -> bool {
        self.message == "directory contains unresolved local content"
    }

    /// Whether a read-only metadata observation was superseded locally.
    pub fn is_metadata_changed(&self) -> bool {
        self.message == "directory metadata changed concurrently; retry"
    }

    fn new(message: &'static str) -> Self {
        Self {
            message,
            network: false,
            upload_uncertain: false,
            unauthorized: false,
            dav_properties: None,
            yielded: false,
            retryable_read: false,
            storage_busy: false,
        }
    }

    fn dav_properties(status: u16, properties: Vec<&'static str>) -> Self {
        let mut error = Self::new(if status == 425 {
            "directory metadata is temporarily unavailable"
        } else {
            "directory property request failed"
        });
        error.dav_properties = Some((status, properties));
        error
    }

    fn unauthorized() -> Self {
        Self {
            message: "server rejected the account session; reconnect to sign in",
            network: false,
            upload_uncertain: false,
            unauthorized: true,
            dav_properties: None,
            yielded: false,
            retryable_read: false,
            storage_busy: false,
        }
    }
    fn request(message: &'static str, error: &reqwest::Error) -> Self {
        let mut source: Option<&(dyn Error + 'static)> = Some(error);
        let mut connection_failure = false;
        while let Some(cause) = source {
            if let Some(io) = cause.downcast_ref::<std::io::Error>() {
                connection_failure |= matches!(
                    io.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::NetworkUnreachable
                        | std::io::ErrorKind::HostUnreachable
                        | std::io::ErrorKind::TimedOut
                );
            }
            source = cause.source();
        }
        Self {
            message,
            network: connection_failure || error.is_timeout(),
            upload_uncertain: false,
            unauthorized: false,
            dav_properties: None,
            yielded: false,
            retryable_read: false,
            storage_busy: false,
        }
    }

    fn uncertain_upload(error: &reqwest::Error) -> Self {
        let mut failure = Self::request("upload result is uncertain", error);
        failure.upload_uncertain = true;
        failure
    }

    fn yielded() -> Self {
        let mut error = Self::new("transfer turn yielded before the next request");
        error.yielded = true;
        error
    }

    fn retryable_read(message: &'static str) -> Self {
        let mut error = Self::new(message);
        error.retryable_read = true;
        error
    }

    fn can_retry_read(&self) -> bool {
        self.network
            || self.retryable_read
            || self
                .dav_properties
                .as_ref()
                .is_some_and(|(status, _)| matches!(status, 408 | 425 | 429 | 503))
    }
}
impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)?;
        if let Some((status, properties)) = &self.dav_properties {
            write!(f, " (DAV status {status}; properties: ")?;
            if properties.is_empty() {
                f.write_str("none recognized")?;
            } else {
                f.write_str(&properties.join(", "))?;
            }
            f.write_str(")")?;
        }
        Ok(())
    }
}
impl Error for AccountError {}

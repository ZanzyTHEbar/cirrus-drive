//! Browser-based OpenID account connection and read-only Space discovery.

mod account_storage;
mod browser;
mod cache;
mod callback;
mod dav;
mod executor;
mod http;
mod offline;
mod operation_result;
mod ownership;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod provider_catalog;
pub mod provider_mutation;
mod recovery;
mod secrets;
mod sqlite_open;
mod storage;
mod sync;
mod upload;

#[cfg(target_os = "macos")]
mod native_bridge;

#[cfg(all(test, target_os = "macos"))]
mod native_storage_acceptance;

#[cfg(all(test, target_os = "linux"))]
mod mount_start_tests;

#[cfg(all(test, target_os = "linux", feature = "fault-injection"))]
mod provider_reconciliation_acceptance;

#[cfg(all(test, target_os = "linux"))]
mod retained_import_acceptance;

#[cfg(test)]
mod sign_in_acceptance;

pub use storage::{
    NamespaceStorageReservation, SqlStorageReservation, StorageLimits, StorageLimitsView,
    StorageStatus, StorageUsage,
};

#[cfg(target_os = "linux")]
pub use account_storage::StorageRoot;

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
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

#[doc(hidden)]
pub use browser::BrowserRequest;
pub use browser::{Browser, PortalBrowser};
pub use dav::Entry;
mod directory;
pub use directory::DirectorySnapshot;
use secrets::{AccountData, Store, StoredAccount};

#[cfg(target_os = "macos")]
impl From<secrets::CredentialError> for AccountError {
    fn from(error: secrets::CredentialError) -> Self {
        if error.retryable && executor::is_automatic() {
            Self::retryable_read(error.message)
        } else {
            Self::new(error.message)
        }
    }
}
pub use operation_result::{OperationHandle, OperationResult};
pub use sync::{ForegroundPriority, SchedulerGuard, SyncPhase, SyncStatus};
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

pub use cirrus_api::{CleanCacheStatus, JournalEntry, JournalPage, JournalState, JournalSummary};
use cirrus_api::{
    PinAvailability, PinInfo, PinRemoteEvidence, RetainedPage, RetainedPin, RetainedPinCopy,
    RetainedPinCopyEntry, RetainedPinFile, RetainedStaged,
};

/// A mount's account and Space binding, verified online or from retained activation.
#[derive(Clone)]
pub struct MountBinding {
    root: account_storage::StorageRoot,
    instance: String,
    space: String,
    name: Option<String>,
    issuer: String,
    subject: String,
    offline: bool,
    offline_writable: bool,
}

/// Startup work remaining for an explicit mount; both outcomes use a normal RW binding.
#[derive(Clone, Copy, Debug)]
pub enum MountStartup {
    /// Preflight the live binding and activate synchronization after mounting.
    Normal,
    /// Retained root preflight is complete; leave the existing activation alone.
    Resumed,
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
    storage: account_storage::StorageSelection,
    runtime: RuntimeDir,
    #[cfg(target_os = "macos")]
    keychain: Option<ownership::credentials::KeychainConfig>,
    credentials: Mutex<CredentialState>,
    operation: Mutex<()>,
    cancelled: Arc<AtomicBool>,
    read_session: Mutex<Option<Arc<ReadSession>>>,
    session_ready: Condvar,
    reads_in_flight: Mutex<usize>,
    read_available: Condvar,
    metadata_generation: AtomicU64,
    clean_cache_generation: AtomicU64,
    clean_cache_update: Mutex<()>,
    sync_staging: RwLock<Option<Arc<ReadSession>>>,
    read_ahead_active: AtomicBool,
    active_writes: Mutex<HashSet<(account_storage::RootIdentity, i64)>>,
    background_admission: Arc<sync::BackgroundAdmission>,
    // Live policy scopes, not account/transfer ownership.
    automatic_active: Arc<AtomicUsize>,
}

/// Cancellation fence for one browser sign-in attempt.
#[derive(Debug, Default)]
pub struct SignIn {
    phase: AtomicU8,
}

#[repr(u8)]
enum SignInPhase {
    Pending = 0,
    Finishing = 1,
    Cancelled = 2,
}

impl SignIn {
    /// Cancels the attempt before token exchange starts.
    pub fn cancel(&self) -> Result<(), AccountError> {
        if self.cancel_pending() {
            Ok(())
        } else {
            Err(AccountError::new(
                "sign-in is finishing; wait for its result",
            ))
        }
    }

    // Typed private result for the native adapter; never parse Display text.
    fn cancel_pending(&self) -> bool {
        match self.phase.compare_exchange(
            SignInPhase::Pending as u8,
            SignInPhase::Cancelled as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => true,
            Err(phase) => phase == SignInPhase::Cancelled as u8,
        }
    }

    fn is_cancelled(&self) -> bool {
        self.phase.load(Ordering::Acquire) == SignInPhase::Cancelled as u8
    }

    fn check(&self) -> Result<(), AccountError> {
        if self.is_cancelled() {
            Err(AccountError::new("sign-in cancelled; you can try again"))
        } else {
            Ok(())
        }
    }

    fn begin_exchange(&self) -> Result<(), AccountError> {
        match self.phase.compare_exchange(
            SignInPhase::Pending as u8,
            SignInPhase::Finishing as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(phase) if phase == SignInPhase::Finishing as u8 => Ok(()),
            Err(_) => Err(AccountError::new("sign-in cancelled; you can try again")),
        }
    }
}

#[derive(Clone)]
struct ReadSession {
    root: account_storage::StorageRoot,
    base: Url,
    account: AccountData,
    client: reqwest::blocking::Client,
}

#[derive(Clone, Copy)]
enum SessionAccess<'a> {
    Online,
    BoundOnline(&'a MountBinding),
    BoundSaved(&'a MountBinding),
}

impl<'a> SessionAccess<'a> {
    fn for_space(binding: &'a MountBinding, allow_saved: bool) -> Self {
        if allow_saved {
            Self::BoundSaved(binding)
        } else {
            Self::BoundOnline(binding)
        }
    }

    fn check(
        self,
        root: &account_storage::StorageRoot,
        base: &Url,
        account: &AccountData,
    ) -> Result<(), AccountError> {
        match self {
            Self::Online => Ok(()),
            Self::BoundOnline(binding) | Self::BoundSaved(binding) => {
                check_bound_account(root, base, account, binding)
            }
        }
    }
}

enum CredentialState {
    Idle,
    Active(HashMap<String, AccountData>),
    Retained {
        pending: HashMap<String, AccountData>,
        guard: ownership::Guard,
    },
}

fn check_bound_account(
    root: &account_storage::StorageRoot,
    base: &Url,
    account: &AccountData,
    binding: &MountBinding,
) -> Result<(), AccountError> {
    if binding.root.identity() != root.identity() {
        return Err(AccountError::new("mount storage root changed"));
    }
    if binding.offline {
        return Err(AccountError::new(
            "offline mount is read-only and cannot authenticate",
        ));
    }
    if binding.instance != base.as_str()
        || binding.issuer != account.issuer
        || binding.subject != account.subject
    {
        return Err(AccountError::new("mounted account identity changed"));
    }
    Ok(())
}

fn bound_space<'a>(
    session: &ReadSession,
    binding: &'a MountBinding,
) -> Result<&'a str, AccountError> {
    check_bound_account(&session.root, &session.base, &session.account, binding)?;
    Ok(&binding.space)
}

enum DirectorySnapshotPublication {
    Cli,
    Mount,
    NonTurnSync,
}

enum DirectoryAccess<'a> {
    Cli(&'a MountBinding),
    Mount(&'a MountBinding, &'a str),
}

fn check_stage_file_path(path: &[String]) -> Result<(), AccountError> {
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
    Ok(())
}

fn accept_directory_snapshot_save(
    saved: Result<bool, AccountError>,
    publication: DirectorySnapshotPublication,
    session: &ReadSession,
    space: &str,
    path: &[String],
    entries: &DirectorySnapshot,
) -> Result<(), AccountError> {
    use DirectorySnapshotPublication::{Mount, NonTurnSync};

    const STALE: &str = "directory metadata changed concurrently; retry";
    let rejection = match (&publication, saved) {
        (_, Ok(true)) => return Ok(()),
        (NonTurnSync, Ok(false)) => AccountError::retryable_read(STALE),
        (_, Ok(false)) => AccountError::new(STALE),
        (Mount | NonTurnSync, Err(error)) if error.storage_busy => error,
        (_, Err(error)) => return Err(error),
    };
    // A stale observation or an optional copy blocked by a peer can keep the
    // validated online result only if durable metadata proves it is compatible.
    if !offline::directory_copy_compatible(
        session.base.as_str(),
        space,
        path,
        entries,
        &session.account.issuer,
        &session.account.subject,
    )? {
        return Err(rejection);
    }
    #[cfg(feature = "fault-injection")]
    if rejection.storage_busy
        && matches!(publication, NonTurnSync)
        && std::env::var_os("CIRRUS_TEST_NAMESPACE_TRACE").is_some()
    {
        eprintln!("cirrus lab manual snapshot cache skipped: State lease busy path={path:?}");
    }
    Ok(())
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
    // Admission and the account owner move together until explicit drain.
    _staging: Option<SyncStaging<'a>>,
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
    root: account_storage::StorageRoot,
}

impl PreparedRemoteTree<'_> {
    /// Atomically journals the prepared tree move and returns rebased open versions.
    ///
    /// # Errors
    /// Returns an error if the durable journal no longer permits the move.
    pub fn commit(self) -> Result<Vec<FileVersion>, AccountError> {
        self.commit_operation().map(|(versions, _)| versions)
    }

    /// Journals the move and captures its exact operation in the same transaction.
    ///
    /// # Errors
    /// Refuses changed namespace, parent, pin protection or storage admission.
    pub fn commit_operation(self) -> Result<(Vec<FileVersion>, OperationHandle), AccountError> {
        self.commit_inner(None)
    }

    pub(crate) fn commit_provider(
        self,
        record: &provider_mutation::Record,
    ) -> Result<(Vec<FileVersion>, OperationHandle), AccountError> {
        self.commit_inner(Some(record))
    }

    fn commit_inner(
        mut self,
        record: Option<&provider_mutation::Record>,
    ) -> Result<(Vec<FileVersion>, OperationHandle), AccountError> {
        // Finish admitted local writers before capturing originals. Keep the
        // exclusive account owner until the namespace transaction completes.
        let _operation = self._staging.take().map(SyncStaging::finish);
        offline::protect_moving_pin_originals(
            &self.root,
            &self.instance,
            &self.space,
            self.source,
            self.destination,
            &self.cancelled,
        )?;
        let _turn = self
            .offline
            .as_ref()
            .map(|_| ownership::local_state_turn_in(&self.root, Arc::clone(&self.cancelled)))
            .transpose()?;
        let mut attempts = 0;
        let operation = loop {
            let result = offline::queue_tree_move_correlated(
                &self.root,
                offline::TreeMoveRequest {
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
                },
                record,
            );
            if self.offline.is_some()
                && attempts < 7
                && result
                    .as_ref()
                    .is_err_and(|error| error.is_metadata_changed())
            {
                attempts += 1;
                continue;
            }
            break result?;
        };
        Ok((self.relocated, operation))
    }
}

/// A verified empty-directory move holding account ownership until it is committed.
pub struct PreparedEmptyDirectory<'a> {
    // Owns both staging admission and the original exclusive account guard.
    _staging: SyncStaging<'a>,
    instance: String,
    space: String,
    source: &'a [String],
    destination: &'a [String],
    base: (&'a str, &'a str),
    parents: RenameParents<'a>,
    cancelled: Arc<AtomicBool>,
    root: account_storage::StorageRoot,
}

impl PreparedEmptyDirectory<'_> {
    /// Atomically journals the prepared empty-directory move.
    ///
    /// # Errors
    /// Returns an error if the durable journal no longer permits the move.
    pub fn commit(self) -> Result<i64, AccountError> {
        let _operation = self._staging.finish();
        offline::protect_moving_pin_originals(
            &self.root,
            &self.instance,
            &self.space,
            self.source,
            self.destination,
            &self.cancelled,
        )?;
        offline::queue_empty_directory_move(
            &self.root,
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

// Drop admission before the owned account operation, including early returns.
struct SyncStaging<'a> {
    window: StagingWindow<'a>,
    operation: Operation<'a>,
}

struct StagingWindow<'a>(&'a Accounts);

impl<'a> SyncStaging<'a> {
    fn finish(self) -> Operation<'a> {
        drop(self.window);
        self.operation
    }
}

enum LocalOperation<'a> {
    Staging {
        _lease: RwLockReadGuard<'a, Option<Arc<ReadSession>>>,
    },
    Owned {
        _operation: OwnedLocalOperation<'a>,
    },
}

/// A verified file rename with journal-only or exclusive publication ownership.
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
    runtime: &'a RuntimeDir,
    online: Option<Arc<ReadSession>>,
    local_observation: Option<[String; 2]>,
    root: account_storage::StorageRoot,
}

impl PreparedFileRename<'_> {
    /// Atomically journals the prepared file rename.
    ///
    /// # Errors
    /// Returns an error if either staged version or its parents changed.
    pub fn commit(mut self) -> Result<(FileVersion, Option<FileVersion>), AccountError> {
        // A pristine same-parent create changes only its journal path. Retain
        // the prepared principal owner through classification and publication;
        // ineligible transformations still take the original fresh EX fence.
        if let (Some(session), Some(observation)) = (&self.online, &self.local_observation) {
            match offline::rename_pristine_local_write(
                session,
                self.source,
                self.destination,
                self.parents,
                observation,
                &self.cancelled,
            )? {
                offline::LocalRename::Renamed(version) => {
                    #[cfg(feature = "fault-injection")]
                    if std::env::var_os("CIRRUS_TEST_FILE_RENAME_ADMISSION_TRACE").is_some() {
                        eprintln!(
                            "cirrus lab file rename admission: pid={} thread={:?} boundary=commit-local-renamed",
                            std::process::id(),
                            std::thread::current().id()
                        );
                    }
                    return Ok((version, None));
                }
                offline::LocalRename::NeedsExclusive => {}
            }
        }
        // Online preparation permits unrelated writers during DAV. Release
        // its shared owner before taking a fresh exclusive publication fence;
        // never upgrade a shared lease in place. The transaction below still
        // revalidates the exact prepared versions and parent dependencies.
        let _owner = if let Some(session) = &self.online {
            drop(self._guard.take());
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_FILE_RENAME_ADMISSION_TRACE").is_some() {
                eprintln!(
                    "cirrus lab file rename admission: pid={} thread={:?} boundary=commit-exclusive-request",
                    std::process::id(),
                    std::thread::current().id()
                );
            }
            let owner = ownership::acquire_offline_exclusive_in(&self.root, self.runtime)?;
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_FILE_RENAME_ADMISSION_TRACE").is_some() {
                eprintln!(
                    "cirrus lab file rename admission: pid={} thread={:?} boundary=commit-exclusive-acquired",
                    std::process::id(),
                    std::thread::current().id()
                );
            }
            offline::verify_identity_in(
                &session.root,
                &self.source.instance,
                &session.account.issuer,
                &session.account.subject,
            )?;
            offline::protect_moving_pin_originals(
                &self.root,
                &self.source.instance,
                &self.source.space,
                &self.source.path,
                self.destination,
                &self.cancelled,
            )?;
            // Preserve the previous optional cache retention only AFTER pin
            // agreement. It cannot promote an arbitrary conflicting owner
            // ahead of the protection-specific all-owner comparison.
            for version in std::iter::once(self.source).chain(self.pending_target) {
                let (_, name) = offline::staged_version(
                    &session.root,
                    &version.instance,
                    &version.space,
                    &version.path,
                    &version.id,
                )?
                .filter(|(current, _)| current == version)
                .ok_or_else(|| AccountError::new("rename snapshot changed"))?;
                offline::overlay::Overlay::load_at(&self.root, &name)?.retain_available(
                    |base, offset, length| {
                        cache::read(session, base, offset, length)
                            .ok()
                            .flatten()
                            .or_else(|| offline::read(&session.root, base, offset, length).ok())
                    },
                )?;
            }
            Some(owner)
        } else {
            None
        };
        let _state_turn = self
            .offline
            .as_ref()
            .map(|_| ownership::local_state_turn_in(&self.root, Arc::clone(&self.cancelled)))
            .transpose()?;
        let mut retries = 0;
        loop {
            let result = if let Some(target) = self.pending_target {
                offline::replace_pending_write(
                    &self.root,
                    self.source,
                    target,
                    self.parents.source,
                    self.parents.destination,
                    self.offline.as_ref(),
                )
            } else {
                offline::rename_staged_write(
                    &self.root,
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

enum OwnedLocalOperation<'a> {
    Shared(ownership::Guard),
    Exclusive(Operation<'a>),
}

struct ActiveWrite<'a> {
    accounts: &'a Accounts,
    root: account_storage::StorageRoot,
    id: i64,
}

enum ConflictCopyOutcome {
    ParentChanged,
    Recorded,
}

impl Drop for ActiveWrite<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.accounts.active_writes.lock() {
            active.remove(&(self.root.identity(), self.id));
        }
    }
}

impl Drop for StagingWindow<'_> {
    fn drop(&mut self) {
        let retired = self
            .0
            .sync_staging
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(retired);
    }
}

impl<'a> Operation<'a> {
    fn storage_root(&self) -> Result<&account_storage::StorageRoot, AccountError> {
        self.guard
            .as_ref()
            .map(ownership::Guard::storage_root)
            .ok_or_else(|| AccountError::new("account ownership is unavailable"))
    }
    fn credential_context(&self) -> Result<&ownership::credentials::Context, AccountError> {
        self.guard
            .as_ref()
            .map(ownership::Guard::credential_context)
            .ok_or_else(|| AccountError::new("account ownership is unavailable"))
    }

    fn begin_staging(self, session: Arc<ReadSession>) -> Result<SyncStaging<'a>, AccountError> {
        if self.storage_root()?.identity() != session.root.identity() {
            return Err(AccountError::new("account session storage root changed"));
        }
        let mut active = self
            .accounts
            .sync_staging
            .write()
            .map_err(|_| AccountError::new("account state is unavailable"))?;
        if active.is_some() {
            return Err(AccountError::new("account staging is already active"));
        }
        *active = Some(session);
        drop(active);
        Ok(SyncStaging {
            window: StagingWindow(self.accounts),
            operation: self,
        })
    }

    fn persist_pending(&self, store: &Store, instance: &str) -> Result<(), AccountError> {
        let account = {
            let credentials = self
                .accounts
                .credentials
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            let CredentialState::Active(pending) = &*credentials else {
                return Err(AccountError::new("account ownership is unavailable"));
            };
            pending.get(instance).cloned()
        };
        if let Some(account) = account {
            store.save(&account).map_err(|_| {
                AccountError::new("account credentials are awaiting keyring persistence")
            })?;
            let mut credentials = self
                .accounts
                .credentials
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            let CredentialState::Active(pending) = &mut *credentials else {
                return Err(AccountError::new("account ownership is unavailable"));
            };
            if pending.get(instance) == Some(&account) {
                pending.remove(instance);
            }
        }
        Ok(())
    }
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            let released = {
                // Drop must retain unsaved credentials and their writer fence,
                // even when unwinding poisoned this state mutex.
                let mut credentials = self
                    .accounts
                    .credentials
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match std::mem::replace(&mut *credentials, CredentialState::Idle) {
                    CredentialState::Active(pending) if !pending.is_empty() => {
                        *credentials = CredentialState::Retained { pending, guard };
                        None
                    }
                    CredentialState::Active(_) => Some(guard),
                    previous => {
                        *credentials = previous;
                        Some(guard)
                    }
                }
            };
            drop(released);
        }
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
    /// Creates an account boundary using one previously admitted storage root.
    ///
    /// Does not access credentials or the network. Filesystem operations retain
    /// this capability through deferred work and cleanup. Credentials remain in
    /// the canonical account namespace, shared across storage roots.
    #[cfg(target_os = "linux")]
    pub fn with_storage(runtime: RuntimeDir, root: StorageRoot) -> Self {
        let mut accounts = Self::new(runtime);
        accounts.storage = account_storage::StorageSelection::Explicit(root);
        accounts
    }

    /// Creates an account boundary without accessing the keyring or network.
    pub fn new(runtime: RuntimeDir) -> Self {
        Self {
            storage: account_storage::StorageSelection::Default,
            runtime,
            #[cfg(target_os = "macos")]
            keychain: None,
            credentials: Mutex::new(CredentialState::Idle),
            operation: Mutex::new(()),
            cancelled: Arc::new(AtomicBool::new(false)),
            read_session: Mutex::new(None),
            session_ready: Condvar::new(),
            reads_in_flight: Mutex::new(0),
            read_available: Condvar::new(),
            metadata_generation: AtomicU64::new(0),
            clean_cache_generation: AtomicU64::new(0),
            clean_cache_update: Mutex::new(()),
            sync_staging: RwLock::new(None),
            read_ahead_active: AtomicBool::new(false),
            active_writes: Mutex::new(HashSet::new()),
            background_admission: Arc::new(sync::BackgroundAdmission::default()),
            automatic_active: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Canonicalizes an instance URL without accessing the network.
    ///
    /// # Errors
    /// Returns an error if the instance URL is unsafe or invalid.
    pub fn canonical_instance(instance: &str) -> Result<String, AccountError> {
        http::instance_and_ca(instance, None).map(|(base, _)| base.to_string())
    }

    /// Creates a native account boundary with an explicit Keychain access group.
    ///
    /// The containing app and extension must hold matching entitlements. This
    /// group is separate from filesystem App Group configuration. All Keychain
    /// access is noninteractive, including manual operations. `new` remains
    /// usable for offline work on macOS, but refuses credential access without
    /// this configuration. Construction performs no Keychain or network I/O.
    ///
    /// # Errors
    /// Rejects an empty or malformed group; OS entitlement checks occur on use.
    #[cfg(target_os = "macos")]
    pub fn with_keychain(runtime: RuntimeDir, access_group: &str) -> Result<Self, AccountError> {
        let config = ownership::credentials::KeychainConfig::new(access_group)?;
        let mut accounts = Self::new(runtime);
        accounts.keychain = Some(config);
        Ok(accounts)
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
        cache::status_in(&self.storage_root()?)
    }

    /// Observes all local stores without credentials, network or account-operation ownership.
    ///
    /// # Errors
    /// Returns an error for unsafe paths, unavailable metadata/SQLite, overflow or scan limits.
    pub fn storage_status(&self) -> Result<StorageStatus, AccountError> {
        storage::status_in(&self.storage_root()?)
    }

    /// Reads shared opt-in allocation-pressure policy without credentials/network.
    ///
    /// # Errors
    /// Returns an error for invalid or unsafe private configuration.
    pub fn storage_limits(&self) -> Result<StorageLimitsView, AccountError> {
        storage::limits::view_in(&self.storage_root()?)
    }

    /// Persists user-chosen limits, or disables them, without deleting protected data.
    ///
    /// # Errors
    /// Returns an error for invalid bytes, unsafe paths or failed persistence.
    pub fn configure_storage_limits(
        &self,
        limits: Option<StorageLimits>,
    ) -> Result<StorageLimitsView, AccountError> {
        storage::limits::validate(&limits)?;
        storage::limits::set_in(&self.storage_root()?, limits)
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
        storage::sql_reservation::release_in(&self.storage_root()?, store, token)
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

    /// Evicts clean ranges under an explicit retained Space path without credentials or network.
    /// Leaves pins and staged edits intact; does not assert current remote authorization.
    ///
    /// # Errors
    /// Refuses missing or mismatched retained identity, an unproven Space, or an unsafe cache.
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
        let instance = Self::canonical_instance(instance)?;
        let root = self.storage_root()?;
        self.check_cancelled()?;
        let _guard = self
            .clean_cache_update
            .lock()
            .map_err(|_| AccountError::new("cache is unavailable"))?;
        cache::evict_in(&root, &instance, space, path)?;
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
        let store = Store::open(_guard.credential_context()?)?;
        let (base, ca) = http::instance_and_ca(instance, ca_pem)?;
        _guard.persist_pending(&store, base.as_str())?;
        // A recognized legacy item supplies identity, not usable tokens.
        // Ambiguous items and credential-store failures still abort before OAuth.
        let mut existing = store.load_for_sign_in(base.as_str())?;
        if let Some(StoredAccount::Current(account)) = &existing {
            offline::bind_identity_in(
                _guard.storage_root()?,
                base.as_str(),
                &account.issuer,
                &account.subject,
            )?;
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
        let deadline = std::time::Instant::now() + callback::CALLBACK_TIMEOUT;
        let mut browser_request = browser
            .open_for_sign_in(url.as_str(), attempt, &self.cancelled, deadline)
            .map_err(|_| AccountError::new("desktop browser could not open authorization"))?;
        let deadline = browser_request.deadline();
        let code = listener.wait_for_browser(
            state.secret(),
            config.issuer(),
            config.callback_issuer_required(),
            &self.cancelled,
            attempt,
            &mut browser_request,
            deadline,
        )?;
        self.check_cancelled()?;
        attempt.begin_exchange()?;
        if let Some(StoredAccount::Current(account)) = existing.as_mut() {
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
        if let Some(old) = &existing {
            old.verify_identity(config.issuer(), claims.subject().as_str())
                .map_err(AccountError::new)?;
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
        };
        offline::bind_identity_in(
            _guard.storage_root()?,
            base.as_str(),
            &account.issuer,
            &account.subject,
        )?;
        if let Some(StoredAccount::Legacy(previous)) = existing {
            // No old usable token was rotated. Leave the item intact on failure;
            // a later explicit sign-in must recheck it rather than queue a write.
            store.replace_legacy(&account, &previous)?;
        } else {
            self.save_refresh(&store, &account)?;
        }
        Ok(())
    }

    /// Lists Spaces using the saved account, refreshing its token when required.
    ///
    /// # Errors
    /// Returns an error for missing or locked secrets, refresh failures, or incomplete listings.
    pub fn spaces(&self, instance: &str) -> Result<Vec<Space>, AccountError> {
        let _guard = self.begin_operation()?;
        self.clear_read_session()?;
        let store = Store::open(_guard.credential_context()?)?;
        let (base, _) = http::instance_and_ca(instance, None)?;
        _guard.persist_pending(&store, base.as_str())?;
        let mut account = store.load(base.as_str())?;
        let client = http::client(account.ca_pem.as_deref().map(str::as_bytes))?;
        self.refresh_if_needed(&mut account, &store, &client)?;
        self.account_spaces(&base, &mut account, &store, &client)
    }

    /// Verifies and binds an explicitly requested Space.
    ///
    /// # Errors
    /// Returns an error unless a fresh authenticated listing contains the Space.
    pub fn bind_space(&self, instance: &str, id: &str) -> Result<MountBinding, AccountError> {
        let session =
            self.read_session_in(&self.storage_root()?, instance, SessionAccess::Online)?;
        let spaces = self.read_with_refresh(&session, SessionAccess::Online, |current| {
            list_spaces(
                &current.base,
                &current.account.access_token,
                &current.client,
                &self.cancelled,
            )
        })?;
        Ok(explicit_space_binding(
            &session,
            id,
            unique_space_name(&spaces, id)?,
        ))
    }

    /// Prepares an explicit-path mount, allowing resume only on initial Graph transport loss.
    ///
    /// # Errors
    /// Refuses unavailable credentials, unverified live membership or incompatible retained state.
    pub fn bind_mount_space(
        &self,
        instance: &str,
        id: &str,
    ) -> Result<(MountBinding, MountStartup), AccountError> {
        // Reload the configured principal under ownership before trying Graph.
        // A cached read session alone is not authority to resume an activation.
        let guard = self.begin_operation()?;
        self.clear_read_session()?;
        let (base, _) = http::instance_and_ca(instance, None)?;
        let store = Store::open(guard.credential_context()?)?;
        guard.persist_pending(&store, base.as_str())?;
        let account = store.load(base.as_str())?;
        let client = http::client(account.ca_pem.as_deref().map(str::as_bytes))?;
        let mut session = ReadSession {
            root: guard.storage_root()?.clone(),
            base,
            account,
            client,
        };
        let binding = self.mount_start(&mut session, id, |session| {
            self.refresh_if_needed(&mut session.account, &store, &session.client)
        });
        if binding.as_ref().is_err_and(|error| !error.network) {
            self.invalidate_mount_metadata();
        }
        let binding = binding?;
        self.check_cancelled()?;
        self.publish_read_session(&guard, Arc::new(session))?;
        Ok(binding)
    }

    fn mount_start(
        &self,
        session: &mut ReadSession,
        id: &str,
        refresh: impl FnOnce(&mut ReadSession) -> Result<(), AccountError>,
    ) -> Result<(MountBinding, MountStartup), AccountError> {
        let account = &session.account;
        if account.refresh_in_progress {
            return Err(AccountError::new(
                "previous token refresh was interrupted; reconnect the account",
            ));
        }
        if account.access_token.is_empty() || account.refresh_token.is_empty() {
            return Err(AccountError::new("account credentials are incomplete"));
        }
        if id.is_empty() || id.chars().any(char::is_control) {
            return Err(AccountError::new("invalid Space ID"));
        }
        let near_expiry = account.expires_at
            <= SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| AccountError::new("system clock is invalid"))?
                .as_secs()
                .saturating_add(30);
        let initial = graph_listing(
            &session.base,
            &account.access_token,
            &session.client,
            &self.cancelled,
        );
        let (name, rejected) = match initial {
            Ok(spaces) => (unique_space_name(&spaces, id)?, false),
            Err(GraphListingError::InitialTransport(_)) => {
                self.storage.validate(&session.root)?;
                offline::offline_directory(
                    &session.root,
                    session.base.as_str(),
                    id,
                    &[],
                    Some((&account.issuer, &account.subject)),
                )?;
                return Ok((
                    explicit_space_binding(session, id, None),
                    MountStartup::Resumed,
                ));
            }
            Err(GraphListingError::Other(error)) if error.unauthorized => (None, true),
            Err(error) => return Err(error.into_account_error()),
        };
        offline::bind_identity_in(
            &session.root,
            session.base.as_str(),
            &account.issuer,
            &account.subject,
        )?;
        let name = if near_expiry || rejected {
            // The first probe already reached Graph. A refresh or subsequent
            // listing cannot grant retained startup, even on a transport error.
            if rejected {
                session.account.expires_at = 0;
            }
            self.check_cancelled()?;
            let spaces = refresh(session)
                .and_then(|()| {
                    list_spaces(
                        &session.base,
                        &session.account.access_token,
                        &session.client,
                        &self.cancelled,
                    )
                })
                .map_err(|mut error| {
                    error.network = false;
                    error
                })?;
            unique_space_name(&spaces, id)?
        } else {
            name
        };
        Ok((
            explicit_space_binding(session, id, name),
            MountStartup::Normal,
        ))
    }

    /// Lists a directory in a freshly verified Space without hydrating file contents.
    ///
    /// # Errors
    /// Refuses an unlisted Space, changed account or invalid directory observation.
    pub fn directory_space(
        &self,
        instance: &str,
        space: &str,
        path: &[String],
    ) -> Result<Vec<Entry>, AccountError> {
        let binding = self.bind_space(instance, space)?;
        self.directory_inner(instance, DirectoryAccess::Cli(&binding), path)?
            .collect()
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
        offline::offline_directory(&self.storage_root()?, base.as_str(), space, path, None)?
            .collect()
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
        self.bind_offline_space_in(self.storage_root()?, instance, space)
    }

    fn bind_offline_space_in(
        &self,
        root: account_storage::StorageRoot,
        instance: &str,
        space: &str,
    ) -> Result<MountBinding, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid offline Space"));
        }
        let (issuer, subject) = offline::mount_identity_in(&root, base.as_str(), space)?;
        offline::offline_directory(&root, base.as_str(), space, &[], Some((&issuer, &subject)))?;
        Ok(MountBinding {
            root,
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
        let root = self.storage_root()?;
        let _owner = ownership::acquire_offline_in(&root, &self.runtime)?;
        self.check_cancelled()?;
        let mut binding = self.bind_offline_space_in(root, instance, space)?;
        binding.offline_writable = true;
        Ok(binding)
    }

    fn verify_offline_mount(&self, binding: &MountBinding) -> Result<(), AccountError> {
        self.storage.validate(&binding.root)?;
        if offline::mount_identity_in(&binding.root, &binding.instance, &binding.space)?
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
            self.verify_offline_mount(space)?;
            if instance != space.instance {
                return Err(AccountError::new("offline mount instance changed"));
            }
            return offline::offline_directory(
                &space.root,
                instance,
                &space.space,
                path,
                Some((&space.issuer, &space.subject)),
            );
        }
        self.directory_inner(instance, DirectoryAccess::Mount(space, parent_id), path)
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
        self.storage.validate(&session.root)?;
        let space = bound_space(&session, binding)?;
        offline::verify_identity_in(
            &session.root,
            session.base.as_str(),
            &session.account.issuer,
            &session.account.subject,
        )?;
        let (remote, fenced) =
            offline::tree_remote_path(&session.root, session.base.as_str(), space, path)?;
        if fenced || offline::local_directory(&session.root, session.base.as_str(), space, path)? {
            return Ok(None);
        }
        let observation = offline::begin_snapshot_in(&session.root)?;
        let observed = dav::directory_snapshot_timed_in(
            &session.root,
            &session.base,
            space,
            &remote,
            &session.account.access_token,
            &session.client,
            Duration::from_secs(2),
        );
        if observed.as_ref().is_err_and(|error| error.unauthorized) {
            self.invalidate_read_session(&session)?;
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
            .is_none_or(|current| !Arc::ptr_eq(current, &session))
        {
            return Ok(None);
        }
        offline::verify_identity_in(
            &session.root,
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
        let session = self.read_session_in(
            &binding.root,
            binding.instance(),
            SessionAccess::BoundSaved(binding),
        )?;
        self.confirmed_mount_versions_in(&session, binding, versions, entries)
    }

    fn confirmed_mount_versions_in(
        &self,
        session: &ReadSession,
        binding: &MountBinding,
        versions: &[FileVersion],
        entries: &DirectorySnapshot,
    ) -> Result<Vec<(FileVersion, FileVersion)>, AccountError> {
        bound_space(session, binding)?;
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
        if entries.storage_root()?.identity() != binding.root.identity() {
            return Err(AccountError::new("directory storage root changed"));
        }
        let mut confirmed = Vec::new();
        for staged in versions {
            if staged.instance != binding.instance || staged.space != binding.space {
                return Err(AccountError::new(
                    "file version does not match mounted Space",
                ));
            }
            let Some((id, etag)) = offline::confirmed_write(&binding.root, staged)? else {
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
        let session = self.read_session_in(
            &binding.root,
            binding.instance(),
            SessionAccess::BoundSaved(binding),
        )?;
        self.confirmed_mount_directories_in(&session, binding, directories, entries)
    }

    fn confirmed_mount_directories_in(
        &self,
        session: &ReadSession,
        binding: &MountBinding,
        directories: &[(Vec<String>, String)],
        entries: &DirectorySnapshot,
    ) -> Result<Vec<(Vec<String>, String, Entry)>, AccountError> {
        bound_space(session, binding)?;
        self.confirmed_mount_directories_local(binding, directories, entries)
    }

    fn confirmed_mount_directories_local(
        &self,
        binding: &MountBinding,
        directories: &[(Vec<String>, String)],
        entries: &DirectorySnapshot,
    ) -> Result<Vec<(Vec<String>, String, Entry)>, AccountError> {
        if entries.storage_root()?.identity() != binding.root.identity() {
            return Err(AccountError::new("directory storage root changed"));
        }
        let mut confirmed = Vec::new();
        for (path, resource) in directories {
            let Some(id) = resource
                .strip_prefix("cirrus-dir:")
                .and_then(|value| value.parse::<i64>().ok())
            else {
                return Err(AccountError::new("invalid local directory identity"));
            };
            let Some(confirmed_directory) =
                offline::confirmed_directory(&binding.root, &binding.instance, id)?
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
        access: DirectoryAccess<'_>,
        path: &[String],
    ) -> Result<DirectorySnapshot, AccountError> {
        let (binding, parent_id, publication) = match access {
            DirectoryAccess::Cli(binding) => (binding, None, DirectorySnapshotPublication::Cli),
            DirectoryAccess::Mount(binding, parent_id) => (
                binding,
                Some(parent_id),
                DirectorySnapshotPublication::Mount,
            ),
        };
        let cli = matches!(publication, DirectorySnapshotPublication::Cli);
        let _permit = self.read_permit()?;
        let session_access = SessionAccess::BoundSaved(binding);
        let session = self.read_session_in(&binding.root, instance, session_access)?;
        let space = bound_space(&session, binding)?;
        let observation = offline::begin_snapshot_in(&session.root)?;
        let (remote_path, move_fenced) =
            offline::tree_remote_path(&session.root, session.base.as_str(), space, path)?;
        let mut entries = if offline::local_directory(
            &session.root,
            session.base.as_str(),
            space,
            path,
        )? {
            DirectorySnapshot::empty_in(&session.root)?
        } else if move_fenced {
            offline::directory_snapshot_at(&session.root, session.base.as_str(), space, path)?
                .ok_or_else(|| AccountError::new("directory rename requires attention"))?
        } else {
            match self.read_with_refresh(&session, session_access, |current| {
                dav::directory_snapshot_in(
                    &current.root,
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
                    let _state_turn = if cli {
                        Some(ownership::local_state_turn_in(
                            &session.root,
                            Arc::clone(&self.cancelled),
                        )?)
                    } else {
                        None
                    };
                    let _state_phase = if _state_turn.is_some() {
                        Some(ownership::admit_local_state_turn_in(&session.root)?)
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
                    if cli
                        && saved.as_ref().is_err_and(|error| error.storage_busy)
                        && let Some(marker) =
                            std::env::var_os("CIRRUS_TEST_CLI_SNAPSHOT_BLOCKED_MARKER")
                    {
                        let _ = std::fs::write(marker, b"refused");
                    }
                    accept_directory_snapshot_save(
                        saved,
                        publication,
                        &session,
                        space,
                        path,
                        &entries,
                    )?;
                    entries
                }
                Err(error) if error.network => {
                    let saved = offline::directory_snapshot_at(
                        &session.root,
                        session.base.as_str(),
                        space,
                        path,
                    )?;
                    #[cfg(feature = "fault-injection")]
                    if std::env::var_os("CIRRUS_TEST_BLOCKER_TRACE").is_some() {
                        eprintln!(
                            "cirrus lab directory fallback: path={path:?} remote={remote_path:?} bound_raw={}",
                            saved.is_some()
                        );
                    }
                    if let Some(saved) = saved {
                        saved
                    } else if !cli {
                        // A queued MOVE's destination exists in the projected
                        // ancestor view, not the raw remote parent. Reuse its
                        // exact identity/copy proof, never an orphan fallback.
                        return offline::offline_directory(
                            &session.root,
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
        self.open_file_inner(instance, space, path, id, true)
    }

    fn open_file_inner(
        &self,
        instance: &str,
        binding: &MountBinding,
        path: &[String],
        id: &str,
        allow_offline: bool,
    ) -> Result<FileVersion, AccountError> {
        let (name, _) = path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid file path"))?;
        let _permit = self.read_permit()?;
        let access = SessionAccess::for_space(binding, allow_offline);
        let session = self.read_session_in(&binding.root, instance, access)?;
        let space = bound_space(&session, binding)?;
        let principal = (
            session.account.issuer.as_str(),
            session.account.subject.as_str(),
        );
        if id.starts_with("cirrus-staged:") {
            if !offline::publication::spaces_in(&session.root, session.base.as_str(), Some(space))?
                .is_empty()
            {
                let _guard = self.begin_local_operation(&session, true)?;
                let operation = id
                    .strip_prefix("cirrus-staged:")
                    .and_then(|id| id.parse::<i64>().ok())
                    .ok_or_else(|| AccountError::new("invalid staged identity"))?;
                offline::publication::recover_in(
                    &session.root,
                    session.base.as_str(),
                    space,
                    path,
                    operation,
                    None,
                    true,
                )?;
            }
            return offline::staged_version(&session.root, session.base.as_str(), space, path, id)?
                .map(|(version, _)| version)
                .ok_or_else(|| AccountError::new("staged file is unavailable"));
        }
        let (remote_path, move_fenced) =
            offline::tree_remote_path(&session.root, session.base.as_str(), space, path)?;
        if move_fenced {
            return offline::version(
                &session.root,
                session.base.as_str(),
                space,
                path,
                id,
                principal,
            )?
            .ok_or_else(|| AccountError::new("directory rename requires attention"));
        }
        let (_, remote_parent) = remote_path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid file path"))?;
        let entries = match self.read_with_refresh(&session, access, |current| {
            dav::directory_snapshot_in(
                &current.root,
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
                    &session.root,
                    session.base.as_str(),
                    space,
                    path,
                    id,
                    principal,
                )? {
                    return Ok(version);
                }
                let (name, parent) = path
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid file path"))?;
                let saved = offline::directory_snapshot_at(
                    &session.root,
                    session.base.as_str(),
                    space,
                    parent,
                )?;
                let saved = if saved.is_none() {
                    Some(offline::offline_directory(
                        &session.root,
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
                        &session.root,
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
        storage: &account_storage::StorageRoot,
        instance: &str,
        binding: &MountBinding,
        path: &[String],
        save: bool,
        pin_root: &[String],
    ) -> Result<DirectorySnapshot, AccountError> {
        let _permit = self.read_permit()?;
        let access = SessionAccess::BoundOnline(binding);
        let session = self.read_session_in(storage, instance, access)?;
        let space = bound_space(&session, binding)?;
        let snapshot = if save {
            Some(offline::begin_pin_snapshot_in(
                &session.root,
                session.base.as_str(),
                space,
                pin_root,
            )?)
        } else {
            None
        };
        let entries = self.read_with_refresh(&session, access, |current| {
            dav::directory_snapshot_in(
                &current.root,
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

    /// Pins a path in an explicitly verified Space.
    ///
    /// # Errors
    /// Refuses active staging, unavailable retained originals, or an unverifiable Space or pin.
    pub fn pin_space(
        &self,
        instance: &str,
        space: &str,
        root: &[String],
    ) -> Result<(), AccountError> {
        let binding = self.bind_space(instance, space)?;
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
        let access = SessionAccess::BoundOnline(&binding);
        let session = self.read_session_in(&binding.root, instance, access)?;
        let space = bound_space(&session, &binding)?;
        let instance = session.base.to_string();
        offline::check_pin_path(&session.root, &instance, space, root)?;
        let local_state = offline::current_pin_local_state(&session.root)?;
        let mut retries = 0;
        loop {
            let result = self
                .collect_pin_files(&session.root, &instance, &binding, root, true)
                .and_then(|tree| {
                    offline::replace_pin(
                        &session.root,
                        (&self.runtime, &self.cancelled, &instance, space),
                        root,
                        &tree,
                        (retries != 0).then_some(&local_state),
                        |version, offset, length| {
                            self.read_range_online(&binding, version, offset, length, false)
                                .map(|(bytes, _metadata)| bytes)
                        },
                        |version| {
                            if self.open_file_inner(
                                &version.instance,
                                &binding,
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
                            if self.collect_pin_files(
                                &session.root,
                                &instance,
                                &binding,
                                root,
                                false,
                            )? != tree
                            {
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
                    if offline::current_pin_local_state(&session.root)? != local_state {
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
        storage: &account_storage::StorageRoot,
        instance: &str,
        binding: &MountBinding,
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
            let entries =
                self.online_directory(storage, instance, binding, &root[..depth], save, root)?;
            if !entries
                .get(&root[depth])?
                .is_some_and(|entry| entry.is_directory())
            {
                return Err(AccountError::new("pin ancestor is unavailable"));
            }
        }
        if let Some((name, parent)) = root.split_last() {
            let entries = self.online_directory(storage, instance, binding, parent, save, root)?;
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
            let entries = self.online_directory(storage, instance, binding, &path, save, root)?;
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

    /// Removes only the named local pin, without credentials or network access.
    ///
    /// # Errors
    /// Refuses active staging, unavailable originals, invalid identity or insufficient storage.
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
        let storage_root = self.storage_root()?;
        let _owner = ownership::acquire_offline_exclusive_in(&storage_root, &self.runtime)?;
        offline::unpin(&storage_root, base.as_str(), space, root, &self.cancelled)
    }

    /// Stages a local file in an explicitly verified Space.
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
        check_stage_file_path(path)?;
        let _priority = self.request_foreground();
        let binding = self.bind_space(instance, space)?;
        let session =
            self.read_session_in(&binding.root, instance, SessionAccess::BoundSaved(&binding))?;
        self.stage_observed_file(&session, &binding, path, source)
            .map(|_| ())
    }

    /// Imports an entire local file using retained account, Space and parent evidence.
    /// Does not access credentials, contact the server or activate a Space.
    ///
    /// # Errors
    /// Refuses missing or changed retained evidence, competing ownership or unsafe imports.
    pub fn stage_file_offline_space(
        &self,
        instance: &str,
        space: &str,
        path: &[String],
        source: &std::path::Path,
    ) -> Result<(), AccountError> {
        check_stage_file_path(path)?;
        let (base, _) = http::instance_and_ca(instance, None)?;
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid offline Space"));
        }
        let root = self.storage_root()?;
        // Share mounted staging ownership without loading credentials. Changes
        // of principal still require EX; the journal arbitrates sync races.
        let _priority = self.request_foreground();
        let _owner = ownership::acquire_offline_in(&root, &self.runtime)?;
        self.check_cancelled()?;
        let _state_turn = ownership::local_state_turn_in(&root, Arc::clone(&self.cancelled))?;
        offline::stage_file(
            &root,
            (base.as_str(), space),
            path,
            source,
            offline::ImportEvidence::Retained,
            &self.cancelled,
        )
        .map(|_| ())
    }

    fn stage_observed_file(
        &self,
        session: &ReadSession,
        binding: &MountBinding,
        path: &[String],
        source: &std::path::Path,
    ) -> Result<OperationHandle, AccountError> {
        let ReadSession {
            root,
            base,
            account,
            ..
        } = session;
        check_bound_account(root, base, account, binding)?;
        let space = binding.space.as_str();
        let _owner = self.begin_local_operation(session, true)?;
        let _state_turn = ownership::local_state_turn_in(root, Arc::clone(&self.cancelled))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|v| v.as_secs());
        if !account.refresh_in_progress
            && now.is_some_and(|now| account.expires_at > now.saturating_add(30))
            && let Ok(client) = http::client(account.ca_pem.as_deref().map(str::as_bytes))
        {
            for depth in 0..path.len() {
                self.check_cancelled()?;
                let logical = &path[..depth];
                if offline::local_directory(root, base.as_str(), space, logical)? {
                    continue;
                }
                let (remote, fenced) =
                    offline::tree_remote_path(root, base.as_str(), space, logical)?;
                if fenced {
                    return Err(AccountError::new("directory rename requires attention"));
                }
                let observation = offline::begin_snapshot_in(root)?;
                if let Ok(entries) = dav::directory_snapshot_in(
                    root,
                    base,
                    space,
                    &remote,
                    &account.access_token,
                    &client,
                ) {
                    let _state_phase = ownership::admit_local_state_turn_in(root)?;
                    offline::save_directory_snapshot(
                        observation,
                        base.as_str(),
                        space,
                        logical,
                        &entries,
                    )?;
                }
            }
        }
        offline::stage_file(
            root,
            (base.as_str(), space),
            path,
            source,
            offline::ImportEvidence::Online {
                issuer: &account.issuer,
                subject: &account.subject,
            },
            &self.cancelled,
        )
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
        self.stage_mount_mutation_operation(instance, expected_space, path, mutation, base, parents)
            .map(|(version, _)| version)
    }

    /// Publishes a mounted mutation and its immutable operation correlation together.
    ///
    /// # Errors
    /// Applies the same base-version, parent, principal and storage gates as
    /// `stage_mount_mutation`; an operation handle is not remote confirmation.
    pub fn stage_mount_mutation_operation(
        &self,
        instance: &str,
        expected_space: &MountBinding,
        path: &[String],
        mutation: DirtyMutation<'_>,
        base: Option<&FileVersion>,
        parents: &[DirectoryIdentity],
    ) -> Result<(FileVersion, OperationHandle), AccountError> {
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
            self.storage.validate(&expected_space.root)?;
            let _owner = ownership::acquire_offline_in(&expected_space.root, &self.runtime)?;
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
            let _state_turn =
                ownership::local_state_turn_in(&expected_space.root, Arc::clone(&self.cancelled))?;
            return offline::stage_offline_mutation_operation(
                expected_space,
                path,
                mutation,
                base,
                parents,
            );
        }
        let session = self.read_session_in(
            &expected_space.root,
            instance,
            SessionAccess::BoundSaved(expected_space),
        )?;
        let space = bound_space(&session, expected_space)?;
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
        let _state_turn =
            ownership::local_state_turn_in(&session.root, Arc::clone(&self.cancelled))?;
        let (_, uncertain) =
            offline::tree_remote_path(&session.root, session.base.as_str(), space, path)?;
        if uncertain && !base.is_some_and(|version| version.id.starts_with("cirrus-staged:")) {
            return Err(AccountError::new("directory rename requires attention"));
        }
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_WRITE_TREE_WINDOW")?;
        offline::stage_mutation_operation(expected_space, path, mutation, base, parents)
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
            self.storage.validate(&expected_space.root)?;
            let owner = ownership::acquire_offline_in(&expected_space.root, &self.runtime)?;
            self.check_cancelled()?;
            self.verify_offline_mount(expected_space)?;
            // Preserve only already verified local ranges. Missing originals
            // remain unavailable; no credential lookup, DAV or hydration.
            for version in std::iter::once(source).chain(pending_target) {
                let (_, name) = offline::staged_version(
                    &expected_space.root,
                    &version.instance,
                    &version.space,
                    &version.path,
                    &version.id,
                )?
                .filter(|(current, _)| current == version)
                .ok_or_else(|| AccountError::new("rename snapshot changed"))?;
                offline::overlay::Overlay::load_at(&expected_space.root, &name)?.retain_available(
                    |base, offset, length| {
                        self.read_offline_range(expected_space, base, offset, length)
                            .ok()
                    },
                )?;
            }
            return Ok(PreparedFileRename {
                root: expected_space.root.clone(),
                _guard: None,
                _offline_owner: Some(owner),
                source,
                destination,
                target: observed_target.or(expected_target),
                pending_target,
                parents,
                offline: Some(expected_space.clone()),
                cancelled: Arc::clone(&self.cancelled),
                runtime: &self.runtime,
                online: None,
                local_observation: None,
            });
        }
        let session = self.read_session_in(
            &expected_space.root,
            instance,
            SessionAccess::BoundSaved(expected_space),
        )?;
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_FILE_RENAME_ADMISSION_TRACE").is_some() {
            eprintln!(
                "cirrus lab file rename admission: pid={} thread={:?} boundary=prepare-session-acquired",
                std::process::id(),
                std::thread::current().id()
            );
        }
        let space = bound_space(&session, expected_space)?;
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
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_FILE_RENAME_ADMISSION_TRACE").is_some() {
            eprintln!(
                "cirrus lab file rename admission: pid={} thread={:?} boundary=prepare-staging-acquired",
                std::process::id(),
                std::thread::current().id()
            );
        }
        let source_base = offline::staged_source_base(&session.root, source)?;
        let directory = |path: &[String]| -> Result<DirectorySnapshot, AccountError> {
            let observation = offline::begin_snapshot_in(&session.root)?;
            #[cfg(feature = "fault-injection")]
            wait_test_window("CIRRUS_TEST_FILE_RENAME_PREP_WINDOW")?;
            if offline::local_directory(&session.root, session.base.as_str(), space, path)? {
                return DirectorySnapshot::empty_in(&session.root);
            }
            let (remote_path, uncertain) =
                offline::tree_remote_path(&session.root, session.base.as_str(), space, path)?;
            if uncertain {
                return Err(AccountError::new("directory rename requires attention"));
            }
            match dav::directory_snapshot_in(
                &session.root,
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
                Err(error) if error.network => offline::directory_snapshot_at(
                    &session.root,
                    session.base.as_str(),
                    space,
                    path,
                )?
                .ok_or(error),
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
            let base = offline::staged_source_base(&session.root, pending_target)?;
            if !base
                .as_ref()
                .is_some_and(|(base_id, base_etag)| base_id == id && base_etag == etag)
            {
                return Err(AccountError::new("rename target changed"));
            }
        }
        let local_observation = if source_base.is_none()
            && pending_target.is_none()
            && observed_target.or(expected_target).is_none()
            && source_parent == target_parent
            && source_parent.len() == 1
            && matches!(parents.source, [DirectoryIdentity::Pending(_)])
            && parents.source == parents.destination
        {
            offline::local_rename_observation(
                &session.root,
                session.base.as_str(),
                space,
                source_parent,
            )?
        } else {
            None
        };
        Ok(PreparedFileRename {
            root: session.root.clone(),
            _guard: Some(guard),
            _offline_owner: None,
            source,
            destination,
            target: observed_target.or(expected_target),
            pending_target,
            parents,
            offline: None,
            cancelled: Arc::clone(&self.cancelled),
            runtime: &self.runtime,
            online: Some(session),
            local_observation,
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
            self.storage.validate(&expected_space.root)?;
            let _owner =
                ownership::acquire_offline_exclusive_in(&expected_space.root, &self.runtime)?;
            self.check_cancelled()?;
            self.verify_offline_mount(expected_space)?;
            offline::protect_moving_pin_originals(
                &expected_space.root,
                instance,
                &expected_space.space,
                source,
                destination,
                &self.cancelled,
            )?;
            let _turn =
                ownership::local_state_turn_in(&expected_space.root, Arc::clone(&self.cancelled))?;
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
                &expected_space.root,
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
        let session = self.read_session_in(
            &expected_space.root,
            instance,
            SessionAccess::BoundSaved(expected_space),
        )?;
        let space = bound_space(&session, expected_space)?;
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_LOCAL_TREE_SESSION_WINDOW")?;
        let _guard = self.begin_owned_local_operation(&session)?;
        offline::protect_moving_pin_originals(
            &session.root,
            session.base.as_str(),
            space,
            source,
            destination,
            &self.cancelled,
        )?;
        let mut relocated = Vec::with_capacity(open_versions.len());
        for version in open_versions {
            if version.instance != session.base.as_str()
                || version.space != space
                || !version.path.starts_with(source)
                || !version.id.starts_with("cirrus-staged:")
                || offline::staged_version(
                    &session.root,
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
            &session.root,
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
            self.storage.validate(&expected_space.root)?;
            let owner =
                ownership::acquire_offline_exclusive_in(&expected_space.root, &self.runtime)?;
            self.check_cancelled()?;
            self.verify_offline_mount(expected_space)?;
            let (name, parent) = source_path
                .split_last()
                .ok_or_else(|| AccountError::new("invalid tree source"))?;
            let entry = offline::offline_directory(
                &expected_space.root,
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
                        &expected_space.root,
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
                root: expected_space.root.clone(),
                _staging: None,
                _offline_owner: Some(owner),
                // Exclude admitted sync preflights as well as uncertain MOVEs.
                _sync_owner: Some(ownership::acquire_sync_in(
                    &expected_space.root,
                    &self.runtime,
                )?),
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
        let session = self.read_session_in(
            &expected_space.root,
            instance,
            SessionAccess::BoundSaved(expected_space),
        )?;
        let space = bound_space(&session, expected_space)?;
        let guard = self.begin_owned_local_operation(&session)?;
        // As for empty-directory preparation, keep exclusive cross-process
        // ownership but allow this daemon's local staging during DAV work.
        let staging = guard.begin_staging(Arc::clone(&session))?;
        let (mapped_source, _) =
            offline::tree_remote_path(&session.root, session.base.as_str(), space, source_path)?;
        let (mapped_destination, _) =
            offline::tree_remote_path(&session.root, session.base.as_str(), space, destination)?;
        if mapped_source != source_path || mapped_destination != destination {
            return Err(AccountError::new("path has unresolved operations"));
        }
        let directory = |path: &[String]| -> Result<DirectorySnapshot, AccountError> {
            self.check_cancelled()?;
            let observation = offline::begin_snapshot_in(&session.root)?;
            if offline::local_directory(&session.root, session.base.as_str(), space, path)? {
                return DirectorySnapshot::empty_in(&session.root);
            }
            let (remote, uncertain) =
                offline::tree_remote_path(&session.root, session.base.as_str(), space, path)?;
            if uncertain {
                return Err(AccountError::new("directory rename requires attention"));
            }
            match dav::directory_snapshot_in(
                &session.root,
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
                Err(error) if error.network => offline::directory_snapshot_at(
                    &session.root,
                    session.base.as_str(),
                    space,
                    path,
                )?
                .ok_or(error),
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
                    &session.root,
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
            root: session.root.clone(),
            _staging: Some(staging),
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
        let session = self.read_session_in(
            &expected_space.root,
            instance,
            SessionAccess::BoundSaved(expected_space),
        )?;
        let space = bound_space(&session, expected_space)?;
        let guard = self.begin_owned_local_operation(&session)?;
        // Keep the same cross-process credential/namespace ownership as before,
        // but admit this daemon's identity-checked local staging while DAV is
        // in flight, just as during sync. Other account operations and peer
        // writers still cannot acquire this exclusive account owner.
        let staging = guard.begin_staging(Arc::clone(&session))?;
        let (mapped_source, _) =
            offline::tree_remote_path(&session.root, session.base.as_str(), space, source)?;
        let (mapped_destination, _) =
            offline::tree_remote_path(&session.root, session.base.as_str(), space, destination)?;
        if mapped_source != source || mapped_destination != destination {
            return Err(AccountError::new("path has unresolved operations"));
        }
        let directory = |path: &[String]| -> Result<DirectorySnapshot, AccountError> {
            self.check_cancelled()?;
            let observation = offline::begin_snapshot_in(&session.root)?;
            if offline::local_directory(&session.root, session.base.as_str(), space, path)? {
                return DirectorySnapshot::empty_in(&session.root);
            }
            match dav::directory_snapshot_in(
                &session.root,
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
                Err(error) if error.network => offline::directory_snapshot_at(
                    &session.root,
                    session.base.as_str(),
                    space,
                    path,
                )?
                .ok_or(error),
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
            root: session.root.clone(),
            _staging: staging,
            instance: session.base.to_string(),
            space: space.to_owned(),
            source,
            destination,
            base,
            parents,
            cancelled: Arc::clone(&self.cancelled),
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
        let session = self.read_session_in(
            &expected_space.root,
            instance,
            SessionAccess::BoundSaved(expected_space),
        )?;
        let space = bound_space(&session, expected_space)?;
        offline::any_unresolved_beneath(&session.root, session.base.as_str(), space, path)
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
        self.stage_namespace_operation(instance, expected_space, path, kind, base, parents)
            .map(|operation| operation.id())
    }

    /// Queues namespace work and captures its exact identity in the publication transaction.
    ///
    /// # Errors
    /// Applies the same binding, parent, namespace and storage gates as `stage_namespace`.
    pub fn stage_namespace_operation(
        &self,
        instance: &str,
        expected_space: &MountBinding,
        path: &[String],
        kind: &str,
        base: Option<(&str, &str)>,
        parents: &[DirectoryIdentity],
    ) -> Result<OperationHandle, AccountError> {
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
            self.storage.validate(&expected_space.root)?;
            let _owner = ownership::acquire_offline_in(&expected_space.root, &self.runtime)?;
            self.check_cancelled()?;
            self.verify_offline_mount(expected_space)?;
            let _state_turn =
                ownership::local_state_turn_in(&expected_space.root, Arc::clone(&self.cancelled))?;
            return offline::queue_namespace_operation(
                &expected_space.root,
                instance,
                &expected_space.space,
                path,
                kind,
                base,
                parents,
                Some(expected_space),
            );
        }
        let session = self.read_session_in(
            &expected_space.root,
            instance,
            SessionAccess::BoundSaved(expected_space),
        )?;
        let space = bound_space(&session, expected_space)?;
        let _guard = self.begin_local_operation(&session, false)?;
        let (_, uncertain) =
            offline::tree_remote_path(&session.root, session.base.as_str(), space, path)?;
        if uncertain {
            return Err(AccountError::new("directory rename requires attention"));
        }
        offline::queue_namespace_operation(
            &session.root,
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
        let session = self.read_session_in(
            &expected_space.root,
            instance,
            SessionAccess::BoundSaved(expected_space),
        )?;
        let space = bound_space(&session, expected_space)?;
        let _guard = self.begin_local_operation(&session, false)?;
        offline::remove_staged(
            &session.root,
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
        self.storage.validate(&binding.root)?;
        let _owner = ownership::acquire_offline_in(&binding.root, &self.runtime)?;
        self.check_cancelled()?;
        self.verify_offline_mount(binding)?;
        let _state_turn =
            ownership::local_state_turn_in(&binding.root, Arc::clone(&self.cancelled))?;
        offline::remove_staged(
            &binding.root,
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
            self.storage.validate(&binding.root)?;
            let _owner = ownership::acquire_offline_in(&binding.root, &self.runtime)?;
            self.check_cancelled()?;
            self.verify_offline_mount(binding)?;
            if !offline::verify_offline_detached(binding, version)? {
                return Err(AccountError::new("offline detached version changed"));
            }
            let _state_turn =
                ownership::local_state_turn_in(&binding.root, Arc::clone(&self.cancelled))?;
            return offline::stage_detached_mutation(
                &binding.root,
                version,
                mutation,
                Some(binding),
            );
        }
        let session = self.read_session_in(
            &binding.root,
            &version.instance,
            SessionAccess::BoundSaved(binding),
        )?;
        if bound_space(&session, binding)? != version.space {
            return Err(AccountError::new(
                "file version does not match mounted Space",
            ));
        }
        let _guard = self.begin_local_operation(&session, true)?;
        offline::stage_detached_mutation(&session.root, version, mutation, None)
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
        let root = self.storage_root()?;
        let mut page = offline::journal_in(&root, base.as_str(), space, before)?;
        // Do not hold the upload-state lock while SQLite scans retained history.
        // Another daemon's active upload remains conservatively ambiguous.
        let active = self
            .active_writes
            .lock()
            .map_err(|_| AccountError::new("upload status is unavailable"))?;
        for entry in &mut page.entries {
            if entry.state == JournalState::UncertainOrInProgress
                && active.contains(&(root.identity(), entry.id))
            {
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
    ) -> Result<RetainedPage<RetainedPin>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        let storage = self.storage_root()?;
        recovery::pins(&storage, base.as_str(), offset)
    }

    /// Lists immutable displaced pin copies by independent local ID.
    ///
    /// # Errors
    /// Returns an error for invalid input or unavailable retained metadata.
    pub fn pin_copies(
        &self,
        instance: &str,
        offset: u32,
    ) -> Result<RetainedPage<RetainedPinCopy>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        let storage = self.storage_root()?;
        recovery::pin_copies(&storage, base.as_str(), offset)
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
    ) -> Result<RetainedPage<RetainedPinCopyEntry>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        let storage = self.storage_root()?;
        recovery::pin_copy_entries(&storage, base.as_str(), space, id, offset)
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
        let storage = self.storage_root()?;
        recovery::export_pin_copy(
            &storage,
            base.as_str(),
            space,
            id,
            path,
            selector,
            destination,
        )
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
        let storage = self.storage_root()?;
        recovery::remove_pin_copy(&storage, base.as_str(), space, id)
    }

    /// Lists journal-referenced immutable roots without scanning logical file content.
    ///
    /// # Errors
    /// Returns an error if local journal metadata cannot be read.
    pub fn retained_staged(
        &self,
        instance: &str,
        offset: u32,
    ) -> Result<RetainedPage<RetainedStaged>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        let storage = self.storage_root()?;
        recovery::staged_list(&storage, base.as_str(), offset)
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
        let storage = self.storage_root()?;
        recovery::staged_export(&storage, base.as_str(), id, selector, destination)
    }

    /// Lists retained file metadata for one pin. The selector is not validation.
    ///
    /// # Errors
    /// Returns an error if the instance, path or local database is invalid.
    pub fn retained_files(
        &self,
        instance: &str,
        space: &str,
        root: &[String],
        offset: u32,
    ) -> Result<RetainedPage<RetainedPinFile>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        let storage = self.storage_root()?;
        recovery::files(&storage, base.as_str(), space, root, offset)
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
            &self.storage_root()?,
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

    /// Runs one explicit upload step for the Linux fault-injection lab.
    ///
    /// Stops at the first bounded PUT/verification boundary so the lab can
    /// inspect durable state before manual sync or a restart.
    ///
    /// # Errors
    /// Returns an error for invalid input, account ownership, authentication or storage.
    #[cfg(feature = "fault-injection")]
    #[doc(hidden)]
    pub fn lab_upload_step(
        &self,
        instance: &str,
        space: &str,
    ) -> Result<WriteTurnOutcome, AccountError> {
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid Space ID"));
        }
        match self.sync_pending_in(instance, Some(space), executor::Mode::LabUploadStep) {
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
        let root = self.storage_root()?;
        self.sync_pending_at(&root, instance, requested_space, mode)
    }

    fn sync_pending_at(
        &self,
        root: &account_storage::StorageRoot,
        instance: &str,
        requested_space: Option<&str>,
        mode: executor::Mode,
    ) -> Result<WriteTurnOutcome, AccountError> {
        let _sync_guard = ownership::acquire_sync_in(root, &self.runtime)?;
        let access = SessionAccess::Online;
        let mut session = self
            .read_session_in(root, instance, access)?
            .as_ref()
            .clone();
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
        offline::database_in(&session.root)?.execute("DELETE FROM sync_reads WHERE operation_id IN (SELECT id FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2))", rusqlite::params![session.base.as_str(),requested_space])
            .map_err(|_| AccountError::new("cannot invalidate rejected sync preflight"))?;
        session = self
            .refresh_rejected_session(&session, access)?
            .as_ref()
            .clone();
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
        let mut guard = self.begin_operation_in(&session.root)?;
        self.clear_read_session()?;
        let store = Store::open(guard.credential_context()?)?;
        guard.persist_pending(&store, session.base.as_str())?;
        let account = store.load(session.base.as_str())?;
        if account.issuer != session.account.issuer || account.subject != session.account.subject {
            return Err(AccountError::new(
                "account changed while starting sync; retry",
            ));
        }
        session.account = account;
        if mode == executor::Mode::Automatic {
            offline::verify_identity_in(
                &session.root,
                session.base.as_str(),
                &session.account.issuer,
                &session.account.subject,
            )
            .map_err(|mut error| {
                error.retryable_read = true;
                error
            })?;
        } else {
            offline::bind_identity_in(
                &session.root,
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
        if mode == executor::Mode::Manual
            && let Some(space) = requested_space
            && !offline::publication::spaces_in(&session.root, session.base.as_str(), Some(space))?
                .is_empty()
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
            .as_mut()
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
        drop(store);
        let published = Arc::new(session.clone());
        self.publish_read_session(&guard, Arc::clone(&published))?;
        self.session_ready.notify_all();
        let staging_window = guard.begin_staging(published)?;
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
        #[cfg(feature = "fault-injection")]
        let bounded = mode == executor::Mode::LabUploadStep;
        #[cfg(not(feature = "fault-injection"))]
        let bounded = false;
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
        let preflight_through = offline::journal_high_water(&session.root, session.base.as_str())?;
        let mut after = 0;
        loop {
            self.check_cancelled()?;
            let page = offline::tree_move_page_in(
                &session.root,
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
                &session.root,
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
                    &session.root,
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
            offline::invalid_journal_spaces(&session.root, session.base.as_str(), requested_space)?;
        let local_publications =
            offline::publication::spaces_in(&session.root, session.base.as_str(), requested_space)?;
        let mut blocked = unlisted.clone();
        blocked.extend(local_publications.iter().cloned());
        blocked.extend(invalid_journal.iter().cloned());
        blocked.extend(offline::unsettled_mkdir_spaces(
            &session.root,
            session.base.as_str(),
            requested_space,
        )?);
        blocked.extend(offline::tree_blocked_spaces(
            &session.root,
            session.base.as_str(),
            requested_space,
        )?);
        blocked.extend(offline::parent_conflict_spaces(
            &session.root,
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
                &session.root,
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
                    if !active.insert((session.root.identity(), verification.operation.id)) {
                        return Err(AccountError::new("write is already being synchronized"));
                    }
                }
                let _active = ActiveWrite {
                    accounts: self,
                    root: session.root.clone(),
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
        if bounded
            && offline::write_turn_dependencies(
                &session.root,
                session.base.as_str(),
                requested_space,
            )?
        {
            return Ok(WriteTurnOutcome::Dependencies);
        }
        let trees_through = offline::journal_high_water(&session.root, session.base.as_str())?;
        let mkdir_through = offline::journal_high_water(&session.root, session.base.as_str())?;
        let mut after = (0, 0);
        loop {
            if bounded {
                break;
            }
            self.check_cancelled()?;
            let page = offline::pending_namespace(
                &session.root,
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
                    &session.root,
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
            let page = offline::tree_move_page_in(
                &session.root,
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
                    if offline::tree_blocked_spaces(
                        &session.root,
                        session.base.as_str(),
                        Some(&tree.space),
                    )?
                    .contains(&tree.space)
                    {
                        blocked.insert(tree.space.clone());
                    } else {
                        return Err(error);
                    }
                }
            }
        }
        let mkdir_through = offline::journal_high_water(&session.root, session.base.as_str())?;
        let mut after = (0, 0);
        loop {
            if bounded {
                break;
            }
            self.check_cancelled()?;
            let page = offline::pending_namespace(
                &session.root,
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
        let writes_through = offline::journal_high_water(&session.root, session.base.as_str())?;
        let mut after = 0;
        let mut attempted = false;
        'writes: loop {
            self.check_cancelled()?;
            let page = offline::pending_writes(
                &session.root,
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
                    &session.root,
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
                    if !active.insert((session.root.identity(), operation.id)) {
                        return Err(AccountError::new("write is already being synchronized"));
                    }
                }
                let _active = ActiveWrite {
                    accounts: self,
                    root: session.root.clone(),
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
                        &session.root,
                        session.base.as_str(),
                        &operation,
                        "pending",
                        "conflict",
                        Some(offline::PARENT_WRITE_CONFLICT),
                    )?;
                    blocked.insert(operation.space.clone());
                    continue;
                }
                let data = offline::StagedSnapshot::open_at(&session.root, &operation.staged)?;
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
                    &session.root,
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
                        &session.root,
                        session.base.as_str(),
                        &operation,
                        "uncertain",
                        "pending",
                        Some("remote rejected the precondition; local copy retained"),
                    )?;
                    if offline::write_needs_attention(
                        &session.root,
                        session.base.as_str(),
                        &operation,
                    )? {
                        blocked.insert(operation.space.clone());
                        rejected_upload = true;
                        continue;
                    }
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
                            &session.root,
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
                        &session.root,
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
                        &session.root,
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
                    &session.root,
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
                offline::write_turn_remaining(&session.root, session.base.as_str(), requested_space)
            };
        }
        let namespace_through = offline::journal_high_water(&session.root, session.base.as_str())?;
        let mut after = (0, 0);
        loop {
            self.check_cancelled()?;
            let page = offline::pending_namespace(
                &session.root,
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
                        &session.root,
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
                    if offline::namespace_needs_attention(
                        &session.root,
                        session.base.as_str(),
                        &operation,
                    )? {
                        blocked.insert(operation.space.clone());
                        namespace_attention = true;
                    } else {
                        return Err(error);
                    }
                }
            }
        }
        // Wait for local writes admitted during sync before reporting completion.
        let _operation = staging_window.finish();
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
                "server rejected an upload; local copies retained; other eligible operations may have synced",
            ));
        }
        if !blocked.is_empty() {
            return Err(AccountError::new(
                "directory conflict or uncertain outcome requires attention; other eligible operations may have synced",
            ));
        }
        if offline::has_unresolved(&session.root, session.base.as_str(), requested_space)? {
            return Err(AccountError::new(
                "pending, conflict or uncertain operations require attention; local copies retained",
            ));
        }
        sync::manual_idle(&session.root, session.base.as_str(), requested_space)?;
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
            if offline::unsettled_mkdir_spaces(
                &session.root,
                session.base.as_str(),
                Some(&operation.space),
            )?
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
                if offline::write_needs_attention(&session.root, session.base.as_str(), operation)?
                {
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
                &session.root,
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
                &session.root,
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
                let page = offline::tree_proof_page(
                    &session.root,
                    session.base.as_str(),
                    operation,
                    after.as_deref(),
                )?;
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
                            &session.root,
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
            offline::tree_target_proof(&session.root, session.base.as_str(), operation)?;
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
                    &session.root,
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
            &session.root,
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
                    &session.root,
                    session.base.as_str(),
                    operation,
                    "uncertain",
                    "conflict",
                    Some("server rejected directory MOVE"),
                )?;
            }
            return Err(AccountError::new("directory MOVE failed or is uncertain"));
        }
        if executor::tree_receipt(&session.root, operation)? {
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
            &session.root,
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
        dav::directory_snapshot_once_in(
            &session.root,
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
        offline::tree_target_proof(&session.root, session.base.as_str(), operation)?;
        let mut after = None;
        loop {
            let page = offline::tree_proof_page(
                &session.root,
                session.base.as_str(),
                operation,
                after.as_deref(),
            )?;
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
            &session.root,
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
                &session.root,
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
                offline::confirmed_directory(&session.root, session.base.as_str(), dependency)?
            else {
                offline::set_namespace_state(
                    &session.root,
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
                    &session.root,
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
                offline::confirmed_destination(&session.root, session.base.as_str(), dependency)?
            else {
                offline::set_namespace_state(
                    &session.root,
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
            let data = offline::StagedSnapshot::open_at(&session.root, &destination.staged)?;
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
                        &session.root,
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
                &session.root,
                session.base.as_str(),
                operation,
                "pending",
                "synced",
                Some("target already absent"),
            );
        }
        let matches = executor::namespace_target_matches(operation, current.as_ref());
        if !matches {
            offline::set_namespace_state(
                &session.root,
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
                &session.root,
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
                    &session.root,
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
            if let Some(pending) = offline::pending_rmdir_base(
                &session.root,
                session.base.as_str(),
                &operation.space,
                parent,
            )? {
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
            &session.root,
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
        if !matches!(status.as_u16(), 200 | 201 | 204) {
            if status.is_client_error()
                && status != reqwest::StatusCode::UNAUTHORIZED
                && status != reqwest::StatusCode::REQUEST_TIMEOUT
                && status != reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                offline::set_namespace_state(
                    &session.root,
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
        executor::namespace_receipt(
            &session.root,
            session.base.as_str(),
            (&session.account.issuer, &session.account.subject),
            operation,
            parent_rebase.as_ref(),
            status,
        )?;
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
            &session.root,
            session.base.as_str(),
            operation,
            confirmation.as_deref(),
            rebase
                .as_ref()
                .map(|(parent, etag)| (*parent, etag.as_str())),
        )?;
        executor::retire(&session.root, operation.id)
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
        let target = offline::local_directory_target(&session.root, instance, operation)?;
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
            dav::directory_snapshot_once_in(
                &session.root,
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
                &session.root,
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
        offline::confirm_local_directory_target(&session.root, instance, operation, &target)
            .map_err(|mut error| {
                error.retryable_read = true;
                error
            })?;
        Ok(true)
    }

    /// Acknowledges an inspected conflict or uncertain outcome without deleting its local copy.
    ///
    /// # Errors
    /// Returns an error if no matching unresolved entry exists or the journal cannot be updated.
    pub fn acknowledge(&self, instance: &str, staged: &str) -> Result<(), AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        let _guard = self.begin_operation()?;
        offline::acknowledge(_guard.storage_root()?, base.as_str(), staged)
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
            let observation = offline::begin_snapshot_in(&session.root)?;
            match dav::directory_snapshot_in(
                &session.root,
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
                    accept_directory_snapshot_save(
                        saved,
                        DirectorySnapshotPublication::NonTurnSync,
                        session,
                        space,
                        path,
                        &entries,
                    )?;
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
                    let confirmed =
                        offline::confirmed_directory(&session.root, session.base.as_str(), *id)?
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
                &session.root,
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
            #[cfg(target_os = "linux")]
            let count = rustix::rand::getrandom(
                &mut random[filled..],
                rustix::rand::GetRandomFlags::empty(),
            )
            .map_err(|_| AccountError::new("cannot generate conflict name"))?;
            #[cfg(target_os = "macos")]
            let count = ownership::file_ops::random(&mut random[filled..])
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
                &session.root,
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
            &session.root,
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
                    &session.root,
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
            &session.root,
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

    /// Inspects one Space's locally retained pins, without credentials or network access.
    ///
    /// # Errors
    /// Returns an error for invalid input, missing local identity or durable storage failure.
    pub fn pins_space(&self, instance: &str, space: &str) -> Result<Vec<PinInfo>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid Space ID"));
        }
        Ok(
            offline::pins(&self.storage_root()?, base.as_str(), space, true)?
                .into_iter()
                .map(|pin| PinInfo {
                    path: format!("/{}", pin.path.join("/")),
                    availability: pin_availability(pin.complete, pin.metadata_matches),
                    remote: PinRemoteEvidence::NotChecked,
                })
                .collect(),
        )
    }

    /// Compares retained pins with DAV in a freshly verified Space.
    ///
    /// # Errors
    /// Returns an error if the Space cannot be verified in the authenticated listing
    /// (including transport failure before verification) or retained state is unavailable.
    pub fn pins_space_check_remote(
        &self,
        instance: &str,
        space: &str,
    ) -> Result<Vec<PinInfo>, AccountError> {
        let (base, _) = http::instance_and_ca(instance, None)?;
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid Space ID"));
        }
        let binding = self.bind_space(base.as_str(), space)?;
        let session = self.read_session_in(
            &binding.root,
            base.as_str(),
            SessionAccess::BoundOnline(&binding),
        )?;
        let space = bound_space(&session, &binding)?;
        let mut output = Vec::new();
        for offline::Pin {
            path,
            tree,
            complete,
            metadata_matches,
        } in offline::pins(&session.root, session.base.as_str(), space, true)?
        {
            let availability = pin_availability(complete, metadata_matches);
            let remote = if matches!(availability, PinAvailability::Available) {
                match self.collect_pin_files(
                    &session.root,
                    session.base.as_str(),
                    &binding,
                    &path,
                    true,
                ) {
                    Ok(current) if current == tree => PinRemoteEvidence::Matches,
                    Ok(_) => PinRemoteEvidence::Changed,
                    Err(error) if error.network => PinRemoteEvidence::Unavailable,
                    Err(error)
                        if error
                            .message
                            .starts_with("offline metadata changed during pinning") =>
                    {
                        PinRemoteEvidence::Inconclusive
                    }
                    Err(_) => PinRemoteEvidence::CouldNotVerify,
                }
            } else {
                PinRemoteEvidence::NotChecked
            };
            output.push(PinInfo {
                path: format!("/{}", path.join("/")),
                availability,
                remote,
            });
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
        self.storage.validate(&binding.root)?;
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
            offline::verify_identity_in(
                &binding.root,
                &binding.instance,
                &binding.issuer,
                &binding.subject,
            )?;
            let current = offline::staged_version(
                &binding.root,
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
        self.read_range_in(&binding.root, binding, version, offset, length)
    }

    fn read_range_in(
        &self,
        root: &account_storage::StorageRoot,
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
        if root.identity() != binding.root.identity() {
            return Err(AccountError::new("account storage root changed"));
        }
        self.storage.validate(root)?;
        let cache_generation = self.clean_cache_generation();
        if binding.offline {
            self.verify_file(binding, version)?;
            let bytes = self.read_offline_range(binding, version, offset, length)?;
            self.verify_offline_mount(binding)?;
            return Ok(bytes);
        }
        if version.id.starts_with("cirrus-staged:") {
            // Match cached staged reads: the verified mount principal and exact
            // live snapshot authorize local bytes, not a credential-cache hit.
            // Missing original ranges still take the authenticated path below.
            self.check_cancelled()?;
            self.verify_file(binding, version)?;
            let (current, staged) = offline::staged_version(
                root,
                &version.instance,
                &version.space,
                &version.path,
                &version.id,
            )?
            .ok_or_else(|| AccountError::new("staged file is unavailable"))?;
            if &current != version {
                return Err(AccountError::new("staged file changed"));
            }
            let snapshot = offline::StagedSnapshot::open_at(root, &staged)?;
            if snapshot.len() != version.size {
                return Err(AccountError::new("staged file changed"));
            }
            return snapshot.range_with(offset, length, |base, offset, length| {
                self.read_range_in(root, binding, base, offset, length)
            });
        }
        let access = SessionAccess::BoundSaved(binding);
        let session = self.read_session_in(root, &version.instance, access);
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_RETAINED_SH_OWNER").is_some()
            && let Err(error) = &session
        {
            eprintln!(
                "cirrus lab owner read: pid={} thread={:?} boundary=read-session staged={} error={error}",
                std::process::id(),
                std::thread::current().id(),
                version.id.starts_with("cirrus-staged:")
            );
        }
        let session = session?;
        if bound_space(&session, binding)? != version.space {
            return Err(AccountError::new(
                "file version does not match mounted Space",
            ));
        }
        let (_, move_fenced) = offline::tree_remote_path(
            &session.root,
            &version.instance,
            &version.space,
            &version.path,
        )?;
        if move_fenced {
            return offline::read(&binding.root, version, offset, length);
        }
        let disk_generation = cache::generation_in(&session.root).ok();
        if let Ok(Some(bytes)) = cache::read(&session, version, offset, length) {
            self.verify_file(binding, version)?;
            return Ok(bytes);
        }
        if let Some(origin) = self.moved_cache_version(
            &session.root,
            version,
            &session.account.issuer,
            &session.account.subject,
        )? && let Some(bytes) = cache::read(&session, &origin, offset, length)?
        {
            self.verify_file(binding, version)?;
            return Ok(bytes);
        }
        match self.read_range_online(binding, version, offset, length, true) {
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
                offline::read(&session.root, version, offset, length).map_err(|_| error)
            }
            Err(error) => Err(error),
        }
    }

    // A queued MOVE does not rewrite the separate clean-cache database. Alias
    // only its proven original path, with every other FileVersion field exact.
    fn moved_cache_version(
        &self,
        storage: &account_storage::StorageRoot,
        version: &FileVersion,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<FileVersion>, AccountError> {
        if !offline::tree_destination_contains(
            storage,
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
            storage,
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
            offline::tree_remote_path(storage, &version.instance, &version.space, &version.path)?;
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
                &binding.root,
                &version.instance,
                &version.space,
                &version.path,
                &version.id,
            )?
            .ok_or_else(|| AccountError::new("offline staged file unavailable"))?;
            if current != *version {
                return Err(AccountError::new("offline staged version changed"));
            }
            return offline::StagedSnapshot::open_at(&binding.root, &staged)?.range_with(
                offset,
                length,
                |base, offset, length| {
                    self.read_original_local_range(
                        &binding.root,
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
        if let Some(bytes) = cache::read_identity_in(
            &binding.root,
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
            self.moved_cache_version(&binding.root, version, &binding.issuer, &binding.subject)?
            && let Some(bytes) = cache::read_identity_in(
                &binding.root,
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
        if let Some(bytes) = offline::confirmed_local_range(&binding.root, version, offset, length)?
        {
            return Ok(bytes);
        }
        if let Some(bytes) = offline::read_moved_local(&binding.root, version, offset, length)? {
            return Ok(bytes);
        }
        offline::read(&binding.root, version, offset, length)
    }

    // Only immutable overlay bases use this route. A projected staged head is
    // not evidence against already verified original bytes, nor permission to
    // fetch a newer remote representation at its pathname.
    fn read_original_local_range(
        &self,
        storage: &account_storage::StorageRoot,
        issuer: &str,
        subject: &str,
        version: &FileVersion,
        offset: u64,
        length: u32,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        offline::verify_identity_in(storage, &version.instance, issuer, subject)?;
        let original = offline::tree_content_base(storage, version)?;
        for candidate in original
            .iter()
            .filter(|original| *original != version)
            .chain(std::iter::once(version))
        {
            if let Some(bytes) =
                cache::read_identity_in(storage, issuer, subject, candidate, offset, length, false)?
            {
                return Ok(Some(bytes));
            }
            if let Some(bytes) = offline::confirmed_local_range(storage, candidate, offset, length)?
            {
                return Ok(Some(bytes));
            }
            if let Some(bytes) = offline::read_moved_local(storage, candidate, offset, length)? {
                return Ok(Some(bytes));
            }
            if let Ok(bytes) = offline::read(storage, candidate, offset, length) {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    fn read_range_online(
        &self,
        binding: &MountBinding,
        version: &FileVersion,
        offset: u64,
        length: u32,
        allow_saved: bool,
    ) -> Result<(Vec<u8>, DirectorySnapshot), AccountError> {
        if length == 0 || length > 131_072 || offset >= version.size {
            return Err(AccountError::new("invalid file range"));
        }
        let end = offset
            .checked_add(u64::from(length) - 1)
            .filter(|end| *end < version.size)
            .ok_or_else(|| AccountError::new("invalid file range"))?;
        let _permit = self.read_permit()?;
        let access = SessionAccess::for_space(binding, allow_saved);
        let session = self.read_session_in(&binding.root, &version.instance, access)?;
        if bound_space(&session, binding)? != version.space {
            return Err(AccountError::new("file version does not match Space"));
        }
        self.read_with_refresh(&session, access, |current| {
            let (remote_path, move_fenced) = offline::tree_remote_path(
                &current.root,
                current.base.as_str(),
                &version.space,
                &version.path,
            )?;
            if move_fenced {
                return Err(AccountError::new("directory rename requires attention"));
            }
            let (name, parent) = remote_path
                .split_last()
                .ok_or_else(|| AccountError::new("invalid file path"))?;
            let verify = || {
                let entries = dav::directory_snapshot_in(
                    &current.root,
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
        access: SessionAccess<'_>,
        mut read: impl FnMut(&ReadSession) -> Result<T, AccountError>,
    ) -> Result<T, AccountError> {
        let result = match read(session) {
            Err(error) if error.unauthorized => self
                .refresh_rejected_session(session, access)
                .and_then(|renewed| read(&renewed))
                .map_err(|mut error| {
                    // Neither a failed refresh nor its retry converts a confirmed 401 to offline.
                    error.network = false;
                    error
                }),
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
        access: SessionAccess<'_>,
    ) -> Result<Arc<ReadSession>, AccountError> {
        let guard = if executor::is_automatic() {
            // Yield/back off instead of waiting behind a foreground account
            // owner at this newly released turn boundary.
            executor::preflight_checkpoint()?;
            self.begin_operation_in(&rejected.root)?
        } else {
            let lock = self
                .operation
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            self.operation_with_lock_in(lock, &rejected.root)?
        };
        if guard.storage_root()?.identity() != rejected.root.identity() {
            return Err(AccountError::new("account session storage root changed"));
        }
        self.clear_read_session()?;
        let store = Store::open(guard.credential_context()?)?;
        guard.persist_pending(&store, rejected.base.as_str())?;
        let mut account = store.load(rejected.base.as_str())?;
        if account.issuer != rejected.account.issuer || account.subject != rejected.account.subject
        {
            return Err(AccountError::new("account changed; retry the operation"));
        }
        access.check(&rejected.root, &rejected.base, &account)?;
        offline::verify_identity_in(
            &rejected.root,
            rejected.base.as_str(),
            &account.issuer,
            &account.subject,
        )?;
        let client = http::client(account.ca_pem.as_deref().map(str::as_bytes))?;
        if account.access_token == rejected.account.access_token {
            account.expires_at = 0;
        }
        self.check_cancelled()?;
        executor::preflight_checkpoint()?;
        self.refresh_if_needed(&mut account, &store, &client)?;
        self.check_cancelled()?;
        let session = Arc::new(ReadSession {
            root: guard.storage_root()?.clone(),
            base: rejected.base.clone(),
            account,
            client,
        });
        self.publish_read_session(&guard, Arc::clone(&session))?;
        Ok(session)
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
        if let Some(window) = active.as_ref() {
            let cached = self
                .read_session
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            let current = cached
                .as_ref()
                .ok_or_else(|| AccountError::new("account session is unavailable"))?;
            if current.root.identity() != session.root.identity()
                || current.base != session.base
                || current.account.issuer != session.account.issuer
                || current.account.subject != session.account.subject
                || window.root.identity() != session.root.identity()
                || window.base != session.base
                || window.account.issuer != session.account.issuer
                || window.account.subject != session.account.subject
            {
                return Err(AccountError::new("mounted account identity changed"));
            }
            Ok(LocalOperation::Staging { _lease: active })
        } else {
            drop(active);
            Ok(LocalOperation::Owned {
                _operation: if allow_shared_staging {
                    self.begin_shared_staging_operation(session)?
                } else {
                    OwnedLocalOperation::Exclusive(self.begin_owned_local_operation(session)?)
                },
            })
        }
    }

    fn begin_owned_local_operation(
        &self,
        session: &ReadSession,
    ) -> Result<Operation<'_>, AccountError> {
        let operation = if executor::is_automatic() {
            let lock = self.operation.try_lock().map_err(|_| {
                AccountError::retryable_read("another account operation is in progress")
            })?;
            self.operation_with_principal_lock_in(lock, &session.root, true)?
        } else {
            self.begin_operation_in(&session.root)?
        };
        if operation.storage_root()?.identity() != session.root.identity() {
            return Err(AccountError::new("account session storage root changed"));
        }
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_OWNED_LOCAL_PERSIST_WINDOW")?;
        let store = Store::open(operation.credential_context()?)?;
        operation.persist_pending(&store, session.base.as_str())?;
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_OWNED_LOCAL_OWNER_WINDOW")?;
        // Automatic refresh may have retained SH plus the credential bus
        // owner after a failed save. Persistence above must succeed before
        // relinquishing that fence, but saving does not turn SH into EX.
        // Refuse this turn: Drop releases only durably saved credentials;
        // retry acquires fresh nonblocking EX and revalidates the session.
        // Never attempt a flock upgrade while holding SH.
        if !operation
            .guard
            .as_ref()
            .is_some_and(ownership::Guard::is_exclusive)
        {
            return Err(AccountError::retryable_read(
                "saved credentials require fresh exclusive local ownership; retry local operation",
            ));
        }
        let account = store.load(session.base.as_str())?;
        offline::bind_identity_in(
            &session.root,
            session.base.as_str(),
            &account.issuer,
            &account.subject,
        )?;
        if account.issuer != session.account.issuer || account.subject != session.account.subject {
            return Err(AccountError::new("mounted account identity changed"));
        }
        #[cfg(feature = "fault-injection")]
        wait_test_window("CIRRUS_TEST_OWNED_LOCAL_EXCLUSIVE_WINDOW")?;
        Ok(operation)
    }

    fn begin_shared_staging_operation(
        &self,
        session: &ReadSession,
    ) -> Result<OwnedLocalOperation<'_>, AccountError> {
        let owner = if self.has_pending_credentials()? {
            OwnedLocalOperation::Exclusive(self.begin_owned_local_operation(session)?)
        } else {
            OwnedLocalOperation::Shared(ownership::acquire_shared_in(
                &session.root,
                &self.runtime,
                #[cfg(target_os = "macos")]
                self.keychain.as_ref(),
            )?)
        };
        let connection = match &owner {
            OwnedLocalOperation::Shared(guard) => guard.credential_context(),
            OwnedLocalOperation::Exclusive(operation) => operation.credential_context()?,
        };
        let store = Store::open(connection)?;
        let account = store.load(session.base.as_str())?;
        offline::bind_identity_in(
            &session.root,
            session.base.as_str(),
            &account.issuer,
            &account.subject,
        )?;
        if account.issuer != session.account.issuer || account.subject != session.account.subject {
            return Err(AccountError::new("mounted account identity changed"));
        }
        Ok(owner)
    }

    fn begin_operation(&self) -> Result<Operation<'_>, AccountError> {
        let root = self.storage_root()?;
        self.begin_operation_in(&root)
    }

    fn begin_operation_in(
        &self,
        root: &account_storage::StorageRoot,
    ) -> Result<Operation<'_>, AccountError> {
        if self.automatic_active.load(Ordering::Acquire) != 0 && !executor::is_automatic_for(self) {
            return self.wait_for_automatic_turn_in(root);
        }
        let lock = self.operation.try_lock().map_err(|_| {
            AccountError::retryable_read("another account operation is in progress")
        })?;
        self.operation_with_lock_in(lock, root)
    }

    fn operation_with_lock_in<'a>(
        &'a self,
        lock: MutexGuard<'a, ()>,
        root: &account_storage::StorageRoot,
    ) -> Result<Operation<'a>, AccountError> {
        self.operation_with_principal_lock_in(lock, root, false)
    }

    fn operation_with_principal_lock_in<'a>(
        &'a self,
        lock: MutexGuard<'a, ()>,
        root: &account_storage::StorageRoot,
        local: bool,
    ) -> Result<Operation<'a>, AccountError> {
        self.runtime
            .revalidate()
            .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
        let retained = {
            let mut credentials = self
                .credentials
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            match &*credentials {
                CredentialState::Idle => None,
                CredentialState::Active(_) => {
                    return Err(AccountError::new("account ownership is unavailable"));
                }
                CredentialState::Retained { guard, .. }
                    if guard.storage_root().identity() != root.identity() =>
                {
                    return Err(AccountError::new("retained account ownership root changed"));
                }
                CredentialState::Retained { .. } => {
                    let CredentialState::Retained { pending, guard } =
                        std::mem::replace(&mut *credentials, CredentialState::Idle)
                    else {
                        unreachable!();
                    };
                    *credentials = CredentialState::Active(pending);
                    Some(guard)
                }
            }
        };
        if let Some(guard) = retained {
            // Reconnect may fail. Operation already owns the guard so Drop
            // restores pending credentials and that same fence together.
            let mut operation = Operation {
                accounts: self,
                lock: Some(lock),
                guard: Some(guard),
            };
            operation
                .guard
                .as_mut()
                .ok_or_else(|| AccountError::new("account ownership is unavailable"))?
                .reconnect()?;
            return Ok(operation);
        }
        let guard = if local {
            ownership::acquire_local_in(
                root,
                &self.runtime,
                #[cfg(target_os = "macos")]
                self.keychain.as_ref(),
            )?
        } else {
            ownership::acquire_in(
                root,
                &self.runtime,
                #[cfg(target_os = "macos")]
                self.keychain.as_ref(),
            )?
        };
        *self
            .credentials
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))? =
            CredentialState::Active(HashMap::new());
        Ok(Operation {
            accounts: self,
            lock: Some(lock),
            guard: Some(guard),
        })
    }

    fn clear_read_session(&self) -> Result<(), AccountError> {
        let retired = self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?
            .take();
        drop(retired);
        Ok(())
    }

    fn invalidate_read_session(&self, expected: &Arc<ReadSession>) -> Result<(), AccountError> {
        let retired = {
            let mut cached = self
                .read_session
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            if cached
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, expected))
            {
                cached.take()
            } else {
                None
            }
        };
        drop(retired);
        Ok(())
    }

    fn publish_read_session(
        &self,
        operation: &Operation<'_>,
        session: Arc<ReadSession>,
    ) -> Result<(), AccountError> {
        if operation.storage_root()?.identity() != session.root.identity() {
            return Err(AccountError::new("account session storage root changed"));
        }
        let retired = self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?
            .replace(session);
        drop(retired);
        Ok(())
    }

    fn storage_root(&self) -> Result<account_storage::StorageRoot, AccountError> {
        // Refuse changed default ownership before admitting another hierarchy;
        // do not take/discard a Guard that may still own unsaved credentials.
        let retained_root = {
            let credentials = self
                .credentials
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            match &*credentials {
                CredentialState::Retained { guard, .. } => Some(guard.storage_root().clone()),
                CredentialState::Idle | CredentialState::Active(_) => None,
            }
        };
        if let Some(root) = retained_root {
            root.revalidate()?;
        }
        let cached = self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?
            .clone();
        if let Some(session) = cached {
            self.storage.validate(&session.root)?;
        }
        self.storage.resolve()
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

    fn read_session_in(
        &self,
        root: &account_storage::StorageRoot,
        instance: &str,
        access: SessionAccess<'_>,
    ) -> Result<Arc<ReadSession>, AccountError> {
        self.storage.validate(root)?;
        self.check_cancelled()?;
        let (base, _) = http::instance_and_ca(instance, None)?;
        let usable = |session: &ReadSession| -> bool {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs());
            session.root.identity() == root.identity()
                && session.base == base
                && !session.account.refresh_in_progress
                && now.is_some_and(|now| session.account.expires_at > now.saturating_add(30))
        };
        let lock = loop {
            let cached = self
                .read_session
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            if cached
                .as_ref()
                .is_some_and(|session| session.root.identity() != root.identity())
            {
                return Err(AccountError::new("account session storage root changed"));
            }
            if let Some(session) = cached.as_ref().filter(|session| usable(session)) {
                #[cfg(feature = "fault-injection")]
                if std::env::var_os("CIRRUS_TEST_RETAINED_SH_OWNER").is_some() {
                    eprintln!(
                        "cirrus lab owner session: pid={} thread={:?} cache=usable boundary=identity-verify",
                        std::process::id(),
                        std::thread::current().id()
                    );
                }
                let session = session.clone();
                drop(cached);
                access.check(root, &base, &session.account)?;
                offline::verify_identity_in(
                    &root,
                    session.base.as_str(),
                    &session.account.issuer,
                    &session.account.subject,
                )?;
                return Ok(session);
            }
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_RETAINED_SH_OWNER").is_some() {
                eprintln!(
                    "cirrus lab owner session: pid={} thread={:?} cache=unusable present={} boundary=operation-mutex",
                    std::process::id(),
                    std::thread::current().id(),
                    cached.is_some()
                );
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
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_RETAINED_SH_OWNER").is_some() {
            eprintln!(
                "cirrus lab owner session: pid={} thread={:?} boundary=account-owner-acquire",
                std::process::id(),
                std::thread::current().id()
            );
        }
        let guard = self.operation_with_lock_in(lock, &root)?;
        if guard.storage_root()?.identity() != root.identity() {
            return Err(AccountError::new("account session storage root changed"));
        }
        let cached = self
            .read_session
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?
            .as_ref()
            .filter(|session| usable(session))
            .cloned();
        if let Some(session) = cached {
            access.check(root, &base, &session.account)?;
            offline::verify_identity_in(
                &root,
                session.base.as_str(),
                &session.account.issuer,
                &session.account.subject,
            )?;
            return Ok(session);
        }
        let store = Store::open(guard.credential_context()?)?;
        guard.persist_pending(&store, base.as_str())?;
        let mut account = store.load(base.as_str())?;
        access.check(root, &base, &account)?;
        if executor::is_automatic() {
            offline::verify_identity_in(&root, base.as_str(), &account.issuer, &account.subject)
                .map_err(|mut error| {
                    error.retryable_read = true;
                    error
                })?;
        } else {
            offline::bind_identity_in(&root, base.as_str(), &account.issuer, &account.subject)?;
        }
        let client = http::client(account.ca_pem.as_deref().map(str::as_bytes))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AccountError::new("system clock is invalid"))?
            .as_secs();
        // Probe before fencing a rotating refresh token, so an offline read
        // does not leave an otherwise valid account fenced after a lost refresh.
        let offline = if !account.refresh_in_progress
            && account.expires_at <= now.saturating_add(30)
        {
            let probe = |space| {
                dav::directory_snapshot_in(root, &base, space, &[], &account.access_token, &client)
            };
            match access {
                SessionAccess::BoundSaved(binding) => match probe(&binding.space) {
                    Ok(_) => false,
                    Err(error) if error.network => true,
                    Err(error) if error.unauthorized => false,
                    Err(error) => return Err(error),
                },
                SessionAccess::Online | SessionAccess::BoundOnline(_) => {
                    // Automatic refresh already performs this check under its own turn.
                    if !executor::is_automatic() {
                        self.probe_refresh_listing(&base, &account, &client)?;
                    }
                    false
                }
            }
        } else {
            false
        };
        if !offline {
            self.refresh_if_needed(&mut account, &store, &client)?;
        }
        self.check_cancelled()?;
        let session = Arc::new(ReadSession {
            root: guard.storage_root()?.clone(),
            base,
            account,
            client,
        });
        self.publish_read_session(&guard, Arc::clone(&session))?;
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
        let credentials = self
            .credentials
            .lock()
            .map_err(|_| AccountError::new("account state is unavailable"))?;
        Ok(match &*credentials {
            CredentialState::Idle => false,
            CredentialState::Active(pending) | CredentialState::Retained { pending, .. } => {
                !pending.is_empty()
            }
        })
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
            let mut credentials = self
                .credentials
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?;
            let CredentialState::Active(pending) = &mut *credentials else {
                return Err(AccountError::new("account ownership is unavailable"));
            };
            pending.insert(account.instance.clone(), account.clone());
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
    fn probe_refresh_listing(
        &self,
        base: &Url,
        account: &AccountData,
        client: &reqwest::blocking::Client,
    ) -> Result<(), AccountError> {
        match list_spaces(base, &account.access_token, client, &self.cancelled) {
            Ok(_) => Ok(()),
            Err(error) if error.unauthorized => Ok(()),
            Err(error) => Err(error),
        }
    }

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
            self.probe_refresh_listing(&base, account, client)?;
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

fn unique_space_name(spaces: &[Space], id: &str) -> Result<Option<String>, AccountError> {
    let found = spaces
        .iter()
        .find(|space| space.id == id)
        .ok_or_else(|| AccountError::new("requested Space is not in the authenticated listing"))?;
    Ok((spaces
        .iter()
        .filter(|space| space.name == found.name)
        .count()
        == 1)
        .then(|| found.name.clone()))
}

fn explicit_space_binding(session: &ReadSession, id: &str, name: Option<String>) -> MountBinding {
    MountBinding {
        root: session.root.clone(),
        instance: session.base.to_string(),
        space: id.to_owned(),
        name,
        issuer: session.account.issuer.clone(),
        subject: session.account.subject.clone(),
        offline: false,
        offline_writable: false,
    }
}

pub(crate) enum GraphListingError {
    InitialTransport(AccountError),
    Other(AccountError),
}

impl From<AccountError> for GraphListingError {
    fn from(error: AccountError) -> Self {
        Self::Other(error)
    }
}

impl GraphListingError {
    fn into_account_error(self) -> AccountError {
        match self {
            Self::InitialTransport(error) | Self::Other(error) => error,
        }
    }
}

fn list_spaces(
    base: &Url,
    access_token: &str,
    client: &reqwest::blocking::Client,
    cancelled: &AtomicBool,
) -> Result<Vec<Space>, AccountError> {
    graph_listing(base, access_token, client, cancelled)
        .map_err(GraphListingError::into_account_error)
}

fn graph_listing(
    base: &Url,
    access_token: &str,
    client: &reqwest::blocking::Client,
    cancelled: &AtomicBool,
) -> Result<Vec<Space>, GraphListingError> {
    let mut url = base
        .join("/graph/v1.0/me/drives")
        .map_err(|_| AccountError::new("invalid OpenCloud instance"))?;
    let mut spaces: Vec<Space> = Vec::new();
    for page in 0..32 {
        executor::preflight_checkpoint()?;
        if cancelled.load(Ordering::Acquire) {
            return Err(AccountError::new("account operation cancelled by daemon shutdown").into());
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
                return Err(AccountError::new("Space listing contains invalid fields").into());
            }
            spaces.push(Space {
                id: row.id,
                name: row.name,
            });
            if spaces.len() > 1024 {
                return Err(AccountError::new("Space listing exceeds the limit").into());
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
            return Err(AccountError::new("untrusted Space pagination link").into());
        }
    }
    Err(AccountError::new("Space listing exceeds the page limit").into())
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

fn pin_availability(complete: bool, metadata_matches: bool) -> PinAvailability {
    if !complete {
        PinAvailability::Incomplete
    } else if !metadata_matches {
        PinAvailability::StaleLocalMetadata
    } else {
        PinAvailability::Available
    }
}

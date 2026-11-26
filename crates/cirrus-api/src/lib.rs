//! Typed values exchanged by the Cirrus user service and its clients.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Linux resident release-control operations, independently negotiated from account IPC.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReleaseRequest {
    Status,
    MountEngines,
    Activate { release: String },
    Rollback,
    CredentialPolicy(CredentialPolicyRequest),
}

/// Resident-contained Linux automatic credential writer profiles (ABI 1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialPolicy {
    /// One second per method on an automatic writer connection.
    #[default]
    StandardV1,
    /// Two seconds per method on an automatic writer connection.
    SlowKeyringV1,
}

/// Independent signed credential-policy selection on the existing release endpoint.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CredentialPolicyRequest {
    Status,
    Activate { release: String },
    Rollback,
}

/// Live mounted read-planning identity and mount-local observations.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountEngineReport {
    /// Active engine for all live mounts in this resident.
    pub read_engine: RunningReadEngine,
    /// No inventory while mount publication or removal is in progress.
    pub mounts: Option<Vec<MountEngine>>,
}

/// Identity of the active staged-read planning program, not the FUSE transport.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunningReadEngine {
    /// Signed release supplying the program; absent for the built-in exact engine.
    pub release: Option<String>,
    /// Hash of the exact validated program, if supplied by a release.
    pub sha256: Option<String>,
    /// Monotonic generation in this resident, including rollback to built-in.
    pub generation: u64,
}

/// One live mount using the report's read engine.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountEngine {
    pub path: String,
    pub instance: String,
    pub space: String,
    /// Cumulative successful staged reads composed from existing cached ranges.
    pub composed_reads: u64,
}

/// Resident-observed activation state. A selected set is not proof of a live worker.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseStatus {
    /// Whether this resident owns a signed user install.
    pub managed: bool,
    /// Install directory device and inode observed by this resident.
    pub installation: Option<String>,
    /// PID that continues to own the runtime endpoint and all mounts.
    pub resident_pid: u32,
    /// Version of the running resident, independent of release selection.
    pub resident_version: String,
    /// Digest of the executable inode currently running, when managed.
    pub resident_sha256: Option<String>,
    /// Durable set used for new client processes; may have no live worker.
    pub selected_release: Option<String>,
    /// Previous durable set available for a verified rollback attempt.
    pub previous_release: Option<String>,
    /// Worker currently serving policy, absent if disabled or paused.
    pub worker: Option<RunningWorker>,
    /// A negotiated replacement is waiting for the resident policy turn boundary.
    pub draining_policy_turn: bool,
    /// Whether automatic transfer scheduling is enabled and has a worker if managed.
    pub automatic_sync: bool,
    /// The selected set cannot replace the different running resident live.
    pub resident_update_pending: bool,
    /// Observed pause or persistence diagnostic, if any.
    pub note: Option<String>,
}

/// Identity of the currently negotiated worker, not a staged artifact.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunningWorker {
    /// Signed release that supplied this process's policy executable.
    pub release: String,
    /// Digest of the verified executable bytes.
    pub sha256: String,
    /// Worker process ID, not the resident PID.
    pub pid: u32,
    /// Monotonic fence within this resident process.
    pub generation: u64,
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

/// Unique observed filesystem inodes, not logical overlay EOF or SQL payload bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageUsage {
    /// Number of unique observed inodes in this category.
    pub objects: u64,
    /// Sum of st_size; sparse holes are included, shared references are not added.
    pub logical_bytes: u64,
    /// Sum of st_blocks * 512, including fallocated blocks; not added to logical bytes.
    pub allocated_bytes: u64,
}

/// Local account-owner-wide measurement across all configured accounts/Spaces.
/// Categories are disjoint filesystem inode measurements; SQL counts below are
/// informational subsets of database contents, never extra physical usage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageStatus {
    pub namespace_reservations: Vec<NamespaceStorageReservation>,
    /// Lifetime ceilings less only known local materialization. Other-process
    /// or inactive allocation is unknown, so its entire ceiling remains here.
    pub namespace_outstanding_reserved_bytes: u64,
    /// Durable per-store ceilings, including inactive crash leftovers.
    pub sql_reservations: Vec<SqlStorageReservation>,
    /// Sum of max(ceiling - observed DB/WAL/SHM/journal allocation, 0).
    pub sql_outstanding_reserved_bytes: u64,
    pub storage_limits: Option<StorageLimitsView>,
    pub storage_limits_error: Option<String>,
    /// Shared admission charge, including SQL outstanding allowances. The name
    /// is retained from the original immutable-only admission view.
    pub immutable_admission_charge_bytes: u64,
    pub filesystem_fragment_bytes: u64,
    pub scope: String,
    pub observational_not_atomic: bool,
    pub scan_entry_limit: u64,
    pub vanished_entries: u64,
    pub staging: StorageUsage,
    /// Directory names, including aliases; unlike staging.objects this is not inode-deduplicated.
    pub staging_named_entries: u64,
    pub state_sqlite: StorageUsage,
    pub cache_sqlite: StorageUsage,
    pub named_namespace_scratch: StorageUsage,
    pub named_pin_scratch: StorageUsage,
    pub other_named_files: StorageUsage,
    pub directories: StorageUsage,
    pub daemon_directory_scratch: StorageUsage,
    pub daemon_pin_scratch: StorageUsage,
    pub named_total: StorageUsage,
    pub known_total: StorageUsage,
    /// Other processes and SQLite/internal anonymous temp files are not measured.
    pub anonymous_storage_globally_complete: bool,
    /// False if this process's bounded scratch tracker ever omitted a file.
    /// Constructors and SQLite's internal temp files are outside that tracker.
    pub daemon_scratch_tracking_complete: bool,
    /// Rounded outstanding requests in this daemon, overlapping named allocation.
    pub daemon_staging_reserved_bytes: u64,
    /// Only the unmatched remainder; do not add reserved_bytes to named totals.
    pub daemon_staging_unmaterialized_reserved_bytes: u64,
    /// Deduplicated visibility estimate: max(st_size, allocated) per inode plus
    /// unmatched daemon reservations. The locked allocator remains authoritative
    /// and conservatively charges every name if unexpected hard links exist.
    pub observed_staging_charge_bytes: u64,
    pub staging_byte_limit: u64,
    pub staging_file_limit: u64,
    pub registered_dirty_roots: u64,
    /// Stored chunk-row body bytes in state.db, not a per-Space unique footprint.
    pub pin_payload_bytes: u64,
    pub pin_chunks: u64,
    pub pins: u64,
    /// Stored range bodies in cache.db, already included in its filesystem usage.
    pub clean_payload_bytes: u64,
    pub clean_ranges: u64,
    /// f_bavail * f_frsize for the stores' filesystem; not guaranteed/reserved.
    pub filesystem_available_bytes: u64,
}

/// User-chosen bytes, shared by cooperating daemons for this account owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageLimits {
    pub budget_bytes: u64,
    pub free_space_reserve_bytes: u64,
}

/// Explicit enforcement coverage; a configured policy is not a hard global cap.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageLimitsView {
    pub limits: Option<StorageLimits>,
    pub enforcement: String,
    pub hard_global_limit: bool,
    pub automatic_reclamation: String,
}

/// Conservative per-owner disk allowance, not an exact global physical total.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NamespaceStorageReservation {
    pub token: String,
    pub device: u64,
    pub inode: u64,
    pub ceiling_bytes: u64,
    /// None means other-process or inactive materialization is unknown.
    pub known_local_allocated_bytes: Option<u64>,
    pub outstanding_reserved_bytes: u64,
}

/// Shared pending disk allowance, not additional physical allocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqlStorageReservation {
    pub store: String,
    pub token: String,
    pub ceiling_bytes: u64,
    pub store_allocated_bytes: u64,
    pub outstanding_bytes: u64,
    pub pin_scratch_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncPhase {
    Queued,
    Uploading,
    Verifying,
    Retry,
    Attention,
    ObservedIdle,
}

/// Bounded local-only status for one persistently activated immutable Space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Canonical instance URL for this observation.
    pub instance: String,
    /// Immutable Space ID, independent of selection.
    pub space: String,
    /// Whether a verified mount durably activated this Space.
    pub activated: bool,
    /// Whether the responding daemon runs its automatic worker; absent in account-only calls.
    pub worker_enabled_here: Option<bool>,
    /// Current local scheduling observation, not remote reconciliation status.
    pub phase: SyncPhase,
    /// Pending journal operations, including dependency waiters.
    pub queued: u64,
    /// Live PUTs owned by this daemon; other-daemon unconfirmed PUTs stay conservative.
    pub uploading: u64,
    /// Successful mutation receipts awaiting read-only verification.
    pub verifying: u64,
    /// Unknown mutation outcomes without a successful receipt.
    pub uncertain: u64,
    /// Journaled conflicts requiring inspection.
    pub conflicts: u64,
    /// Invalid journal entries or missing/mismatched local activation identity.
    pub damaged: u64,
    /// Consecutive safe-read/local-capacity retry attempts, capped at 16.
    pub retry_attempt: u32,
    /// Earliest admitted retry, in Unix seconds; an expired value is not proof it ran.
    pub next_attempt: Option<i64>,
    /// Safe-to-display reason; scheduler policy never parses this string.
    pub cause: Option<String>,
    /// Unix seconds of the most recently verified journal operation, historical only.
    pub last_verified: Option<i64>,
    /// Highest currently observed journal ID in this Space.
    pub high_water: i64,
    /// Journal ID observed through a locally idle pass, not a remote consistency watermark.
    pub verified_through: i64,
    /// Local unresolved work or journal growth since that idle observation.
    pub new_work: bool,
}

/// Outcome of one write executor turn, not whole-Space sync status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WriteTurnOutcome {
    /// No unresolved work remains in the requested Space.
    Idle,
    /// Progress was made or a transfer budget expired; call again to continue.
    Yielded,
    /// Namespace or conflict-copy work needs the ordinary explicit sync executor.
    Dependencies,
    /// A conflict, rejected upload or ambiguous outcome needs user attention.
    Attention,
    /// A read-only request or local continuation checkpoint failed; retry is safe.
    Retry,
}

/// A validated immediate child of an explicitly identified Space directory.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedPin {
    /// Space ID.
    pub space: String,
    /// Pin root components.
    pub root: Vec<String>,
}

/// A retained file from an explicitly named pin, not necessarily current remotely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedPinFile {
    /// Space path components.
    pub path: Vec<String>,
    /// Opaque version selector.
    pub selector: String,
    /// Stored length when valid metadata is available.
    pub size: Option<u64>,
    /// Original retained version metadata, not a statement of its validity.
    pub version: serde_json::Value,
}

/// An immutable displaced pin capture, independent of namespace paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedPinCopy {
    /// Stable local capture ID, independent of any active path.
    pub id: i64,
    /// Original immutable Space ID.
    pub space: String,
    /// Original captured logical root, not a live namespace binding.
    pub root: Vec<String>,
    /// Whether the captured root was a directory.
    pub is_directory: bool,
    /// Replacement target path at capture admission.
    pub displaced_path: Vec<String>,
    /// Resource ID from the separate replacement-admission proof.
    pub target_id: String,
    /// Strong ETag from the separate replacement-admission proof.
    pub target_etag: String,
    /// Limits of the captured evidence.
    pub status: String,
}

/// A directory identity or exportable file version in a retained pin capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Captured file-version evidence, absent for directories.
    pub version: Option<serde_json::Value>,
    /// Limits of the captured directory evidence.
    pub status: Option<String>,
}

/// A page whose continuation was computed by the local snapshot reader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedPage<T> {
    pub entries: Vec<T>,
    pub next_offset: Option<u32>,
}

/// An authenticated Space reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceInfo {
    pub id: String,
    pub name: String,
}

/// Availability of the retained copy, independent of checks against the server.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PinAvailability {
    Incomplete,
    StaleLocalMetadata,
    Available,
}

/// Remote comparison evidence for a locally retained pin.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PinRemoteEvidence {
    NotChecked,
    Matches,
    Changed,
    Unavailable,
    Inconclusive,
    CouldNotVerify,
}

/// One pin's local availability and separately observed remote evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinInfo {
    pub path: String,
    pub availability: PinAvailability,
    pub remote: PinRemoteEvidence,
}

impl PinInfo {
    /// Compatibility text for the established tab-separated CLI output.
    pub fn status(&self, remote_requested: bool) -> &'static str {
        use PinAvailability::*;
        use PinRemoteEvidence::*;
        match (self.availability, self.remote, remote_requested) {
            (Incomplete, _, false) => "incomplete (local state; remote not checked)",
            (StaleLocalMetadata, _, false) => "stale (local metadata; remote not checked)",
            (Available, _, false) => "available offline (local state; remote not checked)",
            (Incomplete, _, true) => "incomplete",
            (StaleLocalMetadata, _, true) => "stale",
            (Available, Matches, true) => "available offline",
            (Available, Changed | CouldNotVerify, true) => "stale",
            (Available, Inconclusive, true) => "unknown",
            (Available, Unavailable | NotChecked, true) => "available offline",
        }
    }

    /// Diagnostic for an attempted run that could not provide comparison evidence.
    pub fn remote_diagnostic(&self) -> Option<&'static str> {
        match self.remote {
            PinRemoteEvidence::NotChecked => Some("remote not checked; only local pin status"),
            PinRemoteEvidence::Unavailable => {
                Some("remote check unavailable; only local pin status")
            }
            PinRemoteEvidence::Inconclusive => {
                Some("remote comparison inconclusive; local state changed")
            }
            PinRemoteEvidence::CouldNotVerify => Some("remote version could not be verified"),
            PinRemoteEvidence::Matches | PinRemoteEvidence::Changed => None,
        }
    }
}

/// A typed outcome of one successfully handled account operation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum AccountReply {
    Done,
    Spaces(Vec<SpaceInfo>),
    Entries(Vec<DirectoryEntry>),
    Pins(Vec<PinInfo>),
    Journal(JournalPage),
    SyncStatus(SyncStatus),
    CleanCacheStatus(CleanCacheStatus),
    StorageStatus(StorageStatus),
    StorageLimits(StorageLimitsView),
    Mounted(MountedSpace),
    Mounts(Vec<MountInfo>),
    RetainedPins(RetainedPage<RetainedPin>),
    RetainedFiles(RetainedPage<RetainedPinFile>),
    RetainedStaged(RetainedPage<RetainedStaged>),
    PinCopies(RetainedPage<RetainedPinCopy>),
    PinCopyEntries(RetainedPage<RetainedPinCopyEntry>),
    LabUploadOutcome(WriteTurnOutcome),
}

/// Wire envelope; clients require exactly one of reply and error.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountResponse {
    pub error: Option<String>,
    pub reply: Option<AccountReply>,
}

impl From<Result<AccountReply, String>> for AccountResponse {
    fn from(result: Result<AccountReply, String>) -> Self {
        match result {
            Ok(reply) => Self {
                error: None,
                reply: Some(reply),
            },
            Err(error) => Self {
                error: Some(error),
                reply: None,
            },
        }
    }
}

/// Effective mode and path after mount publication.
#[derive(Debug, Serialize, Deserialize)]
pub struct MountedSpace {
    pub path: String,
    pub mode: MountMode,
    pub automatic_sync_enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MountMode {
    Online,
    OfflineReadOnly,
    OfflineWritable,
}

/// Space-relative components, not a host filesystem path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpacePath(Vec<String>);

impl SpacePath {
    /// Split on slashes without normalizing or hiding invalid components.
    pub fn from_slash_separated(value: &str) -> Self {
        let value = value.strip_prefix('/').unwrap_or(value);
        if value.is_empty() {
            Self::default()
        } else {
            Self(value.split('/').map(str::to_owned).collect())
        }
    }

    pub fn components(&self) -> &[String] {
        &self.0
    }
}

impl From<Vec<String>> for SpacePath {
    fn from(components: Vec<String>) -> Self {
        Self(components)
    }
}

/// Local storage whose explicitly selected reservation may be released.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReservationStore {
    State,
    Cache,
    Namespace,
}

impl ReservationStore {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Cache => "cache",
            Self::Namespace => "namespace",
        }
    }
}

impl std::str::FromStr for ReservationStore {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "state" => Ok(Self::State),
            "cache" => Ok(Self::Cache),
            "namespace" => Ok(Self::Namespace),
            _ => Err("expected state, cache or namespace"),
        }
    }
}

/// Private local IPC request. Authoritative validation still runs in the service.
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum AccountRequest {
    Connect {
        instance: String,
        ca_pem: Option<String>,
        attempt: String,
    },
    CancelConnect {
        attempt: String,
    },
    Spaces {
        instance: String,
    },
    DirectorySpace {
        instance: String,
        space: String,
        path: SpacePath,
    },
    OfflineDirectory {
        instance: String,
        space: String,
        path: SpacePath,
    },
    PinSpace {
        instance: String,
        space: String,
        path: SpacePath,
    },
    UnpinSpace {
        instance: String,
        space: String,
        path: SpacePath,
    },
    PinsSpace {
        instance: String,
        space: String,
    },
    PinsSpaceCheckRemote {
        instance: String,
        space: String,
    },
    CleanCacheStatus,
    StorageStatus,
    StorageLimits,
    SetStorageLimits {
        #[serde(deserialize_with = "Option::deserialize")]
        limits: Option<StorageLimits>,
    },
    ReleaseStorageReservation {
        store: ReservationStore,
        token: String,
    },
    EvictSpace {
        instance: String,
        space: String,
        path: SpacePath,
    },
    RetainedPins {
        instance: String,
        offset: u32,
    },
    PinCopies {
        instance: String,
        offset: u32,
    },
    PinCopyEntries {
        instance: String,
        space: String,
        id: i64,
        offset: u32,
    },
    ExportPinCopy {
        instance: String,
        space: String,
        id: i64,
        path: SpacePath,
        selector: String,
        destination: PathBuf,
    },
    RemovePinCopy {
        instance: String,
        space: String,
        id: i64,
    },
    RetainedStaged {
        instance: String,
        offset: u32,
    },
    ExportStaged {
        instance: String,
        id: i64,
        selector: String,
        destination: PathBuf,
    },
    RetainedFiles {
        instance: String,
        space: String,
        root: SpacePath,
        offset: u32,
    },
    ExportRetained {
        instance: String,
        space: String,
        root: SpacePath,
        path: SpacePath,
        selector: String,
        destination: PathBuf,
    },
    StageFileSpace {
        instance: String,
        space: String,
        path: SpacePath,
        source: PathBuf,
    },
    StageFileOfflineSpace {
        instance: String,
        space: String,
        path: SpacePath,
        source: PathBuf,
    },
    Journal {
        instance: String,
        space: Option<String>,
        before: Option<i64>,
    },
    Sync {
        instance: String,
    },
    SyncSpace {
        instance: String,
        space: String,
    },
    LabUploadStep {
        instance: String,
        space: String,
    },
    SyncStatus {
        instance: String,
        space: String,
    },
    Acknowledge {
        instance: String,
        staged: String,
    },
    MountSpace {
        instance: String,
        space: String,
        path: Option<PathBuf>,
    },
    OfflineMountSpace {
        instance: String,
        space: String,
        path: PathBuf,
    },
    WritableOfflineMountSpace {
        instance: String,
        space: String,
        path: PathBuf,
    },
    UnmountSpace {
        instance: String,
        space: String,
    },
    Mounts,
    RecoverMount {
        path: PathBuf,
    },
}

impl AccountRequest {
    /// Returns the instance supplied by a request, if it has an account scope.
    pub fn instance(&self) -> Option<&str> {
        use AccountRequest::*;
        match self {
            Connect { instance, .. }
            | Spaces { instance }
            | DirectorySpace { instance, .. }
            | OfflineDirectory { instance, .. }
            | PinSpace { instance, .. }
            | UnpinSpace { instance, .. }
            | PinsSpace { instance, .. }
            | PinsSpaceCheckRemote { instance, .. }
            | EvictSpace { instance, .. }
            | RetainedPins { instance, .. }
            | PinCopies { instance, .. }
            | PinCopyEntries { instance, .. }
            | ExportPinCopy { instance, .. }
            | RemovePinCopy { instance, .. }
            | RetainedStaged { instance, .. }
            | ExportStaged { instance, .. }
            | RetainedFiles { instance, .. }
            | ExportRetained { instance, .. }
            | StageFileSpace { instance, .. }
            | StageFileOfflineSpace { instance, .. }
            | Journal { instance, .. }
            | Sync { instance }
            | SyncSpace { instance, .. }
            | LabUploadStep { instance, .. }
            | SyncStatus { instance, .. }
            | Acknowledge { instance, .. }
            | MountSpace { instance, .. }
            | OfflineMountSpace { instance, .. }
            | WritableOfflineMountSpace { instance, .. }
            | UnmountSpace { instance, .. } => Some(instance),
            CancelConnect { .. }
            | CleanCacheStatus
            | StorageStatus
            | StorageLimits
            | SetStorageLimits { .. }
            | ReleaseStorageReservation { .. }
            | Mounts
            | RecoverMount { .. } => None,
        }
    }

    /// Checks that the daemon answered the operation that was submitted.
    pub fn accepts(&self, reply: &AccountReply) -> bool {
        use AccountReply as A;
        use AccountRequest as Q;
        matches!(
            (self, reply),
            (
                Q::Connect { .. }
                    | Q::CancelConnect { .. }
                    | Q::PinSpace { .. }
                    | Q::UnpinSpace { .. }
                    | Q::ReleaseStorageReservation { .. }
                    | Q::EvictSpace { .. }
                    | Q::ExportPinCopy { .. }
                    | Q::RemovePinCopy { .. }
                    | Q::ExportStaged { .. }
                    | Q::ExportRetained { .. }
                    | Q::StageFileSpace { .. }
                    | Q::StageFileOfflineSpace { .. }
                    | Q::Sync { .. }
                    | Q::SyncSpace { .. }
                    | Q::Acknowledge { .. }
                    | Q::UnmountSpace { .. }
                    | Q::RecoverMount { .. },
                A::Done
            ) | (Q::Spaces { .. }, A::Spaces(_))
                | (
                    Q::DirectorySpace { .. } | Q::OfflineDirectory { .. },
                    A::Entries(_)
                )
                | (
                    Q::PinsSpace { .. } | Q::PinsSpaceCheckRemote { .. },
                    A::Pins(_)
                )
                | (Q::Journal { .. }, A::Journal(_))
                | (Q::SyncStatus { .. }, A::SyncStatus(_))
                | (Q::CleanCacheStatus, A::CleanCacheStatus(_))
                | (Q::StorageStatus, A::StorageStatus(_))
                | (
                    Q::StorageLimits | Q::SetStorageLimits { .. },
                    A::StorageLimits(_)
                )
                | (
                    Q::MountSpace { .. }
                        | Q::OfflineMountSpace { .. }
                        | Q::WritableOfflineMountSpace { .. },
                    A::Mounted(_)
                )
                | (Q::Mounts, A::Mounts(_))
                | (Q::RetainedPins { .. }, A::RetainedPins(_))
                | (Q::RetainedFiles { .. }, A::RetainedFiles(_))
                | (Q::RetainedStaged { .. }, A::RetainedStaged(_))
                | (Q::PinCopies { .. }, A::PinCopies(_))
                | (Q::PinCopyEntries { .. }, A::PinCopyEntries(_))
                | (Q::LabUploadStep { .. }, A::LabUploadOutcome(_))
        )
    }
}

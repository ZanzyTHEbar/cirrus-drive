//! Observational storage measurements, not a quota or global reservation ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use rustix::{
    fs::{self, AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags},
    process,
};
use serde::{Deserialize, Serialize};

use crate::{AccountError, offline, ownership};

pub(crate) mod limits;
pub(crate) mod namespace;
pub(crate) mod sql_reservation;
pub use limits::{StorageLimits, StorageLimitsView};
pub use namespace::NamespaceStorageReservation;
pub use sql_reservation::SqlStorageReservation;

const SCAN_LIMIT: u64 = 8192;
const TRACK_LIMIT: usize = 1024;
struct AnonymousFile {
    kind: AnonymousKind,
    file: Weak<std::fs::File>,
    namespace_token: Option<String>,
}
static ANONYMOUS: Mutex<Vec<AnonymousFile>> = Mutex::new(Vec::new());
static TRACKING_OVERFLOWED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
pub(crate) enum AnonymousKind {
    Directory,
    Pin,
}

// Weak file references do not keep scratch storage alive, nor interfere with
// DirectorySnapshot's Arc::get_mut uniqueness checks on its separate Storage.
pub(crate) fn track(file: std::fs::File, kind: AnonymousKind) -> Arc<std::fs::File> {
    let file = Arc::new(file);
    if let Ok(mut live) = ANONYMOUS.lock() {
        live.retain(|entry| entry.file.strong_count() != 0);
        if live.len() < TRACK_LIMIT {
            live.push(AnonymousFile {
                kind,
                file: Arc::downgrade(&file),
                namespace_token: None,
            });
        } else {
            TRACKING_OVERFLOWED.store(true, Ordering::Release);
        }
    } else {
        TRACKING_OVERFLOWED.store(true, Ordering::Release);
    }
    file
}

// Snapshot teardown calls this after closing its file owner, before releasing
// its durable allowance. Sampling references never outlive this registry lock.
pub(crate) fn finish_namespace_observation(token: &str) -> Result<(), AccountError> {
    let mut entries = ANONYMOUS.lock().map_err(|_| unavailable())?;
    for entry in entries
        .iter_mut()
        .filter(|entry| entry.namespace_token.as_deref() == Some(token))
    {
        entry.namespace_token = None;
    }
    Ok(())
}

pub(crate) fn bind_namespace(file: &Arc<std::fs::File>, token: &str) -> Result<(), AccountError> {
    let mut entries = ANONYMOUS.lock().map_err(|_| unavailable())?;
    let entry = entries
        .iter_mut()
        .find(|entry| {
            matches!(entry.kind, AnonymousKind::Directory)
                && entry.file.as_ptr() == Arc::as_ptr(file)
        })
        .ok_or_else(unavailable)?;
    if entry.namespace_token.is_some() {
        return Err(unavailable());
    }
    entry.namespace_token = Some(token.to_owned());
    Ok(())
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

fn unavailable() -> AccountError {
    AccountError::new("cannot safely measure local storage")
}
fn add(left: u64, right: u64) -> Result<u64, AccountError> {
    left.checked_add(right).ok_or_else(unavailable)
}

impl StorageUsage {
    fn record(&mut self, stat: &fs::Stat) -> Result<(), AccountError> {
        self.objects = add(self.objects, 1)?;
        self.logical_bytes = add(
            self.logical_bytes,
            u64::try_from(stat.st_size).map_err(|_| unavailable())?,
        )?;
        self.allocated_bytes = add(
            self.allocated_bytes,
            u64::try_from(stat.st_blocks)
                .map_err(|_| unavailable())?
                .checked_mul(512)
                .ok_or_else(unavailable)?,
        )?;
        Ok(())
    }
    fn include(&mut self, other: &Self) -> Result<(), AccountError> {
        self.objects = add(self.objects, other.objects)?;
        self.logical_bytes = add(self.logical_bytes, other.logical_bytes)?;
        self.allocated_bytes = add(self.allocated_bytes, other.allocated_bytes)?;
        Ok(())
    }
}

// SQLite owns its descriptors: never open/close an extra fd for an existing
// database, which would release process-wide POSIX locks. Reuse the project's
// held-directory procfs path and before/after inode/ownership validation.
fn database(
    dir: &impl AsFd,
    name: &str,
    app: i64,
    version: i64,
) -> Result<Option<Connection>, AccountError> {
    let before = match fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != process::geteuid().as_raw()
        || before.st_mode & 0o7777 != 0o600
        || before.st_nlink != 1
    {
        return Err(unavailable());
    }
    let proc = fs::openat2(
        fs::CWD,
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| unavailable())?;
    if fs::fstatfs(&proc).map_err(|_| unavailable())?.f_type != fs::PROC_SUPER_MAGIC {
        return Err(unavailable());
    }
    let conn = Connection::open_with_flags(
        format!("/proc/self/fd/{}/{name}", dir.as_fd().as_raw_fd()),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| unavailable())?;
    conn.busy_timeout(Duration::from_secs(1))
        .map_err(|_| unavailable())?;
    let identity: i64 = conn
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| unavailable())?;
    let schema: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| unavailable())?;
    let after = fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| unavailable())?;
    if identity != app
        || schema != version
        || (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
        )
    {
        return Err(unavailable());
    }
    Ok(Some(conn))
}

pub(crate) fn status() -> Result<StorageStatus, AccountError> {
    observe(&offline::storage_reservations()?, true)
}

pub(crate) fn allocation_status(
    reservations: &[(String, u64)],
) -> Result<StorageStatus, AccountError> {
    observe(reservations, false)
}

fn observe(
    reservations: &[(String, u64)],
    payload_counts: bool,
) -> Result<StorageStatus, AccountError> {
    let dir = ownership::state_dir()?;
    let device = fs::fstat(&dir).map_err(|_| unavailable())?.st_dev;
    let mut result = StorageStatus {
        namespace_reservations: Vec::new(),
        namespace_outstanding_reserved_bytes: 0,
        sql_reservations: Vec::new(),
        sql_outstanding_reserved_bytes: 0,
        storage_limits: None,
        storage_limits_error: None,
        immutable_admission_charge_bytes: 0,
        filesystem_fragment_bytes: 0,
        scope: "local-account-owner-all-accounts-and-spaces".into(),
        observational_not_atomic: true,
        scan_entry_limit: SCAN_LIMIT,
        vanished_entries: 0,
        staging: StorageUsage::default(),
        staging_named_entries: 0,
        state_sqlite: StorageUsage::default(),
        cache_sqlite: StorageUsage::default(),
        named_namespace_scratch: StorageUsage::default(),
        named_pin_scratch: StorageUsage::default(),
        other_named_files: StorageUsage::default(),
        directories: StorageUsage::default(),
        daemon_directory_scratch: StorageUsage::default(),
        daemon_pin_scratch: StorageUsage::default(),
        named_total: StorageUsage::default(),
        known_total: StorageUsage::default(),
        anonymous_storage_globally_complete: false,
        daemon_scratch_tracking_complete: !TRACKING_OVERFLOWED.load(Ordering::Acquire),
        daemon_staging_reserved_bytes: 0,
        daemon_staging_unmaterialized_reserved_bytes: 0,
        observed_staging_charge_bytes: 0,
        staging_byte_limit: offline::MAX_STAGING_BYTES,
        staging_file_limit: offline::MAX_STAGING_FILES as u64,
        registered_dirty_roots: 0,
        pin_payload_bytes: 0,
        pin_chunks: 0,
        pins: 0,
        clean_payload_bytes: 0,
        clean_ranges: 0,
        filesystem_available_bytes: 0,
    };
    match limits::view() {
        Ok(view) => result.storage_limits = Some(view),
        Err(error) => result.storage_limits_error = Some(error.to_string()),
    }
    if payload_counts && let Some(conn) = database(&dir, "state.db", 0x4344_5231, 17)? {
        (result.pin_payload_bytes, result.pin_chunks) = conn
            .query_row(
                "SELECT coalesce(sum(bytes),0),coalesce(sum(n),0) FROM (SELECT sum(length(body)) AS bytes,count(*) AS n FROM chunks UNION ALL SELECT sum(length(body)),count(*) FROM pin_copy_chunks)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| unavailable())?;
        result.pins = conn
            .query_row(
                "SELECT (SELECT count(*) FROM pins)+(SELECT count(*) FROM pin_copies)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        result.registered_dirty_roots = conn
            .query_row("SELECT count(*) FROM dirty_roots", [], |row| row.get(0))
            .map_err(|_| unavailable())?;
    }
    if payload_counts && let Some(conn) = database(&dir, "cache.db", 0x4344_4331, 2)? {
        (result.clean_payload_bytes, result.clean_ranges) = conn
            .query_row(
                "SELECT coalesce(sum(length(body)),0),count(*) FROM ranges",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| unavailable())?;
    }
    let mut materialized = BTreeMap::new();
    let mut namespace_tokens = Vec::new();
    let mut seen = BTreeSet::new();
    seen.insert((device, fs::fstat(&dir).map_err(|_| unavailable())?.st_ino));
    result
        .directories
        .record(&fs::fstat(&dir).map_err(|_| unavailable())?)?;
    let mut visited = 0;
    // Exactly one known directory level, never a recursive tree walk. Unexpected
    // directories/symlinks/devices fail explicitly instead of reporting zero.
    let mut roots = vec![(dir.try_clone().map_err(|_| unavailable())?, String::new())];
    while let Some((directory, kind)) = roots.pop() {
        let mut entries = Dir::read_from(&directory).map_err(|_| unavailable())?;
        while let Some(entry) = entries.read() {
            let entry = entry.map_err(|_| unavailable())?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            visited += 1;
            if visited > SCAN_LIMIT {
                return Err(AccountError::new(
                    "storage status enumeration limit exceeded; no complete total available",
                ));
            }
            let stat = match fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => {
                    result.vanished_entries += 1;
                    continue;
                }
                Err(_) => return Err(unavailable()),
            };
            if stat.st_dev != device || stat.st_uid != process::geteuid().as_raw() {
                return Err(unavailable());
            }
            let text = name.to_str().map_err(|_| unavailable())?;
            if kind.is_empty()
                && let Some(token) = text.strip_prefix(namespace::PREFIX)
            {
                namespace_tokens.push(token.to_owned());
            }
            if FileType::from_raw_mode(stat.st_mode) == FileType::Directory
                && kind.is_empty()
                && matches!(text, "staging" | "directory-snapshots")
            {
                let child = fs::openat2(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(|_| unavailable())?;
                let actual = fs::fstat(&child).map_err(|_| unavailable())?;
                if (actual.st_dev, actual.st_ino, actual.st_uid, actual.st_mode)
                    != (stat.st_dev, stat.st_ino, stat.st_uid, stat.st_mode)
                    || actual.st_mode & 0o7777 != 0o700
                {
                    return Err(unavailable());
                }
                if seen.insert((stat.st_dev, stat.st_ino)) {
                    result.directories.record(&stat)?;
                }
                roots.push((child, text.to_owned()));
                continue;
            }
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_mode & 0o7777 != 0o600
            {
                return Err(unavailable());
            }
            let logical = u64::try_from(stat.st_size).map_err(|_| unavailable())?;
            let allocated = u64::try_from(stat.st_blocks)
                .map_err(|_| unavailable())?
                .checked_mul(512)
                .ok_or_else(unavailable)?;
            if kind == "staging" {
                result.staging_named_entries = add(result.staging_named_entries, 1)?;
                materialized.insert(text.to_owned(), logical.max(allocated));
            }
            if !seen.insert((stat.st_dev, stat.st_ino)) {
                continue;
            }
            let usage = if kind == "staging" {
                result.observed_staging_charge_bytes =
                    add(result.observed_staging_charge_bytes, logical.max(allocated))?;
                &mut result.staging
            } else if kind == "directory-snapshots" {
                &mut result.named_namespace_scratch
            } else if text.starts_with(".pin-download-") {
                &mut result.named_pin_scratch
            } else if matches!(
                text,
                "state.db" | "state.db-wal" | "state.db-shm" | "state.db-journal"
            ) {
                &mut result.state_sqlite
            } else if matches!(
                text,
                "cache.db" | "cache.db-wal" | "cache.db-shm" | "cache.db-journal"
            ) {
                &mut result.cache_sqlite
            } else {
                &mut result.other_named_files
            };
            usage.record(&stat)?;
        }
    }
    for (name, reserved) in reservations {
        result.daemon_staging_reserved_bytes =
            add(result.daemon_staging_reserved_bytes, *reserved)?;
        result.daemon_staging_unmaterialized_reserved_bytes = add(
            result.daemon_staging_unmaterialized_reserved_bytes,
            reserved.saturating_sub(materialized.get(name).copied().unwrap_or(0)),
        )?;
    }
    result.observed_staging_charge_bytes = add(
        result.observed_staging_charge_bytes,
        result.daemon_staging_unmaterialized_reserved_bytes,
    )?;
    for usage in [
        &result.staging,
        &result.state_sqlite,
        &result.cache_sqlite,
        &result.named_namespace_scratch,
        &result.named_pin_scratch,
        &result.other_named_files,
        &result.directories,
    ] {
        result.named_total.include(usage)?;
    }
    let anonymous = ANONYMOUS.lock().map_err(|_| unavailable())?;
    let live = anonymous
        .iter()
        .filter_map(|entry| {
            entry
                .file
                .upgrade()
                .map(|file| (entry.kind, entry.namespace_token.clone(), file))
        })
        .collect::<Vec<_>>();
    let mut local_namespace = BTreeMap::new();
    for (kind, namespace_token, file) in live {
        let stat = fs::fstat(&file).map_err(|_| unavailable())?;
        if stat.st_dev != device || stat.st_uid != process::geteuid().as_raw() || stat.st_nlink != 0
        {
            return Err(unavailable());
        }
        if seen.insert((stat.st_dev, stat.st_ino)) {
            match kind {
                AnonymousKind::Directory => {
                    result.daemon_directory_scratch.record(&stat)?;
                    if let Some(token) = namespace_token {
                        local_namespace.insert(
                            token,
                            (
                                stat.st_dev,
                                stat.st_ino,
                                u64::try_from(stat.st_blocks)
                                    .map_err(|_| unavailable())?
                                    .checked_mul(512)
                                    .ok_or_else(unavailable)?,
                            ),
                        );
                    }
                }
                AnonymousKind::Pin => result.daemon_pin_scratch.record(&stat)?,
            }
        }
    }
    drop(anonymous);
    result.known_total = result.named_total.clone();
    result
        .known_total
        .include(&result.daemon_directory_scratch)?;
    result.known_total.include(&result.daemon_pin_scratch)?;
    result.sql_reservations = sql_reservation::observe(&dir, &result)?;
    result.namespace_reservations = namespace::observe(&dir, &namespace_tokens, &local_namespace)?;
    for reservation in &result.namespace_reservations {
        result.namespace_outstanding_reserved_bytes = add(
            result.namespace_outstanding_reserved_bytes,
            reservation.outstanding_reserved_bytes,
        )?;
    }
    for reservation in &result.sql_reservations {
        result.sql_outstanding_reserved_bytes = add(
            result.sql_outstanding_reserved_bytes,
            reservation.outstanding_bytes,
        )?;
    }
    result.immutable_admission_charge_bytes = add(
        result
            .known_total
            .allocated_bytes
            .checked_sub(result.staging.allocated_bytes)
            .ok_or_else(unavailable)?,
        add(
            result.observed_staging_charge_bytes,
            add(
                result.sql_outstanding_reserved_bytes,
                result.namespace_outstanding_reserved_bytes,
            )?,
        )?,
    )?;
    result.daemon_scratch_tracking_complete &= !TRACKING_OVERFLOWED.load(Ordering::Acquire);
    let stat = fs::fstatvfs(&dir).map_err(|_| unavailable())?;
    if stat.f_frsize == 0 {
        return Err(unavailable());
    }
    result.filesystem_fragment_bytes = stat.f_frsize;
    result.filesystem_available_bytes = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or_else(unavailable)?;
    Ok(result)
}

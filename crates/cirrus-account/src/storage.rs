//! Observational storage measurements, not a quota or global reservation ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use rusqlite::Connection;
use rustix::{
    fs::{self, AtFlags, Dir, FileType, Mode, OFlags},
    process,
};

use crate::{
    AccountError,
    account_storage::StorageRoot,
    offline,
    sqlite_open::{Database, OpenMode},
};

pub(crate) mod limits;
pub(crate) mod namespace;
pub(crate) mod sql_reservation;
pub use limits::{StorageLimits, StorageLimitsView};
pub use namespace::NamespaceStorageReservation;
pub use sql_reservation::SqlStorageReservation;

const SCAN_LIMIT: u64 = 8192;
const TRACK_LIMIT: usize = 1024;
struct AnonymousFile {
    root: StorageRoot,
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
pub(crate) fn track(
    root: &StorageRoot,
    file: std::fs::File,
    kind: AnonymousKind,
) -> Arc<std::fs::File> {
    let file = Arc::new(file);
    if let Ok(mut live) = ANONYMOUS.lock() {
        live.retain(|entry| entry.file.strong_count() != 0);
        if live.len() < TRACK_LIMIT {
            live.push(AnonymousFile {
                root: root.clone(),
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
pub(crate) fn finish_namespace_observation(
    root: &StorageRoot,
    token: &str,
) -> Result<(), AccountError> {
    let mut entries = ANONYMOUS.lock().map_err(|_| unavailable())?;
    for entry in entries.iter_mut().filter(|entry| {
        entry.root.identity() == root.identity() && entry.namespace_token.as_deref() == Some(token)
    }) {
        entry.namespace_token = None;
    }
    Ok(())
}

pub(crate) fn bind_namespace(
    root: &StorageRoot,
    file: &Arc<std::fs::File>,
    token: &str,
) -> Result<(), AccountError> {
    let mut entries = ANONYMOUS.lock().map_err(|_| unavailable())?;
    let entry = entries
        .iter_mut()
        .find(|entry| {
            entry.root.identity() == root.identity()
                && matches!(entry.kind, AnonymousKind::Directory)
                && entry.file.as_ptr() == Arc::as_ptr(file)
        })
        .ok_or_else(unavailable)?;
    if entry.namespace_token.is_some() {
        return Err(unavailable());
    }
    entry.namespace_token = Some(token.to_owned());
    Ok(())
}

pub use cirrus_api::{StorageStatus, StorageUsage};

fn unavailable() -> AccountError {
    AccountError::new("cannot safely measure local storage")
}
fn add(left: u64, right: u64) -> Result<u64, AccountError> {
    left.checked_add(right).ok_or_else(unavailable)
}

trait UsageAccounting {
    fn record(&mut self, stat: &fs::Stat) -> Result<(), AccountError>;
    fn include(&mut self, other: &Self) -> Result<(), AccountError>;
}

impl UsageAccounting for StorageUsage {
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

fn database(
    root: &StorageRoot,
    database: Database,
    app: i64,
    version: i64,
) -> Result<Option<Connection>, AccountError> {
    let Some(opening) = database
        .open(root, OpenMode::Inspect)
        .map_err(|_| unavailable())?
    else {
        return Ok(None);
    };
    let conn = opening.connection();
    conn.busy_timeout(Duration::from_secs(1))
        .map_err(|_| unavailable())?;
    let identity: i64 = conn
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| unavailable())?;
    let schema: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| unavailable())?;
    opening.check_named().map_err(|_| unavailable())?;
    if identity != app
        || (schema != version
            // Read-only accounting can inspect the supported pre-migration
            // schema without upgrading or opening a second writer. Its payload
            // tables are unchanged by the additive catalog migration.
            && !(matches!(database, Database::State)
                && matches!(schema, 17 | 18)
                && version == offline::STATE_SCHEMA_VERSION))
    {
        return Err(unavailable());
    }
    opening
        .check_sidecars_and_vfs()
        .map_err(|_| unavailable())?;
    Ok(Some(opening.into_connection()))
}

pub(crate) fn status_in(root: &StorageRoot) -> Result<StorageStatus, AccountError> {
    observe(root, &offline::storage_reservations_in(root)?, true)
}

pub(crate) fn allocation_status_in(
    root: &StorageRoot,
    reservations: &[(String, u64)],
) -> Result<StorageStatus, AccountError> {
    observe(root, reservations, false)
}

fn observe(
    root: &StorageRoot,
    reservations: &[(String, u64)],
    payload_counts: bool,
) -> Result<StorageStatus, AccountError> {
    let dir = root.directory();
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
    match limits::view_in(root) {
        Ok(view) => result.storage_limits = Some(view),
        Err(error) => result.storage_limits_error = Some(error.to_string()),
    }
    if payload_counts
        && let Some(conn) = database(
            root,
            Database::State,
            0x4344_5231,
            offline::STATE_SCHEMA_VERSION,
        )?
    {
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
    if payload_counts && let Some(conn) = database(root, Database::Cache, 0x4344_4331, 2)? {
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
                let child = crate::ownership::open_private_file(
                    &directory,
                    text,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| unavailable())?;
                let actual = fs::fstat(&child).map_err(|_| unavailable())?;
                if (actual.st_dev, actual.st_ino, actual.st_uid, actual.st_mode)
                    != (stat.st_dev, stat.st_ino, stat.st_uid, stat.st_mode)
                    || actual.st_mode & 0o7777 != 0o700
                {
                    return Err(unavailable());
                }
                #[cfg(target_os = "macos")]
                crate::ownership::darwin_acl::check_directory(&child).map_err(|_| unavailable())?;
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
        .filter(|entry| entry.root.identity() == root.identity())
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
                                stat.st_dev as u64,
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::*;

    #[test]
    fn sqlite_inspection_does_not_migrate_or_unlock() {
        const PEER_CONTAINER: &str = "CIRRUS_SQLITE_ADMISSION_PEER_CONTAINER";
        if let Some(path) = std::env::var_os(PEER_CONTAINER) {
            let peer = Connection::open_with_flags(
                Path::new(&path).join("cirrus-drive/state.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            )
            .unwrap();
            peer.busy_timeout(Duration::ZERO).unwrap();
            let error = peer.execute_batch("BEGIN IMMEDIATE").unwrap_err();
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
            return;
        }

        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "cirrus-sqlite-{}",
            offline::namespace_token().unwrap()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let fixture = Fixture(path);
        let root = StorageRoot::open_container(&fixture.0).unwrap();
        assert_eq!(status_in(&root).unwrap().state_sqlite.objects, 0);
        assert_eq!(crate::cache::status_in(&root).unwrap().ranges, 0);
        assert_eq!(status_in(&root).unwrap().cache_sqlite.objects, 0);

        let conn = offline::database_in(&root).unwrap();
        conn.execute_batch(
            "BEGIN IMMEDIATE; DROP TABLE fp_requests; DROP TABLE fp_deletions;
             PRAGMA user_version=18; COMMIT;",
        )
        .unwrap();
        assert!(status_in(&root).unwrap().state_sqlite.objects > 0);
        let version = |conn: &Connection| -> i64 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(
            version(&conn),
            18,
            "storage accounting migrated the database"
        );
        drop(conn);

        limits::set_in(
            &root,
            Some(StorageLimits {
                budget_bytes: 16 * 1024 * 1024,
                free_space_reserve_bytes: 0,
            }),
        )
        .unwrap();
        let writer = offline::database_in(&root).unwrap();
        assert_eq!(version(&writer), offline::STATE_SCHEMA_VERSION);
        assert!(status_in(&root).unwrap().sql_reservations.is_empty());
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        drop(offline::database_in(&root).unwrap());
        status_in(&root).unwrap();

        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::tests::sqlite_inspection_does_not_migrate_or_unlock",
            ])
            .env(PEER_CONTAINER, &fixture.0)
            .output()
            .unwrap();
        let report = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && report.contains("1 passed"),
            "peer writer check failed: {report}"
        );
        writer.execute_batch("ROLLBACK").unwrap();
    }
}

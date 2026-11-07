//! One durable reservation ceiling per SQLite store. Not a SQLite VFS quota.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;

use rusqlite::Connection;
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags},
    process,
};
use serde::{Deserialize, Serialize};

use super::{StorageStatus, limits};
use crate::{AccountError, offline, ownership};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Store {
    State,
    Cache,
}

impl Store {
    fn record(self) -> &'static str {
        match self {
            Self::State => "state-storage.reservation",
            Self::Cache => "cache-storage.reservation",
        }
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Cache => "cache",
        }
    }
    fn allocated(self, status: &StorageStatus) -> u64 {
        match self {
            Self::State => status.state_sqlite.allocated_bytes,
            Self::Cache => status.cache_sqlite.allocated_bytes,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    token: String,
    store: Store,
    ceiling_bytes: u64,
    scratch: Option<String>,
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

fn invalid() -> AccountError {
    AccountError::new("invalid or abandoned SQL storage reservation; inspect storage status")
}

fn record(dir: &OwnedFd, store: Store) -> Result<Option<Record>, AccountError> {
    let fd = match fs::openat2(
        dir,
        store.record(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(invalid()),
    };
    let stat = fs::fstat(&fd).map_err(|_| invalid())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size > 4096
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let record: Record = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if bytes.len() > 4096
        || record.store != store
        || record.token.len() != 32
        || !record.token.bytes().all(|byte| byte.is_ascii_hexdigit())
        || record
            .scratch
            .as_ref()
            .is_some_and(|name| name != &format!(".pin-download-{}", record.token))
    {
        return Err(invalid());
    }
    Ok(Some(record))
}

pub(crate) fn observe(
    dir: &OwnedFd,
    status: &StorageStatus,
) -> Result<Vec<SqlStorageReservation>, AccountError> {
    let mut result = Vec::new();
    for store in [Store::State, Store::Cache] {
        if let Some(record) = record(dir, store)? {
            let allocated = store.allocated(status);
            result.push(SqlStorageReservation {
                store: store.name().into(),
                token: record.token,
                ceiling_bytes: record.ceiling_bytes,
                store_allocated_bytes: allocated,
                outstanding_bytes: record.ceiling_bytes.saturating_sub(allocated),
                pin_scratch_name: record.scratch,
            });
        }
    }
    Ok(result)
}

/// Reservation ownership, never the global allocator lock. Nonblocking: a
/// competing writer refuses/skips rather than waiting through a pin download.
pub(crate) fn cleanup_lease(store: Store) -> Result<Option<ownership::StoreLease>, AccountError> {
    // Cleanup is not new growth: malformed policy must not prohibit clean
    // release, but still coordinate it with any existing store reservation.
    if limits::view().is_ok_and(|view| view.limits.is_none()) {
        return Ok(None);
    }
    ownership::acquire_storage_store(store.name()).map(Some)
}

pub(crate) fn release(store: &str, token: &str) -> Result<(), AccountError> {
    if store == "namespace" {
        return super::namespace::release(token);
    }
    let store = match store {
        "state" => Store::State,
        "cache" => Store::Cache,
        _ => return Err(invalid()),
    };
    let _lease = ownership::acquire_storage_store(store.name())?;
    let _budget = ownership::acquire_staging()?;
    let dir = ownership::state_dir()?;
    if record(&dir, store)?.is_none_or(|record| record.token != token) {
        return Err(invalid());
    }
    // Explicit token-checked release only. A crashed named pin download remains
    // charged/recoverable; never delete it or a pin/dirty DB row here.
    fs::unlinkat(&dir, store.record(), AtFlags::empty()).map_err(|_| invalid())?;
    fs::fsync(&dir).map_err(|_| invalid())
}

pub(crate) struct SqlReservation {
    store: Store,
    token: String,
    dir: OwnedFd,
    _lease: ownership::StoreLease,
    own_record: bool,
    scratch: Option<(String, std::fs::File, u64, u64)>,
    ceiling: u64,
    page_limit: u64,
}

impl SqlReservation {
    pub(crate) fn begin(
        store: Store,
        conn: Option<&Connection>,
        incoming: u64,
        metadata: u64,
        scratch: bool,
    ) -> Result<Option<Self>, AccountError> {
        if limits::view()?.limits.is_none() {
            return Ok(None);
        }
        let lease = ownership::acquire_storage_store(store.name())?;
        // These queries happen before the budget flock, never during contention
        // on that lock. This is a conservative disk planning allowance, not a
        // claim that logical BLOB bytes equal physical SQLite growth.
        let (page, pages): (u64, u64) = if let Some(conn) = conn {
            (
                conn.pragma_query_value(None, "page_size", |row| row.get(0))
                    .map_err(|_| invalid())?,
                conn.pragma_query_value(None, "page_count", |row| row.get(0))
                    .map_err(|_| invalid())?,
            )
        } else {
            (4096, 0)
        };
        // Two page images per estimated incoming row bytes (B-tree/overflow
        // slack), plus eight schema/control pages. Reserve both DB + journal
        // images and two current DB images for replacement/checkpoint work.
        // max_page_count below enforces the planned DB page ceiling; WAL and
        // filesystem allocation are separately observed, not assumed exact.
        let row_allowance = incoming
            .checked_add(metadata)
            .and_then(|bytes| bytes.checked_add(page.checked_mul(8)?))
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(invalid)?;
        let page_limit = pages
            .checked_add(row_allowance.div_ceil(page))
            .ok_or_else(invalid)?;
        let allowance = row_allowance
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(pages.checked_mul(page)?.checked_mul(2)?))
            .ok_or_else(invalid)?;
        let mut reservation = Self {
            store,
            token: offline::namespace_token()?,
            dir: ownership::state_dir()?,
            _lease: lease,
            own_record: false,
            scratch: None,
            ceiling: 0,
            page_limit,
        };
        match reservation.prepare(allowance, scratch.then_some(incoming)) {
            Err(error)
                if limits::is_pressure(&error)
                    && store == Store::State
                    && !reservation.own_record
                    && reservation.scratch.is_none() =>
            {
                // No allocator lock is held. Cache reservation acquisition is
                // nonblocking and cache writers never acquire the State lease.
                if crate::cache::reclaim_for_storage_pressure()? {
                    reservation.prepare(allowance, scratch.then_some(incoming))?;
                } else {
                    return Err(error);
                }
            }
            result => result?,
        }
        #[cfg(feature = "fault-injection")]
        if store == Store::State && crate::executor::is_automatic() {
            crate::wait_test_window("CIRRUS_TEST_AUTO_STATE_RESERVED_WINDOW")?;
        }
        Ok(Some(reservation))
    }

    fn prepare(&mut self, allowance: u64, scratch: Option<u64>) -> Result<(), AccountError> {
        let _budget = ownership::acquire_staging()?;
        if record(&self.dir, self.store)?.is_some() {
            return Err(invalid());
        }
        let reservations = offline::storage_reservations()?;
        let observation = super::allocation_status(&reservations)?;
        let rounded = allowance
            .checked_add(observation.filesystem_fragment_bytes - 1)
            .map(|bytes| {
                bytes / observation.filesystem_fragment_bytes
                    * observation.filesystem_fragment_bytes
            })
            .ok_or_else(invalid)?;
        limits::check(
            rounded
                .checked_add(scratch.unwrap_or(0))
                .and_then(|bytes| bytes.checked_add(observation.filesystem_fragment_bytes))
                .ok_or_else(invalid)?,
            &reservations,
        )?;
        self.ceiling = self
            .store
            .allocated(&observation)
            .checked_add(rounded)
            .ok_or_else(invalid)?;
        if let Some(bytes) = scratch {
            let name = format!(".pin-download-{}", self.token);
            let fd = fs::openat2(
                &self.dir,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(|_| invalid())?;
            let stat = fs::fstat(&fd).map_err(|_| invalid())?;
            self.scratch = Some((name, std::fs::File::from(fd), stat.st_dev, stat.st_ino));
            if bytes > 0 {
                fs::fallocate(
                    &self.scratch.as_ref().ok_or_else(invalid)?.1,
                    fs::FallocateFlags::empty(),
                    0,
                    bytes,
                )
                .map_err(|_| AccountError::new("local storage capacity exhausted"))?;
            }
        }
        let record = Record {
            token: self.token.clone(),
            store: self.store,
            ceiling_bytes: self.ceiling,
            scratch: self.scratch.as_ref().map(|(name, ..)| name.clone()),
        };
        let temporary = format!(".sql-reservation-{}", self.token);
        let fd = fs::openat2(
            &self.dir,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| invalid())?;
        let mut file = std::fs::File::from(fd);
        let published = (|| {
            file.write_all(&serde_json::to_vec(&record).map_err(|_| invalid())?)
                .and_then(|()| file.sync_all())
                .map_err(|_| invalid())?;
            fs::renameat(
                &self.dir,
                temporary.as_str(),
                &self.dir,
                self.store.record(),
            )
            .map_err(|_| invalid())?;
            self.own_record = true;
            Ok::<(), AccountError>(())
        })();
        let _ = fs::unlinkat(&self.dir, temporary.as_str(), AtFlags::empty());
        published?;
        fs::fsync(&self.dir).map_err(|_| invalid())?;
        limits::check(0, &reservations)
    }

    pub(crate) fn scratch(&self) -> Result<&std::fs::File, AccountError> {
        self.scratch
            .as_ref()
            .map(|(_, file, ..)| file)
            .ok_or_else(invalid)
    }

    pub(crate) fn bound_pages(&self, conn: &Connection) -> Result<(), AccountError> {
        // Connection-local and below the clean cache's existing domain cap.
        let existing: u64 = conn
            .pragma_query_value(None, "max_page_count", |row| row.get(0))
            .map_err(|_| invalid())?;
        let maximum = self.page_limit.min(existing);
        let applied: u64 = conn
            .query_row(&format!("PRAGMA max_page_count={maximum}"), [], |row| {
                row.get(0)
            })
            .map_err(|_| invalid())?;
        if applied > maximum {
            return Err(AccountError::new(limits::PRESSURE));
        }
        Ok(())
    }

    pub(crate) fn validate(&self, conn: &Connection) -> Result<(), AccountError> {
        if limits::view()?.limits.is_none() {
            return Ok(());
        }
        // Actual SQLite page count includes BLOB/index/metadata pages, unlike
        // incoming payload length. Late WAL spill/commit/fsync remains outside
        // a hard VFS bound; never report rollback after a successful commit.
        let page: u64 = conn
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .map_err(|_| invalid())?;
        let pages: u64 = conn
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .map_err(|_| invalid())?;
        if pages > self.page_limit
            || pages
                .checked_mul(page)
                .is_none_or(|bytes| bytes > self.ceiling)
        {
            return Err(AccountError::new(limits::PRESSURE));
        }
        let _budget = ownership::acquire_staging()?;
        if record(&self.dir, self.store)?.is_none_or(|record| record.token != self.token) {
            return Err(invalid());
        }
        let reservations = offline::storage_reservations()?;
        if self
            .store
            .allocated(&super::allocation_status(&reservations)?)
            > self.ceiling
        {
            return Err(AccountError::new(limits::PRESSURE));
        }
        limits::check(0, &reservations)
    }
}

impl Drop for SqlReservation {
    fn drop(&mut self) {
        // Close scratch before unlink/releasing its ceiling so no anonymous
        // allocation escapes cross-process measurement during normal cleanup.
        let scratch = self.scratch.take().map(|(name, file, dev, ino)| {
            drop(file);
            (name, dev, ino)
        });
        if let Ok(_budget) = ownership::acquire_staging() {
            if let Some((name, dev, ino)) = scratch
                && let Ok(stat) = fs::statat(&self.dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                && (stat.st_dev, stat.st_ino, stat.st_nlink) == (dev, ino, 1)
            {
                let _ = fs::unlinkat(&self.dir, name.as_str(), AtFlags::empty());
            }
            if self.own_record
                && record(&self.dir, self.store)
                    .is_ok_and(|record| record.is_some_and(|record| record.token == self.token))
            {
                let _ = fs::unlinkat(&self.dir, self.store.record(), AtFlags::empty());
            }
            let _ = fs::fsync(&self.dir);
        }
        // Crash/failed cleanup records remain visible and charged. No expiry,
        // PID inference, automatic stale-record adoption or age-based GC.
    }
}

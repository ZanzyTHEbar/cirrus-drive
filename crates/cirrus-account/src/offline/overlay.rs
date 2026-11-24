//! Immutable bounded extent maps and private, block-verified payload objects.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex, OnceLock};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{AccountError, FileVersion, database_in};
use crate::account_storage::{RootIdentity, StorageRoot};

mod integrity;
pub(crate) use integrity::verify_protected_in;

pub(crate) const MAX_FILE: u64 = 1024 * 1024 * 1024 * 1024;
const BLOCK: u64 = 128 * 1024;
const OBJECT: usize = 8 * 1024 * 1024;
const MAX_EXTENTS: usize = 65_536;
pub(super) const MAX_MANIFEST: u64 = 16 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Object {
    name: String,
    size: u64,
    blocks: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Extent {
    start: u64,
    length: u64,
    object: Object,
    offset: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Overlay {
    // Runtime-only ownership. Never serialized into a manifest or digest.
    #[serde(skip)]
    storage: Option<StorageRoot>,
    size: u64,
    // Never rebased when a predecessor confirms a new replacement ETag.
    base: Option<FileVersion>,
    visible_end: u64,
    extents: Vec<Extent>,
}

// Full immutable version identity plus block offset, not pathname/ETag alone.
// Bound physical work by the union shared across historical interpretations.
pub(super) struct OriginalBudget {
    remaining: u64,
    verified: std::collections::BTreeSet<([u8; 32], u64)>,
}

impl OriginalBudget {
    pub(super) fn new() -> Self {
        Self {
            remaining: super::MAX_PIN_BYTES,
            verified: Default::default(),
        }
    }

    fn first(
        &mut self,
        base: &FileVersion,
        offset: u64,
        length: u64,
    ) -> Result<bool, AccountError> {
        let identity = Sha256::digest(serde_json::to_vec(base).map_err(|_| invalid())?).into();
        if self.verified.contains(&(identity, offset)) {
            return Ok(false);
        }
        if self.verified.len() == 8192 {
            return Err(AccountError::new(
                "local pin protection block limit reached; pin retained",
            ));
        }
        self.remaining = self.remaining.checked_sub(length).ok_or_else(|| AccountError::new(
            "local pin protection verification limit reached; pin retained; required original union exceeds 1 GiB",
        ))?;
        self.verified.insert((identity, offset));
        Ok(true)
    }
}

fn invalid() -> AccountError {
    AccountError::new("dirty snapshot integrity check failed; local data retained")
}

fn save_bytes(
    storage: &StorageRoot,
    bytes: &[u8],
    #[cfg(feature = "fault-injection")] manifest: bool,
) -> Result<String, AccountError> {
    let (mut file, dir, reservation) = super::create_staged_file_in(storage, bytes.len() as u64)?;
    // This ENOSPC lab hook is Linux-only and ignored on other platforms.
    #[cfg(all(feature = "fault-injection", target_os = "linux"))]
    let written = if let Some(marker) = std::env::var_os("CIRRUS_TEST_DIRTY_OBJECT_ENOSPC")
        && std::fs::remove_file(marker).is_ok()
    {
        // Exercise the ordinary write-error path with a real kernel ENOSPC,
        // without filling a host filesystem or modifying any published object.
        // Only this candidate write is redirected; its reservation stays charged.
        let result = (|| -> std::io::Result<()> {
            use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
            let mut full = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open("/dev/full")?;
            let metadata = full.metadata()?;
            if !metadata.file_type().is_char_device() || metadata.rdev() != nix::libc::makedev(1, 7)
            {
                return Err(std::io::Error::other("unexpected lab ENOSPC device"));
            }
            full.write_all(bytes)
        })();
        eprintln!(
            "cirrus lab dirty object write fault: errno={:?} bytes={}",
            result.as_ref().err().and_then(std::io::Error::raw_os_error),
            bytes.len()
        );
        result
    } else {
        file.write_all(bytes)
    };
    #[cfg(not(all(feature = "fault-injection", target_os = "linux")))]
    let written = file.write_all(bytes);
    written.and_then(|()| file.sync_all()).map_err(|error| {
        if matches!(
            error.raw_os_error(),
            Some(nix::libc::ENOSPC) | Some(nix::libc::EDQUOT)
        ) {
            AccountError::new("staging capacity exhausted")
        } else {
            AccountError::new("cannot persist dirty object; local data retained")
        }
    })?;
    #[cfg(feature = "fault-injection")]
    let synced = if manifest
        && let Some(marker) = std::env::var_os("CIRRUS_TEST_DIRTY_MANIFEST_DIRSYNC")
        && std::fs::remove_file(marker).is_ok()
    {
        // The immutable file has been written and sync_all succeeded. Replace
        // only this manifest's containing-directory fsync result, before either
        // dirty_roots or the journal can reference it. This is not kernel I/O.
        eprintln!(
            "cirrus lab manifest file sync complete; synthetic directory fsync EIO: name={} bytes={}",
            reservation.name,
            bytes.len()
        );
        crate::wait_test_window("CIRRUS_TEST_DIRTY_MANIFEST_DIRSYNC_WINDOW")?;
        Err(rustix::io::Errno::IO)
    } else {
        rustix::fs::fsync(&dir)
    };
    #[cfg(not(feature = "fault-injection"))]
    let synced = rustix::fs::fsync(&dir);
    synced.map_err(|_| AccountError::new("cannot persist dirty object directory"))?;
    Ok(reservation.name.clone())
}

impl Object {
    fn save(storage: &StorageRoot, bytes: &[u8]) -> Result<Self, AccountError> {
        if bytes.is_empty() || bytes.len() > OBJECT {
            return Err(invalid());
        }
        let blocks = bytes
            .chunks(BLOCK as usize)
            .map(|block| format!("{:x}", Sha256::digest(block)))
            .collect();
        Ok(Self {
            name: save_bytes(
                storage,
                bytes,
                #[cfg(feature = "fault-injection")]
                false,
            )?,
            size: bytes.len() as u64,
            blocks,
        })
    }

    fn range(
        &self,
        storage: &StorageRoot,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, AccountError> {
        self.verified_range(storage, offset, length)
            .map(|(bytes, _)| bytes)
    }

    fn verified_range(
        &self,
        storage: &StorageRoot,
        offset: u64,
        length: usize,
    ) -> Result<(Vec<u8>, std::fs::Metadata), AccountError> {
        let end = offset
            .checked_add(length as u64)
            .filter(|end| *end <= self.size)
            .ok_or_else(invalid)?;
        if self.size == 0
            || self.size > OBJECT as u64
            || self.blocks.len() as u64 != self.size.div_ceil(BLOCK)
        {
            return Err(invalid());
        }
        let (file, before) = super::open_staged_in(storage, &self.name)?;
        if before.len() != self.size {
            return Err(invalid());
        }
        let mut result = Vec::with_capacity(length);
        let mut block_offset = offset / BLOCK * BLOCK;
        while block_offset < end {
            let mut bytes = vec![0; (self.size - block_offset).min(BLOCK) as usize];
            file.read_exact_at(&mut bytes, block_offset)
                .map_err(|_| invalid())?;
            if format!("{:x}", Sha256::digest(&bytes))
                != self.blocks[(block_offset / BLOCK) as usize]
            {
                return Err(invalid());
            }
            let start = offset.saturating_sub(block_offset) as usize;
            let finish = (end - block_offset).min(bytes.len() as u64) as usize;
            result.extend_from_slice(&bytes[start..finish]);
            block_offset += BLOCK;
        }
        super::verify_staged_metadata(&file, &before)?;
        Ok((result, before))
    }
}

impl Overlay {
    pub(crate) fn empty_in(storage: &StorageRoot) -> Self {
        Self {
            storage: Some(storage.clone()),
            size: 0,
            base: None,
            visible_end: 0,
            extents: Vec::new(),
        }
    }

    pub(crate) fn original_in(
        storage: &StorageRoot,
        version: &FileVersion,
    ) -> Result<Self, AccountError> {
        if version.size > MAX_FILE || version.id.starts_with("cirrus-staged:") {
            return Err(invalid());
        }
        Ok(Self {
            storage: Some(storage.clone()),
            size: version.size,
            base: Some(version.clone()),
            visible_end: version.size,
            extents: Vec::new(),
        })
    }

    pub(crate) fn import_in(
        storage: &StorageRoot,
        input: &mut impl Read,
        size: u64,
    ) -> Result<Self, AccountError> {
        if size > MAX_FILE {
            return Err(AccountError::new("file exceeds 1 TiB"));
        }
        let mut root = Self::empty_in(storage);
        let mut bytes = vec![0; OBJECT];
        while root.size < size {
            let length = (size - root.size).min(OBJECT as u64) as usize;
            input
                .read_exact(&mut bytes[..length])
                .map_err(|_| AccountError::new("cannot read staging source"))?;
            if bytes[..length].iter().all(|byte| *byte == 0) {
                root.resize(root.size + length as u64)?;
            } else {
                root.write(root.size, &bytes[..length])?;
            }
        }
        Ok(root)
    }

    /// An unpublished request import owns every object it creates. Cancellation
    /// can discard those candidates; it must never reclaim a journaled root.
    pub(crate) fn import_candidate_in(
        storage: &StorageRoot,
        input: &mut impl Read,
        size: u64,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Self, AccountError> {
        if size > MAX_FILE {
            return Err(invalid());
        }
        let mut root = Self::empty_in(storage);
        let mut bytes = vec![0; OBJECT];
        while root.size < size {
            let length = (size - root.size).min(OBJECT as u64) as usize;
            let result = input.read_exact(&mut bytes[..length]);
            if cancelled() {
                root.discard_candidate(None)?;
                return Err(AccountError::new("request cancelled before staging"));
            }
            result.map_err(|_| AccountError::new("cannot read staging source"))?;
            if bytes[..length].iter().all(|b| *b == 0) {
                root.resize(root.size + length as u64)?;
            } else {
                root.write(root.size, &bytes[..length])?;
            }
        }
        Ok(root)
    }

    pub(crate) fn discard_candidate(&self, manifest: Option<&str>) -> Result<(), AccountError> {
        let storage = self.storage()?;
        let mut names = std::collections::BTreeSet::new();
        // Only imported objects are uniquely owned; an original-only move has
        // no extents. Never reclaim borrowed original ranges or pinned bytes.
        if self.base.is_some() && !self.extents.is_empty() {
            return Err(invalid());
        }
        for extent in &self.extents {
            names.insert(extent.object.name.clone());
        }
        if let Some(name) = manifest {
            let mut conn = database_in(storage)?;
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|_| invalid())?;
            let published: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM operation_journal WHERE staged_file=?1)",
                    [name],
                    |r| r.get(0),
                )
                .map_err(|_| invalid())?;
            if published {
                return Err(invalid());
            }
            tx.execute("DELETE FROM dirty_roots WHERE root=?1", [name])
                .map_err(|_| invalid())?;
            tx.commit().map_err(|_| invalid())?;
            names.insert(name.to_owned());
        }
        let dir = storage.staging_dir()?;
        for name in names {
            let (file, before) = super::open_staged_in(storage, &name)?;
            super::verify_staged_metadata(&file, &before)?;
            rustix::fs::unlinkat(&dir, name.as_str(), rustix::fs::AtFlags::empty())
                .map_err(|_| invalid())?;
        }
        rustix::fs::fsync(&dir).map_err(|_| invalid())
    }

    pub(crate) fn load_at(storage: &StorageRoot, name: &str) -> Result<Self, AccountError> {
        Self::load_in_root(storage, &database_in(storage)?, name)
    }

    pub(crate) fn load_in_root(
        storage: &StorageRoot,
        conn: &Connection,
        name: &str,
    ) -> Result<Self, AccountError> {
        let (mut file, before) = super::open_staged_in(storage, name)?;
        if before.len() > MAX_MANIFEST {
            return Err(invalid());
        }
        let expected: String = conn
            .query_row(
                "SELECT digest FROM dirty_roots WHERE root=?1",
                [name],
                |row| row.get(0),
            )
            .map_err(|_| invalid())?;
        let mut bytes = Vec::with_capacity(before.len() as usize);
        Read::by_ref(&mut file)
            .take(MAX_MANIFEST + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        super::verify_staged_metadata(&file, &before)?;
        if format!("{:x}", Sha256::digest(&bytes)) != expected {
            return Err(invalid());
        }
        let mut root: Self = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        root.storage = Some(storage.clone());
        root.validate()?;
        Ok(root)
    }

    pub(super) fn storage(&self) -> Result<&StorageRoot, AccountError> {
        self.storage.as_ref().ok_or_else(invalid)
    }

    fn validate(&self) -> Result<(), AccountError> {
        if self.size > MAX_FILE
            || self.extents.len() > MAX_EXTENTS
            || self.visible_end > self.base.as_ref().map_or(0, |base| base.size)
            || self.visible_end > self.size
            || self
                .base
                .as_ref()
                .is_some_and(|base| base.size > MAX_FILE || base.id.starts_with("cirrus-staged:"))
        {
            return Err(invalid());
        }
        let mut end = 0;
        for extent in &self.extents {
            if extent.length == 0
                || extent.start < end
                || extent
                    .start
                    .checked_add(extent.length)
                    .is_none_or(|end| end > self.size)
                || extent
                    .offset
                    .checked_add(extent.length)
                    .is_none_or(|end| end > extent.object.size)
            {
                return Err(invalid());
            }
            end = extent.start + extent.length;
        }
        Ok(())
    }

    pub(crate) fn save(&self) -> Result<String, AccountError> {
        self.save_checked(|_| {
            Err(AccountError::new(
                "dirty root registration plan changed; local copies retained; retry",
            ))
        })
    }

    // Only mounted publication supplies an exact original identity/version/
    // parent guard. Other callers retain their ordinary refusal contract.
    pub(crate) fn save_checked(
        &self,
        check: impl Fn(&Connection) -> Result<(), AccountError>,
    ) -> Result<String, AccountError> {
        let storage = self.storage()?;
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        if bytes.len() as u64 > MAX_MANIFEST {
            return Err(AccountError::new("dirty extent metadata limit exceeded"));
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let name = save_bytes(
            storage,
            &bytes,
            #[cfg(feature = "fault-injection")]
            true,
        )?;
        let base = self
            .base
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| invalid())?;
        let check_candidate = || -> Result<(), AccountError> {
            let (mut candidate, before) = super::open_staged_in(storage, &name)?;
            if before.len() != bytes.len() as u64 {
                return Err(invalid());
            }
            let mut observed = Vec::with_capacity(bytes.len());
            Read::by_ref(&mut candidate)
                .take(MAX_MANIFEST + 1)
                .read_to_end(&mut observed)
                .map_err(|_| invalid())?;
            super::verify_staged_metadata(&candidate, &before)?;
            if observed != bytes {
                return Err(invalid());
            }
            Ok(())
        };
        // One immutable candidate, at most eight SQL plans. No INSERT or
        // COMMIT result is ever retried, including an ambiguous success.
        let mut plans_left = 8;
        loop {
            // Candidate durability precedes State admission, including refusal.
            // Mounted local turns may wait for a same-process lease here, before
            // opening/capturing any SQL plan. Release it before head publication;
            // other callers retain the ordinary per-reservation ownership.
            #[cfg(feature = "fault-injection")]
            crate::wait_test_window("CIRRUS_TEST_ROOT_REGISTRATION_ADMISSION_WINDOW")?;
            let _state_phase = crate::ownership::admit_local_state_turn_in(storage)?;
            let reservation;
            let mut conn = database_in(storage)?;
            let planning_version: i64 = conn
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| AccountError::new("cannot inspect dirty root registration plan"))?;
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_REGISTRATION_TRACE").is_some() {
                eprintln!(
                    "cirrus lab registration plan: candidate={name} digest={digest} size={} data_version={planning_version}",
                    self.size
                );
            }
            let planned = if crate::storage::limits::view_in(storage)?.limits.is_some() {
                serde_json::to_vec(&(&name, &digest, self.size, &base))
                    .map_err(|_| invalid())?
                    .len() as u64
            } else {
                0
            };
            reservation = crate::storage::sql_reservation::SqlReservation::begin_in(
                storage,
                crate::storage::sql_reservation::Store::State,
                Some(&conn),
                planned,
                0,
                false,
            )?;
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_REGISTRATION_TRACE").is_some() {
                let current: i64 = conn
                    .pragma_query_value(None, "data_version", |row| row.get(0))
                    .map_err(|_| invalid())?;
                eprintln!(
                    "cirrus lab registration reserved: candidate={name} data_version={current}"
                );
            }
            if let Some(reservation) = &reservation {
                reservation.bound_pages(&conn)?;
            }
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_REGISTRATION_TRACE").is_some() {
                let current: i64 = conn
                    .pragma_query_value(None, "data_version", |row| row.get(0))
                    .map_err(|_| invalid())?;
                eprintln!(
                    "cirrus lab registration bounded: candidate={name} data_version={current}"
                );
            }
            #[cfg(feature = "fault-injection")]
            crate::wait_test_window("CIRRUS_TEST_ROOT_REGISTRATION_RESERVED_WINDOW")?;
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| {
                    super::sqlite_storage_error(error, "cannot begin dirty root registration")
                })?;
            if reservation.is_some() {
                let current: i64 = tx
                    .pragma_query_value(None, "data_version", |row| row.get(0))
                    .map_err(|_| {
                        AccountError::new("cannot inspect dirty root registration plan")
                    })?;
                if current != planning_version {
                    #[cfg(feature = "fault-injection")]
                    if std::env::var_os("CIRRUS_TEST_REGISTRATION_TRACE").is_some() {
                        eprintln!(
                            "cirrus lab registration refused before INSERT: candidate={name} plan={planning_version} current={current}"
                        );
                    }
                    if plans_left == 1 {
                        return Err(AccountError::new(
                            "dirty root registration plan changed; local copies retained; retry",
                        ));
                    }
                    check(&tx)?;
                    check_candidate()?;
                    tx.rollback().map_err(|_| {
                        AccountError::new(
                            "cannot roll back registration plan; local copies retained",
                        )
                    })?;
                    conn.close().map_err(|_| {
                        AccountError::new("cannot close registration plan; local copies retained")
                    })?;
                    drop(reservation);
                    drop(_state_phase);
                    plans_left -= 1;
                    #[cfg(feature = "fault-injection")]
                    if std::env::var_os("CIRRUS_TEST_REGISTRATION_TRACE").is_some() {
                        eprintln!(
                            "cirrus lab registration replan before INSERT: candidate={name} remaining={plans_left}"
                        );
                    }
                    continue;
                }
            }
            if plans_left < 8 {
                // Recheck inside the new writer transaction too: changes in
                // the release/re-admission gap must not authorize registration.
                check(&tx)?;
                check_candidate()?;
            }
            tx.execute(
                "INSERT INTO dirty_roots(root,digest,size,base) VALUES(?1,?2,?3,?4)",
                params![name, digest, self.size, base],
            )
            .map_err(|error| super::sqlite_storage_error(error, "cannot persist dirty root"))?;
            #[cfg(feature = "fault-injection")]
            crate::wait_test_window("CIRRUS_TEST_ROOT_REGISTRATION_COMMIT_WINDOW")?;
            if let Some(reservation) = &reservation {
                reservation.validate(&tx)?;
            } else if crate::storage::limits::view_in(storage)?.limits.is_some() {
                return Err(AccountError::new(crate::storage::limits::PRESSURE));
            }
            let committed = tx.commit();
            #[cfg(feature = "fault-injection")]
            let committed = if committed.is_ok()
                && let Some(marker) =
                    std::env::var_os("CIRRUS_TEST_ROOT_REGISTRATION_COMMITTED_ERROR")
                && std::fs::remove_file(marker).is_ok()
            {
                eprintln!(
                    "cirrus lab registration committed-but-returned-error (not hardware I/O)"
                );
                Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                    None,
                ))
            } else {
                committed
            };
            // A registry row is NOT a journal head or acknowledgement. Even if a
            // failed COMMIT actually persisted it, return an error, never advance
            // the caller or infer success from metadata. No marker repair needed:
            // neither possible outcome is eligible for upload without publication.
            conn.close().map_err(|_| AccountError::new(
            "cannot close dirty root registration database; outcome unknown; local copies retained",
        ))?;
            committed.map_err(|_| {
                AccountError::new(
                    "cannot commit dirty root registration; outcome unknown; local copies retained",
                )
            })?;
            return Ok(name);
        }
    }

    pub(crate) fn len(&self) -> u64 {
        self.size
    }

    // A metadata-only preservation root contains no acknowledged edit. Keep
    // its original identity separate from a later journal PUT precondition.
    pub(super) fn unchanged_base(&self) -> Option<&FileVersion> {
        self.base.as_ref().filter(|base| {
            self.extents.is_empty() && self.size == base.size && self.visible_end == base.size
        })
    }

    pub(super) fn original_base_json(&self) -> Result<Option<String>, AccountError> {
        self.base
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| invalid())
    }

    // A pin may be removed only when every original gap in this immutable
    // interpretation has independent durable bytes. No pin/cache fallback,
    // durable object allocation or second State connection is allowed here.
    pub(super) fn originals_independent_in(
        &self,
        conn: &Connection,
        budget: &mut OriginalBudget,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<bool, AccountError> {
        let Some(base) = &self.base else {
            return Ok(true);
        };
        let mut offset = 0;
        let mut verified_block = None;
        while offset < self.visible_end {
            super::check_pin_cancelled(cancelled)?;
            let index = self
                .extents
                .partition_point(|extent| extent.start + extent.length <= offset);
            let extent = self.extents.get(index);
            if let Some(extent) = extent.filter(|extent| extent.start <= offset) {
                offset = (extent.start + extent.length).min(self.visible_end);
                continue;
            }
            let block = offset / BLOCK * BLOCK;
            if verified_block != Some(block) {
                let Some(object) = retained_in(conn, base, block)? else {
                    return Ok(false);
                };
                let length = (base.size - block).min(BLOCK);
                if object.size != length {
                    return Err(invalid());
                }
                if budget.first(base, block, length)? {
                    object.range(self.storage()?, 0, length as usize)?;
                }
                verified_block = Some(block);
            }
            offset = (block + BLOCK)
                .min(self.visible_end)
                .min(extent.map_or(self.visible_end, |extent| extent.start));
        }
        Ok(true)
    }

    // Advance through required original blocks, verifying already durable
    // objects. The caller closes its pin read transaction before capture.
    pub(super) fn next_missing_original_in(
        &self,
        conn: &Connection,
        cursor: &mut u64,
        budget: &mut OriginalBudget,
    ) -> Result<Option<(FileVersion, u64, u32)>, AccountError> {
        let Some(base) = &self.base else {
            return Ok(None);
        };
        while *cursor < self.visible_end {
            let index = self
                .extents
                .partition_point(|extent| extent.start + extent.length <= *cursor);
            let extent = self.extents.get(index);
            if let Some(extent) = extent.filter(|extent| extent.start <= *cursor) {
                *cursor = (extent.start + extent.length).min(self.visible_end);
                continue;
            }
            let block = *cursor / BLOCK * BLOCK;
            let length = (base.size - block).min(BLOCK);
            let first = budget.first(base, block, length)?;
            *cursor = (block + BLOCK).min(self.visible_end);
            if let Some(object) = retained_in(conn, base, block)? {
                if object.size != length {
                    return Err(invalid());
                }
                if first {
                    object.range(self.storage()?, 0, length as usize)?;
                }
            } else {
                return Ok(Some((base.clone(), block, length as u32)));
            }
        }
        Ok(None)
    }

    // Recovery verifies local extents without fetching missing original bytes.
    // Original-byte protected-union admission remains mandatory before PUT.
    pub(super) fn verify_payloads(&self) -> Result<(), AccountError> {
        let mut seen = std::collections::BTreeSet::new();
        for extent in &self.extents {
            if seen.insert(&extent.object.name) {
                extent
                    .object
                    .range(self.storage()?, 0, extent.object.size as usize)?;
            }
        }
        Ok(())
    }

    /// Preserve a bounded amount of already verified local content at a rename
    /// boundary. This never fetches missing content or hydrates the whole file.
    pub(crate) fn retain_available(
        &self,
        mut local: impl FnMut(&FileVersion, u64, u32) -> Option<Vec<u8>>,
    ) -> Result<(), AccountError> {
        let Some(base) = &self.base else {
            return Ok(());
        };
        let mut offset = 0;
        let mut blocks = 0;
        while offset < self.visible_end && blocks < 4 {
            let index = self
                .extents
                .partition_point(|extent| extent.start + extent.length <= offset);
            let extent = self.extents.get(index);
            if let Some(extent) = extent.filter(|extent| extent.start <= offset) {
                offset = (extent.start + extent.length).min(self.visible_end);
            } else {
                let block = offset / BLOCK * BLOCK;
                if retained(self.storage()?, base, block)?.is_none()
                    && let Some(bytes) = local(base, block, (base.size - block).min(BLOCK) as u32)
                {
                    capture(self.storage()?, base, block, &bytes)?;
                }
                offset = (block + BLOCK)
                    .min(self.visible_end)
                    .min(extent.map_or(self.visible_end, |extent| extent.start));
                blocks += 1;
            }
        }
        Ok(())
    }

    pub(crate) fn resize(&mut self, size: u64) -> Result<(), AccountError> {
        if size > MAX_FILE {
            return Err(AccountError::new("file exceeds 1 TiB"));
        }
        self.visible_end = self.visible_end.min(size);
        self.extents.retain(|extent| extent.start < size);
        for extent in &mut self.extents {
            extent.length = extent.length.min(size - extent.start);
        }
        self.size = size;
        Ok(())
    }

    pub(crate) fn write(&mut self, start: u64, bytes: &[u8]) -> Result<(), AccountError> {
        let end = start
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= MAX_FILE)
            .ok_or_else(|| AccountError::new("file exceeds 1 TiB"))?;
        if bytes.is_empty() {
            return Ok(());
        }
        let mut extents = Vec::with_capacity(self.extents.len() + bytes.len().div_ceil(OBJECT) + 2);
        for extent in &self.extents {
            let old_end = extent.start + extent.length;
            if old_end <= start || extent.start >= end {
                extents.push(extent.clone());
                continue;
            }
            if extent.start < start {
                let mut left = extent.clone();
                left.length = start - left.start;
                extents.push(left);
            }
            if old_end > end {
                let mut right = extent.clone();
                right.offset += end - right.start;
                right.start = end;
                right.length = old_end - end;
                extents.push(right);
            }
        }
        if extents.len() + bytes.len().div_ceil(OBJECT) > MAX_EXTENTS {
            return Err(AccountError::new("dirty extent metadata limit exceeded"));
        }
        for (index, bytes) in bytes.chunks(OBJECT).enumerate() {
            extents.push(Extent {
                start: start + (index * OBJECT) as u64,
                length: bytes.len() as u64,
                object: Object::save(self.storage()?, bytes)?,
                offset: 0,
            });
        }
        extents.sort_by_key(|extent| extent.start);
        self.extents = extents;
        self.size = self.size.max(end);
        Ok(())
    }

    pub(crate) fn range(
        &self,
        offset: u64,
        length: u32,
        mut fetch: impl FnMut(&FileVersion, u64, u32) -> Result<Vec<u8>, AccountError>,
    ) -> Result<Vec<u8>, AccountError> {
        self.range_objects(offset, length, |base, offset, length| {
            if let Some(object) = retained(self.storage()?, base, offset)? {
                return Ok(object);
            }
            capture(self.storage()?, base, offset, &fetch(base, offset, length)?)
        })
    }

    pub(super) fn local_objects(&self) -> Result<BTreeMap<u64, Object>, AccountError> {
        let mut objects = BTreeMap::new();
        let Some(base) = &self.base else {
            return Ok(objects);
        };
        if self.visible_end == 0 {
            return Ok(objects);
        }
        let version = serde_json::to_string(base).map_err(|_| invalid())?;
        let conn = database_in(self.storage()?)?;
        let mut stmt = conn.prepare("SELECT offset,CASE WHEN length(object)<=24000 THEN object END FROM dirty_bases WHERE version=?1 ORDER BY offset LIMIT 4097").map_err(|_| invalid())?;
        let rows = stmt
            .query_map([version], |row| {
                Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| invalid())?;
        for row in rows {
            let (offset, encoded) = row.map_err(|_| invalid())?;
            let object: Object = serde_json::from_str(&encoded).map_err(|_| invalid())?;
            if offset >= base.size
                || !offset.is_multiple_of(BLOCK)
                || object.size != (base.size - offset).min(BLOCK)
                || objects.len() == 4096
            {
                return Err(invalid());
            }
            objects.insert(offset, object);
        }
        Ok(objects)
    }

    pub(super) fn range_local(
        &self,
        offset: u64,
        length: u32,
        objects: &BTreeMap<u64, Object>,
    ) -> Result<Vec<u8>, AccountError> {
        self.range_objects(offset, length, |_, offset, _| {
            objects.get(&offset).cloned().ok_or_else(|| {
                AccountError::new("exact original content base is unavailable locally")
            })
        })
    }

    fn range_objects(
        &self,
        offset: u64,
        length: u32,
        mut original: impl FnMut(&FileVersion, u64, u32) -> Result<Object, AccountError>,
    ) -> Result<Vec<u8>, AccountError> {
        let end = offset
            .checked_add(u64::from(length))
            .filter(|end| *end <= self.size)
            .ok_or_else(invalid)?;
        let mut bytes = vec![0; length as usize];
        let mut cursor = offset;
        let mut index = self
            .extents
            .partition_point(|extent| extent.start + extent.length <= cursor);
        while cursor < end {
            let extent = self.extents.get(index);
            let finish = if let Some(extent) = extent.filter(|extent| extent.start <= cursor) {
                let finish = end.min(extent.start + extent.length);
                let part = extent.object.range(
                    self.storage()?,
                    extent.offset + cursor - extent.start,
                    (finish - cursor) as usize,
                )?;
                bytes[(cursor - offset) as usize..(finish - offset) as usize]
                    .copy_from_slice(&part);
                index += 1;
                finish
            } else {
                let finish = end.min(extent.map_or(end, |extent| extent.start));
                let base_end = finish.min(self.visible_end);
                if cursor < base_end {
                    let base = self.base.as_ref().ok_or_else(invalid)?;
                    let mut position = cursor;
                    while position < base_end {
                        let block_start = position / BLOCK * BLOCK;
                        let block_end = (block_start + BLOCK).min(base.size);
                        let part_end = base_end.min(block_end);
                        let object = original(base, block_start, (block_end - block_start) as u32)?;
                        let part = object.range(
                            self.storage()?,
                            position - block_start,
                            (part_end - position) as usize,
                        )?;
                        bytes[(position - offset) as usize..(part_end - offset) as usize]
                            .copy_from_slice(&part);
                        position = part_end;
                    }
                }
                finish
            };
            cursor = finish;
        }
        Ok(bytes)
    }

    // A tiny surviving slice can require verifying a whole payload block.
    // Budget physical verification bytes, not just the logical output length.
    pub(crate) fn bounded_range(
        &self,
        offset: u64,
        length: u32,
        budget: u64,
    ) -> Result<(u32, u64), AccountError> {
        let end = offset
            .checked_add(u64::from(length))
            .filter(|end| *end <= self.size)
            .ok_or_else(invalid)?;
        let mut cursor = offset;
        let mut cost = 0;
        let mut index = self
            .extents
            .partition_point(|extent| extent.start + extent.length <= cursor);
        while cursor < end {
            let extent = self.extents.get(index);
            let (finish, charge) =
                if let Some(extent) = extent.filter(|extent| extent.start <= cursor) {
                    let position = extent.offset + cursor - extent.start;
                    let block = position / BLOCK * BLOCK;
                    let charge = extent
                        .object
                        .size
                        .checked_sub(block)
                        .ok_or_else(invalid)?
                        .min(BLOCK);
                    if charge == 0 {
                        return Err(invalid());
                    }
                    let finish = end
                        .min(extent.start + extent.length)
                        .min(cursor + BLOCK - position % BLOCK);
                    (finish, charge)
                } else {
                    let finish = end.min(extent.map_or(end, |extent| extent.start));
                    if cursor >= self.visible_end {
                        (finish, 0)
                    } else {
                        let base = self.base.as_ref().ok_or_else(invalid)?;
                        let block = cursor / BLOCK * BLOCK;
                        (
                            finish.min(self.visible_end).min(block + BLOCK),
                            (base.size - block).min(BLOCK),
                        )
                    }
                };
            if cost + charge > budget {
                break;
            }
            cost += charge;
            cursor = finish;
            if extent.is_some_and(|extent| extent.start + extent.length == cursor) {
                index += 1;
            }
        }
        Ok(((cursor - offset) as u32, cost))
    }
}

fn retained(
    storage: &StorageRoot,
    base: &FileVersion,
    offset: u64,
) -> Result<Option<Object>, AccountError> {
    retained_in(&database_in(storage)?, base, offset)
}

fn retained_in(
    conn: &Connection,
    base: &FileVersion,
    offset: u64,
) -> Result<Option<Object>, AccountError> {
    let version = serde_json::to_string(base).map_err(|_| invalid())?;
    let encoded: Option<String> = conn
        .query_row(
            "SELECT object FROM dirty_bases WHERE version=?1 AND offset=?2",
            params![version, offset],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| invalid())?;
    encoded
        .map(|encoded| serde_json::from_str(&encoded).map_err(|_| invalid()))
        .transpose()
}

pub(super) fn capture_local_in(
    storage: &StorageRoot,
    base: &FileVersion,
    offset: u64,
    bytes: &[u8],
) -> Result<(), AccountError> {
    capture(storage, base, offset, bytes).map(|_| ())
}

fn capture(
    storage: &StorageRoot,
    base: &FileVersion,
    offset: u64,
    bytes: &[u8],
) -> Result<Object, AccountError> {
    if offset >= base.size
        || !offset.is_multiple_of(BLOCK)
        || bytes.len() as u64 != (base.size - offset).min(BLOCK)
    {
        return Err(invalid());
    }
    let verified = |object: Object| -> Result<Object, AccountError> {
        if object.size != bytes.len() as u64 || object.range(storage, 0, bytes.len())? != bytes {
            return Err(invalid());
        }
        Ok(object)
    };
    // Already published exact-base blocks need neither new allocation nor a
    // State lease, even under pressure. Verify actual bytes, not metadata alone.
    if let Some(object) = retained(storage, base, offset)? {
        return verified(object);
    }
    // The conditional GET has already completed at every caller. Save/sync the
    // bounded candidate before taking State or SQLite writer ownership. A
    // racing loser remains a charged orphan; never delete/reassign its name.
    let object = Object::save(storage, bytes)?;
    let encoded = serde_json::to_string(&object).map_err(|_| invalid())?;
    let version = serde_json::to_string(base).map_err(|_| invalid())?;
    let reservation;
    let mut conn = database_in(storage)?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect original content retention plan"))?;
    let planned = if crate::storage::limits::view_in(storage)?.limits.is_some() {
        serde_json::to_vec(&(&version, offset, &encoded))
            .map_err(|_| invalid())?
            .len() as u64
    } else {
        0
    };
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_BASE_CAPTURE_ADMISSION_WINDOW")?;
    reservation = crate::storage::sql_reservation::SqlReservation::begin_in(
        storage,
        crate::storage::sql_reservation::Store::State,
        Some(&conn),
        planned,
        0,
        false,
    )?;
    if let Some(reservation) = &reservation {
        reservation.bound_pages(&conn)?;
    }
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_BASE_CAPTURE_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| {
            super::sqlite_storage_error(error, "cannot begin original content retention")
        })?;
    // BEGIN serializes the exact (version,block) decision. Reuse the actual
    // winner, not this process's unreferenced candidate. A committed winner
    // makes the growth plan irrelevant; only a new INSERT needs its fence.
    let winner = retained_in(&tx, base, offset)?;
    let inserted = winner.is_none();
    if inserted {
        if reservation.is_some() {
            let current: i64 = tx
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| AccountError::new("cannot inspect original content retention plan"))?;
            if current != planning_version {
                return Err(AccountError::new(
                    "original content retention plan changed; local copies retained; retry",
                ));
            }
        }
        tx.execute(
            "INSERT INTO dirty_bases(version,offset,object) VALUES(?1,?2,?3)",
            params![version, offset, encoded],
        )
        .map_err(|error| {
            super::sqlite_storage_error(error, "cannot retain original content range")
        })?;
        #[cfg(feature = "fault-injection")]
        crate::wait_test_window("CIRRUS_TEST_BASE_CAPTURE_COMMIT_WINDOW")?;
        if let Some(reservation) = &reservation {
            reservation.validate(&tx)?;
        } else if crate::storage::limits::view_in(storage)?.limits.is_some() {
            return Err(AccountError::new(crate::storage::limits::PRESSURE));
        }
    }
    #[cfg(feature = "fault-injection")]
    if inserted
        && std::env::var_os("CIRRUS_TEST_BASE_CAPTURE_COMMIT_ABORT")
            .is_some_and(|path| std::fs::remove_file(path).is_ok())
    {
        tx.commit_hook(Some(|| {
            eprintln!("cirrus lab original capture COMMIT hook veto (SQLite rollback)");
            true
        }));
    }
    let committed = tx.commit();
    #[cfg(feature = "fault-injection")]
    let committed = if inserted
        && committed.is_ok()
        && let Some(marker) = std::env::var_os("CIRRUS_TEST_BASE_CAPTURE_COMMITTED_ERROR")
        && std::fs::remove_file(marker).is_ok()
    {
        eprintln!("cirrus lab capture committed-but-returned-error (not hardware I/O)");
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
            None,
        ))
    } else {
        committed
    };
    conn.close().map_err(|_| AccountError::new(
        "cannot close original content retention database; outcome unknown; local copies retained",
    ))?;
    drop(reservation);
    // An error may have left a reference, but this turn must not authorize a
    // destructive mutation from that fact. A later turn independently reads
    // actual payloads; protected-union admission remains mandatory before PUT.
    committed.map_err(|_| {
        AccountError::new(
            "cannot commit original content retention; outcome unknown; local copies retained",
        )
    })?;
    verified(winner.unwrap_or(object))
}

fn persist_preparation(
    storage: &StorageRoot,
    version: &str,
    offset: u64,
    prepared: &BTreeMap<u64, Object>,
    bounded: bool,
) -> Result<bool, AccountError> {
    let reservation;
    let mut conn = database_in(storage)?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect preparation progress plan"))?;
    let previous: Option<u64> = conn
        .query_row(
            "SELECT offset FROM dirty_preparations WHERE version=?1",
            [version],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| invalid())?;
    // Actual-byte verification is outside State/SQLite writer ownership. Only
    // unchanged metadata witnesses are checked during the short transaction.
    if !integrity::verify_preparation(storage, prepared, bounded)? {
        return Ok(false);
    }
    integrity::preparation_unchanged(storage, prepared)?;
    if previous.is_some_and(|previous| previous >= offset) {
        return Ok(true);
    }
    let planned = if crate::storage::limits::view_in(storage)?.limits.is_some() {
        serde_json::to_vec(&(version, offset))
            .map_err(|_| invalid())?
            .len() as u64
    } else {
        0
    };
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_PREPARATION_ADMISSION_WINDOW")?;
    reservation = crate::storage::sql_reservation::SqlReservation::begin_in(
        storage,
        crate::storage::sql_reservation::Store::State,
        Some(&conn),
        planned,
        0,
        false,
    )?;
    if let Some(reservation) = &reservation {
        reservation.bound_pages(&conn)?;
    }
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| super::sqlite_storage_error(error, "cannot begin preparation progress"))?;
    if reservation.is_some() {
        let current: i64 = tx
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect preparation progress plan"))?;
        if current != planning_version {
            return Err(AccountError::new(
                "preparation progress plan changed; local copies retained; retry",
            ));
        }
    }
    tx.execute("INSERT INTO dirty_preparations(version,offset) VALUES(?1,?2) ON CONFLICT(version) DO UPDATE SET offset=max(offset,excluded.offset)",params![version,offset])
        .map_err(|error| super::sqlite_storage_error(error,"cannot persist original content preparation"))?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_PREPARATION_COMMIT_WINDOW")?;
    integrity::preparation_unchanged(storage, prepared)?;
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view_in(storage)?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    let committed = tx.commit();
    #[cfg(feature = "fault-injection")]
    let committed = if committed.is_ok()
        && let Some(marker) = std::env::var_os("CIRRUS_TEST_PREPARATION_COMMITTED_ERROR")
        && std::fs::remove_file(marker).is_ok()
    {
        eprintln!("cirrus lab preparation committed-but-returned-error (not hardware I/O)");
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
            None,
        ))
    } else {
        committed
    };
    conn.close().map_err(|_| {
        AccountError::new(
            "cannot close preparation progress database; outcome unknown; local copies retained",
        )
    })?;
    committed.map_err(|_| {
        AccountError::new(
            "cannot commit preparation progress; outcome unknown; local copies retained",
        )
    })?;
    Ok(true)
}

/// Retain the original blocks actually needed by this immutable byte map.
pub(crate) fn prepare_base(
    root: &Overlay,
    mut fetch: impl FnMut(&FileVersion, u64, u32) -> Result<Vec<u8>, AccountError>,
    bounded: bool,
) -> Result<bool, AccountError> {
    let storage = root.storage()?;
    let Some(base) = &root.base else {
        return Ok(true);
    };
    let version = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(root).map_err(|_| invalid())?)
    );
    let mut requests = 0;
    // A successor normally shares all original blocks with its predecessor.
    // Inspect the bounded reference map once, rather than spending another
    // automatic turn (and SQLite commit) on every four already retained blocks.
    let mut available = root.local_objects()?;
    let saved: u64 = database_in(storage)?
        .query_row(
            "SELECT offset FROM dirty_preparations WHERE version=?1",
            [&version],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| invalid())?
        .unwrap_or(0);
    if saved > root.visible_end {
        return Err(invalid());
    }
    // The durable cursor is advisory, not evidence that references or bytes
    // still exist. Re-enumerate gaps from zero on every turn; the bounded
    // ephemeral witness cache avoids rehashing unchanged prefixes each time.
    let mut prepared = BTreeMap::new();
    let mut gap = |start: u64, end: u64| {
        for (&offset, object) in available.range((start / BLOCK * BLOCK)..end) {
            prepared.insert(offset, object.clone());
        }
    };
    let mut cursor = 0;
    for extent in &root.extents {
        if cursor >= root.visible_end {
            break;
        }
        let start = extent.start.min(root.visible_end);
        if cursor < start {
            gap(cursor, start);
        }
        cursor = (extent.start + extent.length).min(root.visible_end);
    }
    if cursor < root.visible_end {
        gap(cursor, root.visible_end);
    }
    if !integrity::verify_preparation(storage, &prepared, bounded)? {
        return Ok(false);
    }
    let mut offset = 0;
    while offset < root.visible_end {
        let index = root
            .extents
            .partition_point(|extent| extent.start + extent.length <= offset);
        let extent = root.extents.get(index);
        if let Some(extent) = extent.filter(|extent| extent.start <= offset) {
            offset = (extent.start + extent.length).min(root.visible_end);
        } else {
            let block = offset / BLOCK * BLOCK;
            let mut captured = false;
            if let std::collections::btree_map::Entry::Vacant(slot) = available.entry(block) {
                if bounded && requests == 4 {
                    return Ok(false);
                }
                let length = (base.size - block).min(BLOCK) as u32;
                let body = fetch(base, block, length)?;
                let object = capture(storage, base, block, &body)?;
                prepared.insert(block, object.clone());
                slot.insert(object);
                crate::executor::mark_progress();
                requests += 1;
                captured = true;
            }
            offset = (block + BLOCK)
                .min(root.visible_end)
                .min(extent.map_or(root.visible_end, |extent| extent.start));
            if captured && !persist_preparation(storage, &version, offset, &prepared, bounded)? {
                return Ok(false);
            }
        }
    }
    persist_preparation(storage, &version, offset, &prepared, bounded)
}

/// Protect every journal-referenced byte interpretation, including resolved
/// recovery and detached roots. Unreferenced objects are still never collected.
pub(crate) fn protected_bases_in(
    storage: &StorageRoot,
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<Vec<String>, AccountError> {
    let conn = database_in(storage)?;
    let mut stmt = conn.prepare("SELECT DISTINCT r.root,r.base FROM dirty_roots r JOIN operation_journal j ON j.staged_file=r.root WHERE r.base IS NOT NULL AND j.op_type='write' AND j.instance=?1 AND j.space=?2")
        .map_err(|_| invalid())?;
    let rows = stmt
        .query_map(params![instance, space], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| invalid())?;
    let mut roots = Vec::new();
    for row in rows {
        let (name, base) = row.map_err(|_| invalid())?;
        let base: FileVersion = serde_json::from_str(&base).map_err(|_| invalid())?;
        if base.path.starts_with(path) {
            roots.push(name);
        }
    }
    Ok(roots)
}

enum HashPass {
    Advancing {
        _storage: StorageRoot,
        offset: u64,
        hash: Sha256,
    },
    Retired,
}
static HASH_PASSES: OnceLock<
    Mutex<BTreeMap<(RootIdentity, String, String), Arc<Mutex<HashPass>>>>,
> = OnceLock::new();

/// At most 1 MiB per turn. Never trust a process-local prefix across restart.
pub(crate) fn digest_step(
    name: &str,
    purpose: &str,
    root: &Overlay,
) -> Result<Option<String>, AccountError> {
    let storage = root.storage()?;
    let key = (storage.identity(), name.to_owned(), purpose.to_owned());
    let registry = HASH_PASSES.get_or_init(Default::default);
    loop {
        let entry = {
            let mut passes = registry.lock().map_err(|_| invalid())?;
            if !passes.contains_key(&key) && passes.len() >= 4096 {
                return Err(AccountError::new("dirty hashing capacity exhausted"));
            }
            Arc::clone(passes.entry(key.clone()).or_insert_with(|| {
                Arc::new(Mutex::new(HashPass::Advancing {
                    _storage: storage.clone(),
                    offset: 0,
                    hash: Sha256::new(),
                }))
            }))
        };
        // Only this immutable manifest/purpose waits for its payload work.
        let mut pass = entry.lock().map_err(|_| invalid())?;
        let HashPass::Advancing { offset, hash, .. } = &mut *pass else {
            // Another caller consumed this entry while we waited for it.
            continue;
        };
        let end = root.len().min(offset.saturating_add(1024 * 1024));
        let mut budget = 1024 * 1024;
        while *offset < end {
            let (length, cost) =
                root.bounded_range(*offset, (end - *offset).min(BLOCK) as u32, budget)?;
            if length == 0 {
                break;
            }
            hash.update(root.range(*offset, length, |_, _, _| {
                Err(AccountError::new(
                    "exact original content base is unavailable locally",
                ))
            })?);
            *offset += u64::from(length);
            crate::executor::mark_progress();
            budget -= cost;
        }
        if *offset != root.len() {
            return Ok(None);
        }
        let HashPass::Advancing { hash, .. } = std::mem::replace(&mut *pass, HashPass::Retired)
        else {
            unreachable!();
        };
        let removed = {
            let mut passes = registry.lock().map_err(|_| invalid())?;
            if !passes
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &entry))
            {
                return Err(invalid());
            }
            passes.remove(&key)
        };
        drop(removed);
        return Ok(Some(format!("{:x}", hash.finalize())));
    }
}

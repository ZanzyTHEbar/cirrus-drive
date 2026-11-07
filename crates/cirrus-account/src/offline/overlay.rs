//! Immutable bounded extent maps and private, block-verified payload objects.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::sync::{Mutex, OnceLock};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{AccountError, FileVersion, database};

mod integrity;
pub(crate) use integrity::verify_protected;

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
    size: u64,
    // Never rebased when a predecessor confirms a new replacement ETag.
    base: Option<FileVersion>,
    visible_end: u64,
    extents: Vec<Extent>,
}

fn invalid() -> AccountError {
    AccountError::new("dirty snapshot integrity check failed; local data retained")
}

fn save_bytes(
    bytes: &[u8],
    #[cfg(feature = "fault-injection")] manifest: bool,
) -> Result<String, AccountError> {
    let (mut file, dir, reservation) = super::create_staged_file(bytes.len() as u64)?;
    #[cfg(feature = "fault-injection")]
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
    #[cfg(not(feature = "fault-injection"))]
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
    fn save(bytes: &[u8]) -> Result<Self, AccountError> {
        if bytes.is_empty() || bytes.len() > OBJECT {
            return Err(invalid());
        }
        let blocks = bytes
            .chunks(BLOCK as usize)
            .map(|block| format!("{:x}", Sha256::digest(block)))
            .collect();
        Ok(Self {
            name: save_bytes(
                bytes,
                #[cfg(feature = "fault-injection")]
                false,
            )?,
            size: bytes.len() as u64,
            blocks,
        })
    }

    fn range(&self, offset: u64, length: usize) -> Result<Vec<u8>, AccountError> {
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
        let (file, before) = super::open_staged(&self.name)?;
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
        Ok(result)
    }
}

impl Overlay {
    pub(crate) fn empty() -> Self {
        Self {
            size: 0,
            base: None,
            visible_end: 0,
            extents: Vec::new(),
        }
    }

    pub(crate) fn original(version: &FileVersion) -> Result<Self, AccountError> {
        if version.size > MAX_FILE || version.id.starts_with("cirrus-staged:") {
            return Err(invalid());
        }
        Ok(Self {
            size: version.size,
            base: Some(version.clone()),
            visible_end: version.size,
            extents: Vec::new(),
        })
    }

    pub(crate) fn import(input: &mut impl Read, size: u64) -> Result<Self, AccountError> {
        if size > MAX_FILE {
            return Err(AccountError::new("file exceeds 1 TiB"));
        }
        let mut root = Self::empty();
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

    pub(crate) fn load(name: &str) -> Result<Self, AccountError> {
        Self::load_in(&database()?, name)
    }

    pub(crate) fn load_in(conn: &Connection, name: &str) -> Result<Self, AccountError> {
        let (mut file, before) = super::open_staged(name)?;
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
        let root: Self = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        root.validate()?;
        Ok(root)
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
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        if bytes.len() as u64 > MAX_MANIFEST {
            return Err(AccountError::new("dirty extent metadata limit exceeded"));
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let name = save_bytes(
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
            let (mut candidate, before) = super::open_staged(&name)?;
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
            let _state_phase = crate::ownership::admit_local_state_turn()?;
            let reservation;
            let mut conn = database()?;
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
            let planned = if crate::storage::limits::view()?.limits.is_some() {
                serde_json::to_vec(&(&name, &digest, self.size, &base))
                    .map_err(|_| invalid())?
                    .len() as u64
            } else {
                0
            };
            reservation = crate::storage::sql_reservation::SqlReservation::begin(
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
            } else if crate::storage::limits::view()?.limits.is_some() {
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

    // Recovery verifies local extents without fetching missing original bytes.
    // Original-byte protected-union admission remains mandatory before PUT.
    pub(super) fn verify_payloads(&self) -> Result<(), AccountError> {
        let mut seen = std::collections::BTreeSet::new();
        for extent in &self.extents {
            if seen.insert(&extent.object.name) {
                extent.object.range(0, extent.object.size as usize)?;
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
                if retained(base, block)?.is_none()
                    && let Some(bytes) = local(base, block, (base.size - block).min(BLOCK) as u32)
                {
                    capture(base, block, &bytes)?;
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
                object: Object::save(bytes)?,
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
            if let Some(object) = retained(base, offset)? {
                return Ok(object);
            }
            capture(base, offset, &fetch(base, offset, length)?)
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
        let conn = database()?;
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
                        let part =
                            object.range(position - block_start, (part_end - position) as usize)?;
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

fn retained(base: &FileVersion, offset: u64) -> Result<Option<Object>, AccountError> {
    retained_in(&database()?, base, offset)
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

fn capture(base: &FileVersion, offset: u64, bytes: &[u8]) -> Result<Object, AccountError> {
    if offset >= base.size
        || !offset.is_multiple_of(BLOCK)
        || bytes.len() as u64 != (base.size - offset).min(BLOCK)
    {
        return Err(invalid());
    }
    let verified = |object: Object| -> Result<Object, AccountError> {
        if object.size != bytes.len() as u64 || object.range(0, bytes.len())? != bytes {
            return Err(invalid());
        }
        Ok(object)
    };
    // Already published exact-base blocks need neither new allocation nor a
    // State lease, even under pressure. Verify actual bytes, not metadata alone.
    if let Some(object) = retained(base, offset)? {
        return verified(object);
    }
    // The conditional GET has already completed at every caller. Save/sync the
    // bounded candidate before taking State or SQLite writer ownership. A
    // racing loser remains a charged orphan; never delete/reassign its name.
    let object = Object::save(bytes)?;
    let encoded = serde_json::to_string(&object).map_err(|_| invalid())?;
    let version = serde_json::to_string(base).map_err(|_| invalid())?;
    let reservation;
    let mut conn = database()?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect original content retention plan"))?;
    let planned = if crate::storage::limits::view()?.limits.is_some() {
        serde_json::to_vec(&(&version, offset, &encoded))
            .map_err(|_| invalid())?
            .len() as u64
    } else {
        0
    };
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_BASE_CAPTURE_ADMISSION_WINDOW")?;
    reservation = crate::storage::sql_reservation::SqlReservation::begin(
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
        } else if crate::storage::limits::view()?.limits.is_some() {
            return Err(AccountError::new(crate::storage::limits::PRESSURE));
        }
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
    version: &str,
    offset: u64,
    prepared: &BTreeMap<u64, Object>,
    bounded: bool,
) -> Result<bool, AccountError> {
    let reservation;
    let mut conn = database()?;
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
    if !integrity::verify_preparation(prepared, bounded)? {
        return Ok(false);
    }
    integrity::preparation_unchanged(prepared)?;
    if previous.is_some_and(|previous| previous >= offset) {
        return Ok(true);
    }
    let planned = if crate::storage::limits::view()?.limits.is_some() {
        serde_json::to_vec(&(version, offset))
            .map_err(|_| invalid())?
            .len() as u64
    } else {
        0
    };
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_PREPARATION_ADMISSION_WINDOW")?;
    reservation = crate::storage::sql_reservation::SqlReservation::begin(
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
    integrity::preparation_unchanged(prepared)?;
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
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
    let saved: u64 = database()?
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
    if !integrity::verify_preparation(&prepared, bounded)? {
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
                let object = capture(base, block, &body)?;
                prepared.insert(block, object.clone());
                slot.insert(object);
                crate::executor::mark_progress();
                requests += 1;
                captured = true;
            }
            offset = (block + BLOCK)
                .min(root.visible_end)
                .min(extent.map_or(root.visible_end, |extent| extent.start));
            if captured && !persist_preparation(&version, offset, &prepared, bounded)? {
                return Ok(false);
            }
        }
    }
    persist_preparation(&version, offset, &prepared, bounded)
}

/// Protect every journal-referenced byte interpretation, including resolved
/// recovery and detached roots. Unreferenced objects are still never collected.
pub(crate) fn protected_bases(
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<Vec<String>, AccountError> {
    let conn = database()?;
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

struct HashPass {
    offset: u64,
    hash: Sha256,
}
static HASH_PASSES: OnceLock<Mutex<BTreeMap<(String, String), HashPass>>> = OnceLock::new();

/// At most 1 MiB per turn. Never trust a process-local prefix across restart.
pub(crate) fn digest_step(
    name: &str,
    purpose: &str,
    root: &Overlay,
) -> Result<Option<String>, AccountError> {
    let mut passes = HASH_PASSES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| invalid())?;
    let key = (name.to_owned(), purpose.to_owned());
    if !passes.contains_key(&key) && passes.len() >= 4096 {
        return Err(AccountError::new("dirty hashing capacity exhausted"));
    }
    let pass = passes.entry(key.clone()).or_insert_with(|| HashPass {
        offset: 0,
        hash: Sha256::new(),
    });
    let end = root.len().min(pass.offset.saturating_add(1024 * 1024));
    let mut budget = 1024 * 1024;
    while pass.offset < end {
        let (length, cost) =
            root.bounded_range(pass.offset, (end - pass.offset).min(BLOCK) as u32, budget)?;
        if length == 0 {
            break;
        }
        pass.hash.update(root.range(pass.offset, length, |_, _, _| {
            Err(AccountError::new(
                "exact original content base is unavailable locally",
            ))
        })?);
        pass.offset += u64::from(length);
        crate::executor::mark_progress();
        budget -= cost;
    }
    if pass.offset == root.len() {
        let pass = passes.remove(&key).ok_or_else(invalid)?;
        Ok(Some(format!("{:x}", pass.hash.finalize())))
    } else {
        Ok(None)
    }
}

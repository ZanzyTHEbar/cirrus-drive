//! Lifetime allowances for capped anonymous directory SQLite owners. Other
//! processes' actual materialization is unknown, never fabricated as zero.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::sync::Arc;

use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags},
    process,
};
use serde::{Deserialize, Serialize};

use super::limits;
use crate::{AccountError, offline, ownership};

pub(crate) const PREFIX: &str = ".namespace-reservation-";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    token: String,
    device: u64,
    inode: u64,
    ceiling_bytes: u64,
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

fn invalid() -> AccountError {
    AccountError::new("invalid namespace scratch reservation; inspect storage status")
}
fn name(token: &str) -> String {
    format!("{PREFIX}{token}")
}

fn record(dir: &OwnedFd, token: &str) -> Result<Record, AccountError> {
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let fd = fs::openat2(
        dir,
        name(token).as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| invalid())?;
    let stat = fs::fstat(&fd).map_err(|_| invalid())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || !(0..=4096).contains(&stat.st_size)
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
        || record.token != token
        || record.ceiling_bytes < crate::directory::SQLITE_BYTES
    {
        return Err(invalid());
    }
    Ok(record)
}

pub(crate) fn observe(
    dir: &OwnedFd,
    tokens: &[String],
    local: &BTreeMap<String, (u64, u64, u64)>,
) -> Result<Vec<NamespaceStorageReservation>, AccountError> {
    let mut result = Vec::new();
    for token in tokens {
        let record = match record(dir, token) {
            Ok(record) => record,
            Err(_)
                if matches!(
                    fs::statat(dir, name(token).as_str(), AtFlags::SYMLINK_NOFOLLOW),
                    Err(rustix::io::Errno::NOENT)
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        // Inode numbers can be reused after a crashed anonymous file dies.
        // Match the original live owner token as well, never its inode alone.
        let allocated = local
            .get(&record.token)
            .filter(|(device, inode, _)| (*device, *inode) == (record.device, record.inode))
            .map(|(_, _, allocated)| *allocated);
        result.push(NamespaceStorageReservation {
            token: record.token,
            device: record.device,
            inode: record.inode,
            ceiling_bytes: record.ceiling_bytes,
            known_local_allocated_bytes: allocated,
            outstanding_reserved_bytes: record.ceiling_bytes.saturating_sub(allocated.unwrap_or(0)),
        });
    }
    Ok(result)
}

pub(crate) fn release(token: &str) -> Result<(), AccountError> {
    // Never create a marker while inspecting/releasing a nonexistent token.
    let _lease = ownership::namespace_lease(token, false)?;
    let _budget = ownership::acquire_staging()?;
    let dir = ownership::state_dir()?;
    record(&dir, token)?;
    fs::unlinkat(&dir, name(token).as_str(), AtFlags::empty()).map_err(|_| invalid())?;
    fs::unlinkat(
        &dir,
        format!(".namespace-lease-{token}").as_str(),
        AtFlags::empty(),
    )
    .map_err(|_| invalid())?;
    fs::fsync(&dir).map_err(|_| {
        AccountError::new("cannot sync reservation release; inspect storage status before retry")
    })
}

pub(crate) struct NamespaceReservation {
    token: String,
    dir: OwnedFd,
    _lease: OwnedFd,
    published: bool,
    ceiling: u64,
    device: u64,
    inode: u64,
}

impl NamespaceReservation {
    pub(crate) fn begin(file: &Arc<std::fs::File>) -> Result<Option<Self>, AccountError> {
        if limits::view()?.limits.is_none() {
            return Ok(None);
        }
        let token = offline::namespace_token()?;
        let lease = ownership::namespace_lease(&token, true)?;
        let stat = fs::fstat(file).map_err(|_| invalid())?;
        let mut reservation = Self {
            token,
            dir: ownership::state_dir()?,
            _lease: lease,
            published: false,
            ceiling: 0,
            device: stat.st_dev,
            inode: stat.st_ino,
        };
        // No store lease, SQL query, SQLite contention or network under this
        // flock. The reservation covers the unchanged 16 MiB page ceiling.
        // Namespace callers can own SQL read transactions/FUSE state. Never
        // wait for cache eviction here: refuse, without reentrant reclamation.
        reservation.prepare(file)?;
        Ok(Some(reservation))
    }

    fn prepare(&mut self, file: &Arc<std::fs::File>) -> Result<(), AccountError> {
        let _budget = ownership::acquire_staging()?;
        let local = offline::storage_reservations()?;
        let observation = super::allocation_status(&local)?;
        let block = observation.filesystem_fragment_bytes;
        self.ceiling = crate::directory::SQLITE_BYTES
            .div_ceil(block)
            .checked_mul(block)
            .ok_or_else(invalid)?;
        let stat = fs::fstat(file).map_err(|_| invalid())?;
        let allocated = u64::try_from(stat.st_blocks)
            .map_err(|_| invalid())?
            .checked_mul(512)
            .ok_or_else(invalid)?;
        // The original file is already in the local weak tracker. Charge only
        // its unmaterialized remainder, plus this new bounded control record.
        limits::check(
            self.ceiling
                .saturating_sub(allocated)
                .checked_add(block)
                .ok_or_else(invalid)?,
            &local,
        )?;
        let record = Record {
            token: self.token.clone(),
            device: self.device,
            inode: self.inode,
            ceiling_bytes: self.ceiling,
        };
        let temp = format!(".namespace-publish-{}", self.token);
        let fd = fs::openat2(
            &self.dir,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| invalid())?;
        let published = (|| {
            let mut output = std::fs::File::from(fd);
            output
                .write_all(&serde_json::to_vec(&record).map_err(|_| invalid())?)
                .and_then(|()| output.sync_all())
                .map_err(|_| invalid())?;
            // Random token has an exclusively owned lease. Refuse an existing
            // record rather than overwrite user work on an unexpected collision.
            match fs::statat(
                &self.dir,
                name(&self.token).as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Err(rustix::io::Errno::NOENT) => (),
                _ => return Err(invalid()),
            }
            fs::renameat(
                &self.dir,
                temp.as_str(),
                &self.dir,
                name(&self.token).as_str(),
            )
            .map_err(|_| invalid())?;
            self.published = true;
            super::bind_namespace(file, &self.token)?;
            fs::fsync(&self.dir).map_err(|_| invalid())?;
            limits::check(0, &local)
        })();
        let _ = fs::unlinkat(&self.dir, temp.as_str(), AtFlags::empty());
        published
    }

    pub(crate) fn validate_file(&self, file: &std::fs::File) -> Result<(), AccountError> {
        let stat = fs::fstat(file).map_err(|_| invalid())?;
        if (stat.st_dev, stat.st_ino, stat.st_nlink) != (self.device, self.inode, 0)
            || u64::try_from(stat.st_blocks)
                .ok()
                .and_then(|blocks| blocks.checked_mul(512))
                .is_none_or(|bytes| bytes > self.ceiling)
            || u64::try_from(stat.st_size)
                .ok()
                .is_none_or(|bytes| bytes > crate::directory::SQLITE_BYTES)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Drop for NamespaceReservation {
    fn drop(&mut self) {
        if let Ok(_budget) = ownership::acquire_staging() {
            if super::finish_namespace_observation(&self.token).is_err() {
                return;
            }
            if self.published {
                if !record(&self.dir, &self.token)
                    .is_ok_and(|record| (record.device, record.inode) == (self.device, self.inode))
                {
                    return;
                }
                if fs::unlinkat(&self.dir, name(&self.token).as_str(), AtFlags::empty()).is_err() {
                    return;
                }
            }
            let _ = fs::unlinkat(
                &self.dir,
                format!(".namespace-lease-{}", self.token).as_str(),
                AtFlags::empty(),
            );
            let _ = fs::fsync(&self.dir);
        }
        // No expiry/adoption/GC. Failed cleanup or a crash leaves the durable
        // ceiling charged until explicit inactive-token release.
    }
}

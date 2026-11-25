//! Opt-in admission for immutable, pin, clean, snapshot publication and namespace
//! scratch owners. Independent SQLite/physical growth still precludes a hard quota.

use std::io::{Read, Write};

use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags},
    process,
};
use serde::{Deserialize, Serialize};

use crate::{AccountError, account_storage::StorageRoot, offline, ownership};

const FILE: &str = "storage-limits.json";
pub(crate) const PRESSURE: &str = "configured storage pressure limit reached";

pub use cirrus_api::{StorageLimits, StorageLimitsView};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(deserialize_with = "Option::deserialize")]
    limits: Option<StorageLimits>,
}

fn invalid() -> AccountError {
    AccountError::new("invalid or unsafe local storage limits; local growth refused")
}

pub(crate) fn validate(limits: &Option<StorageLimits>) -> Result<(), AccountError> {
    if limits
        .as_ref()
        .is_some_and(|limits| limits.budget_bytes == 0)
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn view_in(root: &StorageRoot) -> Result<StorageLimitsView, AccountError> {
    let dir = root.directory();
    let fd = match ownership::open_private_file(
        &dir,
        FILE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => Some(fd),
        Err(rustix::io::Errno::NOENT) => None,
        Err(_) => return Err(invalid()),
    };
    let limits = if let Some(fd) = fd {
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
        #[cfg(target_os = "macos")]
        ownership::darwin_acl::check_file(&fd).map_err(|_| invalid())?;
        std::fs::File::from(fd)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() > 4096 {
            return Err(invalid());
        }
        let config: Config = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        validate(&config.limits)?;
        config.limits
    } else {
        None
    };
    Ok(StorageLimitsView {
        limits,
        enforcement:
            "aggregate-pressure-gated-immutable-pin-clean-snapshots-scratch-namespace-empty-tree-staged-file-pending-replacements-local-directories-staged-removals-dirty-root-cli-import-candidate-registration-original-capture-preparation-progress-verification-progress-detached-head-new-activation-and-read-evidence"
                .into(),
        hard_global_limit: false,
        automatic_reclamation: "persisted-clean-cache-only".into(),
    })
}

pub(crate) fn set_in(
    root: &StorageRoot,
    limits: Option<StorageLimits>,
) -> Result<StorageLimitsView, AccountError> {
    validate(&limits)?;
    // Same lock as admission + actual fallocation. No account, network or SQLite
    // lock is acquired here. Below-current settings are allowed without cleanup.
    let _staging = ownership::acquire_staging_in(root)?;
    let dir = root.directory();
    match fs::statat(&dir, FILE, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat)
            if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && stat.st_uid == process::geteuid().as_raw()
                && stat.st_mode & 0o7777 == 0o600
                && stat.st_nlink == 1 =>
        {
            #[cfg(target_os = "macos")]
            {
                let fd = ownership::open_private_file(
                    dir,
                    FILE,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|_| invalid())?;
                let actual = fs::fstat(&fd).map_err(|_| invalid())?;
                if (stat.st_dev, stat.st_ino) != (actual.st_dev, actual.st_ino) {
                    return Err(invalid());
                }
                ownership::darwin_acl::check_file(&fd).map_err(|_| invalid())?;
            }
        }
        Err(rustix::io::Errno::NOENT) => (),
        _ => return Err(invalid()),
    }
    let temporary = format!(".storage-limits-{}", offline::namespace_token()?);
    let fd = ownership::open_private_file(
        &dir,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| invalid())?;
    let result = (|| {
        let mut file = std::fs::File::from(fd);
        #[cfg(target_os = "macos")]
        ownership::darwin_acl::check_file(&file).map_err(|_| invalid())?;
        let bytes = serde_json::to_vec(&Config { limits }).map_err(|_| invalid())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| AccountError::new("cannot persist local storage limits"))?;
        fs::renameat(&dir, temporary.as_str(), &dir, FILE)
            .map_err(|_| AccountError::new("cannot publish local storage limits"))?;
        fs::fsync(&dir).map_err(|_| {
            AccountError::new(
                "cannot sync local storage limits; inspect current policy before retry",
            )
        })?;
        view_in(root)
    })();
    // Only our exclusively created configuration scratch name. Never touch a
    // payload, pin, journal, recovery copy or charged staging orphan.
    let _ = fs::unlinkat(&dir, temporary.as_str(), AtFlags::empty());
    result
}

pub(crate) fn is_pressure(error: &AccountError) -> bool {
    error.message == PRESSURE
}

/// Caller holds staging flock and supplies a local reservation snapshot. Metadata-only:
/// no SQL queries, cache reclamation, network or additional staging lock.
pub(crate) fn check_in(
    root: &StorageRoot,
    bytes: u64,
    reservations: &[(String, u64)],
) -> Result<(), AccountError> {
    if view_in(root)?.limits.is_none() {
        return Ok(());
    }
    let observation = super::allocation_status_in(root, reservations)?;
    if observation.storage_limits_error.is_some() {
        return Err(invalid());
    }
    let limits = observation
        .storage_limits
        .and_then(|view| view.limits)
        .ok_or_else(invalid)?;
    if !observation.daemon_scratch_tracking_complete {
        return Err(AccountError::new(
            "local scratch tracking incomplete; local growth refused",
        ));
    }
    let block = observation.filesystem_fragment_bytes;
    let rounded = bytes
        .checked_add(block - 1)
        .and_then(|bytes| bytes.checked_div(block))
        .and_then(|blocks| blocks.checked_mul(block))
        .ok_or_else(invalid)?;
    if observation
        .immutable_admission_charge_bytes
        .checked_add(rounded)
        .is_none_or(|charge| charge > limits.budget_bytes)
        || observation
            .filesystem_available_bytes
            .checked_sub(observation.sql_outstanding_reserved_bytes)
            .and_then(|available| {
                available.checked_sub(observation.namespace_outstanding_reserved_bytes)
            })
            .and_then(|available| available.checked_sub(rounded))
            .is_none_or(|remaining| remaining < limits.free_space_reserve_bytes)
    {
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_NAMESPACE_TRACE").is_some() {
            eprintln!(
                "cirrus lab policy refusal: charge={} incoming={} budget={} namespace_reserved={}",
                observation.immutable_admission_charge_bytes,
                rounded,
                limits.budget_bytes,
                observation.namespace_outstanding_reserved_bytes
            );
        }
        return Err(AccountError::new(PRESSURE));
    }
    Ok(())
}

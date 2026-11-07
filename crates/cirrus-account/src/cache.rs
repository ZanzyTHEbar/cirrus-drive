use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags},
    process,
};
use sha2::{Digest, Sha256};

use crate::{AccountError, CleanCacheStatus, FileVersion, ReadSession, ownership};

const CACHE_APP_ID: i64 = 0x4344_4331;
const MAX_BYTES: i64 = 64 * 1024 * 1024;
const MAX_ENTRIES: i64 = 1024;
static OPEN_LOCK: Mutex<()> = Mutex::new(());

fn database(create: bool) -> Result<Option<Connection>, AccountError> {
    let _guard = OPEN_LOCK
        .lock()
        .map_err(|_| AccountError::new("cache is unavailable"))?;
    let dir = ownership::state_dir()?;
    let stat_existing = || fs::statat(&dir, "cache.db", AtFlags::SYMLINK_NOFOLLOW);
    let (stat, created) = if create {
        match fs::openat2(
            &dir,
            "cache.db",
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(fd) => (
                fs::fstat(&fd).map_err(|_| AccountError::new("cannot inspect cache"))?,
                true,
            ),
            Err(rustix::io::Errno::EXIST) => (
                stat_existing().map_err(|_| AccountError::new("cannot inspect cache"))?,
                false,
            ),
            Err(_) => return Err(AccountError::new("cannot create cache")),
        }
    } else {
        match stat_existing() {
            Ok(stat) => (stat, false),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(AccountError::new("cannot inspect cache")),
        }
    };
    // An extra open/close of an existing file releases process-wide SQLite locks.
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(AccountError::new(
            "cache has unsafe ownership or permissions",
        ));
    }
    let proc = fs::openat2(
        fs::CWD,
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| AccountError::new("trusted procfs is required for cache"))?;
    if fs::fstatfs(&proc)
        .map_err(|_| AccountError::new("cannot inspect procfs"))?
        .f_type
        != fs::PROC_SUPER_MAGIC
    {
        return Err(AccountError::new("trusted procfs is required for cache"));
    }
    let path = format!("/proc/self/fd/{}/cache.db", dir.as_raw_fd());
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|_| AccountError::new("cannot open cache"))?;
    conn.busy_timeout(Duration::from_secs(1))
        .map_err(|_| AccountError::new("cannot configure cache"))?;
    if created {
        conn.execute_batch("PRAGMA page_size=4096; PRAGMA auto_vacuum=FULL; BEGIN IMMEDIATE; PRAGMA application_id=1128547121; PRAGMA user_version=2;
            CREATE TABLE ranges (issuer TEXT NOT NULL, subject TEXT NOT NULL, version TEXT NOT NULL, offset INTEGER NOT NULL, body BLOB NOT NULL, digest TEXT NOT NULL, accessed INTEGER NOT NULL, PRIMARY KEY(issuer,subject,version,offset));
            CREATE INDEX range_eviction ON ranges(accessed); CREATE TABLE generation(value INTEGER NOT NULL); INSERT INTO generation VALUES(0); COMMIT;")
            .map_err(|_| AccountError::new("cannot initialize cache"))?;
        fs::fsync(&dir).map_err(|_| AccountError::new("cannot persist cache directory"))?;
    }
    let app: i64 = conn
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect cache"))?;
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect cache"))?;
    let page_size: i64 = conn
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect cache"))?;
    if app != CACHE_APP_ID || version != 2 || page_size != 4096 {
        return Err(AccountError::new("unrecognized cache"));
    }
    let current = stat_existing().map_err(|_| AccountError::new("cache changed"))?;
    if (stat.st_dev, stat.st_ino) != (current.st_dev, current.st_ino)
        || current.st_nlink != 1
        || FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
        || current.st_uid != process::geteuid().as_raw()
        || current.st_mode & 0o7777 != 0o600
    {
        return Err(AccountError::new("cache changed"));
    }
    // The clean cache is separate from dirty data and pins, with room for SQLite metadata.
    conn.execute_batch("PRAGMA max_page_count=24576")
        .map_err(|_| AccountError::new("cannot bound cache"))?;
    Ok(Some(conn))
}

fn encoded(version: &FileVersion) -> Result<String, AccountError> {
    serde_json::to_string(version).map_err(|_| AccountError::new("invalid cache version"))
}

pub(crate) fn status() -> Result<CleanCacheStatus, AccountError> {
    let (bytes, ranges) = match database(false)? {
        Some(conn) => conn
            .query_row(
                "SELECT coalesce(sum(length(body)),0),count(*) FROM ranges",
                [],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
            )
            .map_err(|_| AccountError::new("cannot inspect clean cache usage"))?,
        None => (0, 0),
    };
    Ok(CleanCacheStatus {
        bytes,
        ranges,
        byte_limit: MAX_BYTES as u64,
        range_limit: MAX_ENTRIES as u64,
    })
}

/// Reclaim only disposable persisted clean ranges. Caller must hold no staging
/// or budget lock: SQLite may wait, checkpoint, or fail to release physical WAL
/// space. Admission always remeasures afterward; row deletion is not free-space
/// proof. State DB, pins, dirty objects and orphans are never touched here.
pub(crate) fn reclaim_for_storage_pressure() -> Result<bool, AccountError> {
    let _lease = match crate::storage::sql_reservation::cleanup_lease(
        crate::storage::sql_reservation::Store::Cache,
    ) {
        Ok(lease) => lease,
        Err(error) if error.is_operation_busy() => return Ok(false),
        Err(error) => return Err(error),
    };
    let Some(mut conn) = database(false)? else {
        return Ok(false);
    };
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| AccountError::new("cannot begin clean storage reclamation"))?;
    if tx
        .execute("DELETE FROM ranges", [])
        .map_err(|_| AccountError::new("cannot reclaim clean ranges"))?
        == 0
    {
        return Ok(false);
    }
    if tx
        .execute(
            "UPDATE generation SET value=value+1 WHERE value < 9223372036854775807",
            [],
        )
        .map_err(|_| AccountError::new("cannot advance clean reclamation generation"))?
        != 1
    {
        return Err(AccountError::new("invalid cache generation"));
    }
    tx.commit()
        .map_err(|_| AccountError::new("cannot commit clean storage reclamation"))?;
    // A busy checkpoint is not treated as reclaimed bytes. The subsequent
    // physical admission check decides whether any allocation can proceed.
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(|_| AccountError::new("cannot checkpoint reclaimed clean cache"))?;
    Ok(true)
}

pub(crate) fn contains(session: &ReadSession, version: &FileVersion) -> Result<bool, AccountError> {
    let Some(conn) = database(false)? else {
        return Ok(false);
    };
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ranges WHERE issuer=?1 AND subject=?2 AND version=?3)",
        params![
            session.account.issuer,
            session.account.subject,
            encoded(version)?
        ],
        |row| row.get(0),
    )
    .map_err(|_| AccountError::new("cannot inspect cached ranges"))
}

pub(crate) fn generation() -> Result<i64, AccountError> {
    let Some(conn) = database(false)? else {
        return Ok(0);
    };
    conn.query_row("SELECT value FROM generation", [], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect cache generation"))
}

pub(crate) fn evict(
    session: &ReadSession,
    space: &str,
    path: &[String],
) -> Result<(), AccountError> {
    let _lease = crate::storage::sql_reservation::cleanup_lease(
        crate::storage::sql_reservation::Store::Cache,
    )?;
    let Some(mut conn) =
        database(crate::storage::limits::view().is_ok_and(|view| view.limits.is_none()))?
    else {
        return Ok(());
    };
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| AccountError::new("cannot begin cache eviction"))?;
    let mut remove = Vec::new();
    {
        let mut statement = tx
            .prepare("SELECT rowid,version FROM ranges WHERE issuer=?1 AND subject=?2")
            .map_err(|_| AccountError::new("cannot inspect cached ranges"))?;
        let rows = statement
            .query_map(
                params![session.account.issuer, session.account.subject],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|_| AccountError::new("cannot inspect cached ranges"))?;
        for row in rows {
            let (id, encoded) = row.map_err(|_| AccountError::new("invalid cached range"))?;
            let version: FileVersion = serde_json::from_str(&encoded)
                .map_err(|_| AccountError::new("invalid cached version"))?;
            if version.instance == session.base.as_str()
                && version.space == space
                && version.path.starts_with(path)
            {
                remove.push(id);
            }
        }
    }
    for id in remove {
        tx.execute("DELETE FROM ranges WHERE rowid=?1", [id])
            .map_err(|_| AccountError::new("cannot evict cached range"))?;
    }
    let updated = tx
        .execute(
            "UPDATE generation SET value=value+1 WHERE value < 9223372036854775807",
            [],
        )
        .map_err(|_| AccountError::new("cannot advance cache generation"))?;
    if updated != 1 {
        return Err(AccountError::new("invalid cache generation"));
    }
    tx.commit()
        .map_err(|_| AccountError::new("cannot commit cache eviction"))
}

pub(crate) fn read(
    session: &ReadSession,
    version: &FileVersion,
    offset: u64,
    length: u32,
) -> Result<Option<Vec<u8>>, AccountError> {
    read_identity(
        &session.account.issuer,
        &session.account.subject,
        version,
        offset,
        length,
        true,
    )
}

pub(crate) fn read_identity(
    issuer: &str,
    subject: &str,
    version: &FileVersion,
    offset: u64,
    length: u32,
    touch: bool,
) -> Result<Option<Vec<u8>>, AccountError> {
    let end = offset
        .checked_add(u64::from(length))
        .filter(|end| length > 0 && *end <= version.size && *end <= i64::MAX as u64)
        .ok_or_else(|| AccountError::new("invalid cached range"))?;
    let Some(conn) = database(false)? else {
        return Ok(None);
    };
    let version = encoded(version)?;
    let mut position = offset;
    let mut result = Vec::with_capacity(length as usize);
    while position < end {
        let row: Option<(i64, i64, Vec<u8>, String)> = conn.query_row(
            "SELECT rowid,offset,body,digest FROM ranges WHERE issuer=?1 AND subject=?2 AND version=?3 AND offset<=?4 AND offset+length(body)>?4 ORDER BY offset+length(body) DESC LIMIT 1",
            params![issuer,subject,version,position as i64],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(|_| AccountError::new("cannot read cached range"))?;
        let Some((id, start, body, digest)) = row else {
            return Ok(None);
        };
        if start < 0
            || body.is_empty()
            || body.len() > 131_072
            || format!("{:x}", Sha256::digest(&body)) != digest
        {
            return Ok(None);
        }
        let start = usize::try_from(position - start as u64)
            .map_err(|_| AccountError::new("invalid cached range"))?;
        let count = (end - position).min((body.len() - start) as u64) as usize;
        result.extend_from_slice(&body[start..start + count]);
        position += count as u64;
        // With policy enabled a cache hit is read-only, not an unreserved
        // metadata transaction. The next admitted insert still bounds the LRU.
        if touch && crate::storage::limits::view().is_ok_and(|view| view.limits.is_none()) {
            let _ = conn.execute(
                "UPDATE ranges SET accessed=unixepoch() WHERE rowid=?1",
                [id],
            );
        }
    }
    Ok(Some(result))
}

pub(crate) fn store(
    session: &ReadSession,
    version: &FileVersion,
    offset: u64,
    bytes: &[u8],
    generation: i64,
) -> Result<(), AccountError> {
    if bytes.is_empty()
        || bytes.len() > 131_072
        || offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > version.size || end > i64::MAX as u64)
    {
        return Err(AccountError::new("invalid cached range"));
    }
    let reservation = if crate::storage::limits::view()?.limits.is_some() {
        let existing = database(false)?;
        let metadata = serde_json::to_vec(version)
            .map_err(|_| AccountError::new("invalid cached version"))?
            .len() as u64
            + session.account.issuer.len() as u64
            + session.account.subject.len() as u64;
        crate::storage::sql_reservation::SqlReservation::begin(
            crate::storage::sql_reservation::Store::Cache,
            existing.as_ref(),
            bytes.len() as u64,
            metadata,
            false,
        )?
    } else {
        None
    };
    let Some(mut conn) = database(true)? else {
        return Err(AccountError::new("cache is unavailable"));
    };
    if let Some(reservation) = &reservation {
        reservation.bound_pages(&conn)?;
    }
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| AccountError::new("cannot update cache"))?;
    let current: i64 = tx
        .query_row("SELECT value FROM generation", [], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect cache generation"))?;
    if current != generation {
        return Ok(());
    }
    let version = encoded(version)?;
    tx.execute(
        "DELETE FROM ranges WHERE issuer=?1 AND subject=?2 AND version=?3 AND offset=?4",
        params![
            session.account.issuer,
            session.account.subject,
            version,
            offset as i64
        ],
    )
    .map_err(|_| AccountError::new("cannot update cache"))?;
    loop {
        let (count, total): (i64, i64) = tx
            .query_row(
                "SELECT count(*),coalesce(sum(length(body)),0) FROM ranges",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| AccountError::new("cannot inspect cache size"))?;
        if count < MAX_ENTRIES && total + bytes.len() as i64 <= MAX_BYTES {
            break;
        }
        let removed = tx.execute("DELETE FROM ranges WHERE rowid=(SELECT rowid FROM ranges ORDER BY accessed,rowid LIMIT 1)", [])
            .map_err(|_| AccountError::new("cannot evict cached range"))?;
        if removed != 1 {
            return Err(AccountError::new("cannot bound cache"));
        }
    }
    tx.execute("INSERT INTO ranges(issuer,subject,version,offset,body,digest,accessed) VALUES (?1,?2,?3,?4,?5,?6,unixepoch())",
        params![session.account.issuer,session.account.subject,version,offset as i64,bytes,format!("{:x}", Sha256::digest(bytes))])
        .map_err(|_| AccountError::new("cannot save cached range"))?;
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|_| AccountError::new("cannot commit cached range"))
}

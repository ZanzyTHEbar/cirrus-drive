use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use rustix::fs;
use sha2::{Digest, Sha256};

use crate::{
    AccountError, CleanCacheStatus, FileVersion, ReadSession,
    account_storage::StorageRoot,
    offline,
    sqlite_open::{Database, OpenMode},
};

const CACHE_APP_ID: i64 = 0x4344_4331;
const MAX_BYTES: i64 = 64 * 1024 * 1024;
const MAX_ENTRIES: i64 = 1024;

fn database(root: &StorageRoot, create: bool) -> Result<Option<Connection>, AccountError> {
    let mode = if create {
        OpenMode::CreateOrOpen
    } else {
        OpenMode::Existing
    };
    let Some(opening) = Database::Cache.open(root, mode)? else {
        return Ok(None);
    };
    let conn = opening.connection();
    conn.busy_timeout(Duration::from_secs(1))
        .map_err(|_| AccountError::new("cannot configure cache"))?;
    if opening.created() {
        conn.execute_batch("PRAGMA page_size=4096; PRAGMA auto_vacuum=FULL; BEGIN IMMEDIATE; PRAGMA application_id=1128547121; PRAGMA user_version=2;
            CREATE TABLE ranges (issuer TEXT NOT NULL, subject TEXT NOT NULL, version TEXT NOT NULL, offset INTEGER NOT NULL, body BLOB NOT NULL, digest TEXT NOT NULL, accessed INTEGER NOT NULL, PRIMARY KEY(issuer,subject,version,offset));
            CREATE INDEX range_eviction ON ranges(accessed); CREATE TABLE generation(value INTEGER NOT NULL); INSERT INTO generation VALUES(0); COMMIT;")
            .map_err(|_| AccountError::new("cannot initialize cache"))?;
        fs::fsync(root.directory())
            .map_err(|_| AccountError::new("cannot persist cache directory"))?;
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
    opening.check_named()?;
    // The clean cache is separate from dirty data and pins, with room for SQLite metadata.
    conn.execute_batch("PRAGMA max_page_count=24576")
        .map_err(|_| AccountError::new("cannot bound cache"))?;
    opening.check_sidecars_and_vfs()?;
    Ok(Some(opening.into_connection()))
}

fn encoded(version: &FileVersion) -> Result<String, AccountError> {
    serde_json::to_string(version).map_err(|_| AccountError::new("invalid cache version"))
}

pub(crate) fn status_in(root: &StorageRoot) -> Result<CleanCacheStatus, AccountError> {
    let (bytes, ranges) = match database(root, false)? {
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
pub(crate) fn reclaim_for_storage_pressure_in(root: &StorageRoot) -> Result<bool, AccountError> {
    let _lease = match crate::storage::sql_reservation::cleanup_lease_in(
        root,
        crate::storage::sql_reservation::Store::Cache,
    ) {
        Ok(lease) => lease,
        Err(error) if error.is_operation_busy() => return Ok(false),
        Err(error) => return Err(error),
    };
    let Some(mut conn) = database(root, false)? else {
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
    let Some(conn) = database(&session.root, false)? else {
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

pub(crate) fn generation_in(root: &StorageRoot) -> Result<i64, AccountError> {
    let Some(conn) = database(root, false)? else {
        return Ok(0);
    };
    conn.query_row("SELECT value FROM generation", [], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect cache generation"))
}

pub(crate) fn evict_in(
    root: &StorageRoot,
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<(), AccountError> {
    let (issuer, subject, activated) = offline::cache_eviction_identity_in(root, instance, space)?;
    let unproven = || AccountError::new("Space has no retained activation or clean ranges");
    let _lease = crate::storage::sql_reservation::cleanup_lease_in(
        root,
        crate::storage::sql_reservation::Store::Cache,
    )?;
    let Some(mut conn) = database(
        root,
        activated && crate::storage::limits::view_in(root).is_ok_and(|view| view.limits.is_none()),
    )?
    else {
        return if activated { Ok(()) } else { Err(unproven()) };
    };
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| AccountError::new("cannot begin cache eviction"))?;
    let mut remove = Vec::new();
    let mut known_space = activated;
    {
        let mut statement = tx
            .prepare("SELECT rowid,version FROM ranges WHERE issuer=?1 AND subject=?2")
            .map_err(|_| AccountError::new("cannot inspect cached ranges"))?;
        let rows = statement
            .query_map(params![issuer, subject], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| AccountError::new("cannot inspect cached ranges"))?;
        for row in rows {
            let (id, encoded) = row.map_err(|_| AccountError::new("invalid cached range"))?;
            let version: FileVersion = serde_json::from_str(&encoded)
                .map_err(|_| AccountError::new("invalid cached version"))?;
            if version.instance == instance && version.space == space {
                // An exact principal/instance/Space range proves local cache
                // scope even when this Space has never enabled sync.
                known_space = true;
                if version.path.starts_with(path) {
                    remove.push(id);
                }
            }
        }
    }
    if !known_space {
        return Err(unproven());
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
    read_identity_in(
        &session.root,
        &session.account.issuer,
        &session.account.subject,
        version,
        offset,
        length,
        true,
    )
}

pub(crate) fn read_identity_in(
    root: &StorageRoot,
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
    let Some(conn) = database(root, false)? else {
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
        if touch && crate::storage::limits::view_in(root).is_ok_and(|view| view.limits.is_none()) {
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
    let root = &session.root;
    if bytes.is_empty()
        || bytes.len() > 131_072
        || offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > version.size || end > i64::MAX as u64)
    {
        return Err(AccountError::new("invalid cached range"));
    }
    let reservation = if crate::storage::limits::view_in(root)?.limits.is_some() {
        let existing = database(root, false)?;
        let metadata = serde_json::to_vec(version)
            .map_err(|_| AccountError::new("invalid cached version"))?
            .len() as u64
            + session.account.issuer.len() as u64
            + session.account.subject.len() as u64;
        crate::storage::sql_reservation::SqlReservation::begin_in(
            root,
            crate::storage::sql_reservation::Store::Cache,
            existing.as_ref(),
            bytes.len() as u64,
            metadata,
            false,
        )?
    } else {
        None
    };
    let Some(mut conn) = database(root, true)? else {
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
    } else if crate::storage::limits::view_in(root)?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|_| AccountError::new("cannot commit cached range"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use cirrus_runtime::RuntimeDir;

    use super::*;
    use crate::Accounts;

    #[test]
    fn explicit_cache_eviction_is_local_scoped_and_atomic() {
        const INSTANCE: &str = "https://instance.invalid/";
        const ISSUER: &str = "https://issuer.invalid/";
        const SPACE: &str = "requested";

        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let dir =
            std::env::temp_dir().join(format!("ev-{}-{}", std::process::id(), nonce.as_nanos()));
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let fixture = Fixture(dir);
        let runtime = fixture.0.join("rt");
        DirBuilder::new().mode(0o700).create(&runtime).unwrap();
        let root = StorageRoot::open_container(&fixture.0).unwrap();
        let accounts = Accounts::with_storage(RuntimeDir::open(&runtime).unwrap(), root.clone());
        let folder = ["folder".to_owned()];
        let evict = |space| accounts.evict_space("https://INSTANCE.invalid", space, &folder);
        assert!(evict(SPACE).is_err());
        assert!(!fixture.0.join("cirrus-drive/state.db").exists());
        assert!(!fixture.0.join("cirrus-drive/cache.db").exists());

        let cache = database(&root, true).unwrap().unwrap();
        let insert = |(instance, space, subject): (&str, &str, &str), path: &[&str], body: &str| {
            let version = FileVersion {
                instance: instance.to_owned(),
                space: space.to_owned(),
                path: path.iter().map(|part| (*part).to_owned()).collect(),
                id: "version-id".to_owned(),
                etag: "\"v1\"".to_owned(),
                size: body.len() as u64,
                checksums: Vec::new(),
            };
            let key = encoded(&version).unwrap();
            let hash = format!("{:x}", Sha256::digest(body));
            cache
                .execute(
                    "INSERT INTO ranges VALUES (?1,?2,?3,0,?4,?5,0)",
                    params![ISSUER, subject, key, body.as_bytes(), hash],
                )
                .unwrap();
        };
        let owner = (INSTANCE, SPACE, "owner");
        let leaf = &["folder", "leaf"];
        insert(owner, leaf, "delete");
        insert(owner, &["folder-ish"], "prefix sibling");
        insert((INSTANCE, "peer", "owner"), leaf, "peer Space");
        insert((INSTANCE, SPACE, "peer"), leaf, "peer principal");
        insert(
            ("https://peer.invalid/", SPACE, "owner"),
            leaf,
            "peer instance",
        );
        let cache_payloads = || {
            cache
                .prepare("SELECT CAST(body AS TEXT) FROM ranges ORDER BY body")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let before = cache_payloads();
        assert!(
            evict(SPACE).is_err(),
            "cache rows alone do not establish a principal"
        );
        offline::bind_identity_in(&root, INSTANCE, ISSUER, "owner").unwrap();
        let state = offline::database_in(&root).unwrap();
        assert!(evict("unknown").is_err());
        assert!(evict("requested/peer").is_err());
        assert!(
            accounts
                .evict_space("https://user@instance.invalid", SPACE, &folder)
                .is_err()
        );
        assert!(
            accounts
                .evict_space(INSTANCE, SPACE, &["..".to_owned()])
                .is_err()
        );
        state.execute(
            "INSERT INTO sync_spaces(instance,space,issuer,subject,phase,failures,next_at,verified_through)
             VALUES (?1,?2,?3,'wrong','Attention',0,0,0)",
            params![INSTANCE, SPACE, ISSUER],
        ).unwrap();
        assert!(
            evict(SPACE).is_err(),
            "conflicting activation outweighs exact ranges"
        );
        state.execute("DELETE FROM sync_spaces", []).unwrap();

        cache
            .execute_batch(
                "CREATE TRIGGER abort_eviction BEFORE UPDATE ON generation
                 BEGIN SELECT RAISE(ABORT, 'generation update refused'); END;",
            )
            .unwrap();
        assert!(evict(SPACE).is_err());
        assert_eq!(cache_payloads(), before, "range deletion must roll back");
        assert_eq!(generation_in(&root).unwrap(), 0);
        assert_eq!(accounts.clean_cache_generation(), 0);
        cache.execute_batch("DROP TRIGGER abort_eviction").unwrap();

        let state_generation = || {
            state
                .pragma_query_value(None, "data_version", |row| row.get::<_, i64>(0))
                .unwrap()
        };
        let peers = ["peer Space", "peer instance", "peer principal"];
        let state_before = state_generation();
        evict(SPACE).unwrap(); // No activation, credentials or live session.
        assert_eq!(
            cache_payloads(),
            [peers.as_slice(), &["prefix sibling"]].concat()
        );
        assert_eq!(generation_in(&root).unwrap(), 1);
        assert_eq!(accounts.clean_cache_generation(), 1);
        assert_eq!(state_generation(), state_before);

        let journal_mode: String = state
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "wal");
        state.execute(
            "INSERT INTO sync_spaces(instance,space,issuer,subject,phase,failures,next_at,verified_through)
             VALUES (?1,?2,?3,'owner','Attention',3,0,0)",
            params![INSTANCE, SPACE, ISSUER],
        ).unwrap();
        let state_before = state_generation();
        accounts.evict_space(INSTANCE, SPACE, &[]).unwrap();
        accounts.evict_space(INSTANCE, SPACE, &[]).unwrap(); // Activation proves an empty scope.
        assert_eq!(cache_payloads(), peers);
        assert_eq!(generation_in(&root).unwrap(), 3);
        assert_eq!(accounts.clean_cache_generation(), 3);
        assert_eq!(
            state_generation(),
            state_before,
            "eviction must not change the sync fence"
        );
    }
}

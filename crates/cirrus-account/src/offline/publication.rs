//! Local journal publication recovery, distinct from remote upload uncertainty.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::{
    AccountError, database, load_operation_parents, path_key, validate_parent_dependencies,
};

const PREFIX: &str = "local publication recovery:";

#[derive(Serialize, Deserialize, PartialEq)]
struct Head {
    instance: String,
    space: String,
    path: String,
    root: String,
    base_id: Option<String>,
    base_etag: Option<String>,
    parents: String,
    predecessor: Option<i64>,
    digest: String,
    size: u64,
    original_base: Option<String>,
    previous_error: Option<String>,
}

fn unavailable() -> AccountError {
    AccountError::new(
        "local publication requires recovery; Space fenced, local copies retained; reopen the file to recover",
    )
}

fn head(conn: &Connection, id: i64) -> Result<Head, AccountError> {
    conn.query_row("SELECT j.instance,j.space,j.path,j.staged_file,j.base_file_id,j.base_etag,p.parents,d.predecessor_id,r.digest,r.size,r.base,j.error_msg FROM operation_journal j JOIN operation_parents p ON p.operation_id=j.id JOIN dirty_roots r ON r.root=j.staged_file LEFT JOIN write_dependencies d ON d.operation_id=j.id WHERE j.id=?1 AND j.op_type='write' AND j.state='pending' AND p.destination_parents IS NULL AND j.id=(SELECT max(id) FROM operation_journal WHERE instance=j.instance AND space=j.space AND path=j.path AND op_type='write' AND state!='resolved')", [id], |row| Ok(Head {
        instance: row.get(0)?, space: row.get(1)?, path: row.get(2)?, root: row.get(3)?,
        base_id: row.get(4)?, base_etag: row.get(5)?, parents: row.get(6)?, predecessor: row.get(7)?,
        digest: row.get(8)?, size: row.get(9)?, original_base: row.get(10)?, previous_error: row.get(11)?,
    })).map_err(|_| unavailable())
}

/// Installed in the same transaction as the head CAS: either the old head or
/// the fenced candidate survives. A crash cannot expose an unclassified PUT.
pub(super) fn fence(conn: &Connection, id: i64) -> Result<String, AccountError> {
    let snapshot = head(conn, id)?;
    let marker = format!(
        "{PREFIX}{}",
        serde_json::to_string(&snapshot).map_err(|_| unavailable())?
    );
    conn.execute(
        "UPDATE operation_journal SET error_msg=?1 WHERE id=?2",
        params![marker, id],
    )
    .map_err(|error| {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) {
            super::sqlite_storage_error(error, "cannot fence local publication")
        } else {
            unavailable()
        }
    })?;
    Ok(marker)
}

/// Size the same marker representation without publishing or recovering it.
/// This is input planning only: it never authorizes a candidate or skips the
/// exact head/manifest/payload checks in recover's independent connection.
pub(super) fn planned_fence_bytes(
    conn: &Connection,
    instance: &str,
    operation: &super::PendingWrite,
    predecessor: Option<i64>,
    previous_error: Option<&str>,
) -> Result<u64, AccountError> {
    let (digest, size, original_base): (String, u64, Option<String>) = conn
        .query_row(
            "SELECT digest,size,base FROM dirty_roots WHERE root=?1",
            [&operation.staged],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| unavailable())?;
    let snapshot = Head {
        instance: instance.to_owned(),
        space: operation.space.clone(),
        path: path_key(&operation.path)?,
        root: operation.staged.clone(),
        base_id: operation.base_id.clone(),
        base_etag: operation.base_etag.clone(),
        parents: super::encode_parents(&operation.path, &operation.parents)?,
        predecessor,
        digest,
        size,
        original_base,
        previous_error: previous_error.map(str::to_owned),
    };
    let encoded = serde_json::to_string(&snapshot).map_err(|_| unavailable())?;
    (PREFIX.len() as u64)
        .checked_add(encoded.len() as u64)
        .ok_or_else(unavailable)
}

pub(crate) fn spaces(
    instance: &str,
    space: Option<&str>,
) -> Result<std::collections::HashSet<String>, AccountError> {
    let conn = database()?;
    let mut stmt = conn.prepare("SELECT DISTINCT space FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2) AND error_msg GLOB 'local publication recovery:*'")
        .map_err(|_| unavailable())?;
    stmt.query_map(params![instance, space], |row| row.get::<_, String>(0))
        .map_err(|_| unavailable())?
        .collect::<Result<_, _>>()
        .map_err(|_| unavailable())
}

pub(crate) fn ensure_clear(
    conn: &Connection,
    instance: &str,
    space: &str,
) -> Result<(), AccountError> {
    let blocked: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND space=?2 AND error_msg GLOB 'local publication recovery:*')", params![instance,space], |row| row.get(0)).map_err(|_| unavailable())?;
    if blocked {
        // Successful remote response receipts must remain resumable while a
        // concurrent local successor is fenced; this is not PUT uncertainty.
        return Err(AccountError::retryable_read(
            "local publication requires recovery; Space fenced, local copies retained; reopen the file to recover",
        ));
    }
    Ok(())
}

/// Call under account/staging ownership. Reopening closes the failed SQLite
/// transaction before interpreting its outcome. No COMMIT or write is replayed.
/// `expected` is the exact attempted candidate; None is an explicit fresh open.
pub(crate) fn recover(
    instance: &str,
    space: &str,
    path: &[String],
    id: i64,
    expected: Option<&str>,
    verify_payloads: bool,
) -> Result<bool, AccountError> {
    let mut conn = database()?;
    let marker: Option<String> = conn.query_row("SELECT error_msg FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4", params![id,instance,space,path_key(path)?], |row| row.get(0)).optional().map_err(|_| unavailable())?.flatten();
    let Some(marker) = marker.filter(|message| message.starts_with(PREFIX)) else {
        return Ok(false);
    };
    if expected.is_some_and(|expected| expected != marker) {
        return Err(unavailable());
    }
    #[cfg(feature = "fault-injection")]
    if verify_payloads
        && std::env::var_os("CIRRUS_TEST_LOCAL_RECOVERY_FAIL")
            .is_some_and(|marker| std::path::Path::new(&marker).exists())
    {
        return Err(unavailable());
    }
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| unavailable())?;
    let mut current = head(&tx, id)?;
    if current.previous_error.as_deref() != Some(marker.as_str()) {
        return Err(unavailable());
    }
    let saved: Head = serde_json::from_str(marker.strip_prefix(PREFIX).ok_or_else(unavailable)?)
        .map_err(|_| unavailable())?;
    current.previous_error = saved.previous_error.clone();
    if current != saved
        || current.instance != instance
        || current.space != space
        || current.path != path_key(path)?
    {
        return Err(unavailable());
    }
    let parents = load_operation_parents(&tx, id, path)?;
    validate_parent_dependencies(&tx, instance, space, path, &parents)?;
    let root = super::overlay::Overlay::load_in(&tx, &current.root)?;
    if root.len() != current.size || root.original_base_json()? != current.original_base {
        return Err(unavailable());
    }
    if verify_payloads {
        root.verify_payloads()?;
    }
    let count = tx.execute("UPDATE operation_journal SET error_msg=?1 WHERE id=?2 AND instance=?3 AND space=?4 AND path=?5 AND staged_file=?6 AND state='pending' AND error_msg=?7", params![saved.previous_error,id,instance,space,current.path,current.root,marker]).map_err(|_| unavailable())?;
    if count != 1 {
        return Err(unavailable());
    }
    tx.execute(
        "UPDATE sync_spaces SET attention_stamp=NULL WHERE instance=?1 AND space=?2",
        params![instance, space],
    )
    .map_err(|_| unavailable())?;
    // A second error is NOT guessed to be rollback. The fence may remain, or a
    // validated candidate may be admitted; callers still get an error and stale
    // mounted handles must revalidate. A later fresh open can finish recovery.
    tx.commit().map_err(|_| unavailable())?;
    Ok(true)
}

//! Native request publication into the existing journal and immutable staging engine.
use super::*;
use crate::provider_mutation::{Error, Record};

pub(crate) struct Namespace {
    pub path: Vec<String>,
    pub kind: &'static str,
    pub base: Option<(String, String)>,
    pub parents: Vec<DirectoryIdentity>,
    pub dependency: Option<usize>,
}
pub(crate) struct Write {
    pub path: Vec<String>,
    pub root: overlay::Overlay,
    pub base: Option<FileVersion>,
    pub parents: Vec<DirectoryIdentity>,
}

pub(crate) fn attach(
    conn: &Connection,
    record: &Record,
    operations: Vec<crate::OperationHandle>,
) -> Result<Record, AccountError> {
    let mut record = record.clone();
    record.operations = operations;
    let valid: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM fp_domains d JOIN account_identities a ON a.instance=d.instance AND a.issuer=d.issuer AND a.subject=d.subject WHERE d.domain=?1 AND d.epoch=?2 AND d.instance=?3 AND d.space=?4 AND d.issuer=?5 AND d.subject=?6)",
        params![record.domain,record.epoch,record.instance,record.space,record.issuer,record.subject], |r| r.get(0))
        .map_err(|_| AccountError::new("provider request identity unavailable"))?;
    if !valid
        || (record.operations.is_empty() && record.adopted.is_none() && record.waiting.is_none())
    {
        return Err(AccountError::new("provider request identity changed"));
    }
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM fp_requests WHERE domain=?1",
            [&record.domain],
            |r| r.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect provider request capacity"))?;
    if count >= 4096 {
        return Err(AccountError::new("staging capacity exhausted"));
    }
    let payload = serde_json::to_string(&record)
        .map_err(|_| AccountError::new("cannot encode provider request"))?;
    let bytes:i64=conn.query_row("SELECT coalesce(sum(length(CAST(record AS BLOB))+length(CAST(descriptor AS BLOB))+coalesce(length(CAST(result AS BLOB)),0)),0) FROM fp_requests WHERE domain=?1",[&record.domain],|r|r.get(0))
        .map_err(|_|AccountError::new("cannot inspect provider request capacity"))?;
    if payload.len() > 4 * 1024 * 1024
        || bytes.saturating_add(payload.len() as i64 + record.descriptor.len() as i64)
            > 32 * 1024 * 1024
    {
        return Err(AccountError::new("staging capacity exhausted"));
    }
    let advanced = if !record.operations.is_empty() && record.waiting.is_some() {
        conn.execute("UPDATE fp_requests SET record=?4 WHERE domain=?1 AND key=?2 AND descriptor=?3 AND result IS NULL AND json_array_length(record,'$.operations')=0 AND json_type(record,'$.waiting')='object'",
            params![record.domain,record.key,record.descriptor,payload])
            .map_err(|e|sqlite_storage_error(e,"cannot advance waiting provider move"))?
    } else {
        0
    };
    if advanced == 0 {
        conn.execute(
            "INSERT INTO fp_requests(domain,key,descriptor,record,result) VALUES(?1,?2,?3,?4,NULL)",
            params![record.domain, record.key, record.descriptor, payload],
        )
        .map_err(|e| {
            sqlite_storage_error(
                e,
                "provider request already published; retry its exact operation",
            )
        })?;
    }
    Ok(record)
}

/// Caller holds the normal account EX owner and has refreshed the exact namespace.
/// Every child ID and the request association share this publication transaction.
pub(crate) fn stage(
    binding: &crate::MountBinding,
    record: &Record,
    write: Option<Write>,
    namespaces: &[Namespace],
    cancelled: &impl Fn() -> bool,
) -> Result<Record, Error> {
    let name = write.as_ref().map(|w| w.root.save()).transpose()?;
    if cancelled() {
        if let Some(write) = &write {
            write.root.discard_candidate(name.as_deref())?;
        }
        return Err(Error::Cancelled);
    }
    let mut conn = database_in(&binding.root)?;
    let bytes = serde_json::to_vec(record)
        .map_err(|_| Error::Unavailable)?
        .len() as u64
        + namespaces
            .iter()
            .map(|n| {
                (n.path.iter().map(String::len).sum::<usize>() + n.parents.len() * 2048 + 8192)
                    as u64
            })
            .sum::<u64>()
        + 32768;
    let reservation = crate::provider_catalog::Catalog::reserve(&binding.root, &conn, bytes)
        .map_err(Error::from)?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| Error::Unavailable)?;
    let source = record
        .waiting
        .as_ref()
        .map(|w| w.source.as_slice())
        .unwrap_or(&record.path);
    let root_id = record
        .original
        .as_ref()
        .filter(|i| i.directory)
        .map(|i| i.remote.as_str())
        .unwrap_or("");
    for prior in crate::provider_mutation::tree_blockers_in(
        &tx,
        &binding.instance,
        &binding.space,
        source,
        &record.path,
        root_id,
        Some(record),
    )? {
        if prior.waiting.is_some()
            && !record
                .waiting
                .as_ref()
                .is_some_and(|w| w.children.contains(&prior.key))
        {
            return Err(Error::Pending);
        }
    }
    if record.deleting && record.original.as_ref().is_some_and(|i| i.directory) {
        let mut stmt=tx.prepare("SELECT path FROM operation_journal WHERE instance=?1 AND space=?2 AND state IN ('pending','conflict','uncertain')").map_err(|_|Error::Unavailable)?;
        for row in stmt
            .query_map(params![binding.instance, binding.space], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| Error::Unavailable)?
        {
            let path: Vec<String> = serde_json::from_str(&row.map_err(|_| Error::Unavailable)?)
                .map_err(|_| Error::Unavailable)?;
            if path.starts_with(&record.path) {
                return Err(Error::Pending);
            }
        }
    }
    let mut operations = Vec::new();
    let mut publication = None;
    if let (Some(write), Some(name)) = (&write, &name) {
        validate_offline_write(
            &binding.root,
            &tx,
            (&binding.instance, &binding.space),
            &write.path,
            (&binding.issuer, &binding.subject),
            write.base.as_ref(),
            &write.parents,
        )?;
        reject_fenced_ancestor(&tx, &binding.instance, &binding.space, &write.path)?;
        let occupied: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND state IN ('pending','conflict','uncertain'))",
            params![binding.instance,binding.space,path_key(&write.path)?],|r|r.get(0)).map_err(|_|Error::Unavailable)?;
        if occupied {
            return Err(Error::Pending);
        }
        tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,updated_at) VALUES(?1,?2,?3,'write',?4,?5,?6,'pending',strftime('%s','now'))",
                   params![binding.instance,binding.space,path_key(&write.path)?,write.base.as_ref().map(|v|&v.id),write.base.as_ref().map(|v|&v.etag),name]).map_err(|_|Error::Unavailable)?;
        let id = tx.last_insert_rowid();
        save_operation_parents(&tx, id, &write.path, &write.parents, None)?;
        publication = Some((id, String::new()));
        operations.push(crate::OperationHandle::capture(
            &tx,
            &binding.instance,
            &binding.space,
            id,
        )?);
    }
    for namespace in namespaces {
        reject_fenced_ancestor(&tx, &binding.instance, &binding.space, &namespace.path)?;
        validate_parent_dependencies(
            &tx,
            &binding.instance,
            &binding.space,
            &namespace.path,
            &namespace.parents,
        )?;
        let key = path_key(&namespace.path)?;
        let occupied: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND state IN ('pending','conflict','uncertain'))",
            params![binding.instance,binding.space,key],|r|r.get(0)).map_err(|_|Error::Unavailable)?;
        if occupied {
            return Err(Error::Pending);
        }
        let dependency = namespace
            .dependency
            .map(|i| {
                operations
                    .get(i)
                    .map(|o| format!("destination-operation:{}", o.id()))
                    .ok_or(Error::Unavailable)
            })
            .transpose()?;
        tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,'pending',?8,strftime('%s','now'))",
                   params![binding.instance,binding.space,key,namespace.kind,namespace.base.as_ref().map(|v|&v.0),namespace.base.as_ref().map(|v|&v.1),namespace_token()?,dependency]).map_err(|_|Error::Unavailable)?;
        let id = tx.last_insert_rowid();
        save_operation_parents(&tx, id, &namespace.path, &namespace.parents, None)?;
        if namespace.kind == "mkdir" {
            write_local_snapshot(&tx, &binding.instance, &binding.space, &namespace.path, id)?;
        }
        operations.push(crate::OperationHandle::capture(
            &tx,
            &binding.instance,
            &binding.space,
            id,
        )?);
    }
    let count: i64=tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND state IN ('pending','conflict','uncertain')",[&binding.instance],|r|r.get(0)).map_err(|_|Error::Unavailable)?;
    if count > MAX_PENDING_NAMESPACE_OPERATIONS {
        return Err(Error::Capacity);
    }
    // All pre-existing fences were checked before any new marker is installed.
    // Install our own fence last so the composite's source row cannot mistake
    // its destination's uncommitted marker for another publication in flight.
    if let Some((id, marker)) = &mut publication {
        *marker = publication::fence(&tx, *id)?;
    }
    let result = attach(&tx, record, operations)?;
    if let (Some(write), Some(source)) =
        (&write, namespaces.iter().find(|n| n.kind == "move-source"))
    {
        relocate_pins(
            &binding.root,
            &tx,
            &binding.instance,
            &binding.space,
            &source.path,
            &write.path,
        )?;
    }
    if let Some(r) = &reservation {
        r.validate(&tx)?;
    }
    if cancelled() {
        drop(tx);
        drop(conn);
        if let Some(write) = &write {
            write.root.discard_candidate(name.as_deref())?;
        }
        return Err(Error::Cancelled);
    }
    let committed = tx.commit();
    conn.close().map_err(|_| Error::Unavailable)?;
    if let (Some((id, marker)), Some(write)) = (publication, &write) {
        if !publication::recover_in(
            &binding.root,
            &binding.instance,
            &binding.space,
            &write.path,
            id,
            Some(&marker),
            committed.is_err(),
        )? {
            return Err(Error::Unavailable);
        }
    } else {
        committed.map_err(|_| Error::Unavailable)?;
    }
    Ok(result)
}

//! Successful namespace acknowledgements, distinct from observed absence.

use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::{NamespaceOperation, database_in, encode_parents, path_key};
use crate::{AccountError, account_storage::StorageRoot};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Pending,
    Verified,
}

impl Phase {
    fn kind(self) -> &'static str {
        match self {
            Self::Pending => "namespace",
            Self::Verified => "namespace-verified",
        }
    }

    fn state(self) -> &'static str {
        match self {
            Self::Pending => "uncertain",
            Self::Verified => "synced",
        }
    }
}

// Nesting the operation deliberately makes this unreadable as a legacy
// NamespaceOperation. Keep the existing kinds so old retention whitelists
// preserve verified evidence, while old parsers fail closed.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgement {
    namespace_receipt_version: u8,
    http_status: u16,
    root_device: u64,
    root_inode: u64,
    instance: String,
    issuer: String,
    subject: String,
    operation: NamespaceOperation,
    rebase: Option<NamespaceOperation>,
}

pub(crate) struct Receipt {
    _root: StorageRoot,
    operation: NamespaceOperation,
    rebase: Option<NamespaceOperation>,
    phase: Phase,
    snapshot: String,
    extra: String,
}

impl Receipt {
    pub(crate) fn operation(&self) -> &NamespaceOperation {
        &self.operation
    }

    pub(crate) fn rebase(&self) -> Option<&NamespaceOperation> {
        self.rebase.as_ref()
    }

    pub(crate) fn matches_encoded(&self, snapshot: &str, extra: &str) -> bool {
        self.snapshot == snapshot && self.extra == extra
    }

    pub(super) fn promote(&self, tx: &Transaction<'_>) -> Result<(), AccountError> {
        if self.phase != Phase::Pending {
            return Err(unavailable());
        }
        let count = tx.execute(
            "UPDATE mutation_receipts SET kind='namespace-verified' WHERE operation_id=?1 AND kind='namespace' AND snapshot=?2 AND extra=?3",
            params![self.operation.id, self.snapshot, self.extra],
        ).map_err(|_| unavailable())?;
        if count != 1 {
            return Err(unavailable());
        }
        Ok(())
    }
}

pub(crate) fn principal(
    conn: &Connection,
    instance: &str,
) -> Result<(String, String), AccountError> {
    conn.query_row(
        "SELECT issuer,subject FROM account_identities WHERE instance=?1",
        [instance],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .map_err(|_| unavailable())
}

fn root_identity(root: &StorageRoot) -> Result<(u64, u64), AccountError> {
    let stat = rustix::fs::fstat(root.directory()).map_err(|_| unavailable())?;
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

fn successful(status: u16) -> bool {
    matches!(status, 200 | 201 | 204)
}

fn validate_operation(
    conn: &Connection,
    instance: &str,
    owner: (&str, &str),
    operation: &NamespaceOperation,
    phase: Phase,
) -> Result<(), AccountError> {
    if operation.id <= 0
        || !matches!(
            operation.kind.as_str(),
            "mkdir" | "unlink" | "rmdir" | "move-source" | "move-dir-source"
        )
    {
        return Err(unavailable());
    }
    let valid: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM operation_journal j JOIN account_identities a ON a.instance=j.instance WHERE j.id=?1 AND j.instance=?2 AND j.space=?3 AND j.path=?4 AND j.op_type=?5 AND j.base_file_id IS ?6 AND j.base_etag IS ?7 AND j.staged_file=?8 AND j.state=?9 AND a.issuer=?10 AND a.subject=?11 AND EXISTS(SELECT 1 FROM operation_parents WHERE operation_id=j.id AND parents=?12 AND destination_parents IS NULL))",
        params![operation.id,instance,operation.space,path_key(&operation.path)?,operation.kind,operation.base_id,operation.base_etag,operation.token,phase.state(),owner.0,owner.1,encode_parents(&operation.path,&operation.parents)?],
        |row| row.get(0),
    ).map_err(|_| unavailable())?;
    if !valid {
        return Err(unavailable());
    }
    Ok(())
}

fn validate_rebase(
    operation: &NamespaceOperation,
    rebase: Option<&NamespaceOperation>,
) -> Result<(), AccountError> {
    if let Some(parent) = rebase
        && (operation.kind == "mkdir"
            || operation.path.len() < 2
            || parent.kind != "rmdir"
            || parent.space != operation.space
            || parent.path != operation.path[..operation.path.len() - 1])
    {
        return Err(unavailable());
    }
    Ok(())
}

pub(crate) fn record(
    root: &StorageRoot,
    instance: &str,
    owner: (&str, &str),
    operation: &NamespaceOperation,
    rebase: Option<&NamespaceOperation>,
    status: reqwest::StatusCode,
) -> Result<(), AccountError> {
    if !successful(status.as_u16()) {
        return Err(unavailable());
    }
    validate_rebase(operation, rebase)?;
    let (root_device, root_inode) = root_identity(root)?;
    let snapshot = serde_json::to_string(&Acknowledgement {
        namespace_receipt_version: 2,
        http_status: status.as_u16(),
        root_device,
        root_inode,
        instance: instance.to_owned(),
        issuer: owner.0.to_owned(),
        subject: owner.1.to_owned(),
        operation: operation.clone(),
        rebase: rebase.cloned(),
    })
    .map_err(|_| unavailable())?;
    // An acknowledged mutation must retain its uncapped receipt even when
    // ordinary growth admission is closed. Never reset the uncertain claim.
    let mut conn = database_in(root)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| unavailable())?;
    validate_operation(&tx, instance, owner, operation, Phase::Pending)?;
    tx.execute(
        "INSERT INTO mutation_receipts(operation_id,kind,snapshot,extra) VALUES(?1,'namespace',?2,'null')",
        params![operation.id,snapshot],
    ).map_err(|_| unavailable())?;
    tx.execute(
        "DELETE FROM sync_reads WHERE operation_id=?1",
        [operation.id],
    )
    .map_err(|_| unavailable())?;
    tx.commit().map_err(|_| unavailable())
}

pub(crate) fn load(
    root: &StorageRoot,
    conn: &Connection,
    instance: &str,
    owner: (&str, &str),
    id: i64,
    phase: Phase,
) -> Result<Receipt, AccountError> {
    let (snapshot, extra): (String, String) = conn
        .query_row(
            "SELECT snapshot,extra FROM mutation_receipts WHERE operation_id=?1 AND kind=?2",
            params![id, phase.kind()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| unavailable())?;
    let value: serde_json::Value = serde_json::from_str(&snapshot).map_err(|_| unavailable())?;
    let (operation, rebase) = if value.get("namespace_receipt_version").is_some() {
        let ack: Acknowledgement = serde_json::from_value(value).map_err(|_| unavailable())?;
        if ack.namespace_receipt_version != 2
            || !successful(ack.http_status)
            || (ack.root_device, ack.root_inode) != root_identity(root)?
            || ack.instance != instance
            || ack.issuer != owner.0
            || ack.subject != owner.1
            || extra != "null"
        {
            return Err(unavailable());
        }
        (ack.operation, ack.rebase)
    } else {
        let operation: NamespaceOperation =
            serde_json::from_value(value).map_err(|_| unavailable())?;
        // Only historical MKCOL producers had an unambiguous success gate.
        // DELETE404 and 2xx were indistinguishable; GET cannot repair that loss.
        if operation.kind != "mkdir" {
            return Err(unavailable());
        }
        let rebase: Option<NamespaceOperation> =
            serde_json::from_str(&extra).map_err(|_| unavailable())?;
        (operation, rebase)
    };
    if operation.id != id {
        return Err(unavailable());
    }
    validate_operation(conn, instance, owner, &operation, phase)?;
    validate_rebase(&operation, rebase.as_ref())?;
    Ok(Receipt {
        _root: root.clone(),
        operation,
        rebase,
        phase,
        snapshot,
        extra,
    })
}

// Local projection may use a genuine preflight absence observation, but never
// relabel an existing ambiguous receipt as that observation.
pub(super) fn require_removal_observation(
    root: &StorageRoot,
    conn: &Connection,
    instance: &str,
    id: i64,
) -> Result<(), AccountError> {
    let (state, absent, receipt): (String, bool, bool) = conn
        .query_row(
            "SELECT state,error_msg IS 'target already absent',EXISTS(SELECT 1 FROM mutation_receipts WHERE operation_id=j.id) FROM operation_journal j WHERE id=?1 AND instance=?2 AND op_type IN ('unlink','rmdir','move-source','move-dir-source')",
            params![id,instance],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        )
        .map_err(|_| unavailable())?;
    if state == "synced" && absent && !receipt {
        return Ok(());
    }
    let phase = match state.as_str() {
        "uncertain" => Phase::Pending,
        "synced" => Phase::Verified,
        _ => return Err(unavailable()),
    };
    let (issuer, subject) = principal(conn, instance)?;
    load(root, conn, instance, (&issuer, &subject), id, phase)?;
    Ok(())
}

fn unavailable() -> AccountError {
    AccountError::new("namespace acknowledgement unavailable; local data retained")
}

#[cfg(all(test, target_os = "linux"))]
mod acceptance {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    #[ignore = "requires an explicit empty private namespace receipt container"]
    fn legacy_delete_is_retained_and_new_acknowledgement_continues() {
        let container = std::path::PathBuf::from(
            std::env::var_os("CIRRUS_TEST_NAMESPACE_CONTAINER")
                .expect("explicit private container"),
        );
        assert_eq!(container, std::fs::canonicalize(&container).unwrap());
        assert_eq!(
            container.parent().unwrap().parent().unwrap(),
            std::path::Path::new("/workspaces/.ubuntu-disposable-scratch"),
        );
        let metadata = std::fs::symlink_metadata(&container).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert!(std::fs::read_dir(&container).unwrap().next().is_none());
        let root = StorageRoot::open_container(&container).unwrap();
        let instance = "https://namespace-receipt.invalid/";
        let issuer = "acceptance-issuer";
        let subject = "acceptance-subject";
        super::super::bind_identity_in(&root, instance, issuer, subject).unwrap();
        let conn = database_in(&root).unwrap();
        let mut operations = Vec::new();
        for id in 1..=3 {
            let operation = NamespaceOperation {
                id,
                space: "space".into(),
                path: vec![format!("file-{id}")],
                kind: "unlink".into(),
                base_id: Some(format!("remote-{id}")),
                base_etag: Some("\"original\"".into()),
                dependency: None,
                parents: Vec::new(),
                token: format!("{id:032x}"),
                pending_message: None,
            };
            conn.execute(
                "INSERT INTO operation_journal(id,instance,space,path,op_type,base_file_id,base_etag,staged_file,state,updated_at) VALUES(?1,?2,'space',?3,'unlink',?4,?5,?6,?7,1)",
                params![id,instance,path_key(&operation.path).unwrap(),operation.base_id,operation.base_etag,operation.token,if id==2 {"synced"} else {"uncertain"}],
            ).unwrap();
            super::super::save_operation_parents(&conn, id, &operation.path, &[], None).unwrap();
            if id <= 2 {
                conn.execute(
                    "INSERT INTO mutation_receipts VALUES(?1,?2,?3,'null')",
                    params![
                        id,
                        if id == 1 {
                            "namespace"
                        } else {
                            "namespace-verified"
                        },
                        serde_json::to_string(&operation).unwrap()
                    ],
                )
                .unwrap();
            }
            operations.push(operation);
        }
        let binding = crate::MountBinding {
            root: root.clone(),
            instance: instance.into(),
            space: "space".into(),
            name: None,
            issuer: issuer.into(),
            subject: subject.into(),
            offline: true,
            offline_writable: false,
        };
        let old_handle = crate::OperationHandle::capture(&conn, instance, "space", 2).unwrap();
        let new_handle = crate::OperationHandle::capture(&conn, instance, "space", 3).unwrap();
        let legacy_snapshot = |conn: &Connection| {
            let mut statement = conn.prepare(
                "SELECT json_array(j.id,j.instance,j.space,j.path,j.op_type,j.base_file_id,j.base_etag,j.staged_file,j.state,j.error_msg,j.updated_at,j.confirmed_file_id,j.confirmed_etag,r.kind,r.snapshot,r.extra,p.parents,p.destination_parents) FROM operation_journal j JOIN mutation_receipts r ON r.operation_id=j.id JOIN operation_parents p ON p.operation_id=j.id WHERE j.id IN (1,2) ORDER BY j.id",
            ).unwrap();
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap();
            rows.collect::<Result<Vec<_>, _>>().unwrap()
        };
        let original = legacy_snapshot(&conn);
        drop(conn);

        assert!(
            super::super::confirm_namespace(&root, instance, &operations[0], None, None,).is_err()
        );
        let conn = database_in(&root).unwrap();
        assert!(crate::operation_result::result_in(&conn, &binding, &old_handle).is_err());
        assert_eq!(legacy_snapshot(&conn), original);
        drop(conn);

        // This is the real producer/SQLite confirmation boundary with an explicit
        // successful response input, not an HTTP request or simulated readback.
        crate::executor::namespace_receipt(
            &root,
            instance,
            (issuer, subject),
            &operations[2],
            None,
            reqwest::StatusCode::NO_CONTENT,
        )
        .unwrap();
        let conn = database_in(&root).unwrap();
        load(&root, &conn, instance, (issuer, subject), 3, Phase::Pending).unwrap();
        drop(conn);
        super::super::confirm_namespace(&root, instance, &operations[2], None, None).unwrap();
        let conn = database_in(&root).unwrap();
        assert!(matches!(
            crate::operation_result::result_in(&conn, &binding, &new_handle).unwrap(),
            crate::OperationResult::ConfirmedNamespace,
        ));
        assert_eq!(legacy_snapshot(&conn), original);
        println!("LEGACY_DELETE_ROWS_UNCHANGED; NEW_PERSISTED_ACK_CONFIRMED; NO_REMOTE_READBACK");
    }
}

//! Durable evidence of a successful PUT, never permission to replay a mutation.

use rusqlite::{OptionalExtension, params};

use super::{
    AccountError, FileVersion, PendingWrite, StorageRoot, database_in, encode_parents,
    has_unresolved, path_key, sqlite_storage_error, write_needs_attention,
};

pub(crate) fn write_turn_dependencies(
    root: &StorageRoot,
    instance: &str,
    space: Option<&str>,
) -> Result<bool, AccountError> {
    database_in(root)?.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2) AND state='pending' AND op_type!='write')", params![instance,space], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect write dependencies"))
}

pub(crate) fn write_turn_remaining(
    root: &StorageRoot,
    instance: &str,
    space: Option<&str>,
) -> Result<crate::WriteTurnOutcome, AccountError> {
    let conn = database_in(root)?;
    let attention: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2) AND state IN ('conflict','uncertain'))", params![instance,space], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect write outcome"))?;
    Ok(if attention {
        crate::WriteTurnOutcome::Attention
    } else if has_unresolved(root, instance, space)? {
        crate::WriteTurnOutcome::Dependencies
    } else {
        crate::WriteTurnOutcome::Idle
    })
}

pub(crate) struct UploadVerification {
    root: StorageRoot,
    pub operation: PendingWrite,
    pub digest: String,
    pub size: u64,
    pub version: Option<FileVersion>,
    pub offset: u64,
    pub parent_index: usize,
}

impl UploadVerification {
    pub(crate) fn check_progress(&self, instance: &str) -> Result<(), AccountError> {
        if self.offset > self.size
            || self.parent_index > self.operation.parents.len()
            || (self.parent_index != 0 && self.offset != self.size)
            || self.version.as_ref().is_some_and(|version| {
                version.instance != instance
                    || version.space != self.operation.space
                    || version.path != self.operation.path
                    || version.size != self.size
                    || !crate::dav::valid_remote_id(&version.id)
                    || !crate::dav::strong_etag(&version.etag)
            })
            || (self.version.is_none() && (self.offset != 0 || self.parent_index != 0))
        {
            return Err(AccountError::new(
                "invalid upload verification progress; outcome remains uncertain",
            ));
        }
        Ok(())
    }

    pub(crate) fn check_root(&self, root: &StorageRoot) -> Result<(), AccountError> {
        if self.root.identity() != root.identity() {
            return Err(AccountError::new(
                "upload verification storage root changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn record(
        root: &StorageRoot,
        instance: &str,
        operation: &PendingWrite,
        digest: String,
        size: u64,
    ) -> Result<Self, AccountError> {
        // This records an already successful remote response. Never apply
        // opt-in growth admission here: the pre-PUT uncertain fence survives
        // even if receipt persistence fails, and must never be reset to pending.
        #[cfg(feature = "fault-injection")]
        crate::wait_test_window("CIRRUS_TEST_VERIFICATION_RECEIPT_WINDOW")?;
        let mut conn = database_in(root)?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| sqlite_storage_error(error, "cannot begin upload verification"))?;
        // Claim the same exact journal snapshot as confirmation, within the
        // transaction that records receipt of the successful response.
        let count = tx.execute(
            "UPDATE operation_journal SET error_msg='successful upload; read-back verification pending' WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='uncertain' AND staged_file=?5 AND base_file_id IS ?6 AND base_etag IS ?7 AND EXISTS(SELECT 1 FROM operation_parents WHERE operation_id=?1 AND parents=?8 AND destination_parents IS NULL)",
            params![operation.id, instance, operation.space, path_key(&operation.path)?, operation.staged, operation.base_id, operation.base_etag, encode_parents(&operation.path, &operation.parents)?],
        ).map_err(|error| sqlite_storage_error(error, "cannot record successful upload"))?;
        if count != 1 {
            return Err(AccountError::new(
                "staged write changed; local copy retained",
            ));
        }
        let encoded = serde_json::to_string(operation)
            .map_err(|_| AccountError::new("cannot encode upload snapshot"))?;
        tx.execute("INSERT INTO upload_verifications(operation_id,operation,digest,size,version,verified_offset,parent_index) VALUES(?1,?2,?3,?4,NULL,0,0)", params![operation.id, encoded, digest, size])
            .map_err(|error| sqlite_storage_error(error, "cannot persist upload verification"))?;
        #[cfg(feature = "fault-injection")]
        if let Some(marker) = std::env::var_os("CIRRUS_TEST_VERIFICATION_RECEIPT_ABORT")
            && std::fs::remove_file(marker).is_ok()
        {
            tx.commit_hook(Some(|| true));
            eprintln!("cirrus lab upload receipt COMMIT hook veto (not disk I/O)");
        }
        tx.commit()
            .map_err(|error| sqlite_storage_error(error, "cannot commit upload verification"))?;
        Ok(Self {
            root: root.clone(),
            operation: operation.clone(),
            digest,
            size,
            version: None,
            offset: 0,
            parent_index: 0,
        })
    }

    pub(crate) fn save(&self, instance: &str) -> Result<(), AccountError> {
        self.check_progress(instance)?;
        if !write_needs_attention(&self.root, instance, &self.operation).map_err(|mut error| {
            error.retryable_read = true;
            error
        })? {
            return Err(AccountError::new(
                "upload snapshot changed; local copy retained",
            ));
        }
        let version = self
            .version
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| AccountError::new("cannot encode upload version"))?;
        let encoded = serde_json::to_string(&self.operation)
            .map_err(|_| AccountError::new("cannot encode upload snapshot"))?;
        let parents = encode_parents(&self.operation.path, &self.operation.parents)?;
        let path = path_key(&self.operation.path)?;
        // Only GET-only continuation growth is admitted. No reservation spans
        // the PUT/GET or source reads; record/confirmation/recovery stay uncapped.
        let result = (|| {
            let reservation;
            let mut conn = database_in(&self.root)?;
            let planning_version: i64 = conn
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| AccountError::new("cannot inspect verification progress plan"))?;
            let stored: Option<Option<String>> = conn.query_row(
                "SELECT version FROM upload_verifications WHERE operation_id=?1 AND operation=?2 AND digest=?3 AND size=?4",
                params![self.operation.id,encoded,self.digest,self.size], |row| row.get(0),
            ).optional().map_err(|_| AccountError::new("cannot inspect verification progress"))?;
            if stored.is_none()
                || stored
                    .flatten()
                    .is_some_and(|stored| Some(stored) != version)
            {
                return Err(AccountError::new(
                    "upload verification changed; receipt and local copy retained",
                ));
            }
            let planned = if crate::storage::limits::view_in(&self.root)?
                .limits
                .is_some()
            {
                serde_json::to_vec(&(&version, self.offset, self.parent_index, self.operation.id))
                    .map_err(|_| AccountError::new("cannot size verification progress"))?
                    .len() as u64
            } else {
                0
            };
            #[cfg(feature = "fault-injection")]
            crate::wait_test_window("CIRRUS_TEST_VERIFICATION_ADMISSION_WINDOW")?;
            reservation = crate::storage::sql_reservation::SqlReservation::begin_in(
                &self.root,
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
                .map_err(|error| {
                    sqlite_storage_error(error, "cannot begin verification progress")
                })?;
            if reservation.is_some() {
                let current: i64 = tx
                    .pragma_query_value(None, "data_version", |row| row.get(0))
                    .map_err(|_| AccountError::new("cannot inspect verification progress plan"))?;
                if current != planning_version {
                    return Err(AccountError::new(
                        "verification progress plan changed; receipt retained; retry GET verification",
                    ));
                }
            }
            // The receipt identity and first observed remote version are fixed.
            // Stale concurrent observations cannot regress progress or retarget
            // an existing receipt. A waiting successor is a distinct operation.
            let count = tx.execute("UPDATE upload_verifications SET version=?1,verified_offset=max(verified_offset,?2),parent_index=max(parent_index,?5) WHERE operation_id=?3 AND operation=?6 AND digest=?7 AND size=?8 AND (version IS NULL OR version IS ?1) AND EXISTS(SELECT 1 FROM operation_journal j WHERE j.id=?3 AND j.instance=?4 AND j.space=?9 AND j.path=?10 AND j.op_type='write' AND j.state='uncertain' AND j.staged_file=?11 AND j.base_file_id IS ?12 AND j.base_etag IS ?13 AND EXISTS(SELECT 1 FROM operation_parents p WHERE p.operation_id=j.id AND p.parents=?14 AND p.destination_parents IS NULL))",
                params![version,self.offset,self.operation.id,instance,self.parent_index,encoded,self.digest,self.size,self.operation.space,path,self.operation.staged,self.operation.base_id,self.operation.base_etag,parents])
                .map_err(|error| sqlite_storage_error(error, "cannot persist verification progress"))?;
            if count != 1 {
                return Err(AccountError::new(
                    "upload verification changed; receipt and local copy retained",
                ));
            }
            #[cfg(feature = "fault-injection")]
            crate::wait_test_window("CIRRUS_TEST_VERIFICATION_COMMIT_WINDOW")?;
            if let Some(reservation) = &reservation {
                reservation.validate(&tx)?;
            } else if crate::storage::limits::view_in(&self.root)?
                .limits
                .is_some()
            {
                return Err(AccountError::new(crate::storage::limits::PRESSURE));
            }
            let committed = tx.commit();
            #[cfg(feature = "fault-injection")]
            let committed = if self.offset > 0
                && committed.is_ok()
                && let Some(marker) =
                    std::env::var_os("CIRRUS_TEST_VERIFICATION_SAVE_COMMITTED_ERROR")
                && std::fs::remove_file(marker).is_ok()
            {
                eprintln!(
                    "cirrus lab verification progress committed-but-returned-error (not hardware I/O)"
                );
                Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                    None,
                ))
            } else {
                committed
            };
            conn.close().map_err(|_| AccountError::new("cannot close verification progress database; outcome unknown; receipt retained"))?;
            committed.map_err(|_| {
                AccountError::new(
                    "cannot commit verification progress; outcome unknown; receipt retained",
                )
            })?;
            Ok(())
        })();
        // advance_upload must preserve the successful-response receipt on a
        // local persistence/admission error. Next turn reloads durable state
        // and repeats GET only, even after an ambiguous progress COMMIT.
        result.map_err(|mut error: AccountError| {
            error.retryable_read = true;
            error
        })
    }

    pub(crate) fn discard(&self) -> Result<(), AccountError> {
        database_in(&self.root)?
            .execute(
                "DELETE FROM upload_verifications WHERE operation_id=?1",
                [self.operation.id],
            )
            .map_err(|error| sqlite_storage_error(error, "cannot retire upload verification"))?;
        Ok(())
    }
}

pub(crate) fn upload_verifications(
    root: &StorageRoot,
    instance: &str,
    space: Option<&str>,
    after: i64,
) -> Result<Vec<UploadVerification>, AccountError> {
    let conn = database_in(root)?;
    let mut statement = conn.prepare("SELECT v.operation_id,j.space,v.operation,v.digest,v.size,v.version,v.verified_offset,v.parent_index FROM upload_verifications v JOIN operation_journal j ON j.id=v.operation_id WHERE j.instance=?1 AND (?2 IS NULL OR j.space=?2) AND j.state='uncertain' AND j.op_type='write' AND j.id>?3 ORDER BY j.id LIMIT 32")
        .map_err(|_| AccountError::new("cannot load upload verifications"))?;
    let rows = statement
        .query_map(params![instance, space, after], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, u64>(6)?,
                row.get::<_, usize>(7)?,
            ))
        })
        .map_err(|_| AccountError::new("cannot read upload verifications"))?;
    rows.map(|row| {
        let (id, space, operation, digest, size, version, offset, parent_index) =
            row.map_err(|_| AccountError::new("invalid upload verification"))?;
        let operation: PendingWrite = serde_json::from_str(&operation)
            .map_err(|_| AccountError::new("invalid upload snapshot"))?;
        let version = version
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(|_| AccountError::new("invalid upload version"))?;
        if operation.id != id
            || operation.space != space
            || digest.len() != 64
            || !digest.bytes().all(|b| b.is_ascii_hexdigit())
            || !write_needs_attention(root, instance, &operation)?
        {
            return Err(AccountError::new(
                "invalid upload verification; local copy retained",
            ));
        }
        let verification = UploadVerification {
            root: root.clone(),
            operation,
            digest,
            size,
            version,
            offset,
            parent_index,
        };
        verification.check_progress(instance)?;
        Ok(verification)
    })
    .collect()
}

#[cfg(all(test, target_os = "linux"))]
mod acceptance {
    use super::*;
    use sha2::Digest;
    use std::os::unix::fs::MetadataExt;

    #[test]
    #[ignore = "requires an explicit empty private receipt container"]
    fn rejects_unversioned_progress_on_restart() {
        let container = std::path::PathBuf::from(
            std::env::var_os("CIRRUS_TEST_RECEIPT_CONTAINER").expect("explicit private container"),
        );
        assert_eq!(container, std::fs::canonicalize(&container).unwrap());
        assert_eq!(
            container.parent().unwrap().parent().unwrap(),
            std::path::Path::new("/workspaces/.ubuntu-disposable-scratch")
        );
        let metadata = std::fs::symlink_metadata(&container).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert!(std::fs::read_dir(&container).unwrap().next().is_none());
        let root = StorageRoot::open_container(&container).unwrap();
        let instance = "https://receipt-acceptance.invalid/";
        crate::offline::bind_identity_in(&root, instance, "fixture-issuer", "fixture-subject")
            .unwrap();
        let bytes = b"immutable receipt restart payload";
        let mut candidate = crate::offline::overlay::Overlay::empty_in(&root);
        candidate.write(0, bytes).unwrap();
        let staged = candidate.save().unwrap();
        let conn = database_in(&root).unwrap();
        let path = vec!["folder".to_owned(), "draft.txt".to_owned()];
        let parents = vec![crate::DirectoryIdentity::Remote("fixture-parent".into())];
        conn.execute(
            "INSERT INTO operation_journal(instance,space,path,op_type,staged_file,state,updated_at) VALUES(?1,'fixture-space',?2,'write',?3,'uncertain',1)",
            params![instance, path_key(&path).unwrap(), staged],
        )
        .unwrap();
        let id = conn.last_insert_rowid();
        crate::offline::save_operation_parents(&conn, id, &path, &parents, None).unwrap();
        let operation = PendingWrite {
            id,
            space: "fixture-space".into(),
            path,
            base_id: None,
            base_etag: None,
            staged,
            parents,
        };
        drop(conn);
        UploadVerification::record(
            &root,
            instance,
            &operation,
            format!("{:x}", sha2::Sha256::digest(bytes)),
            bytes.len() as u64,
        )
        .unwrap();
        let loaded = upload_verifications(&root, instance, None, 0).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].version.is_none());
        assert_eq!((loaded[0].offset, loaded[0].parent_index), (0, 0));
        drop(loaded);

        let conn = database_in(&root).unwrap();
        conn.execute(
            "UPDATE upload_verifications SET verified_offset=size,parent_index=?2 WHERE operation_id=?1 AND version IS NULL",
            params![id, operation.parents.len()],
        )
        .unwrap();
        let snapshot = |conn: &rusqlite::Connection| -> String {
            conn.query_row(
                "SELECT json_array(j.state,v.operation,v.digest,v.size,v.version,v.verified_offset,v.parent_index) FROM upload_verifications v JOIN operation_journal j ON j.id=v.operation_id WHERE v.operation_id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap()
        };
        let malformed = snapshot(&conn);
        drop(conn);

        assert!(upload_verifications(&root, instance, None, 0).is_err());
        let reopened = database_in(&root).unwrap();
        assert_eq!(snapshot(&reopened), malformed);
    }
}

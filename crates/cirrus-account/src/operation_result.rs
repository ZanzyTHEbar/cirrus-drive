//! Exact journal-operation observations, separate from Space-wide scheduling status.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{AccountError, Accounts, FileVersion, MountBinding, dav, offline};

/// Immutable operation correlation returned from a staged snapshot.
///
/// Retain this value across retries/restarts. It is not permission to submit a
/// second mutation, nor does local journal publication imply remote completion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationHandle {
    instance: String,
    issuer: String,
    subject: String,
    space: String,
    id: i64,
    path: Vec<String>,
    kind: String,
    token: String,
    base_id: Option<String>,
    base_etag: Option<String>,
    manifest_digest: Option<String>,
    destination: Option<String>,
    predecessor: Option<i64>,
}

/// An exact operation's durable outcome; locally resolved is never confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationResult {
    /// Not yet admitted to a remote mutation.
    Pending,
    /// A changed remote precondition requires recovery.
    Conflict,
    /// Remote outcome is unknown, or successful-response verification is pending.
    Uncertain {
        /// A durable successful-response receipt exists; reads may resume.
        verification_pending: bool,
    },
    /// Locally acknowledged or superseded; no remote-success assertion.
    Resolved,
    /// This exact write's bytes were read back and matched by the real executor.
    ConfirmedWrite {
        /// Exact confirmed remote identity, strong ETag, path and size.
        version: FileVersion,
        /// SHA-256 retained by the actual upload verifier.
        digest: String,
    },
    /// This exact namespace mutation passed its successful-response read-back.
    ///
    /// This is deliberately not metadata suitable for catalog publication. A
    /// separate confirmed metadata record is needed before returning an OS item.
    ConfirmedNamespace,
    /// The executor observed an absent target without this operation's DELETE.
    /// This is not causal mutation proof or a current remote postcondition.
    ObservedAbsent,
}

impl OperationHandle {
    pub(crate) fn recover_publication(&self, binding: &MountBinding) -> Result<(), AccountError> {
        if self.instance != binding.instance
            || self.space != binding.space
            || self.issuer != binding.issuer
            || self.subject != binding.subject
        {
            return Err(unavailable());
        }
        if self.kind == "write" {
            offline::publication::recover_in(
                &binding.root,
                &self.instance,
                &self.space,
                &self.path,
                self.id,
                None,
                true,
            )?;
        }
        Ok(())
    }
    /// The actual journal ID, never a Space high-water or a callback pointer.
    pub fn id(&self) -> i64 {
        self.id
    }

    pub(crate) fn path(&self) -> &[String] {
        &self.path
    }

    pub(crate) fn removes(&self, remote: &str) -> bool {
        matches!(self.kind.as_str(), "unlink" | "rmdir") && self.base_id.as_deref() == Some(remote)
    }

    pub(crate) fn capture(
        conn: &rusqlite::Connection,
        instance: &str,
        space: &str,
        id: i64,
    ) -> Result<Self, AccountError> {
        let (issuer, subject, path, kind, token, base_id, base_etag, manifest_digest, destination, predecessor):
            (String, String, String, String, String, Option<String>, Option<String>, Option<String>, Option<String>, Option<i64>) =
            conn.query_row(
                "SELECT a.issuer,a.subject,j.path,j.op_type,j.staged_file,j.base_file_id,j.base_etag,(SELECT digest FROM dirty_roots WHERE root=j.staged_file),(SELECT destination FROM directory_moves WHERE operation_id=j.id),(SELECT predecessor_id FROM write_dependencies WHERE operation_id=j.id) FROM operation_journal j JOIN account_identities a ON a.instance=j.instance WHERE j.id=?1 AND j.instance=?2 AND j.space=?3",
                params![id,instance,space],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
            ).map_err(|_| unavailable())?;
        Ok(Self {
            instance: instance.to_owned(),
            issuer,
            subject,
            space: space.to_owned(),
            id,
            path: serde_json::from_str(&path).map_err(|_| unavailable())?,
            kind,
            token,
            base_id,
            base_etag,
            manifest_digest,
            destination,
            predecessor,
        })
    }
}

impl Accounts {
    /// Captures the immutable journal identity of an exact staged file version.
    ///
    /// # Errors
    /// Refuses a changed staging token, path, principal, Space or storage root.
    /// This query does not stage work or contact credentials/network.
    pub fn staged_operation(
        &self,
        binding: &MountBinding,
        version: &FileVersion,
    ) -> Result<OperationHandle, AccountError> {
        if version.instance != binding.instance || version.space != binding.space {
            return Err(AccountError::new("operation Space binding changed"));
        }
        let id = version
            .id
            .strip_prefix("cirrus-staged:")
            .and_then(|id| id.parse::<i64>().ok())
            .filter(|id| *id > 0)
            .ok_or_else(|| AccountError::new("operation requires a staged version"))?;
        let token = version
            .etag
            .strip_prefix("\"cirrus-staged-")
            .and_then(|token| token.strip_suffix('"'))
            .ok_or_else(|| AccountError::new("invalid operation staging token"))?;
        self.storage.validate(&binding.root)?;
        let mut conn = offline::database_in(&binding.root)?;
        let tx = conn.transaction().map_err(|_| unavailable())?;
        check_principal(&tx, binding)?;
        let operation = OperationHandle::capture(&tx, &binding.instance, &binding.space, id)?;
        if operation.kind != "write" || operation.path != version.path || operation.token != token {
            return Err(unavailable());
        }
        Ok(operation)
    }

    /// Observes only the retained operation, never an unrelated Space's progress.
    ///
    /// # Errors
    /// Refuses changed journal identity and malformed or absent verification
    /// evidence. In particular `synced` alone is not verified write completion.
    pub fn operation_result(
        &self,
        binding: &MountBinding,
        operation: &OperationHandle,
    ) -> Result<OperationResult, AccountError> {
        self.storage.validate(&binding.root)?;
        let mut conn = offline::database_in(&binding.root)?;
        let tx = conn.transaction().map_err(|_| unavailable())?;
        result_in(&tx, binding, operation)
    }
}

pub(crate) fn result_in(
    tx: &rusqlite::Connection,
    binding: &MountBinding,
    operation: &OperationHandle,
) -> Result<OperationResult, AccountError> {
    if operation.id <= 0
        || operation.instance != binding.instance
        || operation.issuer != binding.issuer
        || operation.subject != binding.subject
        || operation.space != binding.space
    {
        return Err(unavailable());
    }
    check_principal(tx, binding)?;
    let row: Option<(String, Option<String>, Option<String>, bool, Option<String>, Option<String>)> = tx.query_row(
            "SELECT state,confirmed_file_id,confirmed_etag,EXISTS(SELECT 1 FROM upload_verifications WHERE operation_id=j.id) OR EXISTS(SELECT 1 FROM mutation_receipts WHERE operation_id=j.id),base_file_id,base_etag FROM operation_journal j WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type=?5 AND staged_file=?6 AND (SELECT digest FROM dirty_roots WHERE root=j.staged_file) IS ?7 AND (SELECT destination FROM directory_moves WHERE operation_id=j.id) IS ?8",
            params![operation.id,operation.instance,operation.space,encode(&operation.path)?,operation.kind,operation.token,operation.manifest_digest,operation.destination],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).optional().map_err(|_| unavailable())?;
    let (state, id, etag, verification_pending, base_id, base_etag) =
        row.ok_or_else(unavailable)?;
    if base_id != operation.base_id || base_etag != operation.base_etag {
        let removal_rebase = operation.kind=="rmdir" && base_id==operation.base_id
                && tx.query_row("SELECT EXISTS(SELECT 1 FROM removal_versions a JOIN removal_versions b ON a.operation_id=b.operation_id WHERE a.operation_id=?1 AND a.etag=?2 AND b.etag=?3)",
                    params![operation.id,operation.base_etag,base_etag],|r|r.get::<_,bool>(0)).map_err(|_|unavailable())?;
        if !removal_rebase {
            // The engine can advance a waiting successor's PUT precondition only
            // from its exact predecessor's verified upload. Retain that relation
            // in the handle even after write_dependencies is retired.
            let predecessor = operation.predecessor.ok_or_else(unavailable)?;
            if operation.kind != "write"
                || operation.base_id.is_some()
                || operation.base_etag.is_some()
            {
                return Err(unavailable());
            }
            let encoded: String = tx.query_row(
                "SELECT v.version FROM verified_uploads v JOIN operation_journal j ON j.id=v.operation_id WHERE j.id=?1 AND j.instance=?2 AND j.space=?3 AND j.path=?4 AND j.op_type='write' AND j.state='synced' AND j.confirmed_file_id=?5 AND j.confirmed_etag=?6",
                params![predecessor,operation.instance,operation.space,encode(&operation.path)?,base_id,base_etag],
                |row| row.get(0),
            ).map_err(|_| unavailable())?;
            let verified: FileVersion =
                serde_json::from_str(&encoded).map_err(|_| unavailable())?;
            if verified.instance != operation.instance
                || verified.space != operation.space
                || verified.path != operation.path
                || Some(&verified.id) != base_id.as_ref()
                || Some(&verified.etag) != base_etag.as_ref()
                || !dav::valid_remote_id(&verified.id)
                || !dav::strong_etag(&verified.etag)
            {
                return Err(unavailable());
            }
        }
    }
    match state.as_str() {
        "pending" => Ok(OperationResult::Pending),
        "conflict" => Ok(OperationResult::Conflict),
        "uncertain" => {
            if verification_pending
                && matches!(
                    operation.kind.as_str(),
                    "mkdir" | "unlink" | "rmdir" | "move-source" | "move-dir-source"
                )
            {
                offline::namespace_receipt::load(
                    &binding.root,
                    tx,
                    &binding.instance,
                    (&binding.issuer, &binding.subject),
                    operation.id,
                    offline::namespace_receipt::Phase::Pending,
                )
                .map_err(|_| unavailable())?;
            }
            Ok(OperationResult::Uncertain {
                verification_pending,
            })
        }
        "resolved" => Ok(OperationResult::Resolved),
        "synced" if operation.kind == "write" => {
            let (digest, encoded): (String, String) = tx
                .query_row(
                    "SELECT digest,version FROM verified_uploads WHERE operation_id=?1",
                    [operation.id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| unavailable())?;
            let version: FileVersion = serde_json::from_str(&encoded).map_err(|_| unavailable())?;
            if version.instance != operation.instance
                || version.space != operation.space
                || version.path != operation.path
                || Some(&version.id) != id.as_ref()
                || Some(&version.etag) != etag.as_ref()
                || !dav::valid_remote_id(&version.id)
                || !dav::strong_etag(&version.etag)
                || digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(unavailable());
            }
            Ok(OperationResult::ConfirmedWrite { version, digest })
        }
        // Only the executor's receipt/read-back path transitions namespace
        // operations to synced. A resolved local acknowledgement cannot.
        "synced"
            if matches!(
                operation.kind.as_str(),
                "mkdir" | "unlink" | "rmdir" | "move-source" | "move-dir-source" | "move-tree"
            ) =>
        {
            let proof: Option<(String,String)> = tx.query_row(
                    "SELECT kind,snapshot FROM mutation_receipts WHERE operation_id=?1 AND kind IN ('namespace-verified','tree-verified')",
                    [operation.id], |r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|unavailable())?;
            let Some((kind, snapshot)) = proof else {
                let absent:bool=tx.query_row("SELECT error_msg IS 'target already absent' FROM operation_journal WHERE id=?1",[operation.id],|r|r.get(0)).map_err(|_|unavailable())?;
                return if absent {
                    Ok(OperationResult::ObservedAbsent)
                } else {
                    Err(unavailable())
                };
            };
            if kind == "namespace-verified" {
                let receipt = offline::namespace_receipt::load(
                    &binding.root,
                    tx,
                    &binding.instance,
                    (&binding.issuer, &binding.subject),
                    operation.id,
                    offline::namespace_receipt::Phase::Verified,
                )
                .map_err(|_| unavailable())?;
                let proof = receipt.operation();
                if proof.id != operation.id
                    || proof.space != operation.space
                    || proof.path != operation.path
                    || proof.kind != operation.kind
                    || proof.token != operation.token
                    || proof.base_id != base_id
                    || proof.base_etag != base_etag
                {
                    return Err(unavailable());
                }
            } else {
                let proof: offline::TreeMove =
                    serde_json::from_str(&snapshot).map_err(|_| unavailable())?;
                if proof.id != operation.id
                    || proof.space != operation.space
                    || proof.source != operation.path
                    || operation.kind != "move-tree"
                    || Some(encode(&proof.destination)?) != operation.destination
                    || Some(proof.entry.id()) != operation.base_id.as_deref()
                    || proof.entry.etag() != operation.base_etag.as_deref()
                {
                    return Err(unavailable());
                }
            }
            Ok(OperationResult::ConfirmedNamespace)
        }
        _ => Err(unavailable()),
    }
}
fn encode<T: Serialize>(value: &T) -> Result<String, AccountError> {
    serde_json::to_string(value).map_err(|_| unavailable())
}
fn unavailable() -> AccountError {
    AccountError::new("exact operation result unavailable; local data retained")
}
fn check_principal(
    conn: &rusqlite::Connection,
    binding: &MountBinding,
) -> Result<(), AccountError> {
    let valid: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM account_identities WHERE instance=?1 AND issuer=?2 AND subject=?3)",
        params![binding.instance,binding.issuer,binding.subject], |row| row.get(0),
    ).map_err(|_| unavailable())?;
    if valid { Ok(()) } else { Err(unavailable()) }
}

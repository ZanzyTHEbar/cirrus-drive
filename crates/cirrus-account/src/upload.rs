//! Bounded GET-only continuation of a durably acknowledged upload.

use std::time::{Duration, Instant};

use crate::{
    AccountError, Accounts, DirectoryIdentity, DirectorySnapshot, FileVersion, ReadSession, dav,
    offline,
};

// Unlike ordinary preflight, a verification request cannot retry behind the
// transfer budget. Keep the same fenced snapshot publication on its one attempt.
fn directory(
    session: &ReadSession,
    space: &str,
    path: &[String],
) -> Result<DirectorySnapshot, AccountError> {
    let observation = offline::begin_snapshot().map_err(|mut error| {
        error.retryable_read = true;
        error
    })?;
    let entries = dav::directory_snapshot_once(
        &session.base,
        space,
        path,
        &session.account.access_token,
        &session.client,
    )?;
    offline::save_directory_snapshot(observation, session.base.as_str(), space, path, &entries)
        .map_err(|mut error| {
            // The GET succeeded; failure to persist its local observation is
            // not evidence against the already successful PUT receipt.
            error.retryable_read = true;
            error
        })?;
    Ok(entries)
}

/// Outcome of one explicitly requested write transfer turn, not whole-Space sync status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WriteTurnOutcome {
    /// No unresolved work remains in the requested Space.
    Idle,
    /// Progress was made or a transfer budget expired; call again to continue.
    Yielded,
    /// Namespace or conflict-copy work needs the ordinary explicit sync executor.
    Dependencies,
    /// A conflict, rejected upload or ambiguous outcome needs user attention.
    Attention,
    /// A read-only request or local continuation checkpoint failed; retry is safe.
    Retry,
}

struct Budget {
    started: Instant,
    requests: u8,
}

impl Budget {
    fn admit(&mut self) -> bool {
        if crate::executor::preflight_checkpoint().is_err() {
            return false;
        }
        if self.requests == 8 || self.started.elapsed() >= Duration::from_secs(5) {
            return false;
        }
        self.requests += 1;
        crate::executor::mark_progress();
        true
    }
}

impl Accounts {
    pub(super) fn prepare_dirty_snapshot(
        &self,
        session: &ReadSession,
        data: &offline::StagedSnapshot,
        bounded: bool,
    ) -> Result<bool, AccountError> {
        data.prepare(
            |version, offset, length| self.capture_original_range(session, version, offset, length),
            bounded,
        )
    }

    // Local original bytes are sufficient to prepare a PUT, but do not prove
    // that an incoming rename's outside source still has its recorded version.
    pub(super) fn verify_incoming_file_source(
        &self,
        session: &ReadSession,
        operation: &offline::PendingWrite,
    ) -> Result<(), AccountError> {
        let Some(source) = offline::incoming_file_source(session.base.as_str(), operation)? else {
            return Ok(());
        };
        let (name, parent) = source
            .version
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid incoming source path"))?;
        let matches = self.verify_parent_identities(
            session,
            &operation.space,
            &source.version.path,
            &source.parents,
        )? && self
            .sync_directory_snapshot(session, &operation.space, parent)?
            .get(name)?
            .is_some_and(|entry| {
                !entry.is_directory()
                    && entry.id() == source.version.id
                    && entry.etag() == Some(source.version.etag.as_str())
                    && entry.size() == Some(source.version.size)
                    && entry.checksums() == source.version.checksums
            });
        if !matches {
            offline::set_write_state(
                session.base.as_str(),
                operation,
                "pending",
                "conflict",
                Some("incoming rename original source changed; no PUT sent"),
            )?;
            return Err(AccountError::new(
                "incoming rename original source changed; local data retained",
            ));
        }
        Ok(())
    }

    fn capture_original_range(
        &self,
        session: &ReadSession,
        version: &FileVersion,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, AccountError> {
        self.check_cancelled()?;
        if version.instance != session.base.as_str() {
            return Err(AccountError::new("original content account changed"));
        }
        if let Some(bytes) = self.read_original_local_range(
            &session.account.issuer,
            &session.account.subject,
            version,
            offset,
            length,
        )? {
            return Ok(bytes);
        }
        let (path, fenced) =
            offline::tree_remote_path(&version.instance, &version.space, &version.path)?;
        if fenced {
            return Err(AccountError::new(
                "original content locator requires attention",
            ));
        }
        let mut remote = version.clone();
        remote.path = path;
        let (name, parent) = remote
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid original content locator"))?;
        // Participate in resumable read-only preflight: slow metadata must not
        // permanently starve the conditional original-version range request.
        let entries = self.sync_directory_snapshot(session, &remote.space, parent)?;
        if !entries.get(name)?.is_some_and(|entry| {
            !entry.is_directory()
                && entry.id() == remote.id
                && entry.etag() == Some(remote.etag.as_str())
                && entry.size() == Some(remote.size)
                && entry.checksums() == remote.checksums
        }) {
            return Err(AccountError::new(
                "exact original content base is unavailable; local data retained",
            ));
        }
        if crate::executor::active() {
            crate::executor::admit(self)?;
        }
        dav::read_range(
            &session.base,
            &remote,
            offset,
            offset + u64::from(length) - 1,
            &session.account.access_token,
            &session.client,
        )
    }

    pub(super) fn protect_dirty_bases(
        &self,
        session: &ReadSession,
        space: &str,
        path: &[String],
        bounded: bool,
    ) -> Result<bool, AccountError> {
        let names = offline::overlay::protected_bases(session.base.as_str(), space, path)?;
        let mut originals = std::collections::BTreeMap::new();
        for name in &names {
            let root = offline::overlay::Overlay::load(name)?;
            if !offline::overlay::prepare_base(
                &root,
                |version, offset, length| {
                    self.capture_original_range(session, version, offset, length)
                },
                bounded,
            )? {
                return Ok(false);
            }
            root.add_required_originals(&mut originals)?;
        }
        #[cfg(feature = "fault-injection")]
        if !originals.is_empty() {
            crate::wait_test_window("CIRRUS_TEST_DIRTY_PROTECTED_WINDOW")?;
        }
        offline::overlay::verify_protected(&names, &originals, bounded)
    }

    /// Advances one successful upload using at most eight verification HTTP requests.
    /// Admission stops after five seconds; an admitted request retains the 15s timeout.
    fn verify_upload_step(
        &self,
        session: &ReadSession,
        verification: &mut offline::UploadVerification,
    ) -> Result<bool, AccountError> {
        let operation = &verification.operation;
        let data = offline::StagedSnapshot::open(&operation.staged)?;
        if data.len() != verification.size {
            return Err(AccountError::new(
                "staged upload digest changed; outcome remains uncertain",
            ));
        }
        // Payload blocks are verified as consumed. A separate bounded whole-
        // source pass below also checks prefixes verified in earlier processes.
        let mut budget = Budget {
            started: Instant::now(),
            requests: 0,
        };
        let (name, parent) = operation
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid upload path"))?;
        // This observation is a durable stage, not mandatory overhead on every
        // turn. Even a successful request longer than the admission window must
        // advance work. Ranges remain conditional on this exact version, and a
        // fresh final listing below is required before confirmation.
        let version = if let Some(version) = &verification.version {
            if version.instance != session.base.as_str()
                || version.space != operation.space
                || version.path != operation.path
                || version.size != verification.size
            {
                return Err(AccountError::new(
                    "invalid persisted upload version; outcome remains uncertain",
                ));
            }
            version.clone()
        } else {
            self.check_cancelled()?;
            if !budget.admit() {
                return Ok(false);
            }
            let entries = directory(session, &operation.space, parent)?;
            let entry = entries
                .get(name)?
                .filter(|entry| !entry.is_directory() && entry.size() == Some(verification.size))
                .ok_or_else(|| {
                    AccountError::new(
                        "uploaded file is missing or changed; outcome remains uncertain",
                    )
                })?;
            let version = FileVersion {
                instance: session.base.to_string(),
                space: operation.space.clone(),
                path: operation.path.clone(),
                id: entry.id().to_owned(),
                etag: entry
                    .etag()
                    .ok_or_else(|| AccountError::new("uploaded file lacks a strong ETag"))?
                    .to_owned(),
                size: verification.size,
                checksums: entry.checksums().to_vec(),
            };
            verification.version = Some(version.clone());
            verification.save(session.base.as_str())?;
            version
        };
        let mut hash_budget = 1024 * 1024;
        while verification.offset < verification.size {
            self.check_cancelled()?;
            let (length, cost) = data.bounded_range(
                verification.offset,
                (verification.size - verification.offset).min(131_072) as u32,
                hash_budget,
            )?;
            if length == 0 {
                return Ok(false);
            }
            if !budget.admit() {
                return Ok(false);
            }
            let bytes = dav::read_range(
                &session.base,
                &version,
                verification.offset,
                verification.offset + u64::from(length) - 1,
                &session.account.access_token,
                &session.client,
            )?;
            if bytes != data.range(verification.offset, length)? {
                return Err(AccountError::new(
                    "uploaded content could not be verified; outcome remains uncertain",
                ));
            }
            verification.offset += u64::from(length);
            hash_budget -= cost;
            verification.save(session.base.as_str())?;
        }
        // Deep parent chains also yield; a turn must not become unbounded after
        // its last data range. Server-side races between observations remain.
        while verification.parent_index < operation.parents.len() {
            self.check_cancelled()?;
            if !budget.admit() {
                return Ok(false);
            }
            let index = verification.parent_index;
            let expected = match &operation.parents[index] {
                DirectoryIdentity::Remote(id) if dav::valid_remote_id(id) => id.clone(),
                DirectoryIdentity::Pending(id) => {
                    let confirmed = offline::confirmed_directory(session.base.as_str(), *id)?
                        .ok_or_else(|| {
                            AccountError::new("parent directory creation is not confirmed")
                        })?;
                    if confirmed.space != operation.space
                        || confirmed.path != operation.path[..=index]
                    {
                        return Err(AccountError::new("parent identity changed after upload"));
                    }
                    confirmed.id
                }
                _ => return Err(AccountError::new("invalid parent identity chain")),
            };
            let entries = directory(session, &operation.space, &operation.path[..index])?;
            if !entries
                .get(&operation.path[index])?
                .is_some_and(|entry| entry.is_directory() && entry.id() == expected)
            {
                return Err(AccountError::new(
                    "parent identity changed after upload; outcome remains uncertain",
                ));
            }
            verification.parent_index += 1;
            verification.save(session.base.as_str())?;
        }
        self.check_cancelled()?;
        let Some(digest) = data.digest_step("successful-upload-final")? else {
            return Ok(false);
        };
        if digest != verification.digest {
            return Err(AccountError::new(
                "staged upload digest changed; outcome remains uncertain",
            ));
        }
        if !budget.admit() {
            return Ok(false);
        }
        let after = directory(session, &operation.space, parent)?;
        if !after.get(name)?.is_some_and(|entry| {
            entry.id() == version.id
                && entry.etag() == Some(version.etag.as_str())
                && entry.size() == Some(version.size)
        }) {
            return Err(AccountError::new(
                "uploaded file changed during verification; outcome remains uncertain",
            ));
        }
        offline::confirm_write(session.base.as_str(), operation, &version)?;
        Ok(true)
    }

    pub(super) fn advance_upload(
        &self,
        session: &ReadSession,
        verification: &mut offline::UploadVerification,
        bounded: bool,
    ) -> Result<WriteTurnOutcome, AccountError> {
        loop {
            match self.verify_upload_step(session, verification) {
                Ok(true) => return Ok(WriteTurnOutcome::Yielded),
                Ok(false) if bounded => return Ok(WriteTurnOutcome::Yielded),
                Ok(false) => {}
                Err(error) => {
                    // Shutdown is resumable. A real verification failure loses
                    // automatic continuation, but never the uncertain journal.
                    self.check_cancelled()?;
                    if error.unauthorized {
                        // A rejected read says nothing about the successful
                        // PUT. Retain exact receipt/version/progress, and let
                        // the caller refresh only after closing this turn.
                        return Err(error);
                    }
                    if error.can_retry_read() || error.is_staging_full() {
                        // Read-only DAV processing may itself need admitted
                        // namespace scratch before directory() can persist an
                        // observation. Local capacity is not contrary evidence
                        // about this successful PUT; preserve its receipt.
                        return Ok(WriteTurnOutcome::Retry);
                    }
                    verification.discard()?;
                    offline::set_write_state(
                        session.base.as_str(),
                        &verification.operation,
                        "uncertain",
                        "uncertain",
                        Some(error.message),
                    )?;
                    return Ok(WriteTurnOutcome::Attention);
                }
            }
        }
    }
}

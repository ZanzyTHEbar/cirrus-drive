//! Persistent activation, retry admission and local-only Space sync observations.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{
    AccountError, Accounts, MountBinding, ReadSession, WriteTurnOutcome, executor, offline,
};

#[cfg(feature = "fault-injection")]
pub(crate) fn trace_automatic(event: &str) {
    static EVENTS: AtomicUsize = AtomicUsize::new(0);
    if std::env::var_os("CIRRUS_TEST_AUTO_DIAGNOSTICS").is_some()
        && EVENTS.fetch_add(1, Ordering::Relaxed) < 2048
    {
        eprintln!(
            "cirrus lab auto diagnostic: time_ms={} pid={} native={:?} thread={:?} {event}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            std::process::id(),
            std::fs::read_link("/proc/thread-self").ok(),
            std::thread::current().id()
        );
    }
}

#[derive(Default)]
pub(crate) struct BackgroundAdmission {
    requests: AtomicUsize,
    paused: AtomicBool,
}

impl BackgroundAdmission {
    pub(crate) fn requested(&self) -> bool {
        self.paused.load(Ordering::Acquire) || self.requests.load(Ordering::Acquire) != 0
    }
}

/// Scoped foreground priority. Dropping one owner cannot release another owner
/// or the independent shutdown pause. Cleanup needs no admission/account lock.
pub struct ForegroundPriority(Arc<BackgroundAdmission>);

impl Drop for ForegroundPriority {
    fn drop(&mut self) {
        let previous = self.0.requests.fetch_sub(1, Ordering::AcqRel);
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_PRIORITY_TRACE").is_some() {
            eprintln!(
                "cirrus lab priority released: remaining={} paused={}",
                previous - 1,
                self.0.paused.load(Ordering::Acquire)
            );
        }
        #[cfg(not(feature = "fault-injection"))]
        let _ = previous;
    }
}

/// Current local scheduling observation, never a global or remote cleanliness claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncPhase {
    Queued,
    Uploading,
    Verifying,
    Retry,
    Attention,
    ObservedIdle,
}

/// Bounded local-only status for one persistently activated immutable Space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Canonical instance URL for this observation.
    pub instance: String,
    /// Immutable Space ID, independent of selection.
    pub space: String,
    /// Whether a verified mount durably activated this Space.
    pub activated: bool,
    /// Whether the responding daemon runs its automatic worker; absent in account-only calls.
    pub worker_enabled_here: Option<bool>,
    /// Current local scheduling observation, not remote reconciliation status.
    pub phase: SyncPhase,
    /// Pending journal operations, including dependency waiters.
    pub queued: u64,
    /// Live PUTs owned by this daemon; other-daemon unconfirmed PUTs stay conservative.
    pub uploading: u64,
    /// Successful mutation receipts awaiting read-only verification.
    pub verifying: u64,
    /// Unknown mutation outcomes without a successful receipt.
    pub uncertain: u64,
    /// Journaled conflicts requiring inspection.
    pub conflicts: u64,
    /// Invalid journal entries or missing/mismatched local activation identity.
    pub damaged: u64,
    /// Consecutive safe-read/local-capacity retry attempts, capped at 16.
    pub retry_attempt: u32,
    /// Earliest admitted retry, in Unix seconds; an expired value is not proof it ran.
    pub next_attempt: Option<i64>,
    /// Safe-to-display reason; scheduler policy never parses this string.
    pub cause: Option<String>,
    /// Unix seconds of the most recently verified journal operation, historical only.
    pub last_verified: Option<i64>,
    /// Highest currently observed journal ID in this Space.
    pub high_water: i64,
    /// Journal ID observed through a locally idle pass, not a remote consistency watermark.
    pub verified_through: i64,
    /// Local unresolved work or journal growth since that idle observation.
    pub new_work: bool,
}

pub(crate) fn now() -> Result<i64, AccountError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|_| AccountError::new("system clock is invalid"))
}

pub(crate) fn phase(instance: &str, space: &str, phase: SyncPhase) -> Result<(), AccountError> {
    offline::database()?
        .execute(
            "UPDATE sync_spaces SET phase=?3 WHERE instance=?1 AND space=?2",
            params![instance, space, format!("{phase:?}")],
        )
        .map_err(|_| AccountError::new("cannot publish Space sync phase"))?;
    Ok(())
}

pub(crate) fn verified(instance: &str, space: Option<&str>) -> Result<(), AccountError> {
    offline::database()?.execute("UPDATE sync_spaces SET last_verified=?3 WHERE instance=?1 AND (?2 IS NULL OR space=?2)",params![instance,space,now()?])
        .map_err(|_| AccountError::new("cannot record verified mutation time"))?;
    Ok(())
}

// Manual sync can finish a queue while its automatic dispatcher is disabled.
// Publish local idle/retire obsolete scheduling, not attention or mutation evidence.
// The single statement rechecks each Space at publication: a concurrently
// queued edit must prevent advancing its idle watermark.
pub(crate) fn manual_idle(instance: &str, space: Option<&str>) -> Result<(), AccountError> {
    offline::database()?.execute(
        "UPDATE sync_spaces AS s SET phase='ObservedIdle',failures=0,next_at=0,cause=NULL,verified_through=COALESCE((SELECT max(j.id) FROM operation_journal j WHERE j.instance=s.instance AND j.space=s.space),0)
         WHERE s.instance=?1 AND (?2 IS NULL OR s.space=?2) AND s.phase IN ('Queued','Retry','ObservedIdle','Uploading','Verifying')
           AND EXISTS(SELECT 1 FROM account_identities a WHERE a.instance=s.instance AND a.issuer=s.issuer AND a.subject=s.subject)
           AND NOT EXISTS(SELECT 1 FROM operation_journal j WHERE j.instance=s.instance AND j.space=s.space AND (j.state IS NULL OR j.state NOT IN ('synced','resolved') OR j.error_msg GLOB 'local publication recovery:*'))",
        params![instance,space],
    ).map_err(|_| AccountError::new("cannot publish completed manual sync status"))?;
    Ok(())
}

pub(crate) fn dependency_confirmed(instance: &str, id: i64) -> Result<bool, AccountError> {
    offline::database()?.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND id=?2 AND state='synced')",params![instance,id],|row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect rename dependency state"))
}

pub(crate) fn pending_tree(
    instance: &str,
    space: &str,
) -> Result<Option<offline::TreeMove>, AccountError> {
    let id: Option<i64> = offline::database()?.query_row("SELECT min(id) FROM operation_journal WHERE instance=?1 AND space=?2 AND op_type='move-tree' AND state='pending'",params![instance,space],|row| row.get(0)).map_err(|_| AccountError::new("cannot inspect pending tree move"))?;
    if let Some(id) = id {
        Ok(offline::tree_move_page(instance, Some(space), id - 1, id)?
            .into_iter()
            .next())
    } else {
        Ok(None)
    }
}

pub(crate) fn has_attention(instance: &str, space: &str) -> Result<bool, AccountError> {
    offline::database()?.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal j WHERE instance=?1 AND space=?2 AND (state='conflict' OR (state='uncertain' AND NOT EXISTS(SELECT 1 FROM upload_verifications v WHERE v.operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM mutation_receipts r WHERE r.operation_id=j.id))))",params![instance,space],|row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect ambiguous operations"))
}

pub(crate) fn check_identity(session: &ReadSession, space: &str) -> Result<(), AccountError> {
    let expected: Option<(String, String)> = offline::database()?
        .query_row(
            "SELECT issuer,subject FROM sync_spaces WHERE instance=?1 AND space=?2",
            params![session.base.as_str(), space],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| AccountError::new("cannot inspect activated Space identity"))?;
    if expected.as_ref().is_none_or(|(issuer, subject)| {
        *issuer != session.account.issuer || *subject != session.account.subject
    }) {
        return Err(AccountError::new(
            "activated Space account identity differs; local data retained",
        ));
    }
    Ok(())
}

fn stamp(status: &SyncStatus) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        status.high_water,
        status.queued,
        status.verifying,
        status.uncertain,
        status.conflicts,
        status.damaged
    )
}

impl Accounts {
    /// Activates automatic synchronization using a verified immutable mount binding.
    ///
    /// # Errors
    /// Returns an error for changed identity, unsafe state, the 64-Space bound
    /// or new-row storage pressure. Commit/close failure has unknown outcome;
    /// inspect persisted status rather than assuming activation rolled back.
    pub fn activate_sync(&self, binding: &MountBinding) -> Result<(), AccountError> {
        let session = self.read_session(&binding.instance)?;
        let _guard = self.begin_local_operation(&session, false)?;
        if binding.issuer != session.account.issuer || binding.subject != session.account.subject {
            return Err(AccountError::new(
                "mount identity differs; automatic activation refused",
            ));
        }
        offline::bind_identity(&binding.instance, &binding.issuer, &binding.subject)?;
        let reservation;
        let mut conn = offline::database()?;
        let planning_version: i64 = conn
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect activation plan"))?;
        let planned_new: bool = !conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sync_spaces WHERE instance=?1 AND space=?2)",
                params![binding.instance, binding.space],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| AccountError::new("cannot inspect sync activation"))?;
        let planned = if planned_new && crate::storage::limits::view()?.limits.is_some() {
            serde_json::to_vec(&(
                &binding.instance,
                &binding.space,
                &binding.issuer,
                &binding.subject,
                "Queued",
                0_i64,
                0_i64,
                Option::<String>::None,
                Option::<i64>::None,
                0_i64,
                Option::<String>::None,
            ))
            .map_err(|_| AccountError::new("cannot size Space activation"))?
            .len() as u64
        } else {
            0
        };
        // Reactivation resets existing control state and must remain possible
        // under pressure. Only a new activation acquires State admission.
        #[cfg(feature = "fault-injection")]
        if !planned_new {
            crate::wait_test_window("CIRRUS_TEST_ACTIVATION_EXISTING_WINDOW")?;
        }
        #[cfg(feature = "fault-injection")]
        if planned_new {
            crate::wait_test_window("CIRRUS_TEST_ACTIVATION_ADMISSION_WINDOW")?;
        }
        reservation = if planned_new {
            crate::storage::sql_reservation::SqlReservation::begin(
                crate::storage::sql_reservation::Store::State,
                Some(&conn),
                planned,
                0,
                false,
            )?
        } else {
            None
        };
        if let Some(reservation) = &reservation {
            reservation.bound_pages(&conn)?;
        }
        #[cfg(feature = "fault-injection")]
        if planned_new {
            crate::wait_test_window("CIRRUS_TEST_ACTIVATION_RESERVED_WINDOW")?;
        }
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| {
                offline::sqlite_storage_error(error, "cannot begin sync activation")
            })?;
        if reservation.is_some() {
            let current: i64 = tx
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| AccountError::new("cannot inspect activation plan"))?;
            if current != planning_version {
                return Err(AccountError::new(
                    "activation plan changed; local state retained; retry mount",
                ));
            }
        }
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT issuer,subject FROM sync_spaces WHERE instance=?1 AND space=?2",
                params![binding.instance, binding.space],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| AccountError::new("cannot inspect sync activation"))?;
        let inserted = existing.is_none();
        if let Some((issuer, subject)) = existing {
            if issuer != binding.issuer || subject != binding.subject {
                return Err(AccountError::new(
                    "activation identity differs; local state retained",
                ));
            }
            tx.execute("UPDATE sync_spaces SET phase='Queued',failures=0,next_at=0,cause=NULL,attention_stamp=NULL WHERE instance=?1 AND space=?2",params![binding.instance,binding.space]).map_err(|_| AccountError::new("cannot reactivate Space sync"))?;
        } else {
            // A concurrent removal of an existing activation must not turn an
            // uncapped reactivation into a new allocation under enabled policy.
            if reservation.is_none() && crate::storage::limits::view()?.limits.is_some() {
                return Err(AccountError::new(crate::storage::limits::PRESSURE));
            }
            let count: i64 = tx
                .query_row("SELECT count(*) FROM sync_spaces", [], |row| row.get(0))
                .map_err(|_| AccountError::new("cannot inspect activation capacity"))?;
            if count >= 64 {
                return Err(AccountError::new(
                    "automatic Space activation limit reached",
                ));
            }
            tx.execute("INSERT INTO sync_spaces(instance,space,issuer,subject,phase,failures,next_at,cause,last_verified,verified_through,attention_stamp) VALUES(?1,?2,?3,?4,'Queued',0,0,NULL,NULL,0,NULL)",params![binding.instance,binding.space,binding.issuer,binding.subject]).map_err(|error| offline::sqlite_storage_error(error, "cannot persist Space activation"))?;
        }
        #[cfg(feature = "fault-injection")]
        if inserted {
            crate::wait_test_window("CIRRUS_TEST_ACTIVATION_COMMIT_WINDOW")?;
        }
        if inserted {
            if let Some(reservation) = &reservation {
                reservation.validate(&tx)?;
            } else if crate::storage::limits::view()?.limits.is_some() {
                return Err(AccountError::new(crate::storage::limits::PRESSURE));
            }
        }
        let committed = tx.commit();
        conn.close().map_err(|_| {
            AccountError::new(
                "cannot close Space activation database; outcome unknown; local state retained",
            )
        })?;
        committed.map_err(|_| {
            AccountError::new(
                "cannot commit Space activation; outcome unknown; local state retained",
            )
        })
    }

    /// Elects one automatic dispatcher across cooperating daemons, without
    /// retaining transfer/account ownership between turns or excluding explicit sync.
    ///
    /// # Errors
    /// Returns an error for unsupported state, unsafe paths or another dispatcher.
    pub fn acquire_scheduler(&self) -> Result<std::os::fd::OwnedFd, AccountError> {
        let _supported = offline::database()?;
        crate::ownership::acquire_scheduler()
    }

    /// Enumerates at most 64 local activations without reading credentials or mounting.
    ///
    /// # Errors
    /// Returns an error for unsupported or unreadable local state.
    pub fn activated_spaces(&self) -> Result<Vec<(String, String)>, AccountError> {
        let conn = offline::database()?;
        let mut statement = conn
            .prepare("SELECT instance,space FROM sync_spaces ORDER BY instance,space LIMIT 64")
            .map_err(|_| AccountError::new("cannot inspect activated Spaces"))?;
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|_| AccountError::new("cannot read activated Spaces"))?
            .collect::<Result<_, _>>()
            .map_err(|_| AccountError::new("invalid activated Space"))
    }

    /// Reports one Space's local queue and retry observations without network/keyring access.
    /// Counts may scan retained history; output size, not local I/O time, is bounded.
    ///
    /// # Errors
    /// Returns an error for invalid input, unsupported schema or damaged state.
    pub fn sync_status(&self, instance: &str, space: &str) -> Result<SyncStatus, AccountError> {
        let instance = Self::canonical_instance(instance)?;
        if space.is_empty() || space.chars().any(char::is_control) {
            return Err(AccountError::new("invalid Space ID"));
        }
        let conn = offline::database()?;
        type Saved = (
            String,
            u32,
            i64,
            Option<String>,
            Option<i64>,
            i64,
            Option<String>,
        );
        let saved: Option<Saved> = conn.query_row("SELECT phase,failures,next_at,cause,last_verified,verified_through,attention_stamp FROM sync_spaces WHERE instance=?1 AND space=?2",params![instance,space],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).optional().map_err(|_| AccountError::new("cannot inspect Space sync status"))?;
        let (queued,verifying,uncertain,conflicts,high_water): (u64,u64,u64,u64,i64) = conn.query_row("SELECT COALESCE(sum(state='pending'),0),COALESCE(sum(state='uncertain' AND (EXISTS(SELECT 1 FROM upload_verifications v WHERE v.operation_id=j.id) OR EXISTS(SELECT 1 FROM mutation_receipts r WHERE r.operation_id=j.id))),0),COALESCE(sum(state='uncertain' AND NOT EXISTS(SELECT 1 FROM upload_verifications v WHERE v.operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM mutation_receipts r WHERE r.operation_id=j.id)),0),COALESCE(sum(state='conflict'),0),COALESCE(max(id),0) FROM operation_journal j WHERE instance=?1 AND space=?2",params![instance,space],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).map_err(|_| AccountError::new("cannot inspect Space queue counts"))?;
        let activated = saved.is_some();
        let mut damaged: u64 = conn.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND space=?2 AND (state IS NULL OR state NOT IN ('pending','synced','conflict','uncertain','resolved') OR (id<=0 AND state NOT IN ('synced','resolved')))",params![instance,space],|row| row.get(0)).map_err(|_| AccountError::new("cannot inspect damaged journal status"))?;
        let identity_ok: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sync_spaces s JOIN account_identities a ON a.instance=s.instance AND a.issuer=s.issuer AND a.subject=s.subject WHERE s.instance=?1 AND s.space=?2)",params![instance,space],|row| row.get(0)).map_err(|_| AccountError::new("cannot inspect local activated identity"))?;
        if activated && !identity_ok {
            damaged += 1;
        }
        let (
            saved_phase,
            retry_attempt,
            next,
            cause,
            last_verified,
            verified_through,
            attention_stamp,
        ) = saved.unwrap_or_else(|| ("Queued".into(), 0, 0, None, None, 0, None));
        let active = self.active_writes.lock().map_err(|_| AccountError::new("upload status unavailable"))?.iter().any(|id| conn.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal j WHERE id=?1 AND instance=?2 AND space=?3 AND state='uncertain' AND NOT EXISTS(SELECT 1 FROM upload_verifications v WHERE v.operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM mutation_receipts r WHERE r.operation_id=j.id))",params![id,instance,space],|row| row.get::<_,bool>(0)).unwrap_or(false));
        let uploading = u64::from(active);
        let uncertain = uncertain.saturating_sub(uploading);
        let mut status = SyncStatus {
            instance,
            space: space.to_owned(),
            activated,
            worker_enabled_here: None,
            phase: SyncPhase::ObservedIdle,
            queued,
            uploading,
            verifying,
            uncertain,
            conflicts,
            damaged,
            retry_attempt,
            next_attempt: (next > 0).then_some(next),
            cause,
            last_verified,
            high_water,
            verified_through,
            new_work: queued > 0
                || uploading > 0
                || verifying > 0
                || uncertain > 0
                || conflicts > 0
                || damaged > 0
                || high_water > verified_through,
        };
        let local_publication: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND space=?2 AND error_msg GLOB 'local publication recovery:*')", params![status.instance,space], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect local publication status"))?;
        if local_publication {
            status.cause = Some("local publication requires recovery; reopen the file; no remote PUT uncertainty is asserted".into());
        }
        status.phase = if local_publication {
            SyncPhase::Attention
        } else if active {
            SyncPhase::Uploading
        } else if damaged > 0
            || conflicts > 0
            || uncertain > 0
            || (saved_phase == "Attention"
                && attention_stamp.as_deref() == Some(stamp(&status).as_str()))
        {
            SyncPhase::Attention
        } else if next > now()? {
            SyncPhase::Retry
        } else if verifying > 0 {
            SyncPhase::Verifying
        } else if queued > 0 {
            SyncPhase::Queued
        } else {
            SyncPhase::ObservedIdle
        };
        Ok(status)
    }

    /// Requests a background yield until this owner's guard is dropped.
    pub fn request_foreground(&self) -> ForegroundPriority {
        self.background_admission
            .requests
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .expect("foreground priority count exhausted");
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_PRIORITY_TRACE").is_some() {
            eprintln!(
                "cirrus lab priority requested: count={}",
                self.background_admission.requests.load(Ordering::Acquire)
            );
        }
        ForegroundPriority(std::sync::Arc::clone(&self.background_admission))
    }

    /// Independently pauses background admission for daemon shutdown/recovery.
    pub fn pause_background(&self, paused: bool) {
        self.background_admission
            .paused
            .store(paused, Ordering::Release);
    }

    /// Whether a foreground account/FUSE operation requested the next admission.
    pub fn background_yield_requested(&self) -> bool {
        self.background_admission.requested()
    }

    // Local namespace preparation needs exclusive ownership. It may wait for
    // this daemon's automatic turn, rather than spuriously returning EBUSY for
    // an ordinary rename. Explicit/cross-daemon contention keeps its old fence.
    pub(super) fn wait_for_automatic_turn(&self) -> Result<crate::Operation<'_>, AccountError> {
        let _priority = self.request_foreground();
        #[cfg(feature = "fault-injection")]
        crate::wait_test_window("CIRRUS_TEST_PRIORITY_WAIT_WINDOW")?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            self.check_cancelled()?;
            match self.operation.try_lock() {
                Ok(lock) => return self.operation_with_lock(lock),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(AccountError::new("account state is unavailable"));
                }
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(AccountError::retryable_read(
                    "automatic turn still owns account preparation; retry local operation",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Executes one automatic turn and reports useful progress for fair re-admission.
    /// Authentication/listing and local storage/hash work are not hard wall-clock bounded.
    ///
    /// # Errors
    /// Returns an error if local activation/status cannot be safely inspected or persisted.
    pub fn automatic_sync_turn(&self, instance: &str, space: &str) -> Result<bool, AccountError> {
        let before = self.sync_status(instance, space)?;
        if !before.activated || matches!(before.phase, SyncPhase::Retry | SyncPhase::Attention) {
            return Ok(false);
        }
        if before.phase == SyncPhase::ObservedIdle && !before.new_work {
            return Ok(false);
        }
        let _automatic = executor::automatic_guard(self);
        let progress = executor::progress_stamp();
        let result = self.sync_pending_in(instance, Some(space), executor::Mode::Automatic);
        #[cfg(feature = "fault-injection")]
        trace_automatic(&format!(
            "transfer space={space} result={result:?} foreground={} cancelled={}",
            self.background_yield_requested(),
            self.cancelled.load(Ordering::Acquire)
        ));
        if self.cancelled.load(Ordering::Acquire)
            || self.background_yield_requested()
            || result
                .as_ref()
                .is_ok_and(|outcome| *outcome == WriteTurnOutcome::Retry)
            || result.as_ref().is_err_and(AccountError::can_retry_read)
        {
            offline::database()?.execute("DELETE FROM sync_reads WHERE operation_id IN (SELECT id FROM operation_journal WHERE instance=?1 AND space=?2)",params![before.instance,space]).map_err(|_| AccountError::new("cannot invalidate interrupted metadata preflight"))?;
        }
        let after = self.sync_status(instance, space)?;
        let advanced = executor::progress_stamp() != progress || stamp(&before) != stamp(&after);
        let (phase,failures,next,cause,attention_stamp) = match result {
            Ok(WriteTurnOutcome::Idle) => (SyncPhase::ObservedIdle,0,0,None,None),
            Ok(WriteTurnOutcome::Yielded) => (if after.verifying>0 { SyncPhase::Verifying } else { SyncPhase::Queued },0,0,None,None),
            Ok(WriteTurnOutcome::Retry) => {
                let failures = before.retry_attempt.saturating_add(1).min(16);
                (SyncPhase::Retry,failures,now()?+(2_i64 << failures.min(5)).min(60),Some("safe verification read temporarily unavailable".to_owned()),None)
            }
            Ok(WriteTurnOutcome::Dependencies | WriteTurnOutcome::Attention) => (SyncPhase::Attention,0,0,Some("journal conflict, ambiguous outcome or unresolved dependency requires attention".into()),Some(stamp(&after))),
            // Capacity can return after original capture/preparation, not just
            // metadata reads. Do not latch an otherwise pending edit in Attention
            // after space is restored. Retry changes scheduling only: journal
            // claims and successful-response/unknown-outcome fences still apply.
            Err(error) if (error.can_retry_read() || error.is_staging_full()) && !error.upload_uncertain => {
                let failures = before.retry_attempt.saturating_add(1).min(16);
                (SyncPhase::Retry,failures,now()?+(2_i64 << failures.min(5)).min(60),Some(error.to_string()),None)
            }
            Err(error) if error.yielded || self.cancelled.load(Ordering::Acquire) || self.background_yield_requested() => return Ok(advanced),
            Err(error) => (SyncPhase::Attention,0,0,Some(error.to_string()),Some(stamp(&after))),
        };
        // A local writer can publish after the executor observed no eligible
        // work. Never advance the idle watermark across that newer queue.
        let idle = phase == SyncPhase::ObservedIdle
            && after.queued == 0
            && after.uploading == 0
            && after.verifying == 0
            && after.uncertain == 0
            && after.conflicts == 0
            && after.damaged == 0;
        offline::database()?.execute("UPDATE sync_spaces SET phase=?3,failures=?4,next_at=?5,cause=?6,attention_stamp=?7,verified_through=CASE WHEN ?8 THEN ?9 ELSE verified_through END WHERE instance=?1 AND space=?2",params![before.instance,space,format!("{phase:?}"),failures,next,cause,attention_stamp,idle,after.high_water]).map_err(|_| AccountError::new("cannot persist automatic sync result"))?;
        Ok(advanced)
    }
}

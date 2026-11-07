//! Serial, resumable operation turns. Read evidence never authorizes mutation replay.

use std::cell::{Cell, RefCell};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock, atomic::AtomicBool};
use std::time::{Duration, Instant};

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{
    AccountError, Accounts, ActiveWrite, DirectorySnapshot, Entry, FileVersion, ReadSession,
    WriteTurnOutcome, dav, offline, sync,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Manual,
    Write,
    Automatic,
}

// At most eight transfer requests per turn; an admitted request keeps its 15s
// timeout. Auth/listing and bounded local hashing are separate admission phases.
const REQUESTS: usize = 8;
const ADMISSION: Duration = Duration::from_secs(5);
const MAX_EVIDENCE: usize = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Observation {
    path: Vec<String>,
    self_version: (String, String),
    #[serde(with = "directory_evidence")]
    entries: DirectorySnapshot,
}

// Serialize/restore schema-14 child arrays in bounded windows rather than a Vec.
mod directory_evidence {
    use crate::{DirectorySnapshot, Entry, dav};
    use serde::{
        Deserializer, Serializer,
        de::{SeqAccess, Visitor},
        ser::SerializeSeq,
    };
    use std::fmt;

    pub(super) fn serialize<S: Serializer>(
        snapshot: &DirectorySnapshot,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        let mut after = 0;
        loop {
            let page = snapshot.page(after).map_err(serde::ser::Error::custom)?;
            if page.is_empty() {
                break;
            }
            for (cookie, entry) in page {
                sequence.serialize_element(&entry)?;
                after = cookie;
            }
        }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DirectorySnapshot, D::Error> {
        struct CompleteEntries;
        impl<'de> Visitor<'de> for CompleteEntries {
            type Value = DirectorySnapshot;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("complete directory read evidence")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut snapshot = DirectorySnapshot::empty().map_err(serde::de::Error::custom)?;
                while let Some(entry) = sequence.next_element::<Entry>()? {
                    if !dav::valid_remote_id(entry.id()) {
                        return Err(serde::de::Error::custom("invalid directory read identity"));
                    }
                    snapshot.insert(&entry).map_err(serde::de::Error::custom)?;
                }
                Ok(snapshot)
            }
        }
        deserializer.deserialize_seq(CompleteEntries)
    }
}

struct Turn {
    id: i64,
    operation: String,
    snapshot: String,
    phase: &'static str,
    reads: Vec<Observation>,
    requests: usize,
    started: Option<Instant>,
}

thread_local! { static TURN: RefCell<Option<Turn>> = const { RefCell::new(None) }; }
thread_local! { static AUTOMATIC: RefCell<Option<Arc<sync::BackgroundAdmission>>> = const { RefCell::new(None) }; }
thread_local! { static PROGRESS: Cell<u64> = const { Cell::new(0) }; }

pub(crate) fn progress_stamp() -> u64 {
    PROGRESS.with(Cell::get)
}

pub(crate) fn mark_progress() {
    PROGRESS.with(|progress| progress.set(progress.get().wrapping_add(1)));
}

pub(crate) struct AutomaticGuard(Arc<AtomicBool>);
impl Drop for AutomaticGuard {
    fn drop(&mut self) {
        AUTOMATIC.with(|flag| *flag.borrow_mut() = None);
        self.0.store(false, Ordering::Release);
    }
}
pub(crate) fn automatic_guard(accounts: &Accounts) -> AutomaticGuard {
    AUTOMATIC.with(|flag| *flag.borrow_mut() = Some(Arc::clone(&accounts.background_admission)));
    accounts.automatic_active.store(true, Ordering::Release);
    AutomaticGuard(Arc::clone(&accounts.automatic_active))
}
pub(crate) fn is_automatic() -> bool {
    AUTOMATIC.with(|flag| flag.borrow().is_some())
}
pub(crate) fn preflight_checkpoint() -> Result<(), AccountError> {
    if AUTOMATIC.with(|flag| flag.borrow().as_ref().is_some_and(|flag| flag.requested())) {
        Err(AccountError::yielded())
    } else {
        Ok(())
    }
}

struct TurnGuard;
impl Drop for TurnGuard {
    fn drop(&mut self) {
        TURN.with(|turn| *turn.borrow_mut() = None);
    }
}

pub(crate) fn active() -> bool {
    TURN.with(|turn| turn.borrow().is_some())
}

fn start(id: i64, snapshot: String, phase: &'static str) -> Result<TurnGuard, AccountError> {
    // A replacement scheduler must re-observe metadata after a crash, rather
    // than treating an old process's observations as fresh evidence.
    static EPOCH: OnceLock<String> = OnceLock::new();
    let epoch =
        EPOCH.get_or_init(|| format!("{}:{:?}", std::process::id(), std::time::SystemTime::now()));
    let operation = snapshot;
    let snapshot = format!("{epoch}:{operation}");
    let saved: Option<(String, String, String, i64)> = offline::database()?
        .query_row(
            "SELECT snapshot,phase,entries,updated_at FROM sync_reads WHERE operation_id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| AccountError::new("cannot load operation read progress"))?;
    let reads = match saved {
        Some((old, old_phase, entries, updated))
            if old == snapshot
                && old_phase == phase
                && sync::now()?.saturating_sub(updated) < 86_400 =>
        {
            if entries.len() > MAX_EVIDENCE {
                return Err(AccountError::new(
                    "operation read evidence exceeds its bound",
                ));
            }
            serde_json::from_str(&entries)
                .map_err(|_| AccountError::new("invalid operation read progress"))?
        }
        _ => Vec::new(),
    };
    TURN.with(|turn| {
        *turn.borrow_mut() = Some(Turn {
            id,
            operation,
            snapshot,
            phase,
            reads,
            requests: 0,
            started: None,
        })
    });
    Ok(TurnGuard)
}

pub(crate) fn admit(accounts: &Accounts) -> Result<(), AccountError> {
    accounts.check_cancelled()?;
    preflight_checkpoint()?;
    TURN.with(|turn| {
        let mut turn = turn.borrow_mut();
        let Some(turn) = turn.as_mut() else {
            return Ok(());
        };
        let started = turn.started.get_or_insert_with(Instant::now);
        if turn.requests >= REQUESTS || started.elapsed() >= ADMISSION {
            return Err(AccountError::yielded());
        }
        turn.requests += 1;
        Ok(())
    })?;
    mark_progress();
    Ok(())
}

pub(crate) fn directory(
    accounts: &Accounts,
    session: &ReadSession,
    space: &str,
    path: &[String],
) -> Result<DirectorySnapshot, AccountError> {
    accounts.check_cancelled()?;
    if let Some(entries) = TURN.with(|turn| {
        turn.borrow().as_ref().and_then(|turn| {
            turn.reads
                .iter()
                .find(|read| read.path == path)
                .map(|read| (read.entries.clone(), read.self_version.clone()))
        })
    }) {
        let (entries, (id, etag)) = entries;
        // Restored entry arrays do not carry their self metadata in scratch.
        // Rebuild a unique owner before returning the durable observation.
        let mut restored = DirectorySnapshot::empty()?;
        restored.set_remote_parent(&id, &etag)?;
        let mut after = 0;
        loop {
            let page = entries.page(after)?;
            if page.is_empty() {
                break;
            }
            for (cookie, entry) in page {
                restored.insert(&entry)?;
                after = cookie;
            }
        }
        return Ok(restored);
    }
    admit(accounts)?;
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
    )
    .map_err(|mut error| {
        if error.is_staging_full() {
            error.retryable_read = true;
        }
        error
    })?;
    offline::save_directory_snapshot(observation, session.base.as_str(), space, path, &entries)
        .map_err(|mut error| {
            error.retryable_read = true;
            error
        })?;
    TURN.with(|turn| {
        let mut turn = turn.borrow_mut();
        let turn = turn
            .as_mut()
            .ok_or_else(|| AccountError::new("operation turn is unavailable"))?;
        turn.reads.push(Observation {
            path: path.to_vec(),
            self_version: entries.remote_parent()?,
            entries: entries.clone(),
        });
        let saved = (|| {
            let encoded = serde_json::to_string(&turn.reads)
                .map_err(|_| AccountError::new("cannot encode operation read progress"))?;
            if encoded.len() > MAX_EVIDENCE {
                return Err(AccountError::new(
                    "operation read evidence exceeds its bound",
                ));
            }
            persist_reads(turn, session.base.as_str(), space, &encoded)
        })();
        if saved.is_err() {
            // A failed checkpoint must not authorize even this turn's later
            // mutation through its in-memory read cache.
            turn.reads.pop();
        }
        saved
    })?;
    Ok(entries)
}

fn persist_reads(
    turn: &Turn,
    instance: &str,
    space: &str,
    encoded: &str,
) -> Result<(), AccountError> {
    let result = (|| {
        let updated = sync::now()?;
        let reservation;
        let mut conn = offline::database()?;
        let planning_version: i64 = conn
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect read evidence plan"))?;
        let planned = if crate::storage::limits::view()?.limits.is_some() {
            serde_json::to_vec(&(turn.id, &turn.snapshot, turn.phase, encoded, updated))
                .map_err(|_| AccountError::new("cannot size read evidence"))?
                .len() as u64
        } else {
            0
        };
        // The GET and complete snapshot publication have both released their
        // storage ownership before this separate State checkpoint begins.
        #[cfg(feature = "fault-injection")]
        if std::env::var("CIRRUS_TEST_READ_EVIDENCE_SPACE")
            .ok()
            .is_none_or(|expected| expected == space)
        {
            if turn.phase == "verify" {
                crate::wait_test_window("CIRRUS_TEST_READ_EVIDENCE_VERIFY_WINDOW")?;
            }
            crate::wait_test_window("CIRRUS_TEST_READ_EVIDENCE_ADMISSION_WINDOW")?;
        }
        reservation = crate::storage::sql_reservation::SqlReservation::begin(
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
            .map_err(|error| offline::sqlite_storage_error(error, "cannot begin read evidence"))?;
        if reservation.is_some() {
            let current: i64 = tx
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| AccountError::new("cannot inspect read evidence plan"))?;
            if current != planning_version {
                return Err(AccountError::new(
                    "read evidence plan changed; retry observation",
                ));
            }
        }
        // Preflight cannot bless an already claimed operation. Post-success
        // evidence belongs to the exact durable receipt, never replay authority.
        let eligible: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM operation_journal j WHERE j.id=?1 AND j.instance=?2 AND j.space=?3 AND ((?4='prepare' AND j.state='pending') OR (?4='verify' AND j.state='uncertain' AND EXISTS(SELECT 1 FROM mutation_receipts r WHERE r.operation_id=j.id AND r.snapshot=?5))))",
            params![turn.id,instance,space,turn.phase,turn.operation], |row| row.get(0),
        ).map_err(|_| AccountError::new("cannot validate read evidence operation"))?;
        if !eligible {
            return Err(AccountError::new(
                "read evidence operation changed; local state retained",
            ));
        }
        tx.execute("INSERT INTO sync_reads(operation_id,snapshot,phase,entries,updated_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(operation_id) DO UPDATE SET snapshot=excluded.snapshot,phase=excluded.phase,entries=excluded.entries,updated_at=excluded.updated_at", params![turn.id,turn.snapshot,turn.phase,encoded,updated])
            .map_err(|error| offline::sqlite_storage_error(error, "cannot persist operation read progress"))?;
        #[cfg(feature = "fault-injection")]
        if std::env::var("CIRRUS_TEST_READ_EVIDENCE_SPACE")
            .ok()
            .is_none_or(|expected| expected == space)
        {
            crate::wait_test_window("CIRRUS_TEST_READ_EVIDENCE_COMMIT_WINDOW")?;
        }
        if let Some(reservation) = &reservation {
            reservation.validate(&tx)?;
        } else if crate::storage::limits::view()?.limits.is_some() {
            return Err(AccountError::new(crate::storage::limits::PRESSURE));
        }
        let committed = tx.commit();
        conn.close().map_err(|_| {
            AccountError::new("cannot close read evidence; outcome unknown; retry observation")
        })?;
        committed.map_err(|_| {
            AccountError::new("cannot commit read evidence; outcome unknown; retry observation")
        })?;
        Ok(())
    })();
    // Both prepare and verify retry reads only. In particular never retire a
    // successful mutation receipt or reset its uncertain operation to pending.
    result.map_err(|mut error: AccountError| {
        error.retryable_read = true;
        error
    })
}

fn encode(value: &impl Serialize) -> Result<String, AccountError> {
    serde_json::to_string(value).map_err(|_| AccountError::new("cannot encode operation snapshot"))
}

pub(crate) fn retire(id: i64) -> Result<(), AccountError> {
    let mut conn = offline::database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot retire operation turn"))?;
    tx.execute("DELETE FROM sync_reads WHERE operation_id=?1", [id])
        .map_err(|_| AccountError::new("cannot retire operation reads"))?;
    tx.execute("DELETE FROM mutation_receipts WHERE operation_id=?1", [id])
        .map_err(|_| AccountError::new("cannot retire mutation receipt"))?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot commit operation retirement"))
}

fn receipt(id: i64, kind: &str, snapshot: String, extra: String) -> Result<(), AccountError> {
    let mut conn = offline::database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot begin mutation receipt"))?;
    let changed = tx.execute("INSERT INTO mutation_receipts(operation_id,kind,snapshot,extra) SELECT ?1,?2,?3,?4 WHERE EXISTS(SELECT 1 FROM operation_journal WHERE id=?1 AND state='uncertain')", params![id,kind,snapshot,extra])
        .map_err(|_| AccountError::new("cannot persist mutation receipt"))?;
    if changed != 1 {
        return Err(AccountError::new(
            "mutation snapshot changed; receipt not recorded",
        ));
    }
    tx.execute("DELETE FROM sync_reads WHERE operation_id=?1", [id])
        .map_err(|_| AccountError::new("cannot retire mutation preflight"))?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot commit mutation receipt"))
}

pub(crate) fn namespace_receipt(
    operation: &offline::NamespaceOperation,
    rebase: Option<&offline::NamespaceOperation>,
) -> Result<(), AccountError> {
    receipt(
        operation.id,
        "namespace",
        encode(operation)?,
        encode(&rebase)?,
    )
}

pub(crate) fn tree_receipt(operation: &offline::TreeMove) -> Result<bool, AccountError> {
    receipt(operation.id, "tree", encode(operation)?, "null".into())?;
    #[cfg(feature = "fault-injection")]
    if std::env::var("CIRRUS_TEST_TREE_RECEIPT_SOURCE")
        .ok()
        .is_none_or(|source| {
            operation.source
                == source
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
        })
    {
        if std::env::var_os("CIRRUS_TEST_TREE_RECEIPT_WINDOW").is_some() {
            eprintln!(
                "cirrus lab tree receipt barrier: id={} source={:?}",
                operation.id, operation.source
            );
        }
        crate::wait_test_window("CIRRUS_TEST_TREE_RECEIPT_WINDOW")?;
    }
    Ok(active())
}

type ReceiptRow = (i64, String, String, String);
fn receipts(instance: &str, space: Option<&str>) -> Result<Vec<ReceiptRow>, AccountError> {
    let conn = offline::database()?;
    let mut statement = conn.prepare("SELECT r.operation_id,r.kind,r.snapshot,r.extra FROM mutation_receipts r JOIN operation_journal j ON j.id=r.operation_id WHERE j.instance=?1 AND (?2 IS NULL OR j.space=?2) AND j.state='uncertain' ORDER BY j.id LIMIT 1")
        .map_err(|_| AccountError::new("cannot load mutation receipt"))?;
    statement
        .query_map(params![instance, space], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(|_| AccountError::new("cannot read mutation receipt"))?
        .collect::<Result<_, _>>()
        .map_err(|_| AccountError::new("invalid mutation receipt"))
}

impl Accounts {
    fn finish_receipt(&self, session: &ReadSession, row: ReceiptRow) -> Result<(), AccountError> {
        let (id, kind, snapshot, extra) = row;
        let verified_space: String = offline::database()?
            .query_row(
                "SELECT space FROM operation_journal WHERE instance=?1 AND id=?2",
                params![session.base.as_str(), id],
                |row| row.get(0),
            )
            .map_err(|_| AccountError::new("cannot inspect receipt Space"))?;
        let _turn = start(id, snapshot.clone(), "verify")?;
        match kind.as_str() {
            "namespace" => {
                let operation: offline::NamespaceOperation = serde_json::from_str(&snapshot)
                    .map_err(|_| AccountError::new("invalid namespace receipt"))?;
                if operation.id != id {
                    return Err(AccountError::new("mutation receipt identity differs"));
                }
                let rebase: Option<offline::NamespaceOperation> = serde_json::from_str(&extra)
                    .map_err(|_| AccountError::new("invalid parent rebase receipt"))?;
                self.finish_namespace(session, &operation, rebase.as_ref())?;
            }
            "tree" => {
                let operation: offline::TreeMove = serde_json::from_str(&snapshot)
                    .map_err(|_| AccountError::new("invalid tree receipt"))?;
                if operation.id != id {
                    return Err(AccountError::new("mutation receipt identity differs"));
                }
                offline::set_tree_state(
                    session.base.as_str(),
                    &operation,
                    "uncertain",
                    "uncertain",
                    Some("successful MOVE; verification pending"),
                )?;
                if !self.verify_parent_identities(
                    session,
                    &operation.space,
                    &operation.source,
                    &operation.parents,
                )? || !self.verify_parent_identities(
                    session,
                    &operation.space,
                    &operation.destination,
                    &operation.destination_parents,
                )? {
                    return Err(AccountError::new("parent identity changed after MOVE"));
                }
                let (source, parent) = operation
                    .source
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid tree source"))?;
                let (target, destination_parent) = operation
                    .destination
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid tree destination"))?;
                let before = self.sync_directory_snapshot(session, &operation.space, parent)?;
                let after =
                    self.sync_directory_snapshot(session, &operation.space, destination_parent)?;
                if before.get(source)?.is_some()
                    || !after.get(target)?.is_some_and(|entry| {
                        entry.is_directory() && entry.id() == operation.entry.id()
                    })
                {
                    return Err(AccountError::new("MOVE outcome could not be verified"));
                }
                if operation.offline
                    && operation.target.is_some()
                    && !self.verify_replaced_tree(session, &operation)?
                {
                    return Err(AccountError::new(
                        "replacement MOVE structure could not be verified",
                    ));
                }
                offline::set_tree_state(
                    session.base.as_str(),
                    &operation,
                    "uncertain",
                    "synced",
                    None,
                )?;
            }
            _ => return Err(AccountError::new("unknown mutation receipt")),
        }
        retire(id)?;
        sync::verified(session.base.as_str(), Some(&verified_space))?;
        Ok(())
    }

    pub(super) fn resume_mutations(
        &self,
        session: &ReadSession,
        space: Option<&str>,
    ) -> Result<(), AccountError> {
        loop {
            let mut rows = receipts(session.base.as_str(), space)?;
            let Some(row) = rows.pop() else { return Ok(()) };
            if !offline::publication::spaces(session.base.as_str(), space)?.is_empty() {
                return Err(AccountError::new(
                    "local publication requires recovery before resuming Space mutations",
                ));
            }
            match self.finish_receipt(session, row) {
                Err(error) if error.yielded => continue,
                result => result?,
            }
        }
    }

    pub(super) fn automatic_turn(
        &self,
        session: &ReadSession,
        space: &str,
    ) -> Result<WriteTurnOutcome, AccountError> {
        self.check_cancelled()?;
        let result: Result<WriteTurnOutcome, AccountError> = (|| {
            if !offline::publication::spaces(session.base.as_str(), Some(space))?.is_empty() {
                return Ok(WriteTurnOutcome::Attention);
            }
            if let Some(row) = receipts(session.base.as_str(), Some(space))?.pop() {
                self.finish_receipt(session, row)?;
                return Ok(WriteTurnOutcome::Yielded);
            }
            if let Some(mut verification) =
                offline::upload_verifications(session.base.as_str(), Some(space), 0)?
                    .into_iter()
                    .next()
            {
                if self.background_yield_requested() {
                    return Ok(WriteTurnOutcome::Yielded);
                }
                let id = verification.operation.id;
                self.active_writes
                    .lock()
                    .map_err(|_| AccountError::new("upload status unavailable"))?
                    .insert(id);
                let _active = ActiveWrite { accounts: self, id };
                let outcome = self.advance_upload(session, &mut verification, true)?;
                if !offline::write_needs_attention(session.base.as_str(), &verification.operation)?
                {
                    sync::verified(session.base.as_str(), Some(space))?;
                }
                return Ok(outcome);
            }
            if sync::has_attention(session.base.as_str(), space)?
                || !offline::invalid_journal_spaces(session.base.as_str(), Some(space))?.is_empty()
                || !offline::unsettled_mkdir_spaces(session.base.as_str(), Some(space))?.is_empty()
                || !offline::parent_conflict_spaces(session.base.as_str(), Some(space))?.is_empty()
            {
                return Ok(WriteTurnOutcome::Attention);
            }
            let through = offline::journal_high_water(session.base.as_str())?;
            for operation in offline::pending_namespace(
                session.base.as_str(),
                Some(space),
                true,
                (0, 0),
                through,
            )? {
                if offline::tree_destination_contains(
                    session.base.as_str(),
                    space,
                    &operation.path,
                    through,
                )? {
                    continue;
                }
                let _turn = start(operation.id, encode(&operation)?, "prepare")?;
                self.namespace_turn(session, &operation)?;
                return Ok(WriteTurnOutcome::Yielded);
            }
            if let Some(operation) = crate::sync::pending_tree(session.base.as_str(), space)? {
                let _turn = start(operation.id, encode(&operation)?, "prepare")?;
                self.sync_tree_move(session, &operation)?;
                retire(operation.id)?;
                return Ok(WriteTurnOutcome::Yielded);
            }
            let mut after = 0;
            loop {
                let page =
                    offline::pending_writes(session.base.as_str(), Some(space), after, through)?;
                let Some(last) = page.last() else { break };
                after = last.id;
                for operation in page {
                    if self.background_yield_requested() {
                        return Ok(WriteTurnOutcome::Yielded);
                    }
                    // Failed rename preparation can leave a readable retained
                    // source/open-target root. It is not an edit to auto-PUT.
                    // Actual edits or a successful path/precondition retarget
                    // no longer match; existing in-flight receipts above are
                    // resumed unchanged. Explicit manual sync stays explicit.
                    if offline::preservation_only(session.base.as_str(), &operation)? {
                        continue;
                    }
                    let _turn = start(operation.id, encode(&operation)?, "prepare")?;
                    self.upload_turn(session, &operation)?;
                    return Ok(WriteTurnOutcome::Yielded);
                }
            }
            for operation in offline::pending_namespace(
                session.base.as_str(),
                Some(space),
                false,
                (0, 0),
                through,
            )? {
                if let Some(dependency) = operation.dependency
                    && !sync::dependency_confirmed(session.base.as_str(), dependency)?
                {
                    continue;
                }
                if offline::unresolved_beneath(session.base.as_str(), space, &operation.path)? {
                    continue;
                }
                let _turn = start(operation.id, encode(&operation)?, "prepare")?;
                self.namespace_turn(session, &operation)?;
                return Ok(WriteTurnOutcome::Yielded);
            }
            Ok(
                if offline::has_unresolved(session.base.as_str(), Some(space))? {
                    WriteTurnOutcome::Dependencies
                } else {
                    WriteTurnOutcome::Idle
                },
            )
        })();
        match result {
            Err(error) if error.yielded => Ok(WriteTurnOutcome::Yielded),
            result => result,
        }
    }

    fn upload_turn(
        &self,
        session: &ReadSession,
        operation: &offline::PendingWrite,
    ) -> Result<(), AccountError> {
        let instance = session.base.as_str();
        if offline::tree_destination_contains(
            instance,
            &operation.space,
            &operation.path,
            i64::MAX,
        )? {
            return Err(AccountError::yielded());
        }
        if !self.verify_parent_identities(
            session,
            &operation.space,
            &operation.path,
            &operation.parents,
        )? {
            offline::set_write_state(
                instance,
                operation,
                "pending",
                "conflict",
                Some(offline::PARENT_WRITE_CONFLICT),
            )?;
            return Err(AccountError::new("upload parent identity changed"));
        }
        let (name, parent) = operation
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid upload path"))?;
        let entries = self.sync_directory_snapshot(session, &operation.space, parent)?;
        let current = entries.get(name)?;
        let matches = match (&operation.base_id, &operation.base_etag, current) {
            (Some(id), Some(etag), Some(entry)) => {
                !entry.is_directory() && entry.id() == id && entry.etag() == Some(etag.as_str())
            }
            (None, None, None) => true,
            _ => false,
        };
        if !matches {
            offline::set_write_state(
                instance,
                operation,
                "pending",
                "conflict",
                Some("remote file changed; automatic overwrite refused"),
            )?;
            return Err(AccountError::new(
                "remote file changed; local edit retained",
            ));
        }
        let data = offline::StagedSnapshot::open(&operation.staged)?;
        if !self.prepare_dirty_snapshot(session, &data, true)?
            || !self.protect_dirty_bases(session, &operation.space, &operation.path, true)?
        {
            return Err(AccountError::yielded());
        }
        let Some(digest) = data.digest_step("before-put")? else {
            return Err(AccountError::yielded());
        };
        if !self.protect_dirty_bases(session, &operation.space, &operation.path, true)? {
            return Err(AccountError::yielded());
        }
        let body = reqwest::blocking::Body::sized(data.stream()?, data.len());
        self.verify_incoming_file_source(session, operation)?;
        admit(self)?;
        self.active_writes
            .lock()
            .map_err(|_| AccountError::new("upload status unavailable"))?
            .insert(operation.id);
        let _active = ActiveWrite {
            accounts: self,
            id: operation.id,
        };
        offline::set_write_state(
            instance,
            operation,
            "pending",
            "uncertain",
            Some("automatic upload started; outcome not confirmed"),
        )?;
        sync::phase(instance, &operation.space, crate::SyncPhase::Uploading)?;
        let status = dav::put_file(
            &session.base,
            &operation.space,
            &operation.path,
            &session.account.access_token,
            &session.client,
            body,
            operation.base_etag.as_deref(),
        )?;
        if !matches!(status.as_u16(), 200 | 201 | 204) {
            if status.is_client_error() && !matches!(status.as_u16(), 401 | 408 | 429) {
                offline::set_write_state(
                    instance,
                    operation,
                    "uncertain",
                    "conflict",
                    Some("server rejected automatic upload"),
                )?;
            }
            return Err(AccountError::new(
                "upload rejected or outcome uncertain; local edit retained",
            ));
        }
        data.verify()?;
        offline::UploadVerification::record(instance, operation, digest, data.len())?;
        offline::database()?
            .execute(
                "DELETE FROM sync_reads WHERE operation_id=?1",
                [operation.id],
            )
            .map_err(|_| AccountError::new("cannot retire upload preflight"))?;
        sync::phase(instance, &operation.space, crate::SyncPhase::Verifying)
    }

    fn namespace_turn(
        &self,
        session: &ReadSession,
        operation: &offline::NamespaceOperation,
    ) -> Result<(), AccountError> {
        let instance = session.base.as_str();
        let space = &operation.space;
        // Destination verification and MOVE confirmation are independent gates
        // for a source whose destination write is outside the moved tree.
        if offline::tree_destination_contains(instance, space, &operation.path, i64::MAX)? {
            return Err(AccountError::yielded());
        }
        if !self.protect_dirty_bases(session, space, &operation.path, true)? {
            return Err(AccountError::yielded());
        }
        if !self.verify_parent_identities(session, space, &operation.path, &operation.parents)? {
            offline::set_namespace_state(
                instance,
                operation,
                "pending",
                "conflict",
                Some("parent identity changed; no mutation sent"),
            )?;
            return Err(AccountError::new("namespace parent identity changed"));
        }
        if self.reuse_local_directory_target(session, operation)? {
            return Ok(());
        }
        if let Some(dependency) = operation.dependency {
            if operation.kind == "move-dir-source" {
                let destination = offline::confirmed_directory(instance, dependency)?
                    .ok_or_else(AccountError::yielded)?;
                let (name, parent) = destination
                    .path
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid destination"))?;
                if destination.space != *space
                    || !self.verify_parent_identities(
                        session,
                        space,
                        &destination.path,
                        &destination.parents,
                    )?
                    || !self
                        .sync_directory_snapshot(session, space, parent)?
                        .get(name)?
                        .is_some_and(|entry| entry.is_directory() && entry.id() == destination.id)
                {
                    return Err(AccountError::new(
                        "directory rename destination changed; source retained",
                    ));
                }
            } else {
                let destination = offline::confirmed_destination(instance, dependency)?
                    .ok_or_else(AccountError::yielded)?;
                let proof: Option<(String, String)> = offline::database()?
                    .query_row(
                        "SELECT digest,version FROM verified_uploads WHERE operation_id=?1",
                        [dependency],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(|_| AccountError::new("cannot inspect destination verification"))?;
                let (digest, version) = proof.ok_or_else(|| {
                    AccountError::new("rename destination lacks durable verification")
                })?;
                let version: FileVersion = serde_json::from_str(&version)
                    .map_err(|_| AccountError::new("invalid destination verification"))?;
                let data = offline::StagedSnapshot::open(&destination.staged)?;
                let Some(actual_digest) = data.digest_step("before-rename-delete")? else {
                    return Err(AccountError::yielded());
                };
                let (name, parent) = destination
                    .path
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid destination"))?;
                if destination.space != *space
                    || version.instance != instance
                    || version.space != *space
                    || version.size != data.len()
                    || version.id != destination.file_id
                    || version.etag != destination.etag
                    || version.path != destination.path
                    || actual_digest != digest
                    || !self.verify_parent_identities(
                        session,
                        space,
                        &destination.path,
                        &destination.parents,
                    )?
                    || !self
                        .sync_directory_snapshot(session, space, parent)?
                        .get(name)?
                        .is_some_and(|entry| {
                            !entry.is_directory()
                                && entry.id() == version.id
                                && entry.etag() == Some(version.etag.as_str())
                                && entry.size() == Some(version.size)
                        })
                {
                    offline::set_namespace_state(
                        instance,
                        operation,
                        "pending",
                        "conflict",
                        Some("rename destination changed; source retained"),
                    )?;
                    return Err(AccountError::new(
                        "rename destination changed; source retained",
                    ));
                }
            }
        }
        let (name, parent) = operation
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid namespace path"))?;
        let entries = self.sync_directory_snapshot(session, space, parent)?;
        let current = entries.get(name)?;
        let mkdir = operation.kind == "mkdir";
        if !mkdir && current.is_none() {
            offline::set_namespace_state(
                instance,
                operation,
                "pending",
                "synced",
                Some("target already absent"),
            )?;
            return retire(operation.id);
        }
        let matches = if mkdir {
            current.is_none()
        } else {
            current.is_some_and(|entry| {
                entry.is_directory()
                    == matches!(operation.kind.as_str(), "rmdir" | "move-dir-source")
                    && Some(entry.id()) == operation.base_id.as_deref()
                    && entry.etag() == operation.base_etag.as_deref()
                    && operation.base_etag.is_some()
            })
        };
        if !matches {
            offline::set_namespace_state(
                instance,
                operation,
                "pending",
                "conflict",
                Some("namespace target changed; no mutation sent"),
            )?;
            return Err(AccountError::new("namespace target changed"));
        }
        if !mkdir && offline::unresolved_beneath(instance, space, &operation.path)? {
            return Err(AccountError::yielded());
        }
        if matches!(operation.kind.as_str(), "rmdir" | "move-dir-source") {
            let children = self.sync_directory_snapshot(session, space, &operation.path)?;
            let (id, etag) = children.remote_parent()?;
            if Some(id.as_str()) != operation.base_id.as_deref()
                || Some(etag.as_str()) != operation.base_etag.as_deref()
                || !children.is_empty()?
            {
                offline::set_namespace_state(
                    instance,
                    operation,
                    "pending",
                    "conflict",
                    Some("directory version changed or is not empty; source retained"),
                )?;
                return Err(AccountError::new("directory is not empty"));
            }
        }
        let rebase = if !mkdir && !parent.is_empty() {
            if let Some(pending) = offline::pending_rmdir_base(instance, space, parent)? {
                let (name, grandparent) = parent
                    .split_last()
                    .ok_or_else(|| AccountError::new("invalid parent removal"))?;
                if self
                    .sync_directory_snapshot(session, space, grandparent)?
                    .get(name)?
                    .is_some_and(|entry| {
                        entry.is_directory()
                            && Some(entry.id()) == pending.base_id.as_deref()
                            && entry.etag() == pending.base_etag.as_deref()
                    })
                {
                    Some(pending)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        if !self.protect_dirty_bases(session, space, &operation.path, true)? {
            return Err(AccountError::yielded());
        }
        admit(self)?;
        offline::set_namespace_state(
            instance,
            operation,
            "pending",
            "uncertain",
            Some("automatic namespace request started"),
        )?;
        let status = dav::namespace_request(
            &session.base,
            space,
            &operation.path,
            &session.account.access_token,
            &session.client,
            mkdir,
            operation.base_etag.as_deref(),
        )?;
        if !matches!(status.as_u16(), 200 | 201 | 204) && !(!mkdir && status.as_u16() == 404) {
            if status.is_client_error() && !matches!(status.as_u16(), 401 | 408 | 429) {
                offline::set_namespace_state(
                    instance,
                    operation,
                    "uncertain",
                    "conflict",
                    Some("server rejected namespace request"),
                )?;
            }
            return Err(AccountError::new("namespace request rejected or uncertain"));
        }
        namespace_receipt(operation, rebase.as_ref())
    }

    fn finish_namespace(
        &self,
        session: &ReadSession,
        operation: &offline::NamespaceOperation,
        rebase: Option<&offline::NamespaceOperation>,
    ) -> Result<(), AccountError> {
        let instance = session.base.as_str();
        let space = &operation.space;
        offline::set_namespace_state(
            instance,
            operation,
            "uncertain",
            "uncertain",
            Some("successful namespace response; verification pending"),
        )?;
        if !self.verify_parent_identities(session, space, &operation.path, &operation.parents)? {
            return Err(AccountError::new(
                "parent identity changed after namespace mutation",
            ));
        }
        let (name, parent) = operation
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid namespace receipt path"))?;
        let entries = self.sync_directory_snapshot(session, space, parent)?;
        let present = entries.get(name)?;
        let mkdir = operation.kind == "mkdir";
        if (mkdir && !present.as_ref().is_some_and(Entry::is_directory))
            || (!mkdir && present.is_some())
        {
            return Err(AccountError::new("namespace outcome could not be verified"));
        }
        let rebased = if let Some(pending) = rebase {
            let (name, grandparent) = parent
                .split_last()
                .ok_or_else(|| AccountError::new("invalid parent rebase"))?;
            self.sync_directory_snapshot(session, space, grandparent)?
                .get(name)?
                .filter(|entry| {
                    entry.is_directory() && Some(entry.id()) == pending.base_id.as_deref()
                })
                .and_then(|entry| entry.etag().map(str::to_owned))
                .map(|etag| (pending, etag))
        } else {
            None
        };
        let confirmation = if mkdir {
            present.map(|entry| format!("confirmed-directory:{}", entry.id()))
        } else {
            None
        };
        offline::confirm_namespace(
            instance,
            operation,
            confirmation.as_deref(),
            rebased
                .as_ref()
                .map(|(parent, etag)| (*parent, etag.as_str())),
        )
    }
}

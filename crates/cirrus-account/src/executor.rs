//! Serial, resumable operation turns. Read evidence never authorizes mutation replay.

use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock, atomic::AtomicUsize};
use std::time::{Duration, Instant};

use crate::account_storage::StorageRoot;
use rusqlite::{OptionalExtension, params};
use serde::{Serialize, de::DeserializeSeed};

use crate::{
    AccountError, Accounts, ActiveWrite, DirectorySnapshot, Entry, FileVersion, ReadSession,
    WriteTurnOutcome, dav, offline, sync,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Manual,
    Automatic,
    #[cfg(feature = "fault-injection")]
    LabUploadStep,
}

pub(crate) fn namespace_target_matches(
    operation: &offline::NamespaceOperation,
    current: Option<&Entry>,
) -> bool {
    if operation.kind == "mkdir" {
        current.is_none()
    } else {
        current.is_some_and(|entry| {
            entry.is_directory() == matches!(operation.kind.as_str(), "rmdir" | "move-dir-source")
                && Some(entry.id()) == operation.base_id.as_deref()
                && entry.etag() == operation.base_etag.as_deref()
                && operation.base_etag.is_some()
        })
    }
}

// At most eight transfer requests per turn; an admitted request keeps its 15s
// timeout. Auth/listing and bounded local hashing are separate admission phases.
const REQUESTS: usize = 8;
const ADMISSION: Duration = Duration::from_secs(5);
const MAX_EVIDENCE: usize = 4 * 1024 * 1024;

#[derive(Serialize)]
struct Observation {
    path: Vec<String>,
    self_version: (String, String),
    #[serde(with = "directory_evidence")]
    entries: DirectorySnapshot,
}

// Serialize/restore schema-14 child arrays in bounded windows rather than a Vec.
mod directory_evidence {
    use crate::account_storage::StorageRoot;
    use crate::{DirectorySnapshot, Entry, dav};
    use serde::{
        Deserializer, Serializer,
        de::{DeserializeSeed, SeqAccess, Visitor},
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

    pub(super) struct Seed<'a>(pub(super) &'a StorageRoot);

    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = DirectorySnapshot;

        fn deserialize<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            struct CompleteEntries<'a>(&'a StorageRoot);
            impl<'de> Visitor<'de> for CompleteEntries<'_> {
                type Value = DirectorySnapshot;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("complete directory read evidence")
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut sequence: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut snapshot =
                        DirectorySnapshot::empty_in(self.0).map_err(serde::de::Error::custom)?;
                    while let Some(entry) = sequence.next_element::<Entry>()? {
                        if !dav::valid_remote_id(entry.id()) {
                            return Err(serde::de::Error::custom(
                                "invalid directory read identity",
                            ));
                        }
                        snapshot.insert(&entry).map_err(serde::de::Error::custom)?;
                    }
                    Ok(snapshot)
                }
            }
            deserializer.deserialize_seq(CompleteEntries(self.0))
        }
    }
}

// The serialized schema stays unchanged. Rehydration gets its capability from
// the caller, never from serialized paths, HOME or the thread-local turn.
struct ReadsSeed<'a>(&'a StorageRoot);

impl<'de> DeserializeSeed<'de> for ReadsSeed<'_> {
    type Value = Vec<Observation>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        struct Reads<'a>(&'a StorageRoot);
        impl<'de> serde::de::Visitor<'de> for Reads<'_> {
            type Value = Vec<Observation>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("operation read observations")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut reads = Vec::new();
                while let Some(read) = sequence.next_element_seed(ObservationSeed(self.0))? {
                    reads.push(read);
                }
                Ok(reads)
            }
        }
        deserializer.deserialize_seq(Reads(self.0))
    }
}

struct ObservationSeed<'a>(&'a StorageRoot);

impl<'de> DeserializeSeed<'de> for ObservationSeed<'_> {
    type Value = Observation;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        struct Read<'a>(&'a StorageRoot);
        impl<'de> serde::de::Visitor<'de> for Read<'_> {
            type Value = Observation;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("directory read observation")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let (mut path, mut self_version, mut entries) = (None, None, None);
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "path" => {
                            if path.is_some() {
                                return Err(serde::de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                        "self_version" => {
                            if self_version.is_some() {
                                return Err(serde::de::Error::duplicate_field("self_version"));
                            }
                            self_version = Some(map.next_value()?);
                        }
                        "entries" => {
                            if entries.is_some() {
                                return Err(serde::de::Error::duplicate_field("entries"));
                            }
                            entries = Some(map.next_value_seed(directory_evidence::Seed(self.0))?);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(Observation {
                    path: path.ok_or_else(|| serde::de::Error::missing_field("path"))?,
                    self_version: self_version
                        .ok_or_else(|| serde::de::Error::missing_field("self_version"))?,
                    entries: entries.ok_or_else(|| serde::de::Error::missing_field("entries"))?,
                })
            }
        }
        deserializer.deserialize_struct(
            "Observation",
            &["path", "self_version", "entries"],
            Read(self.0),
        )
    }
}

struct Turn {
    root: StorageRoot,
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

pub(crate) struct AutomaticGuard {
    active: Arc<AtomicUsize>,
    previous: Option<Arc<sync::BackgroundAdmission>>,
    // TLS policy scopes are lexical and must unwind on their creating thread.
    _thread: PhantomData<Rc<()>>,
}
impl Drop for AutomaticGuard {
    fn drop(&mut self) {
        AUTOMATIC.with(|flag| *flag.borrow_mut() = self.previous.take());
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(crate) fn automatic_guard(accounts: &Accounts) -> AutomaticGuard {
    let previous = AUTOMATIC.with(|flag| {
        let mut flag = flag.borrow_mut();
        accounts
            .automatic_active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .expect("automatic scope count exhausted");
        flag.replace(Arc::clone(&accounts.background_admission))
    });
    AutomaticGuard {
        active: Arc::clone(&accounts.automatic_active),
        previous,
        _thread: PhantomData,
    }
}
pub(crate) fn is_automatic() -> bool {
    AUTOMATIC.with(|flag| flag.borrow().is_some())
}
pub(crate) fn is_automatic_for(accounts: &Accounts) -> bool {
    AUTOMATIC.with(|flag| {
        flag.borrow()
            .as_ref()
            .is_some_and(|flag| Arc::ptr_eq(flag, &accounts.background_admission))
    })
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

fn start(
    root: &StorageRoot,
    id: i64,
    snapshot: String,
    phase: &'static str,
) -> Result<TurnGuard, AccountError> {
    // A replacement scheduler must re-observe metadata after a crash, rather
    // than treating an old process's observations as fresh evidence.
    static EPOCH: OnceLock<String> = OnceLock::new();
    let epoch =
        EPOCH.get_or_init(|| format!("{}:{:?}", std::process::id(), std::time::SystemTime::now()));
    let operation = snapshot;
    let snapshot = format!("{epoch}:{operation}");
    let saved: Option<(String, String, String, i64)> = offline::database_in(root)?
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
            let mut deserializer = serde_json::Deserializer::from_str(&entries);
            let reads = ReadsSeed(root)
                .deserialize(&mut deserializer)
                .map_err(|_| AccountError::new("invalid operation read progress"))?;
            deserializer
                .end()
                .map_err(|_| AccountError::new("invalid operation read progress"))?;
            reads
        }
        _ => Vec::new(),
    };
    TURN.with(|turn| {
        *turn.borrow_mut() = Some(Turn {
            root: root.clone(),
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
    TURN.with(|turn| {
        if turn
            .borrow()
            .as_ref()
            .is_some_and(|turn| turn.root.identity() != session.root.identity())
        {
            return Err(AccountError::new("operation turn storage root changed"));
        }
        Ok(())
    })?;
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
        let mut restored = DirectorySnapshot::empty_in(&session.root)?;
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
    let observation = offline::begin_snapshot_in(&session.root).map_err(|mut error| {
        error.retryable_read = true;
        error
    })?;
    let entries = dav::directory_snapshot_once_in(
        &session.root,
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
            persist_reads(&session.root, turn, session.base.as_str(), space, &encoded)
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
    root: &StorageRoot,
    turn: &Turn,
    instance: &str,
    space: &str,
    encoded: &str,
) -> Result<(), AccountError> {
    let result = (|| {
        let updated = sync::now()?;
        let reservation;
        let mut conn = offline::database_in(root)?;
        let planning_version: i64 = conn
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect read evidence plan"))?;
        let planned = if crate::storage::limits::view_in(root)?.limits.is_some() {
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
        reservation = crate::storage::sql_reservation::SqlReservation::begin_in(
            root,
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
        } else if crate::storage::limits::view_in(root)?.limits.is_some() {
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

pub(crate) fn retire(root: &StorageRoot, id: i64) -> Result<(), AccountError> {
    let mut conn = offline::database_in(root)?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot retire operation turn"))?;
    tx.execute("DELETE FROM sync_reads WHERE operation_id=?1", [id])
        .map_err(|_| AccountError::new("cannot retire operation reads"))?;
    tx.execute("DELETE FROM mutation_receipts WHERE operation_id=?1 AND kind NOT IN ('namespace-verified','tree-verified')", [id])
        .map_err(|_| AccountError::new("cannot retire mutation receipt"))?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot commit operation retirement"))
}

fn receipt(
    root: &StorageRoot,
    id: i64,
    kind: &str,
    snapshot: String,
    extra: String,
) -> Result<(), AccountError> {
    let mut conn = offline::database_in(root)?;
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
    root: &StorageRoot,
    instance: &str,
    principal: (&str, &str),
    operation: &offline::NamespaceOperation,
    rebase: Option<&offline::NamespaceOperation>,
    status: reqwest::StatusCode,
) -> Result<(), AccountError> {
    offline::namespace_receipt::record(root, instance, principal, operation, rebase, status)
}

pub(crate) fn tree_receipt(
    root: &StorageRoot,
    operation: &offline::TreeMove,
) -> Result<bool, AccountError> {
    receipt(
        root,
        operation.id,
        "tree",
        encode(operation)?,
        "null".into(),
    )?;
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
fn receipts(
    root: &StorageRoot,
    instance: &str,
    space: Option<&str>,
) -> Result<Vec<ReceiptRow>, AccountError> {
    let conn = offline::database_in(root)?;
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
        let verified_space: String = offline::database_in(&session.root)?
            .query_row(
                "SELECT space FROM operation_journal WHERE instance=?1 AND id=?2",
                params![session.base.as_str(), id],
                |row| row.get(0),
            )
            .map_err(|_| AccountError::new("cannot inspect receipt Space"))?;
        // Reject ambiguous legacy DELETE before starting a verification turn,
        // updating journal progress, observing remotely, rebasing or retiring.
        let namespace = if kind == "namespace" {
            let receipt = offline::namespace_receipt::load(
                &session.root,
                &offline::database_in(&session.root)?,
                session.base.as_str(),
                (&session.account.issuer, &session.account.subject),
                id,
                offline::namespace_receipt::Phase::Pending,
            )?;
            if !receipt.matches_encoded(&snapshot, &extra) {
                return Err(AccountError::new("mutation receipt identity differs"));
            }
            Some(receipt)
        } else {
            None
        };
        let _turn = start(&session.root, id, snapshot.clone(), "verify")?;
        match kind.as_str() {
            "namespace" => {
                let receipt = namespace
                    .as_ref()
                    .expect("namespace receipt validated before turn");
                self.finish_namespace(session, receipt.operation(), receipt.rebase())?;
            }
            "tree" => {
                let operation: offline::TreeMove = serde_json::from_str(&snapshot)
                    .map_err(|_| AccountError::new("invalid tree receipt"))?;
                if operation.id != id {
                    return Err(AccountError::new("mutation receipt identity differs"));
                }
                offline::set_tree_state(
                    &session.root,
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
                    &session.root,
                    session.base.as_str(),
                    &operation,
                    "uncertain",
                    "synced",
                    None,
                )?;
            }
            _ => return Err(AccountError::new("unknown mutation receipt")),
        }
        retire(&session.root, id)?;
        sync::verified(&session.root, session.base.as_str(), Some(&verified_space))?;
        Ok(())
    }

    pub(super) fn resume_mutations(
        &self,
        session: &ReadSession,
        space: Option<&str>,
    ) -> Result<(), AccountError> {
        loop {
            let mut rows = receipts(&session.root, session.base.as_str(), space)?;
            let Some(row) = rows.pop() else { return Ok(()) };
            if !offline::publication::spaces_in(&session.root, session.base.as_str(), space)?
                .is_empty()
            {
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
            if !offline::publication::spaces_in(&session.root, session.base.as_str(), Some(space))?
                .is_empty()
            {
                return Ok(WriteTurnOutcome::Attention);
            }
            if let Some(row) = receipts(&session.root, session.base.as_str(), Some(space))?.pop() {
                self.finish_receipt(session, row)?;
                return Ok(WriteTurnOutcome::Yielded);
            }
            if let Some(mut verification) =
                offline::upload_verifications(&session.root, session.base.as_str(), Some(space), 0)?
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
                    .insert((session.root.identity(), id));
                let _active = ActiveWrite {
                    accounts: self,
                    root: session.root.clone(),
                    id,
                };
                let outcome = self.advance_upload(session, &mut verification, true)?;
                if !offline::write_needs_attention(
                    &session.root,
                    session.base.as_str(),
                    &verification.operation,
                )? {
                    sync::verified(&session.root, session.base.as_str(), Some(space))?;
                }
                return Ok(outcome);
            }
            if sync::has_attention(&session.root, session.base.as_str(), space)?
                || !offline::invalid_journal_spaces(
                    &session.root,
                    session.base.as_str(),
                    Some(space),
                )?
                .is_empty()
                || !offline::unsettled_mkdir_spaces(
                    &session.root,
                    session.base.as_str(),
                    Some(space),
                )?
                .is_empty()
                || !offline::parent_conflict_spaces(
                    &session.root,
                    session.base.as_str(),
                    Some(space),
                )?
                .is_empty()
            {
                return Ok(WriteTurnOutcome::Attention);
            }
            let through = offline::journal_high_water(&session.root, session.base.as_str())?;
            for operation in offline::pending_namespace(
                &session.root,
                session.base.as_str(),
                Some(space),
                true,
                (0, 0),
                through,
            )? {
                if offline::tree_destination_contains(
                    &session.root,
                    session.base.as_str(),
                    space,
                    &operation.path,
                    through,
                )? {
                    continue;
                }
                let _turn = start(&session.root, operation.id, encode(&operation)?, "prepare")?;
                self.namespace_turn(session, &operation)?;
                return Ok(WriteTurnOutcome::Yielded);
            }
            if let Some(operation) =
                crate::sync::pending_tree(&session.root, session.base.as_str(), space)?
            {
                let _turn = start(&session.root, operation.id, encode(&operation)?, "prepare")?;
                self.sync_tree_move(session, &operation)?;
                retire(&session.root, operation.id)?;
                return Ok(WriteTurnOutcome::Yielded);
            }
            let mut after = 0;
            loop {
                let page = offline::pending_writes(
                    &session.root,
                    session.base.as_str(),
                    Some(space),
                    after,
                    through,
                )?;
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
                    if offline::preservation_only(&session.root, session.base.as_str(), &operation)?
                    {
                        continue;
                    }
                    let _turn = start(&session.root, operation.id, encode(&operation)?, "prepare")?;
                    self.upload_turn(session, &operation)?;
                    return Ok(WriteTurnOutcome::Yielded);
                }
            }
            for operation in offline::pending_namespace(
                &session.root,
                session.base.as_str(),
                Some(space),
                false,
                (0, 0),
                through,
            )? {
                if let Some(dependency) = operation.dependency
                    && !sync::dependency_confirmed(
                        &session.root,
                        session.base.as_str(),
                        dependency,
                    )?
                {
                    continue;
                }
                if offline::unresolved_beneath(
                    &session.root,
                    session.base.as_str(),
                    space,
                    &operation.path,
                )? {
                    continue;
                }
                let _turn = start(&session.root, operation.id, encode(&operation)?, "prepare")?;
                self.namespace_turn(session, &operation)?;
                return Ok(WriteTurnOutcome::Yielded);
            }
            Ok(
                if offline::has_unresolved(&session.root, session.base.as_str(), Some(space))? {
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
            &session.root,
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
                &session.root,
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
                &session.root,
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
        let data = offline::StagedSnapshot::open_at(&session.root, &operation.staged)?;
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
            .insert((session.root.identity(), operation.id));
        let _active = ActiveWrite {
            accounts: self,
            root: session.root.clone(),
            id: operation.id,
        };
        offline::set_write_state(
            &session.root,
            instance,
            operation,
            "pending",
            "uncertain",
            Some("automatic upload started; outcome not confirmed"),
        )?;
        sync::phase(
            &session.root,
            instance,
            &operation.space,
            crate::SyncPhase::Uploading,
        )?;
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
                    &session.root,
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
        offline::UploadVerification::record(
            &session.root,
            instance,
            operation,
            digest,
            data.len(),
        )?;
        offline::database_in(&session.root)?
            .execute(
                "DELETE FROM sync_reads WHERE operation_id=?1",
                [operation.id],
            )
            .map_err(|_| AccountError::new("cannot retire upload preflight"))?;
        sync::phase(
            &session.root,
            instance,
            &operation.space,
            crate::SyncPhase::Verifying,
        )
    }

    fn namespace_turn(
        &self,
        session: &ReadSession,
        operation: &offline::NamespaceOperation,
    ) -> Result<(), AccountError> {
        let refreshed = if operation.kind == "rmdir" {
            let children =
                self.sync_directory_snapshot(session, &operation.space, &operation.path)?;
            self.refresh_provider_removal(session, operation, &children)?
        } else {
            None
        };
        let operation = refreshed.as_ref().unwrap_or(operation);
        let instance = session.base.as_str();
        let space = &operation.space;
        // Destination verification and MOVE confirmation are independent gates
        // for a source whose destination write is outside the moved tree.
        if offline::tree_destination_contains(
            &session.root,
            instance,
            space,
            &operation.path,
            i64::MAX,
        )? {
            return Err(AccountError::yielded());
        }
        if !self.protect_dirty_bases(session, space, &operation.path, true)? {
            return Err(AccountError::yielded());
        }
        if !self.verify_parent_identities(session, space, &operation.path, &operation.parents)? {
            offline::set_namespace_state(
                &session.root,
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
                let destination =
                    offline::confirmed_directory(&session.root, instance, dependency)?
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
                let destination =
                    offline::confirmed_destination(&session.root, instance, dependency)?
                        .ok_or_else(AccountError::yielded)?;
                let proof: Option<(String, String)> = offline::database_in(&session.root)?
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
                let data = offline::StagedSnapshot::open_at(&session.root, &destination.staged)?;
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
                        &session.root,
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
                &session.root,
                instance,
                operation,
                "pending",
                "synced",
                Some("target already absent"),
            )?;
            return retire(&session.root, operation.id);
        }
        let matches = namespace_target_matches(operation, current.as_ref());
        if !matches {
            offline::set_namespace_state(
                &session.root,
                instance,
                operation,
                "pending",
                "conflict",
                Some("namespace target changed; no mutation sent"),
            )?;
            return Err(AccountError::new("namespace target changed"));
        }
        if !mkdir && offline::unresolved_beneath(&session.root, instance, space, &operation.path)? {
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
                    &session.root,
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
            if let Some(pending) =
                offline::pending_rmdir_base(&session.root, instance, space, parent)?
            {
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
            &session.root,
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
        if !matches!(status.as_u16(), 200 | 201 | 204) {
            if status.is_client_error() && !matches!(status.as_u16(), 401 | 408 | 429) {
                offline::set_namespace_state(
                    &session.root,
                    instance,
                    operation,
                    "uncertain",
                    "conflict",
                    Some("server rejected namespace request"),
                )?;
            }
            return Err(AccountError::new("namespace request rejected or uncertain"));
        }
        namespace_receipt(
            &session.root,
            session.base.as_str(),
            (&session.account.issuer, &session.account.subject),
            operation,
            rebase.as_ref(),
            status,
        )
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
            &session.root,
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
            &session.root,
            instance,
            operation,
            confirmation.as_deref(),
            rebased
                .as_ref()
                .map(|(parent, etag)| (*parent, etag.as_str())),
        )
    }
}

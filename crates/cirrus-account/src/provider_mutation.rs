//! Durable FileProvider requests using the account engine's staging and executor.
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::provider_catalog::Item as ProviderItem;
use crate::{
    AccountError, Accounts, DirectoryIdentity, Entry, FileVersion, MountBinding, OperationHandle,
    OperationResult, dav, offline,
    provider_catalog::{Catalog, Item},
};

pub(crate) const DDL: &str = "
CREATE TABLE fp_requests(domain TEXT NOT NULL,key TEXT NOT NULL,descriptor TEXT NOT NULL,record TEXT NOT NULL,result TEXT,PRIMARY KEY(domain,key));
CREATE TABLE fp_deletions(domain TEXT NOT NULL,seq INTEGER NOT NULL,id TEXT NOT NULL,PRIMARY KEY(domain,seq));
";

/// Only basic mutation fields; unsupported OS metadata remains pending in Swift.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub kind: String,
    pub id: Option<String>,
    pub parent: String,
    pub name: String,
    pub directory: bool,
    pub base: Option<Vec<String>>,
    pub metadata: Option<String>,
    pub contents: bool,
    pub options: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reply {
    pub item: Option<Item>,
    pub deleted: Vec<String>,
    pub operation_ids: Vec<i64>,
}
#[derive(Debug)]
pub enum Error {
    Invalid,
    Unavailable,
    Pending,
    Conflict,
    Uncertain,
    Cancelled,
    Capacity,
    Unsupported,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "provider mutation {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<AccountError> for Error {
    fn from(e: AccountError) -> Self {
        #[cfg(feature = "fault-injection")]
        crate::sync::trace_automatic(&format!("provider boundary error={e}"));
        if e.is_staging_full() {
            Self::Capacity
        } else if e.upload_uncertain {
            Self::Uncertain
        } else if e.retryable_read || e.yielded {
            Self::Pending
        } else {
            Self::Unavailable
        }
    }
}
impl From<crate::provider_catalog::Error> for Error {
    fn from(e: crate::provider_catalog::Error) -> Self {
        use crate::provider_catalog::Error as C;
        match e {
            C::Capacity => Self::Capacity,
            C::Cancelled => Self::Cancelled,
            C::VersionMismatch => Self::Conflict,
            _ => Self::Unavailable,
        }
    }
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Default)]
pub(crate) struct ReconciliationCursor {
    after: std::collections::BTreeMap<
        (crate::account_storage::RootIdentity, String, String),
        (String, String),
    >,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Record {
    pub domain: String,
    pub epoch: String,
    pub key: String,
    pub descriptor: String,
    pub instance: String,
    pub issuer: String,
    pub subject: String,
    pub space: String,
    pub original: Option<Item>,
    pub parent: String,
    pub path: Vec<String>,
    pub removed: Vec<Item>,
    pub operations: Vec<OperationHandle>,
    pub deleting: bool,
    pub adopted: Option<Entry>,
    #[serde(default)]
    pub waiting: Option<WaitingMove>,
    #[serde(default)]
    pub postcondition: Option<Postcondition>,
}
/// Qualified observations made after this request's exact operations confirmed,
/// retained atomically with its reply. Not a server-atomic claim of causality.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Postcondition {
    operations: Vec<i64>,
    item: Option<Entry>,
    parents: Vec<(Vec<String>, Entry)>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct WaitingMove {
    pub(crate) source: Vec<String>,
    before: Vec<(Vec<String>, Entry)>,
    pub(crate) children: Vec<String>,
    catalog_base: Option<Item>,
}

impl Record {
    fn verify(&self, catalog: &Catalog, key: &str, descriptor: &str) -> Result<()> {
        if self.domain != catalog.domain
            || self.epoch != catalog.epoch
            || self.key != key
            || self.descriptor != descriptor
            || self.instance != catalog.binding.instance
            || self.space != catalog.binding.space
            || self.issuer != catalog.binding.issuer
            || self.subject != catalog.binding.subject
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn overlaps_tree(
        &self,
        source: &[String],
        destination: &[String],
        root_id: &str,
    ) -> bool {
        let overlap = |p: &[String]| {
            [source, destination]
                .iter()
                .any(|q| !p.is_empty() && !q.is_empty() && (p.starts_with(q) || q.starts_with(p)))
        };
        overlap(&self.path)
            || self.operations.iter().any(|op| overlap(op.path()))
            || self.waiting.as_ref().is_some_and(|w| overlap(&w.source))
            || self
                .original
                .as_ref()
                .is_some_and(|i| i.directory && i.remote == root_id)
    }
}

/// One overlap rule for preflight, waiting admission, and the actual tree
/// publication transaction. Later waiting intents explicitly await earlier ones;
/// the earlier intent must not be fenced by its own dependents.
pub(crate) fn tree_blockers_in(
    conn: &rusqlite::Connection,
    instance: &str,
    space: &str,
    source: &[String],
    destination: &[String],
    root_id: &str,
    current: Option<&Record>,
) -> std::result::Result<Vec<Record>, AccountError> {
    let mut stmt=conn.prepare("SELECT r.domain,r.key,r.descriptor,d.epoch,d.issuer,d.subject,r.record FROM fp_requests r JOIN fp_domains d ON d.domain=r.domain WHERE d.instance=?1 AND d.space=?2 AND r.result IS NULL ORDER BY r.rowid")
        .map_err(|_|AccountError::new("cannot inspect provider tree dependencies"))?;
    let mut blockers = Vec::new();
    for row in stmt
        .query_map(params![instance, space], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })
        .map_err(|_| AccountError::new("cannot inspect provider tree dependencies"))?
    {
        let (domain, key, descriptor, epoch, issuer, subject, encoded) =
            row.map_err(|_| AccountError::new("invalid provider tree dependency"))?;
        let prior: Record = serde_json::from_str(&encoded)
            .map_err(|_| AccountError::new("invalid provider tree dependency"))?;
        if (
            prior.domain.as_str(),
            prior.key.as_str(),
            prior.descriptor.as_str(),
            prior.epoch.as_str(),
            prior.issuer.as_str(),
            prior.subject.as_str(),
            prior.instance.as_str(),
            prior.space.as_str(),
        ) != (
            domain.as_str(),
            key.as_str(),
            descriptor.as_str(),
            epoch.as_str(),
            issuer.as_str(),
            subject.as_str(),
            instance,
            space,
        ) {
            return Err(AccountError::new(
                "provider tree dependency identity changed",
            ));
        }
        if let Some(current) = current {
            if prior.domain == current.domain && prior.key == current.key {
                if prior.descriptor != current.descriptor
                    || prior.original.as_ref().map(|i| (&i.id, &i.remote))
                        != current.original.as_ref().map(|i| (&i.id, &i.remote))
                {
                    return Err(AccountError::new("provider tree intent identity changed"));
                }
                continue;
            }
            if prior.domain == current.domain
                && prior.operations.is_empty()
                && prior
                    .waiting
                    .as_ref()
                    .is_some_and(|w| w.children.contains(&current.key))
            {
                continue;
            }
        }
        if prior.overlaps_tree(source, destination, root_id) {
            blockers.push(prior);
        }
    }
    Ok(blockers)
}

fn own_operations_in(
    conn: &rusqlite::Connection,
    catalog: &Catalog,
    record: &Record,
) -> Result<()> {
    record.verify(catalog, &record.key, &record.descriptor)?;
    for op in &record.operations {
        if !matches!(
            crate::operation_result::result_in(conn, &catalog.binding, op)?,
            OperationResult::ConfirmedWrite { .. } | OperationResult::ConfirmedNamespace
        ) {
            return Err(Error::Unavailable);
        }
    }
    Ok(())
}
fn json<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|_| Error::Invalid)
}
fn valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)
}
fn leaf(s: &str) -> bool {
    valid(s) && s != "." && s != ".." && !s.contains('/')
}
fn version(item: &Item) -> Vec<String> {
    vec![
        item.remote.clone(),
        item.etag.clone().unwrap_or_default(),
        item.size.map(|s| s.to_string()).unwrap_or_default(),
    ]
}

struct Source {
    file: std::fs::File,
    before: std::fs::Metadata,
    digest: String,
}
impl Source {
    fn open(
        path: &Path,
        cancelled: &impl Fn() -> bool,
        progress: &impl Fn(u64, u64),
    ) -> Result<Self> {
        use rustix::fs::{Mode, OFlags};
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Error::Invalid);
        }
        #[cfg(target_os = "linux")]
        let fd = rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        );
        #[cfg(target_os = "macos")]
        let fd = crate::ownership::file_ops::open_absolute(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        );
        let mut file = std::fs::File::from(fd.map_err(|_| Error::Invalid)?);
        let before = file.metadata().map_err(|_| Error::Unavailable)?;
        if !before.is_file() || before.len() > offline::overlay::MAX_FILE {
            return Err(Error::Invalid);
        }
        let mut hash = Sha256::new();
        let mut bytes = [0; 131072];
        let mut count = 0u64;
        loop {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            let n = file.read(&mut bytes).map_err(|_| Error::Unavailable)?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(n as u64)
                .filter(|n| *n <= before.len())
                .ok_or(Error::Conflict)?;
            hash.update(&bytes[..n]);
            progress(count, before.len() * 2 + 1);
        }
        if count != before.len() {
            return Err(Error::Conflict);
        }
        let mut source = Self {
            file,
            before,
            digest: format!("{:x}", hash.finalize()),
        };
        source.verify()?;
        source
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Unavailable)?;
        Ok(source)
    }
    fn verify(&self) -> Result<()> {
        let after = self.file.metadata().map_err(|_| Error::Unavailable)?;
        let b = &self.before;
        if (
            b.dev(),
            b.ino(),
            b.len(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn import(
        &mut self,
        root: &crate::account_storage::StorageRoot,
        cancelled: &impl Fn() -> bool,
        progress: &impl Fn(u64, u64),
    ) -> Result<offline::overlay::Overlay> {
        struct Input<'a, F, P> {
            file: &'a mut std::fs::File,
            cancelled: &'a F,
            progress: &'a P,
            size: u64,
            count: u64,
            hash: Sha256,
        }
        impl<F: Fn() -> bool, P: Fn(u64, u64)> Read for Input<'_, F, P> {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                if (self.cancelled)() {
                    return Err(std::io::Error::other("request cancelled"));
                }
                let n = self.file.read(b)?;
                self.hash.update(&b[..n]);
                self.count += n as u64;
                (self.progress)(self.size + self.count, self.size * 2 + 1);
                Ok(n)
            }
        }
        let mut input = Input {
            file: &mut self.file,
            cancelled,
            progress,
            size: self.before.len(),
            count: 0,
            hash: Sha256::new(),
        };
        let overlay = offline::overlay::Overlay::import_candidate_in(
            root,
            &mut input,
            self.before.len(),
            cancelled,
        )
        .map_err(|e| {
            if cancelled() {
                Error::Cancelled
            } else {
                Error::from(e)
            }
        })?;
        if format!("{:x}", input.hash.finalize()) != self.digest {
            return Err(Error::Conflict);
        }
        self.verify()?;
        Ok(overlay)
    }
}

impl Accounts {
    #[cfg(all(test, target_os = "linux", feature = "fault-injection"))]
    pub fn provider_fixture_observe(&self, domain: &str, container: &str) -> Result<Vec<Item>> {
        let _automatic = crate::executor::automatic_guard(self);
        let root = self.storage_root()?;
        let (instance, _, _, space, epoch) = Catalog::stored(&root, domain)?;
        let binding = self.bind_space(&instance, &space)?;
        let retained = self.bind_offline_space_in(root.clone(), &instance, &space)?;
        let catalog = Catalog::resume(&retained, domain, &epoch)?;
        let conn = offline::database_in(&root)?;
        let path = catalog.path(&conn, container)?;
        let parent_id = if container == "root" {
            String::new()
        } else {
            catalog.saved(&conn, container)?.remote
        };
        drop(conn);
        self.mount_directory(&instance, &binding, &path, &parent_id)?;
        let token = catalog
            .capture(container, "name", || false)
            .inspect_err(|error| {
                crate::sync::trace_automatic(&format!("provider fixture capture error={error:?}"));
            })?;
        Ok(catalog.page(container, &token)?.items)
    }

    fn finish_waiting_move(
        &self,
        catalog: &Catalog,
        mut record: Record,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Reply> {
        let mut waiting = record.waiting.clone().ok_or(Error::Invalid)?;
        let mut expected = waiting.before.clone();
        let mut admitted = 0;
        // Each child retains its immutable original handle/path until its reply
        // is durable. No tree journal is published while any child is pending.
        for key in &waiting.children {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            let (mut child, saved) = {
                let mut conn = offline::database_in(&catalog.binding.root)?;
                let tx = conn.transaction()?;
                catalog.verify(&tx)?;
                let (descriptor, r, result): (String, String, Option<String>) = tx.query_row(
                    "SELECT descriptor,record,result FROM fp_requests WHERE domain=?1 AND key=?2",
                    params![catalog.domain, key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                let child: Record = serde_json::from_str(&r).map_err(|_| Error::Unavailable)?;
                child.verify(catalog, key, &descriptor)?;
                (
                    child,
                    result
                        .map(|r| serde_json::from_str::<Reply>(&r).map_err(|_| Error::Unavailable))
                        .transpose()?,
                )
            };
            let reply = if let Some(reply) = saved {
                reply
            } else {
                if admitted == 4 {
                    return Err(Error::Pending);
                }
                admitted += 1;
                self.finish_provider(catalog, child.clone(), cancelled)?
            };
            child = load(catalog, &child.key, &child.descriptor)?
                .ok_or(Error::Unavailable)?
                .0;
            // Only own confirmed operations can authorize the dependency
            // projection; observed absence must never become causal proof.
            let conn = offline::database_in(&catalog.binding.root)?;
            own_operations_in(&conn, catalog, &child)?;
            drop(conn);
            let pinned = child
                .postcondition
                .as_ref()
                .filter(|p| {
                    !child.operations.is_empty()
                        && p.operations
                            == child
                                .operations
                                .iter()
                                .map(OperationHandle::id)
                                .collect::<Vec<_>>()
                })
                .ok_or(Error::Unavailable)?;
            if let Some(old) = &child.original {
                if let Some(old_path) = expected
                    .iter()
                    .find(|(_, e)| e.id() == old.remote)
                    .map(|(p, _)| p.clone())
                {
                    if old.directory && !child.deleting {
                        if old_path == waiting.source {
                            // A competing same-root intent follows the exact
                            // earlier MOVE, not a catalog-inferred relocation.
                            if old.remote != record.original.as_ref().ok_or(Error::Invalid)?.remote
                            {
                                return Err(Error::Conflict);
                            }
                            waiting.source = child.path.clone();
                            waiting.catalog_base = reply.item.clone();
                        }
                        expected.retain_mut(|(p, _)| {
                            if !p.starts_with(&old_path) {
                                return true;
                            }
                            if !child.path.starts_with(&waiting.source) {
                                return false;
                            }
                            let suffix = p[old_path.len()..].to_vec();
                            *p = child.path.clone();
                            p.extend(suffix);
                            true
                        });
                    } else {
                        expected.retain(|(_, e)| e.id() != old.remote);
                    }
                }
            }
            if child.deleting {
                expected.retain(|(p, _)| !p.starts_with(&child.path));
            } else if let Some(item) = reply.item
                && child.path.starts_with(&waiting.source)
            {
                let entry = pinned
                    .item
                    .as_ref()
                    .filter(|e| item_matches(&item, &item.parent, e))
                    .ok_or(Error::Unavailable)?
                    .clone();
                expected.retain(|(p, _)| p != &child.path);
                expected.push((child.path.clone(), entry));
            }
            for (path, entry) in &pinned.parents {
                if let Some((_, prior)) = expected.iter_mut().find(|(p, _)| p == path) {
                    if !prior.is_directory() || !entry.is_directory() || prior.id() != entry.id() {
                        return Err(Error::Conflict);
                    }
                    *prior = entry.clone();
                }
            }
        }
        #[cfg(feature = "fault-injection")]
        crate::wait_test_window("CIRRUS_TEST_PROVIDER_DRAINED_WINDOW")?;
        let binding = self.bind_space(&record.instance, &record.space)?;
        if binding.root.identity() != catalog.binding.root.identity()
            || binding.issuer != record.issuer
            || binding.subject != record.subject
        {
            return Err(Error::Unavailable);
        }
        let session = self.read_session_in(
            &binding.root,
            &binding.instance,
            crate::SessionAccess::BoundOnline(&binding),
        )?;
        crate::bound_space(&session, &binding)?;
        let observed = Observation {
            session: &session,
            space: &binding.space,
        };
        let source = fresh_entry(&observed, &waiting.source)?.ok_or(Error::Conflict)?;
        if Some(source.id()) != record.original.as_ref().map(|i| i.remote.as_str()) {
            return Err(Error::Conflict);
        }
        let mut actual = Vec::new();
        collect_tree(&observed, &waiting.source, &source, &mut actual)?;
        // No foreign additions, removals, replacements or content changes may
        // enter a request that was planned against an earlier directory base.
        if expected.len() != actual.len() {
            return Err(Error::Conflict);
        }
        for (path, e) in &actual {
            let before = expected
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, e)| e)
                .ok_or(Error::Conflict)?;
            if e.id() != before.id()
                || e.is_directory() != before.is_directory()
                || e.name() != before.name()
                || e.etag() != before.etag()
                || e.size() != before.size()
                || e.modified() != before.modified()
            {
                return Err(Error::Conflict);
            }
        }
        let source_parents = observe_chain(&observed, &waiting.source)?;
        let target_parents = observe_chain(&observed, &record.path)?;
        verify_parents(catalog, &record.parent, &target_parents)?;
        let conn = offline::database_in(&binding.root)?;
        let original = record.original.as_ref().ok_or(Error::Invalid)?;
        let current = catalog.saved(&conn, &original.id)?;
        let authorized = waiting
            .catalog_base
            .clone()
            .unwrap_or_else(|| original.clone());
        if current.remote != original.remote
            || current.parent != authorized.parent
            || current.name != authorized.name
            || !current.directory
            || current.etag != original.etag && current.etag.as_deref() != source.etag()
        {
            return Err(Error::Conflict);
        }
        waiting.catalog_base = Some(current);
        drop(conn);
        verify_parents(catalog, &authorized.parent, &source_parents)?;
        record.waiting = Some(waiting.clone());
        let prepared = self.prepare_remote_tree(
            &binding.instance,
            &binding,
            (
                &waiting.source,
                source.id(),
                source
                    .etag()
                    .filter(|e| dav::strong_etag(e))
                    .ok_or(Error::Conflict)?,
            ),
            &record.path,
            None,
            None,
            &[],
            crate::RenameParents {
                source: &source_parents,
                destination: &target_parents,
            },
            &[],
        )?;
        prepared.commit_provider(&record)?;
        let record = load(catalog, &record.key, &record.descriptor)?
            .ok_or(Error::Unavailable)?
            .0;
        self.finish_provider(catalog, record, cancelled)
    }

    /// Descendant removals change ancestor directory validators on OpenCloud.
    /// Rebind only an empty, same-ID directory in this exact recursive request,
    /// after every planned descendant has independently confirmed completion.
    pub(crate) fn refresh_provider_removal(
        &self,
        session: &crate::ReadSession,
        operation: &offline::NamespaceOperation,
        snapshot: &crate::DirectorySnapshot,
    ) -> std::result::Result<Option<offline::NamespaceOperation>, AccountError> {
        if operation.kind != "rmdir" || !snapshot.is_empty()? {
            return Ok(None);
        }
        let (id, etag) = snapshot.remote_parent()?;
        if Some(id.as_str()) != operation.base_id.as_deref() || !dav::strong_etag(&etag) {
            return Ok(None);
        }
        let records = {
            let conn = offline::database_in(&session.root)?;
            let mut stmt = conn
                .prepare(
                    "SELECT domain,key,descriptor,record FROM fp_requests WHERE result IS NULL",
                )
                .map_err(|_| AccountError::new("cannot inspect recursive provider removal"))?;
            stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| AccountError::new("cannot inspect recursive provider removal"))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| AccountError::new("cannot read recursive provider removal"))?
        };
        for (domain, key, descriptor, encoded) in records {
            let record: Record = serde_json::from_str(&encoded)
                .map_err(|_| AccountError::new("invalid provider removal"))?;
            if !record.deleting
                || record.instance != session.base.as_str()
                || record.space != operation.space
                || !record.operations.iter().any(|op| op.id() == operation.id)
            {
                continue;
            }
            let binding =
                self.bind_offline_space_in(session.root.clone(), &record.instance, &record.space)?;
            let catalog = Catalog::resume(&binding, &domain, &record.epoch)
                .map_err(|_| AccountError::new("provider removal catalog changed"))?;
            record
                .verify(&catalog, &key, &descriptor)
                .map_err(|_| AccountError::new("provider removal identity changed"))?;
            let mut conn = offline::database_in(&session.root)?;
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|_| AccountError::new("cannot begin provider directory rebase"))?;
            catalog
                .verify(&tx)
                .map_err(|_| AccountError::new("provider removal catalog changed"))?;
            let current: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM fp_requests WHERE domain=?1 AND key=?2 AND descriptor=?3 AND record=?4 AND result IS NULL)",
                params![domain, key, descriptor, encoded],
                |r| r.get(0),
            ).map_err(|_| AccountError::new("cannot inspect provider removal identity"))?;
            if !current {
                return Ok(None);
            }
            let mut descendants = 0;
            for op in &record.operations {
                let path: String = tx
                    .query_row(
                        "SELECT path FROM operation_journal WHERE id=?1",
                        [op.id()],
                        |r| r.get(0),
                    )
                    .map_err(|_| AccountError::new("cannot inspect provider removal child"))?;
                let path: Vec<String> = serde_json::from_str(&path)
                    .map_err(|_| AccountError::new("invalid removal child path"))?;
                if path.len() > operation.path.len() && path.starts_with(&operation.path) {
                    if !matches!(
                        crate::operation_result::result_in(&tx, &binding, op)?,
                        OperationResult::ConfirmedNamespace
                    ) {
                        return Ok(None);
                    }
                    descendants += 1;
                }
            }
            if descendants == 0 {
                return Ok(None);
            }
            offline::update_rmdir_base_in(&tx, &record.instance, operation, &etag)?;
            tx.commit()
                .map_err(|_| AccountError::new("cannot commit provider directory rebase"))?;
            drop(conn);
            return offline::pending_rmdir_base(
                &session.root,
                &record.instance,
                &operation.space,
                &operation.path,
            );
        }
        Ok(None)
    }

    /// Prepares the existing automatic Finder domain for an authenticated mount.
    pub fn prepare_provider_domain(
        &self,
        binding: &MountBinding,
    ) -> std::result::Result<String, AccountError> {
        self.activate_sync(binding)?;
        self.mount_directory(&binding.instance, binding, &[], "")?;
        Catalog::prepare_authenticated(binding)
            .map_err(|_| AccountError::new("provider domain not ready"))
    }

    /// Executes/resumes an exact durable provider request, never a name-only retry.
    /// No browser is opened. Pending/uncertain operations and staged bytes survive.
    pub fn provider_mutation(
        &self,
        domain: &str,
        request: &Request,
        contents: Option<&Path>,
        cancelled: impl Fn() -> bool,
    ) -> Result<Reply> {
        let _automatic = crate::executor::automatic_guard(self);
        let root = self.storage_root()?;
        let (instance, issuer, subject, space, epoch) = Catalog::stored(&root, domain)?;
        let offline_binding = self.bind_offline_space_in(root, &instance, &space)?;
        if offline_binding.issuer != issuer || offline_binding.subject != subject {
            return Err(Error::Unavailable);
        }
        let catalog = Catalog::resume(&offline_binding, domain, &epoch)?;
        self.mutate_catalog(&catalog, request, contents, &cancelled, &|_, _| {})
    }

    pub(crate) fn mutate_catalog(
        &self,
        catalog: &Catalog,
        request: &Request,
        contents: Option<&Path>,
        cancelled: &impl Fn() -> bool,
        progress: &impl Fn(u64, u64),
    ) -> Result<Reply> {
        if !matches!(request.kind.as_str(), "create" | "modify" | "delete")
            || !valid(&request.parent)
            || !leaf(&request.name)
            || request.options & !(if request.kind == "create" { 3 } else { 1 }) != 0
            || (request.directory && (request.contents || contents.is_some()))
            || request.contents != contents.is_some()
                && !(request.kind == "create" && !request.directory && contents.is_none())
        {
            return Err(Error::Invalid);
        }
        if cancelled() {
            return Err(Error::Cancelled);
        }
        let mut source = contents
            .map(|p| Source::open(p, cancelled, progress))
            .transpose()?;
        let digest = source.as_ref().map(|s| s.digest.clone());
        let size = source.as_ref().map(|s| s.before.len());
        // SDK26 supplies no persistent mutation intent ID. A provider-confirmed
        // namespace deletion closes a create lifecycle. Retained request rows,
        // unlike expiring change anchors, durably preserve that boundary.
        let lifecycle = if request.kind == "create" {
            let conn = offline::database_in(&catalog.binding.root)?;
            catalog.verify(&conn)?;
            let mut stmt=conn.prepare("SELECT r.record,r.result,i.value,r.key,r.descriptor FROM fp_requests r,json_each(r.record,'$.removed') i WHERE r.domain=?1 AND r.result IS NOT NULL AND json_extract(r.record,'$.deleting')=1 AND json_extract(i.value,'$.parent')=?2 AND json_extract(i.value,'$.name')=?3 ORDER BY r.key,json_extract(i.value,'$.id')")?;
            let mut closed = Vec::new();
            for row in
                stmt.query_map(params![catalog.domain, request.parent, request.name], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })?
            {
                let (record, result, removed, key, descriptor) = row?;
                let record: Record =
                    serde_json::from_str(&record).map_err(|_| Error::Unavailable)?;
                record.verify(catalog, &key, &descriptor)?;
                let result: Reply =
                    serde_json::from_str(&result).map_err(|_| Error::Unavailable)?;
                let removed: Item =
                    serde_json::from_str(&removed).map_err(|_| Error::Unavailable)?;
                // Legacy completion/absence is not a lifecycle-closing proof.
                // Defer unknown candidates instead of admitting a replay key.
                own_operations_in(&conn, catalog, &record)?;
                if !record.deleting
                    || !result.deleted.contains(&removed.id)
                    || result.operation_ids
                        != record
                            .operations
                            .iter()
                            .map(OperationHandle::id)
                            .collect::<Vec<_>>()
                    || !record
                        .operations
                        .iter()
                        .any(|op| op.removes(&removed.remote))
                {
                    return Err(Error::Unavailable);
                }
                closed.push((record.key, removed.id));
            }
            if closed.is_empty() {
                None
            } else {
                Some(format!("{:x}", Sha256::digest(json(&closed)?.as_bytes())))
            }
        } else {
            None
        };
        let descriptor = if lifecycle.is_none() {
            json(&(request, digest, size))?
        } else {
            json(&(request, digest, size, lifecycle))?
        };
        if descriptor.len() > 16384 {
            return Err(Error::Invalid);
        }
        let key = format!("{:x}", Sha256::digest(descriptor.as_bytes()));
        if let Some((record, result)) = load(catalog, &key, &descriptor)? {
            if let Some(result) = result {
                return self.saved_provider_reply(catalog, &record, result);
            }
            return self.finish_provider(catalog, record, cancelled);
        }
        // Fresh, noninteractive membership with the SAME storage/principal tuple.
        let _automatic = crate::executor::automatic_guard(self);
        let binding = self.bind_space(&catalog.binding.instance, &catalog.binding.space)?;
        if binding.root.identity() != catalog.binding.root.identity()
            || binding.instance != catalog.binding.instance
            || binding.issuer != catalog.binding.issuer
            || binding.subject != catalog.binding.subject
            || binding.space != catalog.binding.space
        {
            return Err(Error::Unavailable);
        }
        let (original, source_path, parent_path, removed) = {
            let mut conn = offline::database_in(&binding.root)?;
            let tx = conn.transaction()?;
            catalog.verify(&tx)?;
            let original = request
                .id
                .as_deref()
                .map(|id| catalog.saved(&tx, id))
                .transpose()?;
            if request.kind != "create" {
                let old = original.as_ref().ok_or(Error::Invalid)?;
                if old.id == "root"
                    || (request.kind != "delete" && old.directory != request.directory)
                    || request.base.as_ref() != Some(&version(old))
                    || request.metadata.as_deref() != Some(&old.metadata_revision)
                {
                    return Err(Error::Conflict);
                }
            } else if original.is_some() {
                return Err(Error::Invalid);
            }
            let source_path = original
                .as_ref()
                .map(|i| catalog.path(&tx, &i.id))
                .transpose()?
                .unwrap_or_default();
            let parent = catalog.saved(&tx, &request.parent)?;
            if !parent.directory {
                return Err(Error::Invalid);
            }
            let parent_path = catalog.path(&tx, &request.parent)?;
            let mut removed = Vec::new();
            if request.kind == "delete" {
                let old = original.as_ref().ok_or(Error::Invalid)?;
                let mut stmt=tx.prepare("WITH RECURSIVE descendants(id) AS (SELECT ?2 UNION SELECT i.id FROM fp_items i JOIN descendants d ON i.parent=d.id WHERE i.domain=?1 AND i.id<>i.parent) SELECT payload FROM fp_items WHERE domain=?1 AND id IN descendants LIMIT 4097")?;
                for row in
                    stmt.query_map(params![catalog.domain, old.id], |r| r.get::<_, String>(0))?
                {
                    removed.push(serde_json::from_str(&row?).map_err(|_| Error::Unavailable)?);
                }
                if removed.len() > 4096 {
                    return Err(Error::Capacity);
                }
            }
            (original, source_path, parent_path, removed)
        };
        let mut target_path = parent_path.clone();
        target_path.push(request.name.clone());
        if target_path.len() > 128
            || (request.directory
                && !source_path.is_empty()
                && target_path.starts_with(&source_path)
                && target_path != source_path)
        {
            return Err(Error::Invalid);
        }
        let mut record = Record {
            domain: catalog.domain.clone(),
            epoch: catalog.epoch.clone(),
            key,
            descriptor,
            instance: binding.instance.clone(),
            issuer: binding.issuer.clone(),
            subject: binding.subject.clone(),
            space: binding.space.clone(),
            original: original.clone(),
            parent: request.parent.clone(),
            path: if request.kind == "delete" {
                source_path.clone()
            } else {
                target_path.clone()
            },
            removed,
            operations: vec![],
            deleting: request.kind == "delete",
            adopted: None,
            waiting: None,
            postcondition: None,
        };
        let session = self.read_session_in(
            &binding.root,
            &binding.instance,
            crate::SessionAccess::BoundOnline(&binding),
        )?;
        crate::bound_space(&session, &binding)?;
        let priority = self.request_foreground();
        let owner = self.wait_for_automatic_turn_in(&binding.root)?;
        if let Some((prior, result)) = load(catalog, &record.key, &record.descriptor)? {
            drop(owner);
            drop(priority);
            return if let Some(result) = result {
                self.saved_provider_reply(catalog, &prior, result)
            } else {
                self.finish_provider(catalog, prior, cancelled)
            };
        }
        let observed = Observation {
            session: &session,
            space: &binding.space,
        };
        let source_parents = observe_chain(&observed, &source_path)?;
        let target_parents = observe_chain(&observed, &target_path)?;
        verify_parents(catalog, &request.parent, &target_parents)?;
        if let Some(old) = &original {
            verify_parents(catalog, &old.parent, &source_parents)?;
        }
        let old_entry = if let Some(old) = &original {
            let e = fresh_entry(&observed, &source_path)?.ok_or(Error::Conflict)?;
            if e.id() != old.remote
                || e.is_directory() != old.directory
                || e.etag() != old.etag.as_deref()
                || e.size() != old.size
            {
                return Err(Error::Conflict);
            }
            Some(e)
        } else {
            None
        };
        if request.kind != "delete" && source_path != target_path {
            if let Some(existing) = fresh_entry(&observed, &target_path)? {
                if request.kind != "create"
                    || request.options & 1 == 0
                    || existing.is_directory() != request.directory
                {
                    return Err(Error::Conflict);
                }
                if !existing.is_directory() {
                    let remote = entry_version(&binding, &target_path, &existing)?;
                    if remote.size != source.as_ref().map(|s| s.before.len()).unwrap_or(0) {
                        return Err(Error::Conflict);
                    }
                    let mut hash = Sha256::new();
                    let mut offset = 0;
                    while offset < remote.size {
                        if cancelled() {
                            return Err(Error::Cancelled);
                        }
                        let end = (offset + 131072).min(remote.size) - 1;
                        hash.update(dav::read_range(
                            &session.base,
                            &remote,
                            offset,
                            end,
                            &session.account.access_token,
                            &session.client,
                        )?);
                        offset = end + 1;
                    }
                    let expected = source
                        .as_ref()
                        .map(|s| s.digest.clone())
                        .unwrap_or_else(|| format!("{:x}", Sha256::digest([])));
                    if format!("{:x}", hash.finalize()) != expected {
                        return Err(Error::Conflict);
                    }
                }
                let final_entry = fresh_entry(&observed, &target_path)?.ok_or(Error::Conflict)?;
                if final_entry.id() != existing.id()
                    || final_entry.etag() != existing.etag()
                    || final_entry.size() != existing.size()
                {
                    return Err(Error::Conflict);
                }
                record.adopted = Some(final_entry);
                record = offline::provider::stage(&binding, &record, None, &[], cancelled)?;
                drop(owner);
                drop(priority);
                return self.finish_provider(catalog, record, cancelled);
            }
        }
        if cancelled() {
            return Err(Error::Cancelled);
        }
        if request.kind == "modify" && request.directory && source_path != target_path {
            // Never let tree publication relocate an earlier provider handle.
            // Finish its real operations and durable callback first.
            let conn = offline::database_in(&binding.root)?;
            let children = tree_blockers_in(
                &conn,
                &binding.instance,
                &binding.space,
                &source_path,
                &target_path,
                old_entry.as_ref().ok_or(Error::Invalid)?.id(),
                Some(&record),
            )?;
            drop(conn);
            if !children.is_empty() {
                let mut before = Vec::new();
                collect_tree(
                    &observed,
                    &source_path,
                    old_entry.as_ref().ok_or(Error::Invalid)?,
                    &mut before,
                )?;
                record.waiting = Some(WaitingMove {
                    source: source_path.clone(),
                    before,
                    children: children.iter().map(|r| r.key.clone()).collect(),
                    catalog_base: None,
                });
                record = offline::provider::stage(&binding, &record, None, &[], cancelled)?;
                drop(owner);
                drop(priority);
                return self.finish_provider(catalog, record, cancelled);
            }
            drop(owner);
            drop(priority);
            let old = old_entry.as_ref().ok_or(Error::Invalid)?;
            let prepared = self.prepare_remote_tree(
                &binding.instance,
                &binding,
                (
                    &source_path,
                    old.id(),
                    old.etag()
                        .filter(|e| dav::strong_etag(e))
                        .ok_or(Error::Conflict)?,
                ),
                &target_path,
                None,
                None,
                &[],
                crate::RenameParents {
                    source: &source_parents,
                    destination: &target_parents,
                },
                &[],
            )?;
            prepared.commit_provider(&record)?;
            record = load(catalog, &record.key, &record.descriptor)?
                .ok_or(Error::Unavailable)?
                .0;
        } else {
            let mut namespaces = Vec::new();
            let mut write = None;
            if request.kind == "delete" {
                let entry = old_entry.as_ref().ok_or(Error::Invalid)?;
                if entry.is_directory() && request.options & 1 != 0 {
                    collect_removals(
                        &observed,
                        &source_path,
                        entry,
                        &source_parents,
                        &mut namespaces,
                    )?;
                } else {
                    namespaces.push(offline::provider::Namespace {
                        path: source_path.clone(),
                        kind: if entry.is_directory() {
                            "rmdir"
                        } else {
                            "unlink"
                        },
                        base: Some((
                            entry.id().into(),
                            entry.etag().ok_or(Error::Conflict)?.into(),
                        )),
                        parents: source_parents.clone(),
                        dependency: None,
                    });
                }
            } else if request.directory {
                if request.kind == "modify" {
                    record.adopted = old_entry.clone();
                } else {
                    namespaces.push(offline::provider::Namespace {
                        path: target_path.clone(),
                        kind: "mkdir",
                        base: None,
                        parents: target_parents.clone(),
                        dependency: None,
                    });
                }
            } else {
                let moved = request.kind == "modify" && source_path != target_path;
                if offline::any_unresolved_beneath(
                    &binding.root,
                    &binding.instance,
                    &binding.space,
                    &target_path,
                )? || (moved
                    && offline::any_unresolved_beneath(
                        &binding.root,
                        &binding.instance,
                        &binding.space,
                        &source_path,
                    )?)
                {
                    return Err(Error::Pending);
                }
                let base = old_entry
                    .as_ref()
                    .map(|e| entry_version(&binding, &source_path, e))
                    .transpose()?;
                let overlay = if let Some(source) = &mut source {
                    source.import(&binding.root, cancelled, progress)?
                } else if request.kind == "create" {
                    offline::overlay::Overlay::empty_in(&binding.root)
                } else {
                    offline::overlay::Overlay::original_in(
                        &binding.root,
                        base.as_ref().ok_or(Error::Invalid)?,
                    )?
                };
                if moved {
                    offline::protect_moving_pin_originals(
                        &binding.root,
                        &binding.instance,
                        &binding.space,
                        &source_path,
                        &target_path,
                        &self.cancelled,
                    )?;
                    let old = base.as_ref().ok_or(Error::Invalid)?;
                    namespaces.push(offline::provider::Namespace {
                        path: source_path.clone(),
                        kind: "move-source",
                        base: Some((old.id.clone(), old.etag.clone())),
                        parents: source_parents.clone(),
                        dependency: Some(0),
                    });
                }
                write = Some(offline::provider::Write {
                    path: target_path.clone(),
                    root: overlay,
                    base: if moved { None } else { base },
                    parents: target_parents.clone(),
                });
            }
            record = offline::provider::stage(&binding, &record, write, &namespaces, cancelled)?;
            drop(owner);
            drop(priority);
        }
        #[cfg(feature = "fault-injection")]
        crate::wait_test_window("CIRRUS_TEST_PROVIDER_STAGED_WINDOW")?;
        self.finish_provider(catalog, record, cancelled)
    }

    fn finish_provider(
        &self,
        catalog: &Catalog,
        record: Record,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Reply> {
        record.verify(catalog, &record.key, &record.descriptor)?;
        if cancelled() {
            return Err(Error::Cancelled);
        }
        if record.operations.is_empty() && record.waiting.is_some() {
            return self.finish_waiting_move(catalog, record, cancelled);
        }
        for operation in &record.operations {
            operation.recover_publication(&catalog.binding)?;
        }
        for attempt in 0..4 {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            let mut pending = false;
            for op in &record.operations {
                match self.operation_result(&catalog.binding, op)? {
                    OperationResult::ConfirmedWrite { .. }
                    | OperationResult::ConfirmedNamespace => {}
                    OperationResult::Conflict | OperationResult::Resolved => {
                        return Err(Error::Conflict);
                    }
                    OperationResult::ObservedAbsent => return Err(Error::Unavailable),
                    OperationResult::Uncertain {
                        verification_pending: false,
                    } => return Err(Error::Uncertain),
                    _ => pending = true,
                }
            }
            if !pending {
                return self.publish_provider(catalog, &record, cancelled);
            }
            if attempt == 3 {
                return Err(Error::Pending);
            }
            let _automatic = crate::executor::automatic_guard(self);
            // The engine's root transfer guard excludes any concurrent elected
            // dispatcher; this is foreground demand, not a second scheduler.
            if let Err(error) = self.sync_pending_at(
                &catalog.binding.root,
                &record.instance,
                Some(&record.space),
                crate::executor::Mode::Automatic,
            ) {
                #[cfg(feature = "fault-injection")]
                crate::sync::trace_automatic(&format!(
                    "provider transfer request={} error={error}",
                    record.key
                ));
                for op in &record.operations {
                    match self.operation_result(&catalog.binding, op)? {
                        OperationResult::Conflict | OperationResult::Resolved => {
                            return Err(Error::Conflict);
                        }
                        OperationResult::Uncertain {
                            verification_pending: false,
                        } => return Err(Error::Uncertain),
                        _ => {}
                    }
                }
                return Err(error.into());
            }
        }
        Err(Error::Pending)
    }

    pub(crate) fn reconcile_provider_requests(
        &self,
        root: &crate::account_storage::StorageRoot,
        instance: &str,
        space: &str,
        cursor: &mut ReconciliationCursor,
    ) -> Vec<String> {
        let Ok(instance) = Self::canonical_instance(instance) else {
            return Vec::new();
        };
        let instance = instance.as_str();
        let scope = (root.identity(), instance.to_owned(), space.to_owned());
        let after = cursor.after.get(&scope).cloned().unwrap_or_default();
        let rows=(||->Result<Vec<(String,String,rusqlite::Result<(String,String,String)>)>>{
            self.storage.validate(root)?;
            let conn=offline::database_in(root)?;
            let mut stmt=conn.prepare("SELECT r.key,r.domain,d.epoch,r.descriptor,r.record FROM fp_requests r JOIN fp_domains d ON d.domain=r.domain WHERE d.instance=?1 AND d.space=?2 AND r.result IS NULL AND (r.key,r.domain)>(?3,?4) ORDER BY r.key,r.domain LIMIT 4")?;
            let rows = stmt.query_map(params![instance,space,after.0,after.1],|r|{
                let payload = (|| Ok((r.get(2)?,r.get(3)?,r.get(4)?)))();
                Ok((r.get(0)?,r.get(1)?,payload))
            })?.collect::<std::result::Result<Vec<_>,_>>()?;
            if rows.is_empty() {
                cursor.after.remove(&scope);
            }
            Ok(rows)
        })().unwrap_or_default();
        let mut domains = Vec::new();
        for (key, domain, payload) in rows {
            if self.cancelled.load(std::sync::atomic::Ordering::Acquire)
                || self.background_admission.requested()
            {
                break;
            }
            // Every attempted row advances, including malformed or unqualified rows.
            cursor
                .after
                .insert(scope.clone(), (key.clone(), domain.clone()));
            let result = (|| -> Result<()> {
                let (epoch, descriptor, encoded) = payload.map_err(|_| Error::Unavailable)?;
                let record: Record =
                    serde_json::from_str(&encoded).map_err(|_| Error::Unavailable)?;
                let binding = self.bind_offline_space_in(root.clone(), instance, space)?;
                let catalog = Catalog::resume(&binding, &domain, &epoch)?;
                record.verify(&catalog, &key, &descriptor)?;
                if record.operations.is_empty() && record.waiting.is_some() {
                    self.finish_provider(&catalog, record, &|| {
                        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
                            || self.background_admission.paused()
                    })?;
                    return Ok(());
                }
                for op in &record.operations {
                    op.recover_publication(&binding)?;
                    if !matches!(
                        self.operation_result(&binding, op)?,
                        OperationResult::ConfirmedWrite { .. }
                            | OperationResult::ConfirmedNamespace
                    ) {
                        return Err(Error::Pending);
                    }
                }
                self.publish_provider(&catalog, &record, &|| {
                    self.cancelled.load(std::sync::atomic::Ordering::Acquire)
                        || self.background_admission.paused()
                })?;
                Ok(())
            })();
            if result.is_ok() && !domains.contains(&domain) {
                domains.push(domain);
            }
        }
        domains
    }

    fn publish_provider(
        &self,
        catalog: &Catalog,
        record: &Record,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Reply> {
        record.verify(catalog, &record.key, &record.descriptor)?;
        #[cfg(feature = "fault-injection")]
        crate::wait_test_window("CIRRUS_TEST_PROVIDER_PUBLISH_WINDOW")?;
        let _automatic = crate::executor::automatic_guard(self);
        let binding = self.bind_space(&record.instance, &record.space)?;
        if binding.root.identity() != catalog.binding.root.identity()
            || binding.issuer != record.issuer
            || binding.subject != record.subject
        {
            return Err(Error::Unavailable);
        }
        let session = self.read_session_in(
            &binding.root,
            &binding.instance,
            crate::SessionAccess::BoundOnline(&binding),
        )?;
        crate::bound_space(&session, &binding)?;
        let priority = self.request_foreground();
        let owner = self.wait_for_automatic_turn_in(&binding.root)?;
        if let Some((completed, Some(reply))) = load(catalog, &record.key, &record.descriptor)? {
            drop(owner);
            drop(priority);
            return self.saved_provider_reply(catalog, &completed, reply);
        }
        let observed = Observation {
            session: &session,
            space: &binding.space,
        };
        let parents = observe_chain(&observed, &record.path)?;
        verify_parents(
            catalog,
            if record.deleting {
                &record.original.as_ref().ok_or(Error::Invalid)?.parent
            } else {
                &record.parent
            },
            &parents,
        )?;
        let fresh = fresh_entry(&observed, &record.path)?;
        let expected = if record.deleting {
            None
        } else if let Some(entry) = &record.adopted {
            Some((
                entry.id().to_owned(),
                entry.etag().map(str::to_owned),
                entry.size(),
                entry.is_directory(),
            ))
        } else {
            let op = record.operations.first().ok_or(Error::Unavailable)?;
            match self.operation_result(&binding, op)? {
                OperationResult::ConfirmedWrite { version, .. } => {
                    Some((version.id, Some(version.etag), Some(version.size), false))
                }
                OperationResult::ConfirmedNamespace => {
                    let id = if record.original.as_ref().is_some_and(|i| i.directory) {
                        record
                            .original
                            .as_ref()
                            .ok_or(Error::Unavailable)?
                            .remote
                            .clone()
                    } else {
                        offline::confirmed_directory(&binding.root, &record.instance, op.id())?
                            .ok_or(Error::Unavailable)?
                            .id
                    };
                    Some((id, None, None, true))
                }
                _ => return Err(Error::Pending),
            }
        };
        if record.deleting {
            if fresh.is_some() {
                return Err(Error::Conflict);
            }
        } else {
            let (id, etag, size, directory) = expected.as_ref().ok_or(Error::Unavailable)?;
            let entry = fresh.as_ref().ok_or(Error::Conflict)?;
            if entry.id() != id
                || entry.is_directory() != *directory
                || !entry.etag().is_some_and(dav::strong_etag)
                || (!directory && (entry.etag() != etag.as_deref() || entry.size() != *size))
            {
                return Err(Error::Conflict);
            }
        }
        // Owned child operations can change directory validators. Publish fresh
        // same-identity parent metadata with the child, not an arbitrary rebase
        // of a future destructive request's supplied baseVersion.
        let mut parent_updates = Vec::new();
        let mut pinned_parents = Vec::new();
        let mut parent_ids = vec![record.parent.clone()];
        if let Some(old) = &record.original {
            parent_ids.push(old.parent.clone());
        }
        if let Some(base) = record
            .waiting
            .as_ref()
            .and_then(|w| w.catalog_base.as_ref())
        {
            parent_ids.push(base.parent.clone());
        }
        // Pin every non-root ancestor at this own-confirmed postcondition
        // phase. Later enumeration may update fp_items, never these revisions.
        {
            let conn = offline::database_in(&binding.root)?;
            let mut index = 0;
            while index < parent_ids.len() {
                if parent_ids.len() > 256 {
                    return Err(Error::Capacity);
                }
                let id = &parent_ids[index];
                if id != "root" {
                    let parent = catalog.saved(&conn, id)?.parent;
                    if !parent_ids.contains(&parent) {
                        parent_ids.push(parent);
                    }
                }
                index += 1;
            }
        }
        parent_ids.sort();
        parent_ids.dedup();
        for id in parent_ids {
            if id == "root" {
                continue;
            }
            let conn = offline::database_in(&binding.root)?;
            let old = catalog.saved(&conn, &id)?;
            let path = catalog.path(&conn, &id)?;
            drop(conn);
            if let Some(e) = fresh_entry(&observed, &path)? {
                if !e.is_directory() || e.id() != old.remote {
                    return Err(Error::Conflict);
                }
                parent_updates.push(item_from_entry(old.id.clone(), old.parent.clone(), &e)?);
                pinned_parents.push((path, e));
            } else {
                return Err(Error::Conflict);
            }
        }
        let mut conn = offline::database_in(&binding.root)?;
        let reservation = Catalog::reserve(
            &binding.root,
            &conn,
            (record.removed.len() as u64
                + parent_updates.len() as u64
                + pinned_parents.len() as u64
                + 1)
                * 16384,
        )?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        catalog.verify(&tx)?;
        let saved: String = tx.query_row(
            "SELECT record FROM fp_requests WHERE domain=?1 AND key=?2 AND descriptor=?3",
            params![record.domain, record.key, record.descriptor],
            |r| r.get(0),
        )?;
        let saved: Record = serde_json::from_str(&saved).map_err(|_| Error::Unavailable)?;
        if json(&saved)? != json(record)? {
            return Err(Error::Unavailable);
        }
        own_operations_in(&tx, catalog, record)?;
        if let Some(old) = &record.original {
            let current = catalog.saved(&tx, &old.id)?;
            if current != *old
                && record
                    .waiting
                    .as_ref()
                    .and_then(|w| w.catalog_base.as_ref())
                    != Some(&current)
                && (record.deleting
                    || fresh
                        .as_ref()
                        .is_none_or(|e| !item_matches(&current, &record.parent, e)))
            {
                return Err(Error::Conflict);
            }
        }
        let mut deleted = Vec::new();
        let item = if record.deleting {
            for old in &record.removed {
                if catalog.saved(&tx, &old.id)? != *old {
                    return Err(Error::Conflict);
                }
                let seq = next_sequence(&tx, &record.domain)?;
                tx.execute(
                    "INSERT INTO fp_deletions VALUES(?1,?2,?3)",
                    params![record.domain, seq, old.id],
                )?;
                tx.execute(
                    "DELETE FROM fp_items WHERE domain=?1 AND id=?2 AND remote=?3",
                    params![record.domain, old.id, old.remote],
                )?;
                deleted.push(old.id.clone());
            }
            None
        } else {
            let e = fresh.as_ref().ok_or(Error::Unavailable)?;
            let already: Option<String> = tx
                .query_row(
                    "SELECT payload FROM fp_items WHERE domain=?1 AND remote=?2",
                    params![record.domain, e.id()],
                    |r| r.get(0),
                )
                .optional()?;
            let already: Option<Item> = already
                .map(|s| serde_json::from_str(&s).map_err(|_| Error::Unavailable))
                .transpose()?;
            if record.original.is_none()
                && already
                    .as_ref()
                    .is_some_and(|i| i.parent != record.parent || i.name != e.name())
            {
                return Err(Error::Conflict);
            }
            let id = record
                .original
                .as_ref()
                .or(already.as_ref())
                .map(|i| i.id.clone())
                .unwrap_or(tx.query_row("SELECT lower(hex(randomblob(16)))", [], |r| r.get(0))?);
            let item = item_from_entry(id, record.parent.clone(), &e)?;
            let payload = json(&item)?;
            let seq = next_sequence(&tx, &record.domain)?;
            tx.execute("INSERT INTO fp_items VALUES(?1,?2,?3,?4,?5) ON CONFLICT(domain,id) DO UPDATE SET remote=excluded.remote,parent=excluded.parent,payload=excluded.payload",
                params![record.domain,item.id,item.remote,item.parent,payload])?;
            tx.execute(
                "INSERT INTO fp_changes VALUES(?1,?2,?3,'update',?4)",
                params![record.domain, seq, item.id, payload],
            )?;
            Some(item)
        };
        for parent in parent_updates {
            store_item(&tx, &record.domain, &parent)?;
        }
        let reply = Reply {
            item,
            deleted,
            operation_ids: record.operations.iter().map(OperationHandle::id).collect(),
        };
        let mut completed = record.clone();
        completed.postcondition = Some(Postcondition {
            operations: reply.operation_ids.clone(),
            item: fresh.clone(),
            parents: pinned_parents,
        });
        if tx.execute(
            "UPDATE fp_requests SET result=?3,record=?4 WHERE domain=?1 AND key=?2 AND descriptor=?5 AND result IS NULL",
            params![record.domain, record.key, json(&reply)?, json(&completed)?, record.descriptor],
        )? != 1 {
            return Err(Error::Unavailable);
        }
        catalog.quotas(&tx)?;
        if let Some(r) = &reservation {
            r.validate(&tx)?;
        }
        if cancelled() {
            return Err(Error::Cancelled);
        }
        tx.commit()?;
        Ok(reply)
    }

    fn saved_provider_reply(
        &self,
        catalog: &Catalog,
        record: &Record,
        reply: Reply,
    ) -> Result<Reply> {
        // A legacy cached result does not manufacture proof retired by an older
        // implementation. Unknown/observed-absent namespace rows stay unknown.
        {
            let mut conn = offline::database_in(&catalog.binding.root)?;
            let tx = conn.transaction()?;
            catalog.verify(&tx)?;
            own_operations_in(&tx, catalog, record)?;
        }
        let _automatic = crate::executor::automatic_guard(self);
        let binding = self.bind_space(&record.instance, &record.space)?;
        if binding.root.identity() != catalog.binding.root.identity()
            || binding.issuer != record.issuer
            || binding.subject != record.subject
        {
            return Err(Error::Unavailable);
        }
        let session = self.read_session_in(
            &binding.root,
            &binding.instance,
            crate::SessionAccess::BoundOnline(&binding),
        )?;
        crate::bound_space(&session, &binding)?;
        let _priority = self.request_foreground();
        let _owner = self.wait_for_automatic_turn_in(&binding.root)?;
        let observed = Observation {
            session: &session,
            space: &binding.space,
        };
        let path = if let Some(item) = &reply.item {
            completed_reply_path(catalog, record, item)?
        } else {
            record.path.clone()
        };
        let parents = observe_chain(&observed, &path)?;
        verify_parents(
            catalog,
            if record.deleting {
                &record.original.as_ref().ok_or(Error::Invalid)?.parent
            } else {
                &record.parent
            },
            &parents,
        )?;
        let fresh = fresh_entry(&observed, &path)?;
        if let Some(item) = &reply.item {
            if fresh
                .as_ref()
                .is_none_or(|e| !item_matches(item, &item.parent, e))
            {
                return Err(Error::Conflict);
            }
        } else if fresh.is_some() {
            return Err(Error::Conflict);
        }
        saved_reply(catalog, reply)
    }
}

// A completed child's immutable journal path is never rewritten. Only a later
// exact verified tree MOVE can translate the location used to qualify its reply.
fn completed_reply_path(catalog: &Catalog, record: &Record, item: &Item) -> Result<Vec<String>> {
    let conn = offline::database_in(&catalog.binding.root)?;
    let current = catalog.path(&conn, &item.id)?;
    if current == record.path {
        return Ok(current);
    }
    let mut proven = record.path.clone();
    let through = record
        .operations
        .iter()
        .map(OperationHandle::id)
        .max()
        .unwrap_or(0);
    let mut stmt=conn.prepare("SELECT id,path,(SELECT destination FROM directory_moves WHERE operation_id=j.id) FROM operation_journal j WHERE instance=?1 AND space=?2 AND id>?3 AND op_type='move-tree' AND state='synced' ORDER BY id LIMIT 4097")?;
    let moves = stmt
        .query_map(params![record.instance, record.space, through], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if moves.len() > 4096 {
        return Err(Error::Capacity);
    }
    for (id, source, destination) in moves {
        let source: Vec<String> = serde_json::from_str(&source).map_err(|_| Error::Unavailable)?;
        if proven.starts_with(&source) {
            let handle = OperationHandle::capture(&conn, &record.instance, &record.space, id)?;
            if !matches!(
                crate::operation_result::result_in(&conn, &catalog.binding, &handle)?,
                OperationResult::ConfirmedNamespace
            ) {
                return Err(Error::Unavailable);
            }
            let mut relocated: Vec<String> =
                serde_json::from_str(&destination).map_err(|_| Error::Unavailable)?;
            relocated.extend_from_slice(&proven[source.len()..]);
            proven = relocated;
        }
    }
    if current != proven {
        return Err(Error::Conflict);
    }
    Ok(proven)
}

fn item_matches(item: &Item, parent: &str, e: &Entry) -> bool {
    item.parent == parent
        && item.name == e.name()
        && item.remote == e.id()
        && item.directory == e.is_directory()
        && item.etag.as_deref() == e.etag()
        && item.size == e.size()
}
fn item_from_entry(id: String, parent: String, entry: &Entry) -> Result<Item> {
    Item::from_entry(id, parent, entry).map_err(|error| match error {
        crate::provider_catalog::Error::Internal => Error::Invalid,
        other => other.into(),
    })
}

fn store_item(conn: &rusqlite::Connection, domain: &str, item: &Item) -> Result<()> {
    let payload = json(item)?;
    let seq = next_sequence(conn, domain)?;
    conn.execute(
        "UPDATE fp_items SET payload=?3 WHERE domain=?1 AND id=?2 AND remote=?4",
        params![domain, item.id, payload, item.remote],
    )?;
    conn.execute(
        "INSERT INTO fp_changes VALUES(?1,?2,?3,'update',?4)",
        params![domain, seq, item.id, payload],
    )?;
    Ok(())
}

pub(crate) fn correlation_candidates(
    catalog: &Catalog,
    conn: &rusqlite::Connection,
) -> std::result::Result<Vec<Record>, crate::provider_catalog::Error> {
    use crate::provider_catalog::Error as C;
    let mut stmt = conn.prepare(
        "SELECT key,descriptor,record FROM fp_requests WHERE domain=?1 AND result IS NULL",
    )?;
    let mut records = Vec::new();
    let mut bytes = 0usize;
    for row in stmt.query_map([&catalog.domain], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (key, descriptor, encoded) = row?;
        bytes = bytes.checked_add(encoded.len()).ok_or(C::Capacity)?;
        if records.len() >= 4096 || bytes > 32 * 1024 * 1024 {
            return Err(C::Capacity);
        }
        let record: Record = serde_json::from_str(&encoded).map_err(|_| C::Unavailable)?;
        record
            .verify(catalog, &key, &descriptor)
            .map_err(|_| C::Unavailable)?;
        records.push(record);
    }
    Ok(records)
}

/// Capture may reuse an original FPID only for this exact verified in-flight
/// destination. Pending writes and merely matching names grant no alias.
pub(crate) fn correlated_item(
    catalog: &Catalog,
    conn: &rusqlite::Connection,
    parent: &str,
    parent_path: &[String],
    records: &[Record],
    entry: &Entry,
) -> std::result::Result<Option<Item>, crate::provider_catalog::Error> {
    use crate::provider_catalog::Error as C;
    let mut alias = None;
    for record in records {
        let Some((name, path)) = record.path.split_last() else {
            continue;
        };
        if record.deleting || name != entry.name() || path != parent_path {
            continue;
        }
        let Some(original) = &record.original else {
            continue;
        };
        let Some(op) = record.operations.first() else {
            continue;
        };
        let result = crate::operation_result::result_in(conn, &catalog.binding, op);
        #[cfg(feature = "fault-injection")]
        crate::sync::trace_automatic(&format!(
            "provider capture correlation op={} result={result:?} observed_id={} etag={:?}",
            op.id(),
            entry.id(),
            entry.etag()
        ));
        if let Ok(OperationResult::ConfirmedWrite { version, .. }) = result
            && version.id == entry.id()
            && Some(version.etag.as_str()) == entry.etag()
            && Some(version.size) == entry.size()
            && !entry.is_directory()
            && record.operations.iter().all(|op| {
                matches!(
                    crate::operation_result::result_in(conn, &catalog.binding, op),
                    Ok(OperationResult::ConfirmedWrite { .. }
                        | OperationResult::ConfirmedNamespace)
                )
            })
        {
            let current = catalog.saved(conn, &original.id)?;
            if current != *original && !item_matches(&current, parent, entry) {
                return Err(C::Unavailable);
            }
            if alias.is_some() {
                return Err(C::Unavailable);
            }
            alias = Some(original.clone());
        } else if !item_matches(original, &original.parent, entry) {
            // A remote response observed ahead of its verifier must not allocate
            // another FPID or publish unverified edited content.
            return Err(C::Unavailable);
        }
    }
    Ok(alias)
}
fn load(catalog: &Catalog, key: &str, descriptor: &str) -> Result<Option<(Record, Option<Reply>)>> {
    let mut conn = offline::database_in(&catalog.binding.root)?;
    let tx = conn.transaction()?;
    catalog.verify(&tx)?;
    let row: Option<(String, String, Option<String>)> = tx
        .query_row(
            "SELECT descriptor,record,result FROM fp_requests WHERE domain=?1 AND key=?2",
            params![catalog.domain, key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    row.map(|(d, r, result)| {
        if d != descriptor {
            return Err(Error::Conflict);
        }
        let record: Record = serde_json::from_str(&r).map_err(|_| Error::Unavailable)?;
        record.verify(catalog, key, &d)?;
        Ok((
            record,
            result
                .map(|s| serde_json::from_str(&s).map_err(|_| Error::Unavailable))
                .transpose()?,
        ))
    })
    .transpose()
}
fn saved_reply(catalog: &Catalog, reply: Reply) -> Result<Reply> {
    let mut conn = offline::database_in(&catalog.binding.root)?;
    let tx = conn.transaction()?;
    catalog.verify(&tx)?;
    if let Some(item) = &reply.item {
        if catalog.saved(&tx, &item.id)? != *item {
            return Err(Error::Conflict);
        }
    }
    for id in &reply.deleted {
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM fp_items WHERE domain=?1 AND id=?2)",
            params![catalog.domain, id],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(Error::Conflict);
        }
    }
    Ok(reply)
}
fn next_sequence(conn: &rusqlite::Connection, domain: &str) -> Result<i64> {
    if conn.execute(
        "UPDATE fp_domains SET nextseq=nextseq+1 WHERE domain=?1 AND nextseq<9223372036854775807",
        [domain],
    )? != 1
    {
        return Err(Error::Capacity);
    }
    Ok(conn.query_row(
        "SELECT nextseq FROM fp_domains WHERE domain=?1",
        [domain],
        |r| r.get(0),
    )?)
}
fn verify_parents(catalog: &Catalog, parent: &str, observed: &[DirectoryIdentity]) -> Result<()> {
    let mut conn = offline::database_in(&catalog.binding.root)?;
    let tx = conn.transaction()?;
    catalog.verify(&tx)?;
    let mut id = parent.to_owned();
    let mut expected = Vec::new();
    while id != "root" {
        if expected.len() >= 128 {
            return Err(Error::Invalid);
        }
        let item = catalog.saved(&tx, &id)?;
        if !item.directory {
            return Err(Error::Conflict);
        }
        expected.push(DirectoryIdentity::Remote(item.remote));
        id = item.parent;
    }
    expected.reverse();
    if expected != observed {
        return Err(Error::Conflict);
    }
    Ok(())
}
struct Observation<'a> {
    session: &'a crate::ReadSession,
    space: &'a str,
}
fn observe(scope: &Observation<'_>, path: &[String]) -> Result<crate::DirectorySnapshot> {
    let session = scope.session;
    let observation = offline::begin_snapshot_in(&session.root)?;
    let snapshot = dav::directory_snapshot_in(
        &session.root,
        &session.base,
        scope.space,
        path,
        &session.account.access_token,
        &session.client,
    )?;
    if !offline::save_directory_snapshot(
        observation,
        session.base.as_str(),
        scope.space,
        path,
        &snapshot,
    )? {
        return Err(Error::Pending);
    }
    Ok(snapshot)
}
fn fresh_entry(session: &Observation<'_>, path: &[String]) -> Result<Option<Entry>> {
    let (name, parent) = path.split_last().ok_or(Error::Invalid)?;
    Ok(observe(session, parent)?.get(name)?)
}
fn observe_chain(session: &Observation<'_>, path: &[String]) -> Result<Vec<DirectoryIdentity>> {
    let mut parents = Vec::new();
    for depth in 0..path.len().saturating_sub(1) {
        let entries = observe(session, &path[..depth])?;
        let entry = entries
            .get(&path[depth])?
            .filter(Entry::is_directory)
            .ok_or(Error::Conflict)?;
        parents.push(DirectoryIdentity::Remote(entry.id().into()));
    }
    // The direct parent must also be freshly observed, including the root.
    if let Some((_, parent)) = path.split_last() {
        observe(session, parent)?;
    }
    Ok(parents)
}
fn entry_version(binding: &MountBinding, path: &[String], e: &Entry) -> Result<FileVersion> {
    Ok(FileVersion {
        instance: binding.instance.clone(),
        space: binding.space.clone(),
        path: path.to_vec(),
        id: e.id().into(),
        etag: e
            .etag()
            .filter(|s| dav::strong_etag(s))
            .ok_or(Error::Conflict)?
            .into(),
        size: e.size().ok_or(Error::Conflict)?,
        checksums: e.checksums().to_vec(),
    })
}
fn collect_removals(
    session: &Observation<'_>,
    path: &[String],
    entry: &Entry,
    parents: &[DirectoryIdentity],
    out: &mut Vec<offline::provider::Namespace>,
) -> Result<()> {
    if path.len() > 128 || out.len() >= 4096 {
        return Err(Error::Capacity);
    }
    if entry.is_directory() {
        let entries = observe(session, path)?;
        let (id, etag) = entries.remote_parent()?;
        if id != entry.id() || Some(etag.as_str()) != entry.etag() {
            return Err(Error::Conflict);
        }
        let mut after = 0;
        let mut nested = parents.to_vec();
        nested.push(DirectoryIdentity::Remote(entry.id().into()));
        loop {
            let page = entries.page(after)?;
            if page.is_empty() {
                break;
            }
            for (cookie, child) in page {
                after = cookie;
                let mut child_path = path.to_vec();
                child_path.push(child.name().into());
                collect_removals(session, &child_path, &child, &nested, out)?;
            }
        }
    }
    out.push(offline::provider::Namespace {
        path: path.to_vec(),
        kind: if entry.is_directory() {
            "rmdir"
        } else {
            "unlink"
        },
        base: Some((
            entry.id().into(),
            entry
                .etag()
                .filter(|e| dav::strong_etag(e))
                .ok_or(Error::Conflict)?
                .into(),
        )),
        parents: parents.to_vec(),
        dependency: None,
    });
    Ok(())
}

fn collect_tree(
    session: &Observation<'_>,
    path: &[String],
    entry: &Entry,
    out: &mut Vec<(Vec<String>, Entry)>,
) -> Result<()> {
    if path.len() > 128 || out.len() >= 4096 {
        return Err(Error::Capacity);
    }
    out.push((path.to_vec(), entry.clone()));
    if entry.is_directory() {
        let snapshot = observe(session, path)?;
        let (id, etag) = snapshot.remote_parent()?;
        if id != entry.id() || Some(etag.as_str()) != entry.etag() {
            return Err(Error::Conflict);
        }
        let mut after = 0;
        loop {
            let page = snapshot.page(after)?;
            if page.is_empty() {
                break;
            }
            for (cookie, child) in page {
                after = cookie;
                let mut p = path.to_vec();
                p.push(child.name().into());
                collect_tree(session, &p, &child, out)?;
            }
        }
    }
    Ok(())
}

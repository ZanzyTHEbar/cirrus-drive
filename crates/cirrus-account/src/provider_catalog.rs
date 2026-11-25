//! Durable read-only projection of retained observations, never remote authority.
//!
//! All SQL uses the admitted state.db connection. No second opener is allowed
//! while a catalog transaction (or borrowed namespace inspection) is alive.
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{MountBinding, dav, offline};

pub(crate) const DDL: &str = "
CREATE TABLE fp_domains(domain TEXT PRIMARY KEY, instance TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, space TEXT NOT NULL, epoch TEXT NOT NULL, nextseq INTEGER NOT NULL);
CREATE TABLE fp_items(domain TEXT NOT NULL, id TEXT NOT NULL, remote TEXT NOT NULL, parent TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(domain,id), UNIQUE(domain,remote));
CREATE TABLE fp_generations(domain TEXT NOT NULL, generation TEXT NOT NULL, container TEXT NOT NULL, sort TEXT NOT NULL, provenance TEXT NOT NULL CHECK(provenance='retained'), capturedseq INTEGER NOT NULL, expiry INTEGER NOT NULL, PRIMARY KEY(domain,generation));
CREATE TABLE fp_generation_items(domain TEXT NOT NULL, generation TEXT NOT NULL, ordinal INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(domain,generation,ordinal));
CREATE TABLE fp_changes(domain TEXT NOT NULL, seq INTEGER NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind='update'), payload TEXT NOT NULL, PRIMARY KEY(domain,seq));
";

const ROOT: &str = "root";
const MAX_ITEMS: i64 = 4096;
const MAX_ROWS: i64 = 16384;
const MAX_BYTES: i64 = 32 * 1024 * 1024;
const MAX_CHANGES: i64 = 4096;
const TTL: i64 = 86400;
const PAGE: i64 = 32;

#[derive(Debug)]
pub(crate) enum Error {
    Unavailable,
    RetainedSpaceNotReady,
    PageExpired,
    AnchorExpired,
    VersionMismatch,
    Capacity,
    Cancelled,
    Internal,
    Deleted,
}
type Result<T> = std::result::Result<T, Error>;
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(e, _)
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DiskFull | rusqlite::ErrorCode::TooBig
                ) =>
            {
                Self::Capacity
            }
            _ => Self::Unavailable,
        }
    }
}
impl From<crate::AccountError> for Error {
    fn from(error: crate::AccountError) -> Self {
        if error.is_staging_full() {
            Self::Capacity
        } else {
            Self::Unavailable
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Item {
    pub id: String,
    pub remote: String,
    pub parent: String,
    pub name: String,
    pub directory: bool,
    pub etag: Option<String>,
    pub size: Option<u64>,
    pub modified: u64,
    // This payload is immutable in generation/change rows. Content identity is
    // remote+strongETag+size within the principal/Space bound domain.
    pub metadata_revision: String,
}
impl Item {
    pub(crate) fn from_entry(id: String, parent: String, entry: &crate::Entry) -> Result<Self> {
        let mut item = Self {
            id,
            parent,
            remote: entry.id().into(),
            name: entry.name().into(),
            directory: entry.is_directory(),
            etag: entry.etag().map(str::to_owned),
            size: entry.size(),
            modified: entry
                .modified()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Error::Unavailable)?
                .as_secs(),
            metadata_revision: String::new(),
        };
        item.metadata_revision = item.revision()?;
        Ok(item)
    }

    fn revision(&self) -> Result<String> {
        encode(&(&self.parent, &self.name, self.directory, self.modified))
    }
}
#[derive(Serialize, Deserialize)]
struct Token {
    v: u8,
    epoch: String,
    generation: String,
    ordinal: i64,
}
#[derive(Serialize, Deserialize)]
struct Anchor {
    v: u8,
    epoch: String,
    seq: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    baseline: Option<Token>,
}
#[derive(Serialize)]
pub(crate) struct Page {
    pub items: Vec<Item>,
    pub next: Option<String>,
    pub anchor: String,
}
#[derive(Serialize)]
pub(crate) struct Changes {
    pub items: Vec<Item>,
    pub deleted: Vec<String>,
    pub anchor: String,
    pub more: bool,
    /// Always false until a separately implemented authoritative refresh exists.
    pub authoritative: bool,
}
pub(crate) struct Catalog {
    pub binding: MountBinding,
    pub(crate) domain: String,
    pub(crate) epoch: String,
}
fn now() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Unavailable)?
        .as_secs()
        .try_into()
        .map_err(|_| Error::Unavailable)
}
fn opaque(conn: &Connection) -> Result<String> {
    Ok(conn.query_row("SELECT lower(hex(randomblob(16)))", [], |r| r.get(0))?)
}
fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| Error::Internal)
}
fn decode<T: for<'a> Deserialize<'a>>(text: &str) -> Result<T> {
    serde_json::from_str(text).map_err(|_| Error::Unavailable)
}
fn safe(text: &str) -> bool {
    !text.is_empty() && text.len() <= 1024 && !text.chars().any(char::is_control)
}
impl Catalog {
    /// Preparation requires a freshly authenticated application binding. It
    /// admits only previously activated retained data, never enables sync.
    pub fn prepare_authenticated(binding: &MountBinding) -> Result<String> {
        if binding.offline {
            return Err(Error::Unavailable);
        }
        Self::prepare_ready(binding)
    }

    #[cfg(test)]
    pub(super) fn prepare_fixture(binding: &MountBinding) -> Result<String> {
        Self::prepare_ready(binding)
    }

    fn ready(binding: &MountBinding, conn: &Connection) -> Result<()> {
        offline::check_retained_identity(conn, &binding.instance, &binding.space)?;
        let principal: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM account_identities WHERE instance=?1 AND issuer=?2 AND subject=?3)",
            params![binding.instance,binding.issuer,binding.subject], |r| r.get(0))?;
        if !principal {
            return Err(Error::Unavailable);
        }
        let activated: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_spaces WHERE instance=?1 AND space=?2 AND issuer=?3 AND subject=?4)",
            params![binding.instance,binding.space,binding.issuer,binding.subject], |r| r.get(0))?;
        let root_observed: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM snapshots WHERE instance=?1 AND space=?2 AND path='[]')",
            params![binding.instance, binding.space],
            |r| r.get(0),
        )?;
        if !activated || !root_observed {
            return Err(Error::RetainedSpaceNotReady);
        }
        offline::offline_directory_in(
            &binding.root,
            conn,
            &binding.instance,
            &binding.space,
            &[],
            Some((&binding.issuer, &binding.subject)),
        )?;
        Ok(())
    }

    fn prepare_ready(binding: &MountBinding) -> Result<String> {
        let mut conn = offline::database_in(&binding.root)?;
        let reservation = Self::reserve(&binding.root, &conn, 16384)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::ready(binding, &tx)?;
        // No unique tuple constraint exists in schema18: serialize lookup and
        // insertion under the same writer, and refuse pre-existing corruption.
        let domains = {
            let mut statement = tx.prepare(
                "SELECT domain FROM fp_domains WHERE instance=?1 AND issuer=?2 AND subject=?3 AND space=?4 LIMIT 2")?;
            statement
                .query_map(
                    params![
                        binding.instance,
                        binding.issuer,
                        binding.subject,
                        binding.space
                    ],
                    |r| r.get::<_, String>(0),
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let domain = match domains.as_slice() {
            [] => offline::namespace_token()?,
            [domain] if safe(domain) => domain.clone(),
            _ => return Err(Error::Unavailable),
        };
        Self::initialize(binding, &domain, &tx)?;
        if let Some(reservation) = &reservation {
            reservation.validate(&tx)?;
        }
        tx.commit()?;
        Ok(domain)
    }

    /// Copy the immutable saved tuple, then CLOSE this connection before any
    /// account helper opens state.db (POSIX close can release process locks).
    pub fn stored(
        root: &crate::account_storage::StorageRoot,
        domain: &str,
    ) -> Result<(String, String, String, String, String)> {
        if !safe(domain) {
            return Err(Error::Unavailable);
        }
        let conn = offline::database_in(root)?;
        conn.query_row(
            "SELECT instance,issuer,subject,space,epoch FROM fp_domains WHERE domain=?1",
            [domain],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?
        .ok_or(Error::Unavailable)
    }

    pub fn stored_domains(
        root: &crate::account_storage::StorageRoot,
    ) -> Result<Vec<(String, String, String)>> {
        let conn = offline::database_in(root)?;
        let mut statement =
            conn.prepare("SELECT domain,instance,space FROM fp_domains ORDER BY domain LIMIT 17")?;
        let rows = statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if rows.len() > 16 {
            return Err(Error::Capacity);
        }
        Ok(rows)
    }

    pub fn resume(binding: &MountBinding, domain: &str, epoch: &str) -> Result<Self> {
        if !binding.offline || !safe(domain) || !safe(epoch) {
            return Err(Error::Unavailable);
        }
        let mut conn = offline::database_in(&binding.root)?;
        let tx = conn.transaction()?;
        let catalog = Self {
            binding: binding.clone(),
            domain: domain.into(),
            epoch: epoch.into(),
        };
        Self::ready(binding, &tx)?;
        catalog.verify(&tx)?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM fp_domains WHERE instance=?1 AND issuer=?2 AND subject=?3 AND space=?4",
            params![binding.instance,binding.issuer,binding.subject,binding.space], |r| r.get(0))?;
        if count != 1 {
            return Err(Error::Unavailable);
        }
        catalog.saved(&tx, ROOT)?;
        Ok(catalog)
    }

    fn initialize(binding: &MountBinding, domain: &str, tx: &Connection) -> Result<String> {
        let old: Option<(String, String, String, String, String)> = tx
            .query_row(
                "SELECT instance,issuer,subject,space,epoch FROM fp_domains WHERE domain=?1",
                [domain],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let epoch = if let Some((instance, issuer, subject, space, epoch)) = old {
            if (instance, issuer, subject, space)
                != (
                    binding.instance.clone(),
                    binding.issuer.clone(),
                    binding.subject.clone(),
                    binding.space.clone(),
                )
            {
                return Err(Error::Unavailable);
            }
            epoch
        } else {
            let domains: i64 = tx.query_row("SELECT count(*) FROM fp_domains", [], |r| r.get(0))?;
            if domains >= 16 {
                return Err(Error::Capacity);
            }
            let epoch = opaque(&tx)?;
            tx.execute(
                "INSERT INTO fp_domains VALUES(?1,?2,?3,?4,?5,?6,0)",
                params![
                    domain,
                    binding.instance,
                    binding.issuer,
                    binding.subject,
                    binding.space,
                    epoch
                ],
            )?;
            let root = Item {
                id: ROOT.into(),
                remote: String::new(),
                parent: ROOT.into(),
                name: "Space".into(),
                directory: true,
                etag: None,
                size: None,
                modified: 0,
                metadata_revision: epoch.clone(),
            };
            tx.execute(
                "INSERT INTO fp_items VALUES(?1,'root','','root',?2)",
                params![domain, encode(&root)?],
            )?;
            epoch
        };
        Ok(epoch)
    }
    pub(crate) fn reserve(
        root: &crate::account_storage::StorageRoot,
        conn: &Connection,
        bytes: u64,
    ) -> Result<Option<crate::storage::sql_reservation::SqlReservation>> {
        let reservation = crate::storage::sql_reservation::SqlReservation::begin_in(
            root,
            crate::storage::sql_reservation::Store::State,
            Some(conn),
            0,
            bytes,
            false,
        )?;
        if let Some(r) = &reservation {
            r.bound_pages(conn)?;
        }
        Ok(reservation)
    }
    pub(crate) fn verify(&self, conn: &Connection) -> Result<()> {
        offline::check_retained_identity(conn, &self.binding.instance, &self.binding.space)?;
        let matches: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM fp_domains d JOIN account_identities a ON a.instance=d.instance AND a.issuer=d.issuer AND a.subject=d.subject JOIN sync_spaces s ON s.instance=d.instance AND s.space=d.space AND s.issuer=d.issuer AND s.subject=d.subject WHERE d.domain=?1 AND d.epoch=?2 AND d.instance=?3 AND d.space=?4 AND d.issuer=?5 AND d.subject=?6)",
            params![self.domain,self.epoch,self.binding.instance,self.binding.space,self.binding.issuer,self.binding.subject], |r| r.get(0))?;
        if !matches {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    pub(crate) fn saved(&self, conn: &Connection, id: &str) -> Result<Item> {
        let text: Option<String> = conn
            .query_row(
                "SELECT payload FROM fp_items WHERE domain=?1 AND id=?2",
                params![self.domain, id],
                |r| r.get(0),
            )
            .optional()?;
        decode(&text.ok_or(Error::Unavailable)?)
    }
    pub(crate) fn path(&self, conn: &Connection, id: &str) -> Result<Vec<String>> {
        let mut path = Vec::new();
        let mut ancestors = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut current = id.to_owned();
        while current != ROOT {
            if !seen.insert(current.clone()) || path.len() >= 128 {
                return Err(Error::Unavailable);
            }
            let item = self.saved(conn, &current)?;
            if !safe(&item.name)
                || matches!(item.name.as_str(), "." | "..")
                || item.name.contains('/')
            {
                return Err(Error::Unavailable);
            }
            current = item.parent.clone();
            path.push(item.name.clone());
            ancestors.push(item);
        }
        path.reverse();
        ancestors.reverse();
        // The retained namespace validates its own ancestor IDs. Independently
        // bind those IDs to every opaque catalog parent: a replacement directory
        // at the same path must not inherit the old parent's children/FPID.
        for (index, item) in ancestors
            .iter()
            .enumerate()
            .take(ancestors.len().saturating_sub(1))
        {
            let observed = offline::offline_directory_in(
                &self.binding.root,
                conn,
                &self.binding.instance,
                &self.binding.space,
                &path[..index],
                Some((&self.binding.issuer, &self.binding.subject)),
            )?;
            if !item.directory
                || !observed.get(&item.name)?.is_some_and(|entry| {
                    entry.is_directory()
                        && dav::valid_remote_id(entry.id())
                        && entry.id() == item.remote
                })
            {
                return Err(Error::Unavailable);
            }
        }
        Ok(path)
    }
    fn observed(&self, conn: &Connection, id: &str, capture_container: bool) -> Result<Item> {
        let mut saved = self.saved(conn, id)?;
        let path = self.path(conn, id)?;
        if id == ROOT {
            offline::offline_directory_in(
                &self.binding.root,
                conn,
                &self.binding.instance,
                &self.binding.space,
                &[],
                Some((&self.binding.issuer, &self.binding.subject)),
            )?;
            return Ok(saved);
        }
        let (name, parent) = path.split_last().ok_or(Error::Unavailable)?;
        let entries = offline::offline_directory_in(
            &self.binding.root,
            conn,
            &self.binding.instance,
            &self.binding.space,
            parent,
            Some((&self.binding.issuer, &self.binding.subject)),
        )?;
        let entry = entries.get(name)?.ok_or(Error::Unavailable)?;
        if !dav::valid_remote_id(entry.id())
            || entry.id() != saved.remote
            || entry.is_directory() != saved.directory
        {
            return Err(Error::Unavailable);
        }
        if capture_container && saved.directory {
            // A directory validator changes when its children change; it is not
            // the directory's resource identity. Only capture may publish this
            // refresh, atomically with reconciliation of the complete children.
            if entry.etag().is_some_and(|e| !safe(e))
                || entry.size().is_some_and(|s| s > i64::MAX as u64)
            {
                return Err(Error::Unavailable);
            }
            saved.etag = entry.etag().map(str::to_owned);
            saved.size = entry.size();
            saved.modified = entry
                .modified()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Error::Unavailable)?
                .as_secs();
            saved.metadata_revision = saved.revision()?;
        } else if entry.etag() != saved.etag.as_deref() || entry.size() != saved.size {
            return Err(Error::Unavailable);
        }
        Ok(saved)
    }
    fn reclaim(&self, conn: &Connection) -> Result<()> {
        let cutoff = now()?;
        conn.execute("DELETE FROM fp_generation_items WHERE domain=?1 AND generation IN (SELECT generation FROM fp_generations WHERE domain=?1 AND expiry<=?2)", params![self.domain,cutoff])?;
        conn.execute(
            "DELETE FROM fp_generations WHERE domain=?1 AND expiry<=?2",
            params![self.domain, cutoff],
        )?;
        let seq: i64 = conn.query_row(
            "SELECT nextseq FROM fp_domains WHERE domain=?1",
            [&self.domain],
            |r| r.get(0),
        )?;
        conn.execute(
            "DELETE FROM fp_changes WHERE domain=?1 AND seq<=?2",
            params![self.domain, seq - MAX_CHANGES],
        )?;
        conn.execute(
            "DELETE FROM fp_deletions WHERE domain=?1 AND seq<=?2",
            params![self.domain, seq - MAX_CHANGES],
        )?;
        Ok(())
    }
    pub(crate) fn quotas(&self, conn: &Connection) -> Result<()> {
        let (items,gens,rows,bytes): (i64,i64,i64,i64) = conn.query_row(
            "SELECT (SELECT count(*) FROM fp_items WHERE domain=?1),(SELECT count(*) FROM fp_generations WHERE domain=?1),(SELECT count(*) FROM fp_generation_items WHERE domain=?1),coalesce((SELECT sum(length(CAST(payload AS BLOB))) FROM fp_items WHERE domain=?1),0)+coalesce((SELECT sum(length(CAST(payload AS BLOB))) FROM fp_generation_items WHERE domain=?1),0)+coalesce((SELECT sum(length(CAST(payload AS BLOB))) FROM fp_changes WHERE domain=?1),0)+coalesce((SELECT sum(length(CAST(record AS BLOB))+length(CAST(descriptor AS BLOB))+coalesce(length(CAST(result AS BLOB)),0)) FROM fp_requests WHERE domain=?1),0)+coalesce((SELECT sum(length(CAST(id AS BLOB))+32) FROM fp_deletions WHERE domain=?1),0)",
            [&self.domain],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        if items > MAX_ITEMS || gens > 16 || rows > MAX_ROWS || bytes > MAX_BYTES {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    /// Capture one observed container. Absence never proves deletion. If a
    /// published child would disappear, rollback the entire capture instead.
    pub fn capture(
        &self,
        container: &str,
        sort: &str,
        cancelled: impl Fn() -> bool,
    ) -> Result<String> {
        if !matches!(sort, "name" | "date") {
            return Err(Error::Unavailable);
        }
        let mut conn = offline::database_in(&self.binding.root)?;
        let reservation = Self::reserve(&self.binding.root, &conn, MAX_BYTES as u64 * 2)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.verify(&tx)?;
        self.reclaim(&tx)?;
        let generation = opaque(&tx)?;
        let mut count = 0i64;
        if container != "working-set" {
            let item = self.observed(&tx, container, true)?;
            if !item.directory {
                return Err(Error::Unavailable);
            }
            let path = self.path(&tx, container)?;
            let candidates = crate::provider_mutation::correlation_candidates(self, &tx)?;
            let snapshot = offline::offline_directory_in(
                &self.binding.root,
                &tx,
                &self.binding.instance,
                &self.binding.space,
                &path,
                Some((&self.binding.issuer, &self.binding.subject)),
            )?;
            if item != self.saved(&tx, container)? {
                let payload = encode(&item)?;
                if payload.len() > 16384 {
                    return Err(Error::Capacity);
                }
                if tx.execute("UPDATE fp_domains SET nextseq=nextseq+1 WHERE domain=?1 AND nextseq<9223372036854775807",[&self.domain])?!=1 {return Err(Error::Capacity);}
                let seq: i64 = tx.query_row(
                    "SELECT nextseq FROM fp_domains WHERE domain=?1",
                    [&self.domain],
                    |r| r.get(0),
                )?;
                tx.execute(
                    "INSERT INTO fp_changes VALUES(?1,?2,?3,'update',?4)",
                    params![self.domain, seq, item.id, payload],
                )?;
                tx.execute(
                    "UPDATE fp_items SET payload=?3 WHERE domain=?1 AND id=?2",
                    params![self.domain, item.id, payload],
                )?;
            }
            let mut after = 0;
            let mut seen = std::collections::HashSet::new();
            loop {
                if cancelled() {
                    return Err(Error::Cancelled);
                }
                let page = snapshot.page(after)?;
                if page.is_empty() {
                    break;
                }
                for (cookie, entry) in page {
                    after = cookie;
                    // Local staging is not a server identity. The disappearance
                    // check below also refuses replacing a published remote item
                    // with a local overlay, rather than exposing underlying bytes.
                    if !dav::valid_remote_id(entry.id()) {
                        continue;
                    }
                    if !safe(entry.id())
                        || !safe(entry.name())
                        || entry.name().contains('/')
                        || matches!(entry.name(), "." | "..")
                        || entry.etag().is_some_and(|e| !safe(e))
                        || entry.size().is_some_and(|size| size > i64::MAX as u64)
                        || (!entry.is_directory()
                            && (!entry.etag().is_some_and(dav::strong_etag)
                                || entry.size().is_none()))
                    {
                        return Err(Error::Unavailable);
                    }
                    if !seen.insert(entry.id().to_owned()) {
                        return Err(Error::Unavailable);
                    }
                    let old: Option<String> = tx
                        .query_row(
                            "SELECT payload FROM fp_items WHERE domain=?1 AND remote=?2",
                            params![self.domain, entry.id()],
                            |r| r.get(0),
                        )
                        .optional()?;
                    let observed_old: Option<Item> = old.as_deref().map(decode).transpose()?;
                    let alias = crate::provider_mutation::correlated_item(
                        self,
                        &tx,
                        container,
                        &path,
                        &candidates,
                        &entry,
                    )?;
                    if alias
                        .as_ref()
                        .zip(observed_old.as_ref())
                        .is_some_and(|(a, b)| a.id != b.id)
                    {
                        return Err(Error::Unavailable);
                    }
                    let old = alias.or(observed_old);
                    if old
                        .as_ref()
                        .is_some_and(|item| item.directory != entry.is_directory())
                    {
                        // FileProvider cannot update an existing identifier
                        // across the file/folder boundary. Retained observations
                        // cannot authorize the deletion/recreation that requires.
                        return Err(Error::Unavailable);
                    }
                    if let Some(old) = &old
                        && old.remote == entry.id()
                        && (old.parent != container || old.name != entry.name())
                    {
                        let old_path = self.path(&tx, &old.id)?;
                        let (old_name, old_parent) =
                            old_path.split_last().ok_or(Error::Unavailable)?;
                        let observed = offline::offline_directory_in(
                            &self.binding.root,
                            &tx,
                            &self.binding.instance,
                            &self.binding.space,
                            old_parent,
                            Some((&self.binding.issuer, &self.binding.subject)),
                        )?;
                        if observed
                            .get(old_name)?
                            .is_some_and(|e| e.id() == entry.id())
                        {
                            // Same remote ID concurrently at two observed paths.
                            return Err(Error::Unavailable);
                        }
                    }
                    let item = Item::from_entry(
                        old.as_ref().map(|i| i.id.clone()).unwrap_or(opaque(&tx)?),
                        container.into(),
                        &entry,
                    )?;
                    let payload = encode(&item)?;
                    if payload.len() > 16384 {
                        return Err(Error::Capacity);
                    }
                    if old.as_ref() != Some(&item) {
                        if tx.execute("UPDATE fp_domains SET nextseq=nextseq+1 WHERE domain=?1 AND nextseq<9223372036854775807",[&self.domain])?!=1 {return Err(Error::Capacity);}
                        let seq: i64 = tx.query_row(
                            "SELECT nextseq FROM fp_domains WHERE domain=?1",
                            [&self.domain],
                            |r| r.get(0),
                        )?;
                        tx.execute(
                            "INSERT INTO fp_changes VALUES(?1,?2,?3,'update',?4)",
                            params![self.domain, seq, item.id, payload],
                        )?;
                        tx.execute("INSERT INTO fp_items VALUES(?1,?2,?3,?4,?5) ON CONFLICT(domain,id) DO UPDATE SET remote=excluded.remote,parent=excluded.parent,payload=excluded.payload",
                            params![self.domain,item.id,item.remote,item.parent,payload])?;
                    }
                    count += 1;
                    if count > MAX_ITEMS {
                        return Err(Error::Capacity);
                    }
                    tx.execute(
                        "INSERT INTO fp_generation_items VALUES(?1,?2,?3,?4)",
                        params![self.domain, generation, count, payload],
                    )?;
                }
            }
            let missing: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM fp_items i WHERE i.domain=?1 AND i.parent=?2 AND i.id<>'root' AND NOT EXISTS(SELECT 1 FROM fp_generation_items g WHERE g.domain=i.domain AND g.generation=?3 AND json_extract(g.payload,'$.id')=i.id))",
                params![self.domain,container,generation],|r|r.get(0))?;
            if missing {
                return Err(Error::Unavailable);
            }
        } else {
            let mut statement = tx.prepare(
                "SELECT payload FROM fp_items WHERE domain=?1 AND id<>'root' ORDER BY id",
            )?;
            for payload in statement.query_map([&self.domain], |r| r.get::<_, String>(0))? {
                if cancelled() {
                    return Err(Error::Cancelled);
                }
                count += 1;
                tx.execute(
                    "INSERT INTO fp_generation_items VALUES(?1,?2,?3,?4)",
                    params![self.domain, generation, count, payload?],
                )?;
            }
        }
        // Freeze ordering/payloads in the persisted generation, not a live query
        // whose offsets drift with subsequent captures.
        tx.execute("CREATE TEMP TABLE fp_sort AS SELECT payload FROM fp_generation_items WHERE domain=?1 AND generation=?2 ORDER BY CASE WHEN ?3='date' THEN json_extract(payload,'$.modified') END DESC,json_extract(payload,'$.name'),json_extract(payload,'$.id')",params![self.domain,generation,sort])?;
        tx.execute(
            "DELETE FROM fp_generation_items WHERE domain=?1 AND generation=?2",
            params![self.domain, generation],
        )?;
        tx.execute(
            "INSERT INTO fp_generation_items SELECT ?1,?2,rowid,payload FROM fp_sort",
            params![self.domain, generation],
        )?;
        let seq: i64 = tx.query_row(
            "SELECT nextseq FROM fp_domains WHERE domain=?1",
            [&self.domain],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO fp_generations VALUES(?1,?2,?3,?4,'retained',?5,?6)",
            params![self.domain, generation, container, sort, seq, now()? + TTL],
        )?;
        self.reclaim(&tx)?;
        self.quotas(&tx)?;
        if let Some(r) = &reservation {
            r.validate(&tx)?;
        }
        if cancelled() {
            return Err(Error::Cancelled);
        }
        tx.commit()?;
        encode(&Token {
            v: 1,
            epoch: self.epoch.clone(),
            generation,
            ordinal: 0,
        })
    }
    pub fn page(&self, container: &str, token: &str) -> Result<Page> {
        let token: Token = serde_json::from_str(token).map_err(|_| Error::PageExpired)?;
        if token.v != 1 || token.epoch != self.epoch || token.ordinal < 0 {
            return Err(Error::PageExpired);
        }
        let mut conn = offline::database_in(&self.binding.root)?;
        let tx = conn.transaction()?;
        self.verify(&tx)?;
        let seq:Option<i64>=tx.query_row("SELECT capturedseq FROM fp_generations WHERE domain=?1 AND generation=?2 AND container=?3 AND expiry>?4",
            params![self.domain,token.generation,container,now()?],|r|r.get(0)).optional()?;
        let seq = seq.ok_or(Error::PageExpired)?;
        let mut items = Vec::new();
        let mut ordinal = token.ordinal;
        let mut s=tx.prepare("SELECT ordinal,payload FROM fp_generation_items WHERE domain=?1 AND generation=?2 AND ordinal>?3 ORDER BY ordinal LIMIT ?4")?;
        for row in s.query_map(params![self.domain, token.generation, ordinal, PAGE], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })? {
            let (n, payload) = row?;
            ordinal = n;
            items.push(decode(&payload)?);
        }
        let more:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM fp_generation_items WHERE domain=?1 AND generation=?2 AND ordinal>?3)",params![self.domain,token.generation,ordinal],|r|r.get(0))?;
        let next = if more {
            Some(encode(&Token { ordinal, ..token })?)
        } else {
            None
        };
        Ok(Page {
            items,
            next,
            anchor: encode(&Anchor {
                v: 1,
                epoch: self.epoch.clone(),
                seq,
                baseline: None,
            })?,
        })
    }
    pub fn lookup(&self, id: &str) -> Result<Item> {
        let mut conn = offline::database_in(&self.binding.root)?;
        let tx = conn.transaction()?;
        self.verify(&tx)?;
        let deleted:bool=tx.query_row("SELECT NOT EXISTS(SELECT 1 FROM fp_items WHERE domain=?1 AND id=?2) AND EXISTS(SELECT 1 FROM fp_deletions WHERE domain=?1 AND id=?2)",params![self.domain,id],|r|r.get(0))?;
        if deleted {
            return Err(Error::Deleted);
        }
        self.observed(&tx, id, false)
    }
    pub fn changes(&self, anchor: Option<&str>, cancelled: impl Fn() -> bool) -> Result<Changes> {
        if cancelled() {
            return Err(Error::Cancelled);
        }
        if anchor.is_none() {
            let token = self.capture("working-set", "name", &cancelled)?;
            return self.baseline(&token);
        }
        let initial: Anchor = serde_json::from_str(anchor.ok_or(Error::AnchorExpired)?)
            .map_err(|_| Error::AnchorExpired)?;
        if initial.v != 1 || initial.epoch != self.epoch {
            return Err(Error::AnchorExpired);
        }
        if let Some(token) = initial.baseline {
            return self.baseline(&encode(&token)?);
        }
        let mut conn = offline::database_in(&self.binding.root)?;
        let tx = conn.transaction()?;
        self.verify(&tx)?;
        let current: i64 = tx.query_row(
            "SELECT nextseq FROM fp_domains WHERE domain=?1",
            [&self.domain],
            |r| r.get(0),
        )?;
        let seq = if let Some(anchor) = anchor {
            let a: Anchor = serde_json::from_str(anchor).map_err(|_| Error::AnchorExpired)?;
            if a.v != 1
                || a.epoch != self.epoch
                || a.seq < 0
                || a.seq > current
                || a.seq < current - MAX_CHANGES
            {
                return Err(Error::AnchorExpired);
            }
            a.seq
        } else {
            // Baseline is enumerated through a durable working-set generation;
            // callers use its captured anchor, rather than expiring nil forever.
            return Err(Error::Unavailable);
        };
        let mut items = Vec::new();
        let mut deleted = Vec::new();
        let mut last = seq;
        let mut s = tx.prepare(
            "SELECT seq,payload,0 FROM fp_changes WHERE domain=?1 AND seq>?2 UNION ALL SELECT seq,id,1 FROM fp_deletions WHERE domain=?1 AND seq>?2 ORDER BY seq LIMIT ?3",
        )?;
        for row in s.query_map(params![self.domain, seq, PAGE], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
            ))
        })? {
            if cancelled() {
                return Err(Error::Cancelled);
            }
            let (n, p, removed) = row?;
            last = n;
            if removed {
                deleted.push(p);
            } else {
                items.push(decode(&p)?);
            }
        }
        Ok(Changes {
            items,
            deleted,
            anchor: encode(&Anchor {
                v: 1,
                epoch: self.epoch.clone(),
                seq: last,
                baseline: None,
            })?,
            more: last < current,
            authoritative: false,
        })
    }
    fn baseline(&self, token: &str) -> Result<Changes> {
        let page = self.page("working-set", token).map_err(|e| match e {
            Error::PageExpired => Error::AnchorExpired,
            other => other,
        })?;
        let mut anchor: Anchor = decode(&page.anchor)?;
        anchor.baseline = page.next.as_deref().map(decode).transpose()?;
        Ok(Changes {
            items: page.items,
            deleted: Vec::new(),
            anchor: encode(&anchor)?,
            more: page.next.is_some(),
            authoritative: false,
        })
    }
    pub fn open_version(
        &self,
        accounts: &crate::Accounts,
        id: &str,
        etag: &str,
        size: u64,
    ) -> Result<crate::FileVersion> {
        let item = self.lookup(id)?;
        if item.directory || item.etag.as_deref() != Some(etag) || item.size != Some(size) {
            return Err(Error::VersionMismatch);
        }
        // End the SQL reader before invoking existing engine APIs which open
        // their own admitted connections; never nest them under a catalog writer.
        let path = {
            let mut conn = offline::database_in(&self.binding.root)?;
            let tx = conn.transaction()?;
            self.verify(&tx)?;
            self.path(&tx, id)?
        };
        let version =
            accounts.mount_open_file(&self.binding.instance, &self.binding, &path, &item.remote)?;
        if version.id() != item.remote || version.etag() != etag || version.size() != size {
            return Err(Error::VersionMismatch);
        }
        Ok(version)
    }
}

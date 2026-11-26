//! Private ephemeral complete listings, independent of dirty objects and clean ranges.

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use rusqlite::{Connection, OptionalExtension, params};
use rustix::fs::{self, AtFlags, Mode, OFlags};

use crate::account_storage::StorageRoot;
use crate::{AccountError, Entry};

const PAGE: usize = 32;
const MAX_SNAPSHOTS: usize = 256;
pub(crate) const SQLITE_BYTES: u64 = 4096 * 4096;
static LIVE: AtomicUsize = AtomicUsize::new(0);

fn unavailable() -> AccountError {
    AccountError::new("directory snapshot unavailable or capacity exhausted")
}

struct Slot;
impl Drop for Slot {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Storage {
    conn: Connection,
    _file: Arc<std::fs::File>,
    // Drop order closes SQLite and the original anonymous fd before releasing
    // its allowance. This does not change the outer Arc's uniqueness rules.
    reservation: Option<crate::storage::namespace::NamespaceReservation>,
    root: StorageRoot,
    _slot: Slot,
    count: usize,
    bytes: usize,
    parent: Option<String>,
    parent_etag: Option<String>,
    #[cfg(feature = "fault-injection")]
    publication_fault: bool,
}

impl Storage {
    fn validate_allocation(&self) -> Result<(), AccountError> {
        if let Some(reservation) = &self.reservation {
            reservation.validate_file(&self._file)?;
        }
        Ok(())
    }
}

/// An immutable complete listing backed by an anonymous private file.
#[derive(Clone)]
pub struct DirectorySnapshot(Arc<Mutex<Storage>>);

/// One directory enumeration cookie and its already assigned FUSE identity.
pub struct DirectoryChild {
    pub cookie: u64,
    pub inode: u64,
    pub directory: bool,
    pub name: String,
}

#[cfg(target_os = "macos")]
fn open_darwin_snapshot(
    root: &StorageRoot,
    directory: &std::os::fd::OwnedFd,
    name: &str,
    file: &std::os::fd::OwnedFd,
) -> Result<Connection, AccountError> {
    // Created exclusively by this invocation. Install cleanup BEFORE admission;
    // after SQLite opens, its connection drops before this borrowed-FD guard.
    // Never reopen an existing SQLite inode: close would release POSIX locks.
    struct Candidate<'a> {
        directory: &'a std::os::fd::OwnedFd,
        file: &'a std::os::fd::OwnedFd,
        name: &'a str,
        named: bool,
    }
    impl Drop for Candidate<'_> {
        fn drop(&mut self) {
            if !self.named {
                return;
            }
            let Ok(held) = fs::fstat(self.file) else {
                return;
            };
            let Ok(named) = fs::statat(self.directory, self.name, AtFlags::SYMLINK_NOFOLLOW) else {
                return;
            };
            let safe = |s: &fs::Stat| {
                fs::FileType::from_raw_mode(s.st_mode) == fs::FileType::RegularFile
                    && s.st_uid == rustix::process::geteuid().as_raw()
                    && s.st_mode & 0o7777 == 0o600
                    && s.st_nlink == 1
            };
            if safe(&held)
                && safe(&named)
                && (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
                && fs::unlinkat(self.directory, self.name, AtFlags::empty()).is_ok()
            {
                let _ = fs::fsync(self.directory);
            }
        }
    }
    let mut candidate = Candidate {
        directory,
        file,
        name,
        named: true,
    };
    crate::ownership::darwin_acl::check_file(file).map_err(|_| unavailable())?;
    let path = root
        .private_state_path()
        .join("directory-snapshots")
        .join(name);
    let check = || -> Result<(), AccountError> {
        root.revalidate()?;
        let held_dir = fs::fstat(directory).map_err(|_| unavailable())?;
        let named_dir = fs::statat(
            root.directory(),
            "directory-snapshots",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| unavailable())?;
        if (
            held_dir.st_dev,
            held_dir.st_ino,
            held_dir.st_mode,
            held_dir.st_uid,
        ) != (
            named_dir.st_dev,
            named_dir.st_ino,
            named_dir.st_mode,
            named_dir.st_uid,
        ) {
            return Err(unavailable());
        }
        crate::ownership::darwin_acl::check_directory(directory).map_err(|_| unavailable())?;
        let held = fs::fstat(file).map_err(|_| unavailable())?;
        let named =
            fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| unavailable())?;
        let acl = crate::ownership::darwin_acl::checked_path(&path).map_err(|_| unavailable())?;
        for stat in [&held, &named] {
            if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
                || stat.st_uid != rustix::process::geteuid().as_raw()
                || stat.st_mode & 0o7777 != 0o600
                || stat.st_nlink != 1
                || (
                    stat.st_dev as u64,
                    stat.st_ino as u64,
                    stat.st_mode as u32,
                    stat.st_uid,
                    stat.st_nlink as u64,
                ) != (
                    acl.st_dev as u64,
                    acl.st_ino as u64,
                    acl.st_mode as u32,
                    acl.st_uid,
                    acl.st_nlink as u64,
                )
            {
                return Err(unavailable());
            }
        }
        Ok(())
    };
    check()?;
    let conn = Connection::open_with_flags_and_vfs(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        "unix-posix",
    )
    .map_err(|_| unavailable())?;
    crate::sqlite_open::check_unmoved(&conn).map_err(|_| unavailable())?;
    check()?;
    conn.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;")
        .map_err(|_| unavailable())?;
    check()?;
    crate::sqlite_open::check_unmoved(&conn).map_err(|_| unavailable())?;
    fs::unlinkat(directory, name, AtFlags::empty()).map_err(|_| unavailable())?;
    candidate.named = false;
    fs::fsync(directory).map_err(|_| unavailable())?;
    Ok(conn)
}

impl DirectorySnapshot {
    pub(crate) fn storage_root(&self) -> Result<StorageRoot, AccountError> {
        Ok(self.0.lock().map_err(|_| unavailable())?.root.clone())
    }

    /// Tests emptiness of a complete snapshot, never a partially received page.
    pub fn is_empty(&self) -> Result<bool, AccountError> {
        Ok(self.0.lock().map_err(|_| unavailable())?.count == 0)
    }

    /// Whether two owners refer to the same immutable published observation.
    pub fn same_observation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn empty_in(root: &StorageRoot) -> Result<Self, AccountError> {
        LIVE.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_SNAPSHOTS).then_some(n + 1)
        })
        .map_err(|_| unavailable())?;
        let slot = Slot;
        let reservation;
        let directory = root.directory_snapshots_dir()?;
        let name = crate::offline::namespace_token()?;
        let file = crate::ownership::open_private_file(
            &directory,
            name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| unavailable())?;
        // SQLite resolves /proc descriptor paths to the original filename. Open
        // while that exclusively created name still exists, then unlink before
        // allocating contents; opening an O_TMPFILE alias can create a new file.
        #[cfg(target_os = "linux")]
        let opened =
            Connection::open(format!("/proc/self/fd/{}", file.as_raw_fd())).and_then(|conn| {
                conn.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;")?;
                Ok(conn)
            });
        #[cfg(target_os = "linux")]
        let conn = {
            fs::unlinkat(&directory, name.as_str(), AtFlags::empty()).map_err(|_| unavailable())?;
            fs::fsync(&directory).map_err(|_| unavailable())?;
            opened.map_err(|_| unavailable())?
        };
        #[cfg(target_os = "macos")]
        let conn = open_darwin_snapshot(root, &directory, &name, &file)?;
        let file = crate::storage::track(
            root,
            std::fs::File::from(file),
            crate::storage::AnonymousKind::Directory,
        );
        reservation = crate::storage::namespace::NamespaceReservation::begin_in(root, &file)?;
        // No durable state or journal: an incomplete scratch listing is never
        // published, and a process crash closes its last anonymous descriptor.
        conn.execute_batch("PRAGMA page_size=4096; PRAGMA cache_size=-128; PRAGMA mmap_size=0; PRAGMA max_page_count=4096; CREATE TABLE entries(seq INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,entry TEXT NOT NULL,inode INTEGER NOT NULL DEFAULT 0);").map_err(|_| unavailable())?;
        if let Some(reservation) = &reservation {
            reservation.validate_file(&file)?;
        }
        Ok(Self(Arc::new(Mutex::new(Storage {
            root: root.clone(),
            conn,
            _file: file,
            reservation,
            _slot: slot,
            count: 0,
            bytes: 2,
            parent: None,
            parent_etag: None,
            #[cfg(feature = "fault-injection")]
            publication_fault: false,
        }))))
    }

    fn unique(&mut self) -> Result<&mut Storage, AccountError> {
        let state = Arc::get_mut(&mut self.0)
            .ok_or_else(unavailable)?
            .get_mut()
            .map_err(|_| unavailable())?;
        // Owners created while disabled must reserve before later mutation
        // under enabled policy. Immutable retained readers need no new charge.
        if state.reservation.is_none() {
            state.reservation = crate::storage::namespace::NamespaceReservation::begin_in(
                &state.root,
                &state._file,
            )?;
        }
        Ok(state)
    }

    pub(crate) fn insert(&mut self, entry: &Entry) -> Result<(), AccountError> {
        let encoded = serde_json::to_string(entry).map_err(|_| unavailable())?;
        let state = self.unique()?;
        if state.count >= crate::dav::MAX_ENTRIES
            || state.bytes + encoded.len() + 1 > crate::dav::MAX_METADATA
        {
            return Err(AccountError::new("directory metadata exceeds its bound"));
        }
        state
            .conn
            .execute(
                "INSERT INTO entries(name,entry) VALUES(?1,?2)",
                params![entry.name(), encoded],
            )
            .map_err(|_| {
                AccountError::new("duplicate DAV child or directory snapshot capacity exhausted")
            })?;
        state.count += 1;
        state.bytes += encoded.len() + 1;
        state.validate_allocation()
    }

    pub(crate) fn begin_pending(&mut self) -> Result<(), AccountError> {
        let state = self.unique()?;
        state
            .conn
            .execute_batch("CREATE TABLE pending(name TEXT PRIMARY KEY,entry TEXT);")
            .map_err(|_| unavailable())?;
        state.validate_allocation()
    }

    pub(crate) fn reset_pending(&mut self, name: &str) -> Result<(), AccountError> {
        let state = self.unique()?;
        state
            .conn
            .execute("DELETE FROM pending WHERE name=?1", [name])
            .map_err(|_| unavailable())?;
        state.validate_allocation()
    }

    pub(crate) fn pending(
        &mut self,
        name: &str,
        entry: Option<&Entry>,
    ) -> Result<(), AccountError> {
        let encoded = entry
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| unavailable())?;
        if encoded
            .as_ref()
            .is_some_and(|json| json.len() > crate::dav::MAX_METADATA)
        {
            return Err(unavailable());
        }
        let state = self.unique()?;
        state.conn.execute("INSERT INTO pending(name,entry) VALUES(?1,?2) ON CONFLICT(name) DO UPDATE SET entry=excluded.entry", params![name,encoded]).map_err(|_| unavailable())?;
        state.validate_allocation()
    }

    // Remove only an observed base entry, not a pending local replacement.
    // Later synced journal resets must not expose that deleted base again.
    pub(crate) fn remove_observed(&mut self, name: &str) -> Result<(), AccountError> {
        let state = self.unique()?;
        let bytes: Option<usize> = state
            .conn
            .query_row(
                "SELECT length(CAST(entry AS BLOB))+1 FROM entries WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| unavailable())?;
        if let Some(bytes) = bytes {
            state
                .conn
                .execute("DELETE FROM entries WHERE name=?1", [name])
                .map_err(|_| unavailable())?;
            state.count -= 1;
            state.bytes -= bytes;
        }
        state.validate_allocation()
    }

    pub(crate) fn finish_pending(&mut self) -> Result<(), AccountError> {
        let state = self.unique()?;
        let (count, bytes): (usize,usize) = state.conn.query_row("SELECT count(*),coalesce(sum(length(CAST(entry AS BLOB))+1),0)+2 FROM (SELECT entry FROM entries WHERE name NOT IN (SELECT name FROM pending) UNION ALL SELECT entry FROM pending WHERE entry IS NOT NULL)", [], |row| Ok((row.get(0)?,row.get(1)?))).map_err(|_| unavailable())?;
        if count > crate::dav::MAX_ENTRIES || bytes > crate::dav::MAX_METADATA {
            return Err(AccountError::new("directory metadata exceeds its bound"));
        }
        state.conn.execute_batch("DELETE FROM entries WHERE name IN (SELECT name FROM pending); INSERT INTO entries(name,entry) SELECT name,entry FROM pending WHERE entry IS NOT NULL ORDER BY name; DROP TABLE pending;").map_err(|_| unavailable())?;
        state.count = count;
        state.bytes = bytes;
        state.validate_allocation()
    }

    pub(crate) fn set_remote_parent(&mut self, id: &str, etag: &str) -> Result<(), AccountError> {
        if !crate::dav::valid_remote_id(id) || !crate::dav::strong_etag(etag) {
            return Err(AccountError::new("directory self version unavailable"));
        }
        let state = self.unique()?;
        state.parent = Some(id.to_owned());
        state.parent_etag = Some(etag.to_owned());
        Ok(())
    }

    pub(crate) fn remote_parent(&self) -> Result<(String, String), AccountError> {
        let state = self.0.lock().map_err(|_| unavailable())?;
        state
            .parent
            .clone()
            .zip(state.parent_etag.clone())
            .ok_or_else(|| AccountError::new("directory self version unavailable"))
    }

    /// Checks a fresh listing's self identity against the mounted parent.
    pub fn matches_parent(&self, id: &str) -> Result<bool, AccountError> {
        let state = self.0.lock().map_err(|_| unavailable())?;
        Ok(state.parent.as_deref() == Some(id))
    }

    /// Looks up one validated entry without decoding the complete directory.
    pub fn get(&self, name: &str) -> Result<Option<Entry>, AccountError> {
        let encoded: Option<String> = {
            let state = self.0.lock().map_err(|_| unavailable())?;
            state
                .conn
                .query_row("SELECT entry FROM entries WHERE name=?1", [name], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|_| unavailable())?
        };
        encoded
            .map(|json| serde_json::from_str(&json).map_err(|_| unavailable()))
            .transpose()
    }

    /// Decodes at most 32 metadata records after an opaque snapshot cookie.
    pub fn page(&self, after: u64) -> Result<Vec<(u64, Entry)>, AccountError> {
        let encoded = {
            let state = self.0.lock().map_err(|_| unavailable())?;
            let sql = "SELECT seq,entry FROM entries WHERE seq>?1 ORDER BY seq LIMIT ?2";
            #[cfg(feature = "fault-injection")]
            let sql = if after > 0
                && state.count > PAGE
                && state.publication_fault
                && let Some(marker) = std::env::var_os("CIRRUS_TEST_PUBLICATION_READ_FAULT")
                && std::fs::remove_file(marker).is_ok()
            {
                // A one-shot SQLite read/step failure on the candidate's second
                // traversal after a complete page. Never corrupt another owner or
                // require host disk exhaustion to exercise publication rollback.
                eprintln!("cirrus lab publication scratch read fault: after={after}");
                "SELECT seq,entry FROM entries WHERE seq>?1 AND abs(-9223372036854775808)>0 ORDER BY seq LIMIT ?2"
            } else {
                sql
            };
            let mut stmt = state.conn.prepare(sql).map_err(|_| unavailable())?;
            let rows = stmt
                .query_map(params![after, PAGE], |row| {
                    Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| unavailable())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| unavailable())?
        };
        encoded
            .into_iter()
            .map(|(cookie, json)| {
                Ok((
                    cookie,
                    serde_json::from_str(&json).map_err(|_| unavailable())?,
                ))
            })
            .collect()
    }

    #[cfg(feature = "fault-injection")]
    pub fn inject_publication_read_fault(&mut self) -> Result<(), AccountError> {
        self.unique()?.publication_fault = true;
        Ok(())
    }

    pub(crate) fn collect(&self) -> Result<Vec<Entry>, AccountError> {
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_FILE_METADATA_TRACE").is_some() {
            eprintln!("cirrus lab directory collect");
        }
        let mut result = Vec::new();
        let mut after = 0;
        loop {
            let page = self.page(after)?;
            if page.is_empty() {
                break;
            }
            for (cookie, entry) in page {
                after = cookie;
                result.push(entry);
            }
        }
        Ok(result)
    }

    pub(crate) fn json(&self) -> Result<String, AccountError> {
        let state = self.0.lock().map_err(|_| unavailable())?;
        state.conn.query_row("SELECT '[' || coalesce(group_concat(entry,','),'') || ']' FROM (SELECT entry FROM entries ORDER BY name)", [], |row| row.get(0)).map_err(|_| unavailable())
    }

    /// Binds one page of `(cookie, inode)` pairs in ascending cookie order.
    ///
    /// # Errors
    /// Rejects shared snapshots, invalid bindings (including missing or repeated
    /// cookies within a page), and write or allocation failures. On error the
    /// private candidate is consumed: scratch SQLite has no rollback guarantee.
    pub fn bind_inodes(mut self, bindings: &[(u64, u64)]) -> Result<Self, AccountError> {
        if bindings.len() > PAGE || bindings.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(unavailable());
        }
        let state = self.unique()?;
        let mut tx = state.conn.transaction().map_err(|_| unavailable())?;
        // journal_mode=OFF: close and discard the private file on any error.
        tx.set_drop_behavior(rusqlite::DropBehavior::Ignore);
        {
            let mut update = tx
                .prepare("UPDATE entries SET inode=?1 WHERE seq=?2")
                .map_err(|_| unavailable())?;
            for &(cookie, inode) in bindings {
                if inode == 0
                    || update
                        .execute(params![inode, cookie])
                        .map_err(|_| unavailable())?
                        != 1
                {
                    return Err(unavailable());
                }
            }
        }
        tx.commit().map_err(|_| unavailable())?;
        state.validate_allocation()?;
        Ok(self)
    }

    /// Reads at most 32 names/cookies without decoding entry metadata.
    pub fn children(&self, after: u64) -> Result<Vec<DirectoryChild>, AccountError> {
        let state = self.0.lock().map_err(|_| unavailable())?;
        let mut stmt = state.conn.prepare("SELECT seq,inode,name,json_extract(entry,'$.directory') FROM entries WHERE seq>?1 ORDER BY seq LIMIT ?2").map_err(|_| unavailable())?;
        let rows = stmt
            .query_map(params![after, PAGE], |row| {
                Ok(DirectoryChild {
                    cookie: row.get(0)?,
                    inode: row.get(1)?,
                    name: row.get(2)?,
                    directory: row.get(3)?,
                })
            })
            .map_err(|_| unavailable())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| unavailable())
    }

    /// Looks up a single bound directory name for FUSE lookup/getattr.
    pub fn child(&self, name: &str) -> Result<Option<DirectoryChild>, AccountError> {
        let state = self.0.lock().map_err(|_| unavailable())?;
        state.conn.query_row("SELECT seq,inode,name,json_extract(entry,'$.directory') FROM entries WHERE name=?1", [name], |row| Ok(DirectoryChild {cookie:row.get(0)?,inode:row.get(1)?,name:row.get(2)?,directory:row.get(3)?})).optional().map_err(|_| unavailable())
    }
}

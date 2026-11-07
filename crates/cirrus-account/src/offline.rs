use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use md5::Md5;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use rustix::{
    fs::{self, AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags},
    process,
};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{
    AccountError, DirectoryIdentity, Entry, FileVersion, JournalEntry, JournalPage, JournalState,
    JournalSummary, PinTree, ownership,
};

pub(crate) mod overlay;
pub(crate) mod publication;
mod upload;
pub(crate) use upload::{
    UploadVerification, upload_verifications, write_turn_dependencies, write_turn_remaining,
};

const APP_ID: i64 = 0x4344_5231;
const CHUNK: u64 = 128 * 1024;
const MAX_PIN_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const MAX_STAGING_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub(crate) const MAX_STAGING_FILES: usize = 4096;
const MAX_PENDING_NAMESPACE_OPERATIONS: i64 = 4096;
const DETACHED_MESSAGE: &str = "unlinked open file; staged copies retained";
const REUSE_DIRECTORY_TARGET: &str = "reuse exact empty remote directory";
pub(crate) const PARENT_WRITE_CONFLICT: &str = "parent identity changed; local copy retained";
static OPEN_LOCK: Mutex<()> = Mutex::new(());
static STAGING_LOCK: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());

#[cfg(feature = "fault-injection")]
fn pin_move_stop(stage: &str) {
    if std::env::var("CIRRUS_TEST_PIN_MOVE_STOP").ok().as_deref() == Some(stage) {
        eprintln!("cirrus lab pin move stop: {stage}");
        stop_fault_thread();
    }
}

#[cfg(feature = "fault-injection")]
fn repin_stop(stage: &str) {
    if std::env::var("CIRRUS_TEST_REPIN_STOP").ok().as_deref() == Some(stage) {
        eprintln!("cirrus lab repin stop: {stage}");
        stop_fault_thread();
    }
}

#[cfg(feature = "fault-injection")]
fn stop_fault_thread() {
    // SAFETY: raise sends SIGSTOP to this thread; it has no pointer arguments.
    let result = unsafe { nix::libc::raise(nix::libc::SIGSTOP) };
    assert_eq!(result, 0, "cannot stop the fault-injection thread");
}

pub(crate) struct Pin {
    pub path: Vec<String>,
    pub tree: PinTree,
    pub complete: bool,
    pub metadata_matches: bool,
}

pub(crate) fn database() -> Result<Connection, AccountError> {
    let _lock = OPEN_LOCK
        .lock()
        .map_err(|_| AccountError::new("offline state is unavailable"))?;
    let dir = ownership::state_dir()?;
    let (stat, created) = match fs::openat2(
        &dir,
        "state.db",
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => (
            fs::fstat(&fd).map_err(|_| AccountError::new("cannot inspect offline state"))?,
            true,
        ),
        Err(rustix::io::Errno::EXIST) => (
            fs::statat(&dir, "state.db", AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| AccountError::new("cannot inspect offline state"))?,
            false,
        ),
        Err(_) => return Err(AccountError::new("cannot create offline state")),
    };
    // Closing an extra descriptor for an existing SQLite file would release
    // this process's POSIX locks, including locks held by other connections.
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(AccountError::new(
            "offline state has unsafe ownership or permissions",
        ));
    }
    let proc = fs::openat2(
        fs::CWD,
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| AccountError::new("trusted procfs is required for offline state"))?;
    if fs::fstatfs(&proc)
        .map_err(|_| AccountError::new("cannot inspect procfs"))?
        .f_type
        != fs::PROC_SUPER_MAGIC
    {
        return Err(AccountError::new(
            "trusted procfs is required for offline state",
        ));
    }
    // SQLite resolves the held-directory procfs link before opening; NOFOLLOW would
    // reject that link. The private directory and the final inode are checked here.
    let path = format!("/proc/self/fd/{}/state.db", dir.as_raw_fd());
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|_| AccountError::new("cannot open offline state"))?;
    conn.busy_timeout(Duration::from_secs(15))
        .map_err(|_| AccountError::new("cannot configure offline state"))?;
    // EXTRA also syncs the containing directory after deleting a rollback journal.
    conn.execute_batch("PRAGMA synchronous=EXTRA")
        .map_err(|_| AccountError::new("cannot configure offline state durability"))?;
    let id: i64 = conn
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline state"))?;
    if created {
        conn.execute_batch("BEGIN IMMEDIATE; PRAGMA application_id=1128550961; PRAGMA user_version=17;
            CREATE TABLE account_identities(instance TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL);
            CREATE TABLE snapshots(instance TEXT NOT NULL, space TEXT NOT NULL, path TEXT NOT NULL, entries TEXT NOT NULL, updated INTEGER NOT NULL, self_id TEXT, self_etag TEXT, local_operation INTEGER, issuer TEXT NOT NULL, subject TEXT NOT NULL, PRIMARY KEY(instance,space,path), CHECK((self_id IS NOT NULL AND self_etag IS NOT NULL AND local_operation IS NULL) OR (self_id IS NULL AND self_etag IS NULL AND local_operation IS NOT NULL AND local_operation>0)));
            CREATE TABLE pins(instance TEXT NOT NULL, space TEXT NOT NULL, root TEXT NOT NULL, is_dir INTEGER NOT NULL, directories TEXT NOT NULL, manifest TEXT NOT NULL, PRIMARY KEY(instance,space,root));
            CREATE TABLE files(instance TEXT NOT NULL, space TEXT NOT NULL, root TEXT NOT NULL, path TEXT NOT NULL, version TEXT NOT NULL, verified_complete INTEGER NOT NULL CHECK(verified_complete=1), PRIMARY KEY(instance,space,root,path));
            CREATE TABLE chunks(instance TEXT NOT NULL, space TEXT NOT NULL, root TEXT NOT NULL, path TEXT NOT NULL, offset INTEGER NOT NULL, body BLOB NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(instance,space,root,path,offset));
            CREATE TABLE pin_copies(id INTEGER PRIMARY KEY AUTOINCREMENT, instance TEXT NOT NULL, space TEXT NOT NULL, root TEXT NOT NULL, is_dir INTEGER NOT NULL, directories TEXT NOT NULL, manifest TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, displaced_path TEXT NOT NULL, target_id TEXT NOT NULL, target_etag TEXT NOT NULL);
            CREATE INDEX pin_copies_account ON pin_copies(instance,space,id);
            CREATE TABLE pin_copy_files(instance TEXT NOT NULL, space TEXT NOT NULL, root TEXT NOT NULL, path TEXT NOT NULL, version TEXT NOT NULL, verified_complete INTEGER NOT NULL CHECK(verified_complete=1), PRIMARY KEY(instance,space,root,path));
            CREATE TABLE pin_copy_chunks(instance TEXT NOT NULL, space TEXT NOT NULL, root TEXT NOT NULL, path TEXT NOT NULL, offset INTEGER NOT NULL, body BLOB NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(instance,space,root,path,offset));
            CREATE TABLE operation_journal (id INTEGER PRIMARY KEY, instance TEXT NOT NULL, space TEXT NOT NULL, path TEXT NOT NULL, op_type TEXT NOT NULL, base_file_id TEXT, base_etag TEXT, staged_file TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','conflict','synced','uncertain','resolved')), error_msg TEXT, updated_at INTEGER NOT NULL, confirmed_file_id TEXT, confirmed_etag TEXT);
            CREATE TABLE directory_moves (operation_id INTEGER PRIMARY KEY, destination TEXT NOT NULL, source_entry TEXT NOT NULL, target_id TEXT, target_etag TEXT, offline INTEGER NOT NULL DEFAULT 0 CHECK(offline IN (0,1)));
            CREATE TABLE tree_proofs(operation_id INTEGER NOT NULL, path TEXT NOT NULL, self_id TEXT NOT NULL, self_etag TEXT NOT NULL, generation INTEGER NOT NULL, digest TEXT NOT NULL, entries TEXT NOT NULL, PRIMARY KEY(operation_id,path));
            CREATE TABLE tree_targets(operation_id INTEGER PRIMARY KEY, self_id TEXT NOT NULL, self_etag TEXT NOT NULL, generation INTEGER NOT NULL, entries TEXT NOT NULL CHECK(entries='[]'), issuer TEXT NOT NULL, subject TEXT NOT NULL);
            CREATE TABLE write_dependencies (operation_id INTEGER PRIMARY KEY, predecessor_id INTEGER NOT NULL UNIQUE);
            CREATE TABLE operation_parents (operation_id INTEGER PRIMARY KEY, parents TEXT NOT NULL, destination_parents TEXT);
            CREATE TABLE removal_versions(operation_id INTEGER NOT NULL, etag TEXT NOT NULL, PRIMARY KEY(operation_id,etag));
            CREATE TABLE upload_verifications (operation_id INTEGER PRIMARY KEY, operation TEXT NOT NULL, digest TEXT NOT NULL, size INTEGER NOT NULL, version TEXT, verified_offset INTEGER NOT NULL, parent_index INTEGER NOT NULL);
            CREATE TABLE sync_spaces (instance TEXT NOT NULL, space TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, phase TEXT NOT NULL, failures INTEGER NOT NULL, next_at INTEGER NOT NULL, cause TEXT, last_verified INTEGER, verified_through INTEGER NOT NULL, attention_stamp TEXT, PRIMARY KEY(instance,space));
            CREATE TABLE sync_reads (operation_id INTEGER PRIMARY KEY, snapshot TEXT NOT NULL, phase TEXT NOT NULL, entries TEXT NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE mutation_receipts (operation_id INTEGER PRIMARY KEY, kind TEXT NOT NULL, snapshot TEXT NOT NULL, extra TEXT NOT NULL);
             CREATE TABLE verified_uploads (operation_id INTEGER PRIMARY KEY, digest TEXT NOT NULL, version TEXT NOT NULL);
             CREATE TABLE dirty_roots (root TEXT PRIMARY KEY, digest TEXT NOT NULL, size INTEGER NOT NULL, base TEXT);
             CREATE TABLE dirty_bases (version TEXT NOT NULL, offset INTEGER NOT NULL, object TEXT NOT NULL, PRIMARY KEY(version,offset));
             CREATE TABLE dirty_preparations (version TEXT PRIMARY KEY, offset INTEGER NOT NULL);
            CREATE INDEX space_pending ON operation_journal(instance,space,state,op_type,id); COMMIT;")
            .map_err(|_| AccountError::new("cannot initialize offline state"))?;
        fs::fsync(&dir).map_err(|_| AccountError::new("cannot persist offline state"))?;
    } else if id != APP_ID {
        return Err(AccountError::new("unrecognized offline state"));
    }
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline state"))?;
    if version != 17 {
        return Err(AccountError::new("unsupported offline state version"));
    }
    let current = fs::statat(&dir, "state.db", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| AccountError::new("offline state changed"))?;
    if (stat.st_dev, stat.st_ino) != (current.st_dev, current.st_ino)
        || current.st_nlink != 1
        || FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
        || current.st_uid != process::geteuid().as_raw()
        || current.st_mode & 0o7777 != 0o600
    {
        return Err(AccountError::new("offline state changed"));
    }
    #[cfg(feature = "fault-injection")]
    if let Some(marker) = std::env::var_os("CIRRUS_TEST_SQLITE_OPEN_MARKER") {
        let marker = Path::new(&marker);
        if marker.is_file() {
            std::fs::write(marker.with_extension("opened"), b"stat-only")
                .map_err(|_| AccountError::new("cannot mark database test window"))?;
        }
    }
    Ok(conn)
}

/// Bind offline state to the first verified identity for an instance.
pub(crate) fn bind_identity(
    instance: &str,
    issuer: &str,
    subject: &str,
) -> Result<(), AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot inspect offline account identity"))?;
    let existing: Option<(String, String)> = tx
        .query_row(
            "SELECT issuer,subject FROM account_identities WHERE instance=?1",
            [instance],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| AccountError::new("cannot inspect offline account identity"))?;
    match existing {
        Some((saved_issuer, saved_subject))
            if saved_issuer == issuer && saved_subject == subject => {}
        Some(_) => {
            return Err(AccountError::new(
                "mounted account identity changed; offline state belongs to another account; local data retained",
            ));
        }
        None => {
            let has_data: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM snapshots WHERE instance=?1 UNION ALL SELECT 1 FROM pins WHERE instance=?1 UNION ALL SELECT 1 FROM files WHERE instance=?1 UNION ALL SELECT 1 FROM chunks WHERE instance=?1 UNION ALL SELECT 1 FROM pin_copies WHERE instance=?1 UNION ALL SELECT 1 FROM pin_copy_files WHERE instance=?1 UNION ALL SELECT 1 FROM pin_copy_chunks WHERE instance=?1 UNION ALL SELECT 1 FROM operation_journal WHERE instance=?1)",
                    [instance],
                    |row| row.get(0),
                )
                .map_err(|_| AccountError::new("cannot inspect unbound offline state"))?;
            if has_data {
                return Err(AccountError::new(
                    "offline account identity is missing; local data retained",
                ));
            }
            tx.execute(
                "INSERT INTO account_identities(instance,issuer,subject) VALUES (?1,?2,?3)",
                params![instance, issuer, subject],
            )
            .map_err(|error| sqlite_storage_error(error, "cannot bind offline account identity"))?;
        }
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit offline account identity"))
}

pub(crate) fn verify_identity(
    instance: &str,
    issuer: &str,
    subject: &str,
) -> Result<(), AccountError> {
    let existing: Option<(String, String)> = database()?
        .query_row(
            "SELECT issuer,subject FROM account_identities WHERE instance=?1",
            [instance],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| AccountError::new("cannot inspect offline account identity"))?;
    match existing {
        Some((saved_issuer, saved_subject))
            if saved_issuer == issuer && saved_subject == subject =>
        {
            Ok(())
        }
        Some(_) => Err(AccountError::new(
            "mounted account identity changed; offline state belongs to another account; local data retained",
        )),
        None => Err(AccountError::new(
            "offline account identity is missing; local data retained",
        )),
    }
}

pub(crate) fn sqlite_storage_error(error: rusqlite::Error, fallback: &'static str) -> AccountError {
    #[cfg(feature = "fault-injection")]
    if let rusqlite::Error::SqliteFailure(ref failure, _) = error {
        crate::sync::trace_automatic(&format!(
            "sqlite context={fallback:?} code={:?} extended={}",
            failure.code, failure.extended_code
        ));
    }
    if matches!(error, rusqlite::Error::SqliteFailure(ref failure, _) if failure.code == rusqlite::ErrorCode::DiskFull)
    {
        AccountError::new("local storage capacity exhausted")
    } else {
        AccountError::new(fallback)
    }
}

pub(crate) fn stage_file(
    instance: &str,
    space: &str,
    path: &[String],
    source: &Path,
    base: Option<&Entry>,
    parents: &[DirectoryIdentity],
) -> Result<i64, AccountError> {
    if !source.is_absolute()
        || source
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(AccountError::new(
            "staging source must be an absolute safe path",
        ));
    }
    let input = fs::openat2(
        fs::CWD,
        source,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| AccountError::new("cannot safely open staging source"))?;
    let mut input = std::fs::File::from(input);
    let before = input
        .metadata()
        .map_err(|_| AccountError::new("cannot inspect staging source"))?;
    if !before.is_file() || before.len() > overlay::MAX_FILE {
        return Err(AccountError::new(
            "staging source must be a regular file of at most 1 TiB",
        ));
    }
    let root = overlay::Overlay::import(&mut input, before.len())?;
    let count = root.len();
    let after = input.metadata().map_err(|_| {
        AccountError::new("cannot inspect staging source; inspect staging directory")
    })?;
    if count != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(AccountError::new(
            "staging source changed; inspect staging directory",
        ));
    }
    let name = root.save()?;
    // Immutable import objects/registration are independently durable and
    // charged already. Refusal here retains them without publishing a head.
    // Keep the State allowance through rollback/close; exact marker recovery
    // below still opens its own uncapped connection.
    let reservation;
    let mut conn = database()?;
    let encoded = path_key(path)?;
    let base = base.filter(|entry| !entry.is_directory() && entry.etag().is_some());
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect import publication plan"))?;
    let planned = if crate::storage::limits::view()?.limits.is_some() {
        let operation = PendingWrite {
            id: i64::MAX,
            space: space.to_owned(),
            path: path.to_vec(),
            base_id: base.map(|entry| entry.id().to_owned()),
            base_etag: base.and_then(Entry::etag).map(str::to_owned),
            staged: name.clone(),
            parents: parents.to_vec(),
        };
        // This transaction inserts one write/parent row and a marker, not a
        // mounted-root CAS, successor dependency, retained copy or pin move.
        // Local-directory dependencies are encoded in parents, not new rows.
        let rows = serde_json::to_vec(&(
            (
                i64::MAX,
                instance,
                space,
                &encoded,
                "write",
                &operation.base_id,
                &operation.base_etag,
                &name,
                "pending",
                Option::<&str>::None,
                i64::MAX,
            ),
            (
                i64::MAX,
                encode_parents(path, parents)?,
                Option::<&str>::None,
            ),
        ))
        .map_err(|_| AccountError::new("cannot size import publication rows"))?;
        (rows.len() as u64)
            .checked_add(publication::planned_fence_bytes(
                &conn, instance, &operation, None, None,
            )?)
            .ok_or_else(|| AccountError::new("import publication estimate overflow"))?
    } else {
        0
    };
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_IMPORT_PUBLICATION_ADMISSION_WINDOW")?;
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_IMPORT_PUBLICATION_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin staged file"))?;
    if reservation.is_some() {
        let current: i64 = tx
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect import publication plan"))?;
        if current != planning_version {
            return Err(AccountError::new(
                "directory metadata changed concurrently; retry",
            ));
        }
    }
    reject_fenced_ancestor(&tx, instance, space, path)?;
    let namespace: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND op_type!='write' AND state IN ('pending','conflict','uncertain')", params![instance, space, path_key(path)?], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect pending operations"))?;
    if namespace != 0 {
        return Err(AccountError::new(
            "path has unresolved namespace operations; inspect staging directory",
        ));
    }
    tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES (?1,?2,?3,'write',?4,?5,?6,'pending',NULL,strftime('%s','now'))",
        params![instance, space, encoded, base.map(Entry::id), base.and_then(Entry::etag), name]).map_err(|error| sqlite_storage_error(error, "cannot journal staged file; inspect staging directory"))?;
    let id = tx.last_insert_rowid();
    save_operation_parents(&tx, id, path, parents, None)?;
    let publication = publication::fence(&tx, id)?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_IMPORT_PUBLICATION_COMMIT_WINDOW")?;
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    let committed = tx.commit();
    #[cfg(feature = "fault-injection")]
    let committed = if committed.is_ok()
        && let Some(marker) = std::env::var_os("CIRRUS_TEST_IMPORT_COMMITTED_ERROR")
        && std::fs::remove_file(marker).is_ok()
    {
        eprintln!("cirrus lab import committed-but-returned-error (not hardware I/O)");
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
            None,
        ))
    } else {
        committed
    };
    conn.close().map_err(|_| {
        AccountError::new("cannot close publication database; local copies retained")
    })?;
    if !publication::recover(
        instance,
        space,
        path,
        id,
        Some(&publication),
        committed.is_err(),
    )? {
        committed.map_err(|error| sqlite_storage_error(error, "cannot commit staged file"))?;
        return Err(AccountError::new(
            "local publication head changed; local copies retained",
        ));
    }
    Ok(id)
}

fn reject_fenced_ancestor(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<(), AccountError> {
    publication::ensure_clear(conn, instance, space)?;
    let mut statement = conn.prepare("SELECT path FROM operation_journal WHERE instance=?1 AND space=?2 AND op_type IN ('rmdir','move-dir-source') AND (state IN ('pending','conflict','uncertain') OR (state='resolved' AND error_msg='acknowledged locally; remote outcome not asserted'))")
        .map_err(|_| AccountError::new("cannot inspect parent removal"))?;
    let rows = statement
        .query_map(params![instance, space], |row| row.get::<_, String>(0))
        .map_err(|_| AccountError::new("cannot inspect parent removal"))?;
    for row in rows {
        let encoded = row.map_err(|_| AccountError::new("invalid parent removal"))?;
        let ancestor: Vec<String> = serde_json::from_str(&encoded)
            .map_err(|_| AccountError::new("invalid parent removal"))?;
        if path.len() > ancestor.len() && path.starts_with(&ancestor) {
            return Err(AccountError::new(
                "parent directory removal requires attention",
            ));
        }
    }
    let mut statement = conn.prepare("SELECT j.path,m.destination,j.state FROM operation_journal j JOIN directory_moves m ON m.operation_id=j.id WHERE j.instance=?1 AND j.space=?2 AND j.op_type='move-tree' AND (j.state IN ('pending','conflict','uncertain') OR (j.state='resolved' AND j.error_msg='acknowledged locally; remote outcome not asserted'))")
        .map_err(|_| AccountError::new("cannot inspect directory move"))?;
    let rows = statement
        .query_map(params![instance, space], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| AccountError::new("cannot inspect directory move"))?;
    for row in rows {
        let (source, destination, state) =
            row.map_err(|_| AccountError::new("invalid directory move"))?;
        let source: Vec<String> = serde_json::from_str(&source)
            .map_err(|_| AccountError::new("invalid directory move"))?;
        if path.starts_with(&source) {
            return Err(AccountError::new(
                "path is hidden by a pending directory rename",
            ));
        }
        if state == "uncertain" || state == "resolved" {
            let destination: Vec<String> = serde_json::from_str(&destination)
                .map_err(|_| AccountError::new("invalid directory move"))?;
            if path.starts_with(&destination) {
                return Err(AccountError::new(
                    "directory move outcome requires attention",
                ));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingWrite {
    pub id: i64,
    pub space: String,
    pub path: Vec<String>,
    pub base_id: Option<String>,
    pub base_etag: Option<String>,
    pub staged: String,
    pub parents: Vec<DirectoryIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct NamespaceOperation {
    pub id: i64,
    pub space: String,
    pub path: Vec<String>,
    pub kind: String,
    pub base_id: Option<String>,
    pub base_etag: Option<String>,
    pub dependency: Option<i64>,
    pub parents: Vec<DirectoryIdentity>,
    token: String,
    pending_message: Option<String>,
}

impl NamespaceOperation {
    pub(crate) fn reuses_directory(&self) -> bool {
        self.kind == "mkdir" && self.pending_message.as_deref() == Some(REUSE_DIRECTORY_TARGET)
    }
    pub(crate) fn same_rmdir_identity(&self, other: &Self) -> bool {
        self.kind == "rmdir"
            && other.kind == "rmdir"
            && self.id == other.id
            && self.space == other.space
            && self.path == other.path
            && self.base_id == other.base_id
            && self.token == other.token
            && self.pending_message == other.pending_message
            && self.dependency == other.dependency
            && self.parents == other.parents
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct TreeMove {
    pub id: i64,
    pub space: String,
    pub source: Vec<String>,
    pub destination: Vec<String>,
    pub entry: Entry,
    pub target: Option<(String, String)>,
    pub state: String,
    pub parents: Vec<DirectoryIdentity>,
    pub destination_parents: Vec<DirectoryIdentity>,
    pub offline: bool,
}

pub(crate) fn tree_move_page(
    instance: &str,
    space: Option<&str>,
    after: i64,
    through: i64,
) -> Result<Vec<TreeMove>, AccountError> {
    let conn = database()?;
    tree_moves_scoped_in(&conn, instance, space, (Some(after), through))
}

fn tree_moves_scoped_in(
    conn: &Connection,
    instance: &str,
    space: Option<&str>,
    bounds: (Option<i64>, i64),
) -> Result<Vec<TreeMove>, AccountError> {
    tree_move_records_in(conn, instance, space, bounds, false)
}

fn tree_move_records_in(
    conn: &Connection,
    instance: &str,
    space: Option<&str>,
    bounds: (Option<i64>, i64),
    retained: bool,
) -> Result<Vec<TreeMove>, AccountError> {
    let mut statement = conn.prepare("SELECT j.id,j.space,j.path,m.destination,m.source_entry,m.target_id,m.target_etag,j.state,m.offline FROM operation_journal j JOIN directory_moves m ON m.operation_id=j.id WHERE j.instance=?1 AND (?2 IS NULL OR j.space=?2) AND (?3 IS NULL OR j.id>?3) AND j.id<=?4 AND j.op_type='move-tree' AND (j.state IN ('pending','conflict','uncertain') OR (?5 AND j.state='synced')) ORDER BY j.id LIMIT 32").map_err(|_| AccountError::new("cannot inspect directory moves"))?;
    let rows = statement
        .query_map(
            params![instance, space, bounds.0, bounds.1, retained],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, bool>(8)?,
                ))
            },
        )
        .map_err(|_| AccountError::new("cannot inspect directory moves"))?;
    rows.map(|row| {
        let (id, space, source, destination, entry, target_id, target_etag, state, offline) =
            row.map_err(|_| AccountError::new("invalid directory move"))?;
        let target = match (target_id, target_etag) {
            (Some(id), Some(etag)) => Some((id, etag)),
            (None, None) => None,
            _ => return Err(AccountError::new("invalid directory move target")),
        };
        let entry: Entry = serde_json::from_str(&entry)
            .map_err(|_| AccountError::new("invalid directory metadata"))?;
        if !entry.is_directory() || !crate::dav::valid_remote_id(entry.id()) {
            return Err(AccountError::new("invalid directory metadata"));
        }
        let source: Vec<String> = serde_json::from_str(&source)
            .map_err(|_| AccountError::new("invalid directory source"))?;
        let destination: Vec<String> = serde_json::from_str(&destination)
            .map_err(|_| AccountError::new("invalid directory destination"))?;
        let parents = load_operation_parents(conn, id, &source)?;
        let destination_parents = load_destination_parents(conn, id, &destination)?;
        Ok(TreeMove {
            id,
            space,
            source,
            destination,
            entry,
            target,
            state,
            parents,
            destination_parents,
            offline,
        })
    })
    .collect()
}

// Immutable content interpretation, not a namespace open or DAV locator. Only
// admitted offline proofs can alias a moved leaf to its original FileVersion.
fn tree_content_base_in(
    conn: &Connection,
    version: &FileVersion,
    pending: bool,
) -> Result<Option<FileVersion>, AccountError> {
    check_retained_identity(conn, &version.instance, &version.space)?;
    let through: i64 = conn
        .query_row(
            "SELECT coalesce(max(id),0) FROM operation_journal",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect content MOVE high water"))?;
    let mut after = None;
    let mut found = None;
    loop {
        let page = tree_move_records_in(
            conn,
            &version.instance,
            Some(&version.space),
            (after, through),
            true,
        )?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        for operation in page {
            if !operation.offline
                || !version.path.starts_with(&operation.destination)
                || version.path.len() <= operation.destination.len()
            {
                continue;
            }
            if pending {
                if operation.state != "pending" || operation.target.is_some() {
                    continue;
                }
                // New overlays require the live copied root and its exact
                // destination-parent chain too. Retained content reads below
                // do not treat current namespace replacement as byte authority.
                offline_tree_copy_in(
                    conn,
                    (&version.instance, &version.space),
                    &operation.destination,
                    &operation,
                )?
                .ok_or_else(|| AccountError::new("original content MOVE copy unavailable"))?;
            }
            let bound: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='move-tree' AND base_file_id=?5 AND base_etag IS ?6)",params![operation.id,version.instance,version.space,path_key(&operation.source)?,operation.entry.id(),operation.entry.etag()],|row|row.get(0))
                .map_err(|_|AccountError::new("cannot inspect content MOVE identity"))?;
            if !bound {
                return Err(AccountError::new("content MOVE identity changed"));
            }
            let relative = &version.path[operation.destination.len()..];
            let mut expected = (
                operation.entry.id().to_owned(),
                operation.entry.etag().map(str::to_owned),
            );
            let mut leaf = None;
            for depth in 0..relative.len() {
                let (id,etag,digest,json):(String,String,String,String)=conn.query_row("SELECT self_id,self_etag,digest,entries FROM tree_proofs WHERE operation_id=?1 AND path=?2",params![operation.id,path_key(&relative[..depth])?],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))
                    .map_err(|_|AccountError::new("content MOVE proof unavailable"))?;
                if id != expected.0
                    || Some(etag.as_str()) != expected.1.as_deref()
                    || !crate::dav::valid_remote_id(&id)
                    || !crate::dav::strong_etag(&etag)
                    || format!("{:x}", Sha256::digest(json.as_bytes())) != digest
                {
                    return Err(AccountError::new("content MOVE proof changed"));
                }
                let (count,encoded):(u64,Option<String>)=conn.query_row("SELECT count(*),min(value) FROM json_each(?1) WHERE json_extract(value,'$.name')=?2",params![json,relative[depth]],|row|Ok((row.get(0)?,row.get(1)?)))
                    .map_err(|_|AccountError::new("cannot inspect original content proof"))?;
                if count != 1 {
                    break;
                }
                let entry: Entry = serde_json::from_str(
                    &encoded
                        .ok_or_else(|| AccountError::new("original content proof unavailable"))?,
                )
                .map_err(|_| AccountError::new("invalid original content proof"))?;
                if depth + 1 == relative.len() {
                    leaf = Some(entry);
                } else {
                    if !entry.is_directory() {
                        break;
                    }
                    expected = (entry.id().to_owned(), entry.etag().map(str::to_owned));
                }
            }
            if !leaf.is_some_and(|entry| {
                !entry.is_directory()
                    && entry.id() == version.id
                    && entry.etag() == Some(version.etag.as_str())
                    && entry.size() == Some(version.size)
                    && entry.checksums() == version.checksums
            }) {
                // A local create or newer version at the same path is not the
                // leaf in this proof. It must never borrow the old leaf's bytes.
                continue;
            }
            let mut original = version.clone();
            original.path = operation.source;
            original.path.extend_from_slice(relative);
            if original.path.len() > 128
                || found.as_ref().is_some_and(|previous| previous != &original)
            {
                return Err(AccountError::new("ambiguous original content MOVE"));
            }
            found = Some(original);
        }
    }
    Ok(found)
}

pub(crate) fn tree_content_base(
    version: &FileVersion,
) -> Result<Option<FileVersion>, AccountError> {
    content_base(version, false)
}

fn content_base(version: &FileVersion, pending: bool) -> Result<Option<FileVersion>, AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot inspect content MOVE"))?;
    let original = tree_content_base_in(&tx, version, pending)?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot finish content MOVE inspection"))?;
    Ok(original)
}

/// Returns the remote path and whether remote access is fenced by the MOVE state.
pub(crate) fn tree_remote_path(
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<(Vec<String>, bool), AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot inspect directory moves"))?;
    let mut after = None;
    let mut result = None;
    loop {
        let page = tree_moves_scoped_in(&tx, instance, Some(space), (after, i64::MAX))?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        for operation in page {
            if result.is_some() {
                continue;
            }
            if path.starts_with(&operation.source) {
                result = Some(Err(AccountError::new(
                    "path is hidden by a pending directory rename",
                )));
            } else if path.starts_with(&operation.destination) {
                let mut remote = operation.source;
                remote.extend_from_slice(&path[operation.destination.len()..]);
                result = Some(Ok((remote, operation.state != "pending")));
            }
        }
    }
    tx.commit()
        .map_err(|_| AccountError::new("cannot inspect directory moves"))?;
    result.unwrap_or_else(|| Ok((path.to_vec(), false)))
}

pub(crate) fn tree_blocked_spaces(
    instance: &str,
    space: Option<&str>,
) -> Result<std::collections::HashSet<String>, AccountError> {
    let conn = database()?;
    let mut statement = conn.prepare("SELECT DISTINCT j.space FROM operation_journal j JOIN directory_moves m ON m.operation_id=j.id WHERE j.instance=?1 AND (?2 IS NULL OR j.space=?2) AND j.op_type='move-tree' AND j.state IN ('conflict','uncertain')")
        .map_err(|_| AccountError::new("cannot inspect directory moves"))?;
    let rows = statement
        .query_map(params![instance, space], |row| row.get::<_, String>(0))
        .map_err(|_| AccountError::new("cannot inspect directory moves"))?;
    rows.collect::<Result<_, _>>()
        .map_err(|_| AccountError::new("invalid directory move"))
}

pub(crate) fn invalid_journal_spaces(
    instance: &str,
    space: Option<&str>,
) -> Result<std::collections::HashSet<String>, AccountError> {
    let conn = database()?;
    let mut statement = conn
        .prepare("SELECT DISTINCT space FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2) AND (state IS NULL OR state NOT IN ('pending','conflict','uncertain','synced','resolved') OR (id<=0 AND state NOT IN ('synced','resolved')))")
        .map_err(|_| AccountError::new("cannot inspect journal entries"))?;
    let rows = statement
        .query_map(params![instance, space], |row| row.get::<_, String>(0))
        .map_err(|_| AccountError::new("cannot inspect journal entries"))?;
    rows.collect::<Result<_, _>>()
        .map_err(|_| AccountError::new("invalid journal Space"))
}

pub(crate) fn tree_destination_contains(
    instance: &str,
    space: &str,
    path: &[String],
    through: i64,
) -> Result<bool, AccountError> {
    let conn = database()?;
    let mut statement = conn.prepare("SELECT m.destination FROM operation_journal j JOIN directory_moves m ON m.operation_id=j.id WHERE j.instance=?1 AND j.space=?2 AND j.id<=?3 AND j.op_type='move-tree' AND j.state IN ('pending','conflict','uncertain') ORDER BY j.id")
        .map_err(|_| AccountError::new("cannot inspect directory moves"))?;
    let rows = statement
        .query_map(params![instance, space, through], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| AccountError::new("cannot inspect directory moves"))?;
    for row in rows {
        let encoded = row.map_err(|_| AccountError::new("invalid directory destination"))?;
        let destination: Vec<String> = serde_json::from_str(&encoded)
            .map_err(|_| AccountError::new("invalid directory destination"))?;
        if path.starts_with(&destination) {
            return Ok(true);
        }
    }
    Ok(false)
}

// Relocate independent pin copies in the same transaction as the local rename.
// Ordinary rename keeps its split/displacement refusal. Explicit offline
// replacement additionally admits the bounded capture/extraction below.
fn relocate_pins(
    conn: &Connection,
    instance: &str,
    space: &str,
    source: &[String],
    destination: &[String],
) -> Result<(), AccountError> {
    relocate_pins_in(conn, instance, space, source, destination, None, false)
}

// A destination-only ancestor may absorb only one complete, clean source pin.
// Compare its entire captured tree with the admitted observations and verify
// every stored byte in this same writer transaction, never hydrate over DAV.
fn complete_incoming_pin(
    conn: &Connection,
    instance: &str,
    space: &str,
    source: &[String],
    destination: &[String],
) -> Result<crate::PinTree, AccountError> {
    let refused = || AccountError::new("rename would displace or split a pin");
    let root = path_key(source)?;
    let (is_dir, directories, manifest): (bool, String, String) = conn.query_row(
        "SELECT is_dir,CASE WHEN length(directories)<=16777216 THEN directories END,CASE WHEN length(manifest)<=16777216 THEN manifest END FROM pins WHERE instance=?1 AND space=?2 AND root=?3",
        params![instance,space,root], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))
        .optional().map_err(|_|refused())?.ok_or_else(refused)?;
    let directories: Vec<(Vec<String>, String)> =
        serde_json::from_str(&directories).map_err(|_| refused())?;
    let files: Vec<FileVersion> = serde_json::from_str(&manifest).map_err(|_| refused())?;
    if !is_dir
        || directories.len() + files.len() > 4097
        || directories.first().map(|(p, _)| p.as_slice()) != Some(source)
        || directories.windows(2).any(|w| w[0].0 >= w[1].0)
        || files.windows(2).any(|w| w[0].path >= w[1].path)
    {
        return Err(refused());
    }
    let mut pending = conn.prepare("SELECT path FROM operation_journal WHERE instance=?1 AND space=?2 AND state IN ('pending','conflict','uncertain')")
        .map_err(|_|refused())?;
    for row in pending
        .query_map(params![instance, space], |row| row.get::<_, String>(0))
        .map_err(|_| refused())?
    {
        let path: Vec<String> =
            serde_json::from_str(&row.map_err(|_| refused())?).map_err(|_| refused())?;
        // Relocated operations may already have destination coordinates.
        if path.starts_with(source) || path.starts_with(destination) {
            return Err(refused());
        }
    }
    let mut observed_files = 0usize;
    let mut observed_dirs = 1usize;
    for (path, id) in &directories {
        path_key(path)?;
        if !path.starts_with(source) || !crate::dav::valid_remote_id(id) {
            return Err(refused());
        }
        let entries = directory_snapshot_in(conn, instance, space, path)?.ok_or_else(refused)?;
        if entries.remote_parent()?.0 != *id {
            return Err(refused());
        }
        let mut after = 0;
        loop {
            let page = entries.page(after)?;
            if page.is_empty() {
                break;
            }
            for (cookie, entry) in page {
                after = cookie;
                let mut child = path.clone();
                child.push(entry.name().to_owned());
                if entry.is_directory() {
                    let index = directories
                        .binary_search_by(|(p, _)| p.cmp(&child))
                        .map_err(|_| refused())?;
                    if directories[index].1 != entry.id() {
                        return Err(refused());
                    }
                    observed_dirs += 1;
                } else {
                    let index = files
                        .binary_search_by(|file| file.path.cmp(&child))
                        .map_err(|_| refused())?;
                    let version = &files[index];
                    if version.instance != instance
                        || version.space != space
                        || version.id != entry.id()
                        || Some(version.etag.as_str()) != entry.etag()
                        || !crate::dav::strong_etag(&version.etag)
                        || Some(version.size) != entry.size()
                        || version.checksums != entry.checksums()
                    {
                        return Err(refused());
                    }
                    observed_files += 1;
                }
            }
        }
    }
    if observed_dirs != directories.len() || observed_files != files.len() {
        return Err(refused());
    }
    let count: usize = conn
        .query_row(
            "SELECT count(*) FROM files WHERE instance=?1 AND space=?2 AND root=?3",
            params![instance, space, root],
            |row| row.get(0),
        )
        .map_err(|_| refused())?;
    if count != files.len() {
        return Err(refused());
    }
    let orphans:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM chunks c WHERE c.instance=?1 AND c.space=?2 AND c.root=?3 AND NOT EXISTS(SELECT 1 FROM files f WHERE f.instance=c.instance AND f.space=c.space AND f.root=c.root AND f.path=c.path))",params![instance,space,root],|row|row.get(0)).map_err(|_|refused())?;
    if orphans {
        return Err(refused());
    }
    let mut total = 0u64;
    for version in &files {
        total = total
            .checked_add(version.size)
            .filter(|n| *n <= MAX_PIN_BYTES)
            .ok_or_else(refused)?;
        let encoded:String=conn.query_row("SELECT CASE WHEN length(version)<=16777216 THEN version END FROM files WHERE instance=?1 AND space=?2 AND root=?3 AND path=?4 AND verified_complete=1",params![instance,space,root,path_key(&version.path)?],|row|row.get(0)).map_err(|_|refused())?;
        let stored: FileVersion = serde_json::from_str(&encoded).map_err(|_| refused())?;
        if stored != *version {
            return Err(refused());
        }
        crate::recovery::verify_active_file(conn, instance, space, &root, version)?;
    }
    Ok(crate::PinTree {
        is_dir,
        directories,
        files,
    })
}

// Replacement captures are immutable and independently addressed. This runs
// under the SAME admitted writer transaction as every pin/namespace update.
fn relocate_pins_in(
    conn: &Connection,
    instance: &str,
    space: &str,
    source: &[String],
    destination: &[String],
    replacement: Option<(&str, &str)>,
    allow_source_split: bool,
) -> Result<(), AccountError> {
    let rebase = |path: &[String]| -> Result<Vec<String>, AccountError> {
        if !path.starts_with(source) {
            return Ok(path.to_vec());
        }
        let mut next = destination.to_vec();
        next.extend_from_slice(&path[source.len()..]);
        if next.len() > 128 {
            return Err(AccountError::new("invalid Space path"));
        }
        Ok(next)
    };
    // One containing source pin can become two accurate active roots. Multiple
    // overlapping source owners need a separate policy; never guess which one
    // owns the extracted destination. Freeze traversal before inserting a root.
    let through: i64 = conn
        .query_row("SELECT coalesce(max(rowid),0) FROM pins", [], |row| {
            row.get(0)
        })
        .map_err(|_| AccountError::new("cannot inspect pin high water"))?;
    let mut destination_merge = None;
    let source_split_root = if allow_source_split && replacement.is_some() {
        let mut statement = conn
            .prepare("SELECT root FROM pins WHERE instance=?1 AND space=?2 AND rowid<=?3")
            .map_err(|_| AccountError::new("cannot inspect source pin owners"))?;
        let rows = statement
            .query_map(params![instance, space, through], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|_| AccountError::new("cannot inspect source pin owners"))?;
        let mut ancestors = Vec::new();
        let mut overlapping = false;
        let mut roots = Vec::new();
        for row in rows {
            let root = row.map_err(|_| AccountError::new("invalid source pin owner"))?;
            let path: Vec<String> = serde_json::from_str(&root)
                .map_err(|_| AccountError::new("invalid pinned path"))?;
            overlapping |= path.starts_with(source);
            if source.starts_with(&path) && !destination.starts_with(&path) {
                ancestors.push(root.clone());
            }
            roots.push((root, path));
        }
        let destination_ancestors: Vec<_> = roots
            .iter()
            .filter(|(_, path)| {
                destination.starts_with(path)
                    && !source.starts_with(path)
                    && path.as_slice() != destination
            })
            .collect();
        if destination_ancestors.len() == 1 {
            let (root, path) = destination_ancestors[0];
            // Exactly these two owners, no containing/common/source-subtree or
            // target-subtree owners whose policy would be ambiguous.
            let ambiguous = roots.iter().any(|(_, p)| {
                p != path
                    && p.as_slice() != source
                    && (source.starts_with(p)
                        || p.starts_with(source)
                        || destination.starts_with(p)
                        || p.starts_with(destination))
            });
            if !ambiguous && roots.iter().any(|(_, p)| p.as_slice() == source) {
                destination_merge = Some((
                    root.clone(),
                    complete_incoming_pin(conn, instance, space, source, destination)?,
                ));
            }
        }
        if !overlapping && ancestors.len() == 1 {
            ancestors.pop()
        } else {
            None
        }
    } else {
        None
    };
    let mut pins = Vec::new();
    let mut extracted = None;
    {
        let mut stmt = conn
            .prepare(
                "SELECT rowid,root,directories,manifest FROM pins WHERE instance=?1 AND space=?2 AND rowid<=?3",
            )
            .map_err(|_| AccountError::new("cannot inspect pins for rename"))?;
        let rows = stmt
            .query_map(params![instance, space, through], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| AccountError::new("cannot inspect pins for rename"))?;
        for row in rows {
            let (rowid, root, directories, manifest) =
                row.map_err(|_| AccountError::new("invalid pin"))?;
            let path: Vec<String> = serde_json::from_str(&root)
                .map_err(|_| AccountError::new("invalid pinned path"))?;
            let mut dirs: Vec<(Vec<String>, String)> = serde_json::from_str(&directories)
                .map_err(|_| AccountError::new("invalid pinned directories"))?;
            let mut files: Vec<FileVersion> = serde_json::from_str(&manifest)
                .map_err(|_| AccountError::new("invalid pin manifest"))?;
            let moving_root = path.starts_with(source);
            let contains_source = source.starts_with(&path);
            let contains_destination = destination.starts_with(&path);
            let source_split = source_split_root.as_ref() == Some(&root);
            let destination_split = destination_merge
                .as_ref()
                .is_some_and(|(ancestor, _)| ancestor == &root);
            if moving_root
                && path == source
                && let Some((ancestor, _)) = &destination_merge
            {
                pins.push((rowid, root, ancestor.clone(), Vec::new(), Vec::new(), true));
                continue;
            }
            let mut retained_displacement = false;
            if let Some((target_id, target_etag)) = replacement {
                // A containing pin either covers both sides or is the single
                // source-only owner eligible for capture and extraction.
                if !moving_root
                    && contains_source != contains_destination
                    && !path.starts_with(destination)
                    && !source_split
                    && !destination_split
                {
                    return Err(AccountError::new("rename would displace or split a pin"));
                }
                let displaced = path.starts_with(destination)
                    || (contains_destination
                        && !moving_root
                        && (dirs.iter().any(|(p, _)| p.starts_with(destination))
                            || files.iter().any(|file| file.path.starts_with(destination))));
                if displaced || source_split || destination_split {
                    if destination_split
                        && (!dirs
                            .iter()
                            .any(|(p, id)| p == destination && id == target_id)
                            || dirs
                                .iter()
                                .any(|(p, _)| p.starts_with(destination) && p != destination)
                            || files.iter().any(|file| file.path.starts_with(destination)))
                    {
                        return Err(AccountError::new("rename would displace or split a pin"));
                    }
                    let captured=conn.execute("INSERT INTO pin_copies(instance,space,root,is_dir,directories,manifest,issuer,subject,displaced_path,target_id,target_etag) SELECT p.instance,p.space,p.root,p.is_dir,p.directories,p.manifest,a.issuer,a.subject,?2,?3,?4 FROM pins p JOIN account_identities a ON a.instance=p.instance WHERE p.rowid=?1",params![rowid,path_key(destination)?,target_id,target_etag])
                        .map_err(|error|sqlite_storage_error(error,"cannot retain displaced pin"))?;
                    if captured != 1 {
                        return Err(AccountError::new("displaced pin identity unavailable"));
                    }
                    retained_displacement = true;
                    let copy = conn.last_insert_rowid().to_string();
                    conn.execute("INSERT INTO pin_copy_files SELECT instance,space,?4,path,version,verified_complete FROM files WHERE instance=?1 AND space=?2 AND root=?3",params![instance,space,root,copy])
                        .map_err(|error|sqlite_storage_error(error,"cannot retain displaced pin versions"))?;
                    conn.execute("INSERT INTO pin_copy_chunks SELECT instance,space,?4,path,offset,body,digest FROM chunks WHERE instance=?1 AND space=?2 AND root=?3",params![instance,space,root,copy])
                        .map_err(|error|sqlite_storage_error(error,"cannot retain displaced pin chunks"))?;
                    if source_split {
                        if !dirs.iter().any(|(p, _)| p == source) {
                            return Err(AccountError::new("rename would displace or split a pin"));
                        }
                        let mut moving_dirs: Vec<_> = dirs
                            .iter()
                            .filter(|(p, _)| p.starts_with(source))
                            .cloned()
                            .collect();
                        let mut moving_files: Vec<_> = files
                            .iter()
                            .filter(|file| file.path.starts_with(source))
                            .cloned()
                            .collect();
                        let source_key = path_key(source)?;
                        let prefix = format!("{},", source_key.trim_end_matches(']'));
                        for table in ["chunks", "files"] {
                            conn.execute(&format!("UPDATE {table} SET root=?4 WHERE instance=?1 AND space=?2 AND root=?3 AND (path=?4 OR substr(path,1,length(?5))=?5)"), params![instance,space,root,source_key,prefix])
                                .map_err(|error|sqlite_storage_error(error,"cannot extract source pin contents"))?;
                        }
                        dirs.retain(|(p, _)| !p.starts_with(source));
                        files.retain(|file| !file.path.starts_with(source));
                        for (p, _) in &mut moving_dirs {
                            *p = rebase(p)?;
                        }
                        for file in &mut moving_files {
                            file.path = rebase(&file.path)?;
                        }
                        moving_dirs.sort();
                        moving_files.sort_by(|a, b| a.path.cmp(&b.path));
                        extracted = Some((source_key, moving_dirs, moving_files));
                    }
                    if path.starts_with(destination) {
                        for table in ["chunks", "files", "pins"] {
                            conn.execute(
                                &format!(
                                    "DELETE FROM {table} WHERE instance=?1 AND space=?2 AND root=?3"
                                ),
                                params![instance, space, root],
                            )
                            .map_err(|error| {
                                sqlite_storage_error(error, "cannot retire displaced active pin")
                            })?;
                        }
                        continue;
                    }
                    dirs.retain(|(p, _)| !p.starts_with(destination));
                    files.retain(|file| !file.path.starts_with(destination));
                    let key = path_key(destination)?;
                    let prefix = format!("{},", key.trim_end_matches(']'));
                    for table in ["chunks", "files"] {
                        conn.execute(&format!("DELETE FROM {table} WHERE instance=?1 AND space=?2 AND root=?3 AND (path=?4 OR substr(path,1,length(?5))=?5)"),params![instance,space,root,key,prefix])
                            .map_err(|error|sqlite_storage_error(error,"cannot update containing active pin"))?;
                    }
                    if destination_split {
                        let (_, incoming) = destination_merge.as_ref().ok_or_else(|| {
                            AccountError::new("rename would displace or split a pin")
                        })?;
                        for (p, id) in &incoming.directories {
                            dirs.push((rebase(p)?, id.clone()));
                        }
                        for file in &incoming.files {
                            let mut file = file.clone();
                            file.path = rebase(&file.path)?;
                            files.push(file);
                        }
                        if dirs.len() + files.len() > 4097
                            || files
                                .iter()
                                .try_fold(0u64, |total, file| {
                                    total.checked_add(file.size).filter(|n| *n <= MAX_PIN_BYTES)
                                })
                                .is_none()
                            || serde_json::to_string(&dirs)
                                .map_err(|_| AccountError::new("invalid pinned directories"))?
                                .len()
                                > 16777216
                            || serde_json::to_string(&files)
                                .map_err(|_| AccountError::new("invalid pin manifest"))?
                                .len()
                                > 16777216
                        {
                            return Err(AccountError::new("rename would displace or split a pin"));
                        }
                    }
                }
            }
            if (!moving_root
                && contains_source != contains_destination
                && !source_split
                && !destination_split)
                || (!moving_root && path.starts_with(destination))
            {
                return Err(AccountError::new("rename would displace or split a pin"));
            }
            if replacement.is_none()
                && contains_destination
                && !moving_root
                && (dirs.iter().any(|(p, _)| p.starts_with(destination))
                    || files.iter().any(|file| file.path.starts_with(destination)))
            {
                return Err(AccountError::new("rename would displace or split a pin"));
            }
            if !moving_root && !contains_source && !destination_split {
                continue;
            }
            let mut changed = moving_root || retained_displacement;
            for (path, _) in &mut dirs {
                changed |= path.starts_with(source);
                *path = rebase(path)?;
            }
            for file in &mut files {
                changed |= file.path.starts_with(source);
                file.path = rebase(&file.path)?;
            }
            if !changed {
                continue;
            }
            dirs.sort();
            files.sort_by(|a, b| a.path.cmp(&b.path));
            pins.push((rowid, root, path_key(&rebase(&path)?)?, dirs, files, false));
        }
    }
    if let Some((source_key, dirs, files)) = extracted {
        // Insert only after closing the original pin scan: deleted target
        // rowids may be reused, so a rowid high water alone cannot exclude a
        // newly inserted pin from that traversal.
        conn.execute("INSERT INTO pins(instance,space,root,is_dir,directories,manifest) VALUES(?1,?2,?3,1,?4,?5)", params![instance,space,source_key,serde_json::to_string(&dirs).map_err(|_|AccountError::new("invalid pinned directories"))?,serde_json::to_string(&files).map_err(|_|AccountError::new("invalid pin manifest"))?])
            .map_err(|error|sqlite_storage_error(error,"cannot extract source pin"))?;
        pins.push((
            conn.last_insert_rowid(),
            source_key,
            path_key(destination)?,
            dirs,
            files,
            false,
        ));
    }
    for (rowid, old_root, new_root, dirs, files, retire) in pins {
        let mut file_rows = Vec::new();
        {
            let mut stmt = conn.prepare("SELECT rowid,path,version FROM files WHERE instance=?1 AND space=?2 AND root=?3").map_err(|_| AccountError::new("cannot inspect pinned versions"))?;
            let rows = stmt
                .query_map(params![instance, space, old_root], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|_| AccountError::new("cannot inspect pinned versions"))?;
            for row in rows {
                let (id, path, version) =
                    row.map_err(|_| AccountError::new("invalid pinned version"))?;
                let path: Vec<String> = serde_json::from_str(&path)
                    .map_err(|_| AccountError::new("invalid pinned path"))?;
                let mut version: FileVersion = serde_json::from_str(&version)
                    .map_err(|_| AccountError::new("invalid pinned version"))?;
                if version.path != path {
                    return Err(AccountError::new("invalid pinned version"));
                }
                let next = rebase(&path)?;
                if new_root == old_root && next == path {
                    continue;
                }
                version.path = next;
                file_rows.push((
                    id,
                    path_key(&version.path)?,
                    serde_json::to_string(&version)
                        .map_err(|_| AccountError::new("invalid pinned version"))?,
                ));
            }
        }
        let mut chunks = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT rowid,path FROM chunks WHERE instance=?1 AND space=?2 AND root=?3")
                .map_err(|_| AccountError::new("cannot inspect pinned chunks"))?;
            let rows = stmt
                .query_map(params![instance, space, old_root], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| AccountError::new("cannot inspect pinned chunks"))?;
            for row in rows {
                let (id, path) = row.map_err(|_| AccountError::new("invalid pinned chunk"))?;
                let path: Vec<String> = serde_json::from_str(&path)
                    .map_err(|_| AccountError::new("invalid pinned path"))?;
                let next = rebase(&path)?;
                if new_root != old_root || next != path {
                    chunks.push((id, path_key(&next)?));
                }
            }
        }
        for (id, path) in chunks {
            conn.execute(
                "UPDATE chunks SET root=?1,path=?2 WHERE rowid=?3",
                params![new_root, path, id],
            )
            .map_err(|error| sqlite_storage_error(error, "cannot relocate pinned chunks"))?;
        }
        for (id, path, version) in file_rows {
            conn.execute(
                "UPDATE files SET root=?1,path=?2,version=?3 WHERE rowid=?4",
                params![new_root, path, version, id],
            )
            .map_err(|error| sqlite_storage_error(error, "cannot relocate pinned versions"))?;
        }
        if retire {
            conn.execute("DELETE FROM pins WHERE rowid=?1", [rowid])
                .map_err(|error| sqlite_storage_error(error, "cannot retire merged source pin"))?;
            continue;
        }
        conn.execute(
            "UPDATE pins SET root=?1,directories=?2,manifest=?3 WHERE rowid=?4",
            params![
                new_root,
                serde_json::to_string(&dirs)
                    .map_err(|_| AccountError::new("invalid pinned directories"))?,
                serde_json::to_string(&files)
                    .map_err(|_| AccountError::new("invalid pin manifest"))?,
                rowid
            ],
        )
        .map_err(|error| sqlite_storage_error(error, "cannot relocate pin"))?;
    }
    Ok(())
}

pub(crate) struct TreeMoveRequest<'a> {
    pub instance: &'a str,
    pub space: &'a str,
    pub source: &'a [String],
    pub destination: &'a [String],
    pub entry: &'a Entry,
    pub target: Option<&'a Entry>,
    pub local_target: Option<&'a str>,
    pub parents: crate::RenameParents<'a>,
    pub open_versions: &'a [FileVersion],
    pub open_directories: &'a [(Vec<String>, String)],
    pub offline: Option<&'a crate::MountBinding>,
}

fn pin_copy_allowance(conn: &Connection, instance: &str, space: &str) -> Result<u64, AccountError> {
    // Replacement/extraction preserves whole containing pins, not merely a
    // target subtree. Charge all Space pin rows conservatively, including BLOB
    // copies and new root/index/identity metadata. The relocation allowance
    // separately pays for destination path growth; the writer rechecks its plan.
    let bytes:u64=conn.query_row("SELECT coalesce(sum(bytes),0) FROM (SELECT sum(length(CAST(root AS BLOB))+length(CAST(directories AS BLOB))+length(CAST(manifest AS BLOB))+4096) AS bytes FROM pins WHERE instance=?1 AND space=?2 UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(CAST(version AS BLOB))+1024) FROM files WHERE instance=?1 AND space=?2 UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(body)+1024) FROM chunks WHERE instance=?1 AND space=?2)",params![instance,space],|r|r.get(0)).map_err(|_|AccountError::new("cannot size retained pin copies"))?;
    bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(65536))
        .ok_or_else(|| AccountError::new("retained pin storage estimate overflow"))
}

// Only an exact pending destination root can be collapsed. Its original
// source/proofs/token stay immutable; every other overlap remains fenced.
fn tree_chain_in(
    conn: &Connection,
    request: &TreeMoveRequest<'_>,
) -> Result<Option<TreeMove>, AccountError> {
    let through: i64 = conn
        .query_row(
            "SELECT coalesce(max(id),0) FROM operation_journal",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect tree chain high water"))?;
    let mut after = None;
    let mut chain = None;
    loop {
        let page = tree_moves_scoped_in(
            conn,
            request.instance,
            Some(request.space),
            (after, through),
        )?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        for existing in page {
            if ![request.source, request.destination].iter().any(|path| {
                path.starts_with(&existing.source)
                    || existing.source.starts_with(path)
                    || path.starts_with(&existing.destination)
                    || existing.destination.starts_with(path)
            }) {
                continue;
            }
            if chain.is_some()
                || request.offline.is_none()
                || !existing.offline
                || existing.state != "pending"
                || existing.destination != request.source
                || existing.target.is_some()
                || request.target.is_some()
                || request.local_target.is_some()
                || request.destination.starts_with(&existing.source)
                || existing.source.starts_with(request.destination)
                || request.entry.id() != existing.entry.id()
                || request.entry.etag() != existing.entry.etag()
                || !equivalent_parents(
                    conn,
                    request.instance,
                    request.space,
                    request.source,
                    request.parents.source,
                    &existing.destination_parents,
                )?
            {
                return Err(AccountError::new("path has unresolved operations"));
            }
            let eligible: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal j WHERE j.id=?1 AND j.base_file_id=?2 AND j.base_etag IS ?3 AND j.confirmed_file_id IS NULL AND j.confirmed_etag IS NULL AND NOT EXISTS(SELECT 1 FROM sync_reads WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM mutation_receipts WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM upload_verifications WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM tree_targets WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM write_dependencies WHERE operation_id=j.id OR predecessor_id=j.id) AND NOT EXISTS(SELECT 1 FROM operation_journal consumer WHERE consumer.error_msg='destination-operation:'||j.id AND consumer.op_type IN ('move-source','move-dir-source') AND consumer.state IN ('pending','conflict','uncertain')))",params![existing.id,existing.entry.id(),existing.entry.etag()],|row|row.get(0))
                .map_err(|_|AccountError::new("cannot inspect pending tree chain"))?;
            if !eligible {
                return Err(AccountError::new("path has unresolved operations"));
            }
            chain = Some(existing);
        }
    }
    if chain.is_some() {
        // Immutable overlays created at an intermediate name need an alias
        // history, which this bounded collapse deliberately does not invent.
        let key = path_key(request.source)?;
        let prefix = format!("{},", key.trim_end_matches(']'));
        let upper = format!("{}-", key.trim_end_matches(']'));
        let based_here: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM dirty_roots WHERE json_extract(base,'$.instance')=?1 AND json_extract(base,'$.space')=?2 AND (json_extract(base,'$.path')=?3 OR (json_extract(base,'$.path')>=?4 AND json_extract(base,'$.path')<?5)))",params![request.instance,request.space,key,prefix,upper],|row|row.get(0))
            .map_err(|_|AccountError::new("cannot inspect intermediate tree bases"))?;
        if based_here {
            return Err(AccountError::new("path has unresolved operations"));
        }
    }
    Ok(chain)
}

// An unclaimed file-rename edge keeps its IDs and destination verification.
// Only the source need move: an outside create-only destination stays fixed.
// The source's durable tree-destination ancestry separately gates its DELETE.
fn validate_chain_file_rename(
    conn: &Connection,
    previous: &TreeMove,
    context: RelocationContext<'_>,
    change: &RelocatedOperation,
    included: &std::collections::HashSet<i64>,
) -> Result<(), AccountError> {
    let refused = || AccountError::new("path has unresolved operations");
    let (id,etag,message):(String,String,String)=conn.query_row("SELECT base_file_id,base_etag,error_msg FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='move-source' AND state='pending' AND staged_file=?5 AND confirmed_file_id IS NULL AND confirmed_etag IS NULL",params![change.id,context.instance,context.space,path_key(&change.old_path)?,change.token],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))
        .map_err(|_|refused())?;
    let destination_id = message
        .strip_prefix("destination-operation:")
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(refused)?;
    if message != format!("destination-operation:{destination_id}")
        || destination_id == change.id
        || !crate::dav::valid_remote_id(&id)
        || !crate::dav::strong_etag(&etag)
        || change.token.len() != 32
        || !change.token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(refused());
    }
    let (path,root):(String,String)=conn.query_row("SELECT path,staged_file FROM operation_journal j WHERE id=?1 AND instance=?2 AND space=?3 AND op_type='write' AND state='pending' AND base_file_id IS NULL AND base_etag IS NULL AND confirmed_file_id IS NULL AND confirmed_etag IS NULL AND error_msg IS NULL AND NOT EXISTS(SELECT 1 FROM operation_journal other WHERE other.instance=j.instance AND other.space=j.space AND other.path=j.path AND other.id<>j.id)",params![destination_id,context.instance,context.space],|row|Ok((row.get(0)?,row.get(1)?)))
        .map_err(|_|refused())?;
    let destination: Vec<String> = serde_json::from_str(&path).map_err(|_| refused())?;
    if change.state != "pending"
        || change.old_path.len() <= context.source.len()
        || !change.old_path.starts_with(context.source)
        || destination.is_empty()
        || destination == change.old_path
    {
        return Err(refused());
    }
    if !included.contains(&destination_id) {
        // Outside endpoints are inspected, never retargeted or rebound. Require
        // a fresh remote-parent destination, with no other tree/history or
        // admitted work; pending local parents remain outside this exception.
        if destination.starts_with(context.source)
            || destination.starts_with(context.destination)
            || context.destination.starts_with(&destination)
            || destination.starts_with(&previous.source)
            || previous.source.starts_with(&destination)
        {
            return Err(refused());
        }
        let admitted:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sync_reads WHERE operation_id=?1) OR EXISTS(SELECT 1 FROM mutation_receipts WHERE operation_id=?1) OR EXISTS(SELECT 1 FROM upload_verifications WHERE operation_id=?1) OR EXISTS(SELECT 1 FROM write_dependencies WHERE operation_id=?1 OR predecessor_id=?1)",[destination_id],|row|row.get(0))
            .map_err(|_|AccountError::new("cannot inspect outside rename admission"))?;
        if admitted {
            return Err(refused());
        }
        let parents = load_operation_parents(conn, destination_id, &destination)?;
        for (depth, identity) in parents.iter().enumerate() {
            let DirectoryIdentity::Remote(expected) = identity else {
                return Err(refused());
            };
            let observed = offline_directory_in(
                conn,
                context.instance,
                context.space,
                &destination[..depth],
                None,
            )?;
            if !observed
                .get(&destination[depth])?
                .is_some_and(|entry| entry.is_directory() && entry.id() == expected)
            {
                return Err(refused());
            }
        }
        let (name, parent) = destination.split_last().ok_or_else(refused)?;
        let visible = offline_directory_in(conn, context.instance, context.space, parent, None)?;
        if !visible.get(name)?.is_some_and(|entry| {
            entry.id() == format!("cirrus-staged:{destination_id}")
                && entry.etag() == Some(format!("\"cirrus-staged-{root}\"").as_str())
        }) {
            return Err(refused());
        }
        // The raw authenticated observation, unlike its staged projection, must
        // still prove absence. Reconnect rechecks parents and If-None-Match:*.
        if directory_snapshot_in(conn, context.instance, context.space, parent)?
            .ok_or_else(refused)?
            .get(name)?
            .is_some()
        {
            return Err(refused());
        }
        let mut after = None;
        loop {
            let page = tree_moves_scoped_in(
                conn,
                context.instance,
                Some(context.space),
                (after, i64::MAX),
            )?;
            let Some(last) = page.last() else { break };
            after = Some(last.id);
            if page.iter().any(|tree| {
                destination.starts_with(&tree.source)
                    || tree.source.starts_with(&destination)
                    || destination.starts_with(&tree.destination)
                    || tree.destination.starts_with(&destination)
            }) {
                return Err(refused());
            }
        }
    }
    let consumers:u64=conn.query_row("SELECT count(*) FROM operation_journal WHERE op_type IN ('move-source','move-dir-source') AND error_msg=?1 AND state IN ('pending','conflict','uncertain')",[message],|row|row.get(0))
        .map_err(|_|AccountError::new("cannot inspect pending rename consumers"))?;
    if consumers != 1 {
        return Err(refused());
    }
    let original: FileVersion = serde_json::from_str(
        &overlay::Overlay::load_in(conn, &root)?
            .original_base_json()?
            .ok_or_else(refused)?,
    )
    .map_err(|_| refused())?;
    let mut expected_path = previous.source.clone();
    expected_path.extend_from_slice(&change.old_path[context.source.len()..]);
    if original.instance != context.instance
        || original.space != context.space
        || original.path != expected_path
        || original.id != id
        || original.etag != etag
    {
        return Err(refused());
    }
    let mut visible = original.clone();
    visible.path = change.old_path.clone();
    if tree_content_base_in(conn, &visible, false)?.as_ref() != Some(&original) {
        return Err(refused());
    }
    Ok(())
}

// An incoming source stays at its original remote coordinates. Only its
// create-only destination joins the tree relocation; the ID edge stays fixed.
fn validate_chain_incoming_file(
    conn: &Connection,
    binding: &crate::MountBinding,
    change: &RelocatedOperation,
    source_id: i64,
) -> Result<(), AccountError> {
    let refused = || AccountError::new("path has unresolved operations");
    let root:String=conn.query_row("SELECT staged_file FROM operation_journal j WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='pending' AND staged_file=?5 AND base_file_id IS NULL AND base_etag IS NULL AND confirmed_file_id IS NULL AND confirmed_etag IS NULL AND error_msg IS NULL AND NOT EXISTS(SELECT 1 FROM operation_journal other WHERE other.instance=j.instance AND other.space=j.space AND other.path=j.path AND other.id<>j.id)",params![change.id,binding.instance,binding.space,path_key(&change.old_path)?,change.token],|row|row.get(0)).map_err(|_|refused())?;
    let (source,id,etag,token):(String,String,String,String)=conn.query_row("SELECT path,base_file_id,base_etag,staged_file FROM operation_journal j WHERE id=?1 AND instance=?2 AND space=?3 AND op_type='move-source' AND state='pending' AND error_msg=?4 AND confirmed_file_id IS NULL AND confirmed_etag IS NULL AND NOT EXISTS(SELECT 1 FROM operation_journal other WHERE other.instance=j.instance AND other.space=j.space AND other.path=j.path AND other.id<>j.id) AND NOT EXISTS(SELECT 1 FROM sync_reads WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM mutation_receipts WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM upload_verifications WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM write_dependencies WHERE operation_id=j.id OR predecessor_id=j.id)",params![source_id,binding.instance,binding.space,format!("destination-operation:{}",change.id)],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(|_|refused())?;
    let source: Vec<String> = serde_json::from_str(&source).map_err(|_| refused())?;
    if change.state != "pending"
        || source.is_empty()
        || !crate::dav::valid_remote_id(&id)
        || !crate::dav::strong_etag(&etag)
        || token.len() != 32
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(refused());
    }
    let count:u64=conn.query_row("SELECT count(*) FROM operation_journal WHERE op_type IN ('move-source','move-dir-source') AND error_msg=?1 AND state IN ('pending','conflict','uncertain')",[format!("destination-operation:{}",change.id)],|row|row.get(0)).map_err(|_|refused())?;
    if count != 1 {
        return Err(refused());
    }
    let mut after = None;
    loop {
        let page = tree_moves_scoped_in(
            conn,
            &binding.instance,
            Some(&binding.space),
            (after, i64::MAX),
        )?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        if page.iter().any(|tree| {
            source.starts_with(&tree.source)
                || tree.source.starts_with(&source)
                || source.starts_with(&tree.destination)
                || tree.destination.starts_with(&source)
                || source.starts_with(&change.new_path)
                || change.new_path.starts_with(&source)
        }) {
            return Err(refused());
        }
    }
    let parents = load_operation_parents(conn, source_id, &source)?;
    for (depth, parent) in parents.iter().enumerate() {
        let DirectoryIdentity::Remote(expected) = parent else {
            return Err(refused());
        };
        if !offline_directory_proof(conn, binding, &source[..depth])?
            .get(&source[depth])?
            .is_some_and(|entry| entry.is_directory() && entry.id() == expected)
        {
            return Err(refused());
        }
    }
    let (name, parent) = source.split_last().ok_or_else(refused)?;
    offline_directory_proof(conn, binding, parent)?;
    let raw = directory_snapshot_in(conn, &binding.instance, &binding.space, parent)?
        .ok_or_else(refused)?;
    let entry = raw.get(name)?.ok_or_else(refused)?;
    let original: FileVersion = serde_json::from_str(
        &overlay::Overlay::load_in(conn, &root)?
            .original_base_json()?
            .ok_or_else(refused)?,
    )
    .map_err(|_| refused())?;
    if original.instance != binding.instance
        || original.space != binding.space
        || original.path != source
        || original.id != id
        || original.etag != etag
        || entry.is_directory()
        || entry.id() != original.id
        || entry.etag() != Some(original.etag.as_str())
        || entry.size() != Some(original.size)
        || entry.checksums() != original.checksums
    {
        return Err(refused());
    }
    let (name, parent) = change.old_path.split_last().ok_or_else(refused)?;
    let visible = offline_directory_proof(conn, binding, parent)?;
    if !visible.get(name)?.is_some_and(|entry| {
        entry.id() == format!("cirrus-staged:{}", change.id)
            && entry.etag() == Some(format!("\"cirrus-staged-{root}\"").as_str())
    }) {
        return Err(refused());
    }
    // At the exact B root, ordinary saved-parent lookup intentionally cannot
    // relabel A. Use the existing immutable MOVE-copy proof for that identity.
    let raw = match change.old_parents.last() {
        Some(DirectoryIdentity::Remote(id)) => {
            offline_child_snapshot_in(conn, &binding.instance, &binding.space, parent, id)?
        }
        Some(DirectoryIdentity::Pending(_)) => None,
        None => directory_snapshot_in(conn, &binding.instance, &binding.space, parent)?,
    };
    match raw {
        Some(raw) if raw.get(name)?.is_none() => {}
        None if matches!(
            change.old_parents.last(),
            Some(DirectoryIdentity::Pending(_))
        ) => {}
        _ => return Err(refused()),
    }
    Ok(())
}

pub(crate) fn queue_tree_move(request: TreeMoveRequest<'_>) -> Result<i64, AccountError> {
    let TreeMoveRequest {
        instance,
        space,
        source,
        destination,
        entry,
        target,
        local_target,
        parents,
        open_versions,
        open_directories,
        offline,
    } = request;
    let crate::RenameParents {
        source: source_parents,
        destination: destination_parents,
    } = parents;
    if source.is_empty()
        || destination.is_empty()
        || destination.starts_with(source)
        || source.starts_with(destination)
        || !entry.is_directory()
        || entry.etag().is_none()
    {
        return Err(AccountError::new("invalid directory rename"));
    }
    let target_id = local_target
        .map(|value| {
            value
                .strip_prefix("cirrus-dir:")
                .and_then(|id| id.parse::<i64>().ok())
                .ok_or_else(|| AccountError::new("invalid directory target"))
        })
        .transpose()?;
    let token = namespace_token()?;
    // The allowance must outlive rollback and connection close.
    let reservation;
    let mut conn = database()?;
    let chain = tree_chain_in(&conn, &request)?;
    let source_key = path_key(source)?;
    let destination_key = path_key(destination)?;
    let source_chain = encode_parents(source, source_parents)?;
    let destination_chain = encode_parents(destination, destination_parents)?;
    let source_entry = serde_json::to_string(entry)
        .map_err(|_| AccountError::new("invalid directory metadata"))?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect tree rename plan"))?;
    let encoded = serde_json::to_vec(&(
        (
            i64::MAX,
            instance,
            space,
            &source_key,
            "move-tree",
            entry.id(),
            entry.etag(),
            &token,
            "pending",
            Option::<&str>::None,
            i64::MAX,
        ),
        (i64::MAX, &source_chain, &destination_chain),
        (
            i64::MAX,
            &destination_key,
            &source_entry,
            target.map(Entry::id),
            target.and_then(Entry::etag),
            offline.is_some(),
        ),
        (
            target_id,
            "resolved",
            "empty local directory replaced",
            i64::MAX,
        ),
    ))
    .map_err(|_| AccountError::new("cannot size tree rename rows"))?;
    let mut planned = encoded.len() as u64;
    if offline.is_some() && target.is_some() {
        let bytes:u64=conn.query_row("SELECT length(CAST(self_id AS BLOB))+length(CAST(self_etag AS BLOB))+length(CAST(issuer AS BLOB))+length(CAST(subject AS BLOB))+length(CAST(entries AS BLOB))+256 FROM snapshots WHERE instance=?1 AND space=?2 AND path=?3",params![instance,space,destination_key],|row|row.get(0)).map_err(|_|AccountError::new("offline replacement observation unavailable"))?;
        planned = planned
            .checked_add(bytes)
            .ok_or_else(|| AccountError::new("tree storage estimate overflow"))?;
    }
    let mut add = |bytes: u64| -> Result<(), AccountError> {
        planned = planned
            .checked_add(bytes)
            .ok_or_else(|| AccountError::new("tree storage estimate overflow"))?;
        Ok(())
    };
    let root = DirectoryIdentity::Remote(entry.id().to_owned());
    let relocation = RelocationContext {
        instance,
        space,
        source,
        destination,
        parents,
        root: &root,
    };
    // Pending descendants and explicitly open confirmed rows are the only
    // journal rows relocated. Stream bounded path pages, never history/blobs.
    let open_ids: Vec<i64> = open_versions
        .iter()
        .filter_map(|version| {
            version
                .id
                .strip_prefix("cirrus-staged:")
                .and_then(|id| id.parse().ok())
        })
        .chain(open_directories.iter().filter_map(|(_, resource)| {
            resource
                .strip_prefix("cirrus-dir:")
                .and_then(|id| id.parse().ok())
        }))
        .collect();
    let open_ids = serde_json::to_string(&open_ids)
        .map_err(|_| AccountError::new("cannot size open tree identities"))?;
    let through: i64 = conn
        .query_row(
            "SELECT coalesce(max(id),0) FROM operation_journal",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect tree rename plan"))?;
    let mut after: Option<i64> = None;
    loop {
        let mut stmt = conn.prepare("SELECT j.id,j.path,j.state,length(CAST(j.path AS BLOB))+length(CAST(j.staged_file AS BLOB))+coalesce(length(CAST(j.base_file_id AS BLOB)),0)+coalesce(length(CAST(j.base_etag AS BLOB)),0)+coalesce(length(CAST(j.error_msg AS BLOB)),0)+length(CAST(p.parents AS BLOB)) FROM operation_journal j JOIN operation_parents p ON p.operation_id=j.id WHERE j.instance=?1 AND j.space=?2 AND (?3 IS NULL OR j.id>?3) AND j.id<=?4 AND (j.state='pending' OR j.id IN (SELECT value FROM json_each(?5))) ORDER BY j.id LIMIT 32")
            .map_err(|_| AccountError::new("cannot size tree descendants"))?;
        let rows = stmt
            .query_map(params![instance, space, after, through, open_ids], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })
            .map_err(|_| AccountError::new("cannot size tree descendants"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AccountError::new("invalid tree descendant"))?;
        if rows.is_empty() {
            break;
        }
        for (id, path, state, bytes) in rows {
            after = Some(id);
            let path: Vec<String> = serde_json::from_str(&path)
                .map_err(|_| AccountError::new("invalid namespace path"))?;
            if path.starts_with(source) {
                let change = prepare_relocated_operation(&conn, relocation, id, &state, path)?;
                let encoded = serde_json::to_vec(&(
                    id,
                    path_key(&change.new_path)?,
                    encode_parents(&change.new_path, &change.new_parents)?,
                    i64::MAX,
                ))
                .map_err(|_| AccountError::new("cannot size relocated descendant"))?;
                add(bytes)?;
                add(encoded.len() as u64)?;
            }
        }
    }
    // Match the publication's fixed-high-water, 32-path traversal. Inspect only
    // lengths of saved JSON; do not decode or collect saved subtree listings.
    let through: i64 = conn
        .query_row("SELECT coalesce(max(rowid),0) FROM snapshots", [], |row| {
            row.get(0)
        })
        .map_err(|_| AccountError::new("cannot size tree snapshots"))?;
    let mut after: Option<i64> = None;
    loop {
        let mut stmt = conn.prepare("SELECT rowid,path,length(CAST(entries AS BLOB))+coalesce(length(CAST(self_id AS BLOB)),0)+coalesce(length(CAST(self_etag AS BLOB)),0)+length(CAST(issuer AS BLOB))+length(CAST(subject AS BLOB))+64 FROM snapshots WHERE instance=?1 AND space=?2 AND (?3 IS NULL OR rowid>?3) AND rowid<=?4 ORDER BY rowid LIMIT 32")
            .map_err(|_| AccountError::new("cannot size tree snapshots"))?;
        let rows = stmt
            .query_map(params![instance, space, after, through], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .map_err(|_| AccountError::new("cannot size tree snapshots"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AccountError::new("invalid tree snapshot"))?;
        if rows.is_empty() {
            break;
        }
        for (id, path, bytes) in rows {
            after = Some(id);
            let path: Vec<String> = serde_json::from_str(&path)
                .map_err(|_| AccountError::new("invalid snapshot path"))?;
            if path.starts_with(source) {
                let mut next = destination.to_vec();
                next.extend_from_slice(&path[source.len()..]);
                if next.len() > 128 {
                    return Err(AccountError::new("invalid Space path"));
                }
                let encoded = serde_json::to_vec(&(instance, space, path_key(&next)?, i64::MAX))
                    .map_err(|_| AccountError::new("cannot size relocated snapshot"))?;
                add(bytes)?;
                add(encoded.len() as u64)?;
                if offline.is_some() {
                    // Conservative proof-row allowance, including original
                    // relative path/ID/ETag/generation and its 64-byte digest.
                    add(bytes)?;
                    add(encoded.len() as u64 + 128)?;
                }
            }
        }
    }
    // Indexed canonical root ranges include moving pins plus ancestor pins
    // whose manifests can contain the source. Unrelated Space pins need no
    // allowance. Within each selected root charge all rows/BLOBs conservatively.
    let ancestors = (0..source.len())
        .map(|length| path_key(&source[..length]))
        .collect::<Result<Vec<_>, _>>()?;
    let ancestors = serde_json::to_string(&ancestors)
        .map_err(|_| AccountError::new("cannot size pin ancestors"))?;
    let prefix = format!("{},", source_key.trim_end_matches(']'));
    let upper = format!("{}-", source_key.trim_end_matches(']'));
    let (pin_bytes, pin_paths): (u64,u64) = conn.query_row(
        "WITH roots AS (SELECT root FROM pins WHERE instance=?1 AND space=?2 AND (root=?3 OR (root>=?4 AND root<?5) OR root IN (SELECT value FROM json_each(?6))))
        SELECT coalesce(sum(bytes),0),coalesce(sum(paths),0) FROM (
            SELECT sum(length(CAST(root AS BLOB))+length(CAST(directories AS BLOB))+length(CAST(manifest AS BLOB))) AS bytes,sum(1+json_array_length(directories)+json_array_length(manifest)) AS paths FROM pins WHERE instance=?1 AND space=?2 AND root IN roots
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(CAST(version AS BLOB))),count(*)*3 FROM files WHERE instance=?1 AND space=?2 AND root IN roots
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(body)),count(*)*2 FROM chunks WHERE instance=?1 AND space=?2 AND root IN roots
        )", params![instance,space,source_key,prefix,upper,ancestors], |row| Ok((row.get(0)?,row.get(1)?)))
        .map_err(|_| AccountError::new("cannot size tree pin relocation"))?;
    add(pin_bytes)?;
    if offline.is_some() && target.is_some() {
        add(pin_copy_allowance(&conn, instance, space)?)?;
    }
    add(pin_paths
        .checked_mul(destination_key.len() as u64)
        .ok_or_else(|| AccountError::new("tree storage estimate overflow"))?)?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_TREE_MOVE_ADMISSION_WINDOW")?;
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_TREE_MOVE_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin directory rename"))?;
    if reservation.is_some() {
        let current: i64 = tx
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect tree rename plan"))?;
        if current != planning_version {
            return Err(AccountError::new(
                "directory metadata changed concurrently; retry",
            ));
        }
    }
    if serde_json::to_string(&tree_chain_in(&tx, &request)?)
        .map_err(|_| AccountError::new("cannot compare directory chain"))?
        != serde_json::to_string(&chain)
            .map_err(|_| AccountError::new("cannot compare directory chain"))?
    {
        return Err(AccountError::new(
            "directory metadata changed concurrently; retry",
        ));
    }
    reject_fenced_ancestor(&tx, instance, space, source)?;
    reject_fenced_ancestor(&tx, instance, space, destination)?;
    reject_moving_directory_bindings(&tx, instance, space, &[source, destination])?;
    if let Some(binding) = offline {
        validate_offline_tree(
            &tx,
            binding,
            (source, entry.id(), entry.etag()),
            (
                destination,
                local_target.or_else(|| target.map(Entry::id)),
                target.and_then(Entry::etag),
            ),
            parents,
            open_versions,
            chain.as_ref(),
        )?;
    }
    let count: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND state IN ('pending','conflict','uncertain')", [instance], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect namespace operations"))?;
    if count >= MAX_PENDING_NAMESPACE_OPERATIONS {
        return Err(AccountError::new("staging capacity exhausted"));
    }
    let duplicate: i64 = tx
        .query_row(
            "SELECT count(*) FROM operation_journal WHERE staged_file=?1",
            [&token],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect operation token"))?;
    if duplicate != 0 {
        return Err(AccountError::new("operation token collision"));
    }
    let root = DirectoryIdentity::Remote(entry.id().to_owned());
    let relocation = RelocationContext {
        instance,
        space,
        source,
        destination,
        parents,
        root: &root,
    };
    let mut changes = Vec::new();
    let mut found_target = false;
    {
        let through: i64 = tx
            .query_row(
                "SELECT coalesce(max(id),0) FROM operation_journal",
                [],
                |row| row.get(0),
            )
            .map_err(|_| AccountError::new("cannot inspect tree operation high water"))?;
        let mut after = None;
        loop {
            let page = local_directory_page(&tx, instance, space, after, through)?;
            let Some(last) = page.last() else {
                break;
            };
            after = Some(last.id);
            for row in page {
                let id = row.id;
                let kind = row.kind;
                let state = row.state;
                let path: Vec<String> = serde_json::from_str(&row.path)
                    .map_err(|_| AccountError::new("invalid namespace path"))?;
                if path.starts_with(destination) {
                    if Some(id) == target_id
                        && path == destination
                        && kind == "mkdir"
                        && state == "pending"
                    {
                        found_target = true;
                    } else {
                        if offline.is_some() && target.is_some() && path.len() > destination.len() {
                            return Err(AccountError::new("directory is not empty"));
                        }
                        return Err(AccountError::new("path has unresolved operations"));
                    }
                }
                if path.starts_with(source) {
                    if state != "pending"
                        || kind == "move-tree"
                        || (chain.is_some()
                            && !matches!(
                                kind.as_str(),
                                "write" | "mkdir" | "unlink" | "rmdir" | "move-source"
                            ))
                    {
                        return Err(AccountError::new("path has unresolved operations"));
                    }
                    changes.push(prepare_relocated_operation(
                        &tx, relocation, id, "pending", path,
                    )?);
                }
            }
        }
    }
    if target_id.is_some() && !found_target {
        return Err(AccountError::new("path has unresolved operations"));
    }
    if let Some(id) = target_id {
        tx.execute("UPDATE operation_journal SET state='resolved',error_msg='empty local directory replaced',updated_at=strftime('%s','now') WHERE id=?1 AND state='pending'", [id]).map_err(|error| sqlite_storage_error(error, "cannot resolve replaced directory"))?;
    }
    let mut included: std::collections::HashSet<i64> =
        changes.iter().map(|change| change.id).collect();
    for version in open_versions {
        let Some(value) = version.id.strip_prefix("cirrus-staged:") else {
            continue;
        };
        let id: i64 = value
            .parse()
            .map_err(|_| AccountError::new("invalid staged resource"))?;
        let staged = version
            .etag
            .strip_prefix("\"cirrus-staged-")
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| AccountError::new("invalid staged version"))?;
        let state: Option<String> = tx.query_row("SELECT state FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND staged_file=?5", params![id,instance,space,path_key(&version.path)?,staged], |row| row.get(0)).optional().map_err(|_| AccountError::new("cannot inspect open tree file"))?;
        match state.as_deref() {
            Some("pending") if included.contains(&id) => {}
            Some("synced") => {
                if included.insert(id) {
                    changes.push(prepare_relocated_operation(
                        &tx,
                        relocation,
                        id,
                        "synced",
                        version.path.clone(),
                    )?);
                }
            }
            _ => {
                return Err(AccountError::new(
                    "open file changed during directory rename",
                ));
            }
        }
    }
    for (path, resource) in open_directories {
        let id = resource
            .strip_prefix("cirrus-dir:")
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| AccountError::new("invalid local directory identity"))?;
        let state: Option<String> = tx.query_row("SELECT state FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='mkdir'", params![id,instance,space,path_key(path)?], |row| row.get(0)).optional().map_err(|_| AccountError::new("cannot inspect open tree directory"))?;
        match state.as_deref() {
            Some("pending") if included.contains(&id) => {}
            Some("synced") => {
                if included.insert(id) {
                    changes.push(prepare_relocated_operation(
                        &tx,
                        relocation,
                        id,
                        "synced",
                        path.clone(),
                    )?);
                }
            }
            _ => return Err(AccountError::new("directory changed during tree rename")),
        }
    }
    if let Some(previous) = &chain {
        for change in &changes {
            let admitted: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sync_reads WHERE operation_id=?1) OR EXISTS(SELECT 1 FROM mutation_receipts WHERE operation_id=?1) OR EXISTS(SELECT 1 FROM upload_verifications WHERE operation_id=?1) OR EXISTS(SELECT 1 FROM write_dependencies WHERE operation_id=?1 OR predecessor_id=?1)",[change.id],|row|row.get(0))
                .map_err(|_|AccountError::new("cannot inspect tree chain consumers"))?;
            if admitted {
                return Err(AccountError::new("path has unresolved operations"));
            }
            // Closed edges move together; one exact incoming file source can
            // instead remain outside, with its original coordinates/proof.
            let incoming = format!("destination-operation:{}", change.id);
            let prefix = format!("{},", source_key.trim_end_matches(']'));
            let upper = format!("{}-", source_key.trim_end_matches(']'));
            let mut stmt=tx.prepare("SELECT id FROM operation_journal WHERE op_type IN ('move-source','move-dir-source') AND error_msg=?1 AND state IN ('pending','conflict','uncertain') AND (instance<>?2 OR space<>?3 OR state<>'pending' OR op_type<>'move-source' OR NOT(path>=?4 AND path<?5)) LIMIT 2").map_err(|_|AccountError::new("cannot inspect incoming tree consumers"))?;
            let crossing = stmt
                .query_map(params![incoming, instance, space, prefix, upper], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| AccountError::new("cannot inspect incoming tree consumers"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| AccountError::new("invalid incoming tree consumer"))?;
            if !crossing.is_empty() {
                if crossing.len() != 1 {
                    return Err(AccountError::new("path has unresolved operations"));
                }
                validate_chain_incoming_file(
                    &tx,
                    offline.ok_or_else(|| AccountError::new("offline binding unavailable"))?,
                    change,
                    crossing[0],
                )?;
            }
            let kind: String = tx
                .query_row(
                    "SELECT op_type FROM operation_journal WHERE id=?1",
                    [change.id],
                    |row| row.get(0),
                )
                .map_err(|_| AccountError::new("cannot inspect tree consumer kind"))?;
            if kind == "move-source" {
                validate_chain_file_rename(&tx, previous, relocation, change, &included)?;
            }
        }
    }
    // Retain the exact empty target observation before its ordinary snapshot
    // path is reused by the source. This proof is not a destination If-Match.
    let target_proof = if offline.is_some() && target.is_some() {
        Some(tx.query_row("SELECT self_id,self_etag,updated,entries,issuer,subject FROM snapshots WHERE instance=?1 AND space=?2 AND path=?3",params![instance,space,destination_key],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?))).map_err(|_|AccountError::new("offline replacement observation unavailable"))?)
    } else {
        None
    };
    apply_relocated_operations(&tx, instance, space, &changes)?;
    if offline.is_some() && target.is_some() {
        let target = target.ok_or_else(|| AccountError::new("replacement target unavailable"))?;
        relocate_pins_in(
            &tx,
            instance,
            space,
            source,
            destination,
            Some((
                target.id(),
                target
                    .etag()
                    .ok_or_else(|| AccountError::new("replacement target version unavailable"))?,
            )),
            true,
        )?;
    } else {
        relocate_pins(&tx, instance, space, source, destination)?;
    }
    // Source and destination are disjoint. Remove destination snapshots first,
    // then copy only original source rows below a fixed high water. New copies
    // cannot feed this traversal or be deleted by a later destination row.
    // Keep JSON inside SQLite rather than retaining every subtree blob in Rust.
    for copying in [false, true] {
        let through: i64 = tx
            .query_row("SELECT coalesce(max(rowid),0) FROM snapshots", [], |row| {
                row.get(0)
            })
            .map_err(|_| AccountError::new("cannot inspect directory snapshots"))?;
        let mut after: Option<i64> = None;
        loop {
            let mut stmt = tx.prepare("SELECT rowid,path FROM snapshots WHERE instance=?1 AND space=?2 AND (?3 IS NULL OR rowid>?3) AND rowid<=?4 ORDER BY rowid LIMIT 32")
                .map_err(|_| AccountError::new("cannot inspect directory snapshots"))?;
            let rows = stmt
                .query_map(params![instance, space, after, through], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| AccountError::new("cannot inspect directory snapshots"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| AccountError::new("invalid directory snapshot"))?;
            if rows.is_empty() {
                break;
            }
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_FILE_METADATA_TRACE").is_some() {
                eprintln!("cirrus lab tree snapshot path page: rows={}", rows.len());
            }
            drop(stmt);
            for (id, encoded) in rows {
                after = Some(id);
                let path: Vec<String> = serde_json::from_str(&encoded)
                    .map_err(|_| AccountError::new("invalid snapshot path"))?;
                if !copying && path.starts_with(destination) {
                    tx.execute("DELETE FROM snapshots WHERE rowid=?1", [id])
                        .map_err(|error| {
                            sqlite_storage_error(
                                error,
                                "cannot invalidate replaced directory snapshots",
                            )
                        })?;
                } else if copying && path.starts_with(source) {
                    let mut next = destination.to_vec();
                    next.extend_from_slice(&path[source.len()..]);
                    if next.len() > 128 {
                        return Err(AccountError::new("invalid Space path"));
                    }
                    tx.execute("INSERT INTO snapshots SELECT instance,space,?1,entries,updated,self_id,self_etag,local_operation,issuer,subject FROM snapshots WHERE rowid=?2", params![path_key(&next)?,id])
                        .map_err(|error| sqlite_storage_error(error, "cannot relocate directory snapshots"))?;
                }
            }
        }
    }
    let id = if let Some(previous) = &chain {
        // Same IMMEDIATE transaction as all local relocation. Keep the source
        // row, source parent chain, source entry, token and proofs unchanged.
        tx.execute(
            "UPDATE directory_moves SET destination=?1 WHERE operation_id=?2 AND destination=?3",
            params![destination_key, previous.id, source_key],
        )
        .map_err(|error| sqlite_storage_error(error, "cannot collapse directory mapping"))?;
        tx.execute(
            "UPDATE operation_parents SET destination_parents=?1 WHERE operation_id=?2",
            params![destination_chain, previous.id],
        )
        .map_err(|error| sqlite_storage_error(error, "cannot collapse directory parents"))?;
        previous.id
    } else {
        tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES (?1,?2,?3,'move-tree',?4,?5,?6,'pending',NULL,strftime('%s','now'))",params![instance,space,source_key,entry.id(),entry.etag(),token]).map_err(|error| sqlite_storage_error(error, "cannot journal directory rename"))?;
        let id = tx.last_insert_rowid();
        save_operation_parents(
            &tx,
            id,
            source,
            source_parents,
            Some((destination, destination_parents)),
        )?;
        tx.execute(
            "INSERT INTO directory_moves VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                id,
                destination_key,
                source_entry,
                target.map(Entry::id),
                target.and_then(Entry::etag),
                offline.is_some(),
            ],
        )
        .map_err(|error| sqlite_storage_error(error, "cannot journal directory mapping"))?;
        if let Some(binding) = offline {
            walk_tree_proofs(&tx, binding, source, Some(TreeProofUse::Retain(id)))?;
        }
        id
    };
    if let Some((self_id, self_etag, generation, entries, issuer, subject)) = target_proof {
        tx.execute(
            "INSERT INTO tree_targets VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![id, self_id, self_etag, generation, entries, issuer, subject],
        )
        .map_err(|error| sqlite_storage_error(error, "cannot retain replacement target proof"))?;
    }
    #[cfg(feature = "fault-injection")]
    pin_move_stop("before-commit");
    #[cfg(feature = "fault-injection")]
    if std::env::var_os("CIRRUS_TEST_PIN_COPY_COMMIT_ABORT")
        .is_some_and(|path| Path::new(&path).is_file())
    {
        // Exercise SQLite's real COMMIT rejection after private pin-copy,
        // active-pin, journal and snapshot updates, not an early fake refusal.
        tx.commit_hook(Some(|| true));
    }
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit directory rename"))?;
    #[cfg(feature = "fault-injection")]
    pin_move_stop("after-commit");
    Ok(id)
}

pub(crate) fn namespace_token() -> Result<String, AccountError> {
    let mut random = [0u8; 16];
    let mut filled = 0;
    while filled < random.len() {
        let count =
            rustix::rand::getrandom(&mut random[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(|_| AccountError::new("cannot generate operation token"))?;
        if count == 0 {
            return Err(AccountError::new("cannot generate operation token"));
        }
        filled += count;
    }
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn visible_local_descendants(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<bool, AccountError> {
    let mut statement = conn.prepare("SELECT path FROM operation_journal WHERE instance=?1 AND space=?2 AND op_type IN ('write','mkdir') AND state IN ('pending','conflict','uncertain') UNION ALL SELECT m.destination FROM operation_journal j JOIN directory_moves m ON m.operation_id=j.id WHERE j.instance=?1 AND j.space=?2 AND j.op_type='move-tree' AND (j.state IN ('pending','conflict','uncertain') OR (j.state='resolved' AND j.error_msg='acknowledged locally; remote outcome not asserted'))")
        .map_err(|_| AccountError::new("cannot inspect pending descendants"))?;
    let rows = statement
        .query_map(params![instance, space], |row| row.get::<_, String>(0))
        .map_err(|_| AccountError::new("cannot inspect pending descendants"))?;
    for row in rows {
        let encoded = row.map_err(|_| AccountError::new("invalid pending path"))?;
        let candidate: Vec<String> = serde_json::from_str(&encoded)
            .map_err(|_| AccountError::new("invalid pending path"))?;
        if candidate.len() > path.len() && candidate.starts_with(path) {
            return Ok(true);
        }
    }
    Ok(false)
}

// A binding's target path is immutable until authenticated confirmation. Its
// descendant operations may still change locally, but moving/removing the
// binding or an ancestor would retarget its original remote authorization.
fn reject_moving_directory_bindings(
    conn: &Connection,
    instance: &str,
    space: &str,
    paths: &[&[String]],
) -> Result<(), AccountError> {
    let mut stmt=conn.prepare("SELECT path FROM operation_journal WHERE instance=?1 AND space=?2 AND op_type='mkdir' AND state IN ('pending','conflict','uncertain') AND error_msg=?3").map_err(|_|AccountError::new("cannot inspect directory target bindings"))?;
    for row in stmt
        .query_map(params![instance, space, REUSE_DIRECTORY_TARGET], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| AccountError::new("cannot inspect directory target bindings"))?
    {
        let path: Vec<String> = serde_json::from_str(
            &row.map_err(|_| AccountError::new("invalid directory binding path"))?,
        )
        .map_err(|_| AccountError::new("invalid directory binding path"))?;
        if paths.iter().any(|prefix| path.starts_with(prefix)) {
            return Err(AccountError::new("path has unresolved operations"));
        }
    }
    Ok(())
}

pub(crate) fn queue_namespace(
    instance: &str,
    space: &str,
    path: &[String],
    kind: &str,
    base: Option<(&str, &str)>,
    parents: &[DirectoryIdentity],
    offline_binding: Option<&crate::MountBinding>,
) -> Result<i64, AccountError> {
    if !matches!(kind, "mkdir" | "unlink" | "rmdir") {
        return Err(AccountError::new("invalid namespace operation"));
    }
    let token = namespace_token()?;
    let _state_phase = crate::ownership::admit_local_state_turn()?;
    // Lifetime order keeps the paid allowance through rollback/SQLite close.
    let reservation;
    let mut conn = database()?;
    let key = path_key(path)?;
    // Pure byte planning also runs while disabled: enabling policy before
    // lease acquisition must never turn a zero-input plan into admission.
    let planned = {
        let owner: (String, String) = conn
            .query_row(
                "SELECT issuer,subject FROM account_identities WHERE instance=?1",
                [instance],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| AccountError::new("namespace account identity unavailable"))?;
        let parents = encode_parents(path, parents)?;
        // Encode actual row inputs, including duplicated snapshot keys. MAX
        // ids/timestamps conservatively size generated integers; the existing
        // State plan supplies SQLite page/index/journal working allowance.
        let journal = serde_json::to_vec(&(
            i64::MAX,
            instance,
            space,
            &key,
            kind,
            base.map(|value| value.0),
            base.map(|value| value.1),
            &token,
            "pending",
            Option::<&str>::None,
            i64::MAX,
        ))
        .map_err(|_| AccountError::new("cannot size namespace journal row"))?;
        let parent_row = serde_json::to_vec(&(i64::MAX, &parents, Option::<&str>::None))
            .map_err(|_| AccountError::new("cannot size namespace parent row"))?;
        let snapshot = if kind == "mkdir" {
            serde_json::to_vec(&(
                instance,
                space,
                &key,
                "[]",
                i64::MAX,
                Option::<&str>::None,
                Option::<&str>::None,
                i64::MAX,
                owner,
            ))
            .map_err(|_| AccountError::new("cannot size namespace snapshot row"))?
            .len() as u64
        } else {
            0
        };
        (journal.len() as u64)
            .checked_add(parent_row.len() as u64)
            .and_then(|bytes| bytes.checked_add(snapshot))
            .ok_or_else(|| AccountError::new("namespace storage estimate overflow"))?
    };
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_NAMESPACE_JOURNAL_ADMISSION_WINDOW")?;
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_NAMESPACE_JOURNAL_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin namespace operation"))?;
    if let Some(binding) = offline_binding {
        if !matches!(kind, "mkdir" | "rmdir")
            || binding.instance != instance
            || binding.space != space
            || !binding.offline
            || !binding.offline_writable
        {
            return Err(AccountError::new("offline namespace operation unavailable"));
        }
        if kind == "rmdir" {
            reject_moving_directory_bindings(&tx, instance, space, &[path])?;
            let (id, etag) =
                base.ok_or_else(|| AccountError::new("directory version unavailable"))?;
            validate_offline_rmdir(&tx, binding, path, (id, etag), parents)?;
            if let Some(local) = id
                .strip_prefix("cirrus-dir:")
                .and_then(|id| id.parse::<i64>().ok())
            {
                let count = tx.execute("UPDATE operation_journal SET state='resolved',error_msg='removed empty local directory',updated_at=strftime('%s','now') WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='mkdir' AND state='pending' AND base_file_id IS NULL AND base_etag IS NULL",params![local,instance,space,key])
                    .map_err(|error|sqlite_storage_error(error,"cannot resolve local directory"))?;
                if count != 1 {
                    return Err(AccountError::new("local directory changed"));
                }
                reject_fenced_ancestor(&tx, instance, space, path)?;
                if let Some(reservation) = &reservation {
                    reservation.validate(&tx)?;
                } else if crate::storage::limits::view()?.limits.is_some() {
                    return Err(AccountError::new(crate::storage::limits::PRESSURE));
                }
                tx.commit().map_err(|error| {
                    sqlite_storage_error(error, "cannot commit local directory removal")
                })?;
                return Ok(local);
            }
        } else {
            if base.is_some() {
                return Err(AccountError::new("invalid mkdir base"));
            }
            let (name, parent) = path
                .split_last()
                .ok_or_else(|| AccountError::new("invalid offline directory path"))?;
            let entries = offline_directory_in(
                &tx,
                instance,
                space,
                parent,
                Some((&binding.issuer, &binding.subject)),
            )?;
            let occupied: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND state IN ('pending','conflict','uncertain'))", params![instance,space,key], |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect namespace operation"))?;
            if entries.get(name)?.is_some() || occupied {
                return Err(AccountError::new("namespace target already exists"));
            }
            // Absence is local evidence only, from complete identity-bound saved
            // parents or a journaled mkdir. Reconnect must revalidate remotely.
            validate_offline_write(
                &tx,
                (instance, space),
                path,
                (&binding.issuer, &binding.subject),
                None,
                parents,
            )?;
        }
    }
    reject_fenced_ancestor(&tx, instance, space, path)?;
    let pending: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND state IN ('pending','conflict','uncertain')", [instance], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect namespace operations"))?;
    if pending >= MAX_PENDING_NAMESPACE_OPERATIONS {
        return Err(AccountError::new("staging capacity exhausted"));
    }
    let occupied: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND state IN ('pending','conflict','uncertain')", params![instance, space, key], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect namespace operation"))?;
    if occupied != 0 {
        return Err(AccountError::new("path has unresolved operations"));
    }
    if kind == "rmdir" && visible_local_descendants(&tx, instance, space, path)? {
        return Err(AccountError::new(
            "directory contains unresolved local content",
        ));
    }
    let duplicate: i64 = tx
        .query_row(
            "SELECT count(*) FROM operation_journal WHERE staged_file=?1",
            [&token],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect operation token"))?;
    if duplicate != 0 {
        return Err(AccountError::new("operation token collision"));
    }
    tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'pending',NULL,strftime('%s','now'))", params![instance, space, key, kind, base.map(|v| v.0), base.map(|v| v.1), token]).map_err(|error| sqlite_storage_error(error, "cannot journal namespace operation"))?;
    let id = tx.last_insert_rowid();
    save_operation_parents(&tx, id, path, parents, None)?;
    if kind == "mkdir" {
        write_local_snapshot(&tx, instance, space, path, id)?;
    }
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit namespace operation"))?;
    Ok(id)
}

fn validate_offline_rmdir(
    conn: &Connection,
    binding: &crate::MountBinding,
    path: &[String],
    base: (&str, &str),
    parents: &[DirectoryIdentity],
) -> Result<(), AccountError> {
    let (name, parent) = path
        .split_last()
        .ok_or_else(|| AccountError::new("invalid directory path"))?;
    if parents.len() != parent.len() {
        return Err(AccountError::new("directory parents changed"));
    }
    for (index, expected) in parents.iter().enumerate() {
        let entries = offline_directory_in(
            conn,
            &binding.instance,
            &binding.space,
            &parent[..index],
            Some((&binding.issuer, &binding.subject)),
        )?;
        let entry = entries
            .get(&parent[index])?
            .filter(Entry::is_directory)
            .ok_or_else(|| AccountError::new("directory parent unavailable"))?;
        if DirectoryIdentity::from_resource_id(entry.id())? != *expected {
            return Err(AccountError::new("directory parent changed"));
        }
    }
    let entries = offline_directory_in(
        conn,
        &binding.instance,
        &binding.space,
        parent,
        Some((&binding.issuer, &binding.subject)),
    )?;
    let entry = entries
        .get(name)?
        .filter(Entry::is_directory)
        .ok_or_else(|| AccountError::new("offline directory unavailable"))?;
    if entry.id() != base.0 || entry.etag().unwrap_or("") != base.1 {
        return Err(AccountError::new("offline directory version changed"));
    }
    let children = offline_directory_in(
        conn,
        &binding.instance,
        &binding.space,
        path,
        Some((&binding.issuer, &binding.subject)),
    )?;
    if let Some(local) = base
        .0
        .strip_prefix("cirrus-dir:")
        .and_then(|id| id.parse::<i64>().ok())
    {
        let known: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM snapshots s JOIN operation_journal j ON j.id=s.local_operation JOIN account_identities a ON a.instance=s.instance AND a.issuer=s.issuer AND a.subject=s.subject WHERE s.instance=?1 AND s.space=?2 AND s.path=?3 AND s.local_operation=?4 AND s.entries='[]' AND j.instance=s.instance AND j.space=s.space AND j.path=s.path AND j.op_type='mkdir' AND j.state='pending')",params![binding.instance,binding.space,path_key(path)?,local],|row|row.get(0))
            .map_err(|_|AccountError::new("cannot verify local directory observation"))?;
        if !known {
            return Err(AccountError::new("local directory observation unavailable"));
        }
    } else {
        if !crate::dav::valid_remote_id(base.0)
            || !crate::dav::strong_etag(base.1)
            || children.remote_parent()? != (base.0.to_owned(), base.1.to_owned())
        {
            return Err(AccountError::new(
                "offline directory complete version unavailable",
            ));
        }
    }
    if !children.is_empty()?
        || visible_local_descendants(conn, &binding.instance, &binding.space, path)?
    {
        return Err(AccountError::new(
            "directory contains unresolved local content",
        ));
    }
    Ok(())
}

// The destination mkdir must be confirmed before the empty source may be removed.
pub(crate) fn queue_empty_directory_move(
    instance: &str,
    space: &str,
    source: &[String],
    destination: &[String],
    base: (&str, &str),
    source_parents: &[DirectoryIdentity],
    destination_parents: &[DirectoryIdentity],
) -> Result<i64, AccountError> {
    let mkdir_token = namespace_token()?;
    let source_token = namespace_token()?;
    if mkdir_token == source_token {
        return Err(AccountError::new("operation token collision"));
    }
    // Keep the allowance until rollback/connection close, not just commit.
    let reservation;
    let mut conn = database()?;
    let source_key = path_key(source)?;
    let destination_key = path_key(destination)?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect directory rename plan"))?;
    // Size actual row inputs, including the dependency stored in error_msg,
    // both parent rows and the optional destination metadata row. MAX integer
    // widths conservatively cover ids/timestamps not assigned until insertion.
    let planned = {
        let destination_parents = encode_parents(destination, destination_parents)?;
        let source_parents = encode_parents(source, source_parents)?;
        let destination_row = serde_json::to_vec(&(
            i64::MAX,
            instance,
            space,
            &destination_key,
            "mkdir",
            Option::<&str>::None,
            Option::<&str>::None,
            &mkdir_token,
            "pending",
            Option::<&str>::None,
            i64::MAX,
        ))
        .map_err(|_| AccountError::new("cannot size directory destination row"))?;
        let source_row = serde_json::to_vec(&(
            i64::MAX,
            instance,
            space,
            &source_key,
            "move-dir-source",
            base.0,
            base.1,
            &source_token,
            "pending",
            format!("destination-operation:{}", i64::MAX),
            i64::MAX,
        ))
        .map_err(|_| AccountError::new("cannot size directory source row"))?;
        let parents = serde_json::to_vec(&(
            (i64::MAX, destination_parents, Option::<&str>::None),
            (i64::MAX, source_parents, Option::<&str>::None),
        ))
        .map_err(|_| AccountError::new("cannot size directory parent rows"))?;
        let owner: (String, String) = conn
            .query_row(
                "SELECT issuer,subject FROM account_identities WHERE instance=?1",
                [instance],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| AccountError::new("namespace account identity unavailable"))?;
        let snapshot = serde_json::to_vec(&(
            instance,
            space,
            &destination_key,
            "[]",
            i64::MAX,
            Option::<&str>::None,
            Option::<&str>::None,
            i64::MAX,
            owner,
        ))
        .map_err(|_| AccountError::new("cannot size directory snapshot row"))?;
        [
            destination_row.len(),
            source_row.len(),
            parents.len(),
            snapshot.len(),
        ]
        .into_iter()
        .try_fold(0u64, |sum, bytes| sum.checked_add(bytes as u64))
        .ok_or_else(|| AccountError::new("directory storage estimate overflow"))?
    };
    // relocate_pins is part of this transaction too. Conservatively plan all
    // Space pin rows/BLOBs plus a full destination prefix per path occurrence,
    // without collecting another pin tree or assuming an empty remote listing
    // implies empty retained pins. An intervening commit invalidates this plan.
    let (pin_bytes, pin_paths): (u64,u64) = conn.query_row(
        "SELECT coalesce(sum(bytes),0),coalesce(sum(paths),0) FROM (
            SELECT sum(length(CAST(root AS BLOB))+length(CAST(directories AS BLOB))+length(CAST(manifest AS BLOB))) AS bytes,sum(1+json_array_length(directories)+json_array_length(manifest)) AS paths FROM pins WHERE instance=?1 AND space=?2
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(CAST(version AS BLOB))),count(*)*3 FROM files WHERE instance=?1 AND space=?2
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(body)),count(*)*2 FROM chunks WHERE instance=?1 AND space=?2
        )", params![instance,space], |row| Ok((row.get(0)?,row.get(1)?)))
        .map_err(|_| AccountError::new("cannot size directory pin relocation"))?;
    let planned = planned
        .checked_add(pin_bytes)
        .and_then(|bytes| bytes.checked_add(pin_paths.checked_mul(destination_key.len() as u64)?))
        .ok_or_else(|| AccountError::new("directory storage estimate overflow"))?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_EMPTY_MOVE_ADMISSION_WINDOW")?;
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_EMPTY_MOVE_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin directory rename"))?;
    if reservation.is_some() {
        let current: i64 = tx
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect directory rename plan"))?;
        if current != planning_version {
            return Err(AccountError::new(
                "directory metadata changed concurrently; retry",
            ));
        }
    }
    reject_fenced_ancestor(&tx, instance, space, source)?;
    reject_fenced_ancestor(&tx, instance, space, destination)?;
    let count: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND state IN ('pending','conflict','uncertain')", [instance], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect namespace operations"))?;
    if count > MAX_PENDING_NAMESPACE_OPERATIONS - 2 {
        return Err(AccountError::new("staging capacity exhausted"));
    }
    {
        let mut stmt = tx.prepare("SELECT path FROM operation_journal WHERE instance=?1 AND space=?2 AND state IN ('pending','conflict','uncertain')").map_err(|_| AccountError::new("cannot inspect directory operations"))?;
        let rows = stmt
            .query_map(params![instance, space], |row| row.get::<_, String>(0))
            .map_err(|_| AccountError::new("cannot inspect directory operations"))?;
        for row in rows {
            let path: Vec<String> = serde_json::from_str(
                &row.map_err(|_| AccountError::new("invalid namespace path"))?,
            )
            .map_err(|_| AccountError::new("invalid namespace path"))?;
            if path.starts_with(source) || path.starts_with(destination) {
                return Err(AccountError::new("path has unresolved operations"));
            }
        }
    }
    let duplicate: i64 = tx
        .query_row(
            "SELECT count(*) FROM operation_journal WHERE staged_file IN (?1,?2)",
            params![mkdir_token, source_token],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect operation token"))?;
    if duplicate != 0 {
        return Err(AccountError::new("operation token collision"));
    }
    relocate_pins(&tx, instance, space, source, destination)?;
    tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES (?1,?2,?3,'mkdir',NULL,NULL,?4,'pending',NULL,strftime('%s','now'))", params![instance,space,destination_key,mkdir_token]).map_err(|error| sqlite_storage_error(error, "cannot journal directory destination"))?;
    let destination_id = tx.last_insert_rowid();
    save_operation_parents(&tx, destination_id, destination, destination_parents, None)?;
    tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES (?1,?2,?3,'move-dir-source',?4,?5,?6,'pending',?7,strftime('%s','now'))", params![instance,space,source_key,base.0,base.1,source_token,format!("destination-operation:{destination_id}")]).map_err(|error| sqlite_storage_error(error, "cannot journal directory source"))?;
    save_operation_parents(&tx, tx.last_insert_rowid(), source, source_parents, None)?;
    write_local_snapshot(&tx, instance, space, destination, destination_id)?;
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit directory rename"))?;
    Ok(destination_id)
}

pub(crate) fn local_directory(
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<bool, AccountError> {
    let conn = database()?;
    let state: Option<(String,String)> = conn.query_row("SELECT op_type,state FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND op_type IN ('mkdir','rmdir') AND state!='resolved' ORDER BY id DESC LIMIT 1", params![instance, space, path_key(path)?], |row| Ok((row.get(0)?, row.get(1)?))).optional().map_err(|_| AccountError::new("cannot inspect local directory"))?;
    Ok(state.is_some_and(|(kind, state)| {
        kind == "mkdir" && matches!(state.as_str(), "pending" | "conflict" | "uncertain")
    }))
}

// Offline tree admission consumes complete local observations only. A newer
// parent must never supply the version of an older saved child listing.
fn offline_directory_proof(
    conn: &Connection,
    binding: &crate::MountBinding,
    path: &[String],
) -> Result<crate::DirectorySnapshot, AccountError> {
    let owner = Some((binding.issuer.as_str(), binding.subject.as_str()));
    let mut entries = offline_directory_in(conn, &binding.instance, &binding.space, &[], owner)?;
    for depth in 0..path.len() {
        let entry = entries
            .get(&path[depth])?
            .filter(Entry::is_directory)
            .ok_or_else(|| AccountError::new("offline tree parent unavailable"))?;
        entries = offline_directory_in(
            conn,
            &binding.instance,
            &binding.space,
            &path[..=depth],
            owner,
        )?;
        if let Some(id) = entry
            .id()
            .strip_prefix("cirrus-dir:")
            .and_then(|id| id.parse::<i64>().ok())
        {
            let known: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM snapshots s JOIN operation_journal j ON j.id=s.local_operation WHERE s.instance=?1 AND s.space=?2 AND s.path=?3 AND s.issuer=?4 AND s.subject=?5 AND s.local_operation=?6 AND s.entries='[]' AND s.self_id IS NULL AND s.self_etag IS NULL AND j.instance=s.instance AND j.space=s.space AND j.path=s.path AND j.op_type='mkdir' AND j.state='pending')",params![binding.instance,binding.space,path_key(&path[..=depth])?,binding.issuer,binding.subject,id],|row|row.get(0)).map_err(|_|AccountError::new("cannot verify offline tree local observation"))?;
            if !known {
                return Err(AccountError::new("offline tree local observation changed"));
            }
        } else if entries.remote_parent()?
            != (
                entry.id().to_owned(),
                entry
                    .etag()
                    .filter(|etag| crate::dav::strong_etag(etag))
                    .ok_or_else(|| AccountError::new("offline tree parent version unavailable"))?
                    .to_owned(),
            )
        {
            return Err(AccountError::new("offline tree complete version changed"));
        }
    }
    Ok(entries)
}

fn validate_offline_tree(
    conn: &Connection,
    binding: &crate::MountBinding,
    source: (&[String], &str, Option<&str>),
    destination: (&[String], Option<&str>, Option<&str>),
    parents: crate::RenameParents<'_>,
    versions: &[FileVersion],
    chain: Option<&TreeMove>,
) -> Result<(), AccountError> {
    if !binding.offline || !binding.offline_writable {
        return Err(AccountError::new("offline directory rename unavailable"));
    }
    for (path, expected) in [
        (source.0, parents.source),
        (destination.0, parents.destination),
    ] {
        let (name, parent) = path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid tree path"))?;
        let entries = offline_directory_proof(conn, binding, parent)?;
        if expected.len() != parent.len() {
            return Err(AccountError::new("offline tree parents changed"));
        }
        for (index, identity) in expected.iter().enumerate() {
            let ancestors = offline_directory_in(
                conn,
                &binding.instance,
                &binding.space,
                &parent[..index],
                Some((&binding.issuer, &binding.subject)),
            )?;
            let entry = ancestors
                .get(&parent[index])?
                .filter(Entry::is_directory)
                .ok_or_else(|| AccountError::new("offline tree parent unavailable"))?;
            if DirectoryIdentity::from_resource_id(entry.id())? != *identity {
                return Err(AccountError::new("offline tree parent changed"));
            }
        }
        if path == source.0 {
            if !entries.get(name)?.is_some_and(|entry| {
                entry.is_directory() && entry.id() == source.1 && entry.etag() == source.2
            }) {
                return Err(AccountError::new("offline tree source changed"));
            }
            offline_directory_proof(conn, binding, path)?;
        } else {
            match (entries.get(name)?, destination.1) {
                (None, None) => {}
                (Some(entry), Some(id))
                    if entry.is_directory()
                        && entry.id() == id
                        && entry.etag() == destination.2 =>
                {
                    if !offline_directory_proof(conn, binding, path)?.is_empty()?
                        || visible_local_descendants(conn, &binding.instance, &binding.space, path)?
                    {
                        return Err(AccountError::new(
                            "directory contains unresolved local content",
                        ));
                    }
                    if !id.starts_with("cirrus-dir:") {
                        let raw =
                            directory_snapshot_in(conn, &binding.instance, &binding.space, path)?
                                .ok_or_else(|| {
                                AccountError::new("offline replacement observation unavailable")
                            })?;
                        if !raw.is_empty()? {
                            return Err(AccountError::new("directory is not empty"));
                        }
                        let (self_id, self_etag) = raw.remote_parent()?;
                        if self_id != id || Some(self_etag.as_str()) != destination.2 {
                            return Err(AccountError::new("offline replacement version changed"));
                        }
                    }
                }
                _ => return Err(AccountError::new("offline tree destination changed")),
            }
        }
    }
    // Raw remote observations include children hidden by pending removals:
    // those objects still move remotely before the relocated removals drain.
    if crate::dav::valid_remote_id(source.1) {
        if let Some(previous) = chain {
            walk_tree_proofs(
                conn,
                binding,
                &previous.source,
                Some(TreeProofUse::VerifyCopy(previous.id, source.0)),
            )?;
        } else {
            walk_tree_proofs(conn, binding, source.0, None)?;
        }
    } else {
        validate_local_tree_observations(conn, binding, source.0, &mut 0)?;
    }
    // Pending local directories are not in the raw remote proof traversal.
    // Their known-empty bases must still be present and journal-bound before
    // copying/retargeting them; never create an empty proof from the journal.
    let through: i64 = conn
        .query_row(
            "SELECT coalesce(max(id),0) FROM operation_journal",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect pending tree observation high water"))?;
    let mut after = None;
    loop {
        let page = local_directory_page(conn, &binding.instance, &binding.space, after, through)?;
        let Some(last) = page.last() else {
            break;
        };
        after = Some(last.id);
        for row in page {
            if row.kind != "mkdir" || row.state != "pending" {
                continue;
            }
            let path: Vec<String> = serde_json::from_str(&row.path)
                .map_err(|_| AccountError::new("invalid pending tree observation path"))?;
            if path.starts_with(source.0) {
                offline_directory_proof(conn, binding, &path)?;
            }
        }
    }
    for version in versions {
        if version.instance != binding.instance
            || version.space != binding.space
            || !version.path.starts_with(source.0)
        {
            return Err(AccountError::new("open tree file binding changed"));
        }
        let (name, parent) = version
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid open tree file"))?;
        let entries = offline_directory_in(
            conn,
            &binding.instance,
            &binding.space,
            parent,
            Some((&binding.issuer, &binding.subject)),
        )?;
        if !entries.get(name)?.is_some_and(|entry| {
            !entry.is_directory()
                && entry.id() == version.id
                && entry.etag() == Some(version.etag.as_str())
                && entry.size() == Some(version.size)
                && entry.checksums() == version.checksums
        }) {
            return Err(AccountError::new("open tree file changed"));
        }
    }
    Ok(())
}

const MAX_OFFLINE_TREE_DIRECTORIES: usize = 4096;

fn validate_local_tree_observations(
    conn: &Connection,
    binding: &crate::MountBinding,
    path: &[String],
    count: &mut usize,
) -> Result<(), AccountError> {
    *count += 1;
    if *count > MAX_OFFLINE_TREE_DIRECTORIES || path.len() > 128 {
        return Err(AccountError::new("offline tree observation bound exceeded"));
    }
    let entries = offline_directory_proof(conn, binding, path)?;
    let mut after = 0;
    loop {
        let page = entries.page(after)?;
        if page.is_empty() {
            break;
        }
        for (cookie, entry) in page {
            after = cookie;
            if entry.is_directory() {
                let mut child = path.to_vec();
                child.push(entry.name().to_owned());
                validate_local_tree_observations(conn, binding, &child, count)?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TreeProofUse<'a> {
    Retain(i64),
    VerifyCopy(i64, &'a [String]),
}

fn walk_tree_proofs(
    conn: &Connection,
    binding: &crate::MountBinding,
    source: &[String],
    operation: Option<TreeProofUse<'_>>,
) -> Result<(), AccountError> {
    fn walk(
        conn: &Connection,
        binding: &crate::MountBinding,
        root: &[String],
        path: &[String],
        operation: Option<TreeProofUse<'_>>,
        count: &mut usize,
    ) -> Result<(), AccountError> {
        *count += 1;
        if *count > MAX_OFFLINE_TREE_DIRECTORIES || path.len() > 128 {
            return Err(AccountError::new("offline tree observation bound exceeded"));
        }
        let entries = directory_snapshot_in(conn, &binding.instance, &binding.space, path)?
            .ok_or_else(|| AccountError::new("offline tree complete observation unavailable"))?;
        let (id, etag) = entries.remote_parent()?;
        let generation: i64=conn.query_row("SELECT updated FROM snapshots WHERE instance=?1 AND space=?2 AND path=?3 AND issuer=?4 AND subject=?5 AND self_id=?6 AND self_etag=?7 AND local_operation IS NULL",params![binding.instance,binding.space,path_key(path)?,binding.issuer,binding.subject,id,etag],|row|row.get(0)).map_err(|_|AccountError::new("offline tree observation owner changed"))?;
        if let Some(proof_use) = operation {
            let json = entries.json()?;
            let digest = format!("{:x}", Sha256::digest(json.as_bytes()));
            match proof_use {
                TreeProofUse::Retain(operation) => {
                    conn.execute(
                        "INSERT INTO tree_proofs VALUES(?1,?2,?3,?4,?5,?6,?7)",
                        params![
                            operation,
                            path_key(&path[root.len()..])?,
                            id,
                            etag,
                            generation,
                            digest,
                            json
                        ],
                    )
                    .map_err(|error| {
                        sqlite_storage_error(error, "cannot retain offline tree proof")
                    })?;
                }
                TreeProofUse::VerifyCopy(operation, copied_root) => {
                    let relative = &path[root.len()..];
                    let mut copied = copied_root.to_vec();
                    copied.extend_from_slice(relative);
                    // Validate the original remote coordinates, the immutable
                    // proof and its exact copied base. Pending children remain
                    // journal projections, never substitute remote evidence.
                    let exact: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM tree_proofs p JOIN snapshots s ON s.instance=?2 AND s.space=?3 AND s.path=?4 AND s.self_id=p.self_id AND s.self_etag=p.self_etag AND s.updated=p.generation AND s.entries=p.entries AND s.local_operation IS NULL AND s.issuer=?5 AND s.subject=?6 WHERE p.operation_id=?1 AND p.path=?7 AND p.self_id=?8 AND p.self_etag=?9 AND p.generation=?10 AND p.digest=?11 AND p.entries=?12)",params![operation,binding.instance,binding.space,path_key(&copied)?,binding.issuer,binding.subject,path_key(relative)?,id,etag,generation,digest,json],|row|row.get(0))
                        .map_err(|_|AccountError::new("cannot verify chained tree copy"))?;
                    if !exact {
                        return Err(AccountError::new("offline tree copied proof changed"));
                    }
                }
            }
        }
        let mut after = 0;
        loop {
            let page = entries.page(after)?;
            if page.is_empty() {
                break;
            }
            for (cookie, entry) in page {
                after = cookie;
                if !entry.is_directory() {
                    continue;
                }
                let mut child = path.to_vec();
                child.push(entry.name().to_owned());
                let observed =
                    directory_snapshot_in(conn, &binding.instance, &binding.space, &child)?
                        .ok_or_else(|| {
                            AccountError::new("offline tree child observation unavailable")
                        })?;
                if observed.remote_parent()?
                    != (
                        entry.id().to_owned(),
                        entry
                            .etag()
                            .filter(|etag| crate::dav::strong_etag(etag))
                            .ok_or_else(|| {
                                AccountError::new("offline tree child version unavailable")
                            })?
                            .to_owned(),
                    )
                {
                    return Err(AccountError::new("offline tree child observation changed"));
                }
                drop(observed);
                walk(conn, binding, root, &child, operation, count)?;
            }
        }
        Ok(())
    }
    walk(conn, binding, source, source, operation, &mut 0)
}

fn copy_local_tree_snapshots(
    conn: &Connection,
    instance: &str,
    space: &str,
    source: &[String],
    destination: &[String],
) -> Result<(), AccountError> {
    let through: i64 = conn
        .query_row("SELECT coalesce(max(rowid),0) FROM snapshots", [], |row| {
            row.get(0)
        })
        .map_err(|_| AccountError::new("cannot inspect local tree observations"))?;
    for copying in [false, true] {
        let mut after = 0;
        loop {
            let mut stmt=conn.prepare("SELECT rowid,path FROM snapshots WHERE instance=?1 AND space=?2 AND rowid>?3 AND rowid<=?4 ORDER BY rowid LIMIT 32").map_err(|_|AccountError::new("cannot page local tree observations"))?;
            let page = stmt
                .query_map(params![instance, space, after, through], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| AccountError::new("cannot page local tree observations"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| AccountError::new("invalid local tree observation"))?;
            if page.is_empty() {
                break;
            }
            drop(stmt);
            for (id, path) in page {
                after = id;
                let path: Vec<String> = serde_json::from_str(&path)
                    .map_err(|_| AccountError::new("invalid local tree path"))?;
                if !copying && path.starts_with(destination) {
                    conn.execute("DELETE FROM snapshots WHERE rowid=?1", [id])
                        .map_err(|error| {
                            sqlite_storage_error(error, "cannot replace local tree observation")
                        })?;
                } else if copying && path.starts_with(source) {
                    let mut next = destination.to_vec();
                    next.extend_from_slice(&path[source.len()..]);
                    if next.len() > 128 {
                        return Err(AccountError::new("invalid Space path"));
                    }
                    conn.execute("INSERT INTO snapshots SELECT instance,space,?1,entries,updated,self_id,self_etag,local_operation,issuer,subject FROM snapshots WHERE rowid=?2",params![path_key(&next)?,id]).map_err(|error|sqlite_storage_error(error,"cannot copy local tree observation"))?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) struct TreeProof {
    pub path: Vec<String>,
    pub id: String,
    pub etag: String,
    pub digest: String,
}

pub(crate) fn tree_proof_page(
    instance: &str,
    operation: &TreeMove,
    after: Option<&str>,
) -> Result<Vec<(String, TreeProof)>, AccountError> {
    let conn = database()?;
    let root:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM tree_proofs p JOIN operation_journal j ON j.id=p.operation_id JOIN directory_moves m ON m.operation_id=j.id WHERE j.id=?1 AND j.instance=?2 AND j.space=?3 AND j.path=?4 AND j.op_type='move-tree' AND m.offline=1 AND m.destination=?5 AND p.path='[]' AND p.self_id=?6 AND p.self_etag=?7)",params![operation.id,instance,operation.space,path_key(&operation.source)?,path_key(&operation.destination)?,operation.entry.id(),operation.entry.etag()],|row|row.get(0)).map_err(|_|AccountError::new("cannot verify offline tree proof root"))?;
    if !root {
        return Err(AccountError::new("offline tree proof root unavailable"));
    }
    let mut stmt=conn.prepare("SELECT path,self_id,self_etag,digest FROM tree_proofs WHERE operation_id=?1 AND (?2 IS NULL OR path>?2) ORDER BY path LIMIT 32").map_err(|_|AccountError::new("cannot page offline tree proofs"))?;
    stmt.query_map(params![operation.id, after], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })
    .map_err(|_| AccountError::new("cannot page offline tree proofs"))?
    .map(|row| {
        let (key, id, etag, digest) =
            row.map_err(|_| AccountError::new("invalid offline tree proof"))?;
        let path: Vec<String> = serde_json::from_str(&key)
            .map_err(|_| AccountError::new("invalid offline tree proof path"))?;
        if path.len() + operation.source.len() > 128
            || path.iter().any(|part| {
                part.is_empty()
                    || matches!(part.as_str(), "." | "..")
                    || part.contains('/')
                    || part.chars().any(char::is_control)
            })
            || !crate::dav::valid_remote_id(&id)
            || !crate::dav::strong_etag(&etag)
            || digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(AccountError::new("invalid offline tree proof"));
        }
        Ok((
            key,
            TreeProof {
                path,
                id,
                etag,
                digest,
            },
        ))
    })
    .collect()
}

struct LocalDirectoryRow {
    id: i64,
    path: String,
    kind: String,
    state: String,
    bytes: u64,
}

fn local_directory_page(
    conn: &Connection,
    instance: &str,
    space: &str,
    after: Option<i64>,
    through: i64,
) -> Result<Vec<LocalDirectoryRow>, AccountError> {
    let mut stmt = conn.prepare("SELECT j.id,j.path,j.op_type,j.state,length(CAST(j.path AS BLOB))+length(CAST(j.staged_file AS BLOB))+coalesce(length(CAST(j.base_file_id AS BLOB)),0)+coalesce(length(CAST(j.base_etag AS BLOB)),0)+coalesce(length(CAST(j.error_msg AS BLOB)),0)+coalesce(length(CAST(p.parents AS BLOB)),0) FROM operation_journal j LEFT JOIN operation_parents p ON p.operation_id=j.id WHERE j.instance=?1 AND j.space=?2 AND j.state IN ('pending','conflict','uncertain') AND (?3 IS NULL OR j.id>?3) AND j.id<=?4 ORDER BY j.id LIMIT 32")
        .map_err(|_| AccountError::new("cannot inspect local directory operations"))?;
    let rows = stmt
        .query_map(params![instance, space, after, through], |row| {
            Ok(LocalDirectoryRow {
                id: row.get(0)?,
                path: row.get(1)?,
                kind: row.get(2)?,
                state: row.get(3)?,
                bytes: row.get(4)?,
            })
        })
        .map_err(|_| AccountError::new("cannot inspect local directory operations"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AccountError::new("invalid local directory operation"))?;
    #[cfg(feature = "fault-injection")]
    if !rows.is_empty() && std::env::var_os("CIRRUS_TEST_FILE_METADATA_TRACE").is_some() {
        eprintln!("cirrus lab local directory path page: rows={}", rows.len());
    }
    Ok(rows)
}

// Only an entirely local pending tree can be relocated without a remote MOVE.
pub(crate) fn rename_local_directory(
    location: (&str, &str),
    source: &[String],
    destination: &[String],
    resource: &str,
    target: Option<(&str, Option<&str>)>,
    parents: crate::RenameParents<'_>,
    offline: Option<(&crate::MountBinding, &[FileVersion])>,
) -> Result<(), AccountError> {
    let (instance, space) = location;
    let id = resource
        .strip_prefix("cirrus-dir:")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| AccountError::new("directory rename is unsupported"))?;
    if source.is_empty()
        || destination.is_empty()
        || destination.starts_with(source)
        || source.starts_with(destination)
    {
        return Err(AccountError::new("invalid directory rename"));
    }
    let remote_target = target.filter(|(id, _)| !id.starts_with("cirrus-dir:"));
    if remote_target.is_some() && offline.is_none() {
        return Err(AccountError::new("directory rename is unsupported"));
    }
    let target_id = target
        .filter(|(id, _)| id.starts_with("cirrus-dir:"))
        .map(|(resource, _)| {
            resource
                .strip_prefix("cirrus-dir:")
                .and_then(|value| value.parse::<i64>().ok())
                .ok_or_else(|| AccountError::new("directory rename is unsupported"))
        })
        .transpose()?;
    let root = DirectoryIdentity::Pending(id);
    let relocation = RelocationContext {
        instance,
        space,
        source,
        destination,
        parents,
        root: &root,
    };
    // Keep working room through rollback and SQLite connection close.
    let reservation;
    let mut conn = database()?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect local directory plan"))?;
    let through: i64 = conn
        .query_row(
            "SELECT coalesce(max(id),0) FROM operation_journal",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect local directory plan"))?;
    let encoded = serde_json::to_vec(&(
        target_id,
        "resolved",
        "empty local directory replaced",
        i64::MAX,
    ))
    .map_err(|_| AccountError::new("cannot size local directory replacement"))?;
    let mut planned = encoded.len() as u64;
    if remote_target.is_some() {
        let bytes:u64=conn.query_row("SELECT length(CAST(self_id AS BLOB))+length(CAST(self_etag AS BLOB))+length(CAST(issuer AS BLOB))+length(CAST(subject AS BLOB))+512 FROM snapshots WHERE instance=?1 AND space=?2 AND path=?3",params![instance,space,path_key(destination)?],|row|row.get(0)).map_err(|_|AccountError::new("offline replacement observation unavailable"))?;
        planned = planned
            .checked_add(bytes)
            .ok_or_else(|| AccountError::new("local tree storage estimate overflow"))?;
    }
    let mut after = None;
    loop {
        let page = local_directory_page(&conn, instance, space, after, through)?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        for row in page {
            let path: Vec<String> = serde_json::from_str(&row.path)
                .map_err(|_| AccountError::new("invalid namespace path"))?;
            if path.starts_with(source) {
                let change =
                    prepare_relocated_operation(&conn, relocation, row.id, &row.state, path)?;
                let encoded = serde_json::to_vec(&(
                    row.id,
                    path_key(&change.new_path)?,
                    encode_parents(&change.new_path, &change.new_parents)?,
                    i64::MAX,
                ))
                .map_err(|_| AccountError::new("cannot size local directory relocation"))?;
                planned = planned
                    .checked_add(row.bytes)
                    .and_then(|bytes| bytes.checked_add(encoded.len() as u64))
                    .ok_or_else(|| {
                        AccountError::new("local directory storage estimate overflow")
                    })?;
            }
        }
    }
    // Only moving/containing pin roots can be written. Charge their complete
    // retained metadata/BLOB lengths and path expansion conservatively, using
    // indexed canonical ranges/ancestor keys, not another decoded pin tree.
    let source_key = path_key(source)?;
    let destination_key = path_key(destination)?;
    let ancestors = (0..source.len())
        .map(|length| path_key(&source[..length]))
        .collect::<Result<Vec<_>, _>>()?;
    let ancestors = serde_json::to_string(&ancestors)
        .map_err(|_| AccountError::new("cannot size local pin ancestors"))?;
    let prefix = format!("{},", source_key.trim_end_matches(']'));
    let upper = format!("{}-", source_key.trim_end_matches(']'));
    if offline.is_some() {
        let bytes: u64 = conn.query_row("SELECT coalesce(sum(length(CAST(entries AS BLOB))+length(CAST(path AS BLOB))+coalesce(length(CAST(self_id AS BLOB)),0)+coalesce(length(CAST(self_etag AS BLOB)),0)+length(CAST(issuer AS BLOB))+length(CAST(subject AS BLOB))+length(CAST(?5 AS BLOB))+256),0) FROM snapshots WHERE instance=?1 AND space=?2 AND (path=?3 OR substr(path,1,length(?4))=?4)",params![instance,space,source_key,prefix,destination_key],|row|row.get(0)).map_err(|_|AccountError::new("cannot size local tree observations"))?;
        planned = planned
            .checked_add(bytes)
            .ok_or_else(|| AccountError::new("local tree observation estimate overflow"))?;
    }
    let (pin_bytes, pin_paths): (u64,u64) = conn.query_row(
        "WITH roots AS (SELECT root FROM pins WHERE instance=?1 AND space=?2 AND (root=?3 OR (root>=?4 AND root<?5) OR root IN (SELECT value FROM json_each(?6))))
        SELECT coalesce(sum(bytes),0),coalesce(sum(paths),0) FROM (
            SELECT sum(length(CAST(root AS BLOB))+length(CAST(directories AS BLOB))+length(CAST(manifest AS BLOB))) AS bytes,sum(1+json_array_length(directories)+json_array_length(manifest)) AS paths FROM pins WHERE instance=?1 AND space=?2 AND root IN roots
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(CAST(version AS BLOB))),count(*)*3 FROM files WHERE instance=?1 AND space=?2 AND root IN roots
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(body)),count(*)*2 FROM chunks WHERE instance=?1 AND space=?2 AND root IN roots
        )", params![instance,space,source_key,prefix,upper,ancestors], |row| Ok((row.get(0)?,row.get(1)?)))
        .map_err(|_| AccountError::new("cannot size local pin relocation"))?;
    planned = planned
        .checked_add(pin_bytes)
        .and_then(|bytes| bytes.checked_add(pin_paths.checked_mul(destination_key.len() as u64)?))
        .ok_or_else(|| AccountError::new("local directory storage estimate overflow"))?;
    if remote_target.is_some() {
        planned = planned
            .checked_add(pin_copy_allowance(&conn, instance, space)?)
            .ok_or_else(|| AccountError::new("retained pin storage estimate overflow"))?;
    }
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_LOCAL_DIRECTORY_ADMISSION_WINDOW")?;
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_LOCAL_DIRECTORY_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin directory rename"))?;
    if reservation.is_some() {
        let current: i64 = tx
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect local directory plan"))?;
        if current != planning_version {
            return Err(AccountError::new(
                "directory metadata changed concurrently; retry",
            ));
        }
    }
    reject_fenced_ancestor(&tx, instance, space, source)?;
    reject_fenced_ancestor(&tx, instance, space, destination)?;
    reject_moving_directory_bindings(&tx, instance, space, &[source, destination])?;
    if let Some((binding, versions)) = offline {
        validate_offline_tree(
            &tx,
            binding,
            (source, resource, None),
            (
                destination,
                target.map(|value| value.0),
                target.and_then(|value| value.1),
            ),
            parents,
            versions,
            None,
        )?;
    }
    let root: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='mkdir' AND state='pending'", params![id,instance,space,path_key(source)?], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect directory rename"))?;
    if root != 1 {
        return Err(AccountError::new("directory rename is unsupported"));
    }
    if let Some(target_id) = target_id {
        let count: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='mkdir' AND state='pending'", params![target_id,instance,space,path_key(destination)?], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect directory replacement"))?;
        if count != 1 {
            return Err(AccountError::new("path has unresolved operations"));
        }
    }
    let through: i64 = tx
        .query_row(
            "SELECT coalesce(max(id),0) FROM operation_journal",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect local directory operations"))?;
    let mut after = None;
    loop {
        let page = local_directory_page(&tx, instance, space, after, through)?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        for row in page {
            let path: Vec<String> = serde_json::from_str(&row.path)
                .map_err(|_| AccountError::new("invalid namespace path"))?;
            if path.starts_with(destination) && Some(row.id) != target_id {
                return Err(AccountError::new(
                    if remote_target.is_some() && path.len() > destination.len() {
                        "directory is not empty"
                    } else {
                        "path has unresolved operations"
                    },
                ));
            }
            if path.starts_with(source) {
                if row.state != "pending" || !matches!(row.kind.as_str(), "mkdir" | "write") {
                    return Err(AccountError::new("path has unresolved operations"));
                }
                prepare_relocated_operation(&tx, relocation, row.id, "pending", path)?;
            }
        }
    }
    if let Some(target_id) = target_id {
        tx.execute("UPDATE operation_journal SET state='resolved',error_msg='empty local directory replaced',updated_at=strftime('%s','now') WHERE id=?1 AND state='pending'", [target_id]).map_err(|error| sqlite_storage_error(error, "cannot resolve replaced directory"))?;
    }
    // Keep the original all-paths-before-parent-validation ordering without
    // retaining every descendant path/parent chain in memory. The second pass
    // reconstructs old paths from disjoint destination paths; old parent rows
    // still exist until their exact CAS below. No rows are inserted here.
    for paths in [true, false] {
        let mut after = None;
        loop {
            let page = local_directory_page(&tx, instance, space, after, through)?;
            let Some(last) = page.last() else { break };
            after = Some(last.id);
            for row in page {
                let path: Vec<String> = serde_json::from_str(&row.path)
                    .map_err(|_| AccountError::new("invalid namespace path"))?;
                if !path.starts_with(if paths { source } else { destination }) {
                    continue;
                }
                let old_path = if paths {
                    path
                } else {
                    let mut old = source.to_vec();
                    old.extend_from_slice(&path[destination.len()..]);
                    old
                };
                let change =
                    prepare_relocated_operation(&tx, relocation, row.id, "pending", old_path)?;
                let count = if paths {
                    tx.execute("UPDATE operation_journal SET path=?1,updated_at=strftime('%s','now') WHERE id=?2 AND instance=?3 AND space=?4 AND path=?5 AND state=?6", params![path_key(&change.new_path)?,change.id,instance,space,path_key(&change.old_path)?,change.state])
                        .map_err(|error| sqlite_storage_error(error,"cannot relocate directory operation"))?
                } else {
                    validate_parent_dependencies(
                        &tx,
                        instance,
                        space,
                        &change.new_path,
                        &change.new_parents,
                    )?;
                    tx.execute("UPDATE operation_parents SET parents=?1 WHERE operation_id=?2 AND parents=?3 AND destination_parents IS NULL", params![encode_parents(&change.new_path,&change.new_parents)?,change.id,encode_parents(&change.old_path,&change.old_parents)?])
                        .map_err(|error| sqlite_storage_error(error,"cannot relocate parent identities"))?
                };
                if count != 1 {
                    return Err(AccountError::new(if paths {
                        "directory operation changed"
                    } else {
                        "directory parent identity changed"
                    }));
                }
            }
        }
    }
    if let Some((target, etag)) = remote_target {
        let etag = etag
            .filter(|etag| crate::dav::strong_etag(etag))
            .ok_or_else(|| AccountError::new("offline replacement version unavailable"))?;
        let count=tx.execute("INSERT INTO tree_targets SELECT ?1,self_id,self_etag,updated,entries,issuer,subject FROM snapshots WHERE instance=?2 AND space=?3 AND path=?4 AND self_id=?5 AND self_etag=?6 AND entries='[]' AND local_operation IS NULL",params![id,instance,space,destination_key,target,etag]).map_err(|error|sqlite_storage_error(error,"cannot retain local replacement target proof"))?;
        if count != 1 {
            return Err(AccountError::new("offline replacement proof unavailable"));
        }
        let count=tx.execute("UPDATE operation_journal SET error_msg=?1 WHERE id=?2 AND instance=?3 AND space=?4 AND path=?5 AND op_type='mkdir' AND state='pending' AND base_file_id IS NULL AND base_etag IS NULL AND error_msg IS NULL",params![REUSE_DIRECTORY_TARGET,id,instance,space,destination_key]).map_err(|error|sqlite_storage_error(error,"cannot retain local replacement binding"))?;
        if count != 1 {
            return Err(AccountError::new("local directory binding changed"));
        }
    }
    if let Some((target, etag)) = remote_target {
        relocate_pins_in(
            &tx,
            instance,
            space,
            source,
            destination,
            Some((
                target,
                etag.ok_or_else(|| AccountError::new("replacement target version unavailable"))?,
            )),
            false,
        )?;
    } else {
        relocate_pins(&tx, instance, space, source, destination)?;
    }
    if offline.is_some() {
        copy_local_tree_snapshots(&tx, instance, space, source, destination)?;
    }
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit directory rename"))
}

pub(crate) fn remove_staged(
    location: (&str, &str),
    path: &[String],
    resource: &str,
    detached: bool,
    parents: &[DirectoryIdentity],
    offline: Option<(&crate::MountBinding, &FileVersion)>,
) -> Result<(), AccountError> {
    let (instance, space) = location;
    let (kind, value) = if let Some(value) = resource.strip_prefix("cirrus-staged:") {
        ("write", value)
    } else if let Some(value) = resource.strip_prefix("cirrus-dir:") {
        ("mkdir", value)
    } else {
        return Err(AccountError::new("invalid staged resource"));
    };
    if detached && kind != "write" {
        return Err(AccountError::new("invalid detached resource"));
    }
    let id: i64 = value
        .parse()
        .map_err(|_| AccountError::new("invalid staged resource"))?;
    let token = namespace_token()?;
    let key = path_key(path)?;
    let _state_phase = ownership::admit_local_state_turn()?;
    // Even a local-only resolution can enlarge the row's retained-copy message
    // and journal pages. Keep State room through rollback/connection close.
    let reservation;
    let mut conn = database()?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect staged removal plan"))?;
    let planned_row: Option<(Option<String>,Option<String>,String)> = conn.query_row("SELECT base_file_id,base_etag,staged_file FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type=?5 AND state='pending' AND id=(SELECT max(id) FROM operation_journal WHERE instance=?2 AND space=?3 AND path=?4 AND state!='resolved')", params![id,instance,space,key,kind], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().map_err(|_| AccountError::new("cannot inspect staged removal"))?;
    let (planned_base_id, planned_base_etag, planned_file) =
        planned_row.ok_or_else(|| AccountError::new("path has unresolved operations"))?;
    let source_chain = encode_parents(path, &load_operation_parents(&conn, id, path)?)?;
    let message = if detached {
        DETACHED_MESSAGE
    } else {
        "removed locally; staged copies retained"
    };
    let resolved = serde_json::to_vec(&(
        id,
        instance,
        space,
        &key,
        kind,
        &planned_base_id,
        &planned_base_etag,
        &planned_file,
        "resolved",
        message,
        i64::MAX,
    ))
    .map_err(|_| AccountError::new("cannot size staged removal resolution"))?;
    // Delete the journal's currently observed remote target, not the immutable
    // overlay's original content base (which a prior rename need not share).
    let removal = if let (Some(base_id), Some(base_etag)) = (&planned_base_id, &planned_base_etag) {
        serde_json::to_vec(&(
            (
                i64::MAX,
                instance,
                space,
                &key,
                "unlink",
                base_id,
                base_etag,
                &token,
                "pending",
                Option::<&str>::None,
                i64::MAX,
            ),
            (i64::MAX, &source_chain, Option::<&str>::None),
        ))
        .map_err(|_| AccountError::new("cannot size staged removal journal"))?
    } else {
        Vec::new()
    };
    let planned = (resolved.len() as u64)
        .checked_add(removal.len() as u64)
        .ok_or_else(|| AccountError::new("staged removal storage estimate overflow"))?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_REMOVE_STAGED_ADMISSION_WINDOW")?;
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_REMOVE_STAGED_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin removal"))?;
    if let Some((binding, version)) = offline {
        if kind != "write"
            || version.id != resource
            || version.path != path
            || version.instance != instance
            || version.space != space
            || !binding.offline
            || !binding.offline_writable
            || binding.instance != instance
            || binding.space != space
        {
            return Err(AccountError::new("offline unlink binding changed"));
        }
        validate_offline_write(
            &tx,
            (instance, space),
            path,
            (&binding.issuer, &binding.subject),
            Some(version),
            parents,
        )?;
    }
    if reservation.is_some() {
        let current: i64 = tx
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect staged removal plan"))?;
        if current != planning_version {
            return Err(AccountError::new(
                "directory metadata changed concurrently; retry",
            ));
        }
    }
    reject_fenced_ancestor(&tx, instance, space, path)?;
    if kind == "mkdir" {
        reject_moving_directory_bindings(&tx, instance, space, &[path])?;
    }
    let row: Option<(Option<String>, Option<String>)> = tx.query_row("SELECT base_file_id,base_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type=?5 AND state='pending' AND id=(SELECT max(id) FROM operation_journal WHERE instance=?2 AND space=?3 AND path=?4 AND state!='resolved')", params![id,instance,space,key,kind], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|_| AccountError::new("cannot inspect staged removal"))?;
    let (base_id, base_etag) =
        row.ok_or_else(|| AccountError::new("path has unresolved operations"))?;
    let recorded_parents = load_operation_parents(&tx, id, path)?;
    if !equivalent_parents(&tx, instance, space, path, &recorded_parents, parents)? {
        return Err(AccountError::new(
            "parent identity changed; staged copy retained",
        ));
    }
    validate_parent_dependencies(&tx, instance, space, path, &recorded_parents)?;
    let others: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND id!=?4 AND state IN ('pending','conflict','uncertain')", params![instance,space,key,id], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect staged removal"))?;
    if others != 0 {
        return Err(AccountError::new("path has unresolved operations"));
    }
    if base_id.is_some() != base_etag.is_some() || (kind == "mkdir" && base_id.is_some()) {
        return Err(AccountError::new("invalid staged removal base"));
    }
    if kind == "mkdir" {
        let mut stmt = tx.prepare("SELECT path FROM operation_journal WHERE instance=?1 AND space=?2 AND state IN ('pending','conflict','uncertain') AND id!=?3").map_err(|_| AccountError::new("cannot inspect pending descendants"))?;
        let rows = stmt
            .query_map(params![instance, space, id], |row| row.get::<_, String>(0))
            .map_err(|_| AccountError::new("cannot inspect pending descendants"))?;
        for row in rows {
            let encoded = row.map_err(|_| AccountError::new("invalid pending path"))?;
            let candidate: Vec<String> = serde_json::from_str(&encoded)
                .map_err(|_| AccountError::new("invalid pending path"))?;
            if candidate.starts_with(path) {
                return Err(AccountError::new("path has unresolved operations"));
            }
        }
    }
    tx.execute("UPDATE operation_journal SET state='resolved',error_msg=?1,updated_at=strftime('%s','now') WHERE id=?2 AND state='pending'", params![message,id]).map_err(|error| sqlite_storage_error(error, "cannot resolve staged removal"))?;
    if let (Some(base_id), Some(base_etag)) = (base_id, base_etag) {
        let pending: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND state IN ('pending','conflict','uncertain')", [instance], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect namespace operations"))?;
        if pending >= MAX_PENDING_NAMESPACE_OPERATIONS {
            return Err(AccountError::new("staging capacity exhausted"));
        }
        let duplicate: i64 = tx
            .query_row(
                "SELECT count(*) FROM operation_journal WHERE staged_file=?1",
                [&token],
                |row| row.get(0),
            )
            .map_err(|_| AccountError::new("cannot inspect operation token"))?;
        if duplicate != 0 {
            return Err(AccountError::new("operation token collision"));
        }
        tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES (?1,?2,?3,'unlink',?4,?5,?6,'pending',NULL,strftime('%s','now'))", params![instance,space,key,base_id,base_etag,token]).map_err(|error| sqlite_storage_error(error, "cannot journal staged removal"))?;
        save_operation_parents(&tx, tx.last_insert_rowid(), path, &recorded_parents, None)?;
    }
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit staged removal"))
}

// Mkdirs must remain ordered by path depth and then journal ID across pages;
// removals use journal order. Each caller supplies a fixed ID high-water mark.
pub(crate) fn pending_namespace(
    instance: &str,
    space: Option<&str>,
    mkdir: bool,
    after: (usize, i64),
    through: i64,
) -> Result<Vec<NamespaceOperation>, AccountError> {
    let conn = database()?;
    let mut statement = conn.prepare("SELECT id,space,path,op_type,base_file_id,base_etag,error_msg,staged_file FROM operation_journal WHERE instance=?1 AND (?6 IS NULL OR space=?6) AND state='pending' AND ((?2=1 AND op_type='mkdir') OR (?2=0 AND op_type IN ('unlink','rmdir','move-source','move-dir-source'))) AND id<=?5 AND ((CASE WHEN ?2=1 THEN json_array_length(path) ELSE 0 END)>?3 OR ((CASE WHEN ?2=1 THEN json_array_length(path) ELSE 0 END)=?3 AND id>?4)) ORDER BY CASE WHEN ?2=1 THEN json_array_length(path) ELSE 0 END,id LIMIT 32").map_err(|_| AccountError::new("cannot load namespace operations"))?;
    let rows = statement
        .query_map(
            params![instance, mkdir, after.0 as i64, after.1, through, space],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .map_err(|_| AccountError::new("cannot load namespace operations"))?;
    rows.map(|row| {
        let (id, space, path, kind, base_id, base_etag, message, token) =
            row.map_err(|_| AccountError::new("invalid namespace operation"))?;
        let dependency = if matches!(kind.as_str(), "move-source" | "move-dir-source") {
            Some(
                message
                    .as_deref()
                    .and_then(|value| value.strip_prefix("destination-operation:"))
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| AccountError::new("invalid rename dependency"))?,
            )
        } else {
            None
        };
        let path: Vec<String> =
            serde_json::from_str(&path).map_err(|_| AccountError::new("invalid namespace path"))?;
        let parents = load_operation_parents(&conn, id, &path)?;
        Ok(NamespaceOperation {
            id,
            space,
            path,
            kind,
            base_id,
            base_etag,
            dependency,
            parents,
            token,
            pending_message: message,
        })
    })
    .collect::<Result<_, AccountError>>()
}

pub(crate) struct ConfirmedDirectory {
    pub space: String,
    pub path: Vec<String>,
    pub id: String,
    pub parents: Vec<DirectoryIdentity>,
}

pub(crate) fn confirmed_directory(
    instance: &str,
    id: i64,
) -> Result<Option<ConfirmedDirectory>, AccountError> {
    let conn = database()?;
    let row: Option<(String,String,Option<String>)> = conn.query_row("SELECT space,path,error_msg FROM operation_journal WHERE id=?1 AND instance=?2 AND op_type='mkdir' AND state='synced'", params![id,instance], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().map_err(|_| AccountError::new("cannot inspect directory destination"))?;
    row.map(|(space, path, message)| {
        let remote_id = message
            .and_then(|value| {
                value
                    .strip_prefix("confirmed-directory:")
                    .map(str::to_owned)
            })
            .ok_or_else(|| AccountError::new("directory destination identity is unavailable"))?;
        let path: Vec<String> =
            serde_json::from_str(&path).map_err(|_| AccountError::new("invalid namespace path"))?;
        let parents = load_operation_parents(&conn, id, &path)?;
        Ok(ConfirmedDirectory {
            space,
            path,
            id: remote_id,
            parents,
        })
    })
    .transpose()
}

#[derive(PartialEq, Eq)]
pub(crate) struct LocalDirectoryTarget {
    pub id: String,
    pub etag: String,
    generation: i64,
    issuer: String,
    subject: String,
}

fn local_directory_target_in(
    conn: &Connection,
    instance: &str,
    operation: &NamespaceOperation,
) -> Result<LocalDirectoryTarget, AccountError> {
    if !operation.reuses_directory()
        || operation.dependency.is_some()
        || operation.base_id.is_some()
        || operation.base_etag.is_some()
    {
        return Err(AccountError::new("invalid directory target binding"));
    }
    let target=conn.query_row("SELECT t.self_id,t.self_etag,t.generation,t.issuer,t.subject FROM tree_targets t JOIN operation_journal j ON j.id=t.operation_id JOIN account_identities a ON a.instance=j.instance AND a.issuer=t.issuer AND a.subject=t.subject WHERE j.id=?1 AND j.instance=?2 AND j.space=?3 AND j.path=?4 AND j.op_type='mkdir' AND j.state='pending' AND j.base_file_id IS NULL AND j.base_etag IS NULL AND j.staged_file=?5 AND j.error_msg=?6 AND t.entries='[]'",params![operation.id,instance,operation.space,path_key(&operation.path)?,operation.token,REUSE_DIRECTORY_TARGET],|row|Ok(LocalDirectoryTarget{id:row.get(0)?,etag:row.get(1)?,generation:row.get(2)?,issuer:row.get(3)?,subject:row.get(4)?})).map_err(|_|AccountError::new("directory target binding proof unavailable"))?;
    if !crate::dav::valid_remote_id(&target.id) || !crate::dav::strong_etag(&target.etag) {
        return Err(AccountError::new("invalid directory target binding proof"));
    }
    Ok(target)
}

pub(crate) fn local_directory_target(
    instance: &str,
    operation: &NamespaceOperation,
) -> Result<LocalDirectoryTarget, AccountError> {
    local_directory_target_in(&database()?, instance, operation)
}

// This is a GET-only authorization checkpoint, not a successful mutation
// receipt. Pending parent IDs resolve to this confirmed identity atomically;
// no descendant may upload while the root is still pending/conflicted.
pub(crate) fn confirm_local_directory_target(
    instance: &str,
    operation: &NamespaceOperation,
    target: &LocalDirectoryTarget,
) -> Result<(), AccountError> {
    let reservation;
    let mut conn = database()?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect directory binding plan"))?;
    let message = format!("confirmed-directory:{}", target.id);
    let encoded = serde_json::to_vec(&(
        operation,
        &target.id,
        &target.etag,
        &target.issuer,
        &target.subject,
        &message,
    ))
    .map_err(|_| AccountError::new("cannot size directory target confirmation"))?;
    reservation = crate::storage::sql_reservation::SqlReservation::begin(
        crate::storage::sql_reservation::Store::State,
        Some(&conn),
        encoded.len() as u64 + 256,
        0,
        false,
    )?;
    if let Some(reservation) = &reservation {
        reservation.bound_pages(&conn)?;
    }
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| {
            sqlite_storage_error(error, "cannot begin directory target confirmation")
        })?;
    if reservation.is_some()
        && tx
            .pragma_query_value::<i64, _>(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect directory binding plan"))?
            != planning_version
    {
        return Err(AccountError::retryable_read(
            "directory binding plan changed; retry",
        ));
    }
    if local_directory_target_in(&tx, instance, operation)? != *target {
        return Err(AccountError::new("directory target binding changed"));
    }
    // Publish the actual observed empty remote base without revoking local
    // pending-mkdir descendants. They remain bound to their own journal IDs,
    // not to invented remote directory versions.
    let count=tx.execute("UPDATE snapshots SET entries='[]',updated=max(updated+1,strftime('%s','now')),self_id=?1,self_etag=?2,local_operation=NULL WHERE instance=?3 AND space=?4 AND path=?5 AND entries='[]' AND self_id IS NULL AND self_etag IS NULL AND local_operation=?6 AND issuer=?7 AND subject=?8 AND updated<9223372036854775807",params![target.id,target.etag,instance,operation.space,path_key(&operation.path)?,operation.id,target.issuer,target.subject]).map_err(|error|sqlite_storage_error(error,"cannot publish directory target observation"))?;
    if count != 1 {
        return Err(AccountError::new(
            "local directory binding observation changed",
        ));
    }
    set_namespace_state_in(
        &tx,
        instance,
        operation,
        "pending",
        "synced",
        Some(&message),
    )?;
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit directory target binding"))?;
    drop(conn);
    drop(reservation);
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_LOCAL_TARGET_BOUND_WINDOW")?;
    Ok(())
}

pub(crate) fn pending_rmdir_base(
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<Option<NamespaceOperation>, AccountError> {
    let conn = database()?;
    type RemovalRow = (i64, Option<String>, Option<String>, String, Option<String>);
    let row: Option<RemovalRow> = conn.query_row("SELECT id,base_file_id,base_etag,staged_file,error_msg FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND op_type='rmdir' AND state='pending' AND base_file_id IS NOT NULL AND base_etag IS NOT NULL ORDER BY id DESC LIMIT 1", params![instance,space,path_key(path)?], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).optional().map_err(|_| AccountError::new("cannot inspect pending parent removal"))?;
    row.map(|(id, base_id, base_etag, token, pending_message)| {
        Ok(NamespaceOperation {
            id,
            space: space.to_owned(),
            path: path.to_vec(),
            kind: "rmdir".to_owned(),
            base_id,
            base_etag,
            token,
            pending_message,
            dependency: None,
            parents: load_operation_parents(&conn, id, path)?,
        })
    })
    .transpose()
}

fn update_rmdir_base_in(
    conn: &Connection,
    instance: &str,
    operation: &NamespaceOperation,
    new: &str,
) -> Result<(), AccountError> {
    if !crate::dav::strong_etag(new) {
        return Err(AccountError::new("invalid rebased directory version"));
    }
    let count = conn.execute("UPDATE operation_journal SET base_etag=?1,updated_at=strftime('%s','now') WHERE id=?2 AND instance=?3 AND space=?4 AND path=?5 AND op_type='rmdir' AND state='pending' AND base_file_id IS ?6 AND base_etag IS ?7 AND staged_file=?8 AND error_msg IS ?9 AND EXISTS(SELECT 1 FROM operation_parents WHERE operation_id=?2 AND parents=?10 AND destination_parents IS NULL)", params![new,operation.id,instance,operation.space,path_key(&operation.path)?,operation.base_id,operation.base_etag,operation.token,operation.pending_message,encode_parents(&operation.path,&operation.parents)?]).map_err(|_| AccountError::new("cannot update parent removal version"))?;
    if count != 1 {
        return Err(AccountError::new("parent removal changed concurrently"));
    }
    for etag in operation
        .base_etag
        .as_deref()
        .into_iter()
        .chain(std::iter::once(new))
    {
        tx_removal_version(conn, operation.id, etag)?;
    }
    Ok(())
}

fn tx_removal_version(conn: &Connection, operation: i64, etag: &str) -> Result<(), AccountError> {
    if !crate::dav::strong_etag(etag) {
        return Err(AccountError::new("invalid removal version"));
    }
    conn.execute(
        "INSERT OR IGNORE INTO removal_versions VALUES(?1,?2)",
        params![operation, etag],
    )
    .map_err(|error| sqlite_storage_error(error, "cannot retain rebased directory version"))?;
    Ok(())
}

pub(crate) struct ConfirmedDestination {
    pub space: String,
    pub path: Vec<String>,
    pub staged: String,
    pub file_id: String,
    pub etag: String,
    pub parents: Vec<DirectoryIdentity>,
}

pub(crate) fn confirmed_destination(
    instance: &str,
    id: i64,
) -> Result<Option<ConfirmedDestination>, AccountError> {
    let conn = database()?;
    let row: Option<(String,String,String,String,String)> = conn.query_row("SELECT space,path,staged_file,confirmed_file_id,confirmed_etag FROM operation_journal AS original WHERE instance=?1 AND id=?2 AND op_type='write' AND state='synced' AND confirmed_file_id IS NOT NULL AND confirmed_etag IS NOT NULL AND NOT EXISTS (SELECT 1 FROM operation_journal AS newer WHERE newer.instance=original.instance AND newer.space=original.space AND newer.path=original.path AND newer.id>original.id AND newer.state IN ('pending','conflict','uncertain'))", params![instance,id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).optional().map_err(|_| AccountError::new("cannot inspect rename destination"))?;
    row.map(|(space, path, staged, file_id, etag)| {
        let path: Vec<String> = serde_json::from_str(&path)
            .map_err(|_| AccountError::new("invalid rename destination"))?;
        let parents = load_operation_parents(&conn, id, &path)?;
        Ok(ConfirmedDestination {
            space,
            path,
            staged,
            file_id,
            etag,
            parents,
        })
    })
    .transpose()
}

pub(crate) fn unsettled_mkdir_spaces(
    instance: &str,
    requested_space: Option<&str>,
) -> Result<std::collections::HashSet<String>, AccountError> {
    let conn = database()?;
    let mut stmt = conn.prepare("SELECT space,path,state FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2) AND op_type='mkdir' AND (state IN ('conflict','uncertain') OR (state='resolved' AND error_msg='acknowledged locally; remote outcome not asserted'))").map_err(|_| AccountError::new("cannot inspect directory operations"))?;
    let rows = stmt
        .query_map(params![instance, requested_space], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| AccountError::new("cannot inspect directory operations"))?;
    let mut spaces = std::collections::HashSet::new();
    for row in rows {
        let (space, path, state) =
            row.map_err(|_| AccountError::new("invalid directory operation"))?;
        if spaces.contains(&space) {
            continue;
        }
        let path: Vec<String> =
            serde_json::from_str(&path).map_err(|_| AccountError::new("invalid directory path"))?;
        if state != "resolved" || unresolved_beneath(instance, &space, &path)? {
            spaces.insert(space);
        }
    }
    Ok(spaces)
}

pub(crate) fn parent_conflict_spaces(
    instance: &str,
    space: Option<&str>,
) -> Result<std::collections::HashSet<String>, AccountError> {
    let conn = database()?;
    let mut stmt = conn
        .prepare("SELECT DISTINCT space FROM operation_journal WHERE instance=?1 AND op_type='write' AND state='conflict' AND error_msg=?2 AND (?3 IS NULL OR space=?3)")
        .map_err(|_| AccountError::new("cannot inspect parent identity conflicts"))?;
    let rows = stmt
        .query_map(params![instance, PARENT_WRITE_CONFLICT, space], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| AccountError::new("cannot inspect parent identity conflicts"))?;
    rows.collect::<Result<_, _>>()
        .map_err(|_| AccountError::new("invalid parent identity conflict"))
}

pub(crate) fn unresolved_beneath(
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<bool, AccountError> {
    let conn = database()?;
    let mut stmt = conn.prepare("SELECT path,op_type FROM operation_journal WHERE instance=?1 AND space=?2 AND state IN ('pending','conflict','uncertain')").map_err(|_| AccountError::new("cannot inspect pending descendants"))?;
    let rows = stmt
        .query_map(params![instance, space], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| AccountError::new("cannot inspect pending descendants"))?;
    for row in rows {
        let (encoded, kind) = row.map_err(|_| AccountError::new("invalid pending path"))?;
        let candidate: Vec<String> = serde_json::from_str(&encoded)
            .map_err(|_| AccountError::new("invalid pending path"))?;
        if candidate.starts_with(path)
            && (candidate.len() > path.len() || matches!(kind.as_str(), "write" | "mkdir"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn any_unresolved_beneath(
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<bool, AccountError> {
    let conn = database()?;
    let mut stmt=conn.prepare("SELECT path FROM operation_journal WHERE instance=?1 AND space=?2 AND state IN ('pending','conflict','uncertain')").map_err(|_| AccountError::new("cannot inspect pending descendants"))?;
    let rows = stmt
        .query_map(params![instance, space], |row| row.get::<_, String>(0))
        .map_err(|_| AccountError::new("cannot inspect pending descendants"))?;
    for row in rows {
        let candidate: Vec<String> =
            serde_json::from_str(&row.map_err(|_| AccountError::new("invalid pending path"))?)
                .map_err(|_| AccountError::new("invalid pending path"))?;
        if candidate.starts_with(path) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn staged_source_base(
    version: &FileVersion,
) -> Result<Option<(String, String)>, AccountError> {
    let id = version
        .id
        .strip_prefix("cirrus-staged:")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| AccountError::new("rename requires a staged file"))?;
    let staged = version
        .etag
        .strip_prefix("\"cirrus-staged-")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| AccountError::new("invalid staged version"))?;
    let row: Option<(Option<String>,Option<String>)> = database()?.query_row("SELECT base_file_id,base_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND staged_file=?5 AND op_type='write' AND state='pending'", params![id,version.instance,version.space,path_key(&version.path)?,staged], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|_| AccountError::new("cannot inspect rename source"))?;
    match row.ok_or_else(|| AccountError::new("rename source changed"))? {
        (Some(id), Some(etag)) => Ok(Some((id, etag))),
        (None, None) => Ok(None),
        _ => Err(AccountError::new("invalid rename source base")),
    }
}

pub(crate) fn rename_staged_write(
    version: &FileVersion,
    destination: &[String],
    target: Option<(&str, &str)>,
    source_parents: &[DirectoryIdentity],
    destination_parents: &[DirectoryIdentity],
    offline_binding: Option<&crate::MountBinding>,
) -> Result<FileVersion, AccountError> {
    let id = version
        .id
        .strip_prefix("cirrus-staged:")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| AccountError::new("rename requires a staged file"))?;
    let staged = version
        .etag
        .strip_prefix("\"cirrus-staged-")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| AccountError::new("invalid staged version"))?;
    let source = path_key(&version.path)?;
    let destination_key = path_key(destination)?;
    // Retain State working room through rollback/connection close as well.
    let reservation;
    let mut conn = database()?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect file rename plan"))?;
    let planned_base: Option<(Option<String>,Option<String>)> = conn.query_row("SELECT base_file_id,base_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='pending' AND staged_file=?5", params![id,version.instance,version.space,source,staged], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|_| AccountError::new("cannot inspect rename source"))?;
    let planned_base = planned_base.ok_or_else(|| AccountError::new("rename source changed"))?;
    let source_chain = encode_parents(
        &version.path,
        &load_operation_parents(&conn, id, &version.path)?,
    )?;
    let destination_chain = encode_parents(destination, destination_parents)?;
    let token = namespace_token()?;
    // Size the retarget and parent replacement, plus the actual dependency
    // text/row when a remote source must be removed after destination confirms.
    // This journal base is a PUT precondition, never a rebase of the immutable
    // overlay's original bytes or permission to change the inspected snapshot.
    let retarget = serde_json::to_vec(&(
        id,
        &version.instance,
        &version.space,
        &source,
        &destination_key,
        "write",
        &planned_base,
        target,
        staged,
        "pending",
        i64::MAX,
        (id, &source_chain, &destination_chain, Option::<&str>::None),
    ))
    .map_err(|_| AccountError::new("cannot size file rename retarget"))?;
    let source_row = if let (Some(base_id), Some(base_etag)) = &planned_base {
        serde_json::to_vec(&(
            (
                i64::MAX,
                &version.instance,
                &version.space,
                &source,
                "move-source",
                base_id,
                base_etag,
                &token,
                "pending",
                format!("destination-operation:{id}"),
                i64::MAX,
            ),
            (i64::MAX, &source_chain, Option::<&str>::None),
        ))
        .map_err(|_| AccountError::new("cannot size file rename dependency"))?
    } else {
        Vec::new()
    };
    // File-root and containing pins can change; unrelated Space pins cannot.
    // Use the same canonical indexed ranges/ancestor keys as tree planning,
    // charging whole selected roots and prefix growth without loading BLOBs.
    let ancestors = (0..version.path.len())
        .map(|length| path_key(&version.path[..length]))
        .collect::<Result<Vec<_>, _>>()?;
    let ancestors = serde_json::to_string(&ancestors)
        .map_err(|_| AccountError::new("cannot size file pin ancestors"))?;
    let prefix = format!("{},", source.trim_end_matches(']'));
    let upper = format!("{}-", source.trim_end_matches(']'));
    let (pin_bytes, pin_paths): (u64, u64) = if offline_binding.is_some() {
        (0, 0)
    } else {
        conn.query_row(
        "WITH roots AS (SELECT root FROM pins WHERE instance=?1 AND space=?2 AND (root=?3 OR (root>=?4 AND root<?5) OR root IN (SELECT value FROM json_each(?6))))
        SELECT coalesce(sum(bytes),0),coalesce(sum(paths),0) FROM (
            SELECT sum(length(CAST(root AS BLOB))+length(CAST(directories AS BLOB))+length(CAST(manifest AS BLOB))) AS bytes,sum(1+json_array_length(directories)+json_array_length(manifest)) AS paths FROM pins WHERE instance=?1 AND space=?2 AND root IN roots
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(CAST(version AS BLOB))),count(*)*3 FROM files WHERE instance=?1 AND space=?2 AND root IN roots
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(body)),count(*)*2 FROM chunks WHERE instance=?1 AND space=?2 AND root IN roots
        )", params![version.instance,version.space,source,prefix,upper,ancestors], |row| Ok((row.get(0)?,row.get(1)?)))
        .map_err(|_| AccountError::new("cannot size file pin relocation"))?
    };
    let planned = (retarget.len() as u64)
        .checked_add(source_row.len() as u64)
        .and_then(|bytes| bytes.checked_add(pin_bytes))
        .and_then(|bytes| bytes.checked_add(pin_paths.checked_mul(destination_key.len() as u64)?))
        .ok_or_else(|| AccountError::new("file storage estimate overflow"))?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_FILE_MOVE_ADMISSION_WINDOW")?;
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_FILE_MOVE_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin rename"))?;
    if reservation.is_some() {
        let current: i64 = tx
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect file rename plan"))?;
        if current != planning_version {
            return Err(AccountError::new(
                "directory metadata changed concurrently; retry",
            ));
        }
    }
    reject_fenced_ancestor(&tx, &version.instance, &version.space, &version.path)?;
    reject_fenced_ancestor(&tx, &version.instance, &version.space, destination)?;
    if let Some(binding) = offline_binding {
        validate_offline_rename(
            &tx,
            binding,
            version,
            destination,
            (target, None),
            crate::RenameParents {
                source: source_parents,
                destination: destination_parents,
            },
        )?;
    }
    let source_base: Option<(Option<String>,Option<String>)> = tx.query_row("SELECT base_file_id,base_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='pending' AND staged_file=?5", params![id,version.instance,version.space,source,staged], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|_| AccountError::new("cannot inspect rename source"))?;
    let source_base = source_base.ok_or_else(|| AccountError::new("rename source changed"))?;
    let recorded_parents = load_operation_parents(&tx, id, &version.path)?;
    if !equivalent_parents(
        &tx,
        &version.instance,
        &version.space,
        &version.path,
        &recorded_parents,
        source_parents,
    )? {
        return Err(AccountError::new("rename source parent changed"));
    }
    validate_parent_dependencies(
        &tx,
        &version.instance,
        &version.space,
        &version.path,
        &recorded_parents,
    )?;
    validate_parent_dependencies(
        &tx,
        &version.instance,
        &version.space,
        destination,
        destination_parents,
    )?;
    if source_base.0.is_some() != source_base.1.is_some() {
        return Err(AccountError::new("invalid rename source base"));
    }
    let source_others: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND id!=?4 AND state IN ('pending','conflict','uncertain')", params![version.instance,version.space,source,id], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect rename source"))?;
    if source_others != 0 {
        return Err(AccountError::new("path has unresolved operations"));
    }
    let count: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND (state IN ('pending','conflict','uncertain') OR (state='synced' AND id>?4))",
        params![version.instance, version.space, destination_key, id], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect rename target"))?;
    if count != 0 {
        return Err(AccountError::new("rename target has unresolved operations"));
    }
    let count = tx.execute("UPDATE operation_journal SET path=?1,base_file_id=?2,base_etag=?3,updated_at=strftime('%s','now') WHERE id=?4 AND instance=?5 AND space=?6 AND path=?7 AND op_type='write' AND state='pending' AND staged_file=?8 AND id=(SELECT max(id) FROM operation_journal WHERE instance=?5 AND space=?6 AND path=?7 AND op_type='write' AND state!='resolved')",
        params![destination_key, target.map(|target| target.0), target.map(|target| target.1), id, version.instance, version.space, source, staged])
        .map_err(|error| sqlite_storage_error(error, "cannot journal rename"))?;
    if count != 1 {
        return Err(AccountError::new("rename source changed"));
    }
    let count = tx.execute("UPDATE operation_parents SET parents=?1 WHERE operation_id=?2 AND parents=?3 AND destination_parents IS NULL", params![encode_parents(destination,destination_parents)?,id,encode_parents(&version.path,&recorded_parents)?])
        .map_err(|error| sqlite_storage_error(error,"cannot update rename parent identities"))?;
    if count != 1 {
        return Err(AccountError::new("rename source parent changed"));
    }
    if let (Some(base_id), Some(base_etag)) = source_base {
        let pending: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND state IN ('pending','conflict','uncertain')", [&version.instance], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect namespace operations"))?;
        if pending >= MAX_PENDING_NAMESPACE_OPERATIONS {
            return Err(AccountError::new("staging capacity exhausted"));
        }
        let duplicate: i64 = tx
            .query_row(
                "SELECT count(*) FROM operation_journal WHERE staged_file=?1",
                [&token],
                |row| row.get(0),
            )
            .map_err(|_| AccountError::new("cannot inspect operation token"))?;
        if duplicate != 0 {
            return Err(AccountError::new("operation token collision"));
        }
        tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES (?1,?2,?3,'move-source',?4,?5,?6,'pending',?7,strftime('%s','now'))", params![version.instance,version.space,source,base_id,base_etag,token,format!("destination-operation:{id}")]).map_err(|error| sqlite_storage_error(error, "cannot journal rename source"))?;
        save_operation_parents(
            &tx,
            tx.last_insert_rowid(),
            &version.path,
            &recorded_parents,
            None,
        )?;
    }
    if offline_binding.is_none() {
        relocate_pins(
            &tx,
            &version.instance,
            &version.space,
            &version.path,
            destination,
        )?;
    }
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit rename"))?;
    let mut renamed = version.clone();
    renamed.path = destination.to_vec();
    Ok(renamed)
}

pub(crate) fn replace_pending_write(
    source: &FileVersion,
    target: &FileVersion,
    source_parents: &[DirectoryIdentity],
    target_parents: &[DirectoryIdentity],
    offline_binding: Option<&crate::MountBinding>,
) -> Result<(FileVersion, Option<FileVersion>), AccountError> {
    let parse = |version: &FileVersion| -> Result<(i64, String), AccountError> {
        let id = version
            .id
            .strip_prefix("cirrus-staged:")
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| AccountError::new("invalid staged resource"))?;
        let file = version
            .etag
            .strip_prefix("\"cirrus-staged-")
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| AccountError::new("invalid staged version"))?;
        Ok((id, file.to_owned()))
    };
    let (source_id, source_file) = parse(source)?;
    let (target_id, target_file) = parse(target)?;
    if source_id == target_id
        || source.instance != target.instance
        || source.space != target.space
        || source.path == target.path
    {
        return Err(AccountError::new("invalid staged replacement"));
    }
    let source_key = path_key(&source.path)?;
    let target_key = path_key(&target.path)?;
    // The reservation must survive transaction rollback and connection close.
    let reservation;
    let mut conn = database()?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect replacement plan"))?;
    let planned_source: Option<(Option<String>,Option<String>)> = conn.query_row("SELECT base_file_id,base_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='pending' AND staged_file=?5", params![source_id,source.instance,source.space,source_key,source_file], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|_| AccountError::new("cannot inspect replacement source"))?;
    let planned_source =
        planned_source.ok_or_else(|| AccountError::new("path has unresolved operations"))?;
    let planned_target: Option<(Option<String>,Option<String>)> = conn.query_row("SELECT base_file_id,base_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='pending' AND staged_file=?5", params![target_id,target.instance,target.space,target_key,target_file], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|_| AccountError::new("cannot inspect replacement target"))?;
    let planned_target =
        planned_target.ok_or_else(|| AccountError::new("path has unresolved operations"))?;
    let source_chain = encode_parents(
        &source.path,
        &load_operation_parents(&conn, source_id, &source.path)?,
    )?;
    let target_chain = encode_parents(
        &target.path,
        &load_operation_parents(&conn, target_id, &target.path)?,
    )?;
    let token = namespace_token()?;
    // The retained target is a real journal copy, not a new content root. Its
    // original precondition and parent chain stay distinct from source bytes
    // installed into the live target row. Integer widths cover generated IDs.
    let rows = serde_json::to_vec(&(
        (
            i64::MAX,
            &target.instance,
            &target.space,
            &target_key,
            "write",
            &planned_target,
            &target_file,
            "resolved",
            "superseded by local rename; staged copy retained",
            i64::MAX,
        ),
        (i64::MAX, &target_chain, Option::<&str>::None),
        (target_id, &source_file, i64::MAX),
        (
            source_id,
            "resolved",
            "renamed locally; staged copy retained",
            i64::MAX,
        ),
    ))
    .map_err(|_| AccountError::new("cannot size replacement rows"))?;
    let source_row = if let (Some(base_id), Some(base_etag)) = &planned_source {
        serde_json::to_vec(&(
            (
                i64::MAX,
                &source.instance,
                &source.space,
                &source_key,
                "move-source",
                base_id,
                base_etag,
                &token,
                "pending",
                format!("destination-operation:{target_id}"),
                i64::MAX,
            ),
            (i64::MAX, &source_chain, Option::<&str>::None),
        ))
        .map_err(|_| AccountError::new("cannot size replacement source dependency"))?
    } else {
        Vec::new()
    };
    // Existing move-source dependencies are rewritten in bulk. Size their
    // existing variable fields and new text via SQL, not a history collection.
    let (dependency_bytes, dependency_count): (u64,u64) = conn.query_row(
        "SELECT coalesce(sum(length(CAST(path AS BLOB))+length(CAST(staged_file AS BLOB))+coalesce(length(CAST(base_file_id AS BLOB)),0)+coalesce(length(CAST(base_etag AS BLOB)),0)+length(CAST(error_msg AS BLOB))),0),count(*) FROM operation_journal WHERE instance=?1 AND space=?2 AND op_type='move-source' AND state='pending' AND error_msg=?3",
        params![source.instance,source.space,format!("destination-operation:{source_id}")], |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(|_| AccountError::new("cannot size replacement dependencies"))?;
    // Canonical indexed root ranges plus bounded ancestor keys cover moving
    // and containing pins. Charge whole selected roots conservatively without
    // fetching BLOB bodies or collecting another decoded pin tree.
    let ancestors = (0..source.path.len())
        .map(|length| path_key(&source.path[..length]))
        .collect::<Result<Vec<_>, _>>()?;
    let ancestors = serde_json::to_string(&ancestors)
        .map_err(|_| AccountError::new("cannot size replacement pin ancestors"))?;
    let prefix = format!("{},", source_key.trim_end_matches(']'));
    let upper = format!("{}-", source_key.trim_end_matches(']'));
    let (pin_bytes, pin_paths): (u64, u64) = if offline_binding.is_some() {
        (0, 0)
    } else {
        conn.query_row(
        "WITH roots AS (SELECT root FROM pins WHERE instance=?1 AND space=?2 AND (root=?3 OR (root>=?4 AND root<?5) OR root IN (SELECT value FROM json_each(?6))))
        SELECT coalesce(sum(bytes),0),coalesce(sum(paths),0) FROM (
            SELECT sum(length(CAST(root AS BLOB))+length(CAST(directories AS BLOB))+length(CAST(manifest AS BLOB))) AS bytes,sum(1+json_array_length(directories)+json_array_length(manifest)) AS paths FROM pins WHERE instance=?1 AND space=?2 AND root IN roots
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(CAST(version AS BLOB))),count(*)*3 FROM files WHERE instance=?1 AND space=?2 AND root IN roots
            UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(body)),count(*)*2 FROM chunks WHERE instance=?1 AND space=?2 AND root IN roots
        )", params![source.instance,source.space,source_key,prefix,upper,ancestors], |row| Ok((row.get(0)?,row.get(1)?)))
        .map_err(|_| AccountError::new("cannot size replacement pin relocation"))?
    };
    let planned = (rows.len() as u64)
        .checked_add(source_row.len() as u64)
        .and_then(|bytes| bytes.checked_add(dependency_bytes))
        .and_then(|bytes| {
            bytes.checked_add(
                dependency_count
                    .checked_mul(format!("destination-operation:{target_id}").len() as u64)?,
            )
        })
        .and_then(|bytes| bytes.checked_add(pin_bytes))
        .and_then(|bytes| bytes.checked_add(pin_paths.checked_mul(target_key.len() as u64)?))
        .ok_or_else(|| AccountError::new("replacement storage estimate overflow"))?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_PENDING_REPLACE_ADMISSION_WINDOW")?;
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_PENDING_REPLACE_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin staged replacement"))?;
    if reservation.is_some() {
        let current: i64 = tx
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect replacement plan"))?;
        if current != planning_version {
            return Err(AccountError::new(
                "directory metadata changed concurrently; retry",
            ));
        }
    }
    reject_fenced_ancestor(&tx, &source.instance, &source.space, &source.path)?;
    reject_fenced_ancestor(&tx, &target.instance, &target.space, &target.path)?;
    if let Some(binding) = offline_binding {
        validate_offline_rename(
            &tx,
            binding,
            source,
            &target.path,
            (None, Some(target)),
            crate::RenameParents {
                source: source_parents,
                destination: target_parents,
            },
        )?;
    }
    let source_base: Option<(Option<String>,Option<String>)> = tx.query_row("SELECT base_file_id,base_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='pending' AND staged_file=?5 AND id=(SELECT max(id) FROM operation_journal WHERE instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state!='resolved')", params![source_id,source.instance,source.space,source_key,source_file], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|_| AccountError::new("cannot inspect replacement source"))?;
    let source_base =
        source_base.ok_or_else(|| AccountError::new("path has unresolved operations"))?;
    let recorded_source = load_operation_parents(&tx, source_id, &source.path)?;
    let recorded_target = load_operation_parents(&tx, target_id, &target.path)?;
    if !equivalent_parents(
        &tx,
        &source.instance,
        &source.space,
        &source.path,
        &recorded_source,
        source_parents,
    )? || !equivalent_parents(
        &tx,
        &target.instance,
        &target.space,
        &target.path,
        &recorded_target,
        target_parents,
    )? {
        return Err(AccountError::new("rename parent changed"));
    }
    validate_parent_dependencies(
        &tx,
        &source.instance,
        &source.space,
        &source.path,
        &recorded_source,
    )?;
    validate_parent_dependencies(
        &tx,
        &target.instance,
        &target.space,
        &target.path,
        &recorded_target,
    )?;
    if source_base.0.is_some() != source_base.1.is_some() {
        return Err(AccountError::new("invalid rename source base"));
    }
    let target_base: Option<Option<String>> = tx.query_row("SELECT base_file_id FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='pending' AND staged_file=?5", params![target_id,target.instance,target.space,target_key,target_file], |row| row.get(0)).optional().map_err(|_| AccountError::new("cannot inspect replacement target"))?;
    if source_base
        .0
        .as_deref()
        .is_some_and(|id| target_base.as_ref().and_then(|value| value.as_deref()) == Some(id))
    {
        return Err(AccountError::new(
            "rename paths identify the same remote resource",
        ));
    }
    let others: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND space=?2 AND ((path=?3 AND id!=?5) OR (path=?4 AND id!=?6)) AND state IN ('pending','conflict','uncertain')", params![source.instance,source.space,source_key,target_key,source_id,target_id], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect staged replacement"))?;
    if others != 0 {
        return Err(AccountError::new("path has unresolved operations"));
    }
    let backed_up = tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) SELECT instance,space,path,op_type,base_file_id,base_etag,staged_file,'resolved','superseded by local rename; staged copy retained',strftime('%s','now') FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='pending' AND staged_file=?5 AND id=(SELECT max(id) FROM operation_journal WHERE instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state!='resolved')", params![target_id,target.instance,target.space,target_key,target_file]).map_err(|error| sqlite_storage_error(error, "cannot preserve replacement target"))?;
    if backed_up != 1 {
        return Err(AccountError::new("path has unresolved operations"));
    }
    let backup_copy_id = tx.last_insert_rowid();
    save_operation_parents(&tx, backup_copy_id, &target.path, &recorded_target, None)?;
    let mut detached = target.clone();
    detached.id = format!("cirrus-staged:{backup_copy_id}");
    tx.execute("UPDATE operation_journal SET staged_file=?1,updated_at=strftime('%s','now') WHERE id=?2 AND state='pending'", params![source_file,target_id]).map_err(|error| sqlite_storage_error(error, "cannot replace staged target"))?;
    tx.execute("UPDATE operation_journal SET state='resolved',error_msg='renamed locally; staged copy retained',updated_at=strftime('%s','now') WHERE id=?1 AND state='pending'", [source_id]).map_err(|error| sqlite_storage_error(error, "cannot resolve replacement source"))?;
    tx.execute("UPDATE operation_journal SET error_msg=?1 WHERE instance=?2 AND space=?3 AND op_type='move-source' AND state='pending' AND error_msg=?4", params![format!("destination-operation:{target_id}"),source.instance,source.space,format!("destination-operation:{source_id}")]).map_err(|error| sqlite_storage_error(error, "cannot preserve rename dependency"))?;
    if let (Some(base_id), Some(base_etag)) = source_base {
        let pending: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND state IN ('pending','conflict','uncertain')", [&source.instance], |row| row.get(0)).map_err(|_| AccountError::new("cannot inspect namespace operations"))?;
        if pending >= MAX_PENDING_NAMESPACE_OPERATIONS {
            return Err(AccountError::new("staging capacity exhausted"));
        }
        let duplicate: i64 = tx
            .query_row(
                "SELECT count(*) FROM operation_journal WHERE staged_file=?1",
                [&token],
                |row| row.get(0),
            )
            .map_err(|_| AccountError::new("cannot inspect operation token"))?;
        if duplicate != 0 {
            return Err(AccountError::new("operation token collision"));
        }
        tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES (?1,?2,?3,'move-source',?4,?5,?6,'pending',?7,strftime('%s','now'))", params![source.instance,source.space,source_key,base_id,base_etag,token,format!("destination-operation:{target_id}")]).map_err(|error| sqlite_storage_error(error, "cannot journal rename source"))?;
        save_operation_parents(
            &tx,
            tx.last_insert_rowid(),
            &source.path,
            &recorded_source,
            None,
        )?;
    }
    if offline_binding.is_none() {
        relocate_pins(
            &tx,
            &source.instance,
            &source.space,
            &source.path,
            &target.path,
        )?;
    }
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit staged replacement"))?;
    let mut renamed = source.clone();
    renamed.path = target.path.clone();
    renamed.id = target.id.clone();
    Ok((renamed, Some(detached)))
}

struct StagingReservation {
    name: String,
}

pub(crate) fn storage_reservations() -> Result<Vec<(String, u64)>, AccountError> {
    STAGING_LOCK
        .lock()
        .map(|reservations| reservations.clone())
        .map_err(|_| AccountError::new("staging state is unavailable"))
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        if let Ok(mut reservations) = STAGING_LOCK.lock() {
            reservations.retain(|(name, _)| name != &self.name);
        }
    }
}

fn check_staging_capacity(
    dir: &impl AsFd,
    bytes: u64,
    reservations: &[(String, u64)],
) -> Result<(), AccountError> {
    let mut entries =
        Dir::read_from(dir).map_err(|_| AccountError::new("cannot inspect staging directory"))?;
    let mut count = reservations.len();
    let mut total = reservations
        .iter()
        .fold(0u64, |sum, (_, size)| sum.saturating_add(*size));
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|_| AccountError::new("cannot inspect staging directory"))?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        if reservations
            .iter()
            .any(|(name, _)| name.as_bytes() == entry.file_name().to_bytes())
        {
            continue;
        }
        let stat = match fs::statat(dir, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            // A concurrent pin can unlink its private scratch file after readdir.
            Err(rustix::io::Errno::NOENT) => continue,
            Err(_) => return Err(AccountError::new("cannot inspect staging directory")),
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_size < 0 {
            return Err(AccountError::new("unsafe staging directory entry"));
        }
        count += 1;
        // Payload/manifest allocation counts, not the overlay's logical EOF.
        // Unknown private scratch files are conservatively charged by size too.
        let allocated = u64::try_from(stat.st_blocks)
            .map_err(|_| AccountError::new("invalid staging allocation"))?
            .saturating_mul(512);
        total = total.saturating_add((stat.st_size as u64).max(allocated));
    }
    if count >= MAX_STAGING_FILES
        || total.saturating_add(bytes.div_ceil(4096).saturating_mul(4096)) > MAX_STAGING_BYTES
    {
        return Err(AccountError::new("staging capacity exhausted"));
    }
    Ok(())
}

fn create_staged_file(
    bytes: u64,
) -> Result<(std::fs::File, OwnedFd, StagingReservation), AccountError> {
    match allocate_staged_file(bytes) {
        Err(error) if crate::storage::limits::is_pressure(&error) => {
            // allocate_staged_file has dropped staging flock + local mutex.
            // Never wait for cache SQLite while holding the allocator lock.
            if crate::cache::reclaim_for_storage_pressure()? {
                allocate_staged_file(bytes)
            } else {
                Err(error)
            }
        }
        result => result,
    }
}

fn allocate_staged_file(
    bytes: u64,
) -> Result<(std::fs::File, OwnedFd, StagingReservation), AccountError> {
    // Allocate actual payload/metadata capacity under the cross-process lock.
    // Sparse logical EOF never reaches this allocator.
    let staging_guard = ownership::acquire_staging()?;
    let mut reservations = STAGING_LOCK
        .lock()
        .map_err(|_| AccountError::new("staging state is unavailable"))?;
    let dir = ownership::staging_dir()?;
    check_staging_capacity(&dir, bytes, &reservations)?;
    crate::storage::limits::check(bytes, &reservations)?;
    let mut random = [0u8; 16];
    let mut filled = 0;
    while filled < random.len() {
        let count =
            rustix::rand::getrandom(&mut random[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(|_| AccountError::new("cannot generate staging name"))?;
        if count == 0 {
            return Err(AccountError::new("cannot generate staging name"));
        }
        filled += count;
    }
    let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let fd = fs::openat2(
        &dir,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOSPC {
            AccountError::new("staging capacity exhausted")
        } else {
            AccountError::new("cannot create staged file")
        }
    })?;
    if bytes != 0 {
        fs::fallocate(&fd, fs::FallocateFlags::empty(), 0, bytes).map_err(|error| {
            if matches!(error, rustix::io::Errno::NOSPC | rustix::io::Errno::DQUOT) {
                AccountError::new("staging capacity exhausted")
            } else {
                AccountError::new("cannot reserve staged file; inspect staging directory")
            }
        })?;
    }
    // Recheck real file/directory allocation and filesystem availability, not a
    // guessed metadata overhead. A rejection here leaves a charged orphan; do
    // not reclaim/retry and allocate another candidate after materialization.
    crate::storage::limits::check(0, &reservations).map_err(|error| {
        if crate::storage::limits::is_pressure(&error) {
            AccountError::new(
                "configured storage pressure changed after allocation; candidate retained",
            )
        } else {
            error
        }
    })?;
    reservations.push((name.clone(), bytes.div_ceil(4096).saturating_mul(4096)));
    drop(reservations);
    drop(staging_guard);
    let reservation = StagingReservation { name };
    #[cfg(feature = "fault-injection")]
    if bytes >= 64 * 1024
        && let Some(marker) = std::env::var_os("CIRRUS_TEST_STAGING_RESERVATION_WINDOW")
    {
        let marker = Path::new(&marker);
        if marker.is_file() {
            std::fs::write(marker.with_extension("waiting"), b"waiting")
                .map_err(|_| AccountError::new("cannot mark staging test window"))?;
            for _ in 0..1500 {
                if !marker.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if marker.exists() {
                return Err(AccountError::new("staging test window timed out"));
            }
        }
    }
    Ok((std::fs::File::from(fd), dir, reservation))
}

pub(crate) fn stage_detached_mutation(
    version: &FileVersion,
    mutation: crate::DirtyMutation<'_>,
    offline_binding: Option<&crate::MountBinding>,
) -> Result<FileVersion, AccountError> {
    let id = version
        .id
        .strip_prefix("cirrus-staged:")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| AccountError::new("invalid detached file"))?;
    let old_name = version
        .etag
        .strip_prefix("\"cirrus-staged-")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| AccountError::new("invalid detached version"))?;
    let root = mutate_root(Some(version), mutation)?;
    let name = root.save()?;
    // Candidate durability/registration has finished and released State and
    // allocator ownership. Only this new local-only head publication is gated;
    // retained reads/exports and publication recovery remain uncapped.
    let key = path_key(&version.path)?;
    let _state_phase = ownership::admit_local_state_turn()?;
    let reservation;
    let mut conn = database()?;
    publication::ensure_clear(&conn, &version.instance, &version.space)?;
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect detached head plan"))?;
    let planned = if crate::storage::limits::view()?.limits.is_some() {
        serde_json::to_vec(&(
            id,
            &version.instance,
            &version.space,
            &key,
            &name,
            "resolved",
            DETACHED_MESSAGE,
            i64::MAX,
        ))
        .map_err(|_| AccountError::new("cannot size detached head publication"))?
        .len() as u64
    } else {
        0
    };
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_DETACHED_ADMISSION_WINDOW")?;
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_DETACHED_RESERVED_WINDOW")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin detached head publication"))?;
    if reservation.is_some() {
        let current: i64 = tx
            .pragma_query_value(None, "data_version", |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect detached head plan"))?;
        if current != planning_version {
            return Err(AccountError::new(
                "detached head plan changed; local copies retained; retry",
            ));
        }
    }
    publication::ensure_clear(&tx, &version.instance, &version.space)?;
    if let Some(binding) = offline_binding
        && !offline_detached_in(&tx, binding, version)?
    {
        return Err(AccountError::new("offline detached version changed"));
    }
    // Resolved detached identity, not the current pathname head. Never reset
    // its state or copy the replacement's remote precondition/content base.
    let count = tx.execute("UPDATE operation_journal SET staged_file=?1,error_msg=?6,updated_at=strftime('%s','now') WHERE id=?2 AND instance=?3 AND space=?4 AND path=?5 AND op_type='write' AND state='resolved' AND error_msg IN (?6,'superseded by local rename; staged copy retained') AND staged_file=?7", params![name,id,version.instance,version.space,key,DETACHED_MESSAGE,old_name]).map_err(|error| sqlite_storage_error(error, "cannot update detached head; local copies retained"))?;
    if count != 1 {
        return Err(AccountError::new(
            "detached file changed; inspect staging directory",
        ));
    }
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_DETACHED_COMMIT_WINDOW")?;
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    let committed = tx.commit();
    conn.close().map_err(|_| {
        AccountError::new(
            "cannot close detached head database; outcome unknown; local copies retained",
        )
    })?;
    committed.map_err(|_| {
        AccountError::new("cannot commit detached head; outcome unknown; local copies retained")
    })?;
    // No pending-head publication marker: this row is permanently local-only.
    // Unknown results return errors, never replay the CAS or publish a stale
    // FUSE version. An exact later lookup/export observes the durable root.
    let mut next = version.clone();
    next.etag = format!("\"cirrus-staged-{name}\"");
    next.size = root.len();
    Ok(next)
}

// Detached handles are local identities, not pathname opens. Check activation
// and the exact resolved head in one snapshot without requiring a live name.
fn offline_detached_in(
    conn: &Connection,
    binding: &crate::MountBinding,
    version: &FileVersion,
) -> Result<bool, AccountError> {
    if !binding.offline || version.instance != binding.instance || version.space != binding.space {
        return Err(AccountError::new("offline detached binding changed"));
    }
    let owner: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM account_identities a JOIN sync_spaces s ON s.instance=a.instance AND s.issuer=a.issuer AND s.subject=a.subject WHERE a.instance=?1 AND s.space=?2 AND a.issuer=?3 AND a.subject=?4)", params![binding.instance,binding.space,binding.issuer,binding.subject], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline detached identity"))?;
    if !owner {
        return Err(AccountError::new("offline detached identity changed"));
    }
    let Some(id) = version
        .id
        .strip_prefix("cirrus-staged:")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return Ok(false);
    };
    if !version.checksums.is_empty() {
        return Ok(false);
    }
    let Some(root) = version
        .etag
        .strip_prefix("\"cirrus-staged-")
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Ok(false);
    };
    publication::ensure_clear(conn, &version.instance, &version.space)?;
    let matches: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal j JOIN dirty_roots r ON r.root=j.staged_file WHERE j.id=?1 AND j.instance=?2 AND j.space=?3 AND j.path=?4 AND j.op_type='write' AND j.state='resolved' AND j.error_msg IN (?5,'superseded by local rename; staged copy retained') AND j.staged_file=?6 AND r.size=?7)", params![id,version.instance,version.space,path_key(&version.path)?,DETACHED_MESSAGE,root,version.size], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline detached head"))?;
    // As for ordinary staged handles, fsync must not bless a missing/corrupt
    // manifest merely because its registry row still exists.
    Ok(matches && overlay::Overlay::load_in(conn, root)?.len() == version.size)
}

pub(crate) fn verify_offline_detached(
    binding: &crate::MountBinding,
    version: &FileVersion,
) -> Result<bool, AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot inspect offline detached snapshot"))?;
    let matches = offline_detached_in(&tx, binding, version)?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot close offline detached snapshot"))?;
    Ok(matches)
}

fn mutate_root(
    base: Option<&FileVersion>,
    mutation: crate::DirtyMutation<'_>,
) -> Result<overlay::Overlay, AccountError> {
    let mut root = if let Some(base) = base {
        if base.id.starts_with("cirrus-staged:") {
            let (_, name) = staged_version(&base.instance, &base.space, &base.path, &base.id)?
                .filter(|(version, _)| version == base)
                .ok_or_else(|| AccountError::new("staged file changed"))?;
            overlay::Overlay::load(&name)?
        } else {
            overlay::Overlay::original(base)?
        }
    } else {
        overlay::Overlay::empty()
    };
    match mutation {
        crate::DirtyMutation::Preserve => {}
        crate::DirtyMutation::Write { offset, bytes } => root.write(offset, bytes)?,
        crate::DirtyMutation::Resize(size) => root.resize(size)?,
    }
    Ok(root)
}

pub(crate) fn stage_mutation(
    binding: &crate::MountBinding,
    path: &[String],
    mutation: crate::DirtyMutation<'_>,
    base: Option<&FileVersion>,
    parents: &[DirectoryIdentity],
) -> Result<FileVersion, AccountError> {
    let (instance, space) = (binding.instance.as_str(), binding.space.as_str());
    let root = mutate_root(base, mutation)?;
    let name = root.save_checked(|conn| {
        validate_offline_write(
            conn,
            (instance, space),
            path,
            (&binding.issuer, &binding.subject),
            base,
            parents,
        )
    })?;
    publish_root(
        (instance, space),
        path,
        name,
        root.len(),
        base,
        parents,
        None,
    )
}

pub(crate) fn stage_offline_mutation(
    binding: &crate::MountBinding,
    path: &[String],
    mutation: crate::DirtyMutation<'_>,
    base: Option<&FileVersion>,
    parents: &[DirectoryIdentity],
) -> Result<FileVersion, AccountError> {
    // The destination PUT precondition remains `base` at the visible path.
    // Choose original source coordinates only when constructing a NEW overlay;
    // never rewrite an existing root's immutable interpretation.
    let original = base
        .filter(|version| !version.id.starts_with("cirrus-staged:"))
        .map(|version| content_base(version, true))
        .transpose()?
        .flatten();
    let root = mutate_root(original.as_ref().or(base), mutation)?;
    let name = root.save_checked(|conn| {
        validate_offline_write(
            conn,
            (&binding.instance, &binding.space),
            path,
            (&binding.issuer, &binding.subject),
            base,
            parents,
        )?;
        if let (Some(base), Some(original)) = (base, original.as_ref())
            && tree_content_base_in(conn, base, true)?.as_ref() != Some(original)
        {
            return Err(AccountError::new(
                "original content MOVE changed; local copies retained",
            ));
        }
        Ok(())
    })?;
    publish_root(
        (&binding.instance, &binding.space),
        path,
        name,
        root.len(),
        base,
        parents,
        Some((&binding.issuer, &binding.subject)),
    )
}

// Eligibility, original version, create absence and parents share the same
// publication transaction. Never relabel a saved observation after a race.
// Rename changes namespace intent, never the immutable original byte version.
// Pins stay at their original recovery coordinates in explicit offline mode:
// replacing a pinned target must not discard/split either independent copy.
fn validate_offline_rename(
    conn: &Connection,
    binding: &crate::MountBinding,
    source: &FileVersion,
    destination: &[String],
    target: (Option<(&str, &str)>, Option<&FileVersion>),
    parents: crate::RenameParents<'_>,
) -> Result<(), AccountError> {
    if !binding.offline
        || !binding.offline_writable
        || source.instance != binding.instance
        || source.space != binding.space
        || source.path == destination
    {
        return Err(AccountError::new("offline rename binding changed"));
    }
    let owner = (binding.issuer.as_str(), binding.subject.as_str());
    let location = (binding.instance.as_str(), binding.space.as_str());
    // Both sides must have version-bound complete parents. A newer parent
    // entry cannot promote an older same-ID complete listing into a new proof.
    for path in [&source.path[..], destination] {
        for depth in 1..path.len() {
            let parent = offline_directory_in(
                conn,
                location.0,
                location.1,
                &path[..depth - 1],
                Some(owner),
            )?;
            let entry = parent
                .get(&path[depth - 1])?
                .filter(Entry::is_directory)
                .ok_or_else(|| AccountError::new("offline rename parent unavailable"))?;
            let children =
                offline_directory_in(conn, location.0, location.1, &path[..depth], Some(owner))?;
            if let Some(operation) = entry
                .id()
                .strip_prefix("cirrus-dir:")
                .and_then(|id| id.parse::<i64>().ok())
            {
                let known: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM snapshots s JOIN operation_journal j ON j.id=s.local_operation WHERE s.instance=?1 AND s.space=?2 AND s.path=?3 AND s.issuer=?4 AND s.subject=?5 AND s.local_operation=?6 AND s.entries='[]' AND s.self_id IS NULL AND s.self_etag IS NULL AND j.instance=s.instance AND j.space=s.space AND j.path=s.path AND j.op_type='mkdir' AND j.state='pending')",params![location.0,location.1,path_key(&path[..depth])?,owner.0,owner.1,operation],|row|row.get(0))
                    .map_err(|_|AccountError::new("cannot verify offline rename local parent"))?;
                if !known {
                    return Err(AccountError::new("offline rename local parent changed"));
                }
            } else if children.remote_parent()?
                != (
                    entry.id().to_owned(),
                    entry
                        .etag()
                        .filter(|etag| crate::dav::strong_etag(etag))
                        .ok_or_else(|| {
                            AccountError::new("offline rename parent version unavailable")
                        })?
                        .to_owned(),
                )
            {
                return Err(AccountError::new(
                    "offline rename complete parent version changed",
                ));
            }
        }
    }
    validate_offline_write(
        conn,
        location,
        &source.path,
        owner,
        Some(source),
        parents.source,
    )?;
    let verify_base = |version: &FileVersion| -> Result<(), AccountError> {
        let id = version
            .id
            .strip_prefix("cirrus-staged:")
            .and_then(|id| id.parse::<i64>().ok())
            .ok_or_else(|| AccountError::new("offline rename requires staged source"))?;
        let base: (Option<String>,Option<String>) = conn.query_row("SELECT base_file_id,base_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='pending'",params![id,location.0,location.1,path_key(&version.path)?],|row|Ok((row.get(0)?,row.get(1)?)))
            .map_err(|_|AccountError::new("offline rename source changed"))?;
        let (name, parent) = version
            .path
            .split_last()
            .ok_or_else(|| AccountError::new("invalid offline rename source"))?;
        let mut raw = directory_snapshot_in(conn, location.0, location.1, parent)?;
        if raw.is_none()
            && let Some((name, ancestor)) = parent.split_last()
        {
            let entries =
                offline_directory_in(conn, location.0, location.1, ancestor, Some(owner))?;
            if let Some(entry) = entries
                .get(name)?
                .filter(|entry| entry.is_directory() && crate::dav::valid_remote_id(entry.id()))
            {
                raw = offline_child_snapshot_in(conn, location.0, location.1, parent, entry.id())?;
            }
        }
        if let Some(raw) = raw.as_mut() {
            // Filter only confirmed old representations, not the live staged
            // writes whose PUT preconditions are being checked here.
            visit_staged_entries_in(conn, location.0, location.1, parent, |name, entry| {
                if let LocalEntry::ConfirmedRemove(removal) = entry
                    && confirmed_removal_matches(conn, location, &removal, raw)?
                {
                    raw.remove_observed(name)?;
                }
                Ok(())
            })?;
        }
        let entry = raw.as_ref().map(|raw| raw.get(name)).transpose()?.flatten();
        let matches = match (base, entry) {
            ((None, None), None) => true,
            ((Some(id), Some(etag)), Some(entry)) => {
                crate::dav::valid_remote_id(&id)
                    && crate::dav::strong_etag(&etag)
                    && !entry.is_directory()
                    && entry.id() == id
                    && entry.etag() == Some(etag.as_str())
            }
            _ => false,
        };
        if !matches {
            return Err(AccountError::new("offline rename saved base changed"));
        }
        Ok(())
    };
    verify_base(source)?;
    if let Some(pending) = target.1 {
        if pending.instance != source.instance
            || pending.space != source.space
            || pending.path != destination
        {
            return Err(AccountError::new("offline rename target binding changed"));
        }
        validate_offline_write(
            conn,
            location,
            destination,
            owner,
            Some(pending),
            parents.destination,
        )?;
        verify_base(pending)?;
    } else {
        // This validates ancestor identities even for an existing remote target.
        let (name, parent) = destination
            .split_last()
            .ok_or_else(|| AccountError::new("invalid offline rename destination"))?;
        let entries = offline_directory_in(conn, location.0, location.1, parent, Some(owner))?;
        let current = entries.get(name)?;
        match (current, target.0) {
            (None, None) => validate_offline_write(
                conn,
                location,
                destination,
                owner,
                None,
                parents.destination,
            )?,
            (Some(entry), Some((id, etag)))
                if !entry.is_directory()
                    && crate::dav::valid_remote_id(id)
                    && crate::dav::strong_etag(etag)
                    && entry.id() == id
                    && entry.etag() == Some(etag) =>
            {
                let expected = FileVersion {
                    instance: source.instance.clone(),
                    space: source.space.clone(),
                    path: destination.to_vec(),
                    id: id.to_owned(),
                    etag: etag.to_owned(),
                    size: entry
                        .size()
                        .ok_or_else(|| AccountError::new("offline target size unavailable"))?,
                    checksums: entry.checksums().to_vec(),
                };
                validate_offline_write(
                    conn,
                    location,
                    destination,
                    owner,
                    Some(&expected),
                    parents.destination,
                )?;
            }
            _ => return Err(AccountError::new("offline rename target changed")),
        }
    }
    Ok(())
}

fn validate_offline_write(
    conn: &Connection,
    location: (&str, &str),
    path: &[String],
    owner: (&str, &str),
    base: Option<&FileVersion>,
    parents: &[DirectoryIdentity],
) -> Result<(), AccountError> {
    let (instance, space) = location;
    let (name, parent) = path
        .split_last()
        .ok_or_else(|| AccountError::new("invalid offline file path"))?;
    if parents.len() != parent.len() {
        return Err(AccountError::new("offline parent identities changed"));
    }
    for (index, expected) in parents.iter().enumerate() {
        let directory = offline_directory_in(conn, instance, space, &parent[..index], Some(owner))?;
        let entry = directory
            .get(&parent[index])?
            .filter(Entry::is_directory)
            .ok_or_else(|| AccountError::new("offline parent identity unavailable"))?;
        if DirectoryIdentity::from_resource_id(entry.id())? != *expected {
            return Err(AccountError::new("offline parent identity changed"));
        }
    }
    let entries = offline_directory_in(conn, instance, space, parent, Some(owner))?;
    let current = entries.get(name)?;
    let matches = match (base, current) {
        (None, None) => true,
        (Some(base), Some(entry)) => {
            !entry.is_directory()
                && entry.id() == base.id
                && entry.etag() == Some(base.etag.as_str())
                && entry.size() == Some(base.size)
                && entry.checksums() == base.checksums
        }
        _ => false,
    };
    if !matches {
        return Err(AccountError::new("offline file representation changed"));
    }
    Ok(())
}

fn root_publication_bytes(
    conn: &Connection,
    location: (&str, &str),
    path: &[String],
    name: &str,
    base: Option<&FileVersion>,
    parents: &[DirectoryIdentity],
) -> Result<u64, AccountError> {
    let (instance, space) = location;
    let encoded = path_key(path)?;
    let existing = base
        .and_then(|v| v.id.strip_prefix("cirrus-staged:"))
        .and_then(|id| id.parse::<i64>().ok());
    let mut operation = PendingWrite {
        id: i64::MAX,
        space: space.to_owned(),
        path: path.to_vec(),
        base_id: base.map(|v| v.id.clone()),
        base_etag: base.map(|v| v.etag.clone()),
        staged: name.to_owned(),
        parents: parents.to_vec(),
    };
    // Encode actual variable inputs and the same recovery-marker format, using
    // maximum integer widths for IDs/timestamps not yet assigned. For staged
    // updates charge all three possible CAS/successor forms conservatively.
    let row_bytes = |operation: &PendingWrite,
                     predecessor: Option<i64>,
                     error: Option<&str>|
     -> Result<u64, AccountError> {
        let row = serde_json::to_vec(&(
            operation.id,
            instance,
            space,
            &encoded,
            "write",
            &operation.base_id,
            &operation.base_etag,
            name,
            "pending",
            error,
            i64::MAX,
            (
                operation.id,
                encode_parents(path, &operation.parents)?,
                Option::<&str>::None,
            ),
            (operation.id, predecessor),
        ))
        .map_err(|_| AccountError::new("cannot size staged publication rows"))?;
        (row.len() as u64)
            .checked_add(publication::planned_fence_bytes(
                conn,
                instance,
                operation,
                predecessor,
                error,
            )?)
            .ok_or_else(|| AccountError::new("staged publication estimate overflow"))
    };
    if let Some(id) = existing {
        let (base_id,base_etag,confirmed_id,confirmed_etag,error) = conn.query_row(
            "SELECT base_file_id,base_etag,confirmed_file_id,confirmed_etag,error_msg FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write'",
            params![id,instance,space,encoded], |row| Ok((row.get::<_,Option<String>>(0)?,row.get::<_,Option<String>>(1)?,row.get::<_,Option<String>>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<String>>(4)?)),
        ).map_err(|_| AccountError::new("cannot inspect staged publication plan"))?;
        operation.parents = load_operation_parents(conn, id, path)?;
        let predecessor: Option<i64> = conn
            .query_row(
                "SELECT predecessor_id FROM write_dependencies WHERE operation_id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| AccountError::new("cannot inspect staged publication dependency"))?;
        operation.id = id;
        operation.base_id = base_id;
        operation.base_etag = base_etag;
        let pending = row_bytes(&operation, predecessor, error.as_deref())?;
        operation.id = i64::MAX;
        operation.base_id = confirmed_id;
        operation.base_etag = confirmed_etag;
        let confirmed = row_bytes(&operation, None, None)?;
        operation.base_id = None;
        operation.base_etag = None;
        let waiting = row_bytes(
            &operation,
            Some(id),
            Some("waiting for prior upload outcome"),
        )?;
        return pending
            .checked_add(confirmed)
            .and_then(|bytes| bytes.checked_add(waiting))
            .ok_or_else(|| AccountError::new("staged publication estimate overflow"));
    }
    let mut extra = 0u64;
    let moved: Option<(String,String,String)> = conn.query_row(
        "SELECT base_file_id,base_etag,error_msg FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND op_type='move-source' AND state='pending' AND base_file_id IS NOT NULL AND base_etag IS NOT NULL AND error_msg IS NOT NULL",
        params![instance,space,encoded], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional().map_err(|_| AccountError::new("cannot inspect recreated-source plan"))?;
    if let Some((base_id, base_etag, dependency)) = moved {
        let backup_id = dependency
            .strip_prefix("destination-operation:")
            .and_then(|id| id.parse::<i64>().ok())
            .ok_or_else(|| AccountError::new("invalid rename dependency"))?;
        let (backup_path,backup_file,backup_base_id,backup_base_etag): (String,String,Option<String>,Option<String>) = conn.query_row(
            "SELECT path,staged_file,base_file_id,base_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path!=?4 AND op_type='write' AND state='pending'",
            params![backup_id,instance,space,encoded], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).map_err(|_| AccountError::new("rename destination is unavailable"))?;
        let backup_path: Vec<String> = serde_json::from_str(&backup_path)
            .map_err(|_| AccountError::new("invalid rename destination"))?;
        let backup_parents = load_operation_parents(conn, backup_id, &backup_path)?;
        let retained = serde_json::to_vec(&(
            (
                i64::MAX,
                instance,
                space,
                path_key(&backup_path)?,
                "write",
                backup_base_id,
                backup_base_etag,
                backup_file,
                "resolved",
                "backup retained after source recreation",
                i64::MAX,
            ),
            (
                i64::MAX,
                encode_parents(&backup_path, &backup_parents)?,
                Option::<&str>::None,
            ),
            (
                "resolved",
                "source recreated locally; staged copy retained",
                i64::MAX,
            ),
        ))
        .map_err(|_| AccountError::new("cannot size retained rename destination"))?;
        extra = retained.len() as u64;
        if let (Some((name, parent)), Some((backup_name, backup_parent))) =
            (path.split_last(), backup_path.split_last())
            && parent == backup_parent
            && backup_name.strip_suffix('~') == Some(name.as_str())
        {
            // Only this existing Vim recreation branch relocates pins. Query
            // scalar lengths in selected roots, never BLOB bodies/history.
            let backup_key = path_key(&backup_path)?;
            let ancestors = (0..backup_path.len())
                .map(|length| path_key(&backup_path[..length]))
                .collect::<Result<Vec<_>, _>>()?;
            let ancestors = serde_json::to_string(&ancestors)
                .map_err(|_| AccountError::new("cannot size recreation pin ancestors"))?;
            let prefix = format!("{},", backup_key.trim_end_matches(']'));
            let upper = format!("{}-", backup_key.trim_end_matches(']'));
            let (bytes,paths): (u64,u64) = conn.query_row(
                "WITH roots AS (SELECT root FROM pins WHERE instance=?1 AND space=?2 AND (root=?3 OR (root>=?4 AND root<?5) OR root IN (SELECT value FROM json_each(?6))))
                SELECT coalesce(sum(bytes),0),coalesce(sum(paths),0) FROM (
                    SELECT sum(length(CAST(root AS BLOB))+length(CAST(directories AS BLOB))+length(CAST(manifest AS BLOB))) AS bytes,sum(1+json_array_length(directories)+json_array_length(manifest)) AS paths FROM pins WHERE instance=?1 AND space=?2 AND root IN roots
                    UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(CAST(version AS BLOB))),count(*)*3 FROM files WHERE instance=?1 AND space=?2 AND root IN roots
                    UNION ALL SELECT sum(length(CAST(root AS BLOB))+length(CAST(path AS BLOB))+length(body)),count(*)*2 FROM chunks WHERE instance=?1 AND space=?2 AND root IN roots
                )", params![instance,space,backup_key,prefix,upper,ancestors], |row| Ok((row.get(0)?,row.get(1)?)),
            ).map_err(|_| AccountError::new("cannot size recreation pin relocation"))?;
            extra = extra
                .checked_add(bytes)
                .and_then(|sum| sum.checked_add(paths.checked_mul(encoded.len() as u64)?))
                .ok_or_else(|| AccountError::new("staged publication estimate overflow"))?;
        }
        operation.base_id = Some(base_id);
        operation.base_etag = Some(base_etag);
    }
    row_bytes(&operation, None, None)?
        .checked_add(extra)
        .ok_or_else(|| AccountError::new("staged publication estimate overflow"))
}

fn publish_root(
    location: (&str, &str),
    path: &[String],
    name: String,
    size: u64,
    base: Option<&FileVersion>,
    parents: &[DirectoryIdentity],
    offline_owner: Option<(&str, &str)>,
) -> Result<FileVersion, AccountError> {
    let (instance, space) = location;
    // Candidate payload/manifest/dirty_roots registration are already durable
    // and independently charged. Refusal here retains that unacknowledged
    // candidate. The State allowance outlives this connection's close, while
    // marker recovery below continues on its separate UNCAPPED connection.
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_ROOT_PUBLICATION_ADMISSION_WINDOW")?;
    let _state_phase = ownership::admit_local_state_turn()?;
    let reservation;
    let mut conn = database()?;
    let encoded = path_key(path)?;
    let existing = base
        .and_then(|v| v.id.strip_prefix("cirrus-staged:"))
        .and_then(|v| v.parse::<i64>().ok());
    let planning_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect staged publication plan"))?;
    let planned = if crate::storage::limits::view()?.limits.is_some() {
        root_publication_bytes(&conn, (instance, space), path, &name, base, parents)?
    } else {
        0
    };
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
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_ROOT_PUBLICATION_RESERVED_WINDOW")?;
    // Both branch connections are this same owned connection; no recovery
    // path or immutable allocator acquires this State lease recursively.
    let check_plan = |conn: &Connection| -> Result<(), AccountError> {
        if let Some(owner) = offline_owner {
            validate_offline_write(conn, (instance, space), path, owner, base, parents)?;
        }
        if reservation.is_some() {
            let current: i64 = conn
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| AccountError::new("cannot inspect staged publication plan"))?;
            if current != planning_version {
                return Err(AccountError::new(
                    "directory metadata changed concurrently; retry",
                ));
            }
        }
        Ok(())
    };
    let validate = |conn: &Connection| -> Result<(), AccountError> {
        #[cfg(feature = "fault-injection")]
        crate::wait_test_window("CIRRUS_TEST_ROOT_PUBLICATION_COMMIT_WINDOW")?;
        if let Some(reservation) = &reservation {
            reservation.validate(conn)?;
        } else if crate::storage::limits::view()?.limits.is_some() {
            return Err(AccountError::new(crate::storage::limits::PRESSURE));
        }
        Ok(())
    };
    let id = if let Some(id) = existing {
        let expected = base.ok_or_else(|| AccountError::new("missing staged version"))?;
        let old_name = expected
            .etag
            .strip_prefix("\"cirrus-staged-")
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(|| AccountError::new("invalid staged version"))?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| sqlite_storage_error(error, "cannot begin staged update"))?;
        check_plan(&tx)?;
        reject_fenced_ancestor(&tx, instance, space, path)?;
        let recorded_parents = load_operation_parents(&tx, id, path)?;
        if !equivalent_parents(&tx, instance, space, path, &recorded_parents, parents)? {
            return Err(AccountError::new(
                "parent identity changed; staged copy retained",
            ));
        }
        validate_parent_dependencies(&tx, instance, space, path, &recorded_parents)?;
        let count = tx.execute("UPDATE operation_journal SET staged_file=?1,updated_at=strftime('%s','now') WHERE id=?2 AND instance=?3 AND space=?4 AND path=?5 AND state='pending' AND staged_file=?6 AND id=(SELECT max(id) FROM operation_journal WHERE instance=?3 AND space=?4 AND path=?5 AND op_type='write' AND state!='resolved') AND NOT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?3 AND space=?4 AND path=?5 AND op_type!='write' AND state IN ('pending','conflict','uncertain'))",
            params![name, id, instance, space, encoded, old_name])
            .map_err(|error| sqlite_storage_error(error, "cannot update staged file; inspect staging directory"))?;
        let next_id = if count == 1 {
            id
        } else {
            // The write began before sync finished. Create a successor only if the
            // exact snapshot was verified and no intervening operation exists.
            // Rename can retain a resolved recovery copy with a higher row ID;
            // that history is not a newer live version or permission to delete it.
            let inserted = tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) SELECT instance,space,path,'write',confirmed_file_id,confirmed_etag,?1,'pending',NULL,strftime('%s','now') FROM operation_journal AS original WHERE id=?2 AND instance=?3 AND space=?4 AND path=?5 AND op_type='write' AND state='synced' AND staged_file=?6 AND confirmed_file_id IS NOT NULL AND confirmed_etag IS NOT NULL AND NOT EXISTS(SELECT 1 FROM operation_journal AS other WHERE other.instance=original.instance AND other.space=original.space AND other.path=original.path AND other.state!='resolved' AND (other.id>original.id OR other.state IN ('pending','conflict','uncertain')))",
                params![name,id,instance,space,encoded,old_name])
                .map_err(|error| sqlite_storage_error(error, "cannot create staged successor; inspect staging directory"))?;
            if inserted == 1 {
                let successor = tx.last_insert_rowid();
                save_operation_parents(&tx, successor, path, &recorded_parents, None)?;
                successor
            } else {
                // Preserve later edits while the prior upload is in flight or uncertain.
                // The successor cannot be uploaded until the predecessor is verified.
                let inserted = tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) SELECT instance,space,path,'write',NULL,NULL,?1,'pending','waiting for prior upload outcome',strftime('%s','now') FROM operation_journal AS original WHERE id=?2 AND instance=?3 AND space=?4 AND path=?5 AND op_type='write' AND state='uncertain' AND staged_file=?6 AND NOT EXISTS(SELECT 1 FROM operation_journal AS other WHERE other.instance=original.instance AND other.space=original.space AND other.path=original.path AND other.id!=original.id AND other.state!='resolved' AND (other.id>original.id OR other.state IN ('pending','conflict','uncertain')))",
                    params![name,id,instance,space,encoded,old_name])
                    .map_err(|error| sqlite_storage_error(error, "cannot create waiting staged successor"))?;
                if inserted != 1 {
                    return Err(AccountError::new(
                        "staged operation changed; inspect staging directory",
                    ));
                }
                let successor = tx.last_insert_rowid();
                save_operation_parents(&tx, successor, path, &recorded_parents, None)?;
                tx.execute(
                    "INSERT INTO write_dependencies(operation_id,predecessor_id) VALUES(?1,?2)",
                    params![successor, id],
                )
                .map_err(|error| sqlite_storage_error(error, "cannot journal upload dependency"))?;
                successor
            }
        };
        let publication = publication::fence(&tx, next_id)?;
        #[cfg(feature = "fault-injection")]
        let veto = if count == 1
            && let Some(marker) = std::env::var_os("CIRRUS_TEST_DIRTY_COMMIT_ABORT")
            && std::fs::remove_file(marker).is_ok()
        {
            // This is a documented commit-hook veto, not a simulated disk I/O
            // error: SQLite converts COMMIT into ROLLBACK. Candidate objects
            // are durable and the exact pending-root CAS has already executed.
            let candidate: String = tx
                .query_row(
                    "SELECT staged_file FROM operation_journal WHERE id=?1",
                    [id],
                    |row| row.get(0),
                )
                .map_err(|_| AccountError::new("cannot inspect lab dirty commit candidate"))?;
            if candidate != name {
                return Err(AccountError::new(
                    "lab dirty commit CAS did not select candidate",
                ));
            }
            tx.commit_hook(Some(|| {
                eprintln!("cirrus lab dirty commit hook veto");
                true
            }));
            eprintln!("cirrus lab dirty commit candidate selected after CAS");
            crate::wait_test_window("CIRRUS_TEST_DIRTY_COMMIT_WINDOW")?;
            true
        } else {
            false
        };
        validate(&tx)?;
        let committed = tx.commit();
        #[cfg(feature = "fault-injection")]
        let committed = if committed.is_ok()
            && let Some(marker) = std::env::var_os("CIRRUS_TEST_DIRTY_COMMITTED_ERROR")
            && std::fs::remove_file(marker).is_ok()
        {
            eprintln!("cirrus lab committed-but-returned-error (not hardware I/O)");
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                None,
            ))
        } else {
            committed
        };
        #[cfg(feature = "fault-injection")]
        if veto {
            conn.commit_hook(None::<fn() -> bool>);
            let code = match &committed {
                Err(rusqlite::Error::SqliteFailure(error, _)) => Some(error.extended_code),
                _ => None,
            };
            eprintln!(
                "cirrus lab dirty commit result: extended={code:?} autocommit={}",
                conn.is_autocommit()
            );
        }
        // Transaction::commit consumes the transaction; its Drop attempts
        // rollback on error but discards rollback errors. Close before recovery,
        // never use autocommit alone as a statement about the durable outcome.
        conn.close().map_err(|_| {
            AccountError::new("cannot close publication database; local copies retained")
        })?;
        let recovered = publication::recover(
            instance,
            space,
            path,
            next_id,
            Some(&publication),
            committed.is_err(),
        )?;
        if !recovered {
            committed
                .map_err(|error| sqlite_storage_error(error, "cannot commit staged update"))?;
            return Err(AccountError::new(
                "local publication head changed; local copies retained",
            ));
        }
        next_id
    } else {
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| sqlite_storage_error(error, "cannot begin staged file"))?;
        check_plan(&tx)?;
        reject_fenced_ancestor(&tx, instance, space, path)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND state IN ('pending','conflict','uncertain')", params![instance, space, encoded], |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect staged operations"))?;
        let mut original = None;
        if count != 0 {
            if count != 1 || base.is_some() {
                return Err(AccountError::new("path has unresolved staged operations"));
            }
            let moved: Option<(i64, String, String, String)> = tx.query_row("SELECT id,base_file_id,base_etag,error_msg FROM operation_journal WHERE instance=?1 AND space=?2 AND path=?3 AND op_type='move-source' AND state='pending' AND base_file_id IS NOT NULL AND base_etag IS NOT NULL AND error_msg IS NOT NULL", params![instance, space, encoded], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .optional().map_err(|_| AccountError::new("cannot inspect staged operations"))?;
            let (move_id, id, etag, dependency) =
                moved.ok_or_else(|| AccountError::new("path has unresolved staged operations"))?;
            let recorded_parents = load_operation_parents(&tx, move_id, path)?;
            if !equivalent_parents(&tx, instance, space, path, &recorded_parents, parents)? {
                return Err(AccountError::new(
                    "parent identity changed; staged copy retained",
                ));
            }
            let backup_id = dependency
                .strip_prefix("destination-operation:")
                .and_then(|value| value.parse::<i64>().ok())
                .ok_or_else(|| AccountError::new("invalid rename dependency"))?;
            let backup: Option<(String, String)> = tx.query_row("SELECT path,staged_file FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path!=?4 AND op_type='write' AND state='pending'", params![backup_id, instance, space, encoded], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional().map_err(|_| AccountError::new("cannot inspect rename destination"))?;
            let (backup_path, backup) =
                backup.ok_or_else(|| AccountError::new("rename destination is unavailable"))?;
            StagedSnapshot::open(&backup)?;
            let backup_path: Vec<String> = serde_json::from_str(&backup_path)
                .map_err(|_| AccountError::new("invalid rename destination"))?;
            if let (Some((name, parent)), Some((backup_name, backup_parent))) =
                (path.split_last(), backup_path.split_last())
                && parent == backup_parent
                && backup_name.strip_suffix('~') == Some(name.as_str())
            {
                // Vim recreates the original name and removes this temporary backup.
                relocate_pins(&tx, instance, space, &backup_path, path)?;
            }
            // Keep the backup journal-referenced even if its visible name is later removed.
            tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) SELECT instance,space,path,op_type,base_file_id,base_etag,staged_file,'resolved','backup retained after source recreation',strftime('%s','now') FROM operation_journal WHERE id=?1", [backup_id])
                .map_err(|error| sqlite_storage_error(error, "cannot retain rename destination"))?;
            let backup_copy_id = tx.last_insert_rowid();
            let backup_parents = load_operation_parents(&tx, backup_id, &backup_path)?;
            save_operation_parents(&tx, backup_copy_id, &backup_path, &backup_parents, None)?;
            tx.execute("UPDATE operation_journal SET state='resolved',error_msg='source recreated locally; staged copy retained',updated_at=strftime('%s','now') WHERE id=?1 AND state='pending'", [move_id])
                .map_err(|error| sqlite_storage_error(error, "cannot resolve rename source"))?;
            original = Some((id, etag));
        }
        let base_id = original
            .as_ref()
            .map(|v| v.0.as_str())
            .or_else(|| base.map(|v| v.id.as_str()));
        let base_etag = original
            .as_ref()
            .map(|v| v.1.as_str())
            .or_else(|| base.map(|v| v.etag.as_str()));
        tx.execute("INSERT INTO operation_journal(instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at) VALUES (?1,?2,?3,'write',?4,?5,?6,'pending',NULL,strftime('%s','now'))",
            params![instance, space, encoded, base_id, base_etag, name])
            .map_err(|error| sqlite_storage_error(error, "cannot journal staged file; inspect staging directory"))?;
        let id = tx.last_insert_rowid();
        save_operation_parents(&tx, id, path, parents, None)?;
        let publication = publication::fence(&tx, id)?;
        validate(&tx)?;
        let committed = tx.commit();
        conn.close().map_err(|_| {
            AccountError::new("cannot close publication database; local copies retained")
        })?;
        if !publication::recover(
            instance,
            space,
            path,
            id,
            Some(&publication),
            committed.is_err(),
        )? {
            committed.map_err(|error| sqlite_storage_error(error, "cannot commit staged file"))?;
            return Err(AccountError::new(
                "local publication head changed; local copies retained",
            ));
        }
        id
    };
    Ok(FileVersion {
        instance: instance.to_owned(),
        space: space.to_owned(),
        path: path.to_vec(),
        id: format!("cirrus-staged:{id}"),
        etag: format!("\"cirrus-staged-{name}\""),
        size,
        checksums: Vec::new(),
    })
}

pub(crate) fn journal_high_water(instance: &str) -> Result<i64, AccountError> {
    database()?
        .query_row(
            "SELECT COALESCE(MAX(id),0) FROM operation_journal WHERE instance=?1",
            [instance],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect pending operations"))
}

pub(crate) struct IncomingFileSource {
    pub version: FileVersion,
    pub parents: Vec<DirectoryIdentity>,
}

// Synced MOVE history keeps this gate recognizable after confirmation/restart:
// a create-only write inside that destination, based on an outside original,
// must still name its one pending outside source by the same operation ID.
pub(crate) fn incoming_file_source(
    instance: &str,
    operation: &PendingWrite,
) -> Result<Option<IncomingFileSource>, AccountError> {
    if operation.base_id.is_some() || operation.base_etag.is_some() {
        return Ok(None);
    }
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot inspect incoming rename source"))?;
    let Some(json) = overlay::Overlay::load_in(&tx, &operation.staged)?.original_base_json()?
    else {
        return Ok(None);
    };
    let original: FileVersion =
        serde_json::from_str(&json).map_err(|_| AccountError::new("invalid incoming original"))?;
    let ancestors = (1..operation.path.len())
        .map(|depth| path_key(&operation.path[..depth]))
        .collect::<Result<Vec<_>, _>>()?;
    let ancestors = serde_json::to_string(&ancestors)
        .map_err(|_| AccountError::new("invalid incoming ancestry"))?;
    let mut stmt=tx.prepare("SELECT j.path,m.destination FROM operation_journal j JOIN directory_moves m ON m.operation_id=j.id WHERE j.instance=?1 AND j.space=?2 AND j.op_type='move-tree' AND j.state IN ('pending','conflict','uncertain','synced') AND m.destination IN (SELECT value FROM json_each(?3)) LIMIT 2").map_err(|_|AccountError::new("cannot inspect incoming tree ancestry"))?;
    let trees = stmt
        .query_map(params![instance, operation.space, ancestors], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| AccountError::new("cannot inspect incoming tree ancestry"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AccountError::new("invalid incoming tree ancestry"))?;
    if trees.is_empty() {
        return Ok(None);
    }
    if trees.len() != 1 {
        return Err(AccountError::new("ambiguous incoming tree history"));
    }
    let source: Vec<String> = serde_json::from_str(&trees[0].0)
        .map_err(|_| AccountError::new("invalid incoming tree source"))?;
    let destination: Vec<String> = serde_json::from_str(&trees[0].1)
        .map_err(|_| AccountError::new("invalid incoming tree destination"))?;
    if original.path.starts_with(&source) || original.path.starts_with(&destination) {
        return Ok(None);
    }
    let mut stmt=tx.prepare("SELECT id,path,base_file_id,base_etag FROM operation_journal WHERE error_msg=?1 AND op_type IN ('move-source','move-dir-source') AND state IN ('pending','conflict','uncertain') LIMIT 2").map_err(|_|AccountError::new("cannot inspect incoming source edge"))?;
    let rows = stmt
        .query_map([format!("destination-operation:{}", operation.id)], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| AccountError::new("cannot inspect incoming source edge"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AccountError::new("invalid incoming source edge"))?;
    let valid = rows.len() == 1
        && original.instance == instance
        && original.space == operation.space
        && rows[0].1 == path_key(&original.path)?
        && rows[0].2 == original.id
        && rows[0].3 == original.etag;
    if !valid {
        return Err(AccountError::new(
            "incoming rename source changed; local data retained",
        ));
    }
    let pending:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND op_type='move-source' AND state='pending')",params![rows[0].0,instance,operation.space],|row|row.get(0)).map_err(|_|AccountError::new("cannot inspect incoming source state"))?;
    if !pending {
        return Err(AccountError::new(
            "incoming rename source requires attention",
        ));
    }
    let parents = load_operation_parents(&tx, rows[0].0, &original.path)?;
    Ok(Some(IncomingFileSource {
        version: original,
        parents,
    }))
}

pub(crate) fn pending_writes(
    instance: &str,
    space: Option<&str>,
    after: i64,
    through: i64,
) -> Result<Vec<PendingWrite>, AccountError> {
    let conn = database()?;
    let mut stmt = conn.prepare("SELECT id,space,path,base_file_id,base_etag,staged_file FROM operation_journal AS j WHERE instance=?1 AND (?4 IS NULL OR space=?4) AND state='pending' AND op_type='write' AND id>?2 AND id<=?3 AND NOT EXISTS(SELECT 1 FROM write_dependencies AS d WHERE d.operation_id=j.id) ORDER BY id LIMIT 32")
        .map_err(|_| AccountError::new("cannot load pending operations"))?;
    let rows = stmt
        .query_map(params![instance, after, through, space], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get::<_, String>(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .map_err(|_| AccountError::new("cannot load pending operations"))?;
    rows.map(|row| {
        let (id, space, path, base_id, base_etag, staged) =
            row.map_err(|_| AccountError::new("invalid pending operation"))?;
        let path: Vec<String> =
            serde_json::from_str(&path).map_err(|_| AccountError::new("invalid pending path"))?;
        let parents = load_operation_parents(&conn, id, &path)?;
        Ok(PendingWrite {
            id,
            space,
            path,
            base_id,
            base_etag,
            staged,
            parents,
        })
    })
    .collect()
}

pub(crate) fn preservation_only(
    instance: &str,
    operation: &PendingWrite,
) -> Result<bool, AccountError> {
    let root = overlay::Overlay::load(&operation.staged)?;
    if !root.unchanged_base().is_some_and(|base| {
        base.instance == instance
            && base.space == operation.space
            && base.path == operation.path
            && Some(base.id.as_str()) == operation.base_id.as_deref()
            && Some(base.etag.as_str()) == operation.base_etag.as_deref()
    }) {
        return Ok(false);
    }
    // An unchanged byte view can still be actionable namespace/dependency
    // work. Never strand a consumer that requires this exact write to confirm.
    let required: bool = database()?.query_row(
        "SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND space=?2 AND op_type='move-source' AND state IN ('pending','conflict','uncertain') AND error_msg=?3) OR EXISTS(SELECT 1 FROM write_dependencies WHERE predecessor_id=?4)",
        params![instance,operation.space,format!("destination-operation:{}",operation.id),operation.id], |row| row.get(0),
    ).map_err(|_| AccountError::new("cannot inspect preservation dependencies"))?;
    Ok(!required)
}

// A write may only transition the exact snapshot that was inspected. This keeps
// an older upload from claiming or completing a newer local version.
pub(crate) fn set_write_state(
    instance: &str,
    operation: &PendingWrite,
    from: &str,
    to: &str,
    error: Option<&str>,
) -> Result<(), AccountError> {
    let count = database()?.execute(
        "UPDATE operation_journal SET state=?1,error_msg=?2,updated_at=strftime('%s','now') WHERE id=?3 AND instance=?4 AND space=?5 AND path=?6 AND op_type='write' AND state=?7 AND staged_file=?8 AND base_file_id IS ?9 AND base_etag IS ?10 AND EXISTS(SELECT 1 FROM operation_parents WHERE operation_id=?3 AND parents=?11 AND destination_parents IS NULL) AND NOT EXISTS(SELECT 1 FROM operation_journal AS fence WHERE fence.instance=?4 AND fence.space=?5 AND fence.error_msg GLOB 'local publication recovery:*') AND (?7!='pending' OR ?1!='uncertain' OR NOT EXISTS (SELECT 1 FROM operation_journal AS previous WHERE previous.instance=?4 AND previous.space=?5 AND previous.path=?6 AND previous.op_type='write' AND previous.id<?3 AND previous.state IN ('pending','conflict','uncertain')))",
        params![to,error,operation.id,instance,operation.space,path_key(&operation.path)?,from,operation.staged,operation.base_id,operation.base_etag,encode_parents(&operation.path,&operation.parents)?],
    ).map_err(|error| sqlite_storage_error(error, "cannot update staged write"))?;
    if count != 1 {
        let mut error = AccountError::new(
            "staged write changed or an earlier write requires attention; local copy retained",
        );
        error.yielded = from == "pending";
        return Err(error);
    }
    Ok(())
}

pub(crate) fn write_needs_attention(
    instance: &str,
    operation: &PendingWrite,
) -> Result<bool, AccountError> {
    database()?
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state IN ('conflict','uncertain') AND staged_file=?5 AND base_file_id IS ?6 AND base_etag IS ?7 AND EXISTS(SELECT 1 FROM operation_parents WHERE operation_id=?1 AND parents=?8 AND destination_parents IS NULL))",
            params![operation.id, instance, operation.space, path_key(&operation.path)?, operation.staged, operation.base_id, operation.base_etag, encode_parents(&operation.path, &operation.parents)?],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect staged write"))
}

pub(crate) fn set_namespace_state(
    instance: &str,
    operation: &NamespaceOperation,
    from: &str,
    to: &str,
    error: Option<&str>,
) -> Result<(), AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin namespace state transition"))?;
    set_namespace_state_in(&tx, instance, operation, from, to, error)?;
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit namespace state transition"))
}

fn set_namespace_state_in(
    tx: &rusqlite::Transaction<'_>,
    instance: &str,
    operation: &NamespaceOperation,
    from: &str,
    to: &str,
    error: Option<&str>,
) -> Result<(), AccountError> {
    publication::ensure_clear(tx, instance, &operation.space)?;
    let count = tx.execute(
        "UPDATE operation_journal SET state=?1,error_msg=?2,updated_at=strftime('%s','now') WHERE id=?3 AND instance=?4 AND space=?5 AND path=?6 AND op_type=?7 AND base_file_id IS ?8 AND base_etag IS ?9 AND staged_file=?10 AND state=?11 AND (?11!='pending' OR error_msg IS ?12) AND EXISTS(SELECT 1 FROM operation_parents WHERE operation_id=?3 AND parents=?13 AND destination_parents IS NULL)",
        params![to,error,operation.id,instance,operation.space,path_key(&operation.path)?,operation.kind,operation.base_id,operation.base_etag,operation.token,from,operation.pending_message,encode_parents(&operation.path,&operation.parents)?],
    ).map_err(|error| sqlite_storage_error(error, "cannot update namespace operation"))?;
    if count != 1 {
        let mut error = AccountError::new("namespace operation changed concurrently");
        error.yielded = from == "pending";
        return Err(error);
    }
    if to == "synced" {
        finish_sync_records(tx, instance, &operation.space, operation.id)?;
    }
    Ok(())
}

/// Parent version advancement cannot outlive its child success receipt.
/// This recovery/confirmation transaction intentionally has no quota gate.
pub(crate) fn confirm_namespace(
    instance: &str,
    operation: &NamespaceOperation,
    confirmation: Option<&str>,
    rebase: Option<(&NamespaceOperation, &str)>,
) -> Result<(), AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| AccountError::new("cannot begin namespace confirmation"))?;
    let snapshot = serde_json::to_string(operation)
        .map_err(|_| AccountError::new("cannot encode namespace confirmation"))?;
    let saved: Option<(String,String)> = tx.query_row(
        "SELECT snapshot,extra FROM mutation_receipts WHERE operation_id=?1 AND kind='namespace'",
        [operation.id], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(|_| AccountError::new("cannot inspect namespace receipt"))?;
    let Some((recorded, extra)) = saved else {
        return Err(AccountError::new(
            "namespace receipt unavailable; outcome remains uncertain",
        ));
    };
    if recorded != snapshot {
        return Err(AccountError::new(
            "namespace receipt changed; outcome remains uncertain",
        ));
    }
    if let Some((parent, new)) = rebase {
        if parent.space != operation.space
            || operation.path.len() < 2
            || parent.path != operation.path[..operation.path.len() - 1]
            || parent.kind != "rmdir"
            || extra
                != serde_json::to_string(&Some(parent))
                    .map_err(|_| AccountError::new("cannot encode parent rebase"))?
        {
            return Err(AccountError::new(
                "parent rebase differs from successful receipt",
            ));
        }
        update_rmdir_base_in(&tx, instance, parent, new)?;
        #[cfg(feature = "fault-injection")]
        crate::wait_test_window("CIRRUS_TEST_NAMESPACE_REBASE_WINDOW")?;
    }
    set_namespace_state_in(
        &tx,
        instance,
        operation,
        "uncertain",
        "synced",
        confirmation,
    )?;
    tx.commit().map_err(|_| AccountError::new("cannot commit namespace confirmation; outcome unknown; receipt retained if unconfirmed"))
}

pub(crate) fn namespace_needs_attention(
    instance: &str,
    operation: &NamespaceOperation,
) -> Result<bool, AccountError> {
    database()?
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type=?5 AND staged_file=?6 AND state IN ('conflict','uncertain'))",
            params![operation.id, instance, operation.space, path_key(&operation.path)?, operation.kind, operation.token],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect namespace operation"))
}

pub(crate) fn set_tree_state(
    instance: &str,
    operation: &TreeMove,
    from: &str,
    to: &str,
    error: Option<&str>,
) -> Result<(), AccountError> {
    let entry = serde_json::to_string(&operation.entry)
        .map_err(|_| AccountError::new("invalid directory metadata"))?;
    let mut conn = database()?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin tree state transition"))?;
    publication::ensure_clear(&tx, instance, &operation.space)?;
    let count = tx.execute(
        "UPDATE operation_journal SET state=?1,error_msg=?2,updated_at=strftime('%s','now') WHERE id=?3 AND instance=?4 AND space=?5 AND path=?6 AND op_type='move-tree' AND state=?7 AND EXISTS(SELECT 1 FROM directory_moves WHERE operation_id=?3 AND destination=?8 AND source_entry=?9 AND target_id IS ?10 AND target_etag IS ?11) AND EXISTS(SELECT 1 FROM operation_parents WHERE operation_id=?3 AND parents=?12 AND destination_parents=?13)",
        params![to,error,operation.id,instance,operation.space,path_key(&operation.source)?,from,path_key(&operation.destination)?,entry,operation.target.as_ref().map(|v| &v.0),operation.target.as_ref().map(|v| &v.1),encode_parents(&operation.source,&operation.parents)?,encode_parents(&operation.destination,&operation.destination_parents)?],
    ).map_err(|error| sqlite_storage_error(error, "cannot update directory move"))?;
    if count != 1 {
        let mut error = AccountError::new("directory move changed concurrently");
        error.yielded = from == "pending";
        return Err(error);
    }
    if to == "synced" {
        finish_sync_records(&tx, instance, &operation.space, operation.id)?;
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit tree state transition"))
}

fn finish_sync_records(
    tx: &rusqlite::Transaction<'_>,
    instance: &str,
    space: &str,
    id: i64,
) -> Result<(), AccountError> {
    tx.execute(
        "UPDATE sync_spaces SET last_verified=strftime('%s','now') WHERE instance=?1 AND space=?2",
        params![instance, space],
    )
    .map_err(|error| sqlite_storage_error(error, "cannot record verified operation time"))?;
    tx.execute("DELETE FROM sync_reads WHERE operation_id=?1", [id])
        .map_err(|error| sqlite_storage_error(error, "cannot retire operation reads"))?;
    tx.execute("DELETE FROM mutation_receipts WHERE operation_id=?1", [id])
        .map_err(|error| sqlite_storage_error(error, "cannot retire mutation receipt"))?;
    Ok(())
}

pub(crate) fn confirm_write(
    instance: &str,
    operation: &PendingWrite,
    verified: &FileVersion,
) -> Result<(), AccountError> {
    if verified.instance != instance
        || verified.space != operation.space
        || verified.path != operation.path
    {
        return Err(AccountError::new(
            "verified upload does not match staged write",
        ));
    }
    let mut conn = database()?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot begin upload confirmation"))?;
    publication::ensure_clear(&tx, instance, &operation.space)?;
    let count = tx.execute(
        "UPDATE operation_journal SET state='synced',confirmed_file_id=?1,confirmed_etag=?2,error_msg=NULL,updated_at=strftime('%s','now') WHERE id=?3 AND instance=?4 AND space=?5 AND path=?6 AND op_type='write' AND state='uncertain' AND staged_file=?7 AND base_file_id IS ?8 AND base_etag IS ?9 AND EXISTS(SELECT 1 FROM operation_parents WHERE operation_id=?3 AND parents=?10 AND destination_parents IS NULL)",
        params![verified.id,verified.etag,operation.id,instance,operation.space,path_key(&operation.path)?,operation.staged,operation.base_id,operation.base_etag,encode_parents(&operation.path,&operation.parents)?],
    ).map_err(|error| sqlite_storage_error(error, "cannot confirm staged write"))?;
    if count != 1 {
        return Err(AccountError::new(
            "staged write changed concurrently; local copy retained",
        ));
    }
    let successor: Option<i64> = tx
        .query_row(
            "SELECT operation_id FROM write_dependencies WHERE predecessor_id=?1",
            [operation.id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| AccountError::new("cannot inspect upload successor"))?;
    if let Some(successor) = successor {
        let count = tx.execute("UPDATE operation_journal SET base_file_id=?1,base_etag=?2,error_msg=NULL,updated_at=strftime('%s','now') WHERE id=?3 AND instance=?4 AND space=?5 AND path=?6 AND op_type='write' AND state='pending' AND base_file_id IS NULL AND base_etag IS NULL",
            params![verified.id,verified.etag,successor,instance,operation.space,path_key(&operation.path)?])
            .map_err(|error| sqlite_storage_error(error, "cannot rebase waiting write"))?;
        if count != 1 {
            return Err(AccountError::new(
                "waiting write changed; local copies retained",
            ));
        }
        tx.execute(
            "DELETE FROM write_dependencies WHERE operation_id=?1 AND predecessor_id=?2",
            params![successor, operation.id],
        )
        .map_err(|error| sqlite_storage_error(error, "cannot resolve upload dependency"))?;
    }
    tx.execute("INSERT INTO verified_uploads(operation_id,digest,version) SELECT operation_id,digest,?2 FROM upload_verifications WHERE operation_id=?1", params![operation.id,serde_json::to_string(verified).map_err(|_| AccountError::new("cannot encode verified upload"))?])
        .map_err(|error| sqlite_storage_error(error, "cannot retain verified upload evidence"))?;
    finish_sync_records(&tx, instance, &operation.space, operation.id)?;
    tx.execute(
        "DELETE FROM upload_verifications WHERE operation_id=?1",
        [operation.id],
    )
    .map_err(|error| sqlite_storage_error(error, "cannot retire confirmed verification"))?;
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit upload confirmation"))
}

pub(crate) fn confirmed_write(
    version: &FileVersion,
) -> Result<Option<(String, String)>, AccountError> {
    let Some(id) = version
        .id
        .strip_prefix("cirrus-staged:")
        .and_then(|id| id.parse::<i64>().ok())
    else {
        return Ok(None);
    };
    let Some(staged) = version
        .etag
        .strip_prefix("\"cirrus-staged-")
        .and_then(|tag| tag.strip_suffix('"'))
    else {
        return Ok(None);
    };
    database()?.query_row(
        "SELECT confirmed_file_id,confirmed_etag FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state='synced' AND staged_file=?5 AND confirmed_file_id IS NOT NULL AND confirmed_etag IS NOT NULL AND NOT EXISTS (SELECT 1 FROM operation_journal AS newer WHERE newer.instance=?2 AND newer.space=?3 AND newer.path=?4 AND newer.id>?1 AND newer.state!='resolved')",
        params![id,version.instance,version.space,path_key(&version.path)?,staged],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(|_| AccountError::new("cannot inspect verified upload"))
}

// A verified upload does not discard its immutable local bytes. This is an
// exact version cache, not a pathname fallback or proof of current remoteness.
pub(crate) fn confirmed_local_range(
    version: &FileVersion,
    offset: u64,
    length: u32,
) -> Result<Option<Vec<u8>>, AccountError> {
    confirmed_range_at(version, &version.path, offset, length)
}

fn confirmed_range_at(
    version: &FileVersion,
    journal_path: &[String],
    offset: u64,
    length: u32,
) -> Result<Option<Vec<u8>>, AccountError> {
    let conn = database()?;
    check_retained_identity(&conn, &version.instance, &version.space)?;
    let root: Option<String> = conn.query_row("SELECT j.staged_file FROM operation_journal j JOIN verified_uploads v ON v.operation_id=j.id JOIN dirty_roots r ON r.root=j.staged_file WHERE j.instance=?1 AND j.space=?2 AND j.path=?3 AND j.op_type='write' AND j.state='synced' AND j.confirmed_file_id=?4 AND j.confirmed_etag=?5 AND v.version=?6 AND r.size=?7 ORDER BY j.id DESC LIMIT 1",params![version.instance,version.space,path_key(journal_path)?,version.id,version.etag,serde_json::to_string(version).map_err(|_|AccountError::new("cannot encode confirmed local version"))?,version.size],|row|row.get(0))
        .optional().map_err(|_|AccountError::new("cannot inspect confirmed local bytes"))?;
    root.map(|root| StagedSnapshot::open(&root)?.range(offset, length))
        .transpose()
}

pub(crate) fn acknowledge(instance: &str, staged: &str) -> Result<(), AccountError> {
    if staged.len() != 32 || !staged.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AccountError::new("invalid operation token"));
    }
    let mut conn = database()?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| AccountError::new("cannot begin acknowledgement"))?;
    // Acknowledgement can rewrite successors or directory descendants. Resolve
    // the selected token's Spaces inside this transaction before touching any
    // of them; a local publication fence must survive ordinary acknowledgement.
    let spaces = {
        let mut statement = tx.prepare("SELECT DISTINCT space FROM operation_journal WHERE instance=?1 AND staged_file=?2 AND state IN ('conflict','uncertain')")
            .map_err(|_| AccountError::new("cannot inspect acknowledgement Space"))?;
        statement
            .query_map(params![instance, staged], |row| row.get::<_, String>(0))
            .map_err(|_| AccountError::new("cannot inspect acknowledgement Space"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AccountError::new("invalid acknowledgement Space"))?
    };
    for space in spaces {
        publication::ensure_clear(&tx, instance, &space)?;
    }
    let tree: Option<(String,String)> = tx.query_row("SELECT j.space,m.destination FROM operation_journal j JOIN directory_moves m ON m.operation_id=j.id WHERE j.instance=?1 AND j.staged_file=?2 AND j.op_type='move-tree' AND j.state IN ('conflict','uncertain')",params![instance,staged],|row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|_| AccountError::new("cannot inspect directory acknowledgement"))?;
    if let Some((space, destination)) = tree {
        let destination: Vec<String> = serde_json::from_str(&destination)
            .map_err(|_| AccountError::new("invalid directory destination"))?;
        let mut descendants = Vec::new();
        {
            let mut stmt=tx.prepare("SELECT id,path FROM operation_journal WHERE instance=?1 AND space=?2 AND state='pending'").map_err(|_| AccountError::new("cannot inspect directory descendants"))?;
            let rows = stmt
                .query_map(params![instance, space], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| AccountError::new("cannot inspect directory descendants"))?;
            for row in rows {
                let (id, path) =
                    row.map_err(|_| AccountError::new("invalid directory operation"))?;
                let path: Vec<String> = serde_json::from_str(&path)
                    .map_err(|_| AccountError::new("invalid directory path"))?;
                if path.starts_with(&destination) {
                    descendants.push(id);
                }
            }
        }
        for id in descendants {
            tx.execute("UPDATE operation_journal SET state='conflict',error_msg='parent directory move acknowledged; local operation retained',updated_at=strftime('%s','now') WHERE id=?1 AND state='pending'",[id]).map_err(|_| AccountError::new("cannot preserve directory descendant"))?;
        }
    }
    let successor: Option<i64> = tx.query_row("SELECT d.operation_id FROM write_dependencies d JOIN operation_journal previous ON previous.id=d.predecessor_id WHERE previous.instance=?1 AND previous.staged_file=?2 AND previous.state IN ('conflict','uncertain')", params![instance,staged], |row| row.get(0))
        .optional().map_err(|_| AccountError::new("cannot inspect waiting write"))?;
    if let Some(successor) = successor {
        let updated = tx.execute("UPDATE operation_journal SET state='conflict',error_msg='prior upload acknowledged without confirming its outcome; local copy retained',updated_at=strftime('%s','now') WHERE id=?1 AND instance=?2 AND state='pending'", params![successor,instance])
            .map_err(|error| sqlite_storage_error(error, "cannot preserve waiting write"))?;
        if updated != 1 {
            return Err(AccountError::new(
                "waiting write changed; local copy retained",
            ));
        }
        tx.execute(
            "DELETE FROM write_dependencies WHERE operation_id=?1",
            [successor],
        )
        .map_err(|error| sqlite_storage_error(error, "cannot resolve waiting write"))?;
    }
    // Other staging paths may have queued independent writes after this one.
    // Acknowledgement does not establish the earlier remote outcome for them.
    tx.execute("UPDATE operation_journal SET state='conflict',error_msg='prior upload acknowledged without confirming its outcome; local copy retained',updated_at=strftime('%s','now') WHERE id IN (SELECT later.id FROM operation_journal AS later JOIN operation_journal AS previous ON previous.instance=later.instance AND previous.space=later.space AND previous.path=later.path WHERE previous.instance=?1 AND previous.staged_file=?2 AND previous.op_type='write' AND previous.state IN ('conflict','uncertain') AND later.op_type='write' AND later.state='pending' AND later.id>previous.id)", params![instance,staged])
        .map_err(|error| sqlite_storage_error(error, "cannot preserve later writes"))?;
    let count = tx.execute("UPDATE operation_journal SET state='resolved',error_msg='acknowledged locally; remote outcome not asserted',updated_at=strftime('%s','now') WHERE instance=?1 AND staged_file=?2 AND state IN ('conflict','uncertain')", params![instance,staged])
        .map_err(|_| AccountError::new("cannot acknowledge operation"))?;
    if count != 1 {
        return Err(AccountError::new(
            "no matching conflict or uncertain operation",
        ));
    }
    tx.execute("DELETE FROM upload_verifications WHERE operation_id IN (SELECT id FROM operation_journal WHERE instance=?1 AND staged_file=?2 AND state='resolved')", params![instance,staged])
        .map_err(|error| sqlite_storage_error(error, "cannot retire acknowledged verification"))?;
    for table in ["sync_reads", "mutation_receipts"] {
        tx.execute(&format!("DELETE FROM {table} WHERE operation_id IN (SELECT id FROM operation_journal WHERE instance=?1 AND staged_file=?2 AND state='resolved')"), params![instance,staged])
            .map_err(|error| sqlite_storage_error(error, "cannot retire acknowledged operation progress"))?;
    }
    tx.commit()
        .map_err(|_| AccountError::new("cannot commit acknowledgement"))
}

fn open_staged(name: &str) -> Result<(std::fs::File, std::fs::Metadata), AccountError> {
    if name.len() != 32 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AccountError::new("invalid staged file name"));
    }
    let dir = ownership::staging_dir()?;
    let fd = fs::openat2(
        &dir,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| AccountError::new("staged file is unavailable"))?;
    let file = std::fs::File::from(fd);
    let stat = file
        .metadata()
        .map_err(|_| AccountError::new("cannot inspect staged file"))?;
    if !stat.is_file()
        || stat.uid() != process::geteuid().as_raw()
        || stat.mode() & 0o7777 != 0o600
        || stat.nlink() != 1
        || stat.len() > overlay::MAX_MANIFEST
    {
        return Err(AccountError::new("staged file is unsafe"));
    }
    Ok((file, stat))
}

fn verify_staged_metadata(
    file: &std::fs::File,
    before: &std::fs::Metadata,
) -> Result<(), AccountError> {
    let after = file
        .metadata()
        .map_err(|_| AccountError::new("cannot inspect staged file"))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(AccountError::new("staged file changed"));
    }
    Ok(())
}

fn staged_size(name: &str) -> Result<u64, AccountError> {
    Ok(overlay::Overlay::load(name)?.len())
}

pub(crate) struct StagedSnapshot {
    name: String,
    root: overlay::Overlay,
}

impl StagedSnapshot {
    pub(crate) fn root_digest(&self) -> Result<String, AccountError> {
        let encoded = serde_json::to_vec(&self.root)
            .map_err(|_| AccountError::new("cannot encode dirty root"))?;
        Ok(format!("{:x}", Sha256::digest(&encoded)))
    }

    pub(crate) fn digest(&self) -> Result<String, AccountError> {
        let mut digest = Sha256::new();
        let mut offset = 0;
        while offset < self.len() {
            let length = (self.len() - offset).min(CHUNK) as u32;
            digest.update(self.range(offset, length)?);
            offset += u64::from(length);
        }
        self.verify()?;
        Ok(format!("{:x}", digest.finalize()))
    }

    pub(crate) fn open(name: &str) -> Result<Self, AccountError> {
        Ok(Self {
            name: name.to_owned(),
            root: overlay::Overlay::load(name)?,
        })
    }

    pub(crate) fn len(&self) -> u64 {
        self.root.len()
    }

    pub(crate) fn verify(&self) -> Result<(), AccountError> {
        overlay::Overlay::load(&self.name).map(|_| ())
    }

    pub(crate) fn stream(&self) -> Result<StagedStream, AccountError> {
        self.verify()?;
        Ok(StagedStream {
            root: self.root.clone(),
            base: self.root.local_objects()?,
            offset: 0,
            buffer: Vec::new(),
            buffer_offset: 0,
        })
    }

    pub(crate) fn digest_step(&self, purpose: &str) -> Result<Option<String>, AccountError> {
        overlay::digest_step(&self.name, purpose, &self.root)
    }

    pub(crate) fn bounded_range(
        &self,
        offset: u64,
        length: u32,
        budget: u64,
    ) -> Result<(u32, u64), AccountError> {
        self.root.bounded_range(offset, length, budget)
    }

    pub(crate) fn prepare(
        &self,
        fetch: impl FnMut(&FileVersion, u64, u32) -> Result<Vec<u8>, AccountError>,
        bounded: bool,
    ) -> Result<bool, AccountError> {
        overlay::prepare_base(&self.root, fetch, bounded)
    }

    pub(crate) fn range_with(
        &self,
        offset: u64,
        length: u32,
        fetch: impl FnMut(&FileVersion, u64, u32) -> Result<Vec<u8>, AccountError>,
    ) -> Result<Vec<u8>, AccountError> {
        self.root.range(offset, length, fetch)
    }

    pub(crate) fn range(&self, offset: u64, length: u32) -> Result<Vec<u8>, AccountError> {
        self.range_with(offset, length, |_, _, _| {
            Err(AccountError::new(
                "exact original content base is unavailable locally",
            ))
        })
    }
}

pub(crate) struct StagedStream {
    root: overlay::Overlay,
    base: std::collections::BTreeMap<u64, overlay::Object>,
    offset: u64,
    buffer: Vec<u8>,
    buffer_offset: usize,
}

impl Read for StagedStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() || self.offset == self.root.len() {
            return Ok(0);
        }
        if self.buffer_offset == self.buffer.len() {
            // HTTP consumers can ask for tiny pieces. Verify each bounded
            // source range once, rather than rehashing its block for every read.
            self.buffer = self
                .root
                .range_local(
                    self.offset,
                    (self.root.len() - self.offset).min(CHUNK) as u32,
                    &self.base,
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            self.buffer_offset = 0;
        }
        let length = buffer.len().min(self.buffer.len() - self.buffer_offset);
        buffer[..length]
            .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + length]);
        self.buffer_offset += length;
        self.offset += length as u64;
        Ok(length)
    }
}

enum LocalEntry {
    Reset,
    Present(Entry),
    Remove,
    ConfirmedRemove(ConfirmedRemoval),
}

struct ConfirmedRemoval {
    id: i64,
    path: Vec<String>,
    base_id: Option<String>,
    base_etag: Option<String>,
    reset: bool,
    directory: bool,
}

// Only the deleted representation, in its original directory identity, stays
// hidden. A skipped optional parent copy cannot turn confirmation into local
// resurrection; a saved replacement or later local create must remain visible.
fn confirmed_removal_matches(
    conn: &Connection,
    location: (&str, &str),
    removal: &ConfirmedRemoval,
    snapshot: &crate::DirectorySnapshot,
) -> Result<bool, AccountError> {
    let (instance, space) = location;
    let (name, parent) = removal
        .path
        .split_last()
        .ok_or_else(|| AccountError::new("invalid confirmed removal path"))?;
    let Some(entry) = snapshot.get(name)? else {
        return Ok(false);
    };
    let id = removal
        .base_id
        .as_deref()
        .filter(|id| crate::dav::valid_remote_id(id))
        .ok_or_else(|| AccountError::new("confirmed removal identity unavailable"))?;
    if entry.id() != id || entry.is_directory() != removal.directory {
        return Ok(false);
    }
    let etag = removal
        .base_etag
        .as_deref()
        .filter(|etag| crate::dav::strong_etag(etag))
        .ok_or_else(|| AccountError::new("confirmed removal version unavailable"))?;
    let current = entry
        .etag()
        .filter(|etag| crate::dav::strong_etag(etag))
        .ok_or_else(|| AccountError::new("saved removal target version unavailable"))?;
    if current != etag {
        let rebased: bool = removal.directory && conn.query_row("SELECT EXISTS(SELECT 1 FROM removal_versions WHERE operation_id=?1 AND etag=?2)",params![removal.id,current], |row| row.get(0))
            .map_err(|_| AccountError::new("cannot inspect confirmed directory versions"))?;
        if !rebased {
            return Ok(false);
        }
    }
    let parents = load_operation_parents(conn, removal.id, &removal.path)?;
    let Some(expected) = parents.last() else {
        // Root membership is scoped by the exact account/Space and path.
        return Ok(parent.is_empty() && removal.reset);
    };
    let expected = match expected {
        DirectoryIdentity::Remote(id) => id.clone(),
        DirectoryIdentity::Pending(id) => {
            let message: Option<String> = conn.query_row("SELECT error_msg FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='mkdir' AND state='synced'", params![id,instance,space,path_key(parent)?], |row| row.get(0))
                .optional().map_err(|_| AccountError::new("cannot inspect confirmed removal parent"))?;
            message
                .and_then(|message| {
                    message
                        .strip_prefix("confirmed-directory:")
                        .map(str::to_owned)
                })
                .filter(|id| crate::dav::valid_remote_id(id))
                .ok_or_else(|| AccountError::new("confirmed removal parent unavailable"))?
        }
    };
    // Also covers an exact queued tree-MOVE copy: the path changes, not the
    // saved directory's self identity. Never match a different parent by name.
    let matches = snapshot.matches_parent(&expected)?;
    if !matches && removal.reset {
        return Err(AccountError::new(
            "confirmed removal parent identity changed or unavailable",
        ));
    }
    Ok(matches)
}

pub(crate) fn apply_staged_entries(
    instance: &str,
    space: &str,
    parent: &[String],
    snapshot: &mut crate::DirectorySnapshot,
) -> Result<(), AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot load staged entries"))?;
    apply_staged_entries_in(&tx, instance, space, parent, snapshot)?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot load staged entries"))
}

fn apply_staged_entries_in(
    conn: &Connection,
    instance: &str,
    space: &str,
    parent: &[String],
    snapshot: &mut crate::DirectorySnapshot,
) -> Result<(), AccountError> {
    snapshot.begin_pending()?;
    visit_staged_entries_in(conn, instance, space, parent, |name, state| match state {
        LocalEntry::Reset => snapshot.reset_pending(name),
        LocalEntry::Present(entry) => snapshot.pending(name, Some(&entry)),
        LocalEntry::Remove => snapshot.pending(name, None),
        LocalEntry::ConfirmedRemove(removal) => {
            if confirmed_removal_matches(conn, (instance, space), &removal, snapshot)? {
                snapshot.remove_observed(name)?;
                if removal.reset {
                    snapshot.reset_pending(name)
                } else {
                    // A copied MOVE base is historical evidence, not a later
                    // mutation of the destination's pending local entries.
                    Ok(())
                }
            } else if removal.reset {
                snapshot.reset_pending(name)
            } else {
                Ok(())
            }
        }
    })?;
    snapshot.finish_pending()
}

fn visit_staged_entries_in(
    conn: &Connection,
    instance: &str,
    space: &str,
    parent: &[String],
    mut visit: impl FnMut(&str, LocalEntry) -> Result<(), AccountError>,
) -> Result<(), AccountError> {
    let mut stmt = conn.prepare("SELECT id,path,staged_file,state,op_type,base_file_id,base_etag FROM operation_journal WHERE instance=?1 AND space=?2 AND (?3 IS NULL OR id>?3) ORDER BY id LIMIT 32")
        .map_err(|_| AccountError::new("cannot load staged entries"))?;
    let mut cursor: Option<i64> = None;
    loop {
        let rows = stmt
            .query_map(params![instance, space, cursor], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(|_| AccountError::new("cannot load staged entries"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AccountError::new("invalid staged entry"))?;
        if rows.is_empty() {
            break;
        }
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_FILE_METADATA_TRACE").is_some() {
            eprintln!("cirrus lab pending journal page: rows={}", rows.len());
        }
        for row in rows {
            let (id, encoded, staged, state, kind, base_id, base_etag) = row;
            cursor = Some(id);
            let path: Vec<String> = serde_json::from_str(&encoded)
                .map_err(|_| AccountError::new("invalid staged path"))?;
            let Some((name, directory)) = path.split_last() else {
                return Err(AccountError::new("invalid staged path"));
            };
            if state == "synced"
                && matches!(
                    kind.as_str(),
                    "unlink" | "move-source" | "rmdir" | "move-dir-source"
                )
            {
                let name = name.clone();
                let reset = directory == parent;
                visit(
                    &name,
                    LocalEntry::ConfirmedRemove(ConfirmedRemoval {
                        id,
                        path,
                        base_id,
                        base_etag,
                        reset,
                        directory: matches!(kind.as_str(), "rmdir" | "move-dir-source"),
                    }),
                )?;
                continue;
            }
            if directory != parent {
                continue;
            }
            if state == "resolved" {
                continue;
            }
            if state == "synced" {
                visit(name, LocalEntry::Reset)?;
                continue;
            }
            let entry = match kind.as_str() {
                "write" => Some(Entry::staged(
                    name.clone(),
                    id,
                    // Reuse this read transaction. Opening another SQLite reader
                    // here can deadlock a writer waiting for this snapshot to end.
                    overlay::Overlay::load_in(conn, &staged)?.len(),
                    &staged,
                )),
                "mkdir" => Some(Entry::staged_directory(name.clone(), id)),
                "unlink" | "rmdir" | "move-source" | "move-dir-source" => None,
                "move-tree" => None,
                _ => return Err(AccountError::new("unsupported namespace operation")),
            };
            visit(name, entry.map_or(LocalEntry::Remove, LocalEntry::Present))?;
        }
    }
    drop(stmt);
    let mut after = None;
    loop {
        let page = tree_moves_scoped_in(conn, instance, Some(space), (after, i64::MAX))?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        for operation in page {
            if let Some((name, directory)) = operation.destination.split_last()
                && directory == parent
            {
                visit(
                    name,
                    LocalEntry::Present(operation.entry.with_name(name.clone())),
                )?;
            }
        }
    }
    Ok(())
}

pub(crate) fn offline_directory(
    instance: &str,
    space: &str,
    path: &[String],
    owner: Option<(&str, &str)>,
) -> Result<crate::DirectorySnapshot, AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot inspect offline directory"))?;
    let entries = offline_directory_in(&tx, instance, space, path, owner)?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot finish offline directory inspection"))?;
    Ok(entries)
}

fn offline_directory_in(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    owner: Option<(&str, &str)>,
) -> Result<crate::DirectorySnapshot, AccountError> {
    check_retained_identity(conn, instance, space)?;
    if let Some((issuer, subject)) = owner {
        let matches: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM account_identities WHERE instance=?1 AND issuer=?2 AND subject=?3)", params![instance,issuer,subject], |row| row.get(0))
            .map_err(|_| AccountError::new("cannot verify offline mount identity"))?;
        if !matches {
            return Err(AccountError::new("offline mount identity changed"));
        }
    }
    let activated: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_spaces WHERE instance=?1 AND space=?2)",
            params![instance, space],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect retained Space identity"))?;
    if !activated {
        return Err(AccountError::new(
            "Space has no verified local activation; local data retained",
        ));
    }
    // Resolve every ancestor from the same saved namespace and journal view.
    // No saved observation means unavailable, not an invented empty directory.
    let mut directory = Vec::new();
    let mut entries = directory_snapshot_in(conn, instance, space, &directory)?
        .ok_or_else(|| AccountError::new("offline directory metadata is unavailable"))?;
    for component in path {
        apply_staged_entries_in(conn, instance, space, &directory, &mut entries)?;
        let entry = entries
            .get(component)?
            .filter(Entry::is_directory)
            .ok_or_else(|| AccountError::new("offline path is missing or not a directory"))?;
        let local = entry.id().starts_with("cirrus-dir:");
        directory.push(component.clone());
        entries = if local {
            crate::DirectorySnapshot::empty()?
        } else {
            offline_child_snapshot_in(conn, instance, space, &directory, entry.id())?
                .ok_or_else(|| AccountError::new("offline directory metadata is unavailable"))?
        };
    }
    apply_staged_entries_in(conn, instance, space, path, &mut entries)?;
    Ok(entries)
}

fn offline_child_snapshot_in(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    expected_id: &str,
) -> Result<Option<crate::DirectorySnapshot>, AccountError> {
    if let Some(snapshot) =
        offline_replacement_snapshot_in(conn, instance, space, path, expected_id)?
    {
        return Ok(Some(snapshot));
    }
    if let Some(snapshot) = directory_snapshot_in(conn, instance, space, path)? {
        if !snapshot.matches_parent(expected_id)? {
            return Err(AccountError::new(
                "offline directory parent identity changed",
            ));
        }
        return Ok(Some(snapshot));
    }
    // Only the exact unresolved MOVE root lacks a raw parent mapping: its
    // ancestor entry comes from the journal projection. Descendants still use
    // ordinary saved-parent binding, checked against the resolved entry above.
    let mut after = None;
    let mut copied = false;
    loop {
        let page = tree_moves_scoped_in(conn, instance, Some(space), (after, i64::MAX))?;
        let Some(last) = page.last() else { break };
        after = Some(last.id);
        for operation in page {
            if operation.destination != path {
                continue;
            }
            if copied || operation.entry.id() != expected_id {
                return Err(AccountError::new("offline directory MOVE identity differs"));
            }
            if operation.offline {
                let observed = offline_tree_copy_in(conn, (instance, space), path, &operation)?;
                // Every candidate for this destination must be unique, even
                // when the immutable proof is independently complete.
                if observed.is_none() {
                    return Err(AccountError::new(
                        "offline directory MOVE proof unavailable",
                    ));
                }
                copied = true;
                continue;
            }
            let etag = operation.entry.etag().ok_or_else(|| {
                AccountError::new("offline directory MOVE source version is unavailable")
            })?;
            let (name, parent) = path
                .split_last()
                .ok_or_else(|| AccountError::new("invalid directory destination"))?;
            let exact: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM snapshots source JOIN snapshots destination ON destination.instance=source.instance AND destination.space=source.space AND destination.entries=source.entries AND destination.updated=source.updated AND destination.self_id IS source.self_id AND destination.self_etag IS source.self_etag AND destination.local_operation IS source.local_operation AND destination.issuer=source.issuer AND destination.subject=source.subject JOIN operation_journal j ON j.id=?5 AND j.instance=source.instance AND j.space=source.space WHERE source.instance=?1 AND source.space=?2 AND source.path=?3 AND destination.path=?4 AND source.self_id=?6 AND j.op_type='move-tree' AND j.path=source.path AND j.state IN ('pending','conflict','uncertain') AND j.base_file_id=?6 AND j.base_etag IS ?7)
                AND NOT EXISTS(SELECT 1 FROM snapshots saved,json_each(saved.entries) child WHERE saved.instance=?1 AND saved.space=?2 AND saved.path=?8 AND json_extract(child.value,'$.name')=?9 AND (json_extract(child.value,'$.directory') IS NOT 1 OR json_extract(child.value,'$.id') IS NOT ?6))",
                params![instance,space,path_key(&operation.source)?,path_key(path)?,operation.id,expected_id,etag,path_key(parent)?,name], |row| row.get(0))
                .map_err(|_| AccountError::new("cannot verify copied MOVE snapshot"))?;
            if !exact {
                return Err(AccountError::new(
                    "offline directory MOVE copy is unavailable or changed",
                ));
            }
            // The original snapshot must itself remain identity-bound. Never
            // promote an arbitrary orphan merely because its JSON was copied.
            let source = directory_snapshot_in(conn, instance, space, &operation.source)?
                .ok_or_else(|| {
                    AccountError::new("offline directory MOVE source identity is unavailable")
                })?;
            if !source.matches_parent(expected_id)? {
                return Err(AccountError::new(
                    "offline directory MOVE source identity is unavailable",
                ));
            }
            copied = true;
        }
    }
    if !copied {
        return Ok(None);
    }
    directory_snapshot_with_parent_in(conn, instance, space, path, Some(expected_id))
}

// Replacement preflight observes the *old* destination; ordinary cache
// publication may revoke/reuse that path. Serve only the immutable, admitted
// source proof, never the observed target under the source's identity.
fn offline_replacement_snapshot_in(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    expected_id: &str,
) -> Result<Option<crate::DirectorySnapshot>, AccountError> {
    let mut after = None;
    loop {
        let page = tree_moves_scoped_in(conn, instance, Some(space), (after, i64::MAX))?;
        let Some(last) = page.last() else {
            break;
        };
        after = Some(last.id);
        for operation in page {
            if !operation.offline
                || operation.target.is_none()
                || !path.starts_with(&operation.destination)
            {
                continue;
            }
            tree_target_proof_in(conn, instance, &operation)?;
            let mut actual = Vec::with_capacity(operation.destination_parents.len());
            for index in 0..operation.destination.len() - 1 {
                let entries = offline_directory_in(
                    conn,
                    instance,
                    space,
                    &operation.destination[..index],
                    None,
                )?;
                let entry = entries
                    .get(&operation.destination[index])?
                    .filter(Entry::is_directory)
                    .ok_or_else(|| AccountError::new("offline replacement parent unavailable"))?;
                actual.push(DirectoryIdentity::from_resource_id(entry.id())?);
            }
            if !equivalent_parents(
                conn,
                instance,
                space,
                &operation.destination,
                &actual,
                &operation.destination_parents,
            )? {
                return Err(AccountError::new("offline replacement parent changed"));
            }
            let relative = path_key(&path[operation.destination.len()..])?;
            let (id,etag,digest,json):(String,String,String,String)=conn.query_row("SELECT self_id,self_etag,digest,entries FROM tree_proofs WHERE operation_id=?1 AND path=?2",params![operation.id,relative],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(|_|AccountError::new("offline replacement source proof unavailable"))?;
            if id != expected_id || format!("{:x}", Sha256::digest(json.as_bytes())) != digest {
                return Err(AccountError::new(
                    "offline replacement source proof changed",
                ));
            }
            let mut snapshot = crate::DirectorySnapshot::empty()?;
            snapshot.set_remote_parent(&id, &etag)?;
            let mut stmt = conn
                .prepare("SELECT value FROM json_each(?1)")
                .map_err(|_| AccountError::new("cannot read replacement source proof"))?;
            for row in stmt
                .query_map([json], |row| row.get::<_, String>(0))
                .map_err(|_| AccountError::new("cannot read replacement source proof"))?
            {
                let entry: Entry = serde_json::from_str(
                    &row.map_err(|_| AccountError::new("invalid replacement source proof"))?,
                )
                .map_err(|_| AccountError::new("invalid replacement source proof"))?;
                snapshot.insert(&entry)?;
            }
            return Ok(Some(snapshot));
        }
    }
    Ok(None)
}

fn tree_target_proof_in(
    conn: &Connection,
    instance: &str,
    operation: &TreeMove,
) -> Result<(), AccountError> {
    let Some((id, etag)) = &operation.target else {
        return Ok(());
    };
    let known:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM tree_targets t JOIN operation_journal j ON j.id=t.operation_id JOIN directory_moves m ON m.operation_id=j.id JOIN account_identities a ON a.instance=j.instance AND a.issuer=t.issuer AND a.subject=t.subject JOIN tree_proofs p ON p.operation_id=j.id AND p.path='[]' AND p.self_id=j.base_file_id AND p.self_etag=j.base_etag WHERE j.id=?1 AND j.instance=?2 AND j.space=?3 AND j.path=?4 AND j.op_type='move-tree' AND j.base_file_id=json_extract(m.source_entry,'$.id') AND j.base_etag=json_extract(m.source_entry,'$.etag') AND m.offline=1 AND m.destination=?5 AND m.target_id=t.self_id AND m.target_etag=t.self_etag AND t.self_id=?6 AND t.self_etag=?7 AND t.entries='[]')",params![operation.id,instance,operation.space,path_key(&operation.source)?,path_key(&operation.destination)?,id,etag],|row|row.get(0)).map_err(|_|AccountError::new("cannot inspect replacement target proof"))?;
    if !known {
        return Err(AccountError::new(
            "offline replacement target proof unavailable",
        ));
    }
    Ok(())
}

pub(crate) fn tree_target_proof(instance: &str, operation: &TreeMove) -> Result<(), AccountError> {
    tree_target_proof_in(&database()?, instance, operation)
}

fn offline_tree_copy_in(
    conn: &Connection,
    location: (&str, &str),
    path: &[String],
    operation: &TreeMove,
) -> Result<Option<crate::DirectorySnapshot>, AccountError> {
    let (instance, space) = location;
    let (name, parent) = path
        .split_last()
        .ok_or_else(|| AccountError::new("invalid tree copy path"))?;
    let proof:Option<(String,String,i64,String,i64)>=conn.query_row("SELECT p.self_id,p.self_etag,p.generation,p.digest,s.updated FROM tree_proofs p JOIN operation_journal j ON j.id=p.operation_id JOIN directory_moves m ON m.operation_id=j.id JOIN snapshots s ON s.instance=j.instance AND s.space=j.space AND s.path=m.destination WHERE p.operation_id=?1 AND p.path='[]' AND j.instance=?2 AND j.space=?3 AND j.path=?4 AND j.op_type='move-tree' AND j.state IN ('pending','conflict','uncertain') AND m.offline=1 AND m.destination=?5 AND NOT EXISTS(SELECT 1 FROM snapshots saved,json_each(saved.entries) child WHERE saved.instance=?2 AND saved.space=?3 AND saved.path=?6 AND json_extract(child.value,'$.name')=?7 AND (json_extract(child.value,'$.directory') IS NOT 1 OR json_extract(child.value,'$.id') IS NOT ?8))",params![operation.id,instance,space,path_key(&operation.source)?,path_key(path)?,path_key(parent)?,name,operation.entry.id()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).optional().map_err(|_|AccountError::new("cannot inspect immutable tree copy proof"))?;
    let Some((id, etag, generation, digest, copied_generation)) = proof else {
        return Ok(None);
    };
    let mut actual = Vec::with_capacity(parent.len());
    for index in 0..parent.len() {
        let entries = offline_directory_in(conn, instance, space, &parent[..index], None)?;
        let entry = entries
            .get(&parent[index])?
            .filter(Entry::is_directory)
            .ok_or_else(|| AccountError::new("offline tree destination parent unavailable"))?;
        actual.push(DirectoryIdentity::from_resource_id(entry.id())?);
    }
    if !equivalent_parents(
        conn,
        instance,
        space,
        path,
        &actual,
        &operation.destination_parents,
    )? {
        return Err(AccountError::new("offline tree destination parent changed"));
    }
    let snapshot = directory_snapshot_with_parent_in(conn, instance, space, path, Some(&id))?
        .ok_or_else(|| AccountError::new("offline tree copied observation unavailable"))?;
    if id != operation.entry.id()
        || Some(etag.as_str()) != operation.entry.etag()
        || generation != copied_generation
        || snapshot.remote_parent()? != (id, etag)
        || format!("{:x}", Sha256::digest(snapshot.json()?.as_bytes())) != digest
    {
        return Err(AccountError::new("offline tree copied proof changed"));
    }
    Ok(Some(snapshot))
}

pub(crate) fn observed_parent_identities(
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<Vec<DirectoryIdentity>, AccountError> {
    let mut parents = Vec::with_capacity(path.len().saturating_sub(1));
    for index in 0..path.len().saturating_sub(1) {
        let parent = &path[..index];
        let mut entries = match directory_snapshot(instance, space, parent)? {
            Some(entries) => entries,
            None => crate::DirectorySnapshot::empty()?,
        };
        apply_staged_entries(instance, space, parent, &mut entries)?;
        let entry = entries
            .get(&path[index])?
            .filter(|entry| entry.is_directory())
            .ok_or_else(|| AccountError::new("parent directory identity is unavailable"))?;
        parents.push(DirectoryIdentity::from_resource_id(entry.id())?);
    }
    Ok(parents)
}

pub(crate) fn staged_version(
    instance: &str,
    space: &str,
    path: &[String],
    resource: &str,
) -> Result<Option<(FileVersion, String)>, AccountError> {
    let Some(id) = resource
        .strip_prefix("cirrus-staged:")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return Ok(None);
    };
    let conn = database()?;
    // Ordinary handles must identify the current live write, not merely an
    // unchanged historical row. Only explicitly detached retained rows bypass
    // head selection (unlink and replacement-rename keep their open handles).
    let file: Option<String> = conn.query_row("SELECT staged_file FROM operation_journal AS j WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND (id=(SELECT max(id) FROM operation_journal WHERE instance=?2 AND space=?3 AND path=?4 AND op_type='write' AND state!='resolved') OR (state='resolved' AND error_msg IN ('unlinked open file; staged copies retained','superseded by local rename; staged copy retained')))",
        params![id,instance,space,path_key(path)?], |row| row.get(0)).optional().map_err(|_| AccountError::new("cannot load staged version"))?;
    let Some(file) = file else {
        return Ok(None);
    };
    publication::ensure_clear(&conn, instance, space)?;
    let size = staged_size(&file)?;
    Ok(Some((
        FileVersion {
            instance: instance.to_owned(),
            space: space.to_owned(),
            path: path.to_vec(),
            id: resource.to_owned(),
            etag: format!("\"cirrus-staged-{file}\""),
            size,
            checksums: Vec::new(),
        },
        file,
    )))
}

pub(crate) fn has_unresolved(instance: &str, space: Option<&str>) -> Result<bool, AccountError> {
    database()?
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2) AND state NOT IN ('synced','resolved'))",
            params![instance, space],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect operation journal"))
}

pub(crate) fn journal(
    instance: &str,
    space: Option<&str>,
    before: Option<i64>,
) -> Result<JournalPage, AccountError> {
    const MAX_ENTRIES: usize = 50;
    const MAX_ENCODED_BYTES: usize = 128 * 1024;
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot inspect operation journal"))?;
    let (summary, unknown_states) = tx
        .query_row(
            "SELECT COUNT(*) FILTER (WHERE state='pending'), COUNT(*) FILTER (WHERE state='conflict'), COUNT(*) FILTER (WHERE state='uncertain'), COUNT(*) FILTER (WHERE state='synced'), COUNT(*) FILTER (WHERE state='resolved'), COUNT(*) FILTER (WHERE state NOT IN ('pending','conflict','uncertain','synced','resolved')) FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2)",
            params![instance, space],
            |row| Ok((JournalSummary {
                pending: row.get(0)?,
                conflict: row.get(1)?,
                uncertain_or_in_progress: row.get(2)?,
                synced: row.get(3)?,
                resolved: row.get(4)?,
            }, row.get::<_, u64>(5)?)),
        )
        .map_err(|_| AccountError::new("cannot summarize operation journal"))?;
    if unknown_states != 0 {
        return Err(AccountError::new("invalid operation journal state"));
    }
    let mut stmt = tx.prepare("SELECT path,state,staged_file,space,error_msg,op_type,id FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2) AND (?3 IS NULL OR id<?3) ORDER BY id DESC LIMIT 50")
        .map_err(|_| AccountError::new("cannot list operation journal"))?;
    let rows = stmt
        .query_map(params![instance, space, before], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(|_| AccountError::new("cannot list operation journal"))?;
    let mut entries: Vec<JournalEntry> = Vec::new();
    let mut encoded_bytes = 0usize;
    let mut next_before = None;
    for row in rows {
        let (path, state, staged, space, error, kind, id) =
            row.map_err(|_| AccountError::new("cannot list operation journal"))?;
        let state = match state.as_str() {
            "pending" => JournalState::Pending,
            "conflict" => JournalState::Conflict,
            "uncertain" => JournalState::UncertainOrInProgress,
            "synced" => JournalState::Synced,
            "resolved" => JournalState::Resolved,
            _ => return Err(AccountError::new("invalid operation journal state")),
        };
        let path: Vec<String> =
            serde_json::from_str(&path).map_err(|_| AccountError::new("invalid journal path"))?;
        let entry = JournalEntry {
            id,
            path: format!("/{}", path.join("/")),
            space,
            operation: kind,
            token: staged,
            state,
            detail: error,
        };
        let size = serde_json::to_vec(&entry)
            .map_err(|_| AccountError::new("cannot encode journal entry"))?
            .len()
            .saturating_add(1);
        if encoded_bytes.saturating_add(size) > MAX_ENCODED_BYTES {
            next_before = Some(
                entries
                    .last()
                    .ok_or_else(|| AccountError::new("journal entry exceeds response limit"))?
                    .id,
            );
            break;
        }
        encoded_bytes += size;
        entries.push(entry);
    }
    drop(stmt);
    if next_before.is_none() && entries.len() == MAX_ENTRIES {
        let last = entries
            .last()
            .ok_or_else(|| AccountError::new("cannot inspect journal cursor"))?
            .id;
        let older: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operation_journal WHERE instance=?1 AND (?2 IS NULL OR space=?2) AND id<?3)",
                params![instance, space, last],
                |row| row.get(0),
            )
            .map_err(|_| AccountError::new("cannot inspect journal cursor"))?;
        if older {
            next_before = Some(last);
        }
    }
    if next_before == Some(0) {
        return Err(AccountError::new(
            "journal pagination reached an invalid zero-ID boundary; state preserved",
        ));
    }
    tx.commit()
        .map_err(|_| AccountError::new("cannot finish reading operation journal"))?;
    Ok(JournalPage {
        summary,
        entries,
        next_before,
    })
}

fn path_key(path: &[String]) -> Result<String, AccountError> {
    serde_json::to_string(path).map_err(|_| AccountError::new("invalid offline path"))
}

struct RelocatedOperation {
    id: i64,
    token: String,
    state: String,
    old_path: Vec<String>,
    new_path: Vec<String>,
    old_parents: Vec<DirectoryIdentity>,
    new_parents: Vec<DirectoryIdentity>,
}

#[derive(Clone, Copy)]
struct RelocationContext<'a> {
    instance: &'a str,
    space: &'a str,
    source: &'a [String],
    destination: &'a [String],
    parents: crate::RenameParents<'a>,
    root: &'a DirectoryIdentity,
}

fn prepare_relocated_operation(
    conn: &Connection,
    context: RelocationContext<'_>,
    id: i64,
    state: &str,
    old_path: Vec<String>,
) -> Result<RelocatedOperation, AccountError> {
    let RelocationContext {
        instance,
        space,
        source,
        destination,
        parents,
        root,
    } = context;
    let crate::RenameParents {
        source: source_parents,
        destination: destination_parents,
    } = parents;
    let old_parents = load_operation_parents(conn, id, &old_path)?;
    // Local mkdir relocation reconstructs old coordinates in its parent pass
    // after paths have moved. Token identity belongs to the scoped row, while
    // the publication CAS below independently binds the expected old path.
    let token:String=conn.query_row("SELECT staged_file FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND state=?4",params![id,instance,space,state],|row|row.get(0))
        .map_err(|_|AccountError::new("directory operation changed"))?;
    if !old_path.starts_with(source) || source.is_empty() {
        return Err(AccountError::new("directory source parent changed"));
    }
    if !equivalent_parents(
        conn,
        instance,
        space,
        source,
        &old_parents[..source.len() - 1],
        source_parents,
    )? {
        return Err(AccountError::new("directory source parent changed"));
    }
    let mut new_path = destination.to_vec();
    new_path.extend_from_slice(&old_path[source.len()..]);
    if new_path.len() > 128 {
        return Err(AccountError::new("invalid Space path"));
    }
    let mut new_parents = destination_parents.to_vec();
    if old_path.len() > source.len() {
        let mut expected = source_parents.to_vec();
        expected.push(root.clone());
        if !equivalent_parents(
            conn,
            instance,
            space,
            &old_path[..source.len() + 1],
            &old_parents[..source.len()],
            &expected,
        )? {
            return Err(AccountError::new("directory identity changed"));
        }
        new_parents.push(root.clone());
        for (index, identity) in old_parents.iter().enumerate().skip(source.len()) {
            if let DirectoryIdentity::Pending(id) = identity {
                let confirmed: Option<String> = conn.query_row(
                    "SELECT error_msg FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='mkdir' AND state='synced'",
                    params![id,instance,space,path_key(&old_path[..=index])?], |row| row.get(0),
                ).optional().map_err(|_| AccountError::new("cannot inspect confirmed parent"))?;
                if let Some(message) = confirmed {
                    let remote = message
                        .strip_prefix("confirmed-directory:")
                        .filter(|id| crate::dav::valid_remote_id(id))
                        .ok_or_else(|| AccountError::new("invalid confirmed parent identity"))?;
                    new_parents.push(DirectoryIdentity::Remote(remote.to_owned()));
                    continue;
                }
            }
            new_parents.push(identity.clone());
        }
    }
    encode_parents(&new_path, &new_parents)?;
    Ok(RelocatedOperation {
        id,
        token,
        state: state.to_owned(),
        old_path,
        new_path,
        old_parents,
        new_parents,
    })
}

fn apply_relocated_operations(
    conn: &Connection,
    instance: &str,
    space: &str,
    changes: &[RelocatedOperation],
) -> Result<(), AccountError> {
    for change in changes {
        let count = conn.execute("UPDATE operation_journal SET path=?1,updated_at=strftime('%s','now') WHERE id=?2 AND instance=?3 AND space=?4 AND path=?5 AND state=?6 AND staged_file=?7", params![path_key(&change.new_path)?, change.id, instance, space, path_key(&change.old_path)?,change.state,change.token])
            .map_err(|error| sqlite_storage_error(error, "cannot relocate directory operation"))?;
        if count != 1 {
            return Err(AccountError::new("directory operation changed"));
        }
    }
    for change in changes {
        validate_parent_dependencies(conn, instance, space, &change.new_path, &change.new_parents)?;
        let count = conn.execute("UPDATE operation_parents SET parents=?1 WHERE operation_id=?2 AND parents=?3 AND destination_parents IS NULL", params![encode_parents(&change.new_path,&change.new_parents)?,change.id,encode_parents(&change.old_path,&change.old_parents)?])
            .map_err(|error| sqlite_storage_error(error, "cannot relocate parent identities"))?;
        if count != 1 {
            return Err(AccountError::new("directory parent identity changed"));
        }
    }
    Ok(())
}

fn encode_parents(path: &[String], parents: &[DirectoryIdentity]) -> Result<String, AccountError> {
    if path.is_empty()
        || parents.len() != path.len() - 1
        || parents.iter().any(|parent| match parent {
            DirectoryIdentity::Remote(id) => !crate::dav::valid_remote_id(id),
            DirectoryIdentity::Pending(id) => *id <= 0,
        })
    {
        return Err(AccountError::new("invalid parent identity chain"));
    }
    serde_json::to_string(parents).map_err(|_| AccountError::new("invalid parent identity chain"))
}

fn equivalent_parents(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    left: &[DirectoryIdentity],
    right: &[DirectoryIdentity],
) -> Result<bool, AccountError> {
    encode_parents(path, left)?;
    encode_parents(path, right)?;
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        if left == right {
            continue;
        }
        let (pending, remote) = match (left, right) {
            (DirectoryIdentity::Pending(id), DirectoryIdentity::Remote(remote))
            | (DirectoryIdentity::Remote(remote), DirectoryIdentity::Pending(id)) => (id, remote),
            _ => return Ok(false),
        };
        let matches: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='mkdir' AND state='synced' AND error_msg=?5)",
            params![pending,instance,space,path_key(&path[..=index])?,format!("confirmed-directory:{remote}")], |row| row.get(0),
        ).map_err(|_| AccountError::new("cannot inspect confirmed parent"))?;
        if !matches {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_parent_dependencies(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    parents: &[DirectoryIdentity],
) -> Result<(), AccountError> {
    encode_parents(path, parents)?;
    for (index, parent) in parents.iter().enumerate() {
        if let DirectoryIdentity::Pending(parent_id) = parent {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM operation_journal WHERE id=?1 AND instance=?2 AND space=?3 AND path=?4 AND op_type='mkdir' AND state IN ('pending','conflict','uncertain','synced'))",
                params![parent_id,instance,space,path_key(&path[..=index])?], |row| row.get(0),
            ).map_err(|_| AccountError::new("cannot inspect parent dependency"))?;
            if !exists {
                return Err(AccountError::new("local parent directory changed"));
            }
        }
    }
    Ok(())
}

fn save_operation_parents(
    conn: &Connection,
    id: i64,
    path: &[String],
    parents: &[DirectoryIdentity],
    destination: Option<(&[String], &[DirectoryIdentity])>,
) -> Result<(), AccountError> {
    let (instance, space): (String, String) = conn
        .query_row(
            "SELECT instance,space FROM operation_journal WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| AccountError::new("operation is unavailable"))?;
    validate_parent_dependencies(conn, &instance, &space, path, parents)?;
    if let Some((path, parents)) = destination {
        validate_parent_dependencies(conn, &instance, &space, path, parents)?;
    }
    let parents = encode_parents(path, parents)?;
    let destination = destination
        .map(|(path, parents)| encode_parents(path, parents))
        .transpose()?;
    conn.execute(
        "INSERT INTO operation_parents(operation_id,parents,destination_parents) VALUES (?1,?2,?3)",
        params![id, parents, destination],
    )
    .map_err(|error| sqlite_storage_error(error, "cannot journal parent identities"))?;
    Ok(())
}

fn load_operation_parents(
    conn: &Connection,
    id: i64,
    path: &[String],
) -> Result<Vec<DirectoryIdentity>, AccountError> {
    let encoded: String = conn
        .query_row(
            "SELECT parents FROM operation_parents WHERE operation_id=?1",
            [id],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("operation parent identities are unavailable"))?;
    let parents: Vec<DirectoryIdentity> = serde_json::from_str(&encoded)
        .map_err(|_| AccountError::new("invalid parent identity chain"))?;
    encode_parents(path, &parents)?;
    Ok(parents)
}

fn load_destination_parents(
    conn: &Connection,
    id: i64,
    path: &[String],
) -> Result<Vec<DirectoryIdentity>, AccountError> {
    let encoded: String = conn
        .query_row(
            "SELECT destination_parents FROM operation_parents WHERE operation_id=?1",
            [id],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("destination parent identities are unavailable"))?;
    let parents: Vec<DirectoryIdentity> = serde_json::from_str(&encoded)
        .map_err(|_| AccountError::new("invalid parent identity chain"))?;
    encode_parents(path, &parents)?;
    Ok(parents)
}

pub(crate) const PIN_SNAPSHOT_INTERRUPTED: &str =
    "offline metadata changed during pinning; a local update interrupted the snapshot, retry";

fn pin_local_state(conn: &Connection) -> Result<[u8; 32], AccountError> {
    let mut hash = Sha256::new();
    for sql in [
        "SELECT json_array(id,instance,space,path,op_type,base_file_id,base_etag,staged_file,state,error_msg,updated_at,confirmed_file_id,confirmed_etag) FROM operation_journal ORDER BY id",
        "SELECT json_array(operation_id,destination,source_entry,target_id,target_etag) FROM directory_moves ORDER BY operation_id",
        "SELECT json_array(instance,space,root,is_dir,directories,manifest) FROM pins ORDER BY instance,space,root",
    ] {
        hash.update(sql.as_bytes());
        let mut statement = conn
            .prepare(sql)
            .map_err(|_| AccountError::new("cannot inspect local pin state"))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| AccountError::new("cannot inspect local pin state"))?;
        for row in rows {
            let value = row.map_err(|_| AccountError::new("invalid local pin state"))?;
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
    }
    Ok(hash.finalize().into())
}

pub(crate) fn current_pin_local_state() -> Result<[u8; 32], AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot inspect local pin state"))?;
    let state = pin_local_state(&tx)?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot inspect local pin state"))?;
    Ok(state)
}

pub(crate) struct SnapshotObservation {
    conn: Connection,
    data_version: i64,
}

pub(crate) fn begin_snapshot() -> Result<SnapshotObservation, AccountError> {
    let conn = database()?;
    let data_version = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline metadata"))?;
    Ok(SnapshotObservation { conn, data_version })
}

// A descendant can retain eligibility only through a directory child whose
// identity is established by both the old and new parent listings, or by an
// exact unresolved tree-MOVE destination copy with no conflicting fresh ID.
// Direct nested CLI observations alone establish no such mapping.
// Preserve an empty unresolved mkdir record only at the observed parent's
// direct, remotely absent child. A fresh occupied name or changed ancestor
// must revoke it too, so resolution cannot relabel local emptiness as remote
// evidence. Offline traversal still uses the mkdir's journal identity.
// Select paths, not decoded listings, and scope every row to instance/Space.
const UNBOUND_SNAPSHOT_DESCENDANTS: &str = "SELECT child.path FROM snapshots child
    WHERE child.instance=?1 AND child.space=?2
      AND json_array_length(child.path)>?6
      AND (?3='[]' OR substr(child.path,1,length(?5))=?5)
      AND NOT (child.entries='[]' AND json_array_length(child.path)=?6+1
        AND NOT EXISTS (SELECT 1 FROM json_each(?4) fresh
          WHERE json_extract(fresh.value,'$.name')=json_extract(child.path,?7))
        AND EXISTS (
        SELECT 1 FROM operation_journal local
        WHERE local.instance=child.instance AND local.space=child.space
          AND local.path=child.path AND local.op_type='mkdir'
          AND local.state IN ('pending','conflict','uncertain')))
      AND NOT EXISTS (
        SELECT 1 FROM snapshots saved,json_each(saved.entries) old
        JOIN json_each(?4) fresh ON json_extract(fresh.value,'$.name')=json_extract(old.value,'$.name')
        WHERE saved.instance=?1 AND saved.space=?2 AND saved.path=?3
          AND json_extract(old.value,'$.name')=json_extract(child.path,?7)
          AND json_extract(old.value,'$.directory')=1
          AND json_extract(fresh.value,'$.directory')=1
          AND json_extract(old.value,'$.id') IS json_extract(fresh.value,'$.id'))
      AND NOT EXISTS (
        SELECT 1 FROM operation_journal j JOIN directory_moves m ON m.operation_id=j.id
        WHERE j.instance=?1 AND j.space=?2 AND j.op_type='move-tree'
          AND j.state IN ('pending','conflict','uncertain')
          AND json_array_length(m.destination)=?6+1
          AND (?3='[]' OR substr(m.destination,1,length(?5))=?5)
          AND json_extract(m.destination,?7)=json_extract(child.path,?7)
          AND json_extract(m.source_entry,'$.directory')=1
          AND json_type(m.source_entry,'$.id')='text'
          AND j.base_file_id IS json_extract(m.source_entry,'$.id')
          AND NOT EXISTS (SELECT 1 FROM json_each(?4) fresh
            WHERE json_extract(fresh.value,'$.name')=json_extract(m.destination,?7)
              AND (json_extract(fresh.value,'$.directory') IS NOT 1
                OR json_extract(fresh.value,'$.id') IS NOT json_extract(m.source_entry,'$.id'))))";

fn write_snapshot_json(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    json: &str,
    self_version: &(String, String),
) -> Result<(), AccountError> {
    // Complete schema-14 observations retain their own ID/ETag and owner.
    // Revoke eligibility in this same transaction if the prior parent mapping
    // is absent, or a directory disappears or changes type/identity. Publishing
    // a first parent must not relabel previously saved A children as B's.
    // Delete metadata snapshots only: pins, journal roots and recovery survive.
    let key = path_key(path)?;
    let prefix = format!("{},", key.trim_end_matches(']'));
    let component = format!("$[{}]", path.len());
    conn.execute(
        &format!("DELETE FROM snapshots WHERE instance=?1 AND space=?2 AND path IN ({UNBOUND_SNAPSHOT_DESCENDANTS})"),
        params![instance,space,key,json,prefix,path.len(),component],
    ).map_err(|error| sqlite_storage_error(error,"cannot invalidate unbound descendant snapshots"))?;
    // Even an unchanged observation must advance the durable fence: an older
    // response could otherwise replace it after this observation completes.
    let count = conn.execute("INSERT INTO snapshots SELECT ?1,?2,?3,?4,strftime('%s','now'),?5,?6,NULL,issuer,subject FROM account_identities WHERE instance=?1 ON CONFLICT(instance,space,path) DO UPDATE SET entries=excluded.entries,updated=max(excluded.updated,snapshots.updated+1),self_id=excluded.self_id,self_etag=excluded.self_etag,local_operation=NULL,issuer=excluded.issuer,subject=excluded.subject WHERE snapshots.updated < 9223372036854775807",
        params![instance, space, path_key(path)?, json,self_version.0,self_version.1]).map_err(|error| sqlite_storage_error(error, "cannot save offline metadata"))?;
    if count != 1 {
        return Err(AccountError::new("offline metadata generation exhausted"));
    }
    Ok(())
}

fn write_local_snapshot(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    operation: i64,
) -> Result<(), AccountError> {
    let count = conn.execute("INSERT INTO snapshots SELECT ?1,?2,?3,'[]',strftime('%s','now'),NULL,NULL,?4,a.issuer,a.subject FROM account_identities a JOIN operation_journal j ON j.instance=a.instance WHERE a.instance=?1 AND j.space=?2 AND j.path=?3 AND j.id=?4 AND j.op_type='mkdir' AND j.state='pending' ON CONFLICT(instance,space,path) DO UPDATE SET entries='[]',updated=max(excluded.updated,snapshots.updated+1),self_id=NULL,self_etag=NULL,local_operation=excluded.local_operation,issuer=excluded.issuer,subject=excluded.subject WHERE snapshots.updated < 9223372036854775807",params![instance,space,path_key(path)?,operation])
        .map_err(|error| sqlite_storage_error(error,"cannot save local directory observation"))?;
    if count != 1 {
        return Err(AccountError::new("local directory observation changed"));
    }
    Ok(())
}

pub(crate) fn save_directory_snapshot(
    observation: SnapshotObservation,
    instance: &str,
    space: &str,
    path: &[String],
    entries: &crate::DirectorySnapshot,
) -> Result<bool, AccountError> {
    save_snapshot_json(
        observation,
        instance,
        space,
        path,
        &entries.json()?,
        &entries.remote_parent()?,
    )
}

/// A skipped copy is safe only if no unaccounted directory mapping needs revocation.
/// Compare against current durable metadata, not a possibly stale live listing.
fn removed_directory_copy_compatible(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    fresh: &crate::DirectorySnapshot,
) -> Result<bool, AccountError> {
    let Some(saved) = directory_snapshot_in(conn, instance, space, path)? else {
        return Ok(false);
    };
    let permits = |entry: &Entry| -> Result<bool, AccountError> {
        if !entry.is_directory() || fresh.get(entry.name())?.is_some() {
            return Ok(false);
        }
        let mut target = path.to_vec();
        target.push(entry.name().to_owned());
        // A successful receipt is proof of the completed DELETE, never a
        // pending/uncertain request alone. Synced rows retain the same scoped
        // projection after receipt retirement. No replacement mapping is allowed.
        let mut stmt = conn.prepare("SELECT j.id,j.base_file_id,j.base_etag FROM operation_journal j LEFT JOIN mutation_receipts r ON r.operation_id=j.id AND r.kind='namespace' JOIN operation_parents p ON p.operation_id=j.id WHERE j.instance=?1 AND j.space=?2 AND j.path=?3 AND j.op_type IN ('rmdir','move-dir-source') AND (j.state='synced' OR (j.state='uncertain' AND json_extract(r.snapshot,'$.id')=j.id AND json_extract(r.snapshot,'$.space')=j.space AND json_extract(r.snapshot,'$.path')=j.path AND json_extract(r.snapshot,'$.kind')=j.op_type AND json_extract(r.snapshot,'$.base_id')=j.base_file_id AND json_extract(r.snapshot,'$.base_etag')=j.base_etag AND json_extract(r.snapshot,'$.token')=j.staged_file AND json_extract(r.snapshot,'$.parents')=p.parents)) ORDER BY j.id")
            .map_err(|_|AccountError::new("cannot inspect directory removal receipt"))?;
        let rows = stmt
            .query_map(params![instance, space, path_key(&target)?], |row| {
                Ok(ConfirmedRemoval {
                    id: row.get(0)?,
                    path: target.clone(),
                    base_id: row.get(1)?,
                    base_etag: row.get(2)?,
                    reset: true,
                    directory: true,
                })
            })
            .map_err(|_| AccountError::new("cannot inspect directory removal receipt"))?;
        for row in rows {
            if confirmed_removal_matches(
                conn,
                (instance, space),
                &row.map_err(|_| AccountError::new("invalid directory removal receipt"))?,
                &saved,
            )? {
                return Ok(true);
            }
        }
        Ok(false)
    };
    let mut removed = false;
    let mut after = 0;
    loop {
        let page = saved.page(after)?;
        if page.is_empty() {
            break;
        }
        for (cookie, entry) in page {
            after = cookie;
            if !entry.is_directory() {
                continue;
            }
            if fresh
                .get(entry.name())?
                .is_some_and(|current| current.is_directory() && current.id() == entry.id())
            {
                continue;
            }
            if !permits(&entry)? {
                return Ok(false);
            }
            removed = true;
        }
    }
    if !removed {
        return Ok(false);
    }
    let key = path_key(path)?;
    let prefix = format!("{},", key.trim_end_matches(']'));
    let component = format!("$[{}]", path.len());
    let mut stmt = conn
        .prepare(UNBOUND_SNAPSHOT_DESCENDANTS)
        .map_err(|_| AccountError::new("cannot inspect removed directory descendants"))?;
    let json = fresh.json()?;
    let rows = stmt
        .query_map(
            params![instance, space, key, json, prefix, path.len(), component],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| AccountError::new("cannot inspect removed directory descendants"))?;
    for row in rows {
        let revoked: Vec<String> = serde_json::from_str(
            &row.map_err(|_| AccountError::new("invalid removed directory descendant"))?,
        )
        .map_err(|_| AccountError::new("invalid removed directory descendant"))?;
        let Some(name) = revoked.get(path.len()) else {
            return Ok(false);
        };
        let Some(entry) = saved.get(name)? else {
            return Ok(false);
        };
        if !permits(&entry)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn directory_copy_compatible(
    instance: &str,
    space: &str,
    path: &[String],
    entries: &crate::DirectorySnapshot,
    issuer: &str,
    subject: &str,
) -> Result<bool, AccountError> {
    let json = entries.json()?;
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot inspect optional directory publication"))?;
    let identity: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM account_identities WHERE instance=?1 AND issuer=?2 AND subject=?3)",params![instance,issuer,subject],|row|row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline account identity"))?;
    if let Some(saved) = directory_snapshot_in(&tx, instance, space, path)?
        && !entries.matches_parent(&saved.remote_parent()?.0)?
    {
        return Ok(false);
    }
    if identity && removed_directory_copy_compatible(&tx, instance, space, path, entries)? {
        tx.commit()
            .map_err(|_| AccountError::new("cannot finish removed directory comparison"))?;
        return Ok(true);
    }
    let key = path_key(path)?;
    let prefix = format!("{},", key.trim_end_matches(']'));
    let component = format!("$[{}]", path.len());
    // A local mkdir's empty direct row with NO durable parent name mapping
    // is already ineligible as remote content. Skipping its optional copy
    // cannot relabel it when a successful receipt is confirmed under peer
    // State contention. Any mapped row or other descendant still requires
    // publication/revocation; the ordinary writer deletes the local row when
    // the remote name first appears, even if its journal has since resolved.
    let descendants_known: bool = tx
        .query_row(
            &format!("SELECT NOT EXISTS(
                SELECT 1 FROM ({UNBOUND_SNAPSHOT_DESCENDANTS}) revoked
                JOIN snapshots local_copy ON local_copy.instance=?1 AND local_copy.space=?2 AND local_copy.path=revoked.path
                WHERE NOT (local_copy.entries='[]' AND json_array_length(local_copy.path)=?6+1
                  AND EXISTS (SELECT 1 FROM operation_journal local WHERE local.instance=?1 AND local.space=?2 AND local.path=local_copy.path AND local.op_type='mkdir' AND local.state IN ('pending','conflict','uncertain'))
                  AND NOT EXISTS (SELECT 1 FROM snapshots saved,json_each(saved.entries) old WHERE saved.instance=?1 AND saved.space=?2 AND saved.path=?3 AND json_extract(old.value,'$.name')=json_extract(local_copy.path,?7))))"),
            params![instance, space, key, json, prefix, path.len(), component],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot compare descendant snapshot eligibility"))?;
    // A first observation is safe only if the same transaction proves there
    // are no durable descendant copies to misbind (including an empty Space).
    let compatible: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM snapshots saved WHERE saved.instance=?1 AND saved.space=?2 AND saved.path=?3 AND json_type(saved.entries)='array' AND NOT EXISTS(SELECT 1 FROM json_each(saved.entries) old LEFT JOIN json_each(?4) fresh ON json_extract(fresh.value,'$.name')=json_extract(old.value,'$.name') WHERE json_extract(old.value,'$.directory')=1 AND (fresh.value IS NULL OR json_extract(fresh.value,'$.directory') IS NOT 1 OR json_extract(fresh.value,'$.id') IS NOT json_extract(old.value,'$.id')))) OR (NOT EXISTS(SELECT 1 FROM snapshots WHERE instance=?1 AND space=?2 AND path=?3) AND NOT EXISTS(SELECT 1 FROM snapshots WHERE instance=?1 AND space=?2 AND (?3='[]' OR substr(path,1,length(?5))=?5)))",
        params![instance,space,key,json,prefix],|row|row.get(0),
    ).map_err(|_| AccountError::new("cannot compare optional directory identities"))?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot finish optional directory comparison"))?;
    Ok(identity && compatible && descendants_known)
}

fn snapshot_reservation(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    json: &str,
    self_version: &(String, String),
) -> Result<Option<crate::storage::sql_reservation::SqlReservation>, AccountError> {
    use crate::storage::sql_reservation::{SqlReservation, Store};
    #[cfg(feature = "fault-injection")]
    if std::env::var_os("CIRRUS_TEST_BLOCKER_TRACE").is_some() {
        eprintln!(
            "cirrus lab snapshot admission: pid={} thread={:?} path={path:?} enabled={}",
            std::process::id(),
            std::thread::current().id(),
            crate::storage::limits::view()?.limits.is_some()
        );
    }
    let owner: (String, String) = conn
        .query_row(
            "SELECT issuer,subject FROM account_identities WHERE instance=?1",
            [instance],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| AccountError::new("snapshot account identity unavailable"))?;
    let metadata = (instance.len() as u64)
        .checked_add(space.len() as u64)
        .and_then(|bytes| bytes.checked_add(path_key(path).ok()?.len() as u64))
        .and_then(|bytes| {
            bytes.checked_add(
                (self_version.0.len() + self_version.1.len() + owner.0.len() + owner.1.len() + 64)
                    as u64,
            )
        })
        .ok_or_else(|| AccountError::new("snapshot storage estimate overflow"))?;
    // Complete bounded JSON already exists; no lease spans DAV, and this cap
    // belongs only to the publication connection, never recovery connections.
    let reservation =
        SqlReservation::begin(Store::State, Some(conn), json.len() as u64, metadata, false).inspect_err(|error| {
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_BLOCKER_TRACE").is_some() {
                eprintln!("cirrus lab snapshot refusal: path={path:?} storage_busy={} retryable_read={} unauthorized={}", error.storage_busy, error.retryable_read, error.unauthorized);
            }
            let _ = error;
        })?;
    if let Some(reservation) = &reservation {
        reservation.bound_pages(conn)?;
        #[cfg(feature = "fault-injection")]
        crate::wait_test_window("CIRRUS_TEST_SNAPSHOT_RESERVATION_WINDOW")?;
    }
    Ok(reservation)
}

fn save_snapshot_json(
    observation: SnapshotObservation,
    instance: &str,
    space: &str,
    path: &[String],
    json: &str,
    self_version: &(String, String),
) -> Result<bool, AccountError> {
    let reservation =
        snapshot_reservation(&observation.conn, instance, space, path, json, self_version)?;
    // Move after the guard declaration: SQLite closes/rolls back before the
    // durable allowance is released, including all early-return paths.
    let mut observation = observation;
    let tx = observation
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot start offline transaction"))?;
    let current: i64 = tx
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline metadata"))?;
    if current != observation.data_version {
        return Ok(false);
    }
    write_snapshot_json(&tx, instance, space, path, json, self_version)?;
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit offline metadata"))?;
    Ok(true)
}

pub(crate) fn directory_snapshot(
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<Option<crate::DirectorySnapshot>, AccountError> {
    let mut database = database()?;
    let tx = database
        .transaction()
        .map_err(|_| AccountError::new("cannot load directory snapshot"))?;
    let snapshot = directory_snapshot_in(&tx, instance, space, path)?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot finish directory snapshot"))?;
    Ok(snapshot)
}

fn directory_snapshot_in(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
) -> Result<Option<crate::DirectorySnapshot>, AccountError> {
    directory_snapshot_with_parent_in(conn, instance, space, path, None)
}

fn directory_snapshot_with_parent_in(
    conn: &Connection,
    instance: &str,
    space: &str,
    path: &[String],
    copied_move_parent: Option<&str>,
) -> Result<Option<crate::DirectorySnapshot>, AccountError> {
    let key = path_key(path)?;
    let kind: Option<String> = conn
        .query_row(
            "SELECT json_type(entries) FROM snapshots WHERE instance=?1 AND space=?2 AND path=?3",
            params![instance, space, key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| AccountError::new("cannot load directory snapshot"))?;
    match kind.as_deref() {
        None => return Ok(None),
        Some("array") => (),
        _ => return Err(AccountError::new("invalid offline metadata")),
    }
    let mut snapshot = crate::DirectorySnapshot::empty()?;
    let proof: Option<(String,String)> = conn.query_row("SELECT s.self_id,s.self_etag FROM snapshots s JOIN account_identities a ON a.instance=s.instance AND a.issuer=s.issuer AND a.subject=s.subject WHERE s.instance=?1 AND s.space=?2 AND s.path=?3 AND s.local_operation IS NULL",params![instance,space,key], |row|Ok((row.get(0)?,row.get(1)?)))
        .optional().map_err(|_| AccountError::new("invalid saved directory observation"))?;
    let Some((self_id, self_etag)) = proof else {
        return Ok(None);
    };
    snapshot.set_remote_parent(&self_id, &self_etag)?;
    // Never infer a self version from a newer parent. The retained observation
    // proves its own version; path eligibility additionally needs the same
    // directory identity in this transaction's parent/MOVE namespace.
    if let Some(id) = copied_move_parent {
        if self_id != id {
            return Err(AccountError::new("copied directory self identity changed"));
        }
    } else if let Some((name, parent)) = path.split_last() {
        let id: Option<String> = conn.query_row(
            "SELECT json_extract(value,'$.id') FROM snapshots,json_each(snapshots.entries) WHERE snapshots.instance=?1 AND snapshots.space=?2 AND snapshots.path=?3 AND json_extract(value,'$.name')=?4 AND json_extract(value,'$.directory')=1",
            params![instance,space,path_key(parent)?,name],|row|row.get(0),
        ).optional().map_err(|_| AccountError::new("cannot inspect saved directory parent"))?;
        let Some(id) = id else {
            // Direct nested observations may precede their parent. Without a
            // durable directory mapping they are not eligible offline copies.
            return Ok(None);
        };
        if self_id != id {
            return Err(AccountError::new("saved directory self identity changed"));
        }
    }
    let mut stmt = conn.prepare("SELECT json_each.value FROM snapshots,json_each(snapshots.entries) WHERE snapshots.instance=?1 AND snapshots.space=?2 AND snapshots.path=?3").map_err(|_| AccountError::new("cannot load directory snapshot"))?;
    let rows = stmt
        .query_map(params![instance, space, key], |row| row.get::<_, String>(0))
        .map_err(|_| AccountError::new("cannot load directory snapshot"))?;
    for row in rows {
        let entry: Entry =
            serde_json::from_str(&row.map_err(|_| AccountError::new("invalid offline metadata"))?)
                .map_err(|_| AccountError::new("invalid offline metadata"))?;
        if !crate::dav::valid_remote_id(entry.id()) {
            return Err(AccountError::new("invalid offline metadata"));
        }
        snapshot.insert(&entry)?;
    }
    drop(stmt);
    Ok(Some(snapshot))
}

fn check_pin_operations(
    conn: &Connection,
    instance: &str,
    space: &str,
    root: &[String],
) -> Result<(), AccountError> {
    let mut stmt = conn.prepare("SELECT j.path,m.destination FROM operation_journal j LEFT JOIN directory_moves m ON m.operation_id=j.id WHERE j.instance=?1 AND j.space=?2 AND j.state IN ('pending','conflict','uncertain')").map_err(|_| AccountError::new("cannot inspect pending pin operations"))?;
    let rows = stmt
        .query_map(params![instance, space], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(|_| AccountError::new("cannot inspect pending pin operations"))?;
    for row in rows {
        let (path, destination) =
            row.map_err(|_| AccountError::new("invalid pending pin operation"))?;
        for encoded in std::iter::once(path).chain(destination) {
            let path: Vec<String> = serde_json::from_str(&encoded)
                .map_err(|_| AccountError::new("invalid pending path"))?;
            if path.starts_with(root) || root.starts_with(&path) {
                return Err(AccountError::new("path has unresolved operations"));
            }
        }
    }
    Ok(())
}

pub(crate) fn check_pin_path(
    instance: &str,
    space: &str,
    root: &[String],
) -> Result<(), AccountError> {
    check_pin_operations(&database()?, instance, space, root)
}

pub(crate) struct PinSnapshot {
    conn: Connection,
    data_version: i64,
}

pub(crate) fn begin_pin_snapshot(
    instance: &str,
    space: &str,
    root: &[String],
) -> Result<PinSnapshot, AccountError> {
    let conn = database()?;
    check_pin_operations(&conn, instance, space, root)?;
    let data_version = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline metadata"))?;
    Ok(PinSnapshot { conn, data_version })
}

pub(crate) fn save_pin_snapshot(
    snapshot: PinSnapshot,
    instance: &str,
    space: &str,
    root: &[String],
    path: &[String],
    entries: &crate::DirectorySnapshot,
) -> Result<(), AccountError> {
    #[cfg(feature = "fault-injection")]
    if let Some(marker) = std::env::var_os("CIRRUS_TEST_PIN_SNAPSHOT_WINDOW") {
        let marker = Path::new(&marker);
        if marker.is_file() {
            eprintln!("cirrus lab pin snapshot window");
            for _ in 0..1500 {
                if !marker.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if marker.exists() {
                return Err(AccountError::new("pin snapshot test window timed out"));
            }
        }
    }
    let json = entries.json()?;
    let reservation = snapshot_reservation(
        &snapshot.conn,
        instance,
        space,
        path,
        &json,
        &entries.remote_parent()?,
    )?;
    let mut snapshot = snapshot;
    let tx = snapshot
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot start offline transaction"))?;
    let current: i64 = tx
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline metadata"))?;
    if current != snapshot.data_version {
        return Err(AccountError::new(PIN_SNAPSHOT_INTERRUPTED));
    }
    check_pin_operations(&tx, instance, space, root)?;
    write_snapshot_json(&tx, instance, space, path, &json, &entries.remote_parent()?)?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_PIN_PEER_SNAPSHOT_COMMIT_WINDOW")?;
    if let Some(reservation) = &reservation {
        reservation.validate(&tx)?;
    } else if crate::storage::limits::view()?.limits.is_some() {
        return Err(AccountError::new(crate::storage::limits::PRESSURE));
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit offline metadata"))
}

enum PinScratch {
    Anonymous(std::sync::Arc<std::fs::File>),
    Reserved(crate::storage::sql_reservation::SqlReservation),
}

impl PinScratch {
    fn file(&self) -> Result<&std::fs::File, AccountError> {
        match self {
            Self::Anonymous(file) => Ok(file),
            Self::Reserved(reservation) => reservation.scratch(),
        }
    }
    fn validate(&self, conn: &Connection) -> Result<(), AccountError> {
        match self {
            Self::Anonymous(_) if crate::storage::limits::view()?.limits.is_none() => Ok(()),
            Self::Anonymous(_) => Err(AccountError::new(crate::storage::limits::PRESSURE)),
            Self::Reserved(reservation) => reservation.validate(conn),
        }
    }
}

fn pin_scratch(conn: &Connection, bytes: u64, metadata: u64) -> Result<PinScratch, AccountError> {
    if let Some(reservation) = crate::storage::sql_reservation::SqlReservation::begin(
        crate::storage::sql_reservation::Store::State,
        Some(conn),
        bytes,
        metadata,
        true,
    )? {
        return Ok(PinScratch::Reserved(reservation));
    }
    let dir = ownership::staging_dir()?;
    let name = namespace_token()?;
    let fd = fs::openat2(
        &dir,
        name.as_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOSPC {
            AccountError::new("local storage capacity exhausted")
        } else {
            AccountError::new("cannot create pin scratch file")
        }
    })?;
    fs::unlinkat(&dir, name.as_str(), AtFlags::empty()).map_err(|_| {
        AccountError::new("cannot unlink pin scratch file; inspect staging directory")
    })?;
    // Persist the unlink before writing so a crash cannot resurrect pin bytes
    // as an apparently dirty staged file.
    fs::fsync(&dir).map_err(|error| {
        if error == rustix::io::Errno::NOSPC {
            AccountError::new("local storage capacity exhausted")
        } else {
            AccountError::new("cannot persist pin scratch removal")
        }
    })?;
    Ok(PinScratch::Anonymous(crate::storage::track(
        std::fs::File::from(fd),
        crate::storage::AnonymousKind::Pin,
    )))
}

pub(crate) fn replace_pin<F, V, T>(
    account: (&str, &str),
    root: &[String],
    tree: &PinTree,
    retry_state: Option<&[u8; 32]>,
    mut fetch: F,
    mut verify: V,
    verify_tree: T,
) -> Result<(), AccountError>
where
    F: FnMut(&FileVersion, u64, u32) -> Result<Vec<u8>, AccountError>,
    V: FnMut(&FileVersion) -> Result<(), AccountError>,
    T: FnOnce() -> Result<(), AccountError>,
{
    let (instance, space) = account;
    let total_bytes = tree
        .files
        .iter()
        .try_fold(0u64, |sum, file| sum.checked_add(file.size))
        .filter(|size| *size <= MAX_PIN_BYTES)
        .ok_or_else(|| AccountError::new("pin exceeds the 1 GiB limit"))?;
    // Declare before the connection so the allowance outlives SQLite close
    // (including rollback/checkpoint work on error paths).
    let scratch_file;
    let mut conn = database()?;
    // Keep this connection without a transaction so other writers can proceed;
    // its data version fences the later publication against intervening commits.
    let data_version: i64 = conn
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline metadata"))?;
    let root_path = root;
    check_pin_operations(&conn, instance, space, root_path)?;
    // Key/version JSON is disk row input too; do not estimate BLOB payload alone.
    let metadata = if crate::storage::limits::view()?.limits.is_some() {
        let mut bytes = path_key(root_path)?.len() as u64;
        for version in &tree.files {
            let chunks = version.size.div_ceil(CHUNK).max(1);
            let row = serde_json::to_vec(version)
                .map_err(|_| AccountError::new("invalid pin version"))?
                .len() as u64;
            bytes = bytes
                .checked_add(
                    row.checked_add(instance.len() as u64)
                        .and_then(|row| row.checked_add(space.len() as u64))
                        .and_then(|row| row.checked_add(path_key(&version.path).ok()?.len() as u64))
                        .and_then(|row| row.checked_mul(chunks + 2))
                        .ok_or_else(|| AccountError::new("pin storage estimate overflow"))?,
                )
                .ok_or_else(|| AccountError::new("pin storage estimate overflow"))?;
        }
        bytes
            .checked_add(
                serde_json::to_vec(&tree.directories)
                    .map_err(|_| AccountError::new("invalid pin directories"))?
                    .len() as u64,
            )
            .ok_or_else(|| AccountError::new("pin storage estimate overflow"))?
    } else {
        0
    };
    scratch_file = pin_scratch(&conn, total_bytes, metadata)?;
    if let PinScratch::Reserved(reservation) = &scratch_file {
        reservation.bound_pages(&conn)?;
    }
    let mut scratch = scratch_file.file()?;
    let mut chunk_digests = Vec::new();
    for version in &tree.files {
        let mut sha256 = Sha256::new();
        let mut sha1 = Sha1::new();
        let mut md5 = Md5::new();
        let mut offset = 0u64;
        while offset < version.size {
            let length = (version.size - offset).min(CHUNK) as u32;
            #[cfg(feature = "fault-injection")]
            crate::wait_test_window("CIRRUS_TEST_PIN_DOWNLOAD_WINDOW")?;
            let bytes = fetch(version, offset, length)?;
            if bytes.len() != length as usize {
                return Err(AccountError::new("invalid pinned chunk"));
            }
            sha256.update(&bytes);
            sha1.update(&bytes);
            md5.update(&bytes);
            chunk_digests.push(Sha256::digest(&bytes));
            scratch.write_all(&bytes).map_err(|error| {
                if error.kind() == std::io::ErrorKind::StorageFull {
                    AccountError::new("local storage capacity exhausted")
                } else {
                    AccountError::new("cannot write pin scratch file")
                }
            })?;
            offset += u64::from(length);
        }
        let digests = [
            ("SHA256", format!("{:x}", sha256.finalize())),
            ("SHA1", format!("{:x}", sha1.finalize())),
            ("MD5", format!("{:x}", md5.finalize())),
        ];
        for checksum in version
            .checksums
            .iter()
            .flat_map(|value| value.split_ascii_whitespace())
        {
            let Some((algorithm, expected)) = checksum.split_once(':') else {
                return Err(AccountError::new("invalid checksum metadata"));
            };
            if let Some((_, actual)) = digests
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(&algorithm.replace('-', "")))
                && !expected.eq_ignore_ascii_case(actual)
            {
                return Err(AccountError::new("pinned checksum mismatch"));
            }
        }
        verify(version)?;
    }
    for version in &tree.files {
        verify(version)?;
    }
    verify_tree()?;
    scratch
        .seek(SeekFrom::Start(0))
        .map_err(|_| AccountError::new("cannot read pin scratch file"))?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| sqlite_storage_error(error, "cannot start offline transaction"))?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_SQLITE_TX_WINDOW")?;
    let current: i64 = tx
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect offline metadata"))?;
    if current != data_version {
        return Err(AccountError::new(PIN_SNAPSHOT_INTERRUPTED));
    }
    check_pin_operations(&tx, instance, space, root_path)?;
    if let Some(expected) = retry_state
        && pin_local_state(&tx)? != *expected
    {
        return Err(AccountError::new(PIN_SNAPSHOT_INTERRUPTED));
    }
    if !snapshots_match(&tx, instance, space, root_path, tree)? {
        return Err(AccountError::new(
            "offline metadata changed during pinning; saved metadata does not match the pin",
        ));
    }
    let root = path_key(root_path)?;
    for table in ["chunks", "files", "pins"] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE instance=?1 AND space=?2 AND root=?3"),
            params![instance, space, root],
        )
        .map_err(|error| sqlite_storage_error(error, "cannot replace offline pin"))?;
    }
    let mut chunk_index = 0;
    for version in &tree.files {
        let path = path_key(&version.path)?;
        let encoded = serde_json::to_string(version)
            .map_err(|_| AccountError::new("invalid pinned version"))?;
        let mut offset = 0u64;
        while offset < version.size {
            let length = (version.size - offset).min(CHUNK) as usize;
            let mut bytes = vec![0; length];
            scratch
                .read_exact(&mut bytes)
                .map_err(|_| AccountError::new("cannot read pin scratch file"))?;
            let digest = Sha256::digest(&bytes);
            if chunk_digests.get(chunk_index) != Some(&digest) {
                return Err(AccountError::new("pin scratch content changed"));
            }
            chunk_index += 1;
            tx.execute(
                "INSERT INTO chunks VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    instance,
                    space,
                    root,
                    path,
                    offset as i64,
                    bytes,
                    format!("{digest:x}")
                ],
            )
            .map_err(|error| sqlite_storage_error(error, "cannot save pinned content"))?;
            offset += length as u64;
        }
        tx.execute(
            "INSERT INTO files VALUES (?1,?2,?3,?4,?5,1)",
            params![instance, space, root, path, encoded],
        )
        .map_err(|error| sqlite_storage_error(error, "cannot save pinned version"))?;
    }
    tx.execute(
        "INSERT INTO pins VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            instance,
            space,
            root,
            tree.is_dir,
            serde_json::to_string(&tree.directories)
                .map_err(|_| AccountError::new("invalid pinned directories"))?,
            serde_json::to_string(&tree.files)
                .map_err(|_| AccountError::new("invalid pin manifest"))?
        ],
    )
    .map_err(|error| sqlite_storage_error(error, "cannot save pin"))?;
    #[cfg(feature = "fault-injection")]
    repin_stop("before-commit");
    scratch_file.validate(&tx)?;
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_PIN_COMMIT_WINDOW")?;
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot commit offline pin"))?;
    #[cfg(feature = "fault-injection")]
    repin_stop("after-commit");
    Ok(())
}

// Explicit local management addresses retained state, not the currently loaded
// keyring account. Never adopt unbound data or infer a new authenticated Space.
// Keep this check in the same transaction as inspection/removal.
pub(crate) fn mount_identity(
    instance: &str,
    space: &str,
) -> Result<(String, String), AccountError> {
    database()?.query_row("SELECT a.issuer,a.subject FROM account_identities a JOIN sync_spaces s ON s.instance=a.instance AND s.issuer=a.issuer AND s.subject=a.subject WHERE a.instance=?1 AND s.space=?2 AND a.issuer<>'' AND a.subject<>''", params![instance,space], |row| Ok((row.get(0)?,row.get(1)?)))
        .optional().map_err(|_| AccountError::new("cannot inspect offline mount identity"))?
        .ok_or_else(|| AccountError::new("offline mount requires matching retained account and verified Space activation"))
}

pub(crate) fn check_retained_identity(
    conn: &Connection,
    instance: &str,
    space: &str,
) -> Result<(), AccountError> {
    let identity: Option<(String, String)> = conn
        .query_row(
            "SELECT issuer,subject FROM account_identities WHERE instance=?1",
            [instance],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| AccountError::new("cannot inspect offline account identity"))?;
    let (issuer, subject) = identity
        .filter(|(issuer, subject)| !issuer.is_empty() && !subject.is_empty())
        .ok_or_else(|| {
            AccountError::new("offline account identity is missing; local data retained")
        })?;
    let differs: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sync_spaces WHERE instance=?1 AND space=?2 AND (issuer<>?3 OR subject<>?4))", params![instance,space,issuer,subject], |row| row.get(0))
        .map_err(|_| AccountError::new("cannot inspect retained Space identity"))?;
    if differs {
        return Err(AccountError::new(
            "retained Space identity differs from offline account; local data retained",
        ));
    }
    Ok(())
}

pub(crate) fn unpin(instance: &str, space: &str, root: &[String]) -> Result<(), AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot start offline transaction"))?;
    check_retained_identity(&tx, instance, space)?;
    let root = path_key(root)?;
    for table in ["chunks", "files", "pins"] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE instance=?1 AND space=?2 AND root=?3"),
            params![instance, space, root],
        )
        .map_err(|_| AccountError::new("cannot remove pin"))?;
    }
    tx.commit()
        .map_err(|_| AccountError::new("cannot commit offline unpin"))
}

fn complete_file(
    conn: &Connection,
    instance: &str,
    space: &str,
    root: &str,
    version: &FileVersion,
    verify_digests: bool,
) -> Result<bool, AccountError> {
    if version.size > MAX_PIN_BYTES {
        return Ok(false);
    }
    let path = path_key(&version.path)?;
    let (count, size, invalid): (u64, u64, u64) = conn.query_row(
        "SELECT count(*), coalesce(sum(length(body)),0), coalesce(sum(CASE WHEN offset < 0 OR offset >= ?5 OR offset % ?6 != 0 OR length(body) != min(?6, ?5 - offset) THEN 1 ELSE 0 END),0) FROM chunks WHERE instance=?1 AND space=?2 AND root=?3 AND path=?4",
        params![instance, space, root, path, version.size as i64, CHUNK as i64],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(|_| AccountError::new("cannot inspect pinned content"))?;
    if invalid != 0 || size != version.size || count != version.size.div_ceil(CHUNK) {
        return Ok(false);
    }
    if verify_digests {
        let mut stmt = conn.prepare("SELECT body,digest FROM chunks WHERE instance=?1 AND space=?2 AND root=?3 AND path=?4")
            .map_err(|_| AccountError::new("cannot inspect pinned content"))?;
        let rows = stmt
            .query_map(params![instance, space, root, path], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| AccountError::new("cannot inspect pinned content"))?;
        for row in rows {
            let (body, digest) =
                row.map_err(|_| AccountError::new("cannot inspect pinned content"))?;
            if format!("{:x}", Sha256::digest(&body)) != digest {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn snapshots_match(
    conn: &Connection,
    instance: &str,
    space: &str,
    root: &[String],
    tree: &PinTree,
) -> Result<bool, AccountError> {
    // Sorted pin files commonly share a large parent. Retain only the latest
    // complete scratch observation inside this publication transaction, rather
    // than decoding/rebuilding that parent for every file.
    let mut latest: Option<(Vec<String>, crate::DirectorySnapshot)> = None;
    let mut load = |path: &[String]| -> Result<Option<crate::DirectorySnapshot>, AccountError> {
        if let Some((parent, snapshot)) = &latest
            && parent == path
        {
            return Ok(Some(snapshot.clone()));
        }
        let snapshot = directory_snapshot_in(conn, instance, space, path)?;
        latest = snapshot
            .as_ref()
            .map(|snapshot| (path.to_vec(), snapshot.clone()));
        Ok(snapshot)
    };
    for depth in 0..root.len().saturating_sub(1) {
        let Some(entries) = load(&root[..depth])? else {
            return Ok(false);
        };
        if !entries
            .get(&root[depth])?
            .is_some_and(|entry| entry.is_directory())
        {
            return Ok(false);
        }
    }
    for (path, id) in &tree.directories {
        if load(path)?.is_none() {
            return Ok(false);
        }
        if let Some((name, parent)) = path.split_last() {
            let Some(entries) = load(parent)? else {
                return Ok(false);
            };
            if !entries
                .get(name)?
                .is_some_and(|entry| entry.is_directory() && entry.id() == id)
            {
                return Ok(false);
            }
        }
    }
    for file in &tree.files {
        let Some((name, parent)) = file.path.split_last() else {
            return Ok(false);
        };
        let Some(entries) = load(parent)? else {
            return Ok(false);
        };
        if !entries.get(name)?.is_some_and(|entry| {
            !entry.is_directory()
                && entry.id() == file.id
                && entry.size() == Some(file.size)
                && entry.etag() == Some(file.etag.as_str())
                && entry.checksums() == file.checksums
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn pins(
    instance: &str,
    space: &str,
    verify_digests: bool,
) -> Result<Vec<Pin>, AccountError> {
    let mut conn = database()?;
    let tx = conn
        .transaction()
        .map_err(|error| sqlite_storage_error(error, "cannot start offline transaction"))?;
    let output = pins_in(&tx, instance, space, verify_digests)?;
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot finish listing pins"))?;
    Ok(output)
}

fn pins_in(
    conn: &Connection,
    instance: &str,
    space: &str,
    verify_digests: bool,
) -> Result<Vec<Pin>, AccountError> {
    check_retained_identity(conn, instance, space)?;
    let mut stmt = conn
        .prepare(
            "SELECT root,is_dir,directories,manifest FROM pins WHERE instance=?1 AND space=?2 ORDER BY root",
        )
        .map_err(|_| AccountError::new("cannot list pins"))?;
    let rows = stmt
        .query_map(params![instance, space], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| AccountError::new("cannot list pins"))?;
    let mut output = Vec::new();
    for row in rows {
        let (root, is_dir, directories, manifest) =
            row.map_err(|_| AccountError::new("cannot list pins"))?;
        let path: Vec<String> =
            serde_json::from_str(&root).map_err(|_| AccountError::new("invalid pinned path"))?;
        let mut files = conn.prepare("SELECT version FROM files WHERE instance=?1 AND space=?2 AND root=?3 AND verified_complete=1 ORDER BY path").map_err(|_| AccountError::new("cannot list pins"))?;
        let mut versions = files
            .query_map(params![instance, space, root], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|_| AccountError::new("cannot list pins"))?
            .map(|row| {
                serde_json::from_str(&row.map_err(|_| AccountError::new("cannot list pins"))?)
                    .map_err(|_| AccountError::new("invalid pinned version"))
            })
            .collect::<Result<Vec<FileVersion>, AccountError>>()?;
        versions.sort_by(|a, b| a.path.cmp(&b.path));
        if versions.iter().any(|version| {
            version.instance != instance
                || version.space != space
                || !version.path.starts_with(&path)
        }) {
            return Err(AccountError::new(
                "pinned file identity differs from local Space",
            ));
        }
        let expected: Vec<FileVersion> = serde_json::from_str(&manifest)
            .map_err(|_| AccountError::new("invalid pin manifest"))?;
        let mut complete = versions == expected;
        for version in &versions {
            complete &= complete_file(conn, instance, space, &root, version, verify_digests)?;
        }
        let directories = serde_json::from_str(&directories)
            .map_err(|_| AccountError::new("invalid pinned directories"))?;
        let tree = PinTree {
            is_dir,
            directories,
            files: versions,
        };
        let metadata_matches =
            !verify_digests || snapshots_match(conn, instance, space, &path, &tree)?;
        output.push(Pin {
            path,
            complete,
            tree,
            metadata_matches,
        });
    }
    drop(stmt);
    Ok(output)
}

pub(crate) fn version(
    instance: &str,
    space: &str,
    path: &[String],
    id: &str,
    owner: Option<(&str, &str)>,
) -> Result<Option<FileVersion>, AccountError> {
    let (name, parent) = path
        .split_last()
        .ok_or_else(|| AccountError::new("invalid pinned path"))?;
    let entries = match directory_snapshot(instance, space, parent)? {
        Some(entries) => entries,
        None if owner.is_some() => offline_directory(instance, space, parent, owner)?,
        None => return Ok(None),
    };
    let roots = pins(instance, space, false)?
        .into_iter()
        .filter(|pin| pin.complete)
        .map(|pin| path_key(&pin.path))
        .collect::<Result<Vec<_>, _>>()?;
    let conn = database()?;
    let mut stmt = conn
        .prepare("SELECT root,version FROM files WHERE instance=?1 AND space=?2 AND path=?3 AND verified_complete=1")
        .map_err(|_| AccountError::new("cannot load pinned version"))?;
    let rows = stmt
        .query_map(params![instance, space, path_key(path)?], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| AccountError::new("cannot load pinned version"))?;
    let mut found = None;
    for row in rows {
        let (root, encoded) = row.map_err(|_| AccountError::new("invalid pinned version"))?;
        let value: FileVersion = serde_json::from_str(&encoded)
            .map_err(|_| AccountError::new("invalid pinned version"))?;
        if value.id != id
            || value.instance != instance
            || value.space != space
            || value.path != path
        {
            continue;
        }
        if !entries.get(name)?.is_some_and(|entry| {
            !entry.is_directory()
                && entry.id() == value.id
                && entry.etag() == Some(value.etag.as_str())
                && entry.size() == Some(value.size)
                && entry.checksums() == value.checksums
        }) {
            continue;
        }
        if !roots.contains(&root) {
            continue;
        }
        if found.as_ref().is_some_and(|old| old != &value) {
            return Err(AccountError::new("ambiguous pinned versions"));
        }
        found = Some(value);
    }
    Ok(found)
}

// Tree relocation changes recovery coordinates, not an overlay's original
// FileVersion. Resolve only exact same-version local bytes through a scoped
// durable MOVE; never fetch, alter the original base or infer remote freshness.
pub(crate) fn read_moved_local(
    version: &FileVersion,
    offset: u64,
    length: u32,
) -> Result<Option<Vec<u8>>, AccountError> {
    let conn = database()?;
    check_retained_identity(&conn, &version.instance, &version.space)?;
    let through: i64 = conn
        .query_row(
            "SELECT coalesce(max(id),0) FROM operation_journal",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AccountError::new("cannot inspect retained MOVE high water"))?;
    let mut after = 0;
    loop {
        let mut stmt=conn.prepare("SELECT j.id,j.path,m.destination FROM operation_journal j JOIN directory_moves m ON m.operation_id=j.id WHERE j.instance=?1 AND j.space=?2 AND j.op_type='move-tree' AND j.state IN ('pending','synced','conflict','uncertain') AND j.id>?3 AND j.id<=?4 ORDER BY j.id LIMIT 32").map_err(|_|AccountError::new("cannot inspect relocated pin"))?;
        let page = stmt
            .query_map(
                params![version.instance, version.space, after, through],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|_| AccountError::new("cannot inspect relocated pin"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AccountError::new("invalid relocated pin mapping"))?;
        if page.is_empty() {
            return Ok(None);
        }
        drop(stmt);
        for (id, source, destination) in page {
            after = id;
            let source: Vec<String> = serde_json::from_str(&source)
                .map_err(|_| AccountError::new("invalid relocated pin source"))?;
            let destination: Vec<String> = serde_json::from_str(&destination)
                .map_err(|_| AccountError::new("invalid relocated pin destination"))?;
            if source.is_empty()
                || destination.is_empty()
                || (!version.path.starts_with(&source) && !version.path.starts_with(&destination))
            {
                continue;
            }
            let mut candidate = version.clone();
            let reverse = version.path.starts_with(&destination);
            let (from, to) = if reverse {
                (&destination, &source)
            } else {
                (&source, &destination)
            };
            candidate.path = to.to_vec();
            candidate
                .path
                .extend_from_slice(&version.path[from.len()..]);
            if candidate.path.len() <= 128
                && let Ok(bytes) = read(&candidate, offset, length)
            {
                return Ok(Some(bytes));
            }
            if candidate.path.len() <= 128 {
                if let Some(bytes) = confirmed_local_range(&candidate, offset, length)? {
                    return Ok(Some(bytes));
                }
                let (original, current) = if reverse {
                    (&candidate, &version.path)
                } else {
                    (version, &candidate.path)
                };
                if let Some(bytes) = confirmed_range_at(original, current, offset, length)? {
                    return Ok(Some(bytes));
                }
            }
        }
    }
}

pub(crate) fn read(
    version: &FileVersion,
    offset: u64,
    length: u32,
) -> Result<Vec<u8>, AccountError> {
    let end = offset
        .checked_add(u64::from(length))
        .filter(|end| length > 0 && u64::from(length) <= CHUNK && *end <= version.size)
        .ok_or_else(|| AccountError::new("invalid pinned range"))?;
    let mut conn = database()?;
    // Pin publication replaces path-keyed chunks. Keep eligibility, the exact
    // FileVersion row and every chunk in ONE read snapshot, including across a
    // peer repin/unpin. No helper here may open another State connection.
    let tx = conn
        .transaction()
        .map_err(|error| sqlite_storage_error(error, "cannot start pinned read"))?;
    let roots = pins_in(&tx, &version.instance, &version.space, false)?
        .into_iter()
        .filter(|pin| pin.complete)
        .map(|pin| path_key(&pin.path))
        .collect::<Result<Vec<_>, _>>()?;
    let path = path_key(&version.path)?;
    let encoded =
        serde_json::to_string(version).map_err(|_| AccountError::new("invalid pinned version"))?;
    let mut stmt = tx.prepare("SELECT root FROM files WHERE instance=?1 AND space=?2 AND path=?3 AND version=?4 AND verified_complete=1")
        .map_err(|_| AccountError::new("pinned content is unavailable"))?;
    let rows = stmt
        .query_map(
            params![version.instance, version.space, path, encoded],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| AccountError::new("pinned content is unavailable"))?;
    let mut root = None;
    for row in rows {
        let candidate = row.map_err(|_| AccountError::new("pinned content is unavailable"))?;
        if roots.contains(&candidate) {
            root = Some(candidate);
            break;
        }
    }
    let root = root.ok_or_else(|| AccountError::new("pinned content is unavailable"))?;
    drop(stmt);
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_PIN_READ_SELECTED_WINDOW")?;
    let mut result = Vec::with_capacity(length as usize);
    let mut position = offset;
    while position < end {
        let chunk_offset = position / CHUNK * CHUNK;
        let (body, digest): (Vec<u8>, String) = tx.query_row("SELECT c.body,c.digest FROM chunks c JOIN files f ON f.instance=c.instance AND f.space=c.space AND f.root=c.root AND f.path=c.path WHERE c.instance=?1 AND c.space=?2 AND c.root=?3 AND c.path=?4 AND c.offset=?5 AND f.version=?6 AND f.verified_complete=1",
            params![version.instance, version.space, root, path, chunk_offset as i64, encoded], |row| Ok((row.get(0)?, row.get(1)?))).map_err(|_| AccountError::new("pinned content is incomplete"))?;
        let expected = (version.size - chunk_offset).min(CHUNK) as usize;
        if body.len() != expected || format!("{:x}", Sha256::digest(&body)) != digest {
            return Err(AccountError::new("pinned content is incomplete"));
        }
        let start = (position - chunk_offset) as usize;
        let count = ((end - position) as usize).min(body.len() - start);
        result.extend_from_slice(&body[start..start + count]);
        position += count as u64;
    }
    tx.commit()
        .map_err(|error| sqlite_storage_error(error, "cannot finish pinned read"))?;
    Ok(result)
}

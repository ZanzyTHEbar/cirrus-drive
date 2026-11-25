//! Shared SQLite opening admission; SQLite alone owns existing database descriptors.

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OpenFlags, ffi};
#[cfg(target_os = "linux")]
use rustix::fs::ResolveFlags;
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags},
    process,
};

use crate::{AccountError, account_storage::StorageRoot};

static STATE_OPEN: Mutex<()> = Mutex::new(());
static CACHE_OPEN: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
pub(crate) enum Database {
    State,
    Cache,
}

#[derive(Clone, Copy)]
pub(crate) enum OpenMode {
    /// Create a named inode exclusively if needed, then open read-write.
    CreateOrOpen,
    /// Open read-write without creating a missing database.
    Existing,
    /// Open read-only without creating a missing database.
    Inspect,
}

/// Keeps the target's opening gate until the caller finishes setup and validation.
pub(crate) struct Opening<'root> {
    conn: Connection,
    database: Database,
    root: &'root StorageRoot,
    stat: fs::Stat,
    created: bool,
    mode: OpenMode,
    #[cfg(target_os = "linux")]
    _proc: OwnedFd,
    // On error, drop SQLite's connection before releasing the gate.
    _gate: MutexGuard<'static, ()>,
}

impl Database {
    fn basename(self) -> &'static str {
        match self {
            Self::State => "state.db",
            Self::Cache => "cache.db",
        }
    }

    fn error(self, state: &'static str, cache: &'static str) -> AccountError {
        AccountError::new(match self {
            Self::State => state,
            Self::Cache => cache,
        })
    }

    fn unsafe_permissions(self) -> AccountError {
        self.error(
            "offline state has unsafe ownership or permissions",
            "cache has unsafe ownership or permissions",
        )
    }

    fn changed(self) -> AccountError {
        self.error("offline state changed", "cache changed")
    }

    pub(crate) fn unavailable(self) -> AccountError {
        self.error("offline state is unavailable", "cache is unavailable")
    }

    pub(crate) fn open(
        self,
        root: &StorageRoot,
        mode: OpenMode,
    ) -> Result<Option<Opening<'_>>, AccountError> {
        let gate = match self {
            Self::State => &STATE_OPEN,
            Self::Cache => &CACHE_OPEN,
        }
        .lock()
        .map_err(|_| self.unavailable())?;
        let Some((stat, created)) = self.prepare(root, mode)? else {
            return Ok(None);
        };
        private_stat(&stat).map_err(|_| self.unsafe_permissions())?;
        let flags = match mode {
            OpenMode::CreateOrOpen | OpenMode::Existing => OpenFlags::SQLITE_OPEN_READ_WRITE,
            OpenMode::Inspect => OpenFlags::SQLITE_OPEN_READ_ONLY,
        };
        #[cfg(target_os = "linux")]
        let proc = self.trusted_procfs(mode)?;
        self.check_files(root, &stat)
            .map_err(|_| self.unsafe_permissions())?;
        #[cfg(target_os = "linux")]
        // SQLite resolves the held-directory procfs link before opening;
        // SQLITE_OPEN_NOFOLLOW would reject that link.
        let conn = Connection::open_with_flags(
            format!(
                "/proc/self/fd/{}/{}",
                root.directory().as_raw_fd(),
                self.basename()
            ),
            flags,
        );
        #[cfg(target_os = "macos")]
        let conn = self.open_darwin(root, flags);
        let conn =
            conn.map_err(|_| self.error("cannot open offline state", "cannot open cache"))?;
        check_unmoved(&conn).map_err(|_| self.changed())?;
        Ok(Some(Opening {
            conn,
            database: self,
            root,
            stat,
            created,
            mode,
            #[cfg(target_os = "linux")]
            _proc: proc,
            _gate: gate,
        }))
    }

    fn prepare(
        self,
        root: &StorageRoot,
        mode: OpenMode,
    ) -> Result<Option<(fs::Stat, bool)>, AccountError> {
        #[cfg(target_os = "linux")]
        let inspect_failed = || self.error("cannot inspect offline state", "cannot inspect cache");
        #[cfg(target_os = "macos")]
        let inspect_failed = || self.error("cannot admit offline state", "cannot admit cache");
        #[cfg(target_os = "macos")]
        root.revalidate().map_err(|_| inspect_failed())?;
        let create = matches!(mode, OpenMode::CreateOrOpen);
        let dir = root.directory();
        // Only exclusive creation can yield an fd here. Never open/close an
        // existing main file or sidecar: POSIX locks belong to the process.
        let fresh = if create {
            let flags = OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC;
            let permissions = Mode::from_raw_mode(0o600);
            #[cfg(target_os = "linux")]
            let result = fs::openat2(
                dir,
                self.basename(),
                flags,
                permissions,
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            );
            #[cfg(target_os = "macos")]
            let result = fs::openat(dir, self.basename(), flags | OFlags::NOFOLLOW, permissions);
            match result {
                Ok(fd) => Some(fd),
                Err(rustix::io::Errno::EXIST) => None,
                #[cfg(target_os = "linux")]
                Err(_) => {
                    return Err(self.error("cannot create offline state", "cannot create cache"));
                }
                #[cfg(target_os = "macos")]
                Err(_) => return Err(inspect_failed()),
            }
        } else {
            None
        };
        let stat = if let Some(fd) = &fresh {
            let stat = fs::fstat(fd).map_err(|_| inspect_failed())?;
            #[cfg(target_os = "macos")]
            {
                private_stat(&stat).map_err(|_| inspect_failed())?;
                let acl =
                    crate::ownership::darwin_acl::checked_fd(fd).map_err(|_| inspect_failed())?;
                same_snapshot(&stat, &acl).map_err(|_| inspect_failed())?;
            }
            stat
        } else {
            match fs::statat(dir, self.basename(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
                Err(_) => return Err(inspect_failed()),
            }
        };
        #[cfg(target_os = "macos")]
        self.check_named_darwin(root, self.basename(), &stat)
            .map_err(|_| inspect_failed())?;
        Ok(Some((stat, fresh.is_some())))
    }

    #[cfg(target_os = "linux")]
    fn trusted_procfs(self, mode: OpenMode) -> Result<OwnedFd, AccountError> {
        let required = || {
            self.error(
                "trusted procfs is required for offline state",
                "trusted procfs is required for cache",
            )
        };
        // The usage path already specified NO_MAGICLINKS explicitly.
        let resolve = if matches!(mode, OpenMode::Inspect) {
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS
        } else {
            ResolveFlags::NO_SYMLINKS
        };
        let proc = fs::openat2(
            fs::CWD,
            "/proc",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )
        .map_err(|_| required())?;
        if fs::fstatfs(&proc)
            .map_err(|_| AccountError::new("cannot inspect procfs"))?
            .f_type
            != fs::PROC_SUPER_MAGIC
        {
            return Err(required());
        }
        Ok(proc)
    }

    fn check_files(self, root: &StorageRoot, _main: &fs::Stat) -> Result<(), ()> {
        #[cfg(target_os = "macos")]
        {
            root.revalidate().map_err(|_| ())?;
            self.check_named_darwin(root, self.basename(), _main)?;
        }
        let dir = root.directory();
        for suffix in ["-journal", "-wal", "-shm"] {
            let name = format!("{}{suffix}", self.basename());
            let stat = match fs::statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => continue,
                Err(_) => return Err(()),
            };
            #[cfg(target_os = "linux")]
            private_stat(&stat)?;
            #[cfg(target_os = "macos")]
            self.check_named_darwin(root, &name, &stat)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn check_named_darwin(
        self,
        root: &StorageRoot,
        name: &str,
        expected: &fs::Stat,
    ) -> Result<(), ()> {
        private_stat(expected)?;
        let snapshot =
            crate::ownership::darwin_acl::checked_path(&root.private_state_path().join(name))
                .map_err(|_| ())?;
        same_snapshot(expected, &snapshot)?;
        let current =
            fs::statat(root.directory(), name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
        same_snapshot(&current, &snapshot)
    }

    #[cfg(target_os = "macos")]
    fn open_darwin(self, root: &StorageRoot, flags: OpenFlags) -> rusqlite::Result<Connection> {
        // No fallback: unix-posix must actually be registered in bundled SQLite.
        // Private ancestors exclude foreign writers, not hostile same-UID rename
        // or privileged mount changes. HAS_MOVED is not a global race oracle.
        Connection::open_with_flags_and_vfs(
            root.private_state_path().join(self.basename()),
            flags | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            "unix-posix",
        )
    }
}

impl Opening<'_> {
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn created(&self) -> bool {
        self.created
    }

    // Cache sets its page cap between this named-file check and the final
    // sidecar/VFS checks. Keep both under the same opening gate.
    pub(crate) fn check_named(&self) -> Result<(), AccountError> {
        let current = fs::statat(
            self.root.directory(),
            self.database.basename(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| self.database.changed())?;
        if (self.stat.st_dev, self.stat.st_ino) != (current.st_dev, current.st_ino) {
            return Err(self.database.changed());
        }
        if matches!(self.mode, OpenMode::Inspect) {
            if (self.stat.st_mode, self.stat.st_uid, self.stat.st_nlink)
                != (current.st_mode, current.st_uid, current.st_nlink)
            {
                return Err(self.database.changed());
            }
            Ok(())
        } else {
            private_stat(&current).map_err(|_| self.database.changed())
        }
    }

    pub(crate) fn check_sidecars_and_vfs(&self) -> Result<(), AccountError> {
        self.database
            .check_files(self.root, &self.stat)
            .map_err(|_| self.database.unsafe_permissions())?;
        check_unmoved(&self.conn).map_err(|_| self.database.changed())
    }

    /// After the final checks, release the gate without closing SQLite's connection.
    pub(crate) fn into_connection(self) -> Connection {
        self.conn
    }
}

fn private_stat(stat: &fs::Stat) -> Result<(), ()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn same_snapshot(stat: &fs::Stat, acl: &libc::stat) -> Result<(), ()> {
    private_stat(stat)?;
    if stat.st_dev as u64 != acl.st_dev as u64
        || stat.st_ino as u64 != acl.st_ino as u64
        || stat.st_uid != acl.st_uid
        || stat.st_mode as u32 != acl.st_mode as u32
        || stat.st_nlink as u64 != acl.st_nlink as u64
    {
        return Err(());
    }
    Ok(())
}

pub(crate) fn check_unmoved(conn: &Connection) -> Result<(), ()> {
    let mut moved: std::ffi::c_int = 1;
    // SAFETY: the borrowed live connection keeps its handle valid for this
    // synchronous call. "main" is NUL-terminated; HAS_MOVED writes one c_int
    // into the live, aligned local. No SQLite-owned descriptor is exposed.
    let result = unsafe {
        ffi::sqlite3_file_control(
            conn.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_HAS_MOVED,
            (&mut moved as *mut std::ffi::c_int).cast(),
        )
    };
    // Bundled Linux unix/posix VFS tracks the opened inode. Its HAS_MOVED
    // comparison is inode-only; held-directory/main dev+inode checks supply
    // the same-filesystem assumption, not protection from privileged mounts.
    if result != ffi::SQLITE_OK || moved != 0 {
        return Err(());
    }
    Ok(())
}

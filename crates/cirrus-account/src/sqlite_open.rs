//! Shared SQLite opening admission; SQLite alone owns existing database descriptors.

use std::os::fd::AsFd;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, ffi};
use rustix::{
    fs::{self, AtFlags, FileType},
    process,
};

static STATE_OPEN: Mutex<()> = Mutex::new(());
static CACHE_OPEN: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
pub(crate) enum Database {
    State,
    Cache,
}

impl Database {
    pub(crate) fn basename(self) -> &'static str {
        match self {
            Self::State => "state.db",
            Self::Cache => "cache.db",
        }
    }

    // Hold through preparation/initialization/final validation, not connection
    // lifetime. No Store/staging lock or accounting acquisition inside this gate.
    pub(crate) fn opening_gate(self) -> Result<MutexGuard<'static, ()>, ()> {
        match self {
            Self::State => &STATE_OPEN,
            Self::Cache => &CACHE_OPEN,
        }
        .lock()
        .map_err(|_| ())
    }

    pub(crate) fn check_auxiliaries(self, dir: &impl AsFd) -> Result<(), ()> {
        for suffix in ["-journal", "-wal", "-shm"] {
            let name = format!("{}{suffix}", self.basename());
            let stat = match fs::statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => continue,
                Err(_) => return Err(()),
            };
            // Never open/close an existing DB or auxiliary for validation:
            // POSIX locks belong to the process, not an individual descriptor.
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != process::geteuid().as_raw()
                || stat.st_mode & 0o7777 != 0o600
                || stat.st_nlink != 1
            {
                return Err(());
            }
        }
        Ok(())
    }

    /// Darwin admission uses metadata snapshots, never an extra existing-inode
    /// descriptor: even closing a read-only SHM/DB fd can lose POSIX writer locks.
    #[cfg(target_os = "macos")]
    pub(crate) fn prepare_darwin(
        self,
        root: &crate::account_storage::StorageRoot,
        create: bool,
    ) -> Result<Option<(fs::Stat, bool)>, ()> {
        root.revalidate().map_err(|_| ())?;
        let dir = root.directory();
        if create {
            match fs::openat(
                dir,
                self.basename(),
                fs::OFlags::CREATE
                    | fs::OFlags::EXCL
                    | fs::OFlags::RDWR
                    | fs::OFlags::NOFOLLOW
                    | fs::OFlags::CLOEXEC,
                fs::Mode::from_raw_mode(0o600),
            ) {
                Ok(fd) => {
                    let stat = fs::fstat(&fd).map_err(|_| ())?;
                    private_stat(&stat)?;
                    let acl = crate::ownership::darwin_acl::checked_fd(&fd).map_err(|_| ())?;
                    same_snapshot(&stat, &acl)?;
                    self.check_named_darwin(root, self.basename(), &stat)?;
                    return Ok(Some((stat, true)));
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(_) => return Err(()),
            }
        }
        let stat = match fs::statat(dir, self.basename(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(_) => return Err(()),
        };
        self.check_named_darwin(root, self.basename(), &stat)?;
        Ok(Some((stat, false)))
    }

    #[cfg(target_os = "macos")]
    fn check_named_darwin(
        self,
        root: &crate::account_storage::StorageRoot,
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
    pub(crate) fn check_darwin(
        self,
        root: &crate::account_storage::StorageRoot,
        main: &fs::Stat,
    ) -> Result<(), ()> {
        root.revalidate().map_err(|_| ())?;
        self.check_named_darwin(root, self.basename(), main)?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let name = format!("{}{suffix}", self.basename());
            let stat = match fs::statat(root.directory(), name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => continue,
                Err(_) => return Err(()),
            };
            self.check_named_darwin(root, &name, &stat)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn open_darwin(
        self,
        root: &crate::account_storage::StorageRoot,
        flags: rusqlite::OpenFlags,
    ) -> rusqlite::Result<Connection> {
        // No fallback: unix-posix must actually be registered in bundled SQLite.
        // Private ancestors exclude foreign writers, not hostile same-UID rename
        // or privileged mount changes. HAS_MOVED is not a global race oracle.
        Connection::open_with_flags_and_vfs(
            root.private_state_path().join(self.basename()),
            flags | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            "unix-posix",
        )
    }
}

#[cfg(target_os = "macos")]
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

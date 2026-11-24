//! Linux and macOS runtime-directory validation for local service endpoints.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("cirrus-runtime supports only Linux and macOS");

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path};

use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::process;

/// An open runtime directory whose owner and permissions were checked.
///
/// This is not authorization to create an endpoint: revalidate it at use and
/// separately secure endpoint creation, peer identity and cleanup.
#[derive(Debug)]
pub struct RuntimeDir {
    fd: OwnedFd,
}

impl RuntimeDir {
    /// Opens an absolute runtime directory without following symlinks.
    ///
    /// The directory must be owned by the effective user and have mode 0700.
    /// The returned descriptor remains attached to the opened directory even
    /// if its pathname is later changed. No files or directories are created.
    /// Ancestors need not be private: neither platform guarantees that the
    /// pathname still names this directory after an ancestor is renamed or
    /// replaced. Use the held descriptor, not a later pathname lookup.
    /// macOS symlink aliases (including `/var`) are rejected, not canonicalized.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, failed resolution, incorrect owner or
    /// permissions, or unsupported resolution flags/syscalls (`openat2` on Linux).
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime directory must be an absolute path without parent components",
            ));
        }

        let fd = open_directory(path).map_err(|error| {
            let error = io::Error::from(error);
            io::Error::new(
                error.kind(),
                format!("cannot open runtime directory: {error}"),
            )
        })?;
        let runtime = Self { fd };
        runtime.revalidate()?;
        Ok(runtime)
    }

    /// Rechecks directory type, ownership and permissions on the held descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error if metadata cannot be read or the type, owner or mode is invalid.
    pub fn revalidate(&self) -> io::Result<()> {
        let metadata = fs::fstat(&self.fd).map_err(io::Error::from)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime directory must be a directory",
            ));
        }
        if metadata.st_uid != process::geteuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime directory must be owned by the effective user",
            ));
        }
        if metadata.st_mode & 0o7777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime directory must have mode 0700",
            ));
        }
        Ok(())
    }

    /// Duplicates the checked directory descriptor for a daemon worker.
    ///
    /// # Errors
    /// Returns an error if the descriptor cannot be duplicated or is no longer safe.
    pub fn try_clone(&self) -> io::Result<Self> {
        self.revalidate()?;
        let fd = self.fd.try_clone()?;
        Ok(Self { fd })
    }
}

impl AsFd for RuntimeDir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> rustix::io::Result<OwnedFd> {
    fs::openat2(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        fs::ResolveFlags::NO_SYMLINKS | fs::ResolveFlags::NO_MAGICLINKS,
    )
}

#[cfg(target_os = "macos")]
fn open_directory(path: &Path) -> rustix::io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let mut fd = fs::open("/", flags, Mode::empty())?;
    for component in path.components() {
        match component {
            // Each lookup has exactly one normal component, so NOFOLLOW
            // applies to every traversed name. Held parents avoid a
            // check-then-open symlink race; no pathname is reopened.
            Component::Normal(name) => fd = fs::openat(&fd, name, flags, Mode::empty())?,
            Component::RootDir | Component::CurDir => {}
            _ => return Err(rustix::io::Errno::INVAL),
        }
    }
    Ok(fd)
}

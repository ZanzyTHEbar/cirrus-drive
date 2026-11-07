//! Linux runtime-directory validation for future local service endpoints.

#[cfg(not(target_os = "linux"))]
compile_error!("cirrus-runtime currently supports Linux only");

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path};

use rustix::fs::{self, Mode, OFlags, ResolveFlags};
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
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, failed resolution, incorrect owner or
    /// permissions, or if the kernel does not support `openat2`.
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime directory must be an absolute path without parent components",
            ));
        }

        let fd = fs::openat2(
            fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|error| {
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

    /// Rechecks ownership and permissions on the held directory descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error if metadata cannot be read or the owner or mode changed.
    pub fn revalidate(&self) -> io::Result<()> {
        let metadata = fs::fstat(&self.fd).map_err(io::Error::from)?;
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

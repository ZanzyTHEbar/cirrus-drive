//! Filesystem ownership capability; not a principal or Space identity.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs;

use crate::{AccountError, ownership};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RootIdentity {
    device: u64,
    inode: u64,
}

struct Root {
    directory: OwnedFd,
    origin: Origin,
    identity: RootIdentity,
    #[cfg(target_os = "linux")]
    _state_admission: OwnedFd,
}

#[derive(Clone, Copy)]
enum StateAdmission {
    Routine,
    #[cfg(target_os = "linux")]
    Maintenance,
}

#[cfg(target_os = "linux")]
impl StateAdmission {
    fn acquire(self, directory: &OwnedFd) -> Result<OwnedFd, AccountError> {
        let operation = match self {
            Self::Routine => fs::FlockOperation::NonBlockingLockShared,
            Self::Maintenance => {
                crate::storage::prune_closed_scratch()?;
                fs::FlockOperation::NonBlockingLockExclusive
            }
        };
        ownership::acquire_state_admission(directory, operation)
    }
}

/// Exclusive admission to the canonical Linux State store, not a credential owner.
#[cfg(target_os = "linux")]
pub(crate) struct StateMaintenance(StorageRoot);

#[cfg(target_os = "linux")]
impl StateMaintenance {
    pub(crate) fn root(&self) -> &StorageRoot {
        &self.0
    }

    fn prepare(self, runtime: &cirrus_runtime::RuntimeDir) -> Result<(), AccountError> {
        let root = self.root();
        root.revalidate()?;
        // Match the existing sync-before-principal order. These markers also
        // exclude old cooperating transfers and staging, but not all old
        // writers; callers must stop them.
        let _sync = ownership::acquire_sync_in(root, runtime)?;
        let _principal = ownership::acquire_offline_exclusive_in(root, runtime)?;
        crate::offline::prepare_state_in(&self)
    }
}

enum Origin {
    DefaultHome(PathBuf),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    ExplicitContainer {
        directory: OwnedFd,
        path: PathBuf,
        identity: RootIdentity,
    },
}

/// Clones retain the admitted private directory, preventing inode reuse while live.
///
/// This is a filesystem capability, not a credential namespace or user profile.
#[derive(Clone)]
pub struct StorageRoot(Arc<Root>);

pub(crate) enum StorageSelection {
    Default,
    Explicit(StorageRoot),
}

impl StorageSelection {
    pub(crate) fn validate(&self, root: &StorageRoot) -> Result<(), AccountError> {
        let matches = match self {
            Self::Default => matches!(root.0.origin, Origin::DefaultHome(_)),
            Self::Explicit(selected) => selected.identity() == root.identity(),
        };
        if !matches {
            return Err(AccountError::new("account storage root changed"));
        }
        root.revalidate()
    }

    pub(crate) fn resolve(&self) -> Result<StorageRoot, AccountError> {
        match self {
            Self::Default => StorageRoot::default(),
            Self::Explicit(root) => {
                root.revalidate()?;
                Ok(root.clone())
            }
        }
    }
}

impl StorageRoot {
    // Resolve only at independent default-operation entry, never through TLS.
    pub(crate) fn default() -> Result<Self, AccountError> {
        Self::admit_default(StateAdmission::Routine)
    }

    fn admit_default(_admission: StateAdmission) -> Result<Self, AccountError> {
        let home = ownership::home()?;
        let directory = ownership::state_dir::state_dir(&home).map_err(AccountError::new)?;
        let identity = identity(&directory)?;
        Ok(Self(Arc::new(Root {
            #[cfg(target_os = "linux")]
            _state_admission: _admission.acquire(&directory)?,
            directory,
            origin: Origin::DefaultHome(home),
            identity,
        })))
    }

    /// Admits an existing absolute, physical, current-user-owned 0700 container.
    ///
    /// Uses its fixed private `cirrus-drive` child, creating that child if absent.
    /// Ancestors must satisfy the account directory ownership/no-follow policy
    /// and the filesystem must support the existing local durability contract.
    /// Clones retain directory descriptors; later operations refuse replacement
    /// of either named directory rather than relocating ownership or data.
    ///
    /// # Errors
    /// Refuses unsafe paths, permissions, unsupported filesystems or replacement.
    #[cfg(target_os = "linux")]
    pub fn open_container(path: &Path) -> Result<Self, AccountError> {
        Self::admit_container(path, StateAdmission::Routine)
    }

    /// Initializes or upgrades the default Linux State store in place.
    ///
    /// # Errors
    /// Refuses competing storage owners, invalid paths or incompatible State.
    /// The caller must first stop and unmount all older writers, which do not
    /// honor the State admission marker.
    #[cfg(target_os = "linux")]
    pub fn prepare_default_state(runtime: &cirrus_runtime::RuntimeDir) -> Result<(), AccountError> {
        StateMaintenance(Self::admit_default(StateAdmission::Maintenance)?).prepare(runtime)
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn prepare_container_state(
        path: &Path,
        runtime: &cirrus_runtime::RuntimeDir,
    ) -> Result<(), AccountError> {
        StateMaintenance(Self::admit_container(path, StateAdmission::Maintenance)?).prepare(runtime)
    }

    // Directory capability only. Not a public Mac storage constructor: C7 must
    // first admit SQLite/files/objects without procfs or lock-breaking reopens.
    #[cfg(target_os = "macos")]
    pub(crate) fn admit_app_group_directory(path: &Path) -> Result<Self, AccountError> {
        Self::admit_container(path, StateAdmission::Routine)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn admit_container(path: &Path, _admission: StateAdmission) -> Result<Self, AccountError> {
        let container =
            ownership::state_dir::existing_container(path).map_err(AccountError::new)?;
        let container_identity = identity(&container)?;
        let directory =
            ownership::state_dir::container_state(&container, true).map_err(AccountError::new)?;
        let state_identity = identity(&directory)?;
        let root = Self(Arc::new(Root {
            #[cfg(target_os = "linux")]
            _state_admission: _admission.acquire(&directory)?,
            directory,
            origin: Origin::ExplicitContainer {
                directory: container,
                path: path.to_owned(),
                identity: container_identity,
            },
            identity: state_identity,
        }));
        root.revalidate()?;
        Ok(root)
    }

    pub(crate) fn staging_dir(&self) -> Result<OwnedFd, AccountError> {
        ownership::state_dir::root_child(self.directory(), "staging").map_err(AccountError::new)
    }

    pub(crate) fn directory_snapshots_dir(&self) -> Result<OwnedFd, AccountError> {
        ownership::state_dir::root_child(self.directory(), "directory-snapshots")
            .map_err(AccountError::new)
    }

    pub(crate) fn directory(&self) -> &OwnedFd {
        &self.0.directory
    }

    // Immutable admitted origin, not discovery/canonicalization or a fallback.
    // Only used after existing-only revalidation under the database opening gate.
    #[cfg(target_os = "macos")]
    pub(crate) fn private_state_path(&self) -> PathBuf {
        match &self.0.origin {
            Origin::DefaultHome(home) => home.join(".local/state/cirrus-drive"),
            Origin::ExplicitContainer { path, .. } => path.join("cirrus-drive"),
        }
    }

    pub(crate) fn identity(&self) -> RootIdentity {
        self.0.identity
    }

    /// Check named and held directories without relocating retained ownership.
    pub(crate) fn revalidate(&self) -> Result<(), AccountError> {
        let home = match &self.0.origin {
            Origin::DefaultHome(home) => home,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Origin::ExplicitContainer {
                directory,
                path,
                identity: expected,
            } => {
                let current =
                    ownership::state_dir::existing_container(path).map_err(AccountError::new)?;
                let state = ownership::state_dir::container_state(&current, false)
                    .map_err(AccountError::new)?;
                if identity(&current)? != *expected
                    || identity(directory)? != *expected
                    || identity(&state)? != self.0.identity
                    || identity(&self.0.directory)? != self.0.identity
                {
                    return Err(AccountError::new("retained account ownership changed"));
                }
                return Ok(());
            }
        };
        let current_home = ownership::home()?;
        // Refuse a changed home before admitting/creating its state hierarchy.
        if current_home != *home {
            return Err(AccountError::new("retained account home changed"));
        }
        let current = ownership::state_dir::existing_state_dir(home).map_err(AccountError::new)?;
        if identity(&current)? != self.0.identity || identity(&self.0.directory)? != self.0.identity
        {
            return Err(AccountError::new("retained account ownership changed"));
        }
        Ok(())
    }
}

fn identity(directory: &OwnedFd) -> Result<RootIdentity, AccountError> {
    let stat = fs::fstat(directory)
        .map_err(|_| AccountError::new("cannot inspect account coordination directory"))?;
    Ok(RootIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

//! FUSE adapter for daemon-owned Space metadata and durable staged file writes.

mod read_engine;
mod recovery;
mod session;

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cirrus_account::{
    AccountError, Accounts, DirectorySnapshot, DirtyMutation, FileVersion, MountBinding,
    MountMetadataWalk, MountStartup,
};
use cirrus_runtime::RuntimeDir;
use fuser::{
    BackgroundSession, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, Session,
    TimeOrNow, WriteFlags,
};
use rustix::{
    fs::{self, AtFlags, Dir, Mode, OFlags, ResolveFlags, StatxFlags},
    process,
};

pub use read_engine::{ReadEngines, ReadProgram};
pub use recovery::MountTable;

const MAX_NODES: usize = 16_384;
const MAX_HANDLES: usize = 128;
const MAX_RANGE: u32 = 128 * 1024;
const READ_AHEAD_BYTES: u32 = 64 * 1024;
const READ_AHEAD_MIN_READ: u32 = 16 * 1024;
const READ_VERSION_ATTEMPTS: usize = 3;
const CACHE_MAX_BYTES: usize = 4 * 1024 * 1024;
const CACHE_MAX_ENTRIES: usize = 64;
const MAX_WRITE_FILE: u64 = 1024 * 1024 * 1024 * 1024;
const OFFLINE_DIRECTORY_CACHE_TTL: Duration = Duration::from_secs(2);
const DIRECTORY_CACHE_MAX: usize = 64;
const DIRECTORY_REFRESH_AGE: Duration = Duration::from_secs(30);
// Demand can renew credentials if the scheduler has no usable cached session.
const DIRECTORY_MAX_AGE: Duration = Duration::from_secs(5 * 60);

/// A validated durable mount owner record, which may require recovery.
#[derive(Debug)]
pub struct RecoveryOwner {
    /// Canonical account instance URL.
    pub instance: String,
    /// Space ID bound to the mount.
    pub space_id: String,
    /// Space name captured when the mount was created.
    pub space_name: String,
    /// Absolute mount path.
    pub path: PathBuf,
    /// Unique FUSE source used to verify the mount.
    pub source: String,
}

fn stage_error(error: &AccountError) -> Errno {
    #[cfg(feature = "fault-injection")]
    if std::env::var_os("CIRRUS_TEST_BLOCKER_TRACE").is_some() {
        eprintln!("cirrus lab staging refusal: {error}");
    }
    if error.is_staging_full() {
        Errno::ENOSPC
    } else if error.is_directory_not_empty() {
        Errno::ENOTEMPTY
    } else if error.is_operation_busy() {
        Errno::EBUSY
    } else if error.is_entry_exists() {
        Errno::EEXIST
    } else {
        Errno::EIO
    }
}

#[cfg(feature = "fault-injection")]
fn wait_test_window(variable: &str) -> Result<(), Errno> {
    if let Some(marker) = std::env::var_os(variable) {
        let marker = Path::new(&marker);
        if marker.is_file() {
            std::fs::write(marker.with_extension("waiting"), b"waiting").map_err(|_| Errno::EIO)?;
            for _ in 0..1500 {
                if !marker.exists() {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            return Err(Errno::EIO);
        }
    }
    Ok(())
}

/// A mount owned by this process. Use explicit teardown to unmount it.
pub struct Mounted {
    path: PathBuf,
    instance: String,
    space_id: String,
    space_name: String,
    source: String,
    session: Option<FuseWorker>,
    mount_id: u64,
    runtime: RuntimeDir,
    refresh: NamespaceRefresh,
}

struct FuseWorker {
    background: BackgroundSession,
    device: OwnedFd,
}

/// A lifetime-fenced handle for scheduler-owned, cached-credentials-only refresh.
#[derive(Clone)]
pub struct NamespaceRefresh {
    drive: Drive,
    alive: Arc<AtomicBool>,
    notifier: Option<fuser::Notifier>,
    walk: Arc<Mutex<MountMetadataWalk>>,
}

impl NamespaceRefresh {
    /// Whether a metadata-only warmup batch is ready for admission.
    pub fn walk_ready(&self) -> bool {
        !self.drive.space.is_offline()
            && self.alive.load(Ordering::Acquire)
            && self.walk.lock().is_ok_and(|walk| walk.ready())
    }

    /// Runs one admitted batch using the account's spare metadata read permits.
    ///
    /// # Errors
    /// Reports directory observation or durable publication failures.
    pub fn walk_batch(&self) -> io::Result<bool> {
        let mut walk = self
            .walk
            .lock()
            .map_err(|_| io::Error::other("mount walk unavailable"))?;
        self.drive
            .accounts
            .warm_mount_metadata(
                &self.drive.space,
                &self.drive.browse_id,
                &self.alive,
                &mut walk,
            )
            .map_err(io::Error::other)
    }

    /// Attempts one stale directory which is already in the hot cache.
    /// No token refresh or DAV retry.
    /// Open readdir handles keep their original immutable snapshots.
    ///
    /// # Errors
    /// Reports failed observations/publication without publishing partial views.
    /// Definitive binding loss disables the prior browse view.
    pub fn refresh_one(&self) -> io::Result<()> {
        if self.drive.space.is_offline()
            || !self.alive.load(Ordering::Acquire)
            || self.drive.accounts.background_yield_requested()
        {
            return Ok(());
        }
        let candidate = {
            let mut state = self
                .drive
                .state
                .lock()
                .map_err(|_| io::Error::other("mount state unavailable"))?;
            let index = state
                .directories
                .iter()
                .enumerate()
                .filter(|(_, d)| {
                    d.started.elapsed() >= DIRECTORY_REFRESH_AGE
                        && d.attempted.elapsed() >= DIRECTORY_REFRESH_AGE
                        && !state.directory_flights.contains(&d.ino)
                        && state
                            .live_node(d.ino)
                            .is_some_and(|node| !d.is_denied(&self.drive.space, node))
                })
                .min_by_key(|(_, d)| (Some(d.ino) != state.browse_focus, d.attempted))
                .map(|(index, _)| index);
            index.map(|index| {
                let d = &mut state.directories[index];
                d.attempted = Instant::now();
                let (ino, before) = (d.ino, d.children.clone());
                state.directory_flights.insert(ino);
                (ino, before)
            })
        };
        let Some((ino, before)) = candidate else {
            return Ok(());
        };
        let flight = DirectoryFlight(&self.drive, ino);
        let result = self
            .drive
            .observe_directory(INodeNo(ino), DirectoryObservation::Background(&self.alive));
        drop(flight);
        let after = match result {
            Ok(after) => after,
            Err(Errno::EAGAIN | Errno::EACCES) => return Ok(()),
            Err(error) => {
                return Err(io::Error::other(format!(
                    "background directory observation failed: {error:?}"
                )));
            }
        };
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_NAMESPACE_POLL").is_some() {
            eprintln!("cirrus lab background directory published: ino={ino}");
        }
        if !self.alive.load(Ordering::Acquire) {
            return Ok(());
        }
        let Some(notifier) = &self.notifier else {
            return Ok(());
        };
        // Kernel invalidations are hints, not inotify delivery guarantees.
        // Decode at most one existing 32-name snapshot page at a time.
        for (old, new) in [(&before, &after), (&after, &before)] {
            let mut cursor = 0;
            loop {
                if !self.alive.load(Ordering::Acquire)
                    || self.drive.accounts.background_yield_requested()
                {
                    return Ok(());
                }
                let page = old.0.page(cursor).map_err(io::Error::other)?;
                if page.is_empty() {
                    break;
                }
                for (next, entry) in page {
                    cursor = next;
                    let other = new.0.get(entry.name()).map_err(io::Error::other)?;
                    if other.as_ref().is_none_or(|e| {
                        e.id() != entry.id()
                            || e.etag() != entry.etag()
                            || e.size() != entry.size()
                            || e.is_directory() != entry.is_directory()
                    }) {
                        notifier.inval_entry(INodeNo(ino), OsStr::new(entry.name()))?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for Mounted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mounted")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Mounted {
    /// Number of staged FUSE reads served by admitted cache composition.
    pub fn composed_reads(&self) -> u64 {
        self.refresh.drive.composed_reads.load(Ordering::Relaxed)
    }

    /// Mounts an explicit Space, allowing retained startup only at a custom path.
    ///
    /// # Errors
    /// Returns an error if the Space, mountpoint or FUSE session cannot be validated.
    pub fn start_space(
        accounts: Arc<Accounts>,
        instance: String,
        id: &str,
        path: Option<&Path>,
        runtime: RuntimeDir,
        engine: Arc<ReadEngines>,
    ) -> io::Result<Self> {
        let (space, startup) = if path.is_some() {
            accounts.bind_mount_space(&instance, id)
        } else {
            accounts
                .bind_space(&instance, id)
                .map(|binding| (binding, MountStartup::Normal))
        }
        .map_err(io::Error::other)?;
        let instance = space.instance().to_owned();
        let created_default = path.is_none();
        let default_path;
        let path = if let Some(path) = path {
            path
        } else {
            let name = space.unique_name().ok_or_else(|| {
                io::Error::other(
                    "Space name is duplicated or unavailable; choose a custom mountpoint",
                )
            })?;
            default_path = create_default_mountpoint(name)?;
            &default_path
        };
        Self::start_bound(accounts, instance, space, path, runtime, startup, engine).map_err(|error| {
            if created_default {
                io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; created mountpoint {} was retained",
                        path.display()
                    ),
                )
            } else {
                error
            }
        })
    }

    /// Mounts retained local data read-only without loading credentials.
    ///
    /// # Errors
    /// Refuses invalid ownership, saved activation/metadata or mount lifecycle state.
    pub fn start_offline_space(
        accounts: Arc<Accounts>,
        instance: &str,
        id: &str,
        path: &Path,
        runtime: RuntimeDir,
        engine: Arc<ReadEngines>,
    ) -> io::Result<Self> {
        let space = accounts
            .bind_offline_space(instance, id)
            .map_err(io::Error::other)?;
        Self::start_bound(
            accounts,
            space.instance().to_owned(),
            space,
            path,
            runtime,
            MountStartup::Normal,
            engine,
        )
    }

    /// Mounts retained files for explicit local editing and file creation.
    ///
    /// # Errors
    /// Refuses missing retained bindings, competing account ownership or unsafe mounts.
    pub fn start_writable_offline_space(
        accounts: Arc<Accounts>,
        instance: &str,
        id: &str,
        path: &Path,
        runtime: RuntimeDir,
        engine: Arc<ReadEngines>,
    ) -> io::Result<Self> {
        let space = accounts
            .bind_writable_offline_space(instance, id)
            .map_err(io::Error::other)?;
        Self::start_bound(
            accounts,
            space.instance().to_owned(),
            space,
            path,
            runtime,
            MountStartup::Normal,
            engine,
        )
    }

    fn start_bound(
        accounts: Arc<Accounts>,
        instance: String,
        space: MountBinding,
        path: &Path,
        runtime: RuntimeDir,
        startup: MountStartup,
        engine: Arc<ReadEngines>,
    ) -> io::Result<Self> {
        recovery::ensure_available(&runtime, path)?;
        let seed = if matches!(startup, MountStartup::Normal) {
            let generation = accounts.metadata_generation();
            let started = Instant::now();
            let entries = accounts
                .mount_directory(&instance, &space, &[], "")
                .map_err(io::Error::other)?;
            Some((entries, generation, started))
        } else {
            // Retained startup verified eligibility, not a current DAV view.
            None
        };
        let dir = validate_mountpoint(path)?;
        let identity = fs::fstat(&dir).map_err(io::Error::from)?;
        let rechecked = validate_mountpoint(path)?;
        let now = fs::fstat(&rechecked).map_err(io::Error::from)?;
        if (identity.st_dev, identity.st_ino) != (now.st_dev, now.st_ino) {
            return Err(io::Error::other(
                "mount directory changed during validation",
            ));
        }
        let mount_instance = space.instance().to_owned();
        let space_id = space.space_id().to_owned();
        let space_name = space.unique_name().unwrap_or(space.space_id()).to_owned();
        let source = recovery::prepare(&runtime, path, &mount_instance, &space_id, &space_name)?;
        #[cfg(feature = "fault-injection")]
        fault_stop("prepared")?;
        let check = validate_mountpoint(path).and_then(|fd| {
            let current = fs::fstat(&fd).map_err(io::Error::from)?;
            if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino) {
                return Err(io::Error::other(
                    "mount directory changed during preparation",
                ));
            }
            Ok(())
        });
        if let Err(error) = check {
            if let Err(cleanup) = recovery::recover(&runtime, path) {
                return Err(io::Error::other(format!(
                    "mountpoint validation failed: {error}; prepared record requires recovery: {cleanup}"
                )));
            }
            return Err(error);
        }
        let offline = space.is_offline();
        let mut config = Config::default();
        config.n_threads = Some(4);
        let filesystem = Drive::new(accounts.clone(), instance, space.clone(), source.clone(), engine);
        let walk_seed = seed.and_then(|(entries, generation, started)| {
            // Reuse the preflight without making a capacity error fatal to mount startup.
            filesystem
                .observe_directory(
                    INodeNo(1),
                    DirectoryObservation::Seed {
                        entries,
                        generation,
                        started,
                    },
                )
                .ok()
                .map(|view| view.0)
        });
        let refresh_drive = filesystem.clone();
        let start = (|| -> io::Result<_> {
            let device = session::mount(path, &source, offline && !space.is_offline_writable())?;
            let mount_id = recovery::mount_state(path, &source)?
                .exact_id
                .ok_or_else(|| io::Error::other("cannot verify the new FUSE mount identity"))?;
            // from_fd never installs fuser's pathname-unmount guard.
            let background =
                Session::from_fd(filesystem, device.try_clone()?, config.acl, config)?.spawn()?;
            Ok((FuseWorker { background, device }, mount_id))
        })();
        let (session, mount_id) = match start {
            Ok(mounted) => mounted,
            Err(error) => {
                if let Err(cleanup) = recovery::recover(&runtime, path) {
                    return Err(io::Error::other(format!(
                        "mount failed: {error}; prepared record requires recovery: {cleanup}"
                    )));
                }
                return Err(error);
            }
        };
        #[cfg(feature = "fault-injection")]
        fault_stop("mounted")?;
        let refresh = NamespaceRefresh {
            drive: refresh_drive,
            alive: Arc::new(AtomicBool::new(true)),
            notifier: Some(session.background.notifier()),
            walk: Arc::new(Mutex::new(MountMetadataWalk::new(walk_seed))),
        };
        let mut mounted = Self {
            path: path.to_owned(),
            instance: mount_instance,
            space_id,
            space_name,
            source,
            session: Some(session),
            mount_id,
            runtime,
            refresh,
        };
        if let Err(error) = if !offline && matches!(startup, MountStartup::Normal) {
            accounts.activate_sync(&space)
        } else {
            Ok(())
        } {
            // Activation can refuse after FUSE starts. Do not return an
            // unregistered live mount or leave its prepared owner record on
            // ordinary denial. Cleanup is source-checked and never budgeted.
            if let Err(cleanup) = mounted.unmount() {
                return Err(io::Error::other(format!(
                    "activation failed: {error}; mount requires recovery: {cleanup}"
                )));
            }
            return Err(io::Error::other(format!(
                "activation failed; mount removed: {error}"
            )));
        }
        Ok(mounted)
    }

    /// Returns the selected mountpoint.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the account instance used to start this mount.
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Returns the verified Space ID for this mount.
    pub fn space_id(&self) -> &str {
        &self.space_id
    }

    /// Returns the verified unique Space name, or its ID when unavailable.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }

    /// Returns the unique FUSE source recorded for this mount.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Whether the live mount serves local retained data without authentication.
    pub fn is_offline(&self) -> bool {
        self.refresh.drive.space.is_offline()
    }
    /// Whether explicit local editing and file creation are enabled.
    pub fn is_offline_writable(&self) -> bool {
        self.refresh.drive.space.is_offline_writable()
    }

    /// Returns a refresh handle that cannot publish after this mount is retired.
    pub fn namespace_refresh(&self) -> NamespaceRefresh {
        self.refresh.clone()
    }

    /// Checks whether the recorded FUSE mount is still at its original path.
    ///
    /// # Errors
    /// Returns an error if the mountpoint cannot be inspected.
    pub fn is_active(&self) -> io::Result<bool> {
        Ok(!self.is_disconnected()?
            && recovery::mount_state(&self.path, &self.source)?.exact_id == Some(self.mount_id))
    }

    /// Checks the original mount ID in a previously read namespace table.
    /// Inspect the device separately with [`Self::is_disconnected`].
    pub fn matches_mount_table(&self, table: &MountTable) -> bool {
        table.exact_id(&self.path, &self.source) == Some(self.mount_id)
    }

    /// Checks the old kernel connection, independent of its mountpoint.
    ///
    /// # Errors
    /// Reports an unexpected FUSE descriptor polling error.
    pub fn is_disconnected(&self) -> io::Result<bool> {
        match &self.session {
            Some(worker) => session::disconnected(&worker.device),
            None => Ok(true),
        }
    }

    /// Joins an externally disconnected FUSE worker without unmounting any path.
    ///
    /// # Errors
    /// Refuses a live session or cleanup of an ambiguous or occupied mountpoint.
    pub fn recover_disconnected(&mut self) -> io::Result<()> {
        if !self.is_disconnected()? {
            return Err(io::Error::other("unmount the active Space first"));
        }
        self.quiesce_refresh()?;
        self.refresh.notifier.take();
        if let Some(worker) = self.session.take() {
            worker.background.join()?;
        }
        recovery::remove_owned(self)
    }

    fn quiesce_refresh(&self) -> io::Result<()> {
        self.refresh.alive.store(false, Ordering::Release);
        // A publication already holding this short lock completes first. DAV
        // never holds it; a retired handle checks alive again before the swap.
        drop(
            self.refresh
                .drive
                .mutation
                .lock()
                .map_err(|_| io::Error::other("mount publication unavailable"))?,
        );
        Ok(())
    }

    /// Unmounts and joins the FUSE session.
    ///
    /// # Errors
    /// Returns an error when the unmount or FUSE worker fails.
    pub fn unmount(&mut self) -> io::Result<()> {
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_UNMOUNT_FAILURE")
            .is_some_and(|marker| Path::new(&marker).is_file())
        {
            return Err(io::Error::other("injected unmount failure"));
        }
        if self.is_disconnected()? {
            return self.recover_disconnected();
        }
        self.quiesce_refresh()?;
        let unmount = (|| {
            if recovery::mount_state(&self.path, &self.source)?.exact_id != Some(self.mount_id)
                || mount_id(&self.path)? != self.mount_id
            {
                return Err(io::Error::other(
                    "mountpoint identity changed; refusing to unmount",
                ));
            }
            if self.is_disconnected()? {
                return Ok(());
            }
            session::unmount(&self.path)
        })();
        if self.is_disconnected()? {
            return self.recover_disconnected();
        }
        self.refresh.alive.store(true, Ordering::Release);
        unmount?;
        // A connection may outlive removal of one attachment (e.g. a mount
        // cloned into another namespace). Do not wait forever for that worker.
        Err(io::Error::other(
            "mount detached but the FUSE connection is still live",
        ))
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        self.refresh.alive.store(false, Ordering::Release);
    }
}

#[cfg(feature = "fault-injection")]
fn fault_stop(stage: &str) -> io::Result<()> {
    if std::env::var("CIRRUS_TEST_MOUNT_STOP").as_deref() == Ok(stage) {
        eprintln!("cirrus lab mount stop: {stage}");
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGSTOP).map_err(io::Error::from)?;
    }
    Ok(())
}

/// Removes only the stale mount recorded by Cirrus in this runtime and mount namespace.
///
/// # Errors
/// Returns an error if the record, mount identity or unmount cannot be verified.
pub fn recover(runtime: &RuntimeDir, path: &Path) -> io::Result<()> {
    recovery::recover(runtime, path)
}

/// Lists paths and FUSE sources from verified mount owner records.
///
/// # Errors
/// Returns an error if any owner record is unsafe or invalid.
pub fn recovery_owners(runtime: &RuntimeDir) -> io::Result<Vec<RecoveryOwner>> {
    recovery::owners(runtime)
}

fn mount_id(path: &Path) -> io::Result<u64> {
    let stat = fs::statx(fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW, StatxFlags::MNT_ID)
        .map_err(io::Error::from)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(io::Error::other("kernel did not return a mount identity"));
    }
    Ok(stat.stx_mnt_id)
}

fn create_default_mountpoint(name: &str) -> io::Result<PathBuf> {
    if name.is_empty()
        || name.trim() != name
        || name == "."
        || name == ".."
        || name.len() > 255
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe Space name; choose a custom mountpoint",
        ));
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| io::Error::other("HOME is unavailable; choose a custom mountpoint"))?;
    let home = std::fs::canonicalize(home)?;
    let dir = fs::openat2(
        fs::CWD,
        &home,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let stat = fs::fstat(&dir).map_err(io::Error::from)?;
    if stat.st_uid != process::geteuid().as_raw() || stat.st_mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "home directory has unsafe ownership or permissions",
        ));
    }
    fs::mkdirat(&dir, name, Mode::from_raw_mode(0o700)).map_err(|error| {
        let error = io::Error::from(error);
        if error.kind() == io::ErrorKind::AlreadyExists {
            io::Error::new(
                error.kind(),
                "default mountpoint already exists and will not be reused",
            )
        } else {
            error
        }
    })?;
    fs::fsync(&dir).map_err(|error| {
        io::Error::new(
            io::Error::from(error).kind(),
            format!(
                "cannot persist home directory; created mountpoint {} was retained",
                home.join(name).display()
            ),
        )
    })?;
    Ok(home.join(name))
}

fn validate_mountpoint(path: &Path) -> io::Result<std::os::fd::OwnedFd> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mountpoint must be an absolute directory without dot components",
        ));
    }
    if path.canonicalize()? != path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mountpoint path must be canonical",
        ));
    }
    let fd = fs::openat2(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let stat = fs::fstat(&fd).map_err(io::Error::from)?;
    if stat.st_uid != process::geteuid().as_raw() || stat.st_mode & 0o7777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mountpoint must be user-owned with mode 0700",
        ));
    }
    let mut entries = Dir::read_from(&fd).map_err(io::Error::from)?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(io::Error::from)?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "mountpoint is not empty",
            ));
        }
    }
    let escaped = escape_mount_path(path);
    // mountinfo is read before mounting; do not cover any existing mount.
    let info = std::fs::read_to_string("/proc/self/mountinfo")?;
    if info
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .any(|mount| {
            mount.as_bytes() == escaped
                || (mount.as_bytes().starts_with(&escaped)
                    && mount.as_bytes().get(escaped.len()) == Some(&b'/'))
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "mountpoint is already mounted",
        ));
    }
    Ok(fd)
}

fn escape_mount_path(path: &Path) -> Vec<u8> {
    path.as_os_str()
        .as_bytes()
        .iter()
        .fold(Vec::new(), |mut out, &b| {
            match b {
                b' ' => out.extend_from_slice(b"\\040"),
                b'\t' => out.extend_from_slice(b"\\011"),
                b'\n' => out.extend_from_slice(b"\\012"),
                b'\\' => out.extend_from_slice(b"\\134"),
                _ => out.push(b),
            };
            out
        })
}

#[derive(Clone)]
// Slots are allocated before a journal fence and bound once to its actual result.
struct SharedVersion(Arc<std::sync::OnceLock<FileVersion>>);

impl SharedVersion {
    fn new(version: FileVersion) -> Self {
        let owner = Self::unbound();
        owner.bind(version);
        owner
    }

    fn unbound() -> Self {
        Self(Arc::new(std::sync::OnceLock::new()))
    }

    fn bind(&self, version: FileVersion) {
        assert!(self.0.set(version).is_ok(), "version already bound");
    }

    fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::ops::Deref for SharedVersion {
    type Target = FileVersion;

    fn deref(&self) -> &FileVersion {
        self.0.get().expect("published version is bound")
    }
}

impl PartialEq for SharedVersion {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for SharedVersion {}

impl PartialEq<FileVersion> for SharedVersion {
    fn eq(&self, other: &FileVersion) -> bool {
        **self == *other
    }
}

impl PartialEq<SharedVersion> for FileVersion {
    fn eq(&self, other: &SharedVersion) -> bool {
        *self == **other
    }
}

#[cfg(feature = "fault-injection")]
impl std::hash::Hash for SharedVersion {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&**self, state);
    }
}

#[derive(Clone)]
enum ResourceText {
    Literal(String),
    VersionId(SharedVersion),
    VersionTag(SharedVersion),
}

impl From<String> for ResourceText {
    fn from(value: String) -> Self {
        Self::Literal(value)
    }
}

impl ResourceText {
    fn as_str(&self) -> &str {
        self
    }

    fn bind_directory_id(identity: &mut String, id: i64) {
        // "cirrus-dir:" plus any signed i64 fits the prepared 32-byte buffer.
        let mut digits = [0u8; 20];
        let mut remaining = id.unsigned_abs();
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        if id < 0 {
            identity.push('-');
        }
        for digit in &digits[start..] {
            identity.push(char::from(*digit));
        }
    }
}

impl std::ops::Deref for ResourceText {
    type Target = str;

    fn deref(&self) -> &str {
        match self {
            Self::Literal(value) => value,
            Self::VersionId(version) => version.id(),
            Self::VersionTag(version) => version.etag(),
        }
    }
}

impl PartialEq for ResourceText {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for ResourceText {}

impl PartialEq<&str> for ResourceText {
    fn eq(&self, other: &&str) -> bool {
        **self == **other
    }
}

impl PartialEq<ResourceText> for &str {
    fn eq(&self, other: &ResourceText) -> bool {
        **self == **other
    }
}

impl PartialEq<String> for ResourceText {
    fn eq(&self, other: &String) -> bool {
        **self == **other
    }
}

#[cfg(feature = "fault-injection")]
impl std::hash::Hash for ResourceText {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&**self, state);
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "fault-injection", derive(Hash))]
struct Node {
    path: Vec<String>,
    parent: u64,
    directory: bool,
    size: u64,
    modified: SystemTime,
    resource_id: ResourceText,
    etag: Option<ResourceText>,
    checksums: Vec<String>,
    revision: u64,
}

impl Node {
    fn matches_version(&self, version: &FileVersion) -> bool {
        !self.directory
            && self.resource_id == version.id()
            && self.etag.as_deref() == Some(version.etag())
            && self.size == version.size()
            && self.checksums == version.checksums()
    }
}

#[derive(Clone)]
struct Namespace {
    nodes: HashMap<u64, Node>,
    paths: HashMap<Vec<String>, u64>,
    scans: HashMap<u64, u64>,
    mutation_epoch: u64,
    observed: HashMap<Vec<String>, (String, String)>,
    observations_exhausted: bool,
}

struct State {
    namespace: Arc<Namespace>,
    next_node: u64,
    next_handle: u64,
    handles: HashMap<u64, OpenDirectory>,
    files: HashMap<u64, OpenFile>,
    detached: HashMap<u64, Arc<Node>>,
    cache: VecDeque<Arc<CachedRange>>,
    cache_bytes: usize,
    cache_generation: u64,
    directories: VecDeque<CachedDirectory>,
    directory_flights: HashSet<u64>,
    browse_focus: Option<u64>,
    next_scan: u64,
}

struct ListingEffects {
    promotions: Vec<FilePromotion>,
    invalidated_handles: Vec<u64>,
    removed_range_versions: Vec<SharedVersion>,
}

struct FilePromotion {
    handle: u64,
    expected: SharedVersion,
    replacement: SharedVersion,
}

struct PreparedListing {
    namespace: Namespace,
    next_node: u64,
    children: DirectoryView,
    promotions: Vec<(usize, u64)>,
    invalidated: Vec<String>,
}

impl std::ops::Deref for State {
    type Target = Namespace;

    fn deref(&self) -> &Namespace {
        &self.namespace
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct RangeKey {
    version: FileVersion,
    offset: u64,
    length: u32,
    staged_cache_generation: Option<u64>,
}

#[derive(Clone, Copy)]
enum RangePriority<'a> {
    Foreground,
    Staged(u64),
    ReadAhead(&'a str),
}

impl RangePriority<'_> {
    fn read(
        self,
        accounts: &Accounts,
        binding: &MountBinding,
        version: &FileVersion,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, AccountError> {
        match self {
            Self::Foreground | Self::Staged(_) => {
                accounts.read_range(binding, version, offset, length)
            }
            Self::ReadAhead(id) => accounts.read_range_ahead(binding, version, offset, length, id),
        }
    }
}

struct Flight {
    result: Mutex<Option<Result<Vec<u8>, ()>>>,
    ready: Condvar,
    speculative: bool,
}

struct FlightLeader<'a> {
    flights: &'a Mutex<HashMap<RangeKey, Arc<Flight>>>,
    key: Option<RangeKey>,
    flight: Arc<Flight>,
}

impl FlightLeader<'_> {
    fn complete(mut self, result: Result<Vec<u8>, ()>) -> Result<(), Errno> {
        {
            let mut shared = self.flight.result.lock().map_err(|_| Errno::EIO)?;
            *shared = Some(result);
            self.flight.ready.notify_all();
        }
        self.retire()
    }

    fn retire(&mut self) -> Result<(), Errno> {
        let mut flights = self.flights.lock().map_err(|_| Errno::EIO)?;
        if let Some(key) = self.key.take()
            && flights
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &self.flight))
        {
            flights.remove(&key);
        }
        Ok(())
    }
}

impl Drop for FlightLeader<'_> {
    fn drop(&mut self) {
        if self.key.is_none() {
            return;
        }
        if let Ok(mut shared) = self.flight.result.lock()
            && shared.is_none()
        {
            *shared = Some(Err(()));
        }
        self.flight.ready.notify_all();
        let _ = self.retire();
    }
}

#[derive(Clone, PartialEq, Eq)]
struct CachedRange {
    version: SharedVersion,
    offset: u64,
    bytes: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
struct CachedDirectory {
    ino: u64,
    remote_path: Vec<String>,
    parent_revision: u64,
    rejected: bool,
    started: Instant,
    attempted: Instant,
    mutation_epoch: u64,
    metadata_generation: u64,
    children: DirectoryView,
}

impl CachedDirectory {
    fn is_denied(&self, binding: &MountBinding, node: &Node) -> bool {
        binding.directory_denied(&self.remote_path, &node.resource_id)
    }
}

enum DirectoryObservation<'a> {
    Demand,
    Browse,
    Background(&'a AtomicBool),
    Seed {
        entries: DirectorySnapshot,
        generation: u64,
        started: Instant,
    },
}

struct DirectoryFlight<'a>(&'a Drive, u64);

impl Drop for DirectoryFlight<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.directory_flights.remove(&self.1);
            self.0.directory_ready.notify_all();
        }
    }
}

#[derive(Clone)]
struct DirectoryView(DirectorySnapshot);

impl PartialEq for DirectoryView {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl Eq for DirectoryView {}

impl DirectoryView {
    fn find(&self, name: &str) -> Result<Option<(u64, FileType, String)>, Errno> {
        Ok(self.0.child(name).map_err(|_| Errno::EIO)?.map(|entry| {
            (
                entry.inode,
                if entry.directory {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                },
                entry.name,
            )
        }))
    }
    fn page(&self, after: u64) -> Result<Vec<(u64, u64, FileType, String)>, Errno> {
        Ok(self
            .0
            .children(after)
            .map_err(|_| Errno::EIO)?
            .into_iter()
            .map(|entry| {
                (
                    entry.cookie,
                    entry.inode,
                    if entry.directory {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    },
                    entry.name,
                )
            })
            .collect())
    }

    fn is_empty(&self) -> Result<bool, Errno> {
        self.0.is_empty().map_err(|_| Errno::EIO)
    }

    fn matches(&self, expected: &Self) -> bool {
        self.0.same_observation(&expected.0)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct OpenDirectory {
    ino: u64,
    parent: u64,
    children: DirectoryView,
}

struct PreparedRenameFile {
    ino: u64,
    node: Node,
    version: FileVersion,
    data: Option<DirtyMutation<'static>>,
}

struct LockedRenameInputs<'a> {
    guard: MutexGuard<'a, ()>,
    source: DirectoryView,
    destination: DirectoryView,
    source_children: Option<DirectoryView>,
    destination_children: Option<DirectoryView>,
    source_file: Option<PreparedRenameFile>,
}

#[cfg(feature = "fault-injection")]
fn publication_witness(
    namespace: &Namespace,
    next_node: u64,
    detached: &[(u64, Arc<Node>)],
    files: &[(u64, OpenFile)],
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    let mut nodes: Vec<_> = namespace
        .nodes
        .iter()
        .chain(detached.iter().map(|(id, node)| (id, &**node)))
        .collect();
    nodes.sort_unstable_by_key(|(id, _)| **id);
    nodes.hash(&mut hash);
    let mut paths: Vec<_> = namespace.paths.iter().collect();
    paths.sort_unstable_by_key(|(path, _)| *path);
    paths.hash(&mut hash);
    let mut files: Vec<_> = files.iter().map(|(id, file)| (id, file)).collect();
    files.sort_unstable_by_key(|(id, _)| **id);
    files.hash(&mut hash);
    next_node.hash(&mut hash);
    namespace.mutation_epoch.hash(&mut hash);
    hash.finish()
}

impl Namespace {
    fn parent_identities(
        &self,
        path: &[String],
    ) -> Result<Vec<cirrus_account::DirectoryIdentity>, Errno> {
        if path.is_empty() {
            return Err(Errno::EINVAL);
        }
        let mut result = Vec::with_capacity(path.len() - 1);
        let mut parent = 1;
        for depth in 1..path.len() {
            let prefix = &path[..depth];
            let id = *self.paths.get(prefix).ok_or(Errno::ENOENT)?;
            let node = self.nodes.get(&id).ok_or(Errno::ENOENT)?;
            if !node.directory || node.parent != parent || node.path != prefix {
                return Err(Errno::EIO);
            }
            result.push(
                cirrus_account::DirectoryIdentity::from_resource_id(&node.resource_id)
                    .map_err(|_| Errno::EIO)?,
            );
            parent = id;
        }
        Ok(result)
    }
}

impl State {
    fn read_file(&self, ino: INodeNo, handle: FileHandle) -> Result<&OpenFile, Errno> {
        let file = self
            .files
            .get(&handle.0)
            .filter(|file| file.ino == ino.0)
            .ok_or(Errno::EBADF)?;
        if file.failed {
            return Err(Errno::EIO);
        }
        Ok(file)
    }

    fn live_node(&self, ino: u64) -> Option<&Node> {
        self.nodes
            .get(&ino)
            .filter(|node| self.paths.get(&node.path) == Some(&ino))
    }

    fn retire_ranges(
        &mut self,
        retired: &mut Vec<Arc<CachedRange>>,
        remove: impl Fn(&CachedRange) -> bool,
    ) {
        let mut index = 0;
        while index < self.cache.len() {
            if remove(&self.cache[index]) {
                retired.push(self.cache.remove(index).expect("present range"));
            } else {
                index += 1;
            }
        }
        self.cache_bytes = self.cache.iter().map(|entry| entry.bytes.len()).sum();
    }

    fn refresh_cache_generation(&mut self, generation: u64, retired: &mut Vec<Arc<CachedRange>>) {
        if self.cache_generation != generation {
            self.retire_ranges(retired, |_| true);
            self.cache_generation = generation;
        }
    }

    fn invalidate_id(&mut self, id: &str, retired: &mut Vec<Arc<CachedRange>>) {
        self.retire_ranges(retired, |entry| entry.version.id() == id);
        for file in self.files.values_mut() {
            if file.version.id() == id {
                file.failed = true;
            }
        }
    }

    fn observe_version(&mut self, version: &FileVersion, retired: &mut Vec<Arc<CachedRange>>) {
        let changed = self
            .cache
            .iter()
            .any(|entry| entry.version.same_resource(version) && entry.version != *version)
            || self.files.values().any(|file| {
                file.version.same_resource(version) && *file.version != *version && !file.failed
            });
        if changed {
            self.invalidate_id(version.id(), retired);
        }
    }

    fn insert_range(&mut self, entry: Arc<CachedRange>, retired: &mut Vec<Arc<CachedRange>>) {
        while self.cache.len() >= CACHE_MAX_ENTRIES
            || self.cache_bytes + entry.bytes.len() > CACHE_MAX_BYTES
        {
            if let Some(oldest) = self.cache.pop_front() {
                self.cache_bytes -= oldest.bytes.len();
                retired.push(oldest);
            } else {
                retired.push(entry);
                return;
            }
        }
        self.cache_bytes += entry.bytes.len();
        self.cache.push_back(entry);
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "fault-injection", derive(Hash))]
struct OpenFile {
    ino: u64,
    version: SharedVersion,
    namespace_rebind: u64,
    failed: bool,
    writable: bool,
    append: bool,
    last_read: Option<(u64, u32)>,
}

impl OpenFile {
    // Only ordinary content publication may change the version within a
    // read's original lineage. Namespace changes must not be retried as writes.
    fn rebind_namespace(&mut self, version: SharedVersion) -> SharedVersion {
        self.namespace_rebind = self.namespace_rebind.wrapping_add(1);
        self.last_read = None;
        std::mem::replace(&mut self.version, version)
    }
}

struct ReadAheadLease(Arc<Accounts>);

impl Drop for ReadAheadLease {
    fn drop(&mut self) {
        self.0.release_read_ahead();
    }
}

#[derive(Clone)]
struct Drive {
    accounts: Arc<Accounts>,
    instance: String,
    space: MountBinding,
    browse_id: String,
    state: Arc<Mutex<State>>,
    directory_ready: Arc<Condvar>,
    flights: Arc<Mutex<HashMap<RangeKey, Arc<Flight>>>>,
    mutation: Arc<Mutex<()>>,
    engine: Arc<ReadEngines>,
    composed_reads: Arc<AtomicU64>,
}

impl Drive {
    fn new(
        accounts: Arc<Accounts>,
        instance: String,
        space: MountBinding,
        browse_id: String,
        engine: Arc<ReadEngines>,
    ) -> Self {
        let cache_generation = accounts.clean_cache_generation();
        let root = Node {
            path: Vec::new(),
            parent: 1,
            directory: true,
            size: 0,
            modified: UNIX_EPOCH,
            resource_id: String::new().into(),
            etag: None,
            checksums: Vec::new(),
            revision: 0,
        };
        Self {
            accounts,
            instance,
            space,
            browse_id,
            engine,
            composed_reads: Arc::new(AtomicU64::new(0)),
            state: Arc::new(Mutex::new(State {
                namespace: Arc::new(Namespace {
                    nodes: HashMap::from([(1, root)]),
                    paths: HashMap::from([(Vec::new(), 1)]),
                    scans: HashMap::new(),
                    mutation_epoch: 0,
                    observed: HashMap::new(),
                    observations_exhausted: false,
                }),
                next_node: 2,
                next_handle: 1,
                handles: HashMap::with_capacity(MAX_HANDLES),
                files: HashMap::with_capacity(MAX_HANDLES),
                detached: HashMap::with_capacity(MAX_HANDLES * 2),
                cache: VecDeque::with_capacity(CACHE_MAX_ENTRIES),
                cache_bytes: 0,
                cache_generation,
                directories: VecDeque::with_capacity(DIRECTORY_CACHE_MAX),
                directory_flights: HashSet::new(),
                browse_focus: None,
                next_scan: 1,
            })),
            directory_ready: Arc::new(Condvar::new()),
            flights: Arc::new(Mutex::new(HashMap::new())),
            mutation: Arc::new(Mutex::new(())),
        }
    }

    fn namespace(&self) -> Result<Arc<Namespace>, Errno> {
        Ok(self.state.lock().map_err(|_| Errno::EIO)?.namespace.clone())
    }

    fn node(&self, ino: INodeNo) -> Result<Node, Errno> {
        let state = self.namespace()?;
        let id = u64::from(ino);
        let node = state.nodes.get(&id).ok_or(Errno::ENOENT)?;
        if state.paths.get(&node.path) != Some(&id) {
            return Err(Errno::ENOENT);
        }
        Ok(node.clone())
    }

    fn browse<T>(
        &self,
        ino: INodeNo,
        read: impl Fn(&State, &Node, &CachedDirectory) -> Option<T>,
    ) -> Result<T, Errno> {
        let max_age = if self.space.is_offline() {
            OFFLINE_DIRECTORY_CACHE_TTL
        } else {
            DIRECTORY_MAX_AGE
        };
        let mut attempts = 0;
        loop {
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            let parent = state.live_node(ino.0).ok_or(Errno::ENOENT)?;
            if !parent.directory {
                return Err(Errno::ENOTDIR);
            }
            // A successful scan publishes a complete DirectoryView and its
            // immediate children in the namespace together. A replacement
            // removes old inode bindings; local edits change the mutation epoch.
            // No snapshot pages or SQL are needed to validate this cache hit.
            let generation = self.accounts.metadata_generation();
            if let Some(cached) = state.directories.iter().find(|d| {
                d.ino == ino.0
                    && d.parent_revision == parent.revision
                    && !d.rejected
                    && !d.is_denied(&self.space, parent)
                    && d.mutation_epoch == state.mutation_epoch
                    && d.metadata_generation == generation
                    && d.started.elapsed() < max_age
            }) && let Some(result) = read(&state, parent, cached)
            {
                return Ok(result);
            }
            if state.directory_flights.contains(&ino.0) {
                drop(self.directory_ready.wait(state).map_err(|_| Errno::EIO)?);
                continue;
            }
            if attempts == 8 {
                return Err(Errno::EIO);
            }
            attempts += 1;
            state.directory_flights.insert(ino.0);
            drop(state);
            let flight = DirectoryFlight(self, ino.0);
            let observation = if attempts == 1 {
                DirectoryObservation::Browse
            } else {
                DirectoryObservation::Demand
            };
            let result = self.observe_directory(ino, observation);
            drop(flight);
            match result {
                Ok(_) | Err(Errno::EAGAIN) => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn browse_entry(&self, parent: INodeNo, name: &str) -> Result<Option<(u64, Node)>, Errno> {
        self.browse(parent, |state, parent, cached| {
            let mut path = parent.path.clone();
            path.push(name.to_owned());
            if let Some(id) = state.paths.get(&path)
                && let Some(node) = state.nodes.get(id)
            {
                return Some(Some((*id, node.clone())));
            }
            // A name missing from a complete, recent view is a cheap negative.
            // Older negatives demand an observation if background hasn't caught up.
            (cached.started.elapsed() < DIRECTORY_REFRESH_AGE).then_some(None)
        })
    }

    // The returned guard keeps the validated parent stable through journaling.
    fn lock_vacant_parent(
        &self,
        parent: INodeNo,
        name: &str,
    ) -> Result<(MutexGuard<'_, ()>, Node), Errno> {
        for _ in 0..8 {
            let epoch = self.state.lock().map_err(|_| Errno::EIO)?.mutation_epoch;
            let generation = self.accounts.metadata_generation();
            let parent_node = self.node(parent)?;
            let siblings = self.fresh_directory(parent)?;
            if siblings.find(name)?.is_some() {
                return Err(Errno::EEXIST);
            }
            let guard = self.mutation.lock().map_err(|_| Errno::EIO)?;
            let state = self.state.lock().map_err(|_| Errno::EIO)?;
            if state.mutation_epoch != epoch
                || self.accounts.metadata_generation() != generation
                || state.paths.get(&parent_node.path) != Some(&parent.0)
                || !state.nodes.get(&parent.0).is_some_and(|current| {
                    current.resource_id == parent_node.resource_id
                        && current.revision == parent_node.revision
                })
                || !state.directories.iter().any(|cached| {
                    cached.ino == parent.0
                        && cached.mutation_epoch == epoch
                        && cached.metadata_generation == generation
                        && !cached.is_denied(&self.space, &parent_node)
                        && cached.children.matches(&siblings)
                })
            {
                continue;
            }
            drop(state);
            return Ok((guard, parent_node));
        }
        Err(Errno::EIO)
    }

    // Revalidate read-only observations before staging and keep the final guard.
    fn lock_rename_inputs(
        &self,
        parent: INodeNo,
        newparent: INodeNo,
        name: &str,
        newname: &str,
        flags: RenameFlags,
        foreground: &mut Option<cirrus_account::ForegroundPriority>,
    ) -> Result<LockedRenameInputs<'_>, Errno> {
        for _ in 0..8 {
            let epoch = self.state.lock().map_err(|_| Errno::EIO)?.mutation_epoch;
            let generation = self.accounts.metadata_generation();
            let source_parent = self.node(parent)?;
            let destination_parent = self.node(newparent)?;
            let source = self.fresh_directory(parent)?;
            let destination = if parent == newparent {
                source.clone()
            } else {
                self.fresh_directory(newparent)?
            };
            let source_entry = source.find(name)?;
            let target_entry = destination.find(newname)?;
            let source_directory = source_entry
                .as_ref()
                .filter(|entry| entry.1 == FileType::Directory)
                .map(|entry| self.node(INodeNo(entry.0)).map(|node| (entry.0, node)))
                .transpose()?;
            let target_directory = target_entry
                .as_ref()
                .filter(|entry| entry.1 == FileType::Directory)
                .map(|entry| self.node(INodeNo(entry.0)).map(|node| (entry.0, node)))
                .transpose()?;
            let same_path = parent == newparent && name == newname;
            let inspect_children = !same_path
                && !(target_entry.is_some() && flags.contains(RenameFlags::RENAME_NOREPLACE));
            let source_is_file = source_entry
                .as_ref()
                .is_some_and(|entry| entry.1 == FileType::RegularFile);
            if source_is_file && foreground.is_none() {
                // Keep metadata-only source/open-target preservation roots out
                // of fresh automatic claims through every outer rename retry.
                *foreground = Some(self.accounts.request_foreground());
            }
            let target_file = if inspect_children && source_is_file {
                target_entry
                    .as_ref()
                    .filter(|entry| entry.1 == FileType::RegularFile)
                    .map(|entry| self.node(INodeNo(entry.0)).map(|node| (entry.0, node)))
                    .transpose()?
            } else {
                None
            };
            let (target_open, target_handles_match) = if let Some((id, node)) = &target_file {
                let state = self.state.lock().map_err(|_| Errno::EIO)?;
                (
                    state.files.values().any(|file| file.ino == *id),
                    state.files.values().all(|file| {
                        file.ino != *id
                            || file.failed
                            || (file.version.id() == node.resource_id
                                && Some(file.version.etag()) == node.etag.as_deref()
                                && file.version.size() == node.size)
                    }),
                )
            } else {
                (false, true)
            };
            let target_prepared = if let Some((id, node)) = &target_file {
                if target_open
                    && target_handles_match
                    && node.etag.is_some()
                    && !node.resource_id.starts_with("cirrus-staged:")
                {
                    let Some(prepared) =
                        self.load_rename_file(*id, node.clone(), true, epoch, generation)?
                    else {
                        continue;
                    };
                    Some(prepared)
                } else {
                    None
                }
            } else {
                None
            };
            let target_allows_hydration = if target_entry.is_none() {
                true
            } else if let Some((_, node)) = &target_file {
                node.etag.is_some()
                    && (!target_open
                        || (node.resource_id.starts_with("cirrus-staged:") && target_handles_match))
            } else {
                false
            };
            let source_file = if inspect_children && target_allows_hydration {
                match source_entry
                    .as_ref()
                    .filter(|entry| entry.1 == FileType::RegularFile)
                {
                    Some(entry) => {
                        let node = self.node(INodeNo(entry.0))?;
                        if node.resource_id.starts_with("cirrus-staged:") {
                            None
                        } else {
                            #[cfg(feature = "fault-injection")]
                            wait_test_window("CIRRUS_TEST_RENAME_HYDRATION_WINDOW")?;
                            let Some(prepared) = self.load_rename_file(
                                entry.0,
                                node,
                                self.space.is_offline(),
                                epoch,
                                generation,
                            )?
                            else {
                                continue;
                            };
                            Some(prepared)
                        }
                    }
                    None => None,
                }
            } else {
                None
            };
            let source_children = if inspect_children && target_entry.is_none() {
                if let Some((id, node)) = &source_directory {
                    if !node.resource_id.starts_with("cirrus-dir:") {
                        Some((*id, node.clone(), self.fresh_directory(INodeNo(*id))?))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let destination_children = if inspect_children {
                match (&source_directory, &target_directory) {
                    (Some((_, source_node)), Some((id, target_node)))
                        if !source_node.resource_id.starts_with("cirrus-dir:")
                            || target_node.resource_id.starts_with("cirrus-dir:")
                            || self.space.is_offline_writable() =>
                    {
                        Some((
                            *id,
                            target_node.clone(),
                            self.fresh_directory(INodeNo(*id))?,
                        ))
                    }
                    _ => None,
                }
            } else {
                None
            };
            let guard = self.mutation.lock().map_err(|_| Errno::EIO)?;
            let state = self.state.lock().map_err(|_| Errno::EIO)?;
            let same_node = |ino: INodeNo, node: &Node| {
                state.paths.get(&node.path) == Some(&ino.0)
                    && state.nodes.get(&ino.0).is_some_and(|current| {
                        current.resource_id == node.resource_id && current.revision == node.revision
                    })
            };
            let unchanged = |ino: INodeNo, node: &Node, children: &DirectoryView| {
                same_node(ino, node)
                    && state.directories.iter().any(|cached| {
                        cached.ino == ino.0
                            && cached.mutation_epoch == epoch
                            && cached.metadata_generation == generation
                            && !cached.is_denied(&self.space, node)
                            && cached.children.matches(children)
                    })
            };
            if state.mutation_epoch != epoch
                || self.accounts.metadata_generation() != generation
                || !unchanged(parent, &source_parent, &source)
                || !unchanged(newparent, &destination_parent, &destination)
                || source_directory
                    .as_ref()
                    .is_some_and(|(id, node)| !same_node(INodeNo(*id), node))
                || target_directory
                    .as_ref()
                    .is_some_and(|(id, node)| !same_node(INodeNo(*id), node))
                || source_file
                    .as_ref()
                    .is_some_and(|file| !same_node(INodeNo(file.ino), &file.node))
                || target_prepared
                    .as_ref()
                    .is_some_and(|file| !same_node(INodeNo(file.ino), &file.node))
                || (source_file.is_some()
                    && target_file.as_ref().is_some_and(|(id, node)| {
                        !same_node(INodeNo(*id), node)
                            || (!node.resource_id.starts_with("cirrus-staged:")
                                && state.files.values().any(|file| file.ino == *id))
                    }))
                || source_children
                    .as_ref()
                    .is_some_and(|(id, node, children)| !unchanged(INodeNo(*id), node, children))
                || destination_children
                    .as_ref()
                    .is_some_and(|(id, node, children)| !unchanged(INodeNo(*id), node, children))
            {
                continue;
            }
            if source_file.as_ref().is_some_and(|prepared| {
                state.files.values().any(|file| {
                    file.ino == prepared.ino && !file.failed && file.version != prepared.version
                })
            }) {
                return Err(Errno::EBUSY);
            }
            if let Some(prepared) = target_prepared {
                if !state.files.values().any(|file| file.ino == prepared.ino) {
                    continue;
                }
                if state.files.values().any(|file| {
                    file.ino == prepared.ino && !file.failed && file.version != prepared.version
                }) {
                    return Err(Errno::EBUSY);
                }
                drop(state);
                self.stage_write_source(
                    INodeNo(prepared.ino),
                    &prepared.node,
                    prepared.version,
                    prepared.data,
                )?;
                drop(guard);
                continue;
            }
            drop(state);
            return Ok(LockedRenameInputs {
                guard,
                source,
                destination,
                source_children: source_children.map(|(_, _, children)| children),
                destination_children: destination_children.map(|(_, _, children)| children),
                source_file,
            });
        }
        Err(Errno::EIO)
    }

    fn load_rename_file(
        &self,
        ino: u64,
        node: Node,
        preserve: bool,
        epoch: u64,
        generation: u64,
    ) -> Result<Option<PreparedRenameFile>, Errno> {
        match self.load_write_source(&node, false, preserve) {
            Ok((version, data)) => Ok(Some(PreparedRenameFile {
                ino,
                node,
                version,
                data,
            })),
            Err(error) => {
                if self.state.lock().map_err(|_| Errno::EIO)?.mutation_epoch != epoch
                    || self.accounts.metadata_generation() != generation
                {
                    Ok(None)
                } else {
                    Err(error)
                }
            }
        }
    }

    // Namespace mutations must not authorize an operation from the browse cache.
    fn fresh_directory(&self, ino: INodeNo) -> Result<DirectoryView, Errno> {
        for _ in 0..8 {
            match self.observe_directory(ino, DirectoryObservation::Demand) {
                Err(Errno::EAGAIN) => continue,
                result => return result,
            }
        }
        Err(Errno::EIO)
    }

    fn observe_directory(
        &self,
        ino: INodeNo,
        observation: DirectoryObservation<'_>,
    ) -> Result<DirectoryView, Errno> {
        let parent = self.node(ino)?;
        if !parent.directory {
            return Err(Errno::ENOTDIR);
        }
        let load_durable =
            matches!(observation, DirectoryObservation::Browse) && !self.space.is_offline();
        let (seed, generation, mut started, background) = match observation {
            DirectoryObservation::Seed {
                entries,
                generation,
                started,
            } => (Some(entries), generation, started, None),
            DirectoryObservation::Background(alive) => (
                None,
                self.accounts.metadata_generation(),
                Instant::now(),
                Some(alive),
            ),
            DirectoryObservation::Demand | DirectoryObservation::Browse => (
                None,
                self.accounts.metadata_generation(),
                Instant::now(),
                None,
            ),
        };
        let browse_epoch = format!("{}:{generation}", self.browse_id);
        let durable_epoch = self.namespace()?.mutation_epoch;
        let remote_path = self
            .accounts
            .mount_browse_path(&self.space, &parent.path)
            .map_err(|_| Errno::EIO)?;
        let _browse_flight = if background.is_some() {
            Some(
                self.accounts
                    .try_reserve_mount_browse(&self.browse_id, &remote_path)
                    .map_err(|_| Errno::EIO)?
                    .ok_or(Errno::EAGAIN)?,
            )
        } else if seed.is_none() && !self.space.is_offline() {
            Some(
                self.accounts
                    .reserve_mount_browse(&self.browse_id, &remote_path)
                    .map_err(|_| Errno::EAGAIN)?,
            )
        } else {
            None
        };
        let denied = self
            .space
            .directory_denied(&remote_path, &parent.resource_id);
        if denied && background.is_some() {
            return Err(Errno::EAGAIN);
        }
        let durable = if load_durable && !denied {
            // An unusable retained copy never takes down live browse.
            self.accounts
                .load_mount_browse(
                    &self.space,
                    &parent.path,
                    &parent.resource_id,
                    parent.etag.as_deref(),
                    &browse_epoch,
                )
                .ok()
                .flatten()
                .map(|(entries, age)| {
                    started = started.checked_sub(age).unwrap_or(started);
                    entries
                })
        } else {
            None
        };
        let _foreground = (seed.is_none() && durable.is_none() && background.is_none())
            .then(|| self.accounts.request_foreground());
        let mut staged_files = Vec::with_capacity(MAX_HANDLES);
        let (ticket, namespace) = {
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            let ticket = state.next_scan;
            state.next_scan = ticket.checked_add(1).ok_or(Errno::EIO)?;
            staged_files.extend(
                state
                    .files
                    .values()
                    .filter(|file| {
                        !file.failed
                            && file.version.id().starts_with("cirrus-staged:")
                            && state
                                .nodes
                                .get(&file.ino)
                                .is_some_and(|node| node.parent == ino.0)
                    })
                    .map(|file| file.version.clone()),
            );
            (ticket, state.namespace.clone())
        };
        let epoch = namespace.mutation_epoch;
        if epoch != durable_epoch {
            return Err(Errno::EAGAIN);
        }
        let staged_versions: Vec<_> = staged_files
            .iter()
            .map(|version| (**version).clone())
            .collect();
        let staged_directories: Vec<_> = namespace
            .nodes
            .iter()
            .filter(|(id, node)| {
                node.directory
                    && node.parent == ino.0
                    && node.resource_id.starts_with("cirrus-dir:")
                    && namespace.paths.get(&node.path) == Some(*id)
            })
            .map(|(_, node)| (node.path.clone(), node.resource_id.to_string()))
            .collect();
        drop(namespace);
        drop(staged_files);
        let mut recovery = None;
        let (mut entries, confirmed, confirmed_directories) = if let Some(entries) = seed {
            (entries, Vec::new(), Vec::new())
        } else if let Some(alive) = background {
            let refreshed = match self.accounts.refresh_mount_directory(
                &self.space,
                &parent.path,
                &parent.resource_id,
                alive,
                (&browse_epoch, &remote_path),
                (&staged_versions, &staged_directories),
            ) {
                Ok(Some(refreshed)) => refreshed,
                Ok(None) => return Err(Errno::EAGAIN),
                Err(error) => {
                    if error.is_directory_forbidden() {
                        return Err(Errno::EACCES);
                    }
                    if error.is_directory_binding_lost() {
                        let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
                        if alive.load(Ordering::Acquire)
                            && state.mutation_epoch == epoch
                            && self.accounts.metadata_generation() == generation
                            && state.live_node(ino.0) == Some(&parent)
                            && state
                                .scans
                                .get(&ino.0)
                                .is_none_or(|latest| *latest < ticket)
                            && let Some(cached) =
                                state.directories.iter_mut().find(|d| d.ino == ino.0)
                        {
                            cached.rejected = true;
                        }
                    }
                    return Err(Errno::EIO);
                }
            };
            (refreshed.entries, refreshed.files, refreshed.directories)
        } else {
            let entries = if let Some(entries) = durable {
                entries
            } else {
                let (entries, validated_retry) = self
                    .accounts
                    .observe_mount_directory(
                        &self.space,
                        &parent.path,
                        &parent.resource_id,
                        (&browse_epoch, &remote_path),
                    )
                    .map_err(|error| {
                        eprintln!("directory listing failed: {error}");
                        if error.is_directory_forbidden() {
                            Errno::EACCES
                        } else if error.is_metadata_changed() {
                            Errno::EAGAIN
                        } else if error.is_staging_full() {
                            Errno::ENOSPC
                        } else {
                            Errno::EIO
                        }
                    })?;
                recovery = validated_retry;
                entries
            };
            let confirmed = if staged_versions.is_empty() {
                Vec::new()
            } else {
                self.accounts
                    .confirmed_mount_versions(&self.space, &staged_versions, &entries)
                    .map_err(|_| Errno::EIO)?
            };
            let directories = if staged_directories.is_empty() {
                Vec::new()
            } else {
                self.accounts
                    .confirmed_mount_directories(&self.space, &staged_directories, &entries)
                    .map_err(|_| Errno::EIO)?
            };
            (entries, confirmed, directories)
        };
        if !parent.resource_id.is_empty()
            && !parent.resource_id.starts_with("cirrus-dir:")
            && !entries
                .matches_parent(&parent.resource_id)
                .map_err(|_| Errno::EIO)?
        {
            return Err(Errno::EAGAIN);
        }
        let _publication = self.mutation.lock().map_err(|_| Errno::EIO)?;
        if background.is_some_and(|alive| {
            !alive.load(Ordering::Acquire) || self.accounts.background_yield_requested()
        }) {
            return Err(Errno::EAGAIN);
        }
        let mut files = Vec::with_capacity(MAX_HANDLES);
        let mut detached = Vec::with_capacity(MAX_HANDLES * 2);
        let mut ranges = Vec::with_capacity(CACHE_MAX_ENTRIES);
        let (baseline, baseline_next_node) = {
            let live = self.state.lock().map_err(|_| Errno::EIO)?;
            files.extend(
                live.files
                    .iter()
                    .map(|(handle, file)| (*handle, file.clone())),
            );
            detached.extend(live.detached.iter().map(|(id, node)| (*id, node.clone())));
            ranges.extend(live.cache.iter().cloned());
            (live.namespace.clone(), live.next_node)
        };
        if baseline.mutation_epoch != epoch
            || self.accounts.metadata_generation() != generation
            || baseline.paths.get(&parent.path) != Some(&ino.0)
            || baseline.nodes.get(&ino.0) != Some(&parent)
            || baseline
                .scans
                .get(&ino.0)
                .is_some_and(|previous| *previous > ticket)
        {
            return Err(Errno::EAGAIN);
        }
        let mut groups: Vec<(usize, u64, Vec<u64>)> = Vec::new();
        for (index, (staged, _)) in confirmed.iter().enumerate() {
            for (handle, file) in &files {
                if !file.failed
                    && *file.version == *staged
                    && baseline.nodes.get(&file.ino).is_some_and(|node| {
                        node.parent == ino.0
                            && node.resource_id == staged.id()
                            && node.etag.as_deref() == Some(staged.etag())
                            && node.size == staged.size()
                            && baseline.paths.get(&node.path) == Some(&file.ino)
                    })
                {
                    if let Some((_, _, handles)) = groups
                        .iter_mut()
                        .find(|(pair, id, _)| confirmed[*pair].0 == *staged && *id == file.ino)
                    {
                        if !handles.contains(handle) {
                            handles.push(*handle);
                        }
                    } else {
                        groups.push((index, file.ino, vec![*handle]));
                    }
                }
            }
        }
        let remote_versions: Vec<_> = confirmed
            .iter()
            .map(|(_, remote)| SharedVersion::new(remote.clone()))
            .collect();
        #[cfg(feature = "fault-injection")]
        let original_namespace = std::env::var_os("CIRRUS_TEST_PUBLICATION_READ_FAULT")
            .map(|_| publication_witness(&baseline, baseline_next_node, &detached, &files));
        let prepare = |mut state: Namespace,
                       mut next_node: u64,
                       groups: &[(usize, u64, Vec<u64>)],
                       detached: &[(u64, Arc<Node>)],
                       mut entries: DirectorySnapshot|
         -> Result<PreparedListing, Errno> {
            let mut promotions = Vec::with_capacity(MAX_HANDLES);
            for (path, resource, remote) in &confirmed_directories {
                let Some(id) = state.paths.get(path).copied() else {
                    continue;
                };
                let Some(node) = state.nodes.get_mut(&id) else {
                    continue;
                };
                if node.parent != ino.0 || !node.directory || node.resource_id != resource.as_str()
                {
                    continue;
                }
                node.resource_id = remote.id().to_owned().into();
                node.etag = remote.etag().map(|tag| tag.to_owned().into());
                node.modified = remote.modified();
                node.revision = node.revision.wrapping_add(1);
                state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
            }
            for (index, (staged, remote)) in confirmed.iter().enumerate() {
                for (_, id, _) in groups.iter().filter(|(pair, _, _)| *pair == index) {
                    let id = *id;
                    let Some(node) = state.nodes.get(&id) else {
                        continue;
                    };
                    if node.parent != ino.0
                        || node.resource_id != staged.id()
                        || node.etag.as_deref() != Some(staged.etag())
                        || node.size != staged.size()
                        || state.paths.get(&node.path) != Some(&id)
                    {
                        continue;
                    }
                    let node = state.nodes.get_mut(&id).ok_or(Errno::EIO)?;
                    node.resource_id = remote.id().to_owned().into();
                    node.etag = Some(remote.etag().to_owned().into());
                    node.checksums = remote.checksums().to_vec();
                    node.revision = node.revision.wrapping_add(1);
                    promotions.push((index, id));
                    state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
                }
            }
            state.scans.insert(u64::from(ino), ticket);
            let mut replaced = HashSet::new();
            let mut invalidated = Vec::new();
            for (path, id) in &state.paths {
                if path.len() == parent.path.len() + 1 && path.starts_with(&parent.path) {
                    let current = entries
                        .get(path[parent.path.len()].as_str())
                        .map_err(|_| Errno::EIO)?;
                    if !current.as_ref().is_some_and(|entry| {
                        state.nodes.get(id).is_some_and(|node| {
                            node.directory == entry.is_directory() && node.resource_id == entry.id()
                        })
                    }) {
                        replaced.insert(path[parent.path.len()].clone());
                    }
                    if let Some(node) = state.nodes.get(id)
                        && !node.directory
                        && !current.as_ref().is_some_and(|entry| {
                            !entry.is_directory()
                                && node.resource_id == entry.id()
                                && entry.size() == Some(node.size)
                                && node.etag.as_deref() == entry.etag()
                                && node.checksums == entry.checksums()
                        })
                    {
                        invalidated.push(node.resource_id.to_string());
                    }
                }
            }
            // Prune only in the private draft, by the exact path component of
            // each removed/replaced child. A new child has no old subtree.
            let mut live_nodes = HashSet::new();
            state.paths.retain(|path, id| {
                let keep = path.len() <= parent.path.len()
                    || !path.starts_with(&parent.path)
                    || !replaced.contains(&path[parent.path.len()]);
                if keep {
                    live_nodes.insert(*id);
                }
                keep
            });
            let retained_count = live_nodes.len()
                + detached
                    .iter()
                    .filter(|(id, _)| !live_nodes.contains(id))
                    .count();
            let mut new_nodes = 0;
            let mut after = 0;
            let mut bindings = Vec::new();
            loop {
                let page = entries.page(after).map_err(|_| Errno::EIO)?;
                if page.is_empty() {
                    break;
                }
                bindings.reserve(page.len());
                for (cookie, entry) in page {
                    after = cookie;
                    if !entry.is_directory() && entry.size().is_none() {
                        return Err(Errno::EIO);
                    }
                    let mut path = parent.path.clone();
                    path.push(entry.name().to_owned());
                    let existing = state.paths.get(&path).copied().filter(|id| {
                        state.nodes.get(id).is_some_and(|node| {
                            node.directory == entry.is_directory() && node.resource_id == entry.id()
                        })
                    });
                    let id = if let Some(id) = existing {
                        id
                    } else {
                        new_nodes += 1;
                        if retained_count + new_nodes > MAX_NODES {
                            return Err(Errno::ENOSPC);
                        }
                        let id = next_node;
                        next_node = next_node.checked_add(1).ok_or(Errno::ENOSPC)?;
                        id
                    };
                    bindings.push((cookie, id));
                }
                entries = entries.bind_inodes(&bindings).map_err(|_| Errno::EIO)?;
                bindings.clear();
            }
            #[cfg(feature = "fault-injection")]
            for id in &invalidated {
                if std::env::var_os("CIRRUS_TEST_STAGE_WINDOW").is_some()
                    && id.starts_with("cirrus-staged:")
                {
                    eprintln!("injected race: scan invalidated a staged inode");
                }
            }
            // Removed or replaced paths already fail node() validation. Reclaim their
            // inode records without reusing inode numbers, including descendants.
            state.nodes.retain(|id, _| live_nodes.contains(id));
            state.scans.retain(|id, _| {
                live_nodes.contains(id) || detached.iter().any(|(detached, _)| detached == id)
            });
            #[cfg(feature = "fault-injection")]
            entries
                .inject_publication_read_fault()
                .map_err(|_| Errno::EIO)?;
            let mut after = 0;
            loop {
                let page = entries.page(after).map_err(|_| Errno::EIO)?;
                if page.is_empty() {
                    break;
                }
                for (cookie, entry) in page {
                    after = cookie;
                    let mut path = parent.path.clone();
                    path.push(entry.name().to_owned());
                    let existing = state.paths.get(&path).copied().filter(|id| {
                        state.nodes.get(id).is_some_and(|node| {
                            node.directory == entry.is_directory() && node.resource_id == entry.id()
                        })
                    });
                    let id = if let Some(id) = existing {
                        id
                    } else {
                        let id = entries
                            .child(entry.name())
                            .map_err(|_| Errno::EIO)?
                            .ok_or(Errno::EIO)?
                            .inode;
                        state.paths.insert(path.clone(), id);
                        id
                    };
                    let size = if entry.is_directory() {
                        0
                    } else {
                        entry.size().ok_or(Errno::EIO)?
                    };
                    let revision = state.nodes.get(&id).map_or(0, |old| {
                        old.revision.wrapping_add(u64::from(
                            old.size != size
                                || old.etag.as_deref() != entry.etag()
                                || old.checksums != entry.checksums(),
                        ))
                    });
                    let node = Node {
                        path,
                        parent: u64::from(ino),
                        directory: entry.is_directory(),
                        size,
                        modified: entry.modified(),
                        resource_id: entry.id().to_owned().into(),
                        etag: entry.etag().map(|tag| tag.to_owned().into()),
                        checksums: entry.checksums().to_vec(),
                        revision,
                    };
                    state.nodes.insert(id, node);
                }
            }
            let children = DirectoryView(entries);
            Ok(PreparedListing {
                namespace: state,
                next_node,
                children,
                promotions,
                invalidated,
            })
        };
        loop {
            let PreparedListing {
                namespace,
                next_node,
                children,
                promotions,
                invalidated,
            } = match prepare(
                (*baseline).clone(),
                baseline_next_node,
                &groups,
                &detached,
                entries,
            ) {
                Ok(prepared) => prepared,
                Err(error) => {
                    #[cfg(feature = "fault-injection")]
                    if let Some(original) = original_namespace {
                        let mut current_files = Vec::with_capacity(MAX_HANDLES);
                        let mut current_detached = Vec::with_capacity(MAX_HANDLES * 2);
                        let (current, next_node) = {
                            let live = self.state.lock().map_err(|_| Errno::EIO)?;
                            current_files
                                .extend(live.files.iter().map(|(id, file)| (*id, file.clone())));
                            current_detached
                                .extend(live.detached.iter().map(|(id, node)| (*id, node.clone())));
                            (live.namespace.clone(), live.next_node)
                        };
                        eprintln!(
                            "cirrus lab publication failure live namespace unchanged={}",
                            original
                                == publication_witness(
                                    &current,
                                    next_node,
                                    &current_detached,
                                    &current_files
                                )
                        );
                    }
                    return Err(error);
                }
            };
            let mut namespace = Arc::new(namespace);
            let file_promotions: Vec<_> = promotions
                .iter()
                .flat_map(|(pair, id)| {
                    groups
                        .iter()
                        .filter(move |(index, ino, _)| index == pair && ino == id)
                        .flat_map(move |(_, _, handles)| {
                            handles.iter().map(move |handle| (*handle, *pair))
                        })
                })
                .collect();
            let invalidated_handles: Vec<_> = files
                .iter()
                .filter_map(|(handle, file)| {
                    let version = file_promotions
                        .iter()
                        .find(|(promoted, _)| promoted == handle)
                        .map_or(&file.version, |(_, pair)| &remote_versions[*pair]);
                    invalidated
                        .iter()
                        .any(|id| version.id() == id)
                        .then_some(*handle)
                })
                .collect();
            let removed_range_versions: Vec<_> = ranges
                .iter()
                .map(|range| &range.version)
                .chain(files.iter().map(|(_, file)| &file.version))
                .filter(|version| {
                    invalidated.iter().any(|id| version.id() == id)
                        || promotions
                            .iter()
                            .any(|(pair, _)| ***version == confirmed[*pair].0)
                })
                .cloned()
                .collect();
            let effects = ListingEffects {
                promotions: file_promotions
                    .into_iter()
                    .map(|(handle, pair)| FilePromotion {
                        handle,
                        expected: files
                            .iter()
                            .find(|(id, _)| *id == handle)
                            .expect("captured handle")
                            .1
                            .version
                            .clone(),
                        replacement: remote_versions[pair].clone(),
                    })
                    .collect(),
                invalidated_handles,
                removed_range_versions,
            };
            let cached = CachedDirectory {
                ino: ino.0,
                remote_path: remote_path.clone(),
                parent_revision: parent.revision,
                rejected: false,
                started,
                attempted: started,
                mutation_epoch: namespace.mutation_epoch,
                metadata_generation: generation,
                children: children.clone(),
            };
            let mut remaining = Vec::with_capacity(groups.len());
            let mut current_detached = Vec::with_capacity(MAX_HANDLES * 2);
            let mut retired_ranges = Vec::with_capacity(CACHE_MAX_ENTRIES);
            let mut retired_directories = Vec::with_capacity(DIRECTORY_CACHE_MAX);
            let mut retired_versions = Vec::with_capacity(MAX_HANDLES);
            let retired_namespace;
            let mut live = self.state.lock().map_err(|_| Errno::EIO)?;
            if !Arc::ptr_eq(&live.namespace, &baseline)
                || live.next_node != baseline_next_node
                || self.accounts.metadata_generation() != generation
                || background.is_some_and(|alive| {
                    !alive.load(Ordering::Acquire) || self.accounts.background_yield_requested()
                })
            {
                return Err(Errno::EAGAIN);
            }
            for (index, (_, _, handles)) in groups.iter().enumerate() {
                if handles
                    .iter()
                    .any(|handle| live.files.get(handle).is_some_and(|file| !file.failed))
                {
                    remaining.push(index);
                }
            }
            if remaining.len() != groups.len() {
                // Mutation excludes new anchors; each retry loses a nonempty
                // group of the at most MAX_HANDLES captured file handles.
                current_detached.extend(live.detached.iter().map(|(id, node)| (*id, node.clone())));
                drop(live);
                drop(namespace);
                drop(cached);
                // Recover the sole snapshot owner to rebind the changed draft.
                entries = children.0;
                let mut index = 0;
                groups.retain(|_| {
                    let keep = remaining.binary_search(&index).is_ok();
                    index += 1;
                    keep
                });
                detached = current_detached;
                continue;
            }
            if !self.space.admit_directory_publication(
                &remote_path,
                &parent.resource_id,
                recovery.as_ref(),
            ) {
                return Err(if background.is_some() || load_durable && !denied {
                    Errno::EAGAIN
                } else {
                    Errno::EACCES
                });
            }
            let prepared_namespace =
                Arc::get_mut(&mut namespace).expect("private listing namespace");
            for (id, _) in &detached {
                if !live.detached.contains_key(id) {
                    prepared_namespace.scans.remove(id);
                }
            }
            for promotion in &effects.promotions {
                if let Some(file) = live
                    .files
                    .get_mut(&promotion.handle)
                    .filter(|file| !file.failed && file.version.same_owner(&promotion.expected))
                {
                    retired_versions.push(file.rebind_namespace(promotion.replacement.clone()));
                }
            }
            for handle in &effects.invalidated_handles {
                if let Some(file) = live.files.get_mut(handle) {
                    file.failed = true;
                }
            }
            let mut index = 0;
            while index < live.cache.len() {
                let range = &live.cache[index];
                if effects
                    .removed_range_versions
                    .iter()
                    .any(|version| range.version.same_owner(version))
                {
                    retired_ranges.push(live.cache.remove(index).expect("present range"));
                } else {
                    index += 1;
                }
            }
            live.cache_bytes = live.cache.iter().map(|entry| entry.bytes.len()).sum();
            let mut index = 0;
            while index < live.directories.len() {
                let id = live.directories[index].ino;
                if id == ino.0
                    || (!namespace.nodes.contains_key(&id) && !live.detached.contains_key(&id))
                {
                    retired_directories
                        .push(live.directories.remove(index).expect("present directory"));
                } else {
                    index += 1;
                }
            }
            if live.directories.len() == DIRECTORY_CACHE_MAX {
                // Keep the root view: every pathname walk depends on it.
                let oldest = usize::from(live.directories[0].ino == 1);
                retired_directories.push(
                    live.directories
                        .remove(oldest)
                        .expect("full directory cache"),
                );
            }
            live.directories.push_back(cached);
            live.next_node = next_node;
            retired_namespace = std::mem::replace(&mut live.namespace, namespace);
            drop(live);
            drop(retired_namespace);
            return Ok(children);
        }
    }

    fn fetch_range(
        &self,
        version: &FileVersion,
        offset: u64,
        length: u32,
        priority: RangePriority<'_>,
    ) -> Result<Vec<u8>, Errno> {
        Self::fetch_range_with(
            &self.accounts,
            &self.space,
            &self.flights,
            version,
            offset,
            length,
            priority,
        )
    }

    fn fetch_range_with(
        accounts: &Accounts,
        binding: &MountBinding,
        flights: &Mutex<HashMap<RangeKey, Arc<Flight>>>,
        version: &FileVersion,
        offset: u64,
        length: u32,
        priority: RangePriority<'_>,
    ) -> Result<Vec<u8>, Errno> {
        let end = offset.checked_add(u64::from(length)).ok_or(Errno::EIO)?;
        let mut result = vec![0; length as usize];
        let mut remaining = vec![(offset, end)];
        let mut joins = 0;
        while let Some((start, end)) = remaining.pop() {
            let (received_start, received_end, bytes, joined) = Self::fetch_range_part(
                accounts,
                binding,
                flights,
                version,
                (start, end),
                joins < 8,
                priority,
            )?;
            if received_start < start
                || received_end > end
                || received_start >= received_end
                || bytes.len() as u64 != received_end - received_start
            {
                return Err(Errno::EIO);
            }
            joins += usize::from(joined);
            let destination = (received_start - offset) as usize;
            result[destination..destination + bytes.len()].copy_from_slice(&bytes);
            if start < received_start {
                remaining.push((start, received_start));
            }
            if received_end < end {
                remaining.push((received_end, end));
            }
        }
        Ok(result)
    }

    fn fetch_range_part(
        accounts: &Accounts,
        binding: &MountBinding,
        flights: &Mutex<HashMap<RangeKey, Arc<Flight>>>,
        version: &FileVersion,
        range: (u64, u64),
        join: bool,
        priority: RangePriority<'_>,
    ) -> Result<(u64, u64, Vec<u8>, bool), Errno> {
        let (offset, end) = range;
        let length = u32::try_from(end - offset).map_err(|_| Errno::EIO)?;
        if !join {
            let bytes = priority
                .read(accounts, binding, version, offset, length)
                .map_err(|_| Errno::EIO)?;
            return Ok((offset, end, bytes, false));
        }
        let key = RangeKey {
            version: version.clone(),
            offset,
            length,
            staged_cache_generation: match priority {
                RangePriority::Staged(generation) => Some(generation),
                _ => None,
            },
        };
        let (flight, leader, flight_offset, flight_end) = {
            let mut flights = flights.lock().map_err(|_| Errno::EIO)?;
            if let Some((existing, flight)) = flights.iter().find(|(existing, _)| {
                existing.version == *version
                    && existing.staged_cache_generation == key.staged_cache_generation
                    && existing.offset < end
                    && existing
                        .offset
                        .checked_add(u64::from(existing.length))
                        .is_some_and(|flight_end| flight_end > offset)
            }) {
                (
                    Arc::clone(flight),
                    false,
                    existing.offset,
                    existing.offset + u64::from(existing.length),
                )
            } else {
                let flight = Arc::new(Flight {
                    result: Mutex::new(None),
                    ready: Condvar::new(),
                    speculative: matches!(priority, RangePriority::ReadAhead(_)),
                });
                flights.insert(key.clone(), Arc::clone(&flight));
                (flight, true, offset, end)
            }
        };
        if leader {
            let owner = FlightLeader {
                flights,
                key: Some(key),
                flight: Arc::clone(&flight),
            };
            let result = priority.read(accounts, binding, version, offset, length);
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_RETAINED_SH_OWNER").is_some()
                && let Err(error) = &result
            {
                eprintln!(
                    "cirrus lab owner read: pid={} thread={:?} boundary=fuse-range-leader staged={} offset={offset} length={length} error={error}",
                    std::process::id(),
                    std::thread::current().id(),
                    version.id().starts_with("cirrus-staged:")
                );
            }
            owner.complete(result.map_err(|_| ()))?;
        }
        let mut shared = flight.result.lock().map_err(|_| Errno::EIO)?;
        while shared.is_none() {
            let (next, timed) = flight
                .ready
                .wait_timeout(shared, Duration::from_secs(50))
                .map_err(|_| Errno::EIO)?;
            shared = next;
            if timed.timed_out() && shared.is_none() {
                break;
            }
        }
        let bytes = match shared.as_ref() {
            Some(Ok(bytes)) => bytes,
            _ if !leader && matches!(priority, RangePriority::Foreground) && flight.speculative => {
                drop(shared);
                let bytes = accounts
                    .read_range(binding, version, offset, length)
                    .map_err(|_| Errno::EIO)?;
                return Ok((offset, end, bytes, true));
            }
            _ => return Err(Errno::EIO),
        };
        let overlap_start = offset.max(flight_offset);
        let overlap_end = end.min(flight_end);
        let start = usize::try_from(overlap_start - flight_offset).map_err(|_| Errno::EIO)?;
        let finish = start
            .checked_add((overlap_end - overlap_start) as usize)
            .filter(|end| *end <= bytes.len())
            .ok_or(Errno::EIO)?;
        let overlap = bytes[start..finish].to_vec();
        Ok((overlap_start, overlap_end, overlap, !leader))
    }

    fn read_ahead(&self, ino: INodeNo, version: &FileVersion, offset: u64) {
        if version.id().starts_with("cirrus-staged:") || offset >= version.size() {
            return;
        }
        let parent_id = self.state.lock().ok().and_then(|state| {
            let file = state.live_node(ino.0)?;
            let parent = state.live_node(file.parent)?;
            (file.resource_id == version.id() && file.path == version.path())
                .then(|| parent.resource_id.clone())
        });
        let Some(parent_id) = parent_id else { return };
        if !self.accounts.reserve_read_ahead() {
            return;
        }
        let accounts = Arc::clone(&self.accounts);
        let lease = ReadAheadLease(Arc::clone(&accounts));
        let flights = Arc::clone(&self.flights);
        let binding = self.space.clone();
        let version = version.clone();
        let length = (version.size() - offset).min(u64::from(READ_AHEAD_BYTES)) as u32;
        let _ = std::thread::Builder::new()
            .name("cirrus-read-ahead".into())
            .spawn(move || {
                let _lease = lease;
                let _ = Self::fetch_range_with(
                    &accounts,
                    &binding,
                    &flights,
                    &version,
                    offset,
                    length,
                    RangePriority::ReadAhead(&parent_id),
                );
            });
    }

    fn publish_version(
        &self,
        ino: INodeNo,
        old: &Node,
        version: &FileVersion,
    ) -> Result<(), Errno> {
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_STAGE_WINDOW").is_some() {
            std::thread::sleep(Duration::from_millis(500));
        }
        let current = self.namespace()?;
        let mut namespace = (*current).clone();
        if namespace.paths.get(&old.path) != Some(&ino.0) {
            return Err(Errno::EIO);
        }
        let node = namespace.nodes.get_mut(&ino.0).ok_or(Errno::EIO)?;
        node.resource_id = version.id().to_owned().into();
        node.etag = Some(version.etag().to_owned().into());
        node.size = version.size();
        node.checksums.clear();
        node.revision = node.revision.wrapping_add(1);
        namespace.mutation_epoch = namespace.mutation_epoch.wrapping_add(1);
        let namespace = Arc::new(namespace);
        let version = SharedVersion::new(version.clone());
        let mut retired_versions = Vec::with_capacity(MAX_HANDLES);
        let mut retired_ranges = Vec::with_capacity(CACHE_MAX_ENTRIES);
        let retired_namespace;
        let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
        state.retire_ranges(&mut retired_ranges, |entry| {
            entry.version.id() == old.resource_id || entry.version.id() == version.id()
        });
        for file in state
            .files
            .values_mut()
            .filter(|file| file.ino == ino.0 && !file.failed)
        {
            retired_versions.push(std::mem::replace(&mut file.version, version.clone()));
            file.last_read = None;
        }
        retired_namespace = std::mem::replace(&mut state.namespace, namespace);
        drop(state);
        drop(retired_namespace);
        Ok(())
    }

    // The caller serializes local mutations. Every returned version is durable.
    fn prepare_write(&self, ino: INodeNo, truncate: bool) -> Result<FileVersion, Errno> {
        self.prepare_write_checked(ino, truncate, false)
    }

    fn prepare_write_checked(
        &self,
        ino: INodeNo,
        truncate: bool,
        preserve: bool,
    ) -> Result<FileVersion, Errno> {
        let node = self.node(ino)?;
        let (version, data) = self.load_write_source(&node, truncate, preserve)?;
        self.stage_write_source(ino, &node, version, data)
    }

    fn load_write_source(
        &self,
        node: &Node,
        truncate: bool,
        preserve: bool,
    ) -> Result<(FileVersion, Option<DirtyMutation<'static>>), Errno> {
        if node.directory {
            return Err(Errno::EISDIR);
        }
        let version = self
            .accounts
            .mount_open_file(&self.instance, &self.space, &node.path, &node.resource_id)
            .map_err(|_| Errno::EIO)?;
        if preserve
            && (version.id() != node.resource_id
                || Some(version.etag()) != node.etag.as_deref()
                || version.size() != node.size
                || (self.space.is_offline() && version.checksums() != node.checksums))
        {
            return Err(Errno::EBUSY);
        }
        if version.size() > MAX_WRITE_FILE && !truncate {
            return Err(Errno::EFBIG);
        }
        if version.id().starts_with("cirrus-staged:") && !truncate {
            return Ok((version, None));
        }
        let data = if truncate {
            DirtyMutation::Resize(0)
        } else {
            DirtyMutation::Preserve
        };
        Ok((version, Some(data)))
    }

    // The caller holds the mutation lock and has validated the captured node.
    fn stage_write_source(
        &self,
        ino: INodeNo,
        node: &Node,
        version: FileVersion,
        data: Option<DirtyMutation<'static>>,
    ) -> Result<FileVersion, Errno> {
        let Some(data) = data else {
            return Ok(version);
        };
        let parents = self.namespace()?.parent_identities(&node.path)?;
        let staged = self
            .accounts
            .stage_mount_mutation(
                &self.instance,
                &self.space,
                &node.path,
                data,
                Some(&version),
                &parents,
            )
            .map_err(|error| stage_error(&error))?;
        self.publish_version(ino, node, &staged)?;
        Ok(staged)
    }

    // Metadata observation is read-only; retry if local publication supersedes it.
    fn prepare_write_for_mutation(
        &self,
        ino: INodeNo,
        truncate: bool,
        require_handle: bool,
    ) -> Result<(MutexGuard<'_, ()>, FileVersion), Errno> {
        for _ in 0..8 {
            let source = self.node(ino)?;
            #[cfg(feature = "fault-injection")]
            wait_test_window("CIRRUS_TEST_WRITE_OPEN_WINDOW")?;
            let (version, data) = self.load_write_source(&source, truncate, false)?;
            #[cfg(feature = "fault-injection")]
            wait_test_window("CIRRUS_TEST_WRITE_OPEN_COMMIT_WINDOW")?;
            let guard = self.mutation.lock().map_err(|_| Errno::EIO)?;
            let (valid, handles_match, has_capacity) = {
                let state = self.state.lock().map_err(|_| Errno::EIO)?;
                let current = state.nodes.get(&u64::from(ino)).ok_or(Errno::EIO)?;
                let matches_published_version = current.path == source.path
                    && current.resource_id == source.resource_id
                    && current.matches_version(&version);
                (
                    state.paths.get(&source.path) == Some(&u64::from(ino))
                        && current.path == source.path
                        && current.resource_id == source.resource_id
                        && (current.revision == source.revision || matches_published_version),
                    state.files.values().all(|file| {
                        file.ino != u64::from(ino) || file.failed || file.version == version
                    }),
                    state.files.len() < MAX_HANDLES && state.next_handle.checked_add(1).is_some(),
                )
            };
            if !valid {
                continue;
            }
            // Publishing a staged version rebinds live handles; never rebind one
            // that still refers to a different remote or staged version.
            if !handles_match {
                return Err(Errno::EBUSY);
            }
            if require_handle && !has_capacity {
                return Err(Errno::EMFILE);
            }
            if !truncate {
                return Ok((guard, version));
            }
            let staged = self.stage_write_source(ino, &source, version, data)?;
            return Ok((guard, staged));
        }
        Err(Errno::EIO)
    }

    fn resize_file(&self, ino: INodeNo, size: u64, version: &FileVersion) -> Result<Node, Errno> {
        if size > MAX_WRITE_FILE {
            return Err(Errno::EFBIG);
        }
        let node = self.node(ino)?;
        let parents = self.namespace()?.parent_identities(&node.path)?;
        let staged = self
            .accounts
            .stage_mount_mutation(
                &self.instance,
                &self.space,
                &node.path,
                DirtyMutation::Resize(size),
                Some(version),
                &parents,
            )
            .map_err(|error| stage_error(&error))?;
        self.publish_version(ino, &node, &staged)?;
        self.node(ino)
    }

    fn publish_detached(&self, ino: INodeNo, version: &FileVersion) -> Result<Node, Errno> {
        let current = self
            .state
            .lock()
            .map_err(|_| Errno::EIO)?
            .detached
            .get(&ino.0)
            .cloned()
            .ok_or(Errno::EIO)?;
        let mut node = (*current).clone();
        node.size = version.size();
        node.etag = Some(version.etag().to_owned().into());
        node.revision = node.revision.wrapping_add(1);
        let owner = Arc::new(node.clone());
        let version = SharedVersion::new(version.clone());
        let mut retired_versions = Vec::with_capacity(MAX_HANDLES);
        let mut retired_ranges = Vec::with_capacity(CACHE_MAX_ENTRIES);
        let retired_node;
        let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
        let Some(slot) = state.detached.get_mut(&ino.0) else {
            return Err(Errno::EIO);
        };
        retired_node = std::mem::replace(slot, owner);
        state.retire_ranges(&mut retired_ranges, |entry| {
            entry.version.id() == version.id()
        });
        for file in state
            .files
            .values_mut()
            .filter(|file| file.ino == ino.0 && !file.failed)
        {
            retired_versions.push(std::mem::replace(&mut file.version, version.clone()));
            file.last_read = None;
        }
        drop(state);
        drop(retired_node);
        Ok(node)
    }

    fn resize_detached(
        &self,
        ino: INodeNo,
        handle: FileHandle,
        size: Option<u64>,
    ) -> Result<Option<Node>, Errno> {
        let _guard = self.mutation.lock().map_err(|_| Errno::EIO)?;
        let version = {
            let state = self.state.lock().map_err(|_| Errno::EIO)?;
            if !state.detached.contains_key(&ino.0) {
                return Ok(None);
            }
            let file = state
                .files
                .get(&handle.0)
                .filter(|file| file.ino == ino.0 && file.writable && !file.failed)
                .ok_or(Errno::EBADF)?;
            file.version.clone()
        };
        if let Some(size) = size {
            if size > MAX_WRITE_FILE {
                return Err(Errno::EFBIG);
            }
            let staged = self
                .accounts
                .stage_detached_mutation(&self.space, &version, DirtyMutation::Resize(size))
                .map_err(|error| stage_error(&error))?;
            return self.publish_detached(ino, &staged).map(Some);
        }
        let node = self
            .state
            .lock()
            .map_err(|_| Errno::EIO)?
            .detached
            .get(&ino.0)
            .cloned()
            .ok_or(Errno::EIO)?;
        Ok(Some((*node).clone()))
    }

    fn remove_namespace(
        &self,
        parent: INodeNo,
        name: &OsStr,
        directory: bool,
    ) -> Result<(), Errno> {
        if self.space.is_offline() && !self.space.is_offline_writable() {
            return Err(Errno::EROFS);
        }
        for _ in 0..8 {
            match self.remove_namespace_once(parent, name, directory) {
                Err(Errno::EAGAIN) => continue,
                result => return result,
            }
        }
        Err(Errno::EIO)
    }

    fn remove_namespace_once(
        &self,
        parent: INodeNo,
        name: &OsStr,
        directory: bool,
    ) -> Result<(), Errno> {
        let epoch = self.state.lock().map_err(|_| Errno::EIO)?.mutation_epoch;
        let generation = self.accounts.metadata_generation();
        let name = name.to_str().ok_or(Errno::EINVAL)?;
        let siblings = self.fresh_directory(parent)?;
        let id = siblings
            .find(name)?
            .map(|entry| entry.0)
            .ok_or(Errno::ENOENT)?;
        let mut node = self.node(INodeNo(id))?;
        if node.directory != directory {
            return Err(if directory {
                Errno::ENOTDIR
            } else {
                Errno::EISDIR
            });
        }
        let children = if directory {
            let children = self.fresh_directory(INodeNo(id))?;
            if !children.is_empty()? {
                return Err(Errno::ENOTEMPTY);
            }
            Some(children)
        } else {
            None
        };
        let hydrate_open = !directory
            && !node.resource_id.starts_with("cirrus-staged:")
            && (self.space.is_offline()
                || self
                    .state
                    .lock()
                    .map_err(|_| Errno::EIO)?
                    .files
                    .values()
                    .any(|file| file.ino == id));
        let hydrated = if hydrate_open {
            #[cfg(feature = "fault-injection")]
            wait_test_window("CIRRUS_TEST_UNLINK_OPEN_WINDOW")?;
            Some(self.load_write_source(&node, false, true)?)
        } else {
            None
        };
        #[cfg(feature = "fault-injection")]
        if directory && let Some(marker) = std::env::var_os("CIRRUS_TEST_RMDIR_WINDOW") {
            let marker = Path::new(&marker);
            if marker.is_file() {
                std::fs::write(marker.with_extension("waiting"), b"waiting")
                    .map_err(|_| Errno::EIO)?;
                for _ in 0..1500 {
                    if !marker.exists() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if marker.exists() {
                    return Err(Errno::EIO);
                }
            }
        }
        let _guard = self.mutation.lock().map_err(|_| Errno::EIO)?;
        let open_files = {
            let state = self.state.lock().map_err(|_| Errno::EIO)?;
            // The scans ran without the mutation lock; only journal their result
            // if the same inode and empty-directory observation still apply.
            if state.mutation_epoch != epoch
                || self.accounts.metadata_generation() != generation
                || !state.live_node(parent.0).is_some_and(|node| {
                    state.directories.iter().any(|cached| {
                        cached.ino == parent.0
                            && cached.mutation_epoch == epoch
                            && cached.metadata_generation == generation
                            && !cached.is_denied(&self.space, node)
                            && cached.children.matches(&siblings)
                    })
                })
                || state.paths.get(&node.path) != Some(&id)
                || !state.nodes.get(&id).is_some_and(|current| {
                    current.parent == node.parent
                        && current.resource_id == node.resource_id
                        && current.revision == node.revision
                })
                || children.as_ref().is_some_and(|children| {
                    !state.directories.iter().any(|cached| {
                        cached.ino == id
                            && cached.mutation_epoch == epoch
                            && cached.metadata_generation == generation
                            && !cached.is_denied(&self.space, &node)
                            && cached.children.matches(children)
                    })
                })
            {
                return Err(Errno::EAGAIN);
            }
            if directory
                && (state.files.values().any(|file| file.ino == id)
                    || state.handles.values().any(|directory| directory.ino == id))
            {
                return Err(Errno::EBUSY);
            }
            if state.files.values().any(|file| {
                file.ino == id
                    && !file.failed
                    && (file.version.id() != node.resource_id
                        || Some(file.version.etag()) != node.etag.as_deref()
                        || file.version.size() != node.size)
            }) {
                return Err(Errno::EBUSY);
            }
            state.files.values().any(|file| file.ino == id)
        };
        if !directory
            && (open_files || self.space.is_offline())
            && !node.resource_id.starts_with("cirrus-staged:")
        {
            let (version, data) = hydrated.ok_or(Errno::EAGAIN)?;
            self.stage_write_source(INodeNo(id), &node, version, data)?;
            node = self.node(INodeNo(id))?;
        }
        let current = self.namespace()?;
        let mut namespace = (*current).clone();
        namespace.paths.remove(&node.path);
        namespace.observed.remove(&node.path);
        let detached_node = Arc::new(namespace.nodes.remove(&id).ok_or(Errno::EIO)?);
        namespace.mutation_epoch = namespace.mutation_epoch.wrapping_add(1);
        let namespace = Arc::new(namespace);
        let mut retired_ranges = Vec::with_capacity(CACHE_MAX_ENTRIES);
        let retired_namespace;
        if self.space.is_offline() && directory {
            let parents = self.namespace()?.parent_identities(&node.path)?;
            self.accounts
                .stage_namespace(
                    &self.instance,
                    &self.space,
                    &node.path,
                    "rmdir",
                    Some((&node.resource_id, node.etag.as_deref().unwrap_or(""))),
                    &parents,
                )
                .map_err(|error| stage_error(&error))?;
        } else if self.space.is_offline() {
            let version = self
                .accounts
                .mount_open_file(&self.instance, &self.space, &node.path, &node.resource_id)
                .map_err(|_| Errno::EIO)?;
            if !node.matches_version(&version) {
                return Err(Errno::EIO);
            }
            let parents = self.namespace()?.parent_identities(&node.path)?;
            self.accounts
                .remove_offline_file(&self.space, &version, open_files, &parents)
                .map_err(|error| stage_error(&error))?;
        } else if node.resource_id.starts_with("cirrus-staged:")
            || node.resource_id.starts_with("cirrus-dir:")
        {
            let parents = self.namespace()?.parent_identities(&node.path)?;
            self.accounts
                .remove_staged(
                    &self.instance,
                    &self.space,
                    &node.path,
                    &node.resource_id,
                    open_files,
                    &parents,
                )
                .map_err(|error| stage_error(&error))?;
        } else {
            let etag = node.etag.as_deref().ok_or(Errno::EOPNOTSUPP)?;
            let parents = self.namespace()?.parent_identities(&node.path)?;
            self.accounts
                .stage_namespace(
                    &self.instance,
                    &self.space,
                    &node.path,
                    if directory { "rmdir" } else { "unlink" },
                    Some((&node.resource_id, etag)),
                    &parents,
                )
                .map_err(|error| stage_error(&error))?;
        }
        let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
        if open_files && state.files.values().any(|file| file.ino == id) {
            state.detached.insert(id, detached_node);
        }
        state.retire_ranges(&mut retired_ranges, |entry| {
            entry.version.id() == node.resource_id
        });
        retired_namespace = std::mem::replace(&mut state.namespace, namespace);
        drop(state);
        drop(retired_namespace);
        Ok(())
    }
}

fn kind(node: &Node) -> FileType {
    if node.directory {
        FileType::Directory
    } else {
        FileType::RegularFile
    }
}

fn attr(id: u64, node: &Node) -> FileAttr {
    FileAttr {
        ino: INodeNo(id),
        size: node.size,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: node.modified,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: kind(node),
        perm: if node.directory { 0o700 } else { 0o600 },
        nlink: if node.directory { 2 } else { 1 },
        uid: process::geteuid().as_raw(),
        gid: process::getegid().as_raw(),
        rdev: 0,
        flags: 0,
        blksize: 4096,
    }
}

impl Filesystem for Drive {
    fn lookup(&self, _: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.browse_entry(parent, name) {
            Ok(Some((id, node))) => reply.entry(&Duration::ZERO, &attr(id, &node), Generation(0)),
            Ok(None) => reply.error(Errno::ENOENT),
            Err(error) => reply.error(error),
        }
    }

    fn getattr(&self, _: &Request, ino: INodeNo, handle: Option<FileHandle>, reply: ReplyAttr) {
        {
            let result = self.state.lock().map_err(|_| Errno::EIO).and_then(|state| {
                if !state.detached.contains_key(&ino.0) {
                    return Ok(None);
                }
                if let Some(handle) = handle {
                    if state
                        .detached
                        .get(&ino.0)
                        .is_some_and(|node| node.directory)
                    {
                        if !state
                            .handles
                            .get(&handle.0)
                            .is_some_and(|directory| directory.ino == ino.0)
                        {
                            return Err(Errno::EBADF);
                        }
                        return Ok(Some(state.detached.get(&ino.0).cloned().ok_or(Errno::EIO)?));
                    }
                    let file = state
                        .files
                        .get(&handle.0)
                        .filter(|file| file.ino == ino.0)
                        .ok_or(Errno::EBADF)?;
                    if file.failed {
                        return Err(Errno::EIO);
                    }
                }
                Ok(Some(state.detached.get(&ino.0).cloned().ok_or(Errno::EIO)?))
            });
            match result {
                Ok(Some(node)) => {
                    let mut value = attr(ino.0, &node);
                    value.nlink = 0;
                    reply.attr(&Duration::ZERO, &value);
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    reply.error(error);
                    return;
                }
            }
        }
        let result = self.node(ino).and_then(|node| {
            if u64::from(ino) == 1 {
                return Ok(node);
            }
            self.browse_entry(INodeNo(node.parent), node.path.last().ok_or(Errno::EIO)?)?
                .filter(|(id, _)| *id == ino.0)
                .map(|(_, node)| node)
                .ok_or(Errno::ENOENT)
        });
        match result {
            Ok(node) => reply.attr(&Duration::ZERO, &attr(u64::from(ino), &node)),
            Err(error) => reply.error(error),
        }
    }

    fn opendir(&self, _: &Request, ino: INodeNo, _: OpenFlags, reply: ReplyOpen) {
        let result = (|| {
            let children = self.browse(ino, |_, _, cached| Some(cached.children.clone()))?;
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            // A directory rename can finish after listing but before handle
            // registration. Bind '..' to the current live inode, not a node
            // captured outside this lock; the child snapshot stays immutable.
            let parent = state
                .nodes
                .get(&ino.0)
                .filter(|node| state.paths.get(&node.path) == Some(&ino.0))
                .map(|node| node.parent)
                .ok_or(Errno::ENOENT)?;
            if state.handles.len() >= MAX_HANDLES {
                return Err(Errno::EMFILE);
            }
            let handle = state.next_handle;
            state.next_handle = state.next_handle.checked_add(1).ok_or(Errno::EMFILE)?;
            state.handles.insert(
                handle,
                OpenDirectory {
                    ino: ino.0,
                    parent,
                    children,
                },
            );
            state.browse_focus = Some(ino.0);
            Ok(handle)
        })();
        match result {
            Ok(handle) => reply.opened(FileHandle(handle), FopenFlags::empty()),
            Err(error) => reply.error(error),
        }
    }

    fn readdir(
        &self,
        _: &Request,
        _: INodeNo,
        handle: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let directory = self
            .state
            .lock()
            .map_err(|_| Errno::EIO)
            .and_then(|state| state.handles.get(&handle.0).cloned().ok_or(Errno::EBADF));
        let directory = match directory {
            Ok(directory) => directory,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        if offset == 0 && reply.add(INodeNo(directory.ino), 1, FileType::Directory, ".") {
            reply.ok();
            return;
        }
        if offset <= 1 && reply.add(INodeNo(directory.parent), 2, FileType::Directory, "..") {
            reply.ok();
            return;
        }
        let page = match directory.children.page(offset.saturating_sub(2)) {
            Ok(page) => page,
            Err(error) => {
                reply.error(error);
                return;
            }
        };
        for (cookie, id, kind, name) in page {
            if reply.add(INodeNo(id), cookie + 2, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _: &Request,
        ino: INodeNo,
        handle: FileHandle,
        _: OpenFlags,
        reply: ReplyEmpty,
    ) {
        let directory = self.state.lock().map_err(|_| Errno::EIO).map(|mut state| {
            let directory = state.handles.remove(&handle.0);
            let detached = if state.detached.contains_key(&ino.0)
                && !state
                    .handles
                    .values()
                    .any(|directory| directory.ino == ino.0)
            {
                state.detached.remove(&ino.0)
            } else {
                None
            };
            (directory, detached)
        });
        match directory {
            Ok(directory) => {
                drop(directory);
                reply.ok();
            }
            Err(error) => reply.error(error),
        }
    }

    fn open(&self, _: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let writable = flags.0 & (OFlags::WRONLY | OFlags::RDWR).bits() as i32 != 0;
        if writable && self.space.is_offline() && !self.space.is_offline_writable() {
            reply.error(Errno::EROFS);
            return;
        }
        let result = (|| {
            let mutation = if writable {
                let (guard, _) = self.prepare_write_for_mutation(
                    ino,
                    flags.0 & OFlags::TRUNC.bits() as i32 != 0,
                    true,
                )?;
                Some(guard)
            } else {
                None
            };
            let node = self.node(ino)?;
            if node.directory {
                return Err(Errno::EISDIR);
            }
            #[cfg(feature = "fault-injection")]
            if !writable {
                wait_test_window("CIRRUS_TEST_READ_OPEN_WINDOW")?;
            }
            let version = self.accounts.mount_open_file(
                &self.instance,
                &self.space,
                &node.path,
                &node.resource_id,
            );
            let _mutation = match mutation {
                Some(guard) => guard,
                None => self.mutation.lock().map_err(|_| Errno::EIO)?,
            };
            let namespace = self.namespace()?;
            let mut draft = (*namespace).clone();
            if let Ok(version) = &version {
                let current = draft
                    .nodes
                    .get_mut(&ino.0)
                    .filter(|current| {
                        current.path == node.path && current.resource_id == node.resource_id
                    })
                    .ok_or(Errno::EIO)?;
                let changed = current.size != version.size()
                    || current.etag.as_deref() != Some(version.etag())
                    || current.checksums != version.checksums();
                current.size = version.size();
                current.etag = Some(version.etag().to_owned().into());
                current.checksums = version.checksums().to_vec();
                current.revision = current.revision.wrapping_add(u64::from(changed));
                if !version.id().starts_with("cirrus-staged:")
                    && !draft.observed.contains_key(&node.path)
                {
                    if draft.observed.len() >= MAX_NODES {
                        draft.observations_exhausted = true;
                    } else {
                        draft.observed.insert(
                            node.path.clone(),
                            (version.id().to_owned(), version.etag().to_owned()),
                        );
                    }
                }
            }
            let draft = Arc::new(draft);
            let version = version.map(SharedVersion::new);
            let mut retired_ranges = Vec::with_capacity(CACHE_MAX_ENTRIES);
            let retired_namespace;
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            let Some(current) = state.nodes.get(&u64::from(ino)) else {
                return Err(Errno::EIO);
            };
            let matches_published_version = !writable
                && version.as_ref().is_ok_and(|version| {
                    current.path == node.path
                        && current.resource_id == node.resource_id
                        && current.matches_version(version)
                });
            if current.revision != node.revision && !matches_published_version {
                return Err(Errno::EIO);
            }
            let version = match &version {
                Ok(version) => version.clone(),
                Err(_) => {
                    state.invalidate_id(&node.resource_id, &mut retired_ranges);
                    return Err(Errno::EIO);
                }
            };
            if state.files.len() >= MAX_HANDLES {
                return Err(Errno::EMFILE);
            }
            if state.paths.get(&node.path) != Some(&u64::from(ino)) {
                return Err(Errno::EIO);
            }
            state.observe_version(&version, &mut retired_ranges);
            retired_namespace = std::mem::replace(&mut state.namespace, draft);
            let handle = state.next_handle;
            state.next_handle = handle.checked_add(1).ok_or(Errno::EMFILE)?;
            state.files.insert(
                handle,
                OpenFile {
                    ino: u64::from(ino),
                    version,
                    namespace_rebind: 0,
                    failed: false,
                    writable,
                    append: flags.0 & OFlags::APPEND.bits() as i32 != 0,
                    last_read: None,
                },
            );
            drop(state);
            drop(retired_namespace);
            Ok(handle)
        })();
        match result {
            Ok(handle) => reply.opened(FileHandle(handle), FopenFlags::FOPEN_DIRECT_IO),
            Err(error) => reply.error(error),
        }
    }

    fn create(
        &self,
        _: &Request,
        parent: INodeNo,
        name: &OsStr,
        _: u32,
        _: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let result = (|| {
            let name = name.to_str().ok_or(Errno::EINVAL)?;
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.len() > 255
                || name.chars().any(char::is_control)
            {
                return Err(Errno::EINVAL);
            }
            #[cfg(feature = "fault-injection")]
            wait_test_window("CIRRUS_TEST_CREATE_WINDOW")?;
            let (_guard, parent_node) = self.lock_vacant_parent(parent, name)?;
            let id = {
                let state = self.state.lock().map_err(|_| Errno::EIO)?;
                if state.files.len() >= MAX_HANDLES {
                    return Err(Errno::EMFILE);
                }
                if state.nodes.len() + state.detached.len() >= MAX_NODES {
                    return Err(Errno::ENOSPC);
                }
                state.next_node
            };
            let mut path = parent_node.path.clone();
            path.push(name.to_owned());
            let parents = self.namespace()?.parent_identities(&path)?;
            let version = self
                .accounts
                .stage_mount_mutation(
                    &self.instance,
                    &self.space,
                    &path,
                    DirtyMutation::Preserve,
                    None,
                    &parents,
                )
                .map_err(|error| {
                    eprintln!("staged create failed: {error}");
                    stage_error(&error)
                })?;
            let current = self.namespace()?;
            let mut namespace = (*current).clone();
            let next_node = id.checked_add(1).ok_or(Errno::ENOSPC)?;
            let node = Node {
                path: path.clone(),
                parent: parent.0,
                directory: false,
                size: 0,
                modified: SystemTime::now(),
                resource_id: version.id().to_owned().into(),
                etag: Some(version.etag().to_owned().into()),
                checksums: Vec::new(),
                revision: 0,
            };
            namespace.paths.insert(path, id);
            namespace.nodes.insert(id, node.clone());
            namespace.mutation_epoch = namespace.mutation_epoch.wrapping_add(1);
            let namespace = Arc::new(namespace);
            let version = SharedVersion::new(version);
            let retired_namespace;
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            state.next_node = next_node;
            let handle = state.next_handle;
            state.next_handle = handle.checked_add(1).ok_or(Errno::EMFILE)?;
            state.files.insert(
                handle,
                OpenFile {
                    ino: id,
                    version,
                    namespace_rebind: 0,
                    failed: false,
                    writable: true,
                    append: flags & OFlags::APPEND.bits() as i32 != 0,
                    last_read: None,
                },
            );
            retired_namespace = std::mem::replace(&mut state.namespace, namespace);
            drop(state);
            drop(retired_namespace);
            Ok((id, handle, node))
        })();
        match result {
            Ok((id, handle, node)) => reply.created(
                &Duration::ZERO,
                &attr(id, &node),
                Generation(0),
                FileHandle(handle),
                FopenFlags::FOPEN_DIRECT_IO,
            ),
            Err(error) => reply.error(error),
        }
    }

    fn write(
        &self,
        _: &Request,
        ino: INodeNo,
        handle: FileHandle,
        offset: u64,
        data: &[u8],
        _: WriteFlags,
        _: OpenFlags,
        _: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let result = (|| {
            let _guard = self.mutation.lock().map_err(|_| Errno::EIO)?;
            let (version, append, detached) = {
                let state = self.state.lock().map_err(|_| Errno::EIO)?;
                let file = state.files.get(&handle.0).ok_or(Errno::EBADF)?;
                if file.ino != ino.0 || !file.writable {
                    return Err(Errno::EBADF);
                }
                if file.failed {
                    return Err(Errno::EIO);
                }
                (
                    file.version.clone(),
                    file.append,
                    state.detached.contains_key(&ino.0),
                )
            };
            let start = if append { version.size() } else { offset };
            start
                .checked_add(data.len() as u64)
                .filter(|end| *end <= MAX_WRITE_FILE)
                .ok_or(Errno::EFBIG)?;
            if detached {
                let staged = self
                    .accounts
                    .stage_detached_mutation(
                        &self.space,
                        &version,
                        DirtyMutation::Write {
                            offset: start,
                            bytes: data,
                        },
                    )
                    .map_err(|error| stage_error(&error))?;
                self.publish_detached(ino, &staged)?;
            } else {
                let node = self.node(ino)?;
                let parents = self.namespace()?.parent_identities(&node.path)?;
                let staged = self
                    .accounts
                    .stage_mount_mutation(
                        &self.instance,
                        &self.space,
                        &node.path,
                        DirtyMutation::Write {
                            offset: start,
                            bytes: data,
                        },
                        Some(&version),
                        &parents,
                    )
                    .map_err(|error| stage_error(&error))?;
                self.publish_version(ino, &node, &staged)?;
            }
            Ok(data.len() as u32)
        })();
        match result {
            Ok(count) => reply.written(count),
            Err(error) => reply.error(error),
        }
    }

    fn flush(
        &self,
        _: &Request,
        ino: INodeNo,
        handle: FileHandle,
        _: LockOwner,
        reply: ReplyEmpty,
    ) {
        let result = (|| {
            let version = {
                let state = self.state.lock().map_err(|_| Errno::EIO)?;
                let file = state.files.get(&handle.0).ok_or(Errno::EIO)?;
                if file.ino != ino.0 || (file.writable && file.failed) {
                    return Err(Errno::EIO);
                }
                file.version.clone()
            };
            // A failed publication may nevertheless have committed. Never bless
            // an old handle merely because its in-memory failed bit is clear.
            if version.id().starts_with("cirrus-staged:") {
                self.accounts
                    .verify_file(&self.space, &version)
                    .map_err(|_| Errno::EIO)?;
            }
            // Closing a fork-inherited descriptor can flush while its parent
            // write owns mutation and awaits the child. Do not take that lock:
            // validate the local journal snapshot, then reject a changed handle.
            let state = self.state.lock().map_err(|_| Errno::EIO)?;
            if !state.files.get(&handle.0).is_some_and(|file| {
                file.ino == ino.0 && (!file.writable || !file.failed) && file.version == version
            }) {
                return Err(Errno::EIO);
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn fsync(&self, req: &Request, ino: INodeNo, handle: FileHandle, _: bool, reply: ReplyEmpty) {
        self.flush(req, ino, handle, LockOwner(0), reply);
    }

    fn setattr(
        &self,
        _: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        handle: Option<FileHandle>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if mode.is_some()
            || uid.is_some()
            || gid.is_some()
            || flags.is_some()
            || atime.is_some()
            || mtime.is_some()
            || ctime.is_some()
            || crtime.is_some()
            || chgtime.is_some()
            || bkuptime.is_some()
        {
            reply.error(Errno::EOPNOTSUPP);
            return;
        }
        let result = (|| {
            if let Some(handle) = handle
                && let Some(node) = self.resize_detached(ino, handle, size)?
            {
                return Ok((node, true));
            }
            let attached = (|| match size {
                Some(size) => {
                    if size > MAX_WRITE_FILE {
                        return Err(Errno::EFBIG);
                    }
                    let (_guard, version) = self.prepare_write_for_mutation(ino, false, false)?;
                    self.resize_file(ino, size, &version)
                        .map(|node| (node, false))
                }
                None => self.node(ino).map(|node| (node, false)),
            })();
            match attached {
                Ok(result) => Ok(result),
                Err(error) => {
                    if let Some(handle) = handle
                        && let Some(node) = self.resize_detached(ino, handle, size)?
                    {
                        return Ok((node, true));
                    }
                    Err(error)
                }
            }
        })();
        match result {
            Ok((node, detached)) => {
                let mut value = attr(ino.0, &node);
                if detached {
                    value.nlink = 0;
                }
                reply.attr(&Duration::ZERO, &value);
            }
            Err(error) => reply.error(error),
        }
    }

    fn mkdir(&self, _: &Request, parent: INodeNo, name: &OsStr, _: u32, _: u32, reply: ReplyEntry) {
        if self.space.is_offline() && !self.space.is_offline_writable() {
            reply.error(Errno::EROFS);
            return;
        }
        let result = (|| {
            let name = name.to_str().ok_or(Errno::EINVAL)?;
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.len() > 255
                || name.chars().any(char::is_control)
            {
                return Err(Errno::EINVAL);
            }
            #[cfg(feature = "fault-injection")]
            wait_test_window("CIRRUS_TEST_MKDIR_WINDOW")?;
            let (_guard, parent_node) = self.lock_vacant_parent(parent, name)?;
            let id = {
                let state = self.state.lock().map_err(|_| Errno::EIO)?;
                if state.nodes.len() + state.detached.len() >= MAX_NODES
                    || state.next_node.checked_add(1).is_none()
                {
                    return Err(Errno::ENOSPC);
                }
                state.next_node
            };
            let mut path = parent_node.path;
            path.push(name.to_owned());
            let parents = self.namespace()?.parent_identities(&path)?;
            let operation = self
                .accounts
                .stage_namespace(&self.instance, &self.space, &path, "mkdir", None, &parents)
                .map_err(|error| stage_error(&error))?;
            let current = self.namespace()?;
            let mut namespace = (*current).clone();
            let node = Node {
                path: path.clone(),
                parent: parent.0,
                directory: true,
                size: 0,
                modified: UNIX_EPOCH,
                resource_id: format!("cirrus-dir:{operation}").into(),
                etag: None,
                checksums: Vec::new(),
                revision: 0,
            };
            namespace.paths.insert(path, id);
            namespace.nodes.insert(id, node.clone());
            namespace.mutation_epoch = namespace.mutation_epoch.wrapping_add(1);
            let namespace = Arc::new(namespace);
            let retired_namespace;
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            state.next_node = id + 1;
            retired_namespace = std::mem::replace(&mut state.namespace, namespace);
            drop(state);
            drop(retired_namespace);
            Ok((id, node))
        })();
        match result {
            Ok((id, node)) => reply.entry(&Duration::ZERO, &attr(id, &node), Generation(0)),
            Err(error) => reply.error(error),
        }
    }
    fn unlink(&self, _: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.remove_namespace(parent, name, false) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }
    fn rmdir(&self, _: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.remove_namespace(parent, name, true) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }
    fn rename(
        &self,
        _: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if self.space.is_offline() && !self.space.is_offline_writable() {
            reply.error(Errno::EROFS);
            return;
        }
        let result = (|| {
            if !flags.is_empty() && flags != RenameFlags::RENAME_NOREPLACE {
                return Err(Errno::EOPNOTSUPP);
            }
            let name = name.to_str().ok_or(Errno::EINVAL)?;
            let newname = newname.to_str().ok_or(Errno::EINVAL)?;
            if newname.is_empty()
                || newname == "."
                || newname == ".."
                || newname.len() > 255
                || newname.chars().any(char::is_control)
            {
                return Err(Errno::EINVAL);
            }
            let mut foreground = None;
            #[cfg(feature = "fault-injection")]
            wait_test_window("CIRRUS_TEST_RENAME_SCAN_WINDOW")?;
            'retry: for _ in 0..8 {
                let LockedRenameInputs {
                    guard: mut _guard,
                    source: source_listing,
                    destination: destination_listing,
                    source_children,
                    destination_children,
                    source_file,
                } = self.lock_rename_inputs(
                    parent,
                    newparent,
                    name,
                    newname,
                    flags,
                    &mut foreground,
                )?;
                let source_id = source_listing
                    .find(name)?
                    .map(|entry| entry.0)
                    .ok_or(Errno::ENOENT)?;
                if parent == newparent && name == newname {
                    if flags.contains(RenameFlags::RENAME_NOREPLACE) {
                        return Err(Errno::EEXIST);
                    }
                    return Ok(());
                }
                let mut source = self.node(INodeNo(source_id))?;
                let target = destination_listing.find(newname)?.map(|entry| entry.0);
                if target.is_some() && flags.contains(RenameFlags::RENAME_NOREPLACE) {
                    return Err(Errno::EEXIST);
                }
                if source.directory {
                    let new_parent = self.node(newparent)?;
                    let mut destination = new_parent.path.clone();
                    destination.push(newname.to_owned());
                    let (source_parents, destination_parents) = {
                        let state = self.namespace()?;
                        (
                            state.parent_identities(&source.path)?,
                            state.parent_identities(&destination)?,
                        )
                    };
                    if destination.starts_with(&source.path) {
                        return Err(Errno::EINVAL);
                    }
                    if !self.space.is_offline()
                        && !source.resource_id.starts_with("cirrus-dir:")
                        && target.is_none()
                        && source_children.as_ref().ok_or(Errno::EIO)?.is_empty()?
                        && !self
                            .accounts
                            .has_unresolved_subtree(&self.instance, &self.space, &source.path)
                            .map_err(|error| stage_error(&error))?
                    {
                        let state = self.state.lock().map_err(|_| Errno::EIO)?;
                        let in_tree = |id: u64| {
                            state
                                .nodes
                                .get(&id)
                                .is_some_and(|node| node.path.starts_with(&source.path))
                        };
                        let open = state.files.values().any(|file| in_tree(file.ino))
                            || state
                                .handles
                                .values()
                                .any(|directory| in_tree(directory.ino));
                        if !open {
                            let etag = source.etag.as_deref().ok_or(Errno::EOPNOTSUPP)?;
                            if foreground.is_none() {
                                foreground = Some(self.accounts.request_foreground());
                            }
                            let epoch = state.mutation_epoch;
                            let generation = self.accounts.metadata_generation();
                            drop(state);
                            // Account ownership remains with preparation, but
                            // neither FUSE state nor mutation ownership spans DAV.
                            drop(_guard);
                            let prepared = match self.accounts.prepare_empty_directory(
                                &self.instance,
                                &self.space,
                                &source.path,
                                &destination,
                                (&source.resource_id, etag),
                                cirrus_account::RenameParents {
                                    source: &source_parents,
                                    destination: &destination_parents,
                                },
                            ) {
                                Ok(prepared) => prepared,
                                Err(error) if error.is_metadata_changed() => continue 'retry,
                                Err(error) => return Err(stage_error(&error)),
                            };
                            let _guard = self.mutation.lock().map_err(|_| Errno::EIO)?;
                            let current = self.namespace()?;
                            if current.mutation_epoch != epoch
                                || current.paths.get(&source.path) != Some(&source_id)
                                || current.paths.contains_key(&destination)
                                || current.nodes.get(&source_id).is_none_or(|current| {
                                    current.revision != source.revision
                                        || current.resource_id != source.resource_id
                                        || current.etag != source.etag
                                })
                                || current.parent_identities(&source.path)? != source_parents
                                || current.parent_identities(&destination)? != destination_parents
                            {
                                drop(prepared);
                                continue 'retry;
                            }
                            let mut draft = (*current).clone();
                            draft.paths.remove(&source.path);
                            draft.paths.insert(destination.clone(), source_id);
                            draft.observed.retain(|path, _| {
                                !path.starts_with(&source.path) && !path.starts_with(&destination)
                            });
                            let node = draft.nodes.get_mut(&source_id).ok_or(Errno::EIO)?;
                            node.path = destination.clone();
                            node.parent = newparent.0;
                            let mut identity = String::with_capacity(32);
                            identity.push_str("cirrus-dir:");
                            node.resource_id = identity.into();
                            node.etag = None;
                            node.revision = node.revision.wrapping_add(1);
                            draft.mutation_epoch = draft.mutation_epoch.wrapping_add(1);
                            let mut draft = Arc::new(draft);
                            let retired_namespace;
                            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
                            if !Arc::ptr_eq(&state.namespace, &current)
                                || self.accounts.metadata_generation() != generation
                            {
                                continue 'retry;
                            }
                            let in_tree = |id: u64| {
                                state
                                    .nodes
                                    .get(&id)
                                    .is_some_and(|node| node.path.starts_with(&source.path))
                            };
                            if state.files.values().any(|file| in_tree(file.ino))
                                || state
                                    .handles
                                    .values()
                                    .any(|directory| in_tree(directory.ino))
                            {
                                return Err(Errno::EBUSY);
                            }
                            let node = Arc::get_mut(&mut draft)
                                .expect("private namespace")
                                .nodes
                                .get_mut(&source_id)
                                .expect("prepared directory");
                            let ResourceText::Literal(identity) = &mut node.resource_id else {
                                unreachable!("prepared directory identity");
                            };
                            let id = prepared.commit().map_err(|error| stage_error(&error))?;
                            ResourceText::bind_directory_id(identity, id);
                            retired_namespace = std::mem::replace(&mut state.namespace, draft);
                            drop(state);
                            drop(retired_namespace);
                            return Ok(());
                        }
                    }
                    let target_node = target.map(|id| self.node(INodeNo(id))).transpose()?;
                    if let Some(node) = &target_node {
                        if !node.directory {
                            return Err(Errno::ENOTDIR);
                        }
                        if !destination_children
                            .as_ref()
                            .ok_or(Errno::EIO)?
                            .is_empty()?
                        {
                            return Err(Errno::ENOTEMPTY);
                        }
                        if source.resource_id.starts_with("cirrus-dir:")
                            && !node.resource_id.starts_with("cirrus-dir:")
                            && !self.space.is_offline_writable()
                        {
                            return Err(Errno::EOPNOTSUPP);
                        }
                    }
                    let detach_target = self.space.is_offline_writable()
                        && target_node
                            .as_ref()
                            .is_some_and(|node| !node.resource_id.starts_with("cirrus-dir:"));
                    let mut open = Vec::with_capacity(MAX_HANDLES);
                    let state = self.state.lock().map_err(|_| Errno::EIO)?;
                    if !detach_target
                        && target.is_some_and(|id| {
                            state.handles.values().any(|directory| directory.ino == id)
                        })
                    {
                        return Err(Errno::EBUSY);
                    }
                    open.extend(
                        state
                            .files
                            .iter()
                            .filter(|(_, file)| {
                                !file.failed
                                    && !state.detached.contains_key(&file.ino)
                                    && state
                                        .nodes
                                        .get(&file.ino)
                                        .is_some_and(|node| node.path.starts_with(&source.path))
                            })
                            .map(|(handle, file)| (*handle, file.version.clone())),
                    );
                    let epoch = state.mutation_epoch;
                    let generation = self.accounts.metadata_generation();
                    let initial = state.namespace.clone();
                    drop(state);
                    let versions = open
                        .iter()
                        .map(|(_, version)| (**version).clone())
                        .collect::<Vec<_>>();
                    let open_directories: Vec<_> = initial
                        .nodes
                        .iter()
                        .filter(|(id, node)| {
                            node.directory
                                && node.path.starts_with(&source.path)
                                && node.resource_id.starts_with("cirrus-dir:")
                                && initial.paths.get(&node.path) == Some(*id)
                        })
                        .map(|(_, node)| (node.path.clone(), node.resource_id.to_string()))
                        .collect();
                    drop(initial);
                    let local_target = target_node
                        .as_ref()
                        .filter(|node| node.resource_id.starts_with("cirrus-dir:"))
                        .map(|node| node.resource_id.as_str());
                    let prepared = if source.resource_id.starts_with("cirrus-dir:") {
                        None
                    } else {
                        let etag = source.etag.as_deref().ok_or(Errno::EOPNOTSUPP)?;
                        let expected = target_node
                            .as_ref()
                            .filter(|node| !node.resource_id.starts_with("cirrus-dir:"))
                            .map(|node| {
                                node.etag
                                    .as_deref()
                                    .map(|tag| (node.resource_id.as_str(), tag))
                                    .ok_or(Errno::EOPNOTSUPP)
                            })
                            .transpose()?;
                        if foreground.is_none() {
                            foreground = Some(self.accounts.request_foreground());
                        }
                        drop(_guard);
                        let prepared = match self.accounts.prepare_remote_tree(
                            &self.instance,
                            &self.space,
                            (&source.path, &source.resource_id, etag),
                            &destination,
                            expected,
                            local_target,
                            &versions,
                            cirrus_account::RenameParents {
                                source: &source_parents,
                                destination: &destination_parents,
                            },
                            &open_directories,
                        ) {
                            Ok(prepared) => prepared,
                            Err(error) if error.is_metadata_changed() => continue 'retry,
                            Err(error) => return Err(stage_error(&error)),
                        };
                        _guard = self.mutation.lock().map_err(|_| Errno::EIO)?;
                        Some(prepared)
                    };
                    let current = self.namespace()?;
                    if prepared.is_some() {
                        let same_node = |id: u64, node: &Node| {
                            current.paths.get(&node.path) == Some(&id)
                                && current.nodes.get(&id).is_some_and(|current| {
                                    current.revision == node.revision
                                        && current.resource_id == node.resource_id
                                        && current.etag == node.etag
                                })
                        };
                        if current.mutation_epoch != epoch
                            || self.accounts.metadata_generation() != generation
                            || !same_node(source_id, &source)
                            || current.paths.get(&destination).copied() != target
                            || target
                                .zip(target_node.as_ref())
                                .is_some_and(|(id, node)| !same_node(id, node))
                            || current.parent_identities(&source.path)? != source_parents
                            || current.parent_identities(&destination)? != destination_parents
                        {
                            drop(prepared);
                            continue 'retry;
                        }
                    }
                    let mut draft = (*current).clone();
                    let detached_target = target.and_then(|id| {
                        draft.paths.remove(&destination);
                        draft.scans.remove(&id);
                        draft.nodes.remove(&id).map(Arc::new)
                    });
                    let paths: Vec<_> = draft
                        .paths
                        .iter()
                        .filter(|(path, _)| path.starts_with(&source.path))
                        .map(|(path, id)| (path.clone(), *id))
                        .collect();
                    for (path, id) in paths {
                        draft.paths.remove(&path);
                        let mut next = destination.clone();
                        next.extend_from_slice(&path[source.path.len()..]);
                        draft.paths.insert(next.clone(), id);
                        if let Some(node) = draft.nodes.get_mut(&id) {
                            node.path = next;
                            if id == source_id {
                                node.parent = newparent.0;
                            }
                            node.revision = node.revision.wrapping_add(1);
                        }
                    }
                    draft.observed.retain(|path, _| {
                        !path.starts_with(&source.path) && !path.starts_with(&destination)
                    });
                    draft.mutation_epoch = draft.mutation_epoch.wrapping_add(1);
                    let draft = Arc::new(draft);
                    let owners: Vec<_> = open.iter().map(|_| SharedVersion::unbound()).collect();
                    let mut retired_versions = Vec::with_capacity(MAX_HANDLES);
                    let mut retired_ranges = Vec::with_capacity(CACHE_MAX_ENTRIES);
                    let retired_namespace;
                    let mut relocated;
                    let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
                    if !Arc::ptr_eq(&state.namespace, &current) {
                        continue 'retry;
                    }
                    if prepared.is_some() {
                        let same_listing = |id: u64, view: &DirectoryView| {
                            state
                                .directories
                                .iter()
                                .any(|cached| cached.ino == id && cached.children.matches(view))
                        };
                        if self.accounts.metadata_generation() != generation
                            || !same_listing(parent.0, &source_listing)
                            || !same_listing(newparent.0, &destination_listing)
                            || source_children
                                .as_ref()
                                .is_some_and(|view| !same_listing(source_id, view))
                            || target
                                .zip(destination_children.as_ref())
                                .is_some_and(|(id, view)| !same_listing(id, view))
                        {
                            continue 'retry;
                        }
                    }
                    if !detach_target
                        && target.is_some_and(|id| {
                            state.handles.values().any(|directory| directory.ino == id)
                        })
                    {
                        return Err(Errno::EBUSY);
                    }
                    if prepared.is_some()
                        && open.iter().any(|(handle, version)| {
                            state.files.get(handle).is_some_and(|file| {
                                file.failed
                                    || file.version != *version
                                    || state.detached.contains_key(&file.ino)
                            })
                        })
                    {
                        return Err(Errno::EIO);
                    }
                    // Opens need not advance the namespace epoch. Include
                    // every new live source handle in the next preparation;
                    // never leave it at the old path after tree publication.
                    if prepared.is_some()
                        && state.files.iter().any(|(handle, file)| {
                            !file.failed
                                && !state.detached.contains_key(&file.ino)
                                && state
                                    .nodes
                                    .get(&file.ino)
                                    .is_some_and(|node| node.path.starts_with(&source.path))
                                && !open.iter().any(|(known, version)| {
                                    known == handle && *version == file.version
                                })
                        })
                    {
                        continue 'retry;
                    }
                    relocated = VecDeque::from(
                        if let Some(prepared) = prepared {
                            prepared.commit()
                        } else {
                            self.accounts.rename_local_directory(
                                &self.instance,
                                &self.space,
                                &source.path,
                                &destination,
                                &source.resource_id,
                                target_node
                                    .as_ref()
                                    .map(|node| (node.resource_id.as_str(), node.etag.as_deref())),
                                &versions,
                                cirrus_account::RenameParents {
                                    source: &source_parents,
                                    destination: &destination_parents,
                                },
                            )
                        }
                        .map_err(|error| stage_error(&error))?,
                    );
                    for ((handle, _), owner) in open.iter().zip(&owners) {
                        let Some(version) = relocated.pop_front() else {
                            break;
                        };
                        owner.bind(version);
                        if let Some(file) = state.files.get_mut(&handle) {
                            retired_versions.push(file.rebind_namespace(owner.clone()));
                        }
                    }
                    state.retire_ranges(&mut retired_ranges, |entry| {
                        owners
                            .iter()
                            .filter(|owner| owner.0.get().is_some())
                            .any(|owner| owner.id() == entry.version.id())
                    });
                    for directory in state.handles.values_mut() {
                        if directory.ino == source_id {
                            directory.parent = newparent.0;
                        }
                    }
                    if let Some(id) = target {
                        if detach_target
                            && state.handles.values().any(|directory| directory.ino == id)
                        {
                            if let Some(node) = &detached_target {
                                state.detached.insert(id, node.clone());
                            }
                        }
                    }
                    retired_namespace = std::mem::replace(&mut state.namespace, draft);
                    drop(state);
                    drop(retired_namespace);
                    return Ok(());
                }
                let mut target_node = target.map(|id| self.node(INodeNo(id))).transpose()?;
                if target_node.as_ref().is_some_and(|node| node.directory) {
                    return Err(Errno::EISDIR);
                }
                if target_node.as_ref().is_some_and(|node| node.etag.is_none()) {
                    return Err(Errno::EOPNOTSUPP);
                }
                let target_open = if let Some(id) = target {
                    let state = self.state.lock().map_err(|_| Errno::EIO)?;
                    if let Some(node) = target_node.as_ref()
                        && state.files.values().any(|file| {
                            file.ino == id
                                && !file.failed
                                && (file.version.id() != node.resource_id
                                    || Some(file.version.etag()) != node.etag.as_deref()
                                    || file.version.size() != node.size)
                        })
                    {
                        return Err(Errno::EBUSY);
                    }
                    state.files.values().any(|file| file.ino == id)
                } else {
                    false
                };
                if (target_open || self.space.is_offline())
                    && let Some(id) = target
                    && !target_node
                        .as_ref()
                        .is_some_and(|node| node.resource_id.starts_with("cirrus-staged:"))
                {
                    self.prepare_write_checked(INodeNo(id), false, true)?;
                    target_node = Some(self.node(INodeNo(id))?);
                }
                let pending_target = target_node
                    .as_ref()
                    .filter(|node| node.resource_id.starts_with("cirrus-staged:"))
                    .map(|node| {
                        self.accounts.mount_open_file(
                            &self.instance,
                            &self.space,
                            &node.path,
                            &node.resource_id,
                        )
                    })
                    .transpose()
                    .map_err(|_| Errno::EIO)?;
                let new_parent = self.node(newparent)?;
                let mut destination = new_parent.path.clone();
                destination.push(newname.to_owned());
                let observed = {
                    let state = self.namespace()?;
                    let observed = state.observed.get(&destination).cloned();
                    if state.observations_exhausted
                        && observed.is_none()
                        && pending_target.is_none()
                    {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    observed
                };
                let version = if source.resource_id.starts_with("cirrus-staged:") {
                    self.accounts
                        .mount_open_file(
                            &self.instance,
                            &self.space,
                            &source.path,
                            &source.resource_id,
                        )
                        .map_err(|_| Errno::EIO)?
                } else {
                    let version = if let Some(prepared) = source_file {
                        self.stage_write_source(
                            INodeNo(source_id),
                            &prepared.node,
                            prepared.version,
                            prepared.data,
                        )?
                    } else {
                        self.prepare_write(INodeNo(source_id), false)?
                    };
                    source = self.node(INodeNo(source_id))?;
                    version
                };
                let expected = target_node.as_ref().and_then(|node| {
                    node.etag
                        .as_deref()
                        .map(|etag| (node.resource_id.as_str(), etag))
                });
                let (source_parents, destination_parents) = {
                    let state = self.namespace()?;
                    (
                        state.parent_identities(&source.path)?,
                        state.parent_identities(&destination)?,
                    )
                };
                let generation = self.accounts.metadata_generation();
                drop(_guard);
                let prepared = match self.accounts.prepare_file_rename(
                    &self.instance,
                    &self.space,
                    &version,
                    &destination,
                    expected,
                    observed
                        .as_ref()
                        .map(|(id, etag)| (id.as_str(), etag.as_str())),
                    pending_target.as_ref(),
                    cirrus_account::RenameParents {
                        source: &source_parents,
                        destination: &destination_parents,
                    },
                ) {
                    Ok(prepared) => prepared,
                    Err(error) if error.is_metadata_changed() => continue 'retry,
                    Err(error) => {
                        eprintln!("staged rename failed: {error}");
                        return Err(stage_error(&error));
                    }
                };
                let _guard = self.mutation.lock().map_err(|_| Errno::EIO)?;
                let current = self.namespace()?;
                if current.observed.get(&destination) != observed.as_ref()
                    || (current.observations_exhausted
                        && observed.is_none()
                        && pending_target.is_none())
                    || !current
                        .parent_identities(&source.path)
                        .is_ok_and(|parents| parents == source_parents)
                    || !current
                        .parent_identities(&destination)
                        .is_ok_and(|parents| parents == destination_parents)
                {
                    continue 'retry;
                }
                let renamed_owner = SharedVersion::unbound();
                let detached_owner = SharedVersion::unbound();
                let mut draft = (*current).clone();
                draft.paths.remove(&source.path);
                draft.observed.remove(&source.path);
                draft.observed.remove(&destination);
                let detached_node =
                    target
                        .and_then(|id| draft.nodes.remove(&id))
                        .map(|mut node| {
                            node.resource_id = ResourceText::VersionId(detached_owner.clone());
                            node.etag = Some(ResourceText::VersionTag(detached_owner.clone()));
                            Arc::new(node)
                        });
                let mut node = source.clone();
                node.path = destination.clone();
                node.parent = newparent.0;
                node.resource_id = ResourceText::VersionId(renamed_owner.clone());
                node.etag = Some(ResourceText::VersionTag(renamed_owner.clone()));
                node.revision = node.revision.wrapping_add(1);
                draft.paths.insert(destination.clone(), source_id);
                draft.nodes.insert(source_id, node);
                draft.mutation_epoch = draft.mutation_epoch.wrapping_add(1);
                let mut draft = Arc::new(draft);
                let mut retired_versions = Vec::with_capacity(MAX_HANDLES);
                let mut retired_ranges = Vec::with_capacity(CACHE_MAX_ENTRIES);
                let retired_namespace;
                let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
                let source_stable = state.paths.get(&source.path) == Some(&source_id)
                    && state.nodes.get(&source_id).is_some_and(|node| {
                        node.resource_id == source.resource_id && node.revision == source.revision
                    })
                    && !state.detached.contains_key(&source_id)
                    && state.files.values().all(|file| {
                        file.ino != source_id || file.failed || file.version == version
                    });
                let target_stable = match (target, &target_node) {
                    (None, None) => !state.paths.contains_key(&destination),
                    (Some(id), Some(node)) => {
                        state.paths.get(&destination) == Some(&id)
                            && state.nodes.get(&id).is_some_and(|current| {
                                current.resource_id == node.resource_id
                                    && current.revision == node.revision
                            })
                            && state.files.values().all(|file| {
                                file.ino != id
                                    || file.failed
                                    || (file.version.id() == node.resource_id
                                        && Some(file.version.etag()) == node.etag.as_deref()
                                        && file.version.size() == node.size)
                            })
                            && (pending_target.is_some()
                                || !state.files.values().any(|file| file.ino == id))
                    }
                    _ => false,
                };
                if !source_stable
                    || !target_stable
                    || !Arc::ptr_eq(&state.namespace, &current)
                    || self.accounts.metadata_generation() != generation
                {
                    continue 'retry;
                }
                let source_node = Arc::get_mut(&mut draft)
                    .expect("private namespace")
                    .nodes
                    .get_mut(&source_id)
                    .expect("prepared source");
                let (renamed, detached_target) = prepared.commit().map_err(|error| {
                    eprintln!("staged rename failed: {error}");
                    stage_error(&error)
                })?;
                source_node.size = renamed.size();
                renamed_owner.bind(renamed);
                if let Some(id) = target {
                    if let Some(version) = detached_target {
                        detached_owner.bind(version);
                        if state.files.values().any(|file| file.ino == id) {
                            if let Some(node) = &detached_node {
                                state.detached.insert(id, node.clone());
                            }
                            for file in state
                                .files
                                .values_mut()
                                .filter(|file| file.ino == id && !file.failed)
                            {
                                retired_versions.push(file.rebind_namespace(detached_owner.clone()));
                            }
                        }
                    }
                } else if let Some(version) = detached_target {
                    detached_owner.bind(version);
                }
                state.retire_ranges(&mut retired_ranges, |entry| {
                    entry.version.id() == source.resource_id
                        || target_node
                            .as_ref()
                            .is_some_and(|node| node.resource_id == entry.version.id())
                });
                for file in state
                    .files
                    .values_mut()
                    .filter(|file| file.ino == source_id && !file.failed)
                {
                    retired_versions.push(file.rebind_namespace(renamed_owner.clone()));
                }
                retired_namespace = std::mem::replace(&mut state.namespace, draft);
                drop(state);
                drop(retired_namespace);
                return Ok(());
            }
            Err(Errno::EIO)
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn read(
        &self,
        _: &Request,
        ino: INodeNo,
        handle: FileHandle,
        offset: u64,
        size: u32,
        _: OpenFlags,
        _: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let read_once = |retry_lineage: &mut Option<(u64, bool)>| {
            let mut retired_ranges = Vec::with_capacity(CACHE_MAX_ENTRIES * 2 + 1);
            let (version, lineage, length, cached, cache_generation, epoch, ranges) = {
                let _capture;
                let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
                // Decide under the same State guard used to capture the version.
                // If staged, wait out a journal-to-handle publication and recapture.
                if state
                    .read_file(ino, handle)?
                    .version
                    .id()
                    .starts_with("cirrus-staged:")
                {
                    drop(state);
                    _capture = self.mutation.lock().map_err(|_| Errno::EIO)?;
                    state = self.state.lock().map_err(|_| Errno::EIO)?;
                }
                let cache_generation = self.accounts.clean_cache_generation();
                state.refresh_cache_generation(cache_generation, &mut retired_ranges);
                let file = state.read_file(ino, handle)?;
                let staged = file.version.id().starts_with("cirrus-staged:");
                let detached = state.detached.contains_key(&ino.0);
                let lineage = (file.namespace_rebind, detached);
                if retry_lineage.is_some_and(|expected| expected != lineage) {
                    return Err(Errno::EIO);
                }
                let length = u64::from(size.min(MAX_RANGE))
                    .min(file.version.size().saturating_sub(offset))
                    as u32;
                if length == 0 && !staged {
                    return Ok(Some(Vec::new()));
                }
                let cached = state
                    .cache
                    .iter()
                    .find(|entry| {
                        length != 0
                            && entry.version == file.version
                            && entry.offset == offset
                            && entry.bytes.len() == length as usize
                    })
                    .cloned();
                let epoch = staged.then(|| self.engine.snapshot());
                // Capture references, not payloads. Planning and copying run
                // outside both locks. Only staged reads use this ABI.
                let ranges = if cached.is_none()
                    && length != 0
                    && epoch.is_some_and(|epoch| epoch.can_reuse())
                {
                    state
                        .cache
                        .iter()
                        .filter(|entry| {
                            entry.version == file.version
                                && entry.offset < offset + u64::from(length)
                                && entry.offset.saturating_add(entry.bytes.len() as u64) > offset
                        })
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                };
                (
                    file.version.clone(),
                    lineage,
                    length,
                    cached,
                    cache_generation,
                    epoch,
                    ranges,
                )
            };
            let (namespace_rebind, detached) = lineage;
            let staged = epoch.is_some();
            let request = offset..offset + u64::from(length);
            let planned = epoch.and_then(|epoch| {
                if ranges.is_empty() {
                    return None;
                }
                let plan = epoch.plan(request.clone(), &ranges)?;
                Some((epoch, plan))
            });
            #[cfg(feature = "fault-injection")]
            if planned.is_some() {
                wait_test_window("CIRRUS_TEST_READ_ENGINE_PLAN_WINDOW")?;
            }
            let composed = planned.and_then(|(epoch, plan)| {
                // No stale planner result may start effects. A retired
                // proposal falls back to the resident's ordinary demand read.
                (self.accounts.clean_cache_generation() == cache_generation
                    && self.engine.admit(epoch))
                .then_some(plan)
            });
            let using_engine = composed.is_some();
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_RETAINED_SH_OWNER").is_some()
                && staged
                && length != 0
            {
                eprintln!(
                    "cirrus lab owner read: pid={} thread={:?} boundary=fuse-read-dispatch handle={} cached={} offset={offset} length={length}",
                    std::process::id(),
                    std::thread::current().id(),
                    handle.0,
                    cached.is_some(),
                );
            }
            let fetched = if let Some(plan) = composed {
                self.accounts
                    .verify_file(&self.space, &version)
                    .map_err(|_| Errno::EIO)
                    .and_then(|()| plan.assemble(request).ok_or(Errno::EIO))
                    .map(Some)
            } else if length == 0 || cached.is_some() {
                self.accounts
                    .verify_file(&self.space, &version)
                    .map(|()| None)
                    .map_err(|_| Errno::EIO)
            } else {
                let priority = if staged {
                    // An old flight can still answer its own caller, but must
                    // not seed the staged cache for a new generation.
                    RangePriority::Staged(cache_generation)
                } else {
                    RangePriority::Foreground
                };
                self.fetch_range(&version, offset, length, priority).map(Some)
            };
            let mut prepared_range = if using_engine {
                None
            } else {
                fetched
                    .as_ref()
                    .ok()
                    .and_then(|bytes| bytes.as_ref())
                    .map(|bytes| {
                        Arc::new(CachedRange {
                            version: version.clone(),
                            offset,
                            bytes: bytes.clone(),
                        })
                    })
            };
            let mut cached_range = None;
            // Staged range I/O and flight joins above never own mutation. Wait
            // out local publication before trusting staged State (including EOF)
            // or poisoning an old remote version a writer could be replacing.
            let publication = if staged || fetched.is_err() {
                Some(self.mutation.lock().map_err(|_| Errno::EIO)?)
            } else {
                None
            };
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            let file = state.read_file(ino, handle).map_err(|_| Errno::EIO)?;
            let detached_now = state.detached.contains_key(&ino.0);
            if file.namespace_rebind != namespace_rebind {
                return Err(Errno::EIO);
            }
            if file.version != version {
                // A successful local write/resize (including remote -> staged)
                // may have superseded this attempt. Never retry failed, moved,
                // released or newly detached handles as ordinary writes.
                if detached == detached_now && file.version.id().starts_with("cirrus-staged:") {
                    *retry_lineage = Some(lineage);
                    return Ok(None);
                }
                return Err(Errno::EIO);
            }
            if staged {
                if fetched.is_err() {
                    // Missing original-base ranges may become available again.
                    return Err(Errno::EIO);
                }
                drop(state);
                // An ambiguous write/rename may have committed without rebinding
                // the handle. Check the durable head/fence, not just memory.
                let durable_detached = self
                    .accounts
                    .verify_staged_read_head(&self.space, &version)
                    .map_err(|_| Errno::EIO)?;
                state = self.state.lock().map_err(|_| Errno::EIO)?;
                let file = state.read_file(ino, handle).map_err(|_| Errno::EIO)?;
                if file.version != version
                    || file.namespace_rebind != namespace_rebind
                    || durable_detached != detached_now
                    || state.detached.contains_key(&ino.0) != detached_now
                {
                    return Err(Errno::EIO);
                }
                if length == 0 {
                    return Ok(Some(Vec::new()));
                }
            }
            let current_cache_generation = self.accounts.clean_cache_generation();
            state.refresh_cache_generation(current_cache_generation, &mut retired_ranges);
            if staged
                && (using_engine || cached.is_some())
                && cache_generation != current_cache_generation
            {
                return Err(Errno::EIO);
            }
            match &fetched {
                Ok(Some(_)) => {
                    if cache_generation == current_cache_generation && detached == detached_now {
                        if let Some(entry) = &mut prepared_range {
                            // Canonicalize even an equal version captured before
                            // a rebind, so publication can match current owners.
                            Arc::get_mut(entry).expect("private range").version = state
                                .files
                                .get(&handle.0)
                                .expect("validated handle")
                                .version
                                .clone();
                            state.insert_range(entry.clone(), &mut retired_ranges);
                        }
                    }
                }
                Ok(None) => {
                    let position = state
                        .cache
                        .iter()
                        .position(|entry| {
                            entry.version == version
                                && entry.offset == offset
                                && entry.bytes.len() == length as usize
                        });
                    if let Some(position) = position {
                        let entry = state.cache.remove(position).ok_or(Errno::EIO)?;
                        cached_range = Some(entry.clone());
                        state.cache.push_back(entry);
                    } else if staged {
                        // An identical detached head can outlive retirement of
                        // its live cache entry. Do not put that entry back.
                        cached_range = cached;
                    } else {
                        return Err(Errno::EIO);
                    }
                }
                Err(_) => {
                    state.invalidate_id(version.id(), &mut retired_ranges);
                    return Err(Errno::EIO);
                }
            };
            let file = state.files.get_mut(&handle.0).ok_or(Errno::EIO)?;
            let next = offset.checked_add(u64::from(length)).ok_or(Errno::EIO)?;
            let sequential = file.last_read.is_some_and(|(end, previous_length)| {
                end == offset
                    && previous_length >= READ_AHEAD_MIN_READ
                    && length >= READ_AHEAD_MIN_READ
            });
            file.last_read = Some((next, length));
            drop(state);
            drop(publication);
            let bytes = match fetched {
                Ok(Some(bytes)) => bytes,
                Ok(None) => cached_range.expect("validated cache hit").bytes.clone(),
                Err(error) => return Err(error),
            };
            if using_engine {
                self.composed_reads.fetch_add(1, Ordering::Relaxed);
            }
            if sequential {
                self.read_ahead(ino, &version, next);
            }
            Ok(Some(bytes))
        };
        let mut retry_lineage = None;
        for _ in 0..READ_VERSION_ATTEMPTS {
            match read_once(&mut retry_lineage) {
                Ok(Some(bytes)) => return reply.data(&bytes),
                Ok(None) => continue,
                Err(error) => return reply.error(error),
            }
        }
        reply.error(Errno::EIO);
    }

    fn release(
        &self,
        _: &Request,
        ino: INodeNo,
        handle: FileHandle,
        _: OpenFlags,
        _: Option<LockOwner>,
        _: bool,
        reply: ReplyEmpty,
    ) {
        let file = self.state.lock().map_err(|_| Errno::EIO).map(|mut state| {
            let file = state.files.remove(&handle.0);
            let id = u64::from(ino);
            let detached = if state.detached.contains_key(&id)
                && !state.files.values().any(|file| file.ino == id)
            {
                state.detached.remove(&id)
            } else {
                None
            };
            (file, detached)
        });
        match file {
            Ok(file) => {
                drop(file);
                reply.ok();
            }
            Err(error) => reply.error(error),
        }
    }
}

//! FUSE adapter for daemon-owned Space metadata and durable staged file writes.

mod recovery;

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cirrus_account::{
    AccountError, Accounts, DirectorySnapshot, DirtyMutation, FileVersion, MountBinding,
};
use cirrus_runtime::RuntimeDir;
use fuser::{
    BackgroundSession, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem,
    FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
    TimeOrNow, WriteFlags,
};
use rustix::{
    fs::{self, AtFlags, Dir, Mode, OFlags, ResolveFlags, StatxFlags},
    process,
};

const MAX_NODES: usize = 16_384;
const MAX_HANDLES: usize = 128;
const MAX_RANGE: u32 = 128 * 1024;
const READ_AHEAD_BYTES: u32 = 64 * 1024;
const READ_AHEAD_MIN_READ: u32 = 16 * 1024;
const CACHE_MAX_BYTES: usize = 4 * 1024 * 1024;
const CACHE_MAX_ENTRIES: usize = 64;
const MAX_WRITE_FILE: u64 = 1024 * 1024 * 1024 * 1024;
const DIRECTORY_CACHE_TTL: Duration = Duration::from_secs(2);
const DIRECTORY_CACHE_MAX: usize = 64;
const DIRECTORY_REFRESH_AGE: Duration = Duration::from_secs(30);

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

/// A mount owned by this process. Dropping it requests an unmount.
pub struct Mounted {
    path: PathBuf,
    instance: String,
    space_id: String,
    space_name: String,
    source: String,
    session: Option<BackgroundSession>,
    mount_id: u64,
    runtime: RuntimeDir,
    refresh: NamespaceRefresh,
}

/// A lifetime-fenced handle for scheduler-owned, cached-credentials-only refresh.
#[derive(Clone)]
pub struct NamespaceRefresh {
    drive: Drive,
    alive: Arc<AtomicBool>,
    notifier: fuser::Notifier,
}

impl NamespaceRefresh {
    /// Attempts one stale viewed directory. No crawl, token refresh or DAV retry.
    /// Open readdir handles keep their original immutable snapshots.
    ///
    /// # Errors
    /// Reports failed observations/publication; previous live state is preserved.
    pub fn refresh_one(&self) -> io::Result<()> {
        if !self.alive.load(Ordering::Acquire) || self.drive.accounts.background_yield_requested() {
            return Ok(());
        }
        let candidate = {
            let mut state = self
                .drive
                .state
                .lock()
                .map_err(|_| io::Error::other("mount state unavailable"))?;
            let candidate = state
                .directories
                .iter()
                .filter(|d| {
                    d.started.elapsed() >= DIRECTORY_REFRESH_AGE
                        && d.attempted.elapsed() >= DIRECTORY_REFRESH_AGE
                })
                .min_by_key(|d| d.attempted)
                .map(|d| (d.ino, d.children.clone()));
            if let Some((ino, _)) = &candidate
                && let Some(d) = state.directories.iter_mut().find(|d| d.ino == *ino)
            {
                d.attempted = Instant::now();
            }
            candidate
        };
        let Some((ino, before)) = candidate else {
            return Ok(());
        };
        let after = self
            .drive
            .listing_once_mode(INodeNo(ino), true, Some(&self.alive))
            .map_err(|e| {
                io::Error::other(format!("background directory observation failed: {e:?}"))
            })?;
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_NAMESPACE_POLL").is_some() {
            eprintln!("cirrus lab background directory published: ino={ino}");
        }
        if !self.alive.load(Ordering::Acquire) {
            return Ok(());
        }
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
                        self.notifier
                            .inval_entry(INodeNo(ino), OsStr::new(entry.name()))?;
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
    /// Mounts a previously selected Space at an existing empty private directory.
    ///
    /// # Errors
    /// Returns an error if the account, mountpoint or FUSE session cannot be validated.
    pub fn start(
        accounts: Arc<Accounts>,
        instance: String,
        path: &Path,
        runtime: RuntimeDir,
    ) -> io::Result<Self> {
        let space = accounts
            .check_mount_access(&instance)
            .map_err(io::Error::other)?;
        Self::start_bound(accounts, instance, space, path, runtime)
    }

    /// Mounts an explicitly verified Space without changing account selection.
    ///
    /// # Errors
    /// Returns an error if the Space, mountpoint or FUSE session cannot be validated.
    pub fn start_space(
        accounts: Arc<Accounts>,
        instance: String,
        id: &str,
        path: Option<&Path>,
        runtime: RuntimeDir,
    ) -> io::Result<Self> {
        let space = accounts
            .bind_space(&instance, id)
            .map_err(io::Error::other)?;
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
        Self::start_bound(accounts, instance, space, path, runtime).map_err(|error| {
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
    ) -> io::Result<Self> {
        let space = accounts
            .bind_offline_space(instance, id)
            .map_err(io::Error::other)?;
        Self::start_bound(accounts, space.instance().to_owned(), space, path, runtime)
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
    ) -> io::Result<Self> {
        let space = accounts
            .bind_writable_offline_space(instance, id)
            .map_err(io::Error::other)?;
        Self::start_bound(accounts, space.instance().to_owned(), space, path, runtime)
    }

    fn start_bound(
        accounts: Arc<Accounts>,
        instance: String,
        space: MountBinding,
        path: &Path,
        runtime: RuntimeDir,
    ) -> io::Result<Self> {
        recovery::ensure_available(&runtime, path)?;
        accounts
            .mount_directory(&instance, &space, &[], "")
            .map_err(io::Error::other)?;
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
        config.mount_options = vec![
            MountOption::NoDev,
            MountOption::NoSuid,
            MountOption::NoExec,
            MountOption::FSName(source.clone()),
            MountOption::Subtype("cirrus-drive".into()),
        ];
        config.n_threads = Some(4);
        if offline && !space.is_offline_writable() {
            config.mount_options.push(MountOption::RO);
        }
        let activation_accounts = Arc::clone(&accounts);
        let activation = space.clone();
        let filesystem = Drive::new(accounts, instance, space);
        let refresh_drive = filesystem.clone();
        let session = match fuser::spawn_mount(filesystem, path, &config) {
            Ok(session) => session,
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
        let mount_id = mount_id(path)?;
        let refresh = NamespaceRefresh {
            drive: refresh_drive,
            alive: Arc::new(AtomicBool::new(true)),
            notifier: session.notifier(),
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
        if let Err(error) = if offline {
            Ok(())
        } else {
            activation_accounts.activate_sync(&activation)
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
        if self.session.is_none() {
            return Ok(false);
        }
        let info = std::fs::read("/proc/self/mountinfo")?;
        let expected = self.mount_id.to_string();
        let path = escape_mount_path(&self.path);
        Ok(info.split(|byte| *byte == b'\n').any(|line| {
            let fields: Vec<_> = line.split(|byte| *byte == b' ').take(5).collect();
            fields.len() == 5 && fields[0] == expected.as_bytes() && fields[4] == path
        }))
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
        if self.session.is_none() {
            return recovery::remove_owned(&self.runtime, &self.path);
        }
        if mount_id(&self.path)? != self.mount_id {
            return Err(io::Error::other(
                "mountpoint identity changed; refusing to unmount",
            ));
        }
        let session = self
            .session
            .take()
            .ok_or_else(|| io::Error::other("mount session is unavailable"))?;
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
        session.umount_and_join()?;
        recovery::remove_owned(&self.runtime, &self.path)
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

/// Checks whether a prior mount owner record exists in the runtime directory.
///
/// # Errors
/// Returns an error if the owner record is unsafe or invalid.
pub fn recovery_pending(runtime: &RuntimeDir) -> io::Result<bool> {
    recovery::pending(runtime)
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
#[cfg_attr(feature = "fault-injection", derive(Hash))]
struct Node {
    path: Vec<String>,
    parent: u64,
    directory: bool,
    size: u64,
    modified: SystemTime,
    resource_id: String,
    etag: Option<String>,
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
struct State {
    next_node: u64,
    next_handle: u64,
    nodes: HashMap<u64, Node>,
    paths: HashMap<Vec<String>, u64>,
    handles: HashMap<u64, OpenDirectory>,
    files: HashMap<u64, OpenFile>,
    detached: HashSet<u64>,
    cache: VecDeque<CachedRange>,
    cache_bytes: usize,
    cache_generation: u64,
    directories: VecDeque<CachedDirectory>,
    next_scan: u64,
    scans: HashMap<u64, u64>,
    mutation_epoch: u64,
    observed: HashMap<Vec<String>, (String, String)>,
    observations_exhausted: bool,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct RangeKey {
    version: FileVersion,
    offset: u64,
    length: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RangePriority {
    Foreground,
    ReadAhead,
}

struct Flight {
    result: Mutex<Option<Result<Vec<u8>, ()>>>,
    ready: Condvar,
    priority: RangePriority,
}

#[derive(Clone)]
struct CachedRange {
    version: FileVersion,
    offset: u64,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct CachedDirectory {
    ino: u64,
    started: Instant,
    attempted: Instant,
    mutation_epoch: u64,
    metadata_generation: u64,
    children: DirectoryView,
}

#[derive(Clone)]
struct DirectoryView(DirectorySnapshot);

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

    fn valid(&self, state: &State, ino: u64) -> bool {
        let mut after = 0;
        loop {
            let Ok(page) = self.page(after) else {
                return false;
            };
            if page.is_empty() {
                return true;
            }
            for (cookie, id, _, name) in page {
                if !state.nodes.get(&id).is_some_and(|node| {
                    node.parent == ino
                        && node.path.last() == Some(&name)
                        && state.paths.get(&node.path) == Some(&id)
                }) {
                    return false;
                }
                after = cookie;
            }
        }
    }
}

#[derive(Clone)]
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

impl State {
    #[cfg(feature = "fault-injection")]
    fn publication_witness(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        let mut nodes: Vec<_> = self.nodes.iter().collect();
        nodes.sort_unstable_by_key(|(id, _)| **id);
        nodes.hash(&mut hash);
        let mut paths: Vec<_> = self.paths.iter().collect();
        paths.sort_unstable_by_key(|(path, _)| *path);
        paths.hash(&mut hash);
        let mut files: Vec<_> = self.files.iter().collect();
        files.sort_unstable_by_key(|(id, _)| **id);
        files.hash(&mut hash);
        self.next_node.hash(&mut hash);
        self.mutation_epoch.hash(&mut hash);
        hash.finish()
    }

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

    fn refresh_cache_generation(&mut self, generation: u64) {
        if self.cache_generation != generation {
            self.cache.clear();
            self.cache_bytes = 0;
            self.cache_generation = generation;
        }
    }

    fn invalidate_id(&mut self, id: &str) {
        self.cache.retain(|entry| entry.version.id() != id);
        self.cache_bytes = self.cache.iter().map(|entry| entry.bytes.len()).sum();
        for file in self.files.values_mut() {
            if file.version.id() == id {
                file.failed = true;
            }
        }
    }

    fn observe_version(&mut self, version: &FileVersion) {
        let changed = self
            .cache
            .iter()
            .any(|entry| entry.version.same_resource(version) && entry.version != *version)
            || self.files.values().any(|file| {
                file.version.same_resource(version) && file.version != *version && !file.failed
            });
        if changed {
            self.invalidate_id(version.id());
        }
    }

    fn insert_range(&mut self, version: FileVersion, offset: u64, bytes: Vec<u8>) {
        while self.cache.len() >= CACHE_MAX_ENTRIES
            || self.cache_bytes + bytes.len() > CACHE_MAX_BYTES
        {
            if let Some(oldest) = self.cache.pop_front() {
                self.cache_bytes -= oldest.bytes.len();
            } else {
                return;
            }
        }
        self.cache_bytes += bytes.len();
        self.cache.push_back(CachedRange {
            version,
            offset,
            bytes,
        });
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "fault-injection", derive(Hash))]
struct OpenFile {
    ino: u64,
    version: FileVersion,
    failed: bool,
    writable: bool,
    append: bool,
    last_read: Option<(u64, u32)>,
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
    state: Arc<Mutex<State>>,
    flights: Arc<Mutex<HashMap<RangeKey, Arc<Flight>>>>,
    mutation: Arc<Mutex<()>>,
}

impl Drive {
    fn new(accounts: Arc<Accounts>, instance: String, space: MountBinding) -> Self {
        let cache_generation = accounts.clean_cache_generation();
        let root = Node {
            path: Vec::new(),
            parent: 1,
            directory: true,
            size: 0,
            modified: UNIX_EPOCH,
            resource_id: String::new(),
            etag: None,
            checksums: Vec::new(),
            revision: 0,
        };
        Self {
            accounts,
            instance,
            space,
            state: Arc::new(Mutex::new(State {
                next_node: 2,
                next_handle: 1,
                nodes: HashMap::from([(1, root)]),
                paths: HashMap::from([(Vec::new(), 1)]),
                handles: HashMap::new(),
                files: HashMap::new(),
                detached: HashSet::new(),
                cache: VecDeque::new(),
                cache_bytes: 0,
                cache_generation,
                directories: VecDeque::new(),
                next_scan: 1,
                scans: HashMap::new(),
                mutation_epoch: 0,
                observed: HashMap::new(),
                observations_exhausted: false,
            })),
            flights: Arc::new(Mutex::new(HashMap::new())),
            mutation: Arc::new(Mutex::new(())),
        }
    }

    fn node(&self, ino: INodeNo) -> Result<Node, Errno> {
        let state = self.state.lock().map_err(|_| Errno::EIO)?;
        let id = u64::from(ino);
        let node = state.nodes.get(&id).ok_or(Errno::ENOENT)?;
        if state.paths.get(&node.path) != Some(&id) {
            return Err(Errno::ENOENT);
        }
        Ok(node.clone())
    }

    fn listing_for_read(&self, ino: INodeNo, refresh: bool) -> Result<DirectoryView, Errno> {
        self.listing_inner(ino, refresh)
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
            let siblings = self.listing_for_read(parent, false)?;
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
            let source = self.listing_for_read(parent, false)?;
            let destination = if parent == newparent {
                source.clone()
            } else {
                self.listing_for_read(newparent, false)?
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
                        Some((
                            *id,
                            node.clone(),
                            self.listing_for_read(INodeNo(*id), false)?,
                        ))
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
                            self.listing_for_read(INodeNo(*id), false)?,
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

    fn listing_inner(&self, ino: INodeNo, refresh: bool) -> Result<DirectoryView, Errno> {
        for _ in 0..8 {
            match self.listing_once(ino, refresh) {
                Err(Errno::EAGAIN) => continue,
                result => return result,
            }
        }
        Err(Errno::EIO)
    }

    fn listing_once(&self, ino: INodeNo, refresh: bool) -> Result<DirectoryView, Errno> {
        self.listing_once_mode(ino, refresh, None)
    }

    fn listing_once_mode(
        &self,
        ino: INodeNo,
        refresh: bool,
        background: Option<&AtomicBool>,
    ) -> Result<DirectoryView, Errno> {
        let parent = self.node(ino)?;
        if !parent.directory {
            return Err(Errno::ENOTDIR);
        }
        let generation = self.accounts.metadata_generation();
        let started = Instant::now();
        let (ticket, epoch, staged_versions, staged_directories) = {
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            if !refresh
                && let Some(cached) = state.directories.iter().find(|cached| {
                    cached.ino == ino.0
                        && cached.started.elapsed() < DIRECTORY_CACHE_TTL
                        && cached.mutation_epoch == state.mutation_epoch
                        && cached.metadata_generation == generation
                        && cached.children.valid(&state, ino.0)
                })
            {
                return Ok(cached.children.clone());
            }
            let ticket = state.next_scan;
            state.next_scan = ticket.checked_add(1).ok_or(Errno::EIO)?;
            let staged_versions: Vec<_> = state
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
                .map(|file| file.version.clone())
                .collect();
            let staged_directories: Vec<_> = state
                .nodes
                .iter()
                .filter(|(id, node)| {
                    node.directory
                        && node.parent == ino.0
                        && node.resource_id.starts_with("cirrus-dir:")
                        && state.paths.get(&node.path) == Some(*id)
                })
                .map(|(_, node)| (node.path.clone(), node.resource_id.clone()))
                .collect();
            (
                ticket,
                state.mutation_epoch,
                staged_versions,
                staged_directories,
            )
        };
        let (mut entries, confirmed, confirmed_directories) = if let Some(alive) = background {
            let refreshed = self
                .accounts
                .refresh_mount_directory(
                    &self.space,
                    &parent.path,
                    &parent.resource_id,
                    alive,
                    (&staged_versions, &staged_directories),
                )
                .map_err(|_| Errno::EIO)?
                .ok_or(Errno::EAGAIN)?;
            (refreshed.entries, refreshed.files, refreshed.directories)
        } else {
            let entries = self
                .accounts
                .mount_directory(
                    &self.instance,
                    &self.space,
                    &parent.path,
                    &parent.resource_id,
                )
                .map_err(|error| {
                    eprintln!("directory listing failed: {error}");
                    if error.is_staging_full() {
                        Errno::ENOSPC
                    } else {
                        Errno::EIO
                    }
                })?;
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
        let mut live = self.state.lock().map_err(|_| Errno::EIO)?;
        if live.mutation_epoch != epoch
            || self.accounts.metadata_generation() != generation
            || live.paths.get(&parent.path) != Some(&u64::from(ino))
            || live
                .scans
                .get(&u64::from(ino))
                .is_some_and(|previous| *previous > ticket)
        {
            return Err(Errno::EAGAIN);
        }
        // Prepare against an isolated copy of the capped live mount state, not
        // a complete decoded listing. Snapshot owners remain shared/immutable;
        // the bounded range cache is copied too. No handles, inode mappings or
        // confirmation transitions become live until the final infallible swap.
        #[cfg(feature = "fault-injection")]
        let original_namespace = std::env::var_os("CIRRUS_TEST_PUBLICATION_READ_FAULT")
            .map(|_| live.publication_witness());
        let mut state = live.clone();
        for (path, resource, remote) in confirmed_directories {
            let Some(id) = state.paths.get(&path).copied() else {
                continue;
            };
            let Some(node) = state.nodes.get_mut(&id) else {
                continue;
            };
            if node.parent != ino.0 || !node.directory || node.resource_id != resource {
                continue;
            }
            node.resource_id = remote.id().to_owned();
            node.etag = remote.etag().map(str::to_owned);
            node.modified = remote.modified();
            node.revision = node.revision.wrapping_add(1);
            state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
        }
        for (staged, remote) in confirmed {
            let ids: HashSet<_> = state
                .files
                .values()
                .filter(|file| !file.failed && file.version == staged)
                .map(|file| file.ino)
                .collect();
            for id in ids {
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
                node.resource_id = remote.id().to_owned();
                node.etag = Some(remote.etag().to_owned());
                node.checksums = remote.checksums().to_vec();
                node.revision = node.revision.wrapping_add(1);
                for file in state
                    .files
                    .values_mut()
                    .filter(|file| file.ino == id && file.version == staged && !file.failed)
                {
                    file.version = remote.clone();
                    file.last_read = None;
                }
                state.cache.retain(|entry| entry.version != staged);
                state.cache_bytes = state.cache.iter().map(|entry| entry.bytes.len()).sum();
                state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
            }
        }
        let epoch = state.mutation_epoch;
        state.scans.insert(u64::from(ino), ticket);
        let mut replaced = std::collections::HashSet::new();
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
                    invalidated.push(node.resource_id.clone());
                }
            }
        }
        // Reserve inode identities and finish all scratch writes before removing
        // any old paths. Capacity/write failures must not publish half a scan.
        let retained: HashSet<u64> = state
            .paths
            .iter()
            .filter(|(path, _)| {
                path.len() <= parent.path.len()
                    || !path.starts_with(&parent.path)
                    || !replaced.contains(&path[parent.path.len()])
            })
            .map(|(_, id)| *id)
            .chain(state.detached.iter().copied())
            .collect();
        let mut next_node = state.next_node;
        let mut new_nodes = 0;
        let mut after = 0;
        loop {
            let page = entries.page(after).map_err(|_| Errno::EIO)?;
            if page.is_empty() {
                break;
            }
            for (cookie, entry) in page {
                after = cookie;
                if !entry.is_directory() && entry.size().is_none() {
                    return Err(Errno::EIO);
                }
                let mut path = parent.path.clone();
                path.push(entry.name().to_owned());
                let existing = state.paths.get(&path).copied().filter(|id| {
                    retained.contains(id)
                        && state.nodes.get(id).is_some_and(|node| {
                            node.directory == entry.is_directory() && node.resource_id == entry.id()
                        })
                });
                let id = if let Some(id) = existing {
                    id
                } else {
                    new_nodes += 1;
                    if retained.len() + new_nodes > MAX_NODES {
                        return Err(Errno::ENOSPC);
                    }
                    let id = next_node;
                    next_node = next_node.checked_add(1).ok_or(Errno::ENOSPC)?;
                    id
                };
                entries
                    .bind_inode(entry.name(), id)
                    .map_err(|_| Errno::EIO)?;
            }
        }
        state.next_node = next_node;
        for id in invalidated {
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_STAGE_WINDOW").is_some()
                && id.starts_with("cirrus-staged:")
            {
                eprintln!("injected race: scan invalidated a staged inode");
            }
            state.invalidate_id(&id);
        }
        state.paths.retain(|path, _| {
            path.len() <= parent.path.len()
                || !path.starts_with(&parent.path)
                || !replaced.contains(&path[parent.path.len()])
        });
        // Removed or replaced paths already fail node() validation. Reclaim their
        // inode records without reusing inode numbers, including descendants.
        let live_nodes: HashSet<u64> = state
            .paths
            .values()
            .copied()
            .chain(state.detached.iter().copied())
            .collect();
        state.nodes.retain(|id, _| live_nodes.contains(id));
        state.scans.retain(|id, _| live_nodes.contains(id));
        state
            .directories
            .retain(|entry| live_nodes.contains(&entry.ino));
        #[cfg(feature = "fault-injection")]
        entries
            .inject_publication_read_fault()
            .map_err(|_| Errno::EIO)?;
        let mut after = 0;
        loop {
            let page = entries.page(after).map_err(|_| {
                #[cfg(feature = "fault-injection")]
                if let Some(original) = original_namespace {
                    eprintln!(
                        "cirrus lab publication failure live namespace unchanged={}",
                        original == live.publication_witness()
                    );
                }
                Errno::EIO
            })?;
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
                    // A replacement directory must not inherit the old directory's children.
                    state.paths.retain(|candidate, _| {
                        candidate.len() <= path.len() || !candidate.starts_with(&path)
                    });
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
                    resource_id: entry.id().to_owned(),
                    etag: entry.etag().map(str::to_owned),
                    checksums: entry.checksums().to_vec(),
                    revision,
                };
                state.nodes.insert(id, node);
            }
        }
        let children = DirectoryView(entries);
        state.directories.retain(|entry| entry.ino != ino.0);
        while state.directories.len() >= DIRECTORY_CACHE_MAX {
            state.directories.pop_front();
        }
        state.directories.push_back(CachedDirectory {
            ino: ino.0,
            started,
            attempted: started,
            mutation_epoch: epoch,
            metadata_generation: generation,
            children: children.clone(),
        });
        *live = state;
        Ok(children)
    }

    fn fetch_range(
        &self,
        version: &FileVersion,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, Errno> {
        Self::fetch_range_with(
            &self.accounts,
            &self.space,
            &self.flights,
            version,
            offset,
            length,
            RangePriority::Foreground,
        )
    }

    fn fetch_range_with(
        accounts: &Accounts,
        binding: &MountBinding,
        flights: &Mutex<HashMap<RangeKey, Arc<Flight>>>,
        version: &FileVersion,
        offset: u64,
        length: u32,
        priority: RangePriority,
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
        priority: RangePriority,
    ) -> Result<(u64, u64, Vec<u8>, bool), Errno> {
        let (offset, end) = range;
        let length = u32::try_from(end - offset).map_err(|_| Errno::EIO)?;
        if !join {
            let bytes = accounts
                .read_range(binding, version, offset, length)
                .map_err(|_| Errno::EIO)?;
            return Ok((offset, end, bytes, false));
        }
        let key = RangeKey {
            version: version.clone(),
            offset,
            length,
        };
        let (flight, leader, flight_offset, flight_end) = {
            let mut flights = flights.lock().map_err(|_| Errno::EIO)?;
            if let Some((existing, flight)) = flights.iter().find(|(existing, _)| {
                existing.version == *version
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
                    priority,
                });
                flights.insert(key.clone(), Arc::clone(&flight));
                (flight, true, offset, end)
            }
        };
        if leader {
            let result = accounts
                .read_range(binding, version, offset, length)
                .map_err(|_| ());
            let mut shared = flight.result.lock().map_err(|_| Errno::EIO)?;
            *shared = Some(result);
            flight.ready.notify_all();
            drop(shared);
            flights.lock().map_err(|_| Errno::EIO)?.remove(&key);
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
            _ if !leader
                && priority == RangePriority::Foreground
                && flight.priority == RangePriority::ReadAhead =>
            {
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

    fn read_ahead(&self, version: &FileVersion, offset: u64) {
        if version.id().starts_with("cirrus-staged:")
            || offset >= version.size()
            || !self.accounts.reserve_read_ahead()
        {
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
                    RangePriority::ReadAhead,
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
        let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
        if state.paths.get(&old.path) != Some(&ino.0) {
            return Err(Errno::EIO);
        }
        state.cache.retain(|entry| {
            entry.version.id() != old.resource_id && entry.version.id() != version.id()
        });
        state.cache_bytes = state.cache.iter().map(|entry| entry.bytes.len()).sum();
        let node = state.nodes.get_mut(&ino.0).ok_or(Errno::EIO)?;
        node.resource_id = version.id().to_owned();
        node.etag = Some(version.etag().to_owned());
        node.size = version.size();
        node.checksums.clear();
        node.revision = node.revision.wrapping_add(1);
        for file in state
            .files
            .values_mut()
            .filter(|file| file.ino == ino.0 && !file.failed)
        {
            file.version = version.clone();
            file.last_read = None;
        }
        state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
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
        let parents = self
            .state
            .lock()
            .map_err(|_| Errno::EIO)?
            .parent_identities(&node.path)?;
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
        let parents = self
            .state
            .lock()
            .map_err(|_| Errno::EIO)?
            .parent_identities(&node.path)?;
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
        let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
        if !state.detached.contains(&ino.0) {
            return Err(Errno::EIO);
        }
        state
            .cache
            .retain(|entry| entry.version.id() != version.id());
        state.cache_bytes = state.cache.iter().map(|entry| entry.bytes.len()).sum();
        let node = state.nodes.get_mut(&ino.0).ok_or(Errno::EIO)?;
        node.size = version.size();
        node.etag = Some(version.etag().to_owned());
        node.revision = node.revision.wrapping_add(1);
        let node = node.clone();
        for file in state
            .files
            .values_mut()
            .filter(|file| file.ino == ino.0 && !file.failed)
        {
            file.version = version.clone();
            file.last_read = None;
        }
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
            if !state.detached.contains(&ino.0) {
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
        let state = self.state.lock().map_err(|_| Errno::EIO)?;
        Ok(Some(state.nodes.get(&ino.0).cloned().ok_or(Errno::EIO)?))
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
        let siblings = self.listing_for_read(parent, false)?;
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
            let children = self.listing_for_read(INodeNo(id), false)?;
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
        if self.space.is_offline() && directory {
            let parents = self
                .state
                .lock()
                .map_err(|_| Errno::EIO)?
                .parent_identities(&node.path)?;
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
            let parents = self
                .state
                .lock()
                .map_err(|_| Errno::EIO)?
                .parent_identities(&node.path)?;
            self.accounts
                .remove_offline_file(&self.space, &version, open_files, &parents)
                .map_err(|error| stage_error(&error))?;
        } else if node.resource_id.starts_with("cirrus-staged:")
            || node.resource_id.starts_with("cirrus-dir:")
        {
            let parents = self
                .state
                .lock()
                .map_err(|_| Errno::EIO)?
                .parent_identities(&node.path)?;
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
            let parents = self
                .state
                .lock()
                .map_err(|_| Errno::EIO)?
                .parent_identities(&node.path)?;
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
        state.paths.remove(&node.path);
        state.observed.remove(&node.path);
        if open_files && state.files.values().any(|file| file.ino == id) {
            state.detached.insert(id);
        } else {
            state.nodes.remove(&id);
        }
        state
            .cache
            .retain(|entry| entry.version.id() != node.resource_id);
        state.cache_bytes = state.cache.iter().map(|entry| entry.bytes.len()).sum();
        state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
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
        let refresh = {
            let Ok(state) = self.state.lock() else {
                reply.error(Errno::EIO);
                return;
            };
            state.nodes.get(&parent.0).is_some_and(|node| {
                let mut path = node.path.clone();
                path.push(name.to_owned());
                state
                    .paths
                    .get(&path)
                    .and_then(|id| state.nodes.get(id))
                    .is_some_and(|child| child.directory)
            })
        };
        match self
            .listing_inner(parent, refresh)
            .and_then(|entries| entries.find(name)?.ok_or(Errno::ENOENT))
            .and_then(|(id, _, _)| self.node(INodeNo(id)).map(|node| (id, node)))
        {
            Ok((id, node)) => reply.entry(&Duration::ZERO, &attr(id, &node), Generation(0)),
            Err(error) => reply.error(error),
        }
    }

    fn getattr(&self, _: &Request, ino: INodeNo, handle: Option<FileHandle>, reply: ReplyAttr) {
        {
            let result = self.state.lock().map_err(|_| Errno::EIO).and_then(|state| {
                if !state.detached.contains(&ino.0) {
                    return Ok(None);
                }
                if let Some(handle) = handle {
                    if state.nodes.get(&ino.0).is_some_and(|node| node.directory) {
                        if !state
                            .handles
                            .get(&handle.0)
                            .is_some_and(|directory| directory.ino == ino.0)
                        {
                            return Err(Errno::EBADF);
                        }
                        return Ok(Some(state.nodes.get(&ino.0).cloned().ok_or(Errno::EIO)?));
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
                Ok(Some(state.nodes.get(&ino.0).cloned().ok_or(Errno::EIO)?))
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
            let id = u64::from(ino);
            if !self
                .listing_inner(INodeNo(node.parent), node.directory)?
                .find(node.path.last().ok_or(Errno::EIO)?)?
                .is_some_and(|entry| entry.0 == id)
            {
                return Err(Errno::ENOENT);
            }
            self.node(ino)
        });
        match result {
            Ok(node) => reply.attr(&Duration::ZERO, &attr(u64::from(ino), &node)),
            Err(error) => reply.error(error),
        }
    }

    fn opendir(&self, _: &Request, ino: INodeNo, _: OpenFlags, reply: ReplyOpen) {
        let result = (|| {
            let children = self.listing_inner(ino, true)?;
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
        let Ok(state) = self.state.lock() else {
            reply.error(Errno::EIO);
            return;
        };
        let Some(directory) = state.handles.get(&handle.0) else {
            reply.error(Errno::EBADF);
            return;
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
        match self.state.lock() {
            Ok(mut state) => {
                state.handles.remove(&handle.0);
                if state.detached.contains(&ino.0)
                    && !state
                        .handles
                        .values()
                        .any(|directory| directory.ino == ino.0)
                {
                    state.detached.remove(&ino.0);
                    state.nodes.remove(&ino.0);
                }
                reply.ok();
            }
            Err(_) => reply.error(Errno::EIO),
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
            let version = match version {
                Ok(version) => version,
                Err(_) => {
                    state.invalidate_id(&node.resource_id);
                    return Err(Errno::EIO);
                }
            };
            if state.files.len() >= MAX_HANDLES {
                return Err(Errno::EMFILE);
            }
            if state.paths.get(&node.path) != Some(&u64::from(ino)) {
                return Err(Errno::EIO);
            }
            state.observe_version(&version);
            let current = state
                .nodes
                .get_mut(&u64::from(ino))
                .filter(|current| {
                    current.path == node.path && current.resource_id == node.resource_id
                })
                .ok_or(Errno::EIO)?;
            let changed = current.size != version.size()
                || current.etag.as_deref() != Some(version.etag())
                || current.checksums != version.checksums();
            current.size = version.size();
            current.etag = Some(version.etag().to_owned());
            current.checksums = version.checksums().to_vec();
            current.revision = current.revision.wrapping_add(u64::from(changed));
            if !version.id().starts_with("cirrus-staged:")
                && !state.observed.contains_key(&node.path)
            {
                if state.observed.len() >= MAX_NODES {
                    state.observations_exhausted = true;
                } else {
                    state.observed.insert(
                        node.path.clone(),
                        (version.id().to_owned(), version.etag().to_owned()),
                    );
                }
            }
            let handle = state.next_handle;
            state.next_handle = handle.checked_add(1).ok_or(Errno::EMFILE)?;
            state.files.insert(
                handle,
                OpenFile {
                    ino: u64::from(ino),
                    version,
                    failed: false,
                    writable,
                    append: flags.0 & OFlags::APPEND.bits() as i32 != 0,
                    last_read: None,
                },
            );
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
            {
                let state = self.state.lock().map_err(|_| Errno::EIO)?;
                if state.files.len() >= MAX_HANDLES {
                    return Err(Errno::EMFILE);
                }
                if state.nodes.len() >= MAX_NODES {
                    return Err(Errno::ENOSPC);
                }
            }
            let mut path = parent_node.path.clone();
            path.push(name.to_owned());
            let parents = self
                .state
                .lock()
                .map_err(|_| Errno::EIO)?
                .parent_identities(&path)?;
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
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            let id = state.next_node;
            state.next_node = id.checked_add(1).ok_or(Errno::ENOSPC)?;
            let handle = state.next_handle;
            state.next_handle = handle.checked_add(1).ok_or(Errno::EMFILE)?;
            let node = Node {
                path: path.clone(),
                parent: parent.0,
                directory: false,
                size: 0,
                modified: SystemTime::now(),
                resource_id: version.id().to_owned(),
                etag: Some(version.etag().to_owned()),
                checksums: Vec::new(),
                revision: 0,
            };
            state.paths.insert(path, id);
            state.nodes.insert(id, node.clone());
            state.files.insert(
                handle,
                OpenFile {
                    ino: id,
                    version,
                    failed: false,
                    writable: true,
                    append: flags & OFlags::APPEND.bits() as i32 != 0,
                    last_read: None,
                },
            );
            state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
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
                    state.detached.contains(&ino.0),
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
                let parents = self
                    .state
                    .lock()
                    .map_err(|_| Errno::EIO)?
                    .parent_identities(&node.path)?;
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
                if state.nodes.len() >= MAX_NODES || state.next_node.checked_add(1).is_none() {
                    return Err(Errno::ENOSPC);
                }
                state.next_node
            };
            let mut path = parent_node.path;
            path.push(name.to_owned());
            let parents = self
                .state
                .lock()
                .map_err(|_| Errno::EIO)?
                .parent_identities(&path)?;
            let operation = self
                .accounts
                .stage_namespace(&self.instance, &self.space, &path, "mkdir", None, &parents)
                .map_err(|error| stage_error(&error))?;
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            state.next_node = id + 1;
            let node = Node {
                path: path.clone(),
                parent: parent.0,
                directory: true,
                size: 0,
                modified: UNIX_EPOCH,
                resource_id: format!("cirrus-dir:{operation}"),
                etag: None,
                checksums: Vec::new(),
                revision: 0,
            };
            state.paths.insert(path, id);
            state.nodes.insert(id, node.clone());
            state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
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
                        let state = self.state.lock().map_err(|_| Errno::EIO)?;
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
                        let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
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
                            state = self.state.lock().map_err(|_| Errno::EIO)?;
                            if state.mutation_epoch != epoch
                                || self.accounts.metadata_generation() != generation
                                || state.paths.get(&source.path) != Some(&source_id)
                                || state.paths.contains_key(&destination)
                                || state.nodes.get(&source_id).is_none_or(|current| {
                                    current.revision != source.revision
                                        || current.resource_id != source.resource_id
                                        || current.etag != source.etag
                                })
                                || state.parent_identities(&source.path)? != source_parents
                                || state.parent_identities(&destination)? != destination_parents
                            {
                                drop(state);
                                drop(prepared);
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
                            let id = prepared.commit().map_err(|error| stage_error(&error))?;
                            state.paths.remove(&source.path);
                            state.paths.insert(destination.clone(), source_id);
                            state.observed.retain(|path, _| {
                                !path.starts_with(&source.path) && !path.starts_with(&destination)
                            });
                            let node = state.nodes.get_mut(&source_id).ok_or(Errno::EIO)?;
                            node.path = destination;
                            node.parent = newparent.0;
                            node.resource_id = format!("cirrus-dir:{id}");
                            node.etag = None;
                            node.revision = node.revision.wrapping_add(1);
                            state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
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
                    // Keep readers from observing journal paths between the transaction
                    // and the corresponding inode/handle updates.
                    let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
                    if !detach_target
                        && target.is_some_and(|id| {
                            state.handles.values().any(|directory| directory.ino == id)
                        })
                    {
                        return Err(Errno::EBUSY);
                    }
                    let open: Vec<_> = state
                        .files
                        .iter()
                        .filter(|(_, file)| {
                            !file.failed
                                && !state.detached.contains(&file.ino)
                                && state
                                    .nodes
                                    .get(&file.ino)
                                    .is_some_and(|node| node.path.starts_with(&source.path))
                        })
                        .map(|(handle, file)| (*handle, file.version.clone()))
                        .collect();
                    let versions = open
                        .iter()
                        .map(|(_, version)| version.clone())
                        .collect::<Vec<_>>();
                    let open_directories: Vec<_> = state
                        .nodes
                        .iter()
                        .filter(|(id, node)| {
                            node.directory
                                && node.path.starts_with(&source.path)
                                && node.resource_id.starts_with("cirrus-dir:")
                                && state.paths.get(&node.path) == Some(*id)
                        })
                        .map(|(_, node)| (node.path.clone(), node.resource_id.clone()))
                        .collect();
                    let local_target = target_node
                        .as_ref()
                        .filter(|node| node.resource_id.starts_with("cirrus-dir:"))
                        .map(|node| node.resource_id.as_str());
                    let relocated = if source.resource_id.starts_with("cirrus-dir:") {
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
                        let epoch = state.mutation_epoch;
                        let generation = self.accounts.metadata_generation();
                        drop(state);
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
                        state = self.state.lock().map_err(|_| Errno::EIO)?;
                        let same_node = |id: u64, node: &Node| {
                            state.paths.get(&node.path) == Some(&id)
                                && state.nodes.get(&id).is_some_and(|current| {
                                    current.revision == node.revision
                                        && current.resource_id == node.resource_id
                                        && current.etag == node.etag
                                })
                        };
                        let same_listing = |id: u64, view: &DirectoryView| {
                            state
                                .directories
                                .iter()
                                .any(|cached| cached.ino == id && cached.children.matches(view))
                        };
                        if state.mutation_epoch != epoch
                            || self.accounts.metadata_generation() != generation
                            || !same_node(source_id, &source)
                            || state.paths.get(&destination).copied() != target
                            || target
                                .zip(target_node.as_ref())
                                .is_some_and(|(id, node)| !same_node(id, node))
                            || !same_listing(parent.0, &source_listing)
                            || !same_listing(newparent.0, &destination_listing)
                            || source_children
                                .as_ref()
                                .is_some_and(|view| !same_listing(source_id, view))
                            || target
                                .zip(destination_children.as_ref())
                                .is_some_and(|(id, view)| !same_listing(id, view))
                            || state.parent_identities(&source.path)? != source_parents
                            || state.parent_identities(&destination)? != destination_parents
                        {
                            drop(state);
                            drop(prepared);
                            continue 'retry;
                        }
                        if !detach_target
                            && target.is_some_and(|id| {
                                state.handles.values().any(|directory| directory.ino == id)
                            })
                        {
                            return Err(Errno::EBUSY);
                        }
                        if open.iter().any(|(handle, version)| {
                            state.files.get(handle).is_some_and(|file| {
                                file.failed
                                    || file.version != *version
                                    || state.detached.contains(&file.ino)
                            })
                        }) {
                            return Err(Errno::EIO);
                        }
                        // Opens need not advance the namespace epoch. Include
                        // every new live source handle in the next preparation;
                        // never leave it at the old path after tree publication.
                        if state.files.iter().any(|(handle, file)| {
                            !file.failed
                                && !state.detached.contains(&file.ino)
                                && state
                                    .nodes
                                    .get(&file.ino)
                                    .is_some_and(|node| node.path.starts_with(&source.path))
                                && !open.iter().any(|(known, version)| {
                                    known == handle && *version == file.version
                                })
                        }) {
                            drop(state);
                            drop(prepared);
                            continue 'retry;
                        }
                        prepared.commit()
                    }
                    .map_err(|error| stage_error(&error))?;
                    let ids: HashSet<_> = relocated
                        .iter()
                        .map(|version| version.id().to_owned())
                        .collect();
                    state
                        .cache
                        .retain(|entry| !ids.contains(entry.version.id()));
                    state.cache_bytes = state.cache.iter().map(|entry| entry.bytes.len()).sum();
                    for ((handle, _), version) in open.into_iter().zip(relocated) {
                        if let Some(file) = state.files.get_mut(&handle) {
                            file.version = version;
                            file.last_read = None;
                        }
                    }
                    for directory in state.handles.values_mut() {
                        if directory.ino == source_id {
                            directory.parent = newparent.0;
                        }
                    }
                    if let Some(id) = target {
                        state.paths.remove(&destination);
                        if detach_target
                            && state.handles.values().any(|directory| directory.ino == id)
                        {
                            state.detached.insert(id);
                        } else {
                            state.nodes.remove(&id);
                        }
                        state.scans.remove(&id);
                    }
                    let paths: Vec<_> = state
                        .paths
                        .iter()
                        .filter(|(path, _)| path.starts_with(&source.path))
                        .map(|(path, id)| (path.clone(), *id))
                        .collect();
                    for (path, id) in paths {
                        state.paths.remove(&path);
                        let mut next = destination.clone();
                        next.extend_from_slice(&path[source.path.len()..]);
                        state.paths.insert(next.clone(), id);
                        if let Some(node) = state.nodes.get_mut(&id) {
                            node.path = next;
                            if id == source_id {
                                node.parent = newparent.0;
                            }
                            node.revision = node.revision.wrapping_add(1);
                        }
                    }
                    state.observed.retain(|path, _| {
                        !path.starts_with(&source.path) && !path.starts_with(&destination)
                    });
                    state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
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
                    let state = self.state.lock().map_err(|_| Errno::EIO)?;
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
                    let state = self.state.lock().map_err(|_| Errno::EIO)?;
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
                let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
                let source_stable = state.paths.get(&source.path) == Some(&source_id)
                    && state.nodes.get(&source_id).is_some_and(|node| {
                        node.resource_id == source.resource_id && node.revision == source.revision
                    })
                    && !state.detached.contains(&source_id)
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
                    || self.accounts.metadata_generation() != generation
                    || state.observed.get(&destination).cloned() != observed
                    || (state.observations_exhausted
                        && observed.is_none()
                        && pending_target.is_none())
                    || !state
                        .parent_identities(&source.path)
                        .is_ok_and(|parents| parents == source_parents)
                    || !state
                        .parent_identities(&destination)
                        .is_ok_and(|parents| parents == destination_parents)
                {
                    continue 'retry;
                }
                let (renamed, detached_target) = prepared.commit().map_err(|error| {
                    eprintln!("staged rename failed: {error}");
                    stage_error(&error)
                })?;
                state.paths.remove(&source.path);
                state.observed.remove(&source.path);
                state.observed.remove(&destination);
                if let Some(id) = target {
                    if let Some(version) = detached_target {
                        if state.files.values().any(|file| file.ino == id) {
                            state.detached.insert(id);
                            let node = state.nodes.get_mut(&id).ok_or(Errno::EIO)?;
                            node.resource_id = version.id().to_owned();
                            node.etag = Some(version.etag().to_owned());
                            for file in state
                                .files
                                .values_mut()
                                .filter(|file| file.ino == id && !file.failed)
                            {
                                file.version = version.clone();
                                file.last_read = None;
                            }
                        } else {
                            state.nodes.remove(&id);
                        }
                    } else {
                        state.nodes.remove(&id);
                    }
                }
                state.paths.insert(destination.clone(), source_id);
                state.cache.retain(|entry| {
                    entry.version.id() != source.resource_id
                        && !target_node
                            .as_ref()
                            .is_some_and(|node| node.resource_id == entry.version.id())
                });
                state.cache_bytes = state.cache.iter().map(|entry| entry.bytes.len()).sum();
                let mut node = source;
                node.path = destination;
                node.parent = newparent.0;
                node.resource_id = renamed.id().to_owned();
                node.etag = Some(renamed.etag().to_owned());
                node.size = renamed.size();
                node.revision = node.revision.wrapping_add(1);
                state.nodes.insert(source_id, node);
                for file in state
                    .files
                    .values_mut()
                    .filter(|file| file.ino == source_id && !file.failed)
                {
                    file.version = renamed.clone();
                    file.last_read = None;
                }
                state.mutation_epoch = state.mutation_epoch.wrapping_add(1);
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
        let result = (|| {
            let staged = {
                let state = self.state.lock().map_err(|_| Errno::EIO)?;
                state
                    .files
                    .get(&handle.0)
                    .is_some_and(|file| file.version.id().starts_with("cirrus-staged:"))
            };
            // A staged write updates its journal before publishing the new handle version.
            let _mutation = if staged {
                Some(self.mutation.lock().map_err(|_| Errno::EIO)?)
            } else {
                None
            };
            let (version, cached, cache_generation) = {
                let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
                let cache_generation = self.accounts.clean_cache_generation();
                state.refresh_cache_generation(cache_generation);
                let file = state.files.get(&handle.0).ok_or(Errno::EBADF)?;
                if file.ino != u64::from(ino) {
                    return Err(Errno::EBADF);
                }
                if file.failed {
                    return Err(Errno::EIO);
                }
                let length = u64::from(size.min(MAX_RANGE))
                    .min(file.version.size().saturating_sub(offset))
                    as usize;
                let cached = state.cache.iter().any(|entry| {
                    entry.version == file.version
                        && entry.offset == offset
                        && entry.bytes.len() == length
                });
                (file.version.clone(), cached, cache_generation)
            };
            if offset >= version.size() || size == 0 {
                return Ok(Vec::new());
            }
            let length = u64::from(size.min(MAX_RANGE)).min(version.size() - offset) as u32;
            let fetched = if cached {
                self.accounts
                    .verify_file(&self.space, &version)
                    .map(|()| None)
                    .map_err(|_| Errno::EIO)
            } else {
                self.fetch_range(&version, offset, length).map(Some)
            };
            let mut state = self.state.lock().map_err(|_| Errno::EIO)?;
            let current_cache_generation = self.accounts.clean_cache_generation();
            state.refresh_cache_generation(current_cache_generation);
            let still_current = state.files.get(&handle.0).is_some_and(|file| {
                !file.failed && file.ino == u64::from(ino) && file.version == version
            });
            if !still_current {
                return Err(Errno::EIO);
            }
            let bytes = match fetched {
                Ok(Some(bytes)) => {
                    if cache_generation == current_cache_generation {
                        state.insert_range(version.clone(), offset, bytes.clone());
                    }
                    bytes
                }
                Ok(None) => {
                    let position = state
                        .cache
                        .iter()
                        .position(|entry| {
                            entry.version == version
                                && entry.offset == offset
                                && entry.bytes.len() == length as usize
                        })
                        .ok_or(Errno::EIO)?;
                    let entry = state.cache.remove(position).ok_or(Errno::EIO)?;
                    let bytes = entry.bytes.clone();
                    state.cache.push_back(entry);
                    bytes
                }
                Err(_) => {
                    // Missing original-base ranges can become available again;
                    // a transient offline read must not poison a durable handle.
                    if !version.id().starts_with("cirrus-staged:") {
                        state.invalidate_id(version.id());
                    }
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
            if sequential {
                self.read_ahead(&version, next);
            }
            Ok(bytes)
        })();
        match result {
            Ok(bytes) => reply.data(&bytes),
            Err(error) => reply.error(error),
        }
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
        match self.state.lock() {
            Ok(mut state) => {
                state.files.remove(&handle.0);
                let id = u64::from(ino);
                if state.detached.contains(&id) && !state.files.values().any(|file| file.ino == id)
                {
                    state.detached.remove(&id);
                    state.nodes.remove(&id);
                }
                reply.ok();
            }
            Err(_) => reply.error(Errno::EIO),
        }
    }
}

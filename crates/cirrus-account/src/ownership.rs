use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use cirrus_runtime::RuntimeDir;
use nix::unistd::{Uid, User};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::{
    net::{self, sockopt},
    process,
};

use crate::AccountError;

const MARKER: &str = "account.lock";
const CONTENT: &[u8] = b"cirrus-drive account lock v1\n";
const SYNC_MARKER: &str = "sync.lock";
const SYNC_CONTENT: &[u8] = b"cirrus-drive sync lock v1\n";
const STAGING_MARKER: &str = "staging.lock";
const STAGING_CONTENT: &[u8] = b"cirrus-drive staging lock v1\n";
// Linux filesystem magic values for local filesystems with kernel-managed locks.
const LOCAL_FILESYSTEMS: &[u64] = &[
    0xef53,     // ext2/3/4
    0x58465342, // XFS
    0x9123683e, // Btrfs
    0x01021994, // tmpfs
    0xf2f52010, // F2FS
    0x2fc12fc1, // ZFS
];

pub(crate) struct Guard {
    _lock: OwnedFd,
    bus: zbus::blocking::Connection,
}

impl Guard {
    pub fn connection(&self) -> &zbus::blocking::Connection {
        &self.bus
    }

    pub fn reconnect(&mut self) -> Result<(), AccountError> {
        if self.bus.is_closed() {
            self.bus = connect_bus(true)?;
        }
        Ok(())
    }

    pub fn downgrade(&self) -> Result<(), AccountError> {
        fs::flock(&self._lock, fs::FlockOperation::NonBlockingLockShared)
            .map_err(|_| AccountError::new("cannot retain shared account ownership"))
    }
}

pub(crate) fn acquire(runtime: &RuntimeDir) -> Result<Guard, AccountError> {
    runtime
        .revalidate()
        .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
    let lock = lock_file(
        MARKER,
        CONTENT,
        // Automatic work may rotate only the already-bound principal's token.
        // Keep the exclusive bus owner for cross-process credential writers,
        // but do not exclude local retained-principal mounts/edits while the
        // keyring or network is slow. Principal changes still require EX flock.
        if crate::executor::is_automatic() {
            fs::FlockOperation::NonBlockingLockShared
        } else {
            fs::FlockOperation::NonBlockingLockExclusive
        },
    )?;
    let bus = connect_bus(true)?;
    Ok(Guard { _lock: lock, bus })
}

pub(crate) fn acquire_shared(runtime: &RuntimeDir) -> Result<Guard, AccountError> {
    runtime
        .revalidate()
        .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
    let lock = lock_file(MARKER, CONTENT, fs::FlockOperation::NonBlockingLockShared)?;
    // Staging may coexist with sync's exclusive bus name and same-principal
    // automatic rotation. Shared flock still excludes foreground account changes.
    let bus = connect_bus(false)?;
    Ok(Guard { _lock: lock, bus })
}

// Local retained-principal operations exclude foreground account changes
// without contacting Secret Service or acquiring its bus name.
pub(crate) fn acquire_offline(runtime: &RuntimeDir) -> Result<OwnedFd, AccountError> {
    runtime
        .revalidate()
        .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
    lock_file(MARKER, CONTENT, fs::FlockOperation::NonBlockingLockShared)
}

pub(crate) fn acquire_sync(runtime: &RuntimeDir) -> Result<OwnedFd, AccountError> {
    runtime
        .revalidate()
        .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
    lock_file(
        SYNC_MARKER,
        SYNC_CONTENT,
        fs::FlockOperation::NonBlockingLockExclusive,
    )
}

pub(crate) fn acquire_scheduler() -> Result<OwnedFd, AccountError> {
    lock_file(
        "scheduler.lock",
        b"cirrus-drive scheduler lock v1\n",
        fs::FlockOperation::NonBlockingLockExclusive,
    )
}

pub(crate) fn acquire_staging() -> Result<OwnedFd, AccountError> {
    lock_file(
        STAGING_MARKER,
        STAGING_CONTENT,
        fs::FlockOperation::LockExclusive,
    )
}

struct StoreSlot {
    state: Mutex<StoreOwners>,
    released: Condvar,
}

struct StoreOwners {
    owner: Option<std::thread::ThreadId>,
    waiting: VecDeque<std::thread::ThreadId>,
}

static STATE_STORE: StoreSlot = StoreSlot {
    state: Mutex::new(StoreOwners {
        owner: None,
        waiting: VecDeque::new(),
    }),
    released: Condvar::new(),
};
static CACHE_STORE: StoreSlot = StoreSlot {
    state: Mutex::new(StoreOwners {
        owner: None,
        waiting: VecDeque::new(),
    }),
    released: Condvar::new(),
};

pub(crate) type StoreLease = Arc<StoreLeaseInner>;
pub(crate) struct StoreLeaseInner {
    fd: Option<OwnedFd>,
    slot: &'static StoreSlot,
}

impl Drop for StoreLeaseInner {
    fn drop(&mut self) {
        let mut state = self.slot.state.lock().expect("Store owner lock poisoned");
        drop(self.fd.take());
        state.owner = None;
        self.slot.released.notify_all();
    }
}

thread_local! {
    static LOCAL_STATE_TURN: std::cell::RefCell<Option<StateAdmission>> = const { std::cell::RefCell::new(None) };
}

struct StateAdmission {
    lease: Option<StoreLease>,
    cancelled: Arc<AtomicBool>,
}
pub(crate) struct LocalStateTurn {
    previous: Option<StateAdmission>,
    active: bool,
}
impl Drop for LocalStateTurn {
    fn drop(&mut self) {
        if self.active {
            LOCAL_STATE_TURN.with(|turn| {
                turn.replace(self.previous.take());
            });
        }
    }
}

// Payload candidates retain their existing durability-before-admission order.
// Each SQL phase admits before planning and lends its SAME flock to the
// reservation/recovery in that phase, not across independent phases.
pub(crate) fn local_state_turn(cancelled: Arc<AtomicBool>) -> Result<LocalStateTurn, AccountError> {
    if crate::storage::limits::view()?.limits.is_none() {
        return Ok(LocalStateTurn {
            previous: None,
            active: false,
        });
    }
    let previous = LOCAL_STATE_TURN.with(|turn| {
        turn.replace(Some(StateAdmission {
            lease: None,
            cancelled,
        }))
    });
    Ok(LocalStateTurn {
        previous,
        active: true,
    })
}

pub(crate) struct LocalStatePhase(bool);
impl Drop for LocalStatePhase {
    fn drop(&mut self) {
        if self.0 {
            let lease = LOCAL_STATE_TURN.with(|turn| {
                turn.borrow_mut()
                    .as_mut()
                    .and_then(|turn| turn.lease.take())
            });
            drop(lease);
        }
    }
}

pub(crate) fn admit_local_state_turn() -> Result<LocalStatePhase, AccountError> {
    let cancelled = LOCAL_STATE_TURN.with(|turn| {
        turn.borrow()
            .as_ref()
            .filter(|turn| turn.lease.is_none())
            .map(|turn| Arc::clone(&turn.cancelled))
    });
    if let Some(cancelled) = cancelled {
        let lease = acquire_store("state", Some(&cancelled))?;
        LOCAL_STATE_TURN.with(|turn| {
            turn.borrow_mut()
                .as_mut()
                .expect("local State admission missing")
                .lease = Some(lease);
        });
        return Ok(LocalStatePhase(true));
    }
    Ok(LocalStatePhase(false))
}

pub(crate) fn acquire_storage_store(store: &str) -> Result<StoreLease, AccountError> {
    acquire_store(store, None)
}

fn store_busy(mut error: AccountError, store: &str) -> AccountError {
    error.storage_busy = error.is_operation_busy();
    #[cfg(feature = "fault-injection")]
    if error.storage_busy && std::env::var_os("CIRRUS_TEST_BLOCKER_TRACE").is_some() {
        eprintln!(
            "cirrus lab Store lease refused: store={store} automatic={}",
            crate::executor::is_automatic()
        );
        if !crate::executor::is_automatic()
            && let Some(marker) = std::env::var_os("CIRRUS_TEST_LOCAL_STATE_CONTENTION_MARKER")
        {
            let _ = std::fs::write(marker, b"blocked");
        }
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = store;
    error
}

fn acquire_store(store: &str, wait: Option<&AtomicBool>) -> Result<StoreLease, AccountError> {
    if store == "state"
        && let Some(lease) =
            LOCAL_STATE_TURN.with(|turn| turn.borrow().as_ref().and_then(|turn| turn.lease.clone()))
    {
        return Ok(lease);
    }
    let slot = match store {
        "state" => &STATE_STORE,
        "cache" => &CACHE_STORE,
        _ => return Err(AccountError::new("invalid storage reservation store")),
    };
    let mut state = slot
        .state
        .lock()
        .map_err(|_| AccountError::new("Store ownership unavailable"))?;
    let requester = std::thread::current().id();
    let error = || {
        store_busy(
            AccountError::new("another account operation is in progress"),
            store,
        )
    };
    if state.owner == Some(requester) {
        return Err(error());
    }
    if wait.is_some() {
        state.waiting.push_back(requester);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if wait.is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
            || (wait.is_some() && Instant::now() >= deadline)
        {
            state.waiting.retain(|thread| *thread != requester);
            slot.released.notify_all();
            return Err(error());
        }
        let first = state.waiting.front().copied();
        if state.owner.is_none() && first == wait.map(|_| requester) {
            if wait.is_some() {
                state.waiting.pop_front();
                slot.released.notify_all();
            }
            break;
        }
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_BLOCKER_TRACE").is_some() {
            eprintln!(
                "cirrus lab local Store contention: pid={} store={store} owner={:?} requester={requester:?} wait={}",
                std::process::id(),
                state.owner,
                wait.is_some()
            );
        }
        if wait.is_none() {
            return Err(error());
        }
        #[cfg(feature = "fault-injection")]
        {
            let _ = error(); // Witness actual local lease contention in the fixture.
            if let Some(marker) = std::env::var_os("CIRRUS_TEST_CLI_SNAPSHOT_BLOCKED_MARKER") {
                let _ = std::fs::write(marker, b"waiting");
            }
        }
        // Only local admission queues. Nonwaiting optional copies cannot
        // leapfrog it; cross-process flocks below remain nonblocking.
        state = slot
            .released
            .wait_timeout(state, Duration::from_millis(100))
            .map_err(|_| AccountError::new("Store ownership unavailable"))?
            .0;
    }
    let (marker, content): (&str, &[u8]) = match store {
        "state" => (
            "state-storage.lock",
            b"cirrus state storage reservation v1\n",
        ),
        "cache" => (
            "cache-storage.lock",
            b"cirrus cache storage reservation v1\n",
        ),
        _ => return Err(AccountError::new("invalid storage reservation store")),
    };
    let fd = lock_file(
        marker,
        content,
        fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|error| store_busy(error, store))?;
    state.owner = Some(requester);
    Ok(Arc::new(StoreLeaseInner { fd: Some(fd), slot }))
}

fn home() -> Result<PathBuf, AccountError> {
    #[cfg(feature = "fault-injection")]
    if let Some(path) = std::env::var_os("CIRRUS_TEST_ACCOUNT_HOME") {
        return Ok(PathBuf::from(path));
    }
    let user = User::from_uid(Uid::effective())
        .map_err(|_| AccountError::new("cannot resolve the account owner's home directory"))?
        .ok_or_else(|| AccountError::new("account owner has no system home directory"))?;
    Ok(user.dir)
}

fn checked_dir(parent: &OwnedFd, name: &str, private: bool) -> Result<OwnedFd, AccountError> {
    let open = || {
        fs::openat2(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
    };
    let fd = match open() {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => {
            match fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => fs::fsync(parent).map_err(|_| {
                    AccountError::new("cannot persist account coordination directory")
                })?,
                Err(rustix::io::Errno::EXIST) => (),
                Err(_) => {
                    return Err(AccountError::new(
                        "cannot create account coordination directory",
                    ));
                }
            }
            open().map_err(|_| AccountError::new("cannot open account coordination directory"))?
        }
        Err(_) => {
            return Err(AccountError::new(
                "account coordination directory is unsafe",
            ));
        }
    };
    let stat = fs::fstat(&fd)
        .map_err(|_| AccountError::new("cannot inspect account coordination directory"))?;
    if stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o022 != 0
        || (private && stat.st_mode & 0o7777 != 0o700)
    {
        return Err(AccountError::new(
            "account coordination directory has unsafe ownership or permissions",
        ));
    }
    Ok(fd)
}

fn check_local_filesystem(fd: &OwnedFd) -> Result<(), AccountError> {
    let filesystem = fs::fstatfs(fd)
        .map_err(|_| AccountError::new("cannot inspect account lock filesystem"))?
        .f_type as u64;
    if !LOCAL_FILESYSTEMS.contains(&filesystem) {
        return Err(AccountError::new(
            "account coordination requires a supported local filesystem; inspect the system home",
        ));
    }
    Ok(())
}

fn check_home_ancestors(path: &Path) -> Result<(), AccountError> {
    let parent = path
        .parent()
        .ok_or_else(|| AccountError::new("account owner's home is unsafe"))?;
    let mut fd = fs::openat2(
        fs::CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| AccountError::new("cannot inspect account home ancestors"))?;
    for component in parent.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                fd = fs::openat2(
                    &fd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(|_| AccountError::new("cannot inspect account home ancestors"))?;
            }
            _ => return Err(AccountError::new("account home has unsafe path components")),
        }
        let stat = fs::fstat(&fd)
            .map_err(|_| AccountError::new("cannot inspect account home ancestors"))?;
        if (stat.st_uid != 0 && stat.st_uid != process::geteuid().as_raw())
            || (stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0)
        {
            return Err(AccountError::new(
                "account home has unsafe writable ancestors",
            ));
        }
    }
    Ok(())
}

pub(crate) fn state_dir() -> Result<OwnedFd, AccountError> {
    let path = home()?;
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().any(|p| p == Component::ParentDir)
    {
        return Err(AccountError::new(
            "account owner's system home directory is unsafe",
        ));
    }
    check_home_ancestors(&path)?;
    let home = fs::openat2(
        fs::CWD,
        &path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| AccountError::new("cannot safely open account owner's system home directory"))?;
    let stat =
        fs::fstat(&home).map_err(|_| AccountError::new("cannot inspect account owner's home"))?;
    if stat.st_uid != process::geteuid().as_raw() || stat.st_mode & 0o022 != 0 {
        return Err(AccountError::new(
            "account owner's home has unsafe ownership or permissions",
        ));
    }
    check_local_filesystem(&home)?;
    let local = checked_dir(&home, ".local", false)?;
    check_local_filesystem(&local)?;
    let state = checked_dir(&local, "state", false)?;
    check_local_filesystem(&state)?;
    let directory = checked_dir(&state, "cirrus-drive", true)?;
    check_local_filesystem(&directory)?;
    Ok(directory)
}

pub(crate) fn staging_dir() -> Result<OwnedFd, AccountError> {
    let state = state_dir()?;
    let staging = checked_dir(&state, "staging", true)?;
    check_local_filesystem(&staging)?;
    Ok(staging)
}

pub(crate) fn directory_snapshots_dir() -> Result<OwnedFd, AccountError> {
    let state = state_dir()?;
    let directory = checked_dir(&state, "directory-snapshots", true)?;
    check_local_filesystem(&directory)?;
    Ok(directory)
}

fn lock_file(
    marker: &str,
    expected_content: &[u8],
    operation: fs::FlockOperation,
) -> Result<OwnedFd, AccountError> {
    lock_file_mode(marker, expected_content, operation, true)
}

pub(crate) fn namespace_lease(token: &str, create: bool) -> Result<OwnedFd, AccountError> {
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AccountError::new("invalid namespace reservation token"));
    }
    let marker = format!(".namespace-lease-{token}");
    let content = b"cirrus namespace scratch reservation v1\n";
    if create {
        let dir = state_dir()?;
        let fd = fs::openat2(
            &dir,
            marker.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| AccountError::new("cannot create namespace reservation lease"))?;
        let mut output = std::fs::File::from(fd);
        output
            .write_all(content)
            .and_then(|()| output.sync_all())
            .map_err(|_| AccountError::new("cannot persist namespace reservation lease"))?;
        fs::fsync(&dir)
            .map_err(|_| AccountError::new("cannot persist namespace reservation lease"))?;
    }
    lock_file_mode(
        &marker,
        content,
        fs::FlockOperation::NonBlockingLockExclusive,
        false,
    )
}

fn lock_file_mode(
    marker: &str,
    expected_content: &[u8],
    operation: fs::FlockOperation,
    create: bool,
) -> Result<OwnedFd, AccountError> {
    let directory = state_dir()?;
    let open = || {
        fs::openat2(
            &directory,
            marker,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
    };
    let fd = match open() {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) if create => {
            let tmp = fs::openat(
                &directory,
                ".",
                OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| AccountError::new("cannot create account coordination marker"))?;
            let mut tmp = std::fs::File::from(tmp);
            tmp.write_all(expected_content)
                .and_then(|()| tmp.sync_all())
                .map_err(|_| AccountError::new("cannot persist account coordination marker"))?;
            match fs::linkat(&tmp, "", &directory, marker, AtFlags::EMPTY_PATH) {
                Ok(()) => fs::fsync(&directory)
                    .map_err(|_| AccountError::new("cannot persist account coordination marker"))?,
                Err(rustix::io::Errno::EXIST) => (),
                Err(_) => {
                    return Err(AccountError::new(
                        "cannot publish account coordination marker",
                    ));
                }
            }
            open().map_err(|_| AccountError::new("cannot open account coordination marker"))?
        }
        Err(_) => return Err(AccountError::new("account coordination marker is unsafe")),
    };
    let stat = fs::fstat(&fd)
        .map_err(|_| AccountError::new("cannot inspect account coordination marker"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(AccountError::new("account coordination marker is unsafe"));
    }
    let mut content = Vec::new();
    std::fs::File::from(
        fd.try_clone()
            .map_err(|_| AccountError::new("cannot inspect account coordination marker"))?,
    )
    .take((expected_content.len() + 1) as u64)
    .read_to_end(&mut content)
    .map_err(|_| AccountError::new("cannot inspect account coordination marker"))?;
    if content != expected_content {
        return Err(AccountError::new(
            "unrecognized account coordination marker; inspect it manually",
        ));
    }
    fs::flock(&fd, operation).map_err(|_| {
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_NAMESPACE_TRACE").is_some() {
            eprintln!("cirrus lab coordination contention: marker={marker}");
        }
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_BLOCKER_TRACE").is_some() {
            let inode = format!(":{}", stat.st_ino);
            let locks = std::fs::read_to_string("/proc/locks").unwrap_or_default();
            let owners: Vec<_> = locks.lines().filter(|line| line.split_whitespace().nth(5).is_some_and(|key| key.ends_with(&inode))).collect();
            eprintln!("cirrus lab flock refusal: pid={} thread={:?} marker={marker} requested={operation:?} owners={owners:?}", std::process::id(), std::thread::current().id());
        }
        AccountError::retryable_read("another account operation is in progress")
    })?;
    let current = open().map_err(|_| AccountError::new("account coordination marker changed"))?;
    let current =
        fs::fstat(current).map_err(|_| AccountError::new("account coordination marker changed"))?;
    if (stat.st_dev, stat.st_ino) != (current.st_dev, current.st_ino) || current.st_nlink != 1 {
        return Err(AccountError::new("account coordination marker changed"));
    }
    Ok(fd)
}

fn bus_dir() -> PathBuf {
    #[cfg(feature = "fault-injection")]
    if let Some(path) = std::env::var_os("CIRRUS_TEST_USER_BUS_DIR") {
        return PathBuf::from(path);
    }
    PathBuf::from(format!("/run/user/{}", process::geteuid().as_raw()))
}

fn transient_bus_io(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind;
    matches!(
        kind,
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::BrokenPipe
            | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::Interrupted
    )
}

fn transient_bus_error(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::InputOutput(error) | zbus::Error::Connection(error, _) => {
            transient_bus_io(error.kind())
        }
        zbus::Error::FDO(error) => match error.as_ref() {
            zbus::fdo::Error::ZBus(error) => transient_bus_error(error),
            zbus::fdo::Error::NoReply(_)
            | zbus::fdo::Error::Timeout(_)
            | zbus::fdo::Error::TimedOut(_)
            | zbus::fdo::Error::Disconnected(_)
            | zbus::fdo::Error::NoServer(_) => true,
            _ => false,
        },
        zbus::Error::MethodError(name, _, _) => matches!(
            name.as_str(),
            "org.freedesktop.DBus.Error.NoReply"
                | "org.freedesktop.DBus.Error.Timeout"
                | "org.freedesktop.DBus.Error.TimedOut"
                | "org.freedesktop.DBus.Error.Disconnected"
                | "org.freedesktop.DBus.Error.NoServer"
        ),
        // Handshake/format/auth errors (including text-only EOF reports) do
        // not establish a safe transport failure. Never infer from prose.
        _ => false,
    }
}

fn bus_failure(message: &'static str, transient: bool) -> AccountError {
    if crate::executor::is_automatic() && transient {
        AccountError::retryable_read(message)
    } else {
        AccountError::new(message)
    }
}

fn connect_bus(exclusive: bool) -> Result<zbus::blocking::Connection, AccountError> {
    let directory = RuntimeDir::open(&bus_dir()).map_err(|_| {
        AccountError::new("standard per-user bus directory is unavailable or unsafe")
    })?;
    let socket = fs::openat2(
        &directory,
        "bus",
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| {
        // Only an absent socket is availability, not a bad/symlinked path,
        // unsafe directory or rejected permissions.
        bus_failure(
            "standard per-user bus is unavailable",
            error == rustix::io::Errno::NOENT,
        )
    })?;
    let stat = fs::fstat(&socket)
        .map_err(|_| AccountError::new("cannot inspect standard per-user bus"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
        || stat.st_uid != process::geteuid().as_raw()
    {
        return Err(AccountError::new("standard per-user bus socket is unsafe"));
    }
    let proc = fs::openat2(
        fs::CWD,
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| AccountError::new("trusted procfs is required for the per-user bus"))?;
    if fs::fstatfs(&proc)
        .map_err(|_| AccountError::new("cannot inspect procfs"))?
        .f_type
        != fs::PROC_SUPER_MAGIC
    {
        return Err(AccountError::new(
            "trusted procfs is required for the per-user bus",
        ));
    }
    let address =
        net::SocketAddrUnix::new(format!("/proc/self/fd/{}", socket.as_raw_fd()).as_str())
            .map_err(|_| AccountError::new("invalid standard per-user bus address"))?;
    let fd = net::socket_with(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| AccountError::new("cannot connect to standard per-user bus"))?;
    net::connect(&fd, &address).map_err(|error| {
        bus_failure(
            "cannot connect to standard per-user bus",
            transient_bus_io(std::io::Error::from(error).kind()),
        )
    })?;
    let stream = UnixStream::from(fd);
    let peer = sockopt::socket_peercred(&stream)
        .map_err(|_| AccountError::new("cannot verify per-user bus peer"))?;
    if peer.uid != process::geteuid() {
        return Err(AccountError::new("per-user bus peer UID does not match"));
    }
    let builder = zbus::blocking::connection::Builder::async_io_unix_stream(stream);
    // Bound each background Secret Service method, not whole authentication
    // or local I/O. Timed-out credential writes retain existing refresh fences.
    let builder = if crate::executor::is_automatic() {
        builder.method_timeout(Duration::from_secs(1))
    } else {
        builder
    };
    let bus = builder.build().map_err(|error| {
        bus_failure(
            "cannot authenticate standard per-user bus",
            transient_bus_error(&error),
        )
    })?;
    if !exclusive {
        return Ok(bus);
    }
    #[cfg(feature = "fault-injection")]
    if crate::executor::is_automatic() {
        crate::wait_test_window("CIRRUS_TEST_ACCOUNT_BUS_WINDOW")?;
    }
    let reply = bus
        .request_name_with_flags(
            "org.cirrusdrive.AccountOperation",
            zbus::fdo::RequestNameFlags::DoNotQueue.into(),
        )
        .map_err(|error| {
            #[cfg(feature = "fault-injection")]
            if std::env::var_os("CIRRUS_TEST_ACCOUNT_BUS_WINDOW").is_some() {
                eprintln!("cirrus lab credential bus negotiation error: {error:?}");
            }
            match error {
                zbus::Error::NameTaken => {
                    AccountError::retryable_read("another account operation is in progress")
                }
                _ => bus_failure(
                    "cannot acquire account operation bus lock",
                    transient_bus_error(&error),
                ),
            }
        })?;
    if reply != zbus::fdo::RequestNameReply::PrimaryOwner {
        return Err(AccountError::retryable_read(
            "another account operation is in progress",
        ));
    }
    Ok(bus)
}

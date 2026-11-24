use std::collections::VecDeque;
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use cirrus_runtime::RuntimeDir;
use nix::unistd::{Uid, User};
use rustix::fs::{self, Mode, OFlags};
#[cfg(target_os = "linux")]
use rustix::fs::{FileType, ResolveFlags};
#[cfg(target_os = "linux")]
use rustix::net::{self, sockopt};
use rustix::process;

use crate::AccountError;
use crate::account_storage::{RootIdentity, StorageRoot};

pub(crate) mod credentials;
#[cfg(target_os = "macos")]
pub(crate) mod darwin_acl;
pub(crate) mod file_ops;
mod marker;
pub(super) mod state_dir;

// Default wrappers are temporary C6b migration boundaries for unrooted data
// helpers. They do not bind nested helper I/O to an outer Guard's root.

const MARKER: &str = "account.lock";
const CONTENT: &[u8] = b"cirrus-drive account lock v1\n";
const SYNC_MARKER: &str = "sync.lock";
const SYNC_CONTENT: &[u8] = b"cirrus-drive sync lock v1\n";
const STAGING_MARKER: &str = "staging.lock";
const STAGING_CONTENT: &[u8] = b"cirrus-drive staging lock v1\n";
pub(crate) struct Guard {
    _lock: OwnedFd,
    root: StorageRoot,
    credentials: credentials::Context,
    mode: LockMode,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LockMode {
    Shared,
    Exclusive,
    // A failed flock conversion cannot prove that the old lock survived.
    Unknown,
}

impl Guard {
    pub(crate) fn storage_root(&self) -> &StorageRoot {
        &self.root
    }

    pub fn is_exclusive(&self) -> bool {
        self.mode == LockMode::Exclusive
    }

    pub fn credential_context(&self) -> &credentials::Context {
        &self.credentials
    }

    pub fn reconnect(&mut self) -> Result<(), AccountError> {
        if self.mode == LockMode::Unknown {
            return Err(AccountError::new("account lock mode is unavailable"));
        }
        self.root.revalidate()?;
        #[cfg(target_os = "linux")]
        if self.credentials.bus.is_closed() {
            self.credentials.bus = connect_bus(true)?;
        }
        #[cfg(target_os = "macos")]
        {
            self.credentials
                .revalidate_principal(&self._lock, MARKER, CONTENT)?;
        }
        Ok(())
    }

    pub fn downgrade(&mut self) -> Result<(), AccountError> {
        #[cfg(target_os = "macos")]
        if self.mode == LockMode::Unknown {
            return Err(AccountError::new("account lock mode is unavailable"));
        }
        if self.mode == LockMode::Shared {
            return Ok(());
        }
        self.mode = LockMode::Unknown;
        fs::flock(&self._lock, fs::FlockOperation::NonBlockingLockShared)
            .map_err(|_| AccountError::new("cannot retain shared account ownership"))?;
        self.mode = LockMode::Shared;
        Ok(())
    }
}

pub(crate) fn acquire_in(
    root: &StorageRoot,
    runtime: &RuntimeDir,
    #[cfg(target_os = "macos")] config: Option<&credentials::KeychainConfig>,
) -> Result<Guard, AccountError> {
    acquire_principal_in(
        root,
        runtime,
        #[cfg(target_os = "macos")]
        config,
        false,
    )
}

pub(crate) fn acquire_local_in(
    root: &StorageRoot,
    runtime: &RuntimeDir,
    #[cfg(target_os = "macos")] config: Option<&credentials::KeychainConfig>,
) -> Result<Guard, AccountError> {
    acquire_principal_in(
        root,
        runtime,
        #[cfg(target_os = "macos")]
        config,
        true,
    )
}

fn acquire_principal_in(
    root: &StorageRoot,
    runtime: &RuntimeDir,
    #[cfg(target_os = "macos")] config: Option<&credentials::KeychainConfig>,
    local: bool,
) -> Result<Guard, AccountError> {
    runtime
        .revalidate()
        .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
    // Local namespace preparation needs fresh EX, even when credentials must
    // remain noninteractive. Never upgrade a retained shared owner.
    let automatic = crate::executor::is_automatic() && !local;
    #[cfg(target_os = "linux")]
    let lock = lock_file_in(
        root,
        MARKER,
        CONTENT,
        // Automatic work may rotate only the already-bound principal's token.
        // Keep the exclusive bus owner for cross-process credential writers,
        // but do not exclude local retained-principal mounts/edits while the
        // keyring or network is slow. Principal changes still require EX flock.
        if automatic {
            fs::FlockOperation::NonBlockingLockShared
        } else {
            fs::FlockOperation::NonBlockingLockExclusive
        },
    )?;
    #[cfg(target_os = "linux")]
    let credentials = credentials::Context {
        bus: connect_bus(true)?,
    };
    #[cfg(target_os = "macos")]
    let (lock, credentials) = credential_ownership(
        root,
        config,
        if automatic {
            fs::FlockOperation::NonBlockingLockShared
        } else {
            fs::FlockOperation::NonBlockingLockExclusive
        },
        true,
    )?;
    Ok(Guard {
        _lock: lock,
        root: root.clone(),
        credentials,
        mode: if automatic {
            LockMode::Shared
        } else {
            LockMode::Exclusive
        },
    })
}

pub(crate) fn acquire_shared_in(
    root: &StorageRoot,
    runtime: &RuntimeDir,
    #[cfg(target_os = "macos")] config: Option<&credentials::KeychainConfig>,
) -> Result<Guard, AccountError> {
    runtime
        .revalidate()
        .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
    #[cfg(target_os = "linux")]
    let lock = lock_file_in(
        root,
        MARKER,
        CONTENT,
        fs::FlockOperation::NonBlockingLockShared,
    )?;
    // Staging may coexist with sync's exclusive bus name and same-principal
    // automatic rotation. Shared flock still excludes foreground account changes.
    #[cfg(target_os = "linux")]
    let credentials = credentials::Context {
        bus: connect_bus(false)?,
    };
    #[cfg(target_os = "macos")]
    let (lock, credentials) = credential_ownership(
        root,
        config,
        fs::FlockOperation::NonBlockingLockShared,
        false,
    )?;
    Ok(Guard {
        _lock: lock,
        root: root.clone(),
        credentials,
        mode: LockMode::Shared,
    })
}

#[cfg(target_os = "macos")]
fn credential_ownership(
    root: &StorageRoot,
    config: Option<&credentials::KeychainConfig>,
    principal: fs::FlockOperation,
    writer: bool,
) -> Result<(OwnedFd, credentials::Context), AccountError> {
    let config = config.ok_or_else(|| AccountError::new("Keychain access group is required"))?;
    let directory = root.directory();
    // Both markers are admitted under the SAME directory and home binding.
    let lock =
        marker::lock(directory, MARKER, CONTENT, principal, true).map_err(native_marker_error)?;
    // Principal admission has completed. marker::lock releases its publication
    // leaf before this requested writer flock; save never acquires either lock.
    let fd = if writer {
        Some(
            marker::lock(
                directory,
                credentials::Context::MARKER,
                credentials::Context::CONTENT,
                fs::FlockOperation::NonBlockingLockExclusive,
                true,
            )
            .map_err(native_marker_error)?,
        )
    } else {
        None
    };
    Ok((lock, credentials::Context::new(config, root.clone(), fd)?))
}

#[cfg(target_os = "macos")]
fn native_marker_error(error: marker::MarkerError) -> AccountError {
    match error {
        marker::MarkerError::Failure(message) => AccountError::new(message),
        marker::MarkerError::Contended => {
            AccountError::retryable_read("another account operation is in progress")
        }
    }
}

// Local retained-principal operations exclude foreground account changes
// without contacting Secret Service or acquiring its bus name.
pub(crate) fn acquire_offline_in(
    root: &StorageRoot,
    runtime: &RuntimeDir,
) -> Result<OwnedFd, AccountError> {
    runtime
        .revalidate()
        .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
    lock_file_in(
        root,
        MARKER,
        CONTENT,
        fs::FlockOperation::NonBlockingLockShared,
    )
}

// Pin removal/replacement must exclude an entire local staging turn, including an
// immutable candidate not yet registered in SQLite. No Secret Service/bus.
pub(crate) fn acquire_offline_exclusive_in(
    root: &StorageRoot,
    runtime: &RuntimeDir,
) -> Result<OwnedFd, AccountError> {
    runtime
        .revalidate()
        .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
    lock_file_in(
        root,
        MARKER,
        CONTENT,
        fs::FlockOperation::NonBlockingLockExclusive,
    )
}

pub(crate) fn acquire_sync_in(
    root: &StorageRoot,
    runtime: &RuntimeDir,
) -> Result<OwnedFd, AccountError> {
    runtime
        .revalidate()
        .map_err(|_| AccountError::new("runtime directory is unavailable or unsafe"))?;
    lock_file_in(
        root,
        SYNC_MARKER,
        SYNC_CONTENT,
        fs::FlockOperation::NonBlockingLockExclusive,
    )
}

pub(crate) fn acquire_scheduler_in(root: &StorageRoot) -> Result<OwnedFd, AccountError> {
    lock_file_in(
        root,
        "scheduler.lock",
        b"cirrus-drive scheduler lock v1\n",
        fs::FlockOperation::NonBlockingLockExclusive,
    )
}

pub(crate) fn acquire_staging_in(root: &StorageRoot) -> Result<OwnedFd, AccountError> {
    lock_file_in(
        root,
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
    // Reserved through acquisition and final FD close, not just active use.
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
    root: StorageRoot,
    identity: RootIdentity,
}

impl Drop for StoreLeaseInner {
    fn drop(&mut self) {
        drop(self.fd.take());
        let mut state = self.slot.state.lock().expect("Store owner lock poisoned");
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
    root: StorageRoot,
    identity: RootIdentity,
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
pub(crate) fn local_state_turn_in(
    root: &StorageRoot,
    cancelled: Arc<AtomicBool>,
) -> Result<LocalStateTurn, AccountError> {
    // Check before limits I/O or replacing the outer admission. TLS lends
    // ownership only; it never chooses a storage root for a caller.
    check_state_root(root)?;
    if crate::storage::limits::view_in(root)?.limits.is_none() {
        return Ok(LocalStateTurn {
            previous: None,
            active: false,
        });
    }
    let previous = LOCAL_STATE_TURN.with(|turn| {
        turn.replace(Some(StateAdmission {
            lease: None,
            cancelled,
            root: root.clone(),
            identity: root.identity(),
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

pub(crate) fn admit_local_state_turn_in(
    root: &StorageRoot,
) -> Result<LocalStatePhase, AccountError> {
    check_state_root(root)?;
    let cancelled = LOCAL_STATE_TURN.with(|turn| {
        turn.borrow()
            .as_ref()
            .filter(|turn| turn.lease.is_none())
            .map(|turn| Arc::clone(&turn.cancelled))
    });
    if let Some(cancelled) = cancelled {
        let lease = acquire_store_in(root, "state", Some(&cancelled))?;
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

pub(crate) fn acquire_storage_store_in(
    root: &StorageRoot,
    store: &str,
) -> Result<StoreLease, AccountError> {
    acquire_store_in(root, store, None)
}

fn check_state_root(root: &StorageRoot) -> Result<(), AccountError> {
    LOCAL_STATE_TURN.with(|turn| {
        if turn.borrow().as_ref().is_some_and(|turn| {
            turn.identity != root.identity() || turn.root.identity() != root.identity()
        }) {
            return Err(AccountError::new("local State ownership root changed"));
        }
        Ok(())
    })
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

fn acquire_store_in(
    root: &StorageRoot,
    store: &str,
    wait: Option<&AtomicBool>,
) -> Result<StoreLease, AccountError> {
    if store == "state" {
        check_state_root(root)?;
    }
    if store == "state"
        && let Some(lease) =
            LOCAL_STATE_TURN.with(|turn| turn.borrow().as_ref().and_then(|turn| turn.lease.clone()))
    {
        if lease.identity != root.identity() || lease.root.identity() != root.identity() {
            return Err(AccountError::new("local State ownership root changed"));
        }
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
    state.owner = Some(requester);
    drop(state);
    // This local owner also releases the reservation if filesystem admission
    // fails. No other caller may acquire while it is opening or closing the FD.
    let mut lease = StoreLeaseInner {
        fd: None,
        slot,
        root: root.clone(),
        identity: root.identity(),
    };
    lease.fd = Some(
        lock_file_in(
            root,
            marker,
            content,
            fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| store_busy(error, store))?,
    );
    Ok(Arc::new(lease))
}

pub(super) fn home() -> Result<PathBuf, AccountError> {
    #[cfg(feature = "fault-injection")]
    if let Some(path) = std::env::var_os("CIRRUS_TEST_ACCOUNT_HOME") {
        return Ok(PathBuf::from(path));
    }
    let user = User::from_uid(Uid::effective())
        .map_err(|_| AccountError::new("cannot resolve the account owner's home directory"))?
        .ok_or_else(|| AccountError::new("account owner has no system home directory"))?;
    Ok(user.dir)
}

fn lock_file_in(
    root: &StorageRoot,
    marker: &str,
    expected_content: &[u8],
    operation: fs::FlockOperation,
) -> Result<OwnedFd, AccountError> {
    lock_file_mode_in(root, marker, expected_content, operation, true)
}

// Only fixed private basenames or already validated/generated tokens. Not a
// general path resolver: physical ancestor admission belongs to StorageRoot.
pub(crate) fn open_private_file(
    dir: &impl std::os::fd::AsFd,
    name: &str,
    flags: OFlags,
    mode: Mode,
) -> rustix::io::Result<OwnedFd> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(rustix::io::Errno::INVAL);
    }
    #[cfg(target_os = "linux")]
    {
        fs::openat2(
            dir,
            name,
            flags,
            mode,
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
    }
    #[cfg(target_os = "macos")]
    {
        fs::openat(dir, name, flags | OFlags::NOFOLLOW, mode)
    }
}

pub(crate) fn namespace_lease_in(
    root: &StorageRoot,
    token: &str,
    create: bool,
) -> Result<OwnedFd, AccountError> {
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AccountError::new("invalid namespace reservation token"));
    }
    let marker = format!(".namespace-lease-{token}");
    let content = b"cirrus namespace scratch reservation v1\n";
    if create {
        let dir = root.directory();
        #[cfg(target_os = "linux")]
        let fd = fs::openat2(
            dir,
            marker.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        );
        #[cfg(target_os = "macos")]
        let fd = fs::openat(
            dir,
            marker.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        );
        let fd = fd.map_err(|_| AccountError::new("cannot create namespace reservation lease"))?;
        let mut output = std::fs::File::from(fd);
        #[cfg(target_os = "macos")]
        if let Err(error) = darwin_acl::check_file(&output) {
            darwin_acl::discard_unwritten_candidate(dir, &marker, &output);
            return Err(AccountError::new(error));
        }
        output
            .write_all(content)
            .and_then(|()| output.sync_all())
            .map_err(|_| AccountError::new("cannot persist namespace reservation lease"))?;
        fs::fsync(dir)
            .map_err(|_| AccountError::new("cannot persist namespace reservation lease"))?;
    }
    lock_file_mode_in(
        root,
        &marker,
        content,
        fs::FlockOperation::NonBlockingLockExclusive,
        false,
    )
}

fn lock_file_mode_in(
    root: &StorageRoot,
    marker: &str,
    expected_content: &[u8],
    operation: fs::FlockOperation,
    create: bool,
) -> Result<OwnedFd, AccountError> {
    marker::lock(
        root.directory(),
        marker,
        expected_content,
        operation,
        create,
    )
    .map_err(|error| match error {
        marker::MarkerError::Failure(message) => AccountError::new(message),
        marker::MarkerError::Contended => {
            AccountError::retryable_read("another account operation is in progress")
        }
    })
}

#[cfg(target_os = "linux")]
fn bus_dir() -> PathBuf {
    #[cfg(feature = "fault-injection")]
    if let Some(path) = std::env::var_os("CIRRUS_TEST_USER_BUS_DIR") {
        return PathBuf::from(path);
    }
    PathBuf::from(format!("/run/user/{}", process::geteuid().as_raw()))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn bus_failure(message: &'static str, transient: bool) -> AccountError {
    if crate::executor::is_automatic() && transient {
        AccountError::retryable_read(message)
    } else {
        AccountError::new(message)
    }
}

#[cfg(target_os = "linux")]
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

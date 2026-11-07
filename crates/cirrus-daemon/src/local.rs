use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::{DirectoryEntry, MountInfo, MountState};
use cirrus_account::{Accounts, JournalPage, PortalBrowser, SignIn};
use cirrus_fuse::Mounted;
use cirrus_runtime::RuntimeDir;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType, sockopt};
use rustix::process;
use serde::{Deserialize, Serialize};

const SOCKET_NAME: &str = "cirrus-drive.sock";
const OWNER_NAME: &str = "cirrus-drive.owner";
const OWNER_CONTENT: &[u8] = b"cirrus-drive runtime socket v1\n";
const MAX_LINE: usize = 262_144;
const TIMEOUT: Duration = Duration::from_secs(2);
const STATUS_REQUEST: &[u8] = b"CIRRUS/2 STATUS\n";
const STOP_REQUEST: &[u8] = b"CIRRUS/2 STOP\n";
const STATUS_RESPONSE: &[u8] =
    b"CIRRUS/2 OK running; automatic sync available for activated Spaces; local staging is not remote confirmation; rename and open-handle restrictions apply\n";
const STOP_RESPONSE: &[u8] = b"CIRRUS/2 OK stopping\n";
const ERROR_RESPONSE: &[u8] = b"CIRRUS/2 ERROR unsupported request\n";
const STOP_BUSY_RESPONSE: &[u8] = b"CIRRUS/2 ERROR shutdown waiting for account operation; retry\n";
const STOP_PENDING_RESPONSE: &[u8] =
    b"CIRRUS/2 ERROR account credentials await keyring persistence; retry account operation\n";
const STATUS_TEXT: &str = "running; automatic sync available for activated Spaces; local staging is not remote confirmation; rename and open-handle restrictions apply";
type ActiveSignIn = Arc<Mutex<Option<(String, Arc<SignIn>)>>>;

struct JournalPermit(Arc<AtomicUsize>);

impl Drop for JournalPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn check_mount_owners(runtime: &RuntimeDir, mounts: &[Mounted]) -> Result<(), String> {
    let owners = cirrus_fuse::recovery_owners(runtime).map_err(|e| e.to_string())?;
    if owners.len() != mounts.len()
        || mounts.iter().any(|mount| {
            !mount.is_active().unwrap_or(false)
                || owners
                    .iter()
                    .filter(|owner| {
                        owner.path == mount.path()
                            && owner.source == mount.source()
                            && owner.instance == mount.instance()
                            && owner.space_id == mount.space_id()
                            && owner.space_name == mount.space_name()
                    })
                    .count()
                    != 1
        })
    {
        return Err("stale or ambiguous mount records require recovery or inspection".to_owned());
    }
    Ok(())
}

fn mount_statuses(runtime: &RuntimeDir, mounts: &[Mounted]) -> Result<Vec<MountInfo>, String> {
    let owners = cirrus_fuse::recovery_owners(runtime).map_err(|error| error.to_string())?;
    let mut paths = std::collections::HashSet::new();
    let mut spaces = std::collections::HashSet::new();
    let mut sources = std::collections::HashSet::new();
    for owner in &owners {
        if !paths.insert(&owner.path)
            || !spaces.insert((&owner.instance, &owner.space_id))
            || !sources.insert(&owner.source)
        {
            return Err("ambiguous mount owner records require inspection".to_owned());
        }
    }
    for mount in mounts {
        if !mount.is_active().unwrap_or(false)
            || owners
                .iter()
                .filter(|owner| {
                    owner.path == mount.path()
                        && owner.source == mount.source()
                        && owner.instance == mount.instance()
                        && owner.space_id == mount.space_id()
                        && owner.space_name == mount.space_name()
                })
                .count()
                != 1
        {
            return Err("mountpoint identity changed or cannot be verified".to_owned());
        }
    }
    let mut result = Vec::with_capacity(owners.len());
    for owner in owners {
        let active = mounts
            .iter()
            .find(|mount| mount.path() == owner.path && mount.source() == owner.source);
        let offline_read_only =
            active.map(|mount| mount.is_offline() && !mount.is_offline_writable());
        let offline_writable = active.map(Mounted::is_offline_writable);
        result.push(MountInfo {
            instance: owner.instance,
            space_id: owner.space_id,
            space_name: owner.space_name,
            path: owner.path.to_string_lossy().into_owned(),
            state: if active.is_some() {
                MountState::Mounted
            } else {
                MountState::RecoveryRequired
            },
            offline_read_only,
            offline_writable,
        });
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub(crate) enum AccountRequest {
    Connect {
        instance: String,
        ca_pem: Option<String>,
        attempt: String,
    },
    CancelConnect {
        attempt: String,
    },
    Spaces {
        instance: String,
    },
    SelectSpace {
        instance: String,
        id: String,
    },
    Directory {
        instance: String,
        path: Vec<String>,
    },
    OfflineDirectory {
        instance: String,
        space: String,
        path: Vec<String>,
    },
    Pin {
        instance: String,
        path: Vec<String>,
    },
    Unpin {
        instance: String,
        path: Vec<String>,
    },
    Pins {
        instance: String,
    },
    PinSpace {
        instance: String,
        space: String,
        path: Vec<String>,
    },
    UnpinSpace {
        instance: String,
        space: String,
        path: Vec<String>,
    },
    PinsSpace {
        instance: String,
        space: String,
    },
    CleanCacheStatus,
    StorageStatus,
    StorageLimits,
    SetStorageLimits {
        #[serde(deserialize_with = "Option::deserialize")]
        limits: Option<cirrus_account::StorageLimits>,
    },
    ReleaseStorageReservation {
        store: String,
        token: String,
    },
    EvictSpace {
        instance: String,
        space: String,
        path: Vec<String>,
    },
    RetainedPins {
        instance: String,
        offset: u32,
    },
    PinCopies {
        instance: String,
        offset: u32,
    },
    PinCopyEntries {
        instance: String,
        space: String,
        id: i64,
        offset: u32,
    },
    ExportPinCopy {
        instance: String,
        space: String,
        id: i64,
        path: Vec<String>,
        selector: String,
        destination: String,
    },
    RemovePinCopy {
        instance: String,
        space: String,
        id: i64,
    },
    RetainedStaged {
        instance: String,
        offset: u32,
    },
    ExportStaged {
        instance: String,
        id: i64,
        selector: String,
        destination: String,
    },
    RetainedFiles {
        instance: String,
        space: String,
        root: Vec<String>,
        offset: u32,
    },
    ExportRetained {
        instance: String,
        space: String,
        root: Vec<String>,
        path: Vec<String>,
        selector: String,
        destination: String,
    },
    StageFile {
        instance: String,
        path: Vec<String>,
        source: String,
    },
    StageFileSpace {
        instance: String,
        space: String,
        path: Vec<String>,
        source: String,
    },
    Journal {
        instance: String,
        space: Option<String>,
        before: Option<i64>,
    },
    Sync {
        instance: String,
    },
    SyncSpace {
        instance: String,
        space: String,
    },
    WriteTurn {
        instance: String,
        space: String,
    },
    SyncStatus {
        instance: String,
        space: String,
    },
    Acknowledge {
        instance: String,
        staged: String,
    },
    Mount {
        instance: String,
        path: String,
    },
    MountSpace {
        instance: String,
        space: String,
        path: Option<String>,
    },
    OfflineMountSpace {
        instance: String,
        space: String,
        path: String,
    },
    WritableOfflineMountSpace {
        instance: String,
        space: String,
        path: String,
    },
    Unmount,
    UnmountSpace {
        instance: String,
        space: String,
    },
    MountStatus,
    Mounts,
    RecoverMount {
        path: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountResponse {
    error: Option<String>,
    spaces: Vec<(String, String)>,
    entries: Vec<DirectoryEntry>,
    mount: Option<String>,
    journal: Option<JournalPage>,
    write_turn: Option<cirrus_account::WriteTurnOutcome>,
    sync_status: Option<cirrus_account::SyncStatus>,
}

pub(crate) enum Request {
    Status,
    Stop,
}

// Linux resolves these paths through the held descriptor, not the original path.
fn proc_fd_path(fd: impl AsFd, suffix: &str) -> io::Result<String> {
    let proc = fs::openat2(
        fs::CWD,
        "/proc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(io::Error::from)?;
    if fs::fstatfs(&proc).map_err(io::Error::from)?.f_type != fs::PROC_SUPER_MAGIC {
        return Err(io::Error::other(
            "a trusted procfs is required for local IPC",
        ));
    }
    Ok(format!(
        "/proc/self/fd/{}{}",
        fd.as_fd().as_raw_fd(),
        suffix
    ))
}

fn verify_socket(fd: impl AsFd) -> io::Result<()> {
    let metadata = fs::fstat(fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Socket
        || metadata.st_uid != process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "endpoint must be a user-owned socket with mode 0700",
        ));
    }
    Ok(())
}

fn endpoint(runtime: &RuntimeDir) -> io::Result<Option<std::os::fd::OwnedFd>> {
    match fs::openat2(
        runtime,
        SOCKET_NAME,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(fd) => {
            verify_socket(&fd)?;
            Ok(Some(fd))
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(io::Error::from(error)),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OwnerMarker {
    Pending,
    Socket(u64, u64),
}

fn verify_owner(fd: impl AsFd) -> io::Result<()> {
    let stat = fs::fstat(fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unrecognized runtime owner marker",
        ));
    }
    Ok(())
}

fn owner_marker(runtime: &RuntimeDir) -> io::Result<Option<OwnerMarker>> {
    let fd = match fs::openat2(
        runtime,
        OWNER_NAME,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io::Error::from(error)),
    };
    verify_owner(&fd)?;
    let mut content = Vec::new();
    std::fs::File::from(fd)
        .take(129)
        .read_to_end(&mut content)?;
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "unrecognized runtime owner marker",
        )
    };
    let fields = content.strip_prefix(OWNER_CONTENT).ok_or_else(invalid)?;
    let fields = std::str::from_utf8(fields).map_err(|_| invalid())?;
    let fields = fields.strip_suffix('\n').ok_or_else(invalid)?;
    let (device, inode) = fields.split_once(' ').ok_or_else(invalid)?;
    if device.len() != 20 || inode.len() != 20 {
        return Err(invalid());
    }
    let device = device.parse().map_err(|_| invalid())?;
    let inode = inode.parse().map_err(|_| invalid())?;
    Ok(Some(if (device, inode) == (0, 0) {
        OwnerMarker::Pending
    } else {
        OwnerMarker::Socket(device, inode)
    }))
}

fn create_owner_marker(runtime: &RuntimeDir) -> io::Result<()> {
    let fd = fs::openat(
        runtime,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(io::Error::from)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(&marker_bytes(None))?;
    file.sync_all()?;
    fs::linkat(&file, "", runtime, OWNER_NAME, AtFlags::EMPTY_PATH).map_err(io::Error::from)?;
    Ok(())
}

fn write_owner(runtime: &RuntimeDir, identity: Option<(u64, u64)>) -> io::Result<()> {
    let fd = fs::openat2(
        runtime,
        OWNER_NAME,
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(io::Error::from)?;
    verify_owner(&fd)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(&marker_bytes(identity))?;
    file.sync_all()
}

fn marker_bytes(identity: Option<(u64, u64)>) -> Vec<u8> {
    let (device, inode) = identity.unwrap_or((0, 0));
    let mut bytes = OWNER_CONTENT.to_vec();
    bytes.extend_from_slice(format!("{device:020} {inode:020}\n").as_bytes());
    bytes
}

fn remove_endpoint(runtime: &RuntimeDir, socket: impl AsFd) -> io::Result<()> {
    runtime.revalidate()?;
    let original = fs::fstat(socket).map_err(io::Error::from)?;
    let current = endpoint(runtime)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "runtime socket disappeared"))?;
    let observed = fs::fstat(&current).map_err(io::Error::from)?;
    if (original.st_dev, original.st_ino) != (observed.st_dev, observed.st_ino) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime socket identity changed",
        ));
    }
    fs::unlinkat(runtime, SOCKET_NAME, AtFlags::empty()).map_err(io::Error::from)
}

fn recover_endpoint(runtime: &RuntimeDir, socket: impl AsFd) -> io::Result<()> {
    let address =
        SocketAddrUnix::new(proc_fd_path(&socket, "")?.as_str()).map_err(io::Error::from)?;
    let probe = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(io::Error::from)?;
    match net::connect(&probe, &address) {
        Err(rustix::io::Errno::CONNREFUSED) => remove_endpoint(runtime, socket),
        Ok(()) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "runtime socket is active",
        )),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn verify_peer(stream: &UnixStream) -> io::Result<()> {
    let peer = sockopt::socket_peercred(stream).map_err(io::Error::from)?;
    if peer.uid != process::geteuid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket peer UID does not match",
        ));
    }
    Ok(())
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "local request timed out"))
}

fn read_line(stream: &mut UnixStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(MAX_LINE);
    while line.len() < MAX_LINE {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete local message",
                ));
            }
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    return Ok(line);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "local message exceeds limit",
    ))
}

fn write_line(stream: &mut UnixStream, mut data: &[u8], deadline: Instant) -> io::Result<()> {
    while !data.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(data) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "local message was not sent",
                ));
            }
            Ok(n) => data = &data[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn serve(runtime: &RuntimeDir, automatic: bool) -> io::Result<()> {
    runtime.revalidate()?;
    // An unlistening abstract socket is an atomic, process-lifetime guard. It
    // cannot be unlinked or replaced through a pathname while the daemon runs.
    let identity = fs::fstat(runtime).map_err(io::Error::from)?;
    let name = format!(
        "cirrus-drive-lock:{}:{}:{}",
        process::geteuid().as_raw(),
        identity.st_dev,
        identity.st_ino
    );
    let address = SocketAddrUnix::new_abstract_name(name.as_bytes()).map_err(io::Error::from)?;
    let guard = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    net::bind(&guard, &address).map_err(|error| {
        let error = io::Error::from(error);
        io::Error::new(
            error.kind(),
            format!("cannot acquire Cirrus instance guard: {error}"),
        )
    })?;
    if owner_marker(runtime)?.is_none() {
        match create_owner_marker(runtime) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error),
        }
    }
    let marker_lock = fs::openat2(
        runtime,
        OWNER_NAME,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(io::Error::from)?;
    verify_owner(&marker_lock)?;
    fs::flock(&marker_lock, fs::FlockOperation::NonBlockingLockExclusive).map_err(|_| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            "another Cirrus daemon owns this runtime",
        )
    })?;
    let owned = owner_marker(runtime)?;
    if let Some(existing) = endpoint(runtime)? {
        let identity = fs::fstat(&existing).map_err(io::Error::from)?;
        if owned != Some(OwnerMarker::Socket(identity.st_dev, identity.st_ino)) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "runtime socket identity is not recorded by Cirrus",
            ));
        }
        recover_endpoint(runtime, existing)?;
    }
    if owned.is_none() {
        create_owner_marker(runtime)?;
    } else {
        write_owner(runtime, None)?;
    }
    let address = SocketAddrUnix::new(proc_fd_path(runtime, "/cirrus-drive.sock")?.as_str())
        .map_err(io::Error::from)?;
    let fd = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    net::bind(&fd, &address).map_err(|error| {
        let error = io::Error::from(error);
        io::Error::new(error.kind(), format!("cannot bind endpoint: {error}"))
    })?;
    let socket = fs::openat2(
        runtime,
        SOCKET_NAME,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(io::Error::from)?;
    verify_socket(&socket)?;
    let identity = fs::fstat(&socket).map_err(io::Error::from)?;
    write_owner(runtime, Some((identity.st_dev, identity.st_ino)))?;
    net::listen(&fd, 8).map_err(io::Error::from)?;
    let listener = UnixListener::from(fd);
    let busy = Arc::new(AtomicBool::new(false));
    let accounts = Arc::new(Accounts::new(runtime.try_clone()?));
    let mount: Arc<Mutex<Vec<Mounted>>> = Arc::new(Mutex::new(Vec::new()));
    let mut scheduler = crate::scheduler::Scheduler::start(
        Arc::clone(&accounts),
        Arc::clone(&busy),
        Arc::clone(&mount),
        automatic,
    )?;
    let journal_readers = Arc::new(AtomicUsize::new(0));
    let account_replies = Arc::new(AtomicUsize::new(0));
    let storage_readers = Arc::new(AtomicUsize::new(0));
    let sign_in: ActiveSignIn = Arc::new(Mutex::new(None));
    'serve: loop {
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        runtime.revalidate()?;
        if verify_peer(&stream).is_err() {
            continue;
        }
        let deadline = Instant::now() + TIMEOUT;
        let line = match read_line(&mut stream, deadline) {
            Ok(line) => line,
            Err(_) => continue,
        };
        if let Some(json) = line.strip_prefix(b"CIRRUS/2 ") {
            let request = serde_json::from_slice::<AccountRequest>(json);
            if let Ok(request) = request {
                if let AccountRequest::SyncStatus { instance, space } = &request {
                    if journal_readers
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            (count < 4).then_some(count + 1)
                        })
                        .is_err()
                    {
                        let _ = write_account_response(
                            &mut stream,
                            AccountResponse {
                                error: Some("local status is busy; retry".into()),
                                spaces: Vec::new(),
                                entries: Vec::new(),
                                mount: None,
                                journal: None,
                                write_turn: None,
                                sync_status: None,
                            },
                        );
                        continue;
                    }
                    let permit = JournalPermit(Arc::clone(&journal_readers));
                    let accounts = Arc::clone(&accounts);
                    let instance = instance.clone();
                    let space = space.clone();
                    let ownership = (marker_lock.try_clone()?, guard.try_clone()?);
                    let worker_enabled = scheduler.enabled();
                    thread::spawn(move || {
                        let _permit = permit;
                        let _ownership = ownership;
                        let (error, sync_status) = match accounts.sync_status(&instance, &space) {
                            Ok(mut status) => {
                                status.worker_enabled_here = Some(worker_enabled);
                                (None, Some(status))
                            }
                            Err(error) => (Some(error.to_string()), None),
                        };
                        let _ = write_account_response(
                            &mut stream,
                            AccountResponse {
                                error,
                                spaces: Vec::new(),
                                entries: Vec::new(),
                                mount: None,
                                journal: None,
                                write_turn: None,
                                sync_status,
                            },
                        );
                    });
                    continue;
                }
                if matches!(
                    request,
                    AccountRequest::CleanCacheStatus
                        | AccountRequest::StorageStatus
                        | AccountRequest::StorageLimits
                        | AccountRequest::SetStorageLimits { .. }
                        | AccountRequest::ReleaseStorageReservation { .. }
                ) {
                    let storage = !matches!(request, AccountRequest::CleanCacheStatus);
                    let limits = matches!(
                        request,
                        AccountRequest::StorageLimits | AccountRequest::SetStorageLimits { .. }
                    );
                    let release =
                        matches!(request, AccountRequest::ReleaseStorageReservation { .. });
                    // History/payload SUM queries can be slow. One separate
                    // storage reader must not exhaust ordinary status slots.
                    let readers = if storage {
                        &storage_readers
                    } else {
                        &journal_readers
                    };
                    if readers
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            (count < if storage { 1 } else { 4 }).then_some(count + 1)
                        })
                        .is_err()
                    {
                        let _ = write_account_response(
                            &mut stream,
                            AccountResponse {
                                error: Some("local status is busy; retry".to_owned()),
                                spaces: Vec::new(),
                                entries: Vec::new(),
                                mount: None,
                                journal: None,
                                write_turn: None,
                                sync_status: None,
                            },
                        );
                        continue;
                    }
                    let permit = JournalPermit(Arc::clone(readers));
                    let accounts = Arc::clone(&accounts);
                    let ownership = (marker_lock.try_clone()?, guard.try_clone()?);
                    let _ = thread::Builder::new()
                        .name(
                            if storage {
                                "cirrus-storage-status"
                            } else {
                                "cirrus-cache-status"
                            }
                            .into(),
                        )
                        .spawn(move || {
                            let _permit = permit;
                            let _ownership = ownership;
                            let result =
                                if let AccountRequest::SetStorageLimits { limits } = request {
                                    accounts
                                        .configure_storage_limits(limits)
                                        .map_err(|error| error.to_string())
                                        .and_then(|view| {
                                            serde_json::to_string(&view)
                                                .map_err(|error| error.to_string())
                                        })
                                } else if let AccountRequest::ReleaseStorageReservation {
                                    store,
                                    token,
                                } = request
                                {
                                    accounts
                                        .release_storage_reservation(&store, &token)
                                        .map(|()| "{}".to_owned())
                                        .map_err(|error| error.to_string())
                                } else if matches!(request, AccountRequest::StorageLimits) {
                                    accounts
                                        .storage_limits()
                                        .map_err(|error| error.to_string())
                                        .and_then(|view| {
                                            serde_json::to_string(&view)
                                                .map_err(|error| error.to_string())
                                        })
                                } else if storage {
                                    accounts
                                        .storage_status()
                                        .map_err(|error| error.to_string())
                                        .and_then(|status| {
                                            serde_json::to_string(&status)
                                                .map_err(|error| error.to_string())
                                        })
                                } else {
                                    accounts
                                        .clean_cache_status()
                                        .map_err(|error| error.to_string())
                                        .and_then(|status| {
                                            serde_json::to_string(&status)
                                                .map_err(|error| error.to_string())
                                        })
                                };
                            let (error, spaces) = match result {
                                Ok(status) => (
                                    None,
                                    vec![(
                                        if release {
                                            "storage-reservation-released"
                                        } else if limits {
                                            "storage-limits"
                                        } else if storage {
                                            "storage"
                                        } else {
                                            "clean-cache"
                                        }
                                        .to_owned(),
                                        status,
                                    )],
                                ),
                                Err(error) => (Some(error), Vec::new()),
                            };
                            let _ = write_account_response(
                                &mut stream,
                                AccountResponse {
                                    error,
                                    spaces,
                                    entries: Vec::new(),
                                    mount: None,
                                    journal: None,
                                    write_turn: None,
                                    sync_status: None,
                                },
                            );
                        });
                    continue;
                }
                if let AccountRequest::Journal {
                    instance,
                    space,
                    before,
                } = &request
                {
                    if journal_readers
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            (count < 4).then_some(count + 1)
                        })
                        .is_err()
                    {
                        let _ = write_account_response(
                            &mut stream,
                            AccountResponse {
                                error: Some("journal is busy; retry".to_owned()),
                                spaces: Vec::new(),
                                entries: Vec::new(),
                                mount: None,
                                journal: None,
                                write_turn: None,
                                sync_status: None,
                            },
                        );
                        continue;
                    }
                    let permit = JournalPermit(Arc::clone(&journal_readers));
                    let accounts = Arc::clone(&accounts);
                    let instance = instance.clone();
                    let space = space.clone();
                    let before = *before;
                    let ownership = (marker_lock.try_clone()?, guard.try_clone()?);
                    let _ = thread::Builder::new()
                        .name("cirrus-journal".into())
                        .spawn(move || {
                            let _permit = permit;
                            let _ownership = ownership;
                            let (error, journal) =
                                match accounts.journal(&instance, space.as_deref(), before) {
                                    Ok(page) => (None, Some(page)),
                                    Err(error) => (Some(error.to_string()), None),
                                };
                            let _ = write_account_response(
                                &mut stream,
                                AccountResponse {
                                    error,
                                    spaces: Vec::new(),
                                    entries: Vec::new(),
                                    mount: None,
                                    journal,
                                    write_turn: None,
                                    sync_status: None,
                                },
                            );
                        });
                    continue;
                }
                if let AccountRequest::CancelConnect { attempt } = &request {
                    let result = sign_in
                        .lock()
                        .map_err(|_| "sign-in state unavailable".to_owned())
                        .and_then(|active| {
                            let (_, current) = active
                                .as_ref()
                                .filter(|(id, _)| id == attempt)
                                .ok_or_else(|| "sign-in is no longer active".to_owned())?;
                            current.cancel().map_err(|e| e.to_string())
                        });
                    let response = AccountResponse {
                        error: result.err(),
                        spaces: Vec::new(),
                        entries: Vec::new(),
                        mount: None,
                        journal: None,
                        write_turn: None,
                        sync_status: None,
                    };
                    let _ = write_account_response(&mut stream, response);
                    continue;
                }
                if matches!(request, AccountRequest::Mounts) {
                    let result = mount
                        .try_lock()
                        .map_err(|_| "mount operation is in progress".to_owned())
                        .and_then(|mounts| {
                            mount_statuses(runtime, &mounts)?
                                .into_iter()
                                .map(|info| {
                                    serde_json::to_string(&info)
                                        .map(|value| (info.space_id.clone(), value))
                                        .map_err(|error| error.to_string())
                                })
                                .collect::<Result<Vec<_>, _>>()
                        });
                    let (error, spaces) = match result {
                        Ok(spaces) => (None, spaces),
                        Err(error) => (Some(error), Vec::new()),
                    };
                    let _ = write_account_response(
                        &mut stream,
                        AccountResponse {
                            error,
                            spaces,
                            entries: Vec::new(),
                            mount: None,
                            journal: None,
                            write_turn: None,
                            sync_status: None,
                        },
                    );
                    continue;
                }
                if matches!(request, AccountRequest::MountStatus) {
                    let response = match mount.try_lock() {
                        Ok(mount) if mount.iter().any(|m| !m.is_active().unwrap_or(false)) => {
                            AccountResponse {
                                error: Some(
                                    "mountpoint identity changed or cannot be verified".into(),
                                ),
                                spaces: Vec::new(),
                                entries: Vec::new(),
                                mount: None,
                                journal: None,
                                write_turn: None,
                                sync_status: None,
                            }
                        }
                        Ok(mount)
                            if mount.is_empty()
                                && cirrus_fuse::recovery_pending(runtime).unwrap_or(true) =>
                        {
                            AccountResponse {
                                error: Some(
                                    "stale mount record requires recovery or inspection".into(),
                                ),
                                spaces: Vec::new(),
                                entries: Vec::new(),
                                mount: None,
                                journal: None,
                                write_turn: None,
                                sync_status: None,
                            }
                        }
                        Ok(mount)
                            if !mount.is_empty()
                                && check_mount_owners(runtime, &mount).is_err() =>
                        {
                            AccountResponse {
                                error: Some("stale or ambiguous mount records require recovery or inspection".into()),
                                spaces: Vec::new(),
                                entries: Vec::new(),
                                mount: None,
                                journal: None,
                                write_turn: None,
                                sync_status: None,
                            }
                        }
                        Ok(mount) if mount.len() > 1 => AccountResponse {
                            error: Some(
                                "multiple Spaces are mounted; select a Space to unmount".into(),
                            ),
                            spaces: Vec::new(),
                            entries: Vec::new(),
                            mount: None,
                            journal: None,
                            write_turn: None,
                            sync_status: None,
                        },
                        Ok(mount) => AccountResponse {
                            error: None,
                            spaces: Vec::new(),
                            entries: Vec::new(),
                            mount: mount
                                .first()
                                .map(|m| m.path().to_string_lossy().into_owned()),
                            journal: None,
                            write_turn: None,
                            sync_status: None,
                        },
                        Err(_) => AccountResponse {
                            error: Some("mount operation is in progress".into()),
                            spaces: Vec::new(),
                            entries: Vec::new(),
                            mount: None,
                            journal: None,
                            write_turn: None,
                            sync_status: None,
                        },
                    };
                    let _ = write_account_response(&mut stream, response);
                    continue;
                }
                let mut admission = match scheduler.foreground() {
                    Ok(admission) => admission,
                    Err(error) => {
                        let response = AccountResponse {
                            error: Some(error.to_string()),
                            spaces: Vec::new(),
                            entries: Vec::new(),
                            mount: None,
                            journal: None,
                            write_turn: None,
                            sync_status: None,
                        };
                        let _ = write_account_response(&mut stream, response);
                        continue;
                    }
                };
                #[cfg(feature = "fault-injection")]
                if std::env::var_os("CIRRUS_TEST_PRIORITY_TRACE").is_some() {
                    eprintln!("cirrus lab IPC foreground admitted");
                }
                let worker_lock = marker_lock.try_clone()?;
                let worker_guard = guard.try_clone()?;
                let worker_runtime = runtime.try_clone()?;
                let accounts = Arc::clone(&accounts);
                let mount = Arc::clone(&mount);
                let active_sign_in = Arc::clone(&sign_in);
                let attempt = if let AccountRequest::Connect { attempt, .. } = &request {
                    if attempt.len() != 32 || !attempt.bytes().all(|b| b.is_ascii_hexdigit()) {
                        drop(admission);
                        let response = AccountResponse {
                            error: Some("invalid sign-in attempt".into()),
                            spaces: Vec::new(),
                            entries: Vec::new(),
                            mount: None,
                            journal: None,
                            write_turn: None,
                            sync_status: None,
                        };
                        let _ = write_account_response(&mut stream, response);
                        continue;
                    }
                    let control = Arc::new(SignIn::default());
                    *sign_in
                        .lock()
                        .map_err(|_| io::Error::other("sign-in state unavailable"))? =
                        Some((attempt.clone(), Arc::clone(&control)));
                    Some(control)
                } else {
                    None
                };
                account_replies.fetch_add(1, Ordering::AcqRel);
                let reply_permit = JournalPermit(Arc::clone(&account_replies));
                thread::spawn(move || {
                    let _reply = reply_permit;
                    let _ownership = (worker_lock, worker_guard);
                    // Close the client before the reply permit reports
                    // completion, including the admission-cancelled return.
                    // Closure captures otherwise outlive these local guards.
                    let mut stream = stream;
                    // Keep the scoped foreground permit (so another account
                    // command cannot race mount publication), but local-only
                    // writable mount/unmount need not wait for background auth.
                    let local_offline =
                        matches!(&request, AccountRequest::WritableOfflineMountSpace { .. })
                            || mount.lock().is_ok_and(|mounts| match &request {
                                AccountRequest::Unmount => {
                                    mounts.len() == 1 && mounts[0].is_offline_writable()
                                }
                                AccountRequest::UnmountSpace { instance, space } => {
                                    Accounts::canonical_instance(instance).is_ok_and(|canonical| {
                                        mounts.iter().any(|mount| {
                                            mount.instance() == canonical
                                                && mount.space_id() == space
                                                && mount.is_offline_writable()
                                        })
                                    })
                                }
                                _ => false,
                            });
                    if let Err(error) = if local_offline {
                        Ok(())
                    } else {
                        admission.wait()
                    } {
                        let _ = write_account_response(
                            &mut stream,
                            AccountResponse {
                                error: Some(error.to_string()),
                                spaces: Vec::new(),
                                entries: Vec::new(),
                                mount: None,
                                journal: None,
                                write_turn: None,
                                sync_status: None,
                            },
                        );
                        return;
                    }
                    // Operations from the control client can change the journal or
                    // credentials without passing through the mounted filesystem.
                    accounts.invalidate_mount_metadata();
                    let mounted = mount.lock().ok().is_some_and(|m| !m.is_empty());
                    let mut write_turn = None;
                    let offline_writable =
                        matches!(&request, AccountRequest::WritableOfflineMountSpace { .. });
                    let result = match request {
                        AccountRequest::Connect { .. } if mounted => {
                            Err("unmount all Spaces before changing account".to_owned())
                        }
                        AccountRequest::Connect {
                            instance, ca_pem, ..
                        } => accounts
                            .connect(
                                &instance,
                                ca_pem.as_deref().map(str::as_bytes),
                                &PortalBrowser::default(),
                                attempt.as_ref().expect("connect has a sign-in fence"),
                            )
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::Spaces { instance } => accounts
                            .spaces(&instance)
                            .map(|spaces| {
                                spaces
                                    .into_iter()
                                    .map(|space| (space.id().to_owned(), space.name().to_owned()))
                                    .collect::<Vec<_>>()
                            })
                            .map(|spaces| (spaces, Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::SelectSpace { instance, id } => accounts
                            .select_space(&instance, &id)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::Directory { .. }
                        | AccountRequest::OfflineDirectory { .. } => (match &request {
                            AccountRequest::Directory { instance, path } => {
                                accounts.directory(instance, path)
                            }
                            AccountRequest::OfflineDirectory {
                                instance,
                                space,
                                path,
                            } => accounts.offline_directory(instance, space, path),
                            _ => unreachable!(),
                        })
                        .map(|entries| {
                            (
                                Vec::new(),
                                entries
                                    .into_iter()
                                    .map(|entry| DirectoryEntry {
                                        name: entry.name().to_owned(),
                                        directory: entry.is_directory(),
                                        size: entry.size(),
                                    })
                                    .collect(),
                            )
                        })
                        .map_err(|e| e.to_string()),
                        AccountRequest::Pin { instance, path } => accounts
                            .pin(&instance, &path)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::Unpin { instance, path } => accounts
                            .unpin(&instance, &path)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::Pins { instance } => accounts
                            .pins(&instance)
                            .map(|pins| (pins, Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::PinSpace {
                            instance,
                            space,
                            path,
                        } => accounts
                            .pin_space(&instance, &space, &path)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::UnpinSpace {
                            instance,
                            space,
                            path,
                        } => accounts
                            .unpin_space(&instance, &space, &path)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::PinsSpace { instance, space } => accounts
                            .pins_space(&instance, &space)
                            .map(|pins| (pins, Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::EvictSpace {
                            instance,
                            space,
                            path,
                        } => accounts
                            .evict_space(&instance, &space, &path)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::RetainedPins { instance, offset } => accounts
                            .retained_pins(&instance, offset)
                            .map(|v| (v, Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::RetainedStaged { instance, offset } => accounts
                            .retained_staged(&instance, offset)
                            .map(|v| (v, Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::ExportStaged {
                            instance,
                            id,
                            selector,
                            destination,
                        } => accounts
                            .export_staged(
                                &instance,
                                id,
                                &selector,
                                std::path::Path::new(&destination),
                            )
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::PinCopies { instance, offset } => accounts
                            .pin_copies(&instance, offset)
                            .map(|v| (v, Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::PinCopyEntries {
                            instance,
                            space,
                            id,
                            offset,
                        } => accounts
                            .pin_copy_entries(&instance, &space, id, offset)
                            .map(|v| (v, Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::ExportPinCopy {
                            instance,
                            space,
                            id,
                            path,
                            selector,
                            destination,
                        } => accounts
                            .export_pin_copy(
                                &instance,
                                &space,
                                id,
                                &path,
                                &selector,
                                std::path::Path::new(&destination),
                            )
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::RemovePinCopy {
                            instance,
                            space,
                            id,
                        } => accounts
                            .remove_pin_copy(&instance, &space, id)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::RetainedFiles {
                            instance,
                            space,
                            root,
                            offset,
                        } => accounts
                            .retained_files(&instance, &space, &root, offset)
                            .map(|v| (v, Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::ExportRetained {
                            instance,
                            space,
                            root,
                            path,
                            selector,
                            destination,
                        } => accounts
                            .export_retained(
                                &instance,
                                &space,
                                (&root, &path),
                                &selector,
                                std::path::Path::new(&destination),
                            )
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::StageFile {
                            instance,
                            path,
                            source,
                        } => accounts
                            .stage_file(&instance, &path, std::path::Path::new(&source))
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::StageFileSpace {
                            instance,
                            space,
                            path,
                            source,
                        } => accounts
                            .stage_file_space(
                                &instance,
                                &space,
                                &path,
                                std::path::Path::new(&source),
                            )
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::Journal { .. } => {
                            unreachable!("journal is handled before spawning")
                        }
                        AccountRequest::Sync { instance } => accounts
                            .sync_pending(&instance)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::SyncSpace { instance, space } => accounts
                            .sync_space(&instance, &space)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::WriteTurn { instance, space } => accounts
                            .write_turn(&instance, &space)
                            .map(|outcome| {
                                write_turn = Some(outcome);
                                (Vec::new(), Vec::new())
                            })
                            .map_err(|e| e.to_string()),
                        AccountRequest::Acknowledge { instance, staged } => accounts
                            .acknowledge(&instance, &staged)
                            .map(|()| (Vec::new(), Vec::new()))
                            .map_err(|e| e.to_string()),
                        AccountRequest::Mount { instance, path } => (|| {
                            let mut slot = mount
                                .lock()
                                .map_err(|_| "mount state is unavailable".to_owned())?;
                            check_mount_owners(&worker_runtime, &slot)?;
                            if !slot.is_empty() {
                                return Err(
                                    "use an explicit Space ID when another Space is mounted"
                                        .to_owned(),
                                );
                            }
                            let mounted = Mounted::start(
                                Arc::clone(&accounts),
                                instance,
                                std::path::Path::new(&path),
                                worker_runtime,
                            )
                            .map_err(|e| e.to_string())?;
                            slot.push(mounted);
                            Ok((Vec::new(), Vec::new()))
                        })(),
                        AccountRequest::OfflineMountSpace {
                            instance,
                            space,
                            path,
                        }
                        | AccountRequest::WritableOfflineMountSpace {
                            instance,
                            space,
                            path,
                        } => (|| {
                            if automatic && !offline_writable {
                                return Err("offline mounts require restarting the service with --no-auto-sync".to_owned());
                            }
                            let mut slot = mount
                                .lock()
                                .map_err(|_| "mount state is unavailable".to_owned())?;
                            check_mount_owners(&worker_runtime, &slot)?;
                            let canonical = Accounts::canonical_instance(&instance)
                                .map_err(|e| e.to_string())?;
                            let path_ref = std::path::Path::new(&path);
                            if slot.len() >= 64
                                || slot.iter().any(|mount| {
                                    (mount.instance() == canonical && mount.space_id() == space)
                                        || path_ref.starts_with(mount.path())
                                        || mount.path().starts_with(path_ref)
                                })
                            {
                                return Err("Space already mounted, mountpoints overlap or mount limit reached".to_owned());
                            }
                            let start = if offline_writable {
                                Mounted::start_writable_offline_space
                            } else {
                                Mounted::start_offline_space
                            };
                            let mounted = start(
                                Arc::clone(&accounts),
                                &canonical,
                                &space,
                                path_ref,
                                worker_runtime,
                            )
                            .map_err(|e| e.to_string())?;
                            let actual_path = mounted.path().to_string_lossy().into_owned();
                            slot.push(mounted);
                            Ok((vec![(space, actual_path)], Vec::new()))
                        })(),
                        AccountRequest::MountSpace {
                            instance,
                            space,
                            path,
                        } => (|| {
                            let mut slot = mount
                                .lock()
                                .map_err(|_| "mount state is unavailable".to_owned())?;
                            check_mount_owners(&worker_runtime, &slot)?;
                            let canonical = Accounts::canonical_instance(&instance)
                                .map_err(|e| e.to_string())?;
                            if slot.iter().any(|mount| {
                                mount.instance() == canonical && mount.space_id() == space
                            }) {
                                return Err("this Space is already mounted".to_owned());
                            }
                            if slot.len() >= 64 {
                                return Err("mount limit reached".to_owned());
                            }
                            if let Some(path) = path.as_deref() {
                                let path_ref = std::path::Path::new(path);
                                if slot.iter().any(|mount| {
                                    path_ref.starts_with(mount.path())
                                        || mount.path().starts_with(path_ref)
                                }) {
                                    return Err("mountpoints must not overlap".to_owned());
                                }
                            } else {
                                let home = std::env::var_os("HOME")
                                    .ok_or_else(|| "HOME is unavailable".to_owned())?;
                                let home =
                                    std::fs::canonicalize(home).map_err(|e| e.to_string())?;
                                if slot.iter().any(|mount| home.starts_with(mount.path())) {
                                    return Err(
                                        "home directory is inside an existing mount".to_owned()
                                    );
                                }
                            }
                            let mounted = Mounted::start_space(
                                Arc::clone(&accounts),
                                instance,
                                &space,
                                path.as_deref().map(std::path::Path::new),
                                worker_runtime,
                            )
                            .map_err(|e| e.to_string())?;
                            let actual_path = mounted.path().to_string_lossy().into_owned();
                            slot.push(mounted);
                            Ok((vec![(space, actual_path)], Vec::new()))
                        })(),
                        AccountRequest::Unmount => (|| {
                            if accounts.has_pending_credentials().unwrap_or(true) {
                                return Err(
                                    "account credentials await keyring persistence".to_owned()
                                );
                            }
                            let mut slot = mount
                                .lock()
                                .map_err(|_| "mount state is unavailable".to_owned())?;
                            if slot.len() != 1 {
                                return Err(if slot.is_empty() {
                                    "no Space is mounted"
                                } else {
                                    "multiple Spaces are mounted; select a Space to unmount"
                                }
                                .to_owned());
                            }
                            slot[0].unmount().map_err(|e| e.to_string())?;
                            slot.remove(0);
                            if accounts.has_pending_credentials().unwrap_or(true) {
                                return Err("Space unmounted, but account credentials await keyring persistence".to_owned());
                            }
                            Ok((Vec::new(), Vec::new()))
                        })(),
                        AccountRequest::UnmountSpace { instance, space } => (|| {
                            if accounts.has_pending_credentials().unwrap_or(true) {
                                return Err(
                                    "account credentials await keyring persistence".to_owned()
                                );
                            }
                            let canonical = Accounts::canonical_instance(&instance)
                                .map_err(|e| e.to_string())?;
                            let mut slot = mount
                                .lock()
                                .map_err(|_| "mount state is unavailable".to_owned())?;
                            let index = slot
                                .iter()
                                .position(|m| m.instance() == canonical && m.space_id() == space)
                                .ok_or_else(|| "Space is not mounted".to_owned())?;
                            slot[index].unmount().map_err(|e| e.to_string())?;
                            slot.remove(index);
                            if accounts.has_pending_credentials().unwrap_or(true) {
                                return Err("Space unmounted, but account credentials await keyring persistence".to_owned());
                            }
                            Ok((Vec::new(), Vec::new()))
                        })(
                        ),
                        AccountRequest::RecoverMount { path } => (|| {
                            let slot = mount
                                .lock()
                                .map_err(|_| "mount state is unavailable".to_owned())?;
                            if slot
                                .iter()
                                .any(|mount| mount.path() == std::path::Path::new(&path))
                            {
                                return Err("unmount the active Space first".to_owned());
                            }
                            cirrus_fuse::recover(&worker_runtime, std::path::Path::new(&path))
                                .map_err(|e| e.to_string())?;
                            Ok((Vec::new(), Vec::new()))
                        })(),
                        AccountRequest::CleanCacheStatus
                        | AccountRequest::StorageStatus
                        | AccountRequest::StorageLimits
                        | AccountRequest::SetStorageLimits { .. }
                        | AccountRequest::ReleaseStorageReservation { .. }
                        | AccountRequest::SyncStatus { .. }
                        | AccountRequest::MountStatus
                        | AccountRequest::Mounts
                        | AccountRequest::CancelConnect { .. } => {
                            unreachable!("status is handled before spawning")
                        }
                    };
                    accounts.invalidate_mount_metadata();
                    let response = match result {
                        Ok((spaces, entries)) => AccountResponse {
                            error: None,
                            spaces,
                            entries,
                            mount: None,
                            journal: None,
                            write_turn,
                            sync_status: None,
                        },
                        Err(error) => AccountResponse {
                            error: Some(error.to_string()),
                            spaces: Vec::new(),
                            entries: Vec::new(),
                            mount: None,
                            journal: None,
                            write_turn: None,
                            sync_status: None,
                        },
                    };
                    if attempt.is_some()
                        && let Ok(mut active) = active_sign_in.lock()
                    {
                        *active = None;
                    }
                    // Release account admission before replying as before, but
                    // keep the reply counted until its bounded write finishes.
                    drop(admission);
                    let _ = write_account_response(&mut stream, response);
                });
                continue;
            }
        }
        let (response, stop) = match line.as_slice() {
            STATUS_REQUEST => (STATUS_RESPONSE, false),
            STOP_REQUEST => (STOP_RESPONSE, true),
            _ => (ERROR_RESPONSE, false),
        };
        if stop {
            scheduler.pause();
            accounts.cancel();
            #[cfg(feature = "fault-injection")]
            if let Some(marker) = std::env::var_os("CIRRUS_TEST_CANCEL_VERIFY_MARKER") {
                let _ = std::fs::write(marker, b"cancelled");
            }
            let shutdown_deadline = Instant::now() + Duration::from_secs(30);
            while (!scheduler.quiescent() || account_replies.load(Ordering::Acquire) != 0)
                && Instant::now() < shutdown_deadline
            {
                thread::sleep(Duration::from_millis(20));
            }
            if !scheduler.quiescent() || account_replies.load(Ordering::Acquire) != 0 {
                let _ = write_line(&mut stream, STOP_BUSY_RESPONSE, Instant::now() + TIMEOUT);
                continue;
            }
            if accounts.has_pending_credentials().unwrap_or(true) {
                scheduler.resume();
                let _ = write_line(&mut stream, STOP_PENDING_RESPONSE, Instant::now() + TIMEOUT);
                continue;
            }
            {
                let mut slot = mount
                    .lock()
                    .map_err(|_| io::Error::other("mount state is unavailable"))?;
                while !slot.is_empty() {
                    if let Err(error) = slot[0].unmount() {
                        scheduler.resume();
                        let message = format!("CIRRUS/2 ERROR cannot unmount Space: {error}\n");
                        let _ =
                            write_line(&mut stream, message.as_bytes(), Instant::now() + TIMEOUT);
                        continue 'serve;
                    }
                    slot.remove(0);
                }
            }
            // A FUSE request can finish a token refresh during unmount. Check
            // again after joining the worker, before discarding account state.
            if accounts.has_pending_credentials().unwrap_or(true) {
                scheduler.resume();
                let _ = write_line(&mut stream, STOP_PENDING_RESPONSE, Instant::now() + TIMEOUT);
                continue;
            }
            scheduler.join()?;
            remove_endpoint(runtime, &socket)?;
            write_owner(runtime, None)?;
            drop(listener);
            drop(guard);
            write_line(&mut stream, response, Instant::now() + TIMEOUT)?;
            return Ok(());
        }
        let _ = write_line(&mut stream, response, deadline);
    }
}

pub(crate) fn request(runtime: &RuntimeDir, request: Request) -> io::Result<&'static str> {
    let mut stream = connect(runtime)?;
    let deadline = Instant::now()
        + if matches!(request, Request::Stop) {
            Duration::from_secs(35)
        } else {
            TIMEOUT
        };
    let (message, expected, text) = match request {
        Request::Status => (STATUS_REQUEST, STATUS_RESPONSE, STATUS_TEXT),
        Request::Stop => (STOP_REQUEST, STOP_RESPONSE, "stopping"),
    };
    write_line(&mut stream, message, deadline)?;
    let reply = read_line(&mut stream, deadline)?;
    if let Some(error) = reply.strip_prefix(b"CIRRUS/2 ERROR ") {
        return Err(io::Error::other(
            String::from_utf8_lossy(error).trim().to_owned(),
        ));
    }
    if reply != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or incompatible daemon response",
        ));
    }
    Ok(text)
}

fn connect(runtime: &RuntimeDir) -> io::Result<UnixStream> {
    runtime.revalidate()?;
    let socket = fs::openat2(
        runtime,
        SOCKET_NAME,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(io::Error::from)?;
    verify_socket(&socket)?;
    let address =
        SocketAddrUnix::new(proc_fd_path(&socket, "")?.as_str()).map_err(io::Error::from)?;
    let fd = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(io::Error::from)?;
    // A full backlog or an in-progress connection fails immediately rather than blocking.
    net::connect(&fd, &address).map_err(io::Error::from)?;
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    verify_peer(&stream)?;
    Ok(stream)
}

fn write_account_response(stream: &mut UnixStream, response: AccountResponse) -> io::Result<()> {
    let mut bytes = b"CIRRUS/2 ".to_vec();
    serde_json::to_writer(&mut bytes, &response)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LINE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local response exceeds limit",
        ));
    }
    write_line(stream, &bytes, Instant::now() + TIMEOUT)
}

pub(crate) fn account_request(
    runtime: &RuntimeDir,
    request: AccountRequest,
) -> io::Result<Vec<(String, String)>> {
    send_account_request(runtime, request).map(|response| response.spaces)
}

pub(crate) fn write_turn_request(
    runtime: &RuntimeDir,
    instance: &str,
    space: &str,
) -> io::Result<cirrus_account::WriteTurnOutcome> {
    send_account_request(
        runtime,
        AccountRequest::WriteTurn {
            instance: instance.to_owned(),
            space: space.to_owned(),
        },
    )?
    .write_turn
    .ok_or_else(|| io::Error::other("missing write turn outcome"))
}

pub(crate) fn sync_status_request(
    runtime: &RuntimeDir,
    instance: &str,
    space: &str,
) -> io::Result<cirrus_account::SyncStatus> {
    send_account_request(
        runtime,
        AccountRequest::SyncStatus {
            instance: instance.to_owned(),
            space: space.to_owned(),
        },
    )?
    .sync_status
    .ok_or_else(|| io::Error::other("missing Space sync status"))
}

pub(crate) fn journal_request(
    runtime: &RuntimeDir,
    instance: &str,
    space: Option<&str>,
    before: Option<i64>,
) -> io::Result<JournalPage> {
    send_account_request(
        runtime,
        AccountRequest::Journal {
            instance: instance.to_owned(),
            space: space.map(str::to_owned),
            before,
        },
    )?
    .journal
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing journal page"))
}

pub(crate) fn cancel_connect(runtime: &RuntimeDir, attempt: &str) -> io::Result<()> {
    send_account_request_with_timeout(
        runtime,
        AccountRequest::CancelConnect {
            attempt: attempt.to_owned(),
        },
        TIMEOUT,
    )
    .map(|_| ())
}

pub(crate) fn directory_request(
    runtime: &RuntimeDir,
    instance: &str,
    path: Vec<String>,
) -> io::Result<Vec<DirectoryEntry>> {
    send_account_request(
        runtime,
        AccountRequest::Directory {
            instance: instance.to_owned(),
            path,
        },
    )
    .map(|response| response.entries)
}

pub(crate) fn offline_directory_request(
    runtime: &RuntimeDir,
    instance: &str,
    space: &str,
    path: Vec<String>,
) -> io::Result<Vec<DirectoryEntry>> {
    send_account_request(
        runtime,
        AccountRequest::OfflineDirectory {
            instance: instance.to_owned(),
            space: space.to_owned(),
            path,
        },
    )
    .map(|response| response.entries)
}

pub(crate) fn mount_request(
    runtime: &RuntimeDir,
    request: AccountRequest,
) -> io::Result<Option<String>> {
    send_account_request(runtime, request).map(|response| response.mount)
}

fn send_account_request(
    runtime: &RuntimeDir,
    request: AccountRequest,
) -> io::Result<AccountResponse> {
    send_account_request_with_timeout(runtime, request, Duration::from_secs(720))
}

fn send_account_request_with_timeout(
    runtime: &RuntimeDir,
    request: AccountRequest,
    timeout: Duration,
) -> io::Result<AccountResponse> {
    let mut stream = connect(runtime)?;
    let mut bytes = b"CIRRUS/2 ".to_vec();
    serde_json::to_writer(&mut bytes, &request)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LINE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local request exceeds limit",
        ));
    }
    write_line(&mut stream, &bytes, Instant::now() + TIMEOUT)?;
    let response = read_line(&mut stream, Instant::now() + timeout)?;
    let json = response.strip_prefix(b"CIRRUS/2 ").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or incompatible daemon response",
        )
    })?;
    let response: AccountResponse = serde_json::from_slice(json)?;
    if let Some(error) = &response.error {
        return Err(io::Error::other(error.clone()));
    }
    Ok(response)
}

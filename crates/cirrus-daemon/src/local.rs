use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixListener;
use std::time::Instant;

use crate::application::{Application, Shutdown};
use cirrus_api::{AccountRequest, AccountResponse};
use cirrus_client::wire::{
    ERROR_RESPONSE, INCOMPATIBLE_RESPONSE, MANUAL_STATUS_RESPONSE, PREFIX, SOCKET_NAME,
    STATUS_REQUEST, STATUS_RESPONSE, STOP_BUSY_RESPONSE, STOP_PENDING_RESPONSE, STOP_REQUEST,
    STOP_RESPONSE, TIMEOUT, proc_fd_path, read_line, verify_peer, verify_socket,
    write_account_response, write_line,
};
use cirrus_runtime::RuntimeDir;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use rustix::process;

const OWNER_NAME: &str = "cirrus-drive.owner";
const OWNER_CONTENT: &[u8] = b"cirrus-drive runtime socket v1\n";

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
    let mut application = Application::start(runtime.try_clone()?, automatic)?;
    loop {
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
        if let Some(json) = line.strip_prefix(PREFIX) {
            let request = serde_json::from_slice::<AccountRequest>(json);
            if let Ok(request) = request {
                let ownership = (marker_lock.try_clone()?, guard.try_clone()?);
                application.dispatch(request, move |response| {
                    let _ownership = ownership;
                    let mut stream = stream;
                    let _ = write_account_response(&mut stream, AccountResponse::from(response));
                })?;
                continue;
            }
        }
        let (response, stop) = match line.as_slice() {
            STATUS_REQUEST if application.automatic_sync_enabled() => (STATUS_RESPONSE, false),
            STATUS_REQUEST => (MANUAL_STATUS_RESPONSE, false),
            STOP_REQUEST => (STOP_RESPONSE, true),
            old if old.starts_with(b"CIRRUS/2 ") => (INCOMPATIBLE_RESPONSE, false),
            _ => (ERROR_RESPONSE, false),
        };
        if stop {
            match application.shutdown()? {
                Shutdown::Busy => {
                    let _ = write_line(&mut stream, STOP_BUSY_RESPONSE, Instant::now() + TIMEOUT);
                    continue;
                }
                Shutdown::PendingCredentials => {
                    let _ =
                        write_line(&mut stream, STOP_PENDING_RESPONSE, Instant::now() + TIMEOUT);
                    continue;
                }
                Shutdown::UnmountFailed(error) => {
                    let message = format!("CIRRUS/3 ERROR cannot unmount Space: {error}\n");
                    let _ = write_line(&mut stream, message.as_bytes(), Instant::now() + TIMEOUT);
                    continue;
                }
                Shutdown::Complete => {}
            }
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

//! Shared private Unix framing and verified socket access, not an application API.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use cirrus_api::AccountResponse;
use cirrus_runtime::RuntimeDir;
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use rustix::process;

pub const PREFIX: &[u8] = b"CIRRUS/3 ";
pub const RELEASE_PREFIX: &[u8] = b"CIRRUS/3 RELEASE/1 ";
pub const SOCKET_NAME: &str = "cirrus-drive.sock";
pub const MAX_LINE: usize = 262_144;
pub const TIMEOUT: Duration = Duration::from_secs(2);
const READ_CHUNK: usize = 8 * 1024;
pub const STATUS_REQUEST: &[u8] = b"CIRRUS/3 STATUS\n";
pub const STOP_REQUEST: &[u8] = b"CIRRUS/3 STOP\n";
pub const STATUS_RESPONSE: &[u8] =
    b"CIRRUS/3 OK running; automatic sync available for activated Spaces; local staging is not remote confirmation; rename and open-handle restrictions apply\n";
pub const MANUAL_STATUS_RESPONSE: &[u8] =
    b"CIRRUS/3 OK running; automatic sync disabled; local staging is not remote confirmation; rename and open-handle restrictions apply\n";
pub const STOP_RESPONSE: &[u8] = b"CIRRUS/3 OK stopping\n";
pub const ERROR_RESPONSE: &[u8] = b"CIRRUS/3 ERROR unsupported request\n";
pub const STOP_BUSY_RESPONSE: &[u8] =
    b"CIRRUS/3 ERROR shutdown waiting for account operation; retry\n";
pub const STOP_PENDING_RESPONSE: &[u8] =
    b"CIRRUS/3 ERROR account credentials await keyring persistence; retry account operation\n";
pub const STATUS_TEXT: &str = "running; automatic sync available for activated Spaces; local staging is not remote confirmation; rename and open-handle restrictions apply";
pub const MANUAL_STATUS_TEXT: &str = "running; automatic sync disabled; local staging is not remote confirmation; rename and open-handle restrictions apply";
pub const INCOMPATIBLE_RESPONSE: &[u8] =
    b"CIRRUS/3 ERROR incompatible client protocol; use matching binaries and restart the service\n";
// Linux resolves these paths through the held descriptor, not the original path.
pub fn proc_fd_path(fd: impl AsFd, suffix: &str) -> io::Result<String> {
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

pub fn verify_socket(fd: impl AsFd) -> io::Result<()> {
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

pub fn verify_peer(stream: &UnixStream) -> io::Result<()> {
    // A peer outside our PID namespace has PID 0, but still has kernel-bound
    // UID/GID credentials. rustix's UCred requires a nonzero PID, so read the
    // kernel representation directly rather than constructing that type.
    let mut peer = libc::ucred {
        pid: -1,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let expected_len =
        libc::socklen_t::try_from(std::mem::size_of_val(&peer)).map_err(io::Error::other)?;
    let mut len = expected_len;
    // SAFETY: peer is a live, writable Linux ucred with len set to its size.
    // getsockopt cannot write beyond that buffer; stream holds the socket open.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut peer).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if len != expected_len || peer.pid < 0 || peer.uid == u32::MAX || peer.gid == u32::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socket peer credentials",
        ));
    }
    if peer.uid != process::geteuid().as_raw() {
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

/// Accumulates the first newline-terminated frame of a one-shot connection.
#[derive(Debug, Default)]
pub struct LineReader(Vec<u8>);

impl LineReader {
    /// Reads at most one chunk without changing the socket's blocking mode.
    ///
    /// # Errors
    /// Returns the receive error (including `WouldBlock`), or an error for
    /// premature EOF or a frame at the byte limit without a newline.
    pub fn try_read(&mut self, stream: &UnixStream) -> io::Result<Option<Vec<u8>>> {
        self.read_chunk(|buf| {
            net::recv(stream, buf, net::RecvFlags::DONTWAIT)
                .map(|(_, len)| len)
                .map_err(io::Error::from)
        })
    }

    fn read_chunk(
        &mut self,
        read: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> io::Result<Option<Vec<u8>>> {
        let too_long = || io::Error::new(io::ErrorKind::InvalidData, "local message exceeds limit");
        let mut buf = [0; READ_CHUNK];
        let limit = buf.len().min(MAX_LINE - self.0.len());
        if limit == 0 {
            return Err(too_long());
        }
        let len = read(&mut buf[..limit])?;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete local message",
            ));
        }
        let newline = buf[..len].iter().position(|&byte| byte == b'\n');
        let end = newline.map_or(len, |index| index + 1);
        let total = self.0.len() + end;
        if total > self.0.capacity() {
            self.0
                .reserve_exact(total.next_power_of_two().min(MAX_LINE) - self.0.len());
        }
        // No subsequent frame is read on this connection; ignore trailing bytes.
        self.0.extend_from_slice(&buf[..end]);
        if newline.is_some() {
            Ok(Some(std::mem::take(&mut self.0)))
        } else if total == MAX_LINE {
            Err(too_long())
        } else {
            Ok(None)
        }
    }
}

pub fn read_line(stream: &mut UnixStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut reader = LineReader::default();
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match reader.read_chunk(|buf| stream.read(buf)) {
            Ok(Some(line)) => {
                remaining(deadline)?;
                return Ok(line);
            }
            Ok(None) => (),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

pub fn write_line(stream: &mut UnixStream, mut data: &[u8], deadline: Instant) -> io::Result<()> {
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

pub fn connect(runtime: &RuntimeDir) -> io::Result<UnixStream> {
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

pub fn write_account_response(
    stream: &mut UnixStream,
    response: AccountResponse,
) -> io::Result<()> {
    let mut bytes = PREFIX.to_vec();
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

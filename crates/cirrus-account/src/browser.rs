use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use rustix::{event, net};
use zbus::address::transport::{Transport, UnixSocket};
use zbus::export::futures_core::Stream;
use zbus::names::OwnedUniqueName;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::SignIn;

const PORTAL: &str = "org.freedesktop.portal.Desktop";
const DESKTOP: &str = "/org/freedesktop/portal/desktop";
const REQUEST: &str = "org.freedesktop.portal.Request";
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(3);

/// Opens a one-time authorization URL without logging or persisting it.
pub trait Browser {
    /// Opens the authorization URL in an external browser.
    /// Success means the request was submitted, not that authorization completed.
    ///
    /// # Errors
    /// Returns an error if the browser cannot be requested.
    fn open(&self, authorization_url: &str) -> io::Result<()>;

    /// Retains any portal request for the synchronous sign-in operation.
    ///
    /// The default preserves existing browser implementations. Only the portal
    /// implementation uses the cancellation/deadline to bound transport setup.
    #[doc(hidden)]
    fn open_for_sign_in(
        &self,
        authorization_url: &str,
        _attempt: &SignIn,
        _cancelled: &AtomicBool,
        _deadline: Instant,
    ) -> io::Result<BrowserRequest> {
        self.open(authorization_url)?;
        Ok(BrowserRequest::default())
    }
}

/// Opens the system browser through the desktop portal, not process arguments.
/// Requires a local Unix-domain session bus. Unfinished request cleanup waits
/// at most three seconds for Close, without claiming remote cancellation.
#[derive(Debug, Default)]
pub struct PortalBrowser {
    request: Mutex<Option<BrowserRequest>>,
}

impl Browser for PortalBrowser {
    fn open(&self, authorization_url: &str) -> io::Result<()> {
        let request = submit(
            authorization_url,
            Instant::now() + crate::callback::CALLBACK_TIMEOUT,
            &|| false,
        )?;
        let retired = {
            let mut retained = self
                .request
                .lock()
                .map_err(|_| io::Error::other("browser portal lock failed"))?;
            retained.replace(request)
        };
        drop(retired);
        Ok(())
    }

    fn open_for_sign_in(
        &self,
        authorization_url: &str,
        attempt: &SignIn,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<BrowserRequest> {
        submit(authorization_url, deadline, &|| {
            attempt.is_cancelled() || cancelled.load(Ordering::Acquire)
        })
    }
}

/// An operation-local browser request; it contains no authorization URL.
#[doc(hidden)]
pub struct BrowserRequest {
    portal: Option<PortalRequest>,
    deadline: Instant,
}

impl Default for BrowserRequest {
    fn default() -> Self {
        Self {
            portal: None,
            deadline: Instant::now() + crate::callback::CALLBACK_TIMEOUT,
        }
    }
}

impl std::fmt::Debug for BrowserRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserRequest")
            .finish_non_exhaustive()
    }
}

impl BrowserRequest {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn poll(&mut self) {
        if self.portal.as_mut().is_some_and(PortalRequest::responded) {
            // Response ends portal interaction, not OAuth authorization.
            self.portal.take();
        }
    }
}

impl Drop for BrowserRequest {
    fn drop(&mut self) {
        if let Some(mut request) = self.portal.take()
            && !request.responded()
        {
            // Close emits no Response. A failed/timed-out Close leaves its remote
            // outcome unknown; disconnect is not evidence of cancellation.
            let _ = wait(
                request.connection.call_method(
                    Some(request.owner.as_str()),
                    request.handle.as_str(),
                    Some(REQUEST),
                    "Close",
                    &(),
                ),
                Some(&request.connection),
                Instant::now() + CLOSE_TIMEOUT,
                &|| false,
            );
        }
    }
}

struct PortalRequest {
    connection: zbus::Connection,
    responses: zbus::MessageStream,
    owner: OwnedUniqueName,
    handle: OwnedObjectPath,
    _socket: PortalSocket,
}

impl PortalRequest {
    fn responded(&mut self) -> bool {
        let waker = portal_waker();
        let mut context = Context::from_waker(&waker);
        drive(&self.connection, &mut context);
        for _ in 0..64 {
            let Poll::Ready(Some(Ok(message))) =
                Pin::new(&mut self.responses).poll_next(&mut context)
            else {
                return false;
            };
            let header = message.header();
            if header.message_type() == zbus::message::Type::Signal
                && header
                    .sender()
                    .is_some_and(|sender| sender.as_str() == self.owner.as_str())
                && header
                    .path()
                    .is_some_and(|path| path.as_str() == self.handle.as_str())
                && header
                    .interface()
                    .is_some_and(|interface| interface.as_str() == REQUEST)
                && header
                    .member()
                    .is_some_and(|member| member.as_str() == "Response")
                && message
                    .body()
                    .deserialize::<(u32, HashMap<String, OwnedValue>)>()
                    .is_ok_and(|(response, _)| response <= 2)
            {
                return true;
            }
        }
        false
    }
}

// Retaining a separate socket owner also shuts down a cancelled handshake or
// pending call before any library task could keep the transport alive.
struct PortalSocket(UnixStream);

impl Drop for PortalSocket {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

fn submit(
    authorization_url: &str,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<BrowserRequest> {
    check(deadline, cancelled)?;
    let address = zbus::Address::session().map_err(|_| portal_error())?;
    let Transport::Unix(unix) = address.transport() else {
        return Err(portal_error());
    };
    let socket_address = match unix.path() {
        UnixSocket::File(path) => net::SocketAddrUnix::new(path)?,
        #[cfg(target_os = "linux")]
        UnixSocket::Abstract(name) => {
            use std::os::unix::ffi::OsStrExt;
            net::SocketAddrUnix::new_abstract_name(name.as_bytes())?
        }
        _ => return Err(portal_error()),
    };
    let socket = connect(&socket_address, deadline, cancelled)?;
    let connection = wait(
        zbus::connection::Builder::async_io_unix_stream(socket.0.try_clone()?)
            .internal_executor(false)
            .max_queued(64)
            .build(),
        None,
        deadline,
        cancelled,
    )?;
    if address
        .guid()
        .is_some_and(|guid| connection.server_guid().as_str() != guid.as_str())
    {
        return Err(portal_error());
    }
    // Pin the actual service owner: neither Response nor Close may be redirected
    // to a replacement portal process with the same well-known name.
    wait(
        connection.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "StartServiceByName",
            &(PORTAL, 0u32),
        ),
        Some(&connection),
        deadline,
        cancelled,
    )?;
    let reply = wait(
        connection.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "GetNameOwner",
            &(PORTAL,),
        ),
        Some(&connection),
        deadline,
        cancelled,
    )?;
    let owner: OwnedUniqueName = reply.body().deserialize().map_err(|_| portal_error())?;
    let mut random = [0u8; 16];
    let mut filled = 0;
    while filled < random.len() {
        check(deadline, cancelled)?;
        #[cfg(target_os = "linux")]
        let count = rustix::rand::getrandom(
            &mut random[filled..],
            rustix::rand::GetRandomFlags::NONBLOCK,
        )?;
        #[cfg(target_os = "macos")]
        let count = crate::ownership::file_ops::random(&mut random[filled..])?;
        if count == 0 {
            return Err(portal_error());
        }
        filled += count;
    }
    let token = format!(
        "cirrus_{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let sender = connection
        .unique_name()
        .ok_or_else(portal_error)?
        .as_str()
        .trim_start_matches(':')
        .replace('.', "_");
    let handle = OwnedObjectPath::try_from(format!("{DESKTOP}/request/{sender}/{token}"))
        .map_err(|_| portal_error())?;
    // Subscribe before OpenURI. This dedicated connection has one request.
    // A sender-scoped subscription also queues a legacy portal's differently
    // named handle before its method reply; delivery is filtered by exact handle.
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(owner.as_str())
        .map_err(|_| portal_error())?
        .interface(REQUEST)
        .map_err(|_| portal_error())?
        .member("Response")
        .map_err(|_| portal_error())?
        .build()
        .to_string();
    let responses = zbus::MessageStream::from(&connection);
    wait(
        connection.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "AddMatch",
            &(rule,),
        ),
        Some(&connection),
        deadline,
        cancelled,
    )?;
    let mut request = BrowserRequest {
        deadline,
        portal: Some(PortalRequest {
            connection,
            responses,
            owner,
            handle,
            _socket: socket,
        }),
    };
    let pending = request
        .portal
        .as_mut()
        .expect("new portal request owns transport");
    let options = HashMap::from([("handle_token", Value::from(token.as_str()))]);
    let reply = wait(
        pending.connection.call_method(
            Some(pending.owner.as_str()),
            DESKTOP,
            Some("org.freedesktop.portal.OpenURI"),
            "OpenURI",
            &("", authorization_url, options),
        ),
        Some(&pending.connection),
        deadline,
        cancelled,
    )?;
    let returned: OwnedObjectPath = reply.body().deserialize().map_err(|_| portal_error())?;
    if returned != pending.handle {
        pending.handle = returned;
    }
    request.poll();
    Ok(request)
}

fn connect(
    address: &net::SocketAddrUnix,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<PortalSocket> {
    loop {
        check(deadline, cancelled)?;
        #[cfg(not(target_os = "macos"))]
        let fd = net::socket_with(
            net::AddressFamily::UNIX,
            net::SocketType::STREAM,
            net::SocketFlags::NONBLOCK | net::SocketFlags::CLOEXEC,
            None,
        )?;
        #[cfg(target_os = "macos")]
        let fd = {
            let fd = net::socket(net::AddressFamily::UNIX, net::SocketType::STREAM, None)?;
            // Darwin has no atomic SOCK_CLOEXEC/SOCK_NONBLOCK creation flags.
            // Keep the descriptor private until both flags are set.
            rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
            let flags = rustix::fs::fcntl_getfl(&fd)?;
            rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK)?;
            net::sockopt::set_socket_nosigpipe(&fd, true)?;
            fd
        };
        match net::connect(&fd, address) {
            Ok(()) => return Ok(PortalSocket(UnixStream::from(fd))),
            Err(rustix::io::Errno::AGAIN) => {
                // A full Unix listen backlog is not an EINPROGRESS connection.
                drop(fd);
                thread::park_timeout(remaining(deadline)?.min(POLL_INTERVAL));
            }
            Err(rustix::io::Errno::INPROGRESS) => loop {
                check(deadline, cancelled)?;
                let duration = remaining(deadline)?.min(POLL_INTERVAL);
                let timeout = event::Timespec {
                    tv_sec: 0,
                    tv_nsec: duration.subsec_nanos().into(),
                };
                let mut fds = [event::PollFd::new(&fd, event::PollFlags::OUT)];
                if event::poll(&mut fds, Some(&timeout))? != 0 {
                    net::sockopt::socket_error(&fd)??;
                    return Ok(PortalSocket(UnixStream::from(fd)));
                }
            },
            Err(error) => return Err(error.into()),
        }
    }
}

struct PortalWake(thread::Thread);

impl Wake for PortalWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

fn portal_waker() -> Waker {
    Waker::from(Arc::new(PortalWake(thread::current())))
}

// Drive only this connection, on its existing caller thread. No per-attempt
// executor thread or timed-out blocking connect worker is left running.
fn drive(connection: &zbus::Connection, context: &mut Context<'_>) {
    for _ in 0..32 {
        if std::pin::pin!(connection.executor().tick())
            .poll(context)
            .is_pending()
        {
            break;
        }
    }
}

fn wait<T>(
    future: impl Future<Output = zbus::Result<T>>,
    connection: Option<&zbus::Connection>,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> io::Result<T> {
    let mut future = std::pin::pin!(future);
    let waker = portal_waker();
    let mut context = Context::from_waker(&waker);
    loop {
        check(deadline, cancelled)?;
        if let Some(connection) = connection {
            drive(connection, &mut context);
        }
        check(deadline, cancelled)?;
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            check(deadline, cancelled)?;
            return result.map_err(|_| portal_error());
        }
        thread::park_timeout(remaining(deadline)?.min(POLL_INTERVAL));
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(portal_error)
}

fn check(deadline: Instant, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
    if cancelled() || remaining(deadline)?.is_zero() {
        return Err(portal_error());
    }
    Ok(())
}

fn portal_error() -> io::Error {
    io::Error::other("desktop browser portal could not open authorization")
}

#[cfg(all(test, target_os = "linux"))]
mod acceptance {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    #[test]
    #[ignore = "requires an explicitly owned stopped private dbus-daemon"]
    fn sign_in_cancellation_interrupts_stalled_private_bus_setup() {
        let job = std::path::PathBuf::from(std::env::var_os("CIRRUS_TEST_BUS_JOB").unwrap());
        assert_eq!(job, std::fs::canonicalize(&job).unwrap());
        assert_eq!(
            job.parent().unwrap(),
            std::path::Path::new("/workspaces/.ubuntu-disposable-scratch"),
        );
        let uid = rustix::process::geteuid().as_raw();
        let directory = std::fs::symlink_metadata(&job).unwrap();
        assert!(directory.is_dir());
        assert_eq!(directory.uid(), uid);
        assert_eq!(directory.mode() & 0o7777, 0o700);
        let socket = job.join("bus");
        let metadata = std::fs::symlink_metadata(&socket).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.mode() & 0o7777, 0o777);
        let guid = std::env::var("CIRRUS_TEST_BUS_GUID").unwrap();
        assert_eq!(guid.len(), 32);
        assert!(guid.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let expected = format!("unix:path={},guid={guid}", socket.display());
        assert_eq!(std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap(), expected);
        let address = zbus::Address::session().unwrap();
        assert_eq!(address.guid().unwrap().as_str(), guid);
        let Transport::Unix(unix) = address.transport() else {
            panic!("explicit private Unix transport required");
        };
        let UnixSocket::File(actual) = unix.path() else {
            panic!("explicit private filesystem socket required");
        };
        assert_eq!(actual, &socket);

        let pid: u32 = std::env::var("CIRRUS_TEST_BUS_PID")
            .unwrap()
            .parse()
            .unwrap();
        let process = std::path::PathBuf::from(format!("/proc/{pid}"));
        assert_eq!(std::fs::metadata(&process).unwrap().uid(), uid);
        assert_eq!(
            std::fs::read_link(process.join("exe")).unwrap(),
            std::path::Path::new("/usr/bin/dbus-daemon"),
        );
        let stat = std::fs::read_to_string(process.join("stat")).unwrap();
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        assert_eq!(fields[0], "T");
        assert_eq!(fields[1], std::env::var("CIRRUS_TEST_BUS_PARENT").unwrap());
        assert_eq!(fields[19], std::env::var("CIRRUS_TEST_BUS_START").unwrap());

        let attempt = Arc::new(SignIn::default());
        assert!(!attempt.is_cancelled());
        let cancellation = attempt.clone();
        let started = Instant::now();
        let cancel = thread::spawn(move || {
            thread::sleep(Duration::from_millis(500));
            cancellation.cancel().unwrap();
            Instant::now()
        });
        let result = PortalBrowser::default().open_for_sign_in(
            "https://sign-in.invalid/synthetic-only",
            &attempt,
            &AtomicBool::new(false),
            started + Duration::from_secs(8),
        );
        let returned = Instant::now();
        // Capture and assert at product return, before joining the cancel thread.
        let cancelled_at_return = attempt.is_cancelled();
        assert!(
            cancelled_at_return,
            "product returned before SignIn cancellation"
        );
        assert!(returned.duration_since(started) < Duration::from_secs(4));
        let error = result
            .err()
            .expect("stalled handshake must not open a browser");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), portal_error().to_string());
        let cancelled = cancel.join().unwrap();
        assert!(cancelled <= returned);
        println!(
            "SIGN_IN_CANCELLED_AT_PRODUCT_RETURN; NO_HANDSHAKE_COMPLETION; cancel_ms={}; return_ms={}; deadline_ms=8000",
            cancelled.duration_since(started).as_millis(),
            returned.duration_since(started).as_millis(),
        );
    }
}

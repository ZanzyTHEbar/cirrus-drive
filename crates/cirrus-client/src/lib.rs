//! Client operations for terminal and other control adapters. Never starts the service.

#[doc(hidden)]
pub mod wire;

use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cirrus_api::AccountResponse;
pub use cirrus_api::{
    AccountReply, AccountRequest, CredentialPolicy, CredentialPolicyRequest, MountEngineReport,
    MountMode, ReleaseRequest, ReleaseStatus, ReservationStore, RetainedPage, SpacePath,
    StorageLimits,
};
pub use cirrus_discovery::Configuration;
use cirrus_discovery::Discovery;
use cirrus_runtime::RuntimeDir;

/// A client operation, independent of terminal syntax and output.
pub enum Operation {
    CheckRuntime,
    Status,
    Stop,
    Release(ReleaseRequest),
    CredentialPolicy(CredentialPolicyRequest),
    MountEngines,
    Discover {
        instance: String,
        ca: Option<PathBuf>,
    },
    Connect {
        instance: String,
        ca: Option<PathBuf>,
    },
    Account(AccountRequest),
}

/// Typed client result. HTTPS discovery does not need a running local service.
pub enum Reply {
    RuntimeChecked,
    Status(ServiceStatus),
    Stopping,
    Release(ReleaseStatus),
    CredentialPolicy(CredentialPolicy),
    MountEngines(MountEngineReport),
    Discovery(Configuration),
    Account(AccountReply),
}

/// Effective service worker status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    AutomaticSync,
    ManualSync,
}

impl ServiceStatus {
    pub fn automatic_sync_enabled(self) -> bool {
        matches!(self, Self::AutomaticSync)
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::AutomaticSync => wire::STATUS_TEXT,
            Self::ManualSync => wire::MANUAL_STATUS_TEXT,
        }
    }
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// Whether the service answered, and whether an unanswered request was submitted.
#[derive(Debug)]
pub enum ClientError {
    /// Client-side validation, preparation or incomplete send.
    NotSubmitted(io::Error),
    /// The service returned an error; its diagnostic describes its observation.
    Rejected(String),
    /// Matching clients and service are required.
    Incompatible,
    /// The service explicitly asked for another shutdown request after draining.
    ShutdownBusy,
    /// The complete request was sent, but no valid reply was received.
    ReplyLost(io::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSubmitted(error) => error.fmt(f),
            Self::Rejected(error) => f.write_str(error),
            Self::Incompatible => f.write_str(
                "incompatible daemon protocol; use matching binaries and restart the service",
            ),
            Self::ShutdownBusy => f.write_str("shutdown waiting for account operation; retry"),
            Self::ReplyLost(error) => write!(
                f,
                "request submitted but outcome unknown: {error}; inspect state before retrying"
            ),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotSubmitted(error) | Self::ReplyLost(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ClientError> for io::Error {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::NotSubmitted(error) => error,
            ClientError::Incompatible => Self::new(io::ErrorKind::InvalidData, error),
            _ => Self::other(error),
        }
    }
}

fn runtime() -> io::Result<RuntimeDir> {
    let path = env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "XDG_RUNTIME_DIR is not set; a private user runtime directory is required",
        )
    })?;
    RuntimeDir::open(Path::new(&path))
}

/// Executes one operation using the caller's runtime and working directory.
pub fn execute(operation: Operation) -> Result<Reply, ClientError> {
    let not_submitted = ClientError::NotSubmitted;
    match operation {
        Operation::Discover { instance, ca } => {
            // Validate the URL before accessing the CA path or creating a client.
            validate_instance(&instance).map_err(not_submitted)?;
            let ca = ca
                .as_deref()
                .map(read_ca)
                .transpose()
                .map_err(not_submitted)?;
            let discovery = match &ca {
                Some(ca) => Discovery::with_additional_ca(ca),
                None => Discovery::new(),
            };
            discovery
                .and_then(|discovery| discovery.discover(&instance))
                .map(Reply::Discovery)
                .map_err(|error| ClientError::NotSubmitted(io::Error::other(error)))
        }
        Operation::Connect { instance, ca } => {
            validate_instance(&instance).map_err(not_submitted)?;
            // CA paths, unlike paths consumed on the service, are caller-relative.
            let ca_pem = ca
                .as_deref()
                .map(read_ca)
                .transpose()
                .map_err(not_submitted)?
                .map(String::from_utf8)
                .transpose()
                .map_err(|_| not_submitted(io::Error::other("CA certificate must be PEM text")))?;
            let runtime = runtime().map_err(not_submitted)?;
            let attempt = sign_in_attempt().map_err(not_submitted)?;
            account(
                &runtime,
                AccountRequest::Connect {
                    instance,
                    ca_pem,
                    attempt,
                },
            )
            .map(Reply::Account)
        }
        Operation::CheckRuntime => runtime()
            .map(|_| Reply::RuntimeChecked)
            .map_err(not_submitted),
        Operation::Status => status(&runtime().map_err(not_submitted)?).map(Reply::Status),
        Operation::Stop => stop(&runtime().map_err(not_submitted)?).map(|()| Reply::Stopping),
        Operation::Release(request) => release(&runtime().map_err(not_submitted)?, request).map(Reply::Release),
        Operation::CredentialPolicy(request) => {
            credential_policy(&runtime().map_err(not_submitted)?, request)
                .map(Reply::CredentialPolicy)
        }
        Operation::MountEngines => mount_engines(&runtime().map_err(not_submitted)?).map(Reply::MountEngines),
        Operation::Account(request) => {
            account(&runtime().map_err(not_submitted)?, request).map(Reply::Account)
        }
    }
}

fn validate_instance(instance: &str) -> io::Result<()> {
    let url = url::Url::parse(instance)
        .map_err(|_| io::Error::other("invalid OpenCloud instance URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(io::Error::other(
            "instance URL must be HTTPS without credentials, query or fragment",
        ));
    }
    Ok(())
}

fn read_ca(path: &Path) -> io::Result<Vec<u8>> {
    const LIMIT: usize = 65_536;
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take((LIMIT + 1) as u64).read_to_end(&mut bytes))
        .map_err(|_| io::Error::other("cannot read CA certificate"))?;
    if bytes.len() > LIMIT {
        return Err(io::Error::other("CA certificate is too large"));
    }
    Ok(bytes)
}

/// Creates an opaque attempt ID for clients that support sign-in cancellation.
pub fn sign_in_attempt() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Queries the effective worker mode using an already-verified descriptor.
pub fn status(runtime: &RuntimeDir) -> Result<ServiceStatus, ClientError> {
    match exchange(runtime, wire::STATUS_REQUEST, wire::TIMEOUT)?.as_slice() {
        wire::STATUS_RESPONSE => Ok(ServiceStatus::AutomaticSync),
        wire::MANUAL_STATUS_RESPONSE => Ok(ServiceStatus::ManualSync),
        _ => Err(invalid_reply()),
    }
}

/// Requests shutdown and waits for the daemon's acknowledgement.
pub fn stop(runtime: &RuntimeDir) -> Result<(), ClientError> {
    match exchange(runtime, wire::STOP_REQUEST, Duration::from_secs(35))?.as_slice() {
        wire::STOP_RESPONSE => Ok(()),
        _ => Err(invalid_reply()),
    }
}

/// Sends exactly one complete request; never automatically retries it.
pub fn account(runtime: &RuntimeDir, request: AccountRequest) -> Result<AccountReply, ClientError> {
    let timeout = if matches!(request, AccountRequest::CancelConnect { .. }) {
        wire::TIMEOUT
    } else {
        Duration::from_secs(720)
    };
    let mut bytes = wire::PREFIX.to_vec();
    serde_json::to_writer(&mut bytes, &request)
        .map_err(|error| ClientError::NotSubmitted(error.into()))?;
    bytes.push(b'\n');
    if bytes.len() > wire::MAX_LINE {
        return Err(ClientError::NotSubmitted(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local request exceeds limit",
        )));
    }
    let reply = exchange(runtime, &bytes, timeout)?;
    let json = reply.strip_prefix(wire::PREFIX).ok_or_else(invalid_reply)?;
    let response: AccountResponse =
        serde_json::from_slice(json).map_err(|error| ClientError::ReplyLost(error.into()))?;
    match (response.reply, response.error) {
        (Some(reply), None) if request.accepts(&reply) => Ok(reply),
        (None, Some(error)) => Err(ClientError::Rejected(error)),
        _ => Err(invalid_reply()),
    }
}

/// Queries or changes the managed release through the resident's negotiated endpoint.
pub fn release(runtime: &RuntimeDir, request: ReleaseRequest) -> Result<ReleaseStatus, ClientError> {
    if matches!(request, ReleaseRequest::MountEngines) {
        return Err(ClientError::NotSubmitted(io::Error::other("use mount_engines for the mounted-engine report")));
    }
    if matches!(request, ReleaseRequest::CredentialPolicy(_)) {
        return Err(ClientError::NotSubmitted(io::Error::other(
            "use credential_policy for the credential policy report",
        )));
    }
    let timeout = if matches!(request, ReleaseRequest::Status) {
        wire::TIMEOUT
    } else {
        Duration::from_secs(120)
    };
    serde_json::from_slice::<Result<ReleaseStatus, String>>(&release_exchange(runtime, request, timeout)?)
        .map_err(|error| ClientError::ReplyLost(error.into()))?
        .map_err(ClientError::Rejected)
}

/// Queries or changes the resident's Linux automatic writer policy.
pub fn credential_policy(
    runtime: &RuntimeDir,
    request: CredentialPolicyRequest,
) -> Result<CredentialPolicy, ClientError> {
    let timeout = if matches!(request, CredentialPolicyRequest::Status) {
        wire::TIMEOUT
    } else {
        Duration::from_secs(10)
    };
    let json = release_exchange(runtime, ReleaseRequest::CredentialPolicy(request), timeout)?;
    serde_json::from_slice::<Result<CredentialPolicy, String>>(&json)
        .map_err(|error| ClientError::ReplyLost(error.into()))?
        .map_err(ClientError::Rejected)
}

/// Queries the actual read program serving the resident's existing mounts.
pub fn mount_engines(runtime: &RuntimeDir) -> Result<MountEngineReport, ClientError> {
    let json = release_exchange(runtime, ReleaseRequest::MountEngines, wire::TIMEOUT)?;
    serde_json::from_slice::<Result<MountEngineReport, String>>(&json)
        .map_err(|error| ClientError::ReplyLost(error.into()))?
        .map_err(ClientError::Rejected)
}

fn release_exchange(
    runtime: &RuntimeDir,
    request: ReleaseRequest,
    timeout: Duration,
) -> Result<Vec<u8>, ClientError> {
    let mut bytes = wire::RELEASE_PREFIX.to_vec();
    serde_json::to_writer(&mut bytes, &request)
        .map_err(|error| ClientError::NotSubmitted(error.into()))?;
    bytes.push(b'\n');
    if bytes.len() > wire::MAX_LINE {
        return Err(ClientError::NotSubmitted(io::Error::other("release request exceeds limit")));
    }
    let reply = exchange(runtime, &bytes, timeout)?;
    if reply == wire::ERROR_RESPONSE {
        let message = if matches!(request, ReleaseRequest::CredentialPolicy(_)) {
            "running service does not support live credential policy; maintenance is required"
        } else {
            "running service has no live-release protocol; first transition requires maintenance"
        };
        return Err(ClientError::Rejected(message.into()));
    }
    if !reply.starts_with(wire::RELEASE_PREFIX) {
        return Err(invalid_reply());
    }
    let mut reply = reply;
    reply.drain(..wire::RELEASE_PREFIX.len());
    Ok(reply)
}

fn exchange(
    runtime: &RuntimeDir,
    message: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, ClientError> {
    let mut stream = wire::connect(runtime).map_err(ClientError::NotSubmitted)?;
    // The server cannot dispatch a partial line. An error writing here means
    // the terminating newline was not sent.
    wire::write_line(&mut stream, message, Instant::now() + wire::TIMEOUT)
        .map_err(ClientError::NotSubmitted)?;
    let reply =
        wire::read_line(&mut stream, Instant::now() + timeout).map_err(ClientError::ReplyLost)?;
    // The v2 server gives an explicit unsupported-request response to v3.
    if reply == b"CIRRUS/2 ERROR unsupported request\n" || reply == wire::INCOMPATIBLE_RESPONSE {
        return Err(ClientError::Incompatible);
    }
    if message == wire::STOP_REQUEST && reply == wire::STOP_BUSY_RESPONSE {
        return Err(ClientError::ShutdownBusy);
    }
    if let Some(error) = reply.strip_prefix(b"CIRRUS/3 ERROR ") {
        return Err(ClientError::Rejected(
            String::from_utf8_lossy(error).trim().to_owned(),
        ));
    }
    Ok(reply)
}

fn invalid_reply() -> ClientError {
    ClientError::ReplyLost(io::Error::new(
        io::ErrorKind::InvalidData,
        "unexpected daemon response",
    ))
}

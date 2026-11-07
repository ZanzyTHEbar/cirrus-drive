use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{self, PollFd, PollFlags, Timespec};
use subtle::ConstantTimeEq;
use url::Url;

use crate::AccountError;

const MAX_REQUEST: usize = 8192;
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(180);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(3);

const PAGE_START: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cirrus Drive</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; background: #f3f4f6; color: #192630; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; }
    header { background: #233c4c; color: #fff; padding: 18px 24px; font-size: 1rem; font-weight: 600; }
    main { max-width: 680px; margin: 0 auto; padding: 56px 24px; }
    h1 { margin: 0 0 12px; font-size: 1.5rem; line-height: 1.25; }
    p { max-width: 48ch; margin: 0 0 16px; font-size: 1rem; line-height: 1.55; }
    .note { color: #465a68; }
    ::selection { background: #b7d7eb; color: #102633; }
    @media (prefers-color-scheme: dark) {
      :root { background: #182128; color: #f0f4f6; }
      header { background: #263e4e; }
      .note { color: #becdd5; }
      ::selection { background: #315a72; color: #fff; }
    }
    @media (max-width: 480px) { main { padding-top: 36px; } }
  </style>
</head>
<body>
  <header>Cirrus Drive</header>
  <main>
"#;
const PAGE_END: &str = "  </main>\n</body>\n</html>\n";

pub(crate) struct Listener {
    listener: TcpListener,
    port: u16,
}

impl Listener {
    pub fn bind() -> Result<Self, AccountError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| AccountError::new("cannot bind loopback authorization callback"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| AccountError::new("cannot configure authorization callback"))?;
        let port = listener
            .local_addr()
            .map_err(|_| AccountError::new("cannot inspect authorization callback"))?
            .port();
        Ok(Self { listener, port })
    }

    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn wait(
        self,
        state: &str,
        issuer: &str,
        require_issuer: bool,
        cancelled: &AtomicBool,
        sign_in_cancelled: &AtomicBool,
    ) -> Result<String, AccountError> {
        let deadline = Instant::now() + CALLBACK_TIMEOUT;
        let mut attempts = 0;
        while attempts < 16 {
            if sign_in_cancelled.load(Ordering::Acquire) {
                return Err(AccountError::new("sign-in cancelled; you can try again"));
            }
            if cancelled.load(Ordering::Acquire) {
                return Err(AccountError::new(
                    "authorization cancelled by daemon shutdown",
                ));
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    AccountError::new(
                        "authorization timed out; check the browser for errors and compare Cirrus discovery with the working client",
                    )
                })?;
            let remaining = remaining.min(Duration::from_millis(200));
            let timeout = Timespec {
                tv_sec: 0,
                tv_nsec: i64::from(remaining.subsec_nanos()),
            };
            let mut fds = [PollFd::new(&self.listener, PollFlags::IN)];
            if event::poll(&mut fds, Some(&timeout))
                .map_err(|_| AccountError::new("authorization callback failed"))?
                == 0
            {
                continue;
            }
            let (mut stream, peer) = match self.listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => return Err(AccountError::new("authorization callback failed")),
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            attempts += 1;
            let result = self.parse(&mut stream, state, issuer, require_issuer);
            let (status, content) = match &result {
                Ok(_) => (
                    "200 OK",
                    "<h1>Authorization received</h1>\n<p>Return to Cirrus Drive to finish connecting your account.</p>\n<p class=\"note\">You can close this browser tab.</p>\n",
                ),
                Err(CallbackError::Denied(_)) => (
                    "400 Bad Request",
                    "<h1>Authorization was not granted</h1>\n<p>Return to Cirrus Drive for details and try again.</p>\n<p class=\"note\">You can close this browser tab.</p>\n",
                ),
                Err(CallbackError::Invalid) => (
                    "400 Bad Request",
                    "<h1>Authorization response rejected</h1>\n<p>Return to Cirrus Drive to check the sign-in status or try again.</p>\n<p class=\"note\">You can close this browser tab.</p>\n",
                ),
            };
            let body = format!("{PAGE_START}{content}{PAGE_END}");
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.set_write_timeout(Some(CLIENT_TIMEOUT));
            let _ = stream.write_all(response.as_bytes());
            match result {
                Ok(code) => return Ok(code),
                Err(CallbackError::Denied(message)) => return Err(AccountError::new(message)),
                Err(CallbackError::Invalid) => continue,
            }
        }
        Err(AccountError::new(
            "too many invalid authorization callbacks",
        ))
    }

    fn parse(
        &self,
        stream: &mut TcpStream,
        state: &str,
        issuer: &str,
        require_issuer: bool,
    ) -> Result<String, CallbackError> {
        stream
            .set_read_timeout(Some(CLIENT_TIMEOUT))
            .map_err(|_| CallbackError::Invalid)?;
        let deadline = Instant::now() + CLIENT_TIMEOUT;
        let mut request = Vec::with_capacity(MAX_REQUEST);
        while request.len() < MAX_REQUEST {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(CallbackError::Invalid)?;
            if remaining.is_zero() {
                return Err(CallbackError::Invalid);
            }
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| CallbackError::Invalid)?;
            let mut buffer = [0u8; 1024];
            let count = stream
                .read(&mut buffer[..(MAX_REQUEST - request.len()).min(1024)])
                .map_err(|_| CallbackError::Invalid)?;
            if count == 0 {
                return Err(CallbackError::Invalid);
            }
            request.extend_from_slice(&buffer[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Request::new(&mut headers);
        if !matches!(parsed.parse(&request), Ok(httparse::Status::Complete(_)))
            || parsed.method != Some("GET")
            || parsed.version != Some(1)
        {
            return Err(CallbackError::Invalid);
        }
        let expected_host = format!("127.0.0.1:{}", self.port);
        let mut hosts = parsed
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("host"));
        if hosts.next().map(|header| header.value) != Some(expected_host.as_bytes())
            || hosts.next().is_some()
        {
            return Err(CallbackError::Invalid);
        }
        let target = parsed.path.ok_or(CallbackError::Invalid)?;
        if !target.starts_with("/?") {
            return Err(CallbackError::Invalid);
        }
        let url = Url::parse(&format!("http://{expected_host}{target}"))
            .map_err(|_| CallbackError::Invalid)?;
        if url.path() != "/" || url.fragment().is_some() {
            return Err(CallbackError::Invalid);
        }
        let mut received_state = None;
        let mut code = None;
        let mut returned_issuer = None;
        let mut error = None;
        for (name, value) in url.query_pairs() {
            let slot = match name.as_ref() {
                "state" => &mut received_state,
                "code" => &mut code,
                "iss" => &mut returned_issuer,
                "error" => &mut error,
                _ => continue,
            };
            if slot.replace(value.into_owned()).is_some() {
                return Err(CallbackError::Invalid);
            }
        }
        let received = received_state.ok_or(CallbackError::Invalid)?;
        if !bool::from(received.as_bytes().ct_eq(state.as_bytes())) {
            return Err(CallbackError::Invalid);
        }
        if returned_issuer
            .as_deref()
            .is_some_and(|value| value != issuer)
            || (require_issuer && returned_issuer.is_none())
        {
            return Err(CallbackError::Invalid);
        }
        if let Some(error) = error {
            return if code.is_none() {
                Err(CallbackError::Denied(match error.as_str() {
                    "access_denied" => {
                        "the identity provider denied authorization; check the browser and try again"
                    }
                    "login_required" | "interaction_required" | "consent_required" => {
                        "the identity provider requires browser interaction; complete sign-in and try again"
                    }
                    "temporarily_unavailable" | "server_error" => {
                        "the identity provider reported an error; try again later"
                    }
                    _ => {
                        "the identity provider could not authorize the request; check its configuration and try again"
                    }
                }))
            } else {
                Err(CallbackError::Invalid)
            };
        }
        code.filter(|value| !value.is_empty())
            .ok_or(CallbackError::Invalid)
    }
}

enum CallbackError {
    Invalid,
    Denied(&'static str),
}

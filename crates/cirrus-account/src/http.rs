use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use openidconnect::{HttpRequest, HttpResponse};
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use serde::de::DeserializeOwned;
use url::Url;

use crate::AccountError;

const LIMIT: u64 = 65_536;

pub(crate) fn instance_and_ca(
    instance: &str,
    pem: Option<&[u8]>,
) -> Result<(Url, Option<String>), AccountError> {
    let url =
        Url::parse(instance).map_err(|_| AccountError::new("invalid OpenCloud instance URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AccountError::new(
            "instance URL must be HTTPS without credentials, query or fragment",
        ));
    }
    let ca = pem
        .map(|bytes| {
            if bytes.len() > LIMIT as usize {
                return Err(AccountError::new("CA certificate is too large"));
            }
            String::from_utf8(bytes.to_vec())
                .map_err(|_| AccountError::new("CA certificate must be PEM text"))
        })
        .transpose()?;
    Ok((url, ca))
}

pub(crate) fn client(pem: Option<&[u8]>) -> Result<Client, AccountError> {
    let mut builder = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15));
    if let Some(pem) = pem {
        let cert = reqwest::Certificate::from_pem(pem)
            .map_err(|_| AccountError::new("invalid CA certificate"))?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|_| AccountError::new("cannot create HTTPS client"))
}

pub(crate) struct Transport {
    client: Client,
    issuer: Url,
}
impl Transport {
    pub fn new(pem: Option<&[u8]>, issuer: &str) -> Result<Self, AccountError> {
        let issuer = Url::parse(issuer).map_err(|_| AccountError::new("invalid issuer"))?;
        Ok(Self {
            client: client(pem)?,
            issuer,
        })
    }
    pub fn from_client(client: Client, issuer: Url) -> Self {
        Self { client, issuer }
    }

    pub fn call(&self, request: HttpRequest) -> Result<HttpResponse, io::Error> {
        let url = Url::parse(&request.uri().to_string())
            .map_err(|_| io::Error::other("invalid OpenID request URL"))?;
        if url.scheme() != "https"
            || url.origin() != self.issuer.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || request.body().len() > LIMIT as usize
        {
            return Err(io::Error::other("untrusted OpenID request"));
        }
        let request = request
            .try_into()
            .map_err(|_| io::Error::other("invalid OpenID request"))?;
        let mut response = self
            .client
            .execute(request)
            .map_err(|_| io::Error::other("OpenID HTTPS request failed"))?;
        let mut builder = openidconnect::http::Response::builder()
            .status(response.status())
            .version(response.version());
        for (name, value) in response.headers() {
            builder = builder.header(name, value);
        }
        let mut body = Vec::new();
        response.by_ref().take(LIMIT + 1).read_to_end(&mut body)?;
        if body.len() as u64 > LIMIT {
            return Err(io::Error::other("OpenID response exceeds the limit"));
        }
        builder
            .body(body)
            .map_err(|_| io::Error::other("invalid OpenID response"))
    }
}

pub(crate) fn space_page(
    client: &Client,
    url: &Url,
    access_token: &str,
    page: usize,
    cancelled: &AtomicBool,
) -> Result<Response, AccountError> {
    let mut attempt = 0;
    loop {
        crate::executor::preflight_checkpoint()?;
        if cancelled.load(Ordering::Acquire) {
            return Err(AccountError::new(
                "account operation cancelled by daemon shutdown",
            ));
        }
        let response = client
            .get(url.clone())
            .bearer_auth(access_token)
            .send()
            .map_err(|error| {
                if page == 0 {
                    AccountError::request("Space request failed", &error)
                } else {
                    AccountError::new("Space listing was interrupted before completion")
                }
            })?;
        if !matches!(response.status().as_u16(), 429 | 503) || attempt >= 2 {
            return Ok(response);
        }
        let delay = match response.headers().get(reqwest::header::RETRY_AFTER) {
            None => Some(Duration::from_millis(100 << attempt)),
            Some(value) => value.to_str().ok().and_then(|value| {
                let value = value.trim();
                value
                    .parse::<u64>()
                    .ok()
                    .map(Duration::from_secs)
                    .or_else(|| {
                        httpdate::parse_http_date(value)
                            .ok()
                            .map(|time| time.duration_since(SystemTime::now()).unwrap_or_default())
                    })
            }),
        };
        let Some(delay) = delay.filter(|delay| *delay <= Duration::from_secs(2)) else {
            return Ok(response);
        };
        let until = Instant::now() + delay;
        while Instant::now() < until {
            if cancelled.load(Ordering::Acquire) {
                return Err(AccountError::new(
                    "account operation cancelled by daemon shutdown",
                ));
            }
            std::thread::sleep(
                until
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(100)),
            );
        }
        attempt += 1;
    }
}

pub(crate) fn json<T: DeserializeOwned>(mut response: Response) -> Result<T, AccountError> {
    match response.status().as_u16() {
        200 => {}
        401 => return Err(AccountError::unauthorized()),
        403 => {
            return Err(AccountError::new(
                "server denied access to Spaces; check account permissions",
            ));
        }
        429 => {
            return Err(AccountError::retryable_read(
                "server is rate limiting Space requests; wait and retry",
            ));
        }
        500..=599 => {
            return Err(AccountError::retryable_read(
                "server could not list Spaces; retry later",
            ));
        }
        _ => {
            return Err(AccountError::new(
                "Space endpoint returned an unexpected status",
            ));
        }
    }
    let media = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim);
    if !media.is_some_and(|v| v.eq_ignore_ascii_case("application/json")) {
        return Err(AccountError::new("Space endpoint did not return JSON"));
    }
    let mut data = Vec::new();
    response
        .by_ref()
        .take(LIMIT + 1)
        .read_to_end(&mut data)
        .map_err(|_| AccountError::new("cannot read Space listing"))?;
    if data.len() as u64 > LIMIT {
        return Err(AccountError::new("Space listing exceeds the size limit"));
    }
    serde_json::from_slice(&data).map_err(|_| AccountError::new("invalid Space listing"))
}

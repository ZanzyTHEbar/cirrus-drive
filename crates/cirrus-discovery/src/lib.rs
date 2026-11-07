//! HTTPS discovery of an OpenCloud desktop client's OpenID configuration.

use std::error::Error;
use std::fmt;
use std::io::Read;
use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::header::ACCEPT;
use reqwest::redirect::Policy;
use serde::Deserialize;
use url::Url;

const MAX_DOCUMENT: u64 = 65_536;
const ISSUER_REL: &str = "http://openid.net/specs/connect/1.0/issuer";

/// A validated desktop discovery result, not an authenticated account.
#[derive(Debug, Clone)]
pub struct Configuration {
    issuer: String,
    client_id: String,
    scopes: Vec<String>,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    registration_advertised: bool,
    callback_issuer_required: bool,
}

impl Configuration {
    /// Returns the issuer advertised by WebFinger and confirmed by OpenID metadata.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// Returns the desktop client ID.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    /// Returns the requested desktop scopes.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    /// Returns the validated authorization endpoint.
    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }
    /// Returns the validated token endpoint.
    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }
    /// Returns the validated signing-key endpoint.
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }
    /// Whether OpenID metadata advertises dynamic client registration.
    pub fn registration_advertised(&self) -> bool {
        self.registration_advertised
    }
    /// Whether the provider requires its issuer in authorization responses.
    pub fn callback_issuer_required(&self) -> bool {
        self.callback_issuer_required
    }
}

/// A client with bounded HTTPS requests and no automatic redirects or proxies.
#[derive(Debug)]
pub struct Discovery {
    client: Client,
}

impl Discovery {
    /// Builds a client using the bundled public TLS roots.
    ///
    /// # Errors
    /// Returns an error if the HTTPS client cannot be created.
    pub fn new() -> Result<Self, DiscoveryError> {
        Self::build(None)
    }

    /// Adds an explicitly trusted PEM CA certificate without disabling TLS verification.
    ///
    /// # Errors
    /// Returns an error for invalid PEM or if the HTTPS client cannot be created.
    pub fn with_additional_ca(pem: &[u8]) -> Result<Self, DiscoveryError> {
        if pem.len() > MAX_DOCUMENT as usize {
            return Err(DiscoveryError::new("CA certificate is too large"));
        }
        let cert = reqwest::Certificate::from_pem(pem)
            .map_err(|_| DiscoveryError::new("invalid CA certificate"))?;
        Self::build(Some(cert))
    }

    fn build(certificate: Option<reqwest::Certificate>) -> Result<Self, DiscoveryError> {
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15));
        if let Some(cert) = certificate {
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|_| DiscoveryError::new("cannot create HTTPS client"))?;
        Ok(Self { client })
    }

    /// Fetches and validates WebFinger and the advertised issuer's OpenID metadata.
    ///
    /// A different-origin issuer is allowed only when advertised by the HTTPS
    /// instance. OpenID endpoints must share the issuer's origin. Redirects are
    /// rejected, so neither request silently changes origin.
    ///
    /// # Errors
    /// Returns an error on invalid URLs, TLS or HTTP failures, oversized or invalid
    /// documents, issuer mismatch, or unsupported cross-origin OpenID endpoints.
    pub fn discover(&self, instance: &str) -> Result<Configuration, DiscoveryError> {
        let base = secure_url(instance, false)?;
        let mut webfinger = base
            .join("/.well-known/webfinger")
            .map_err(|_| DiscoveryError::new("invalid instance URL"))?;
        webfinger
            .query_pairs_mut()
            .append_pair("resource", base.as_str())
            .append_pair("rel", ISSUER_REL)
            .append_pair("platform", "desktop");
        let document: WebFinger = self.fetch(webfinger)?;
        if document.subject != base.as_str() {
            return Err(DiscoveryError::new(
                "WebFinger subject does not match instance",
            ));
        }
        let mut links = document
            .links
            .into_iter()
            .filter(|link| link.rel == ISSUER_REL);
        let issuer = links
            .next()
            .and_then(|link| link.href)
            .ok_or_else(|| DiscoveryError::new("WebFinger issuer is missing"))?;
        if links.next().is_some() {
            return Err(DiscoveryError::new("WebFinger has multiple issuer links"));
        }
        let issuer_url = secure_url(&issuer, false)?;
        let mut metadata_url = issuer_url.clone();
        let path = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.path().trim_end_matches('/')
        );
        metadata_url.set_path(&path);
        let metadata: OpenIdMetadata = self.fetch(metadata_url)?;
        if metadata.issuer != issuer {
            return Err(DiscoveryError::new(
                "OpenID issuer does not match WebFinger",
            ));
        }
        for value in [
            &metadata.authorization_endpoint,
            &metadata.token_endpoint,
            &metadata.jwks_uri,
        ] {
            let endpoint = secure_url(value, true)?;
            if endpoint.origin() != issuer_url.origin() {
                return Err(DiscoveryError::new(
                    "OpenID endpoint has a different origin from issuer",
                ));
            }
        }
        let props = document.properties;
        if props.client_id.trim().is_empty()
            || props.client_id.chars().any(char::is_control)
            || props.scopes.is_empty()
            || props.scopes.len() > 128
            || !props.scopes.iter().any(|scope| scope == "openid")
            || props.scopes.iter().any(|scope| {
                scope.is_empty()
                    || scope.chars().any(char::is_whitespace)
                    || scope.chars().any(char::is_control)
            })
        {
            return Err(DiscoveryError::new("invalid desktop client ID or scopes"));
        }
        Ok(Configuration {
            issuer,
            client_id: props.client_id,
            scopes: props.scopes,
            authorization_endpoint: metadata.authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            jwks_uri: metadata.jwks_uri,
            registration_advertised: metadata
                .registration_endpoint
                .as_deref()
                .is_some_and(|endpoint| !endpoint.trim().is_empty()),
            callback_issuer_required: metadata.authorization_response_iss_parameter_supported,
        })
    }

    fn fetch<T: serde::de::DeserializeOwned>(&self, url: Url) -> Result<T, DiscoveryError> {
        let response = self
            .client
            .get(url)
            .header(ACCEPT, "application/json, application/jrd+json")
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    DiscoveryError::new("HTTPS discovery request timed out")
                } else if error.is_connect() {
                    DiscoveryError::new("cannot connect or verify the TLS certificate")
                } else {
                    DiscoveryError::new("HTTPS discovery request failed")
                }
            })?;
        parse_response(response)
    }
}

fn secure_url(value: &str, allow_query: bool) -> Result<Url, DiscoveryError> {
    let url = Url::parse(value).map_err(|_| DiscoveryError::new("invalid discovery URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (!allow_query && url.query().is_some())
    {
        return Err(DiscoveryError::new(
            "discovery URLs must be HTTPS without credentials or fragments",
        ));
    }
    Ok(url)
}

fn parse_response<T: serde::de::DeserializeOwned>(
    mut response: Response,
) -> Result<T, DiscoveryError> {
    if !response.status().is_success() || response.status().as_u16() != 200 {
        return Err(DiscoveryError::new(
            "discovery endpoint returned a non-200 status; redirects are not followed",
        ));
    }
    let media = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim);
    if !media.is_some_and(|value| {
        value.eq_ignore_ascii_case("application/json")
            || value.eq_ignore_ascii_case("application/jrd+json")
    }) {
        return Err(DiscoveryError::new(
            "discovery endpoint did not return JSON",
        ));
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take(MAX_DOCUMENT + 1)
        .read_to_end(&mut body)
        .map_err(|_| DiscoveryError::new("cannot read discovery response"))?;
    if body.len() as u64 > MAX_DOCUMENT {
        return Err(DiscoveryError::new("discovery response is too large"));
    }
    serde_json::from_slice(&body).map_err(|_| DiscoveryError::new("invalid discovery JSON"))
}

#[derive(Deserialize)]
struct WebFinger {
    subject: String,
    links: Vec<Link>,
    properties: DesktopProperties,
}
#[derive(Deserialize)]
struct Link {
    rel: String,
    href: Option<String>,
}
#[derive(Deserialize)]
struct DesktopProperties {
    #[serde(rename = "http://opencloud.eu/ns/oidc/client_id")]
    client_id: String,
    #[serde(rename = "http://opencloud.eu/ns/oidc/scopes")]
    scopes: Vec<String>,
}
#[derive(Deserialize)]
struct OpenIdMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    registration_endpoint: Option<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

/// A discovery failure without response bodies or credentials.
#[derive(Debug)]
pub struct DiscoveryError {
    message: &'static str,
}
impl DiscoveryError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}
impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}
impl Error for DiscoveryError {}

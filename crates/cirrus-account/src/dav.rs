use std::io::Read;
use std::time::SystemTime;

use dav_xml::elements::Response;
use percent_encoding::percent_decode_str;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{AccountError, DirectorySnapshot, FileVersion};

mod listing;

// Complete decoded metadata remains bounded for existing snapshot/handle
// consumers. FUSE also has an independent 16,384-live-inode mount limit.
pub(crate) const MAX_ENTRIES: usize = 16_383;
pub(crate) const MAX_METADATA: usize = 2 * 1024 * 1024;
const REQUEST: &str = r#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:getetag/><oc:fileid/><oc:checksums/></d:prop></d:propfind>"#;

struct Checksum(String);
impl dav_xml::Element for Checksum {
    const NAMESPACE: &'static str = "http://owncloud.org/ns";
    const PREFIX: &'static str = "oc";
    const LOCAL_NAME: &'static str = "checksum";
}
impl TryFrom<&dav_xml::Value> for Checksum {
    type Error = dav_xml::Error;
    fn try_from(value: &dav_xml::Value) -> Result<Self, Self::Error> {
        Ok(Self(value.as_str_of::<Self>()?.to_string()))
    }
}

struct Checksums(Vec<String>);
impl dav_xml::Element for Checksums {
    const NAMESPACE: &'static str = "http://owncloud.org/ns";
    const PREFIX: &'static str = "oc";
    const LOCAL_NAME: &'static str = "checksums";
}
impl TryFrom<&dav_xml::Value> for Checksums {
    type Error = dav_xml::Error;
    fn try_from(value: &dav_xml::Value) -> Result<Self, Self::Error> {
        let map = value.as_map_of::<Self>()?;
        let values = map.get_all::<Checksum>()?;
        if map.iter().count() != 1
            || values.len() > 8
            || values.iter().any(|value| {
                value.0.is_empty()
                    || value.0.len() > 256
                    || !value.0.is_ascii()
                    || value.0.chars().any(char::is_control)
            })
        {
            return Err(dav_xml::Error::InvalidValueType {
                element: "checksums",
                expected: "bounded checksum elements",
            });
        }
        Ok(Self(values.into_iter().map(|value| value.0).collect()))
    }
}

struct RawEtag(String);
impl dav_xml::Element for RawEtag {
    const NAMESPACE: &'static str = "DAV:";
    const PREFIX: &'static str = "d";
    const LOCAL_NAME: &'static str = "getetag";
}
impl TryFrom<&dav_xml::Value> for RawEtag {
    type Error = dav_xml::Error;
    fn try_from(value: &dav_xml::Value) -> Result<Self, Self::Error> {
        Ok(Self(value.as_str_of::<Self>()?.to_string()))
    }
}

pub(crate) fn strong_etag(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=1024).contains(&bytes.len())
        && bytes[0] == b'"'
        && bytes[bytes.len() - 1] == b'"'
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte))
}

pub(crate) fn valid_remote_id(id: &str) -> bool {
    !id.is_empty()
        && !id.chars().any(char::is_control)
        && !id.starts_with("cirrus-staged:")
        && !id.starts_with("cirrus-dir:")
}

struct FileId(String);
impl dav_xml::Element for FileId {
    const NAMESPACE: &'static str = "http://owncloud.org/ns";
    const PREFIX: &'static str = "oc";
    const LOCAL_NAME: &'static str = "fileid";
}
impl TryFrom<&dav_xml::Value> for FileId {
    type Error = dav_xml::Error;
    fn try_from(value: &dav_xml::Value) -> Result<Self, Self::Error> {
        Ok(Self(value.as_str_of::<Self>()?.to_string()))
    }
}

/// One immediate child in an authenticated Space directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    name: String,
    directory: bool,
    size: Option<u64>,
    modified: SystemTime,
    id: String,
    etag: Option<String>,
    checksums: Vec<String>,
}

impl Entry {
    pub(crate) fn with_name(&self, name: String) -> Self {
        let mut entry = self.clone();
        entry.name = name;
        entry
    }
    pub(crate) fn staged_directory(name: String, id: i64) -> Self {
        Self {
            name,
            directory: true,
            size: None,
            modified: std::time::UNIX_EPOCH,
            id: format!("cirrus-dir:{id}"),
            etag: None,
            checksums: Vec::new(),
        }
    }
    pub(crate) fn staged(name: String, id: i64, size: u64, staged: &str) -> Self {
        Self {
            name,
            directory: false,
            size: Some(size),
            modified: std::time::UNIX_EPOCH,
            id: format!("cirrus-staged:{id}"),
            etag: Some(format!("\"cirrus-staged-{staged}\"")),
            checksums: Vec::new(),
        }
    }
    /// Original UTF-8 name of the child.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Whether the child is a directory.
    pub fn is_directory(&self) -> bool {
        self.directory
    }
    /// Size of a regular file, if supplied by the server.
    pub fn size(&self) -> Option<u64> {
        self.size
    }
    /// Last modification time supplied by WebDAV.
    pub fn modified(&self) -> SystemTime {
        self.modified
    }
    /// Stable server resource identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Strong representation validator, when available.
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }
    /// Server-provided checksums, not yet independently verified.
    pub fn checksums(&self) -> &[String] {
        &self.checksums
    }
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains('/')
        && !segment.chars().any(char::is_control)
}

fn segments(url: &Url) -> Result<Vec<String>, AccountError> {
    let mut parts = url
        .path_segments()
        .ok_or_else(|| AccountError::new("invalid DAV href"))?
        .peekable();
    let mut nonempty = Vec::new();
    while let Some(part) = parts.next() {
        if part.is_empty() {
            if parts.peek().is_some() {
                return Err(AccountError::new("invalid DAV href segment"));
            }
        } else {
            nonempty.push(part);
        }
    }
    nonempty
        .into_iter()
        .map(|part| {
            let bytes = part.as_bytes();
            for (i, byte) in bytes.iter().enumerate() {
                if *byte == b'%'
                    && (i + 2 >= bytes.len()
                        || !bytes[i + 1].is_ascii_hexdigit()
                        || !bytes[i + 2].is_ascii_hexdigit())
                {
                    return Err(AccountError::new("invalid DAV href encoding"));
                }
            }
            let value = percent_decode_str(part)
                .decode_utf8()
                .map_err(|_| AccountError::new("DAV href is not UTF-8"))?
                .into_owned();
            if !valid_segment(&value) {
                return Err(AccountError::new("invalid DAV href segment"));
            }
            Ok(value)
        })
        .collect()
}

pub(crate) fn directory_snapshot(
    base: &Url,
    space: &str,
    path: &[String],
    token: &str,
    client: &Client,
) -> Result<DirectorySnapshot, AccountError> {
    for attempt in 0..5 {
        match directory_snapshot_once(base, space, path, token, client) {
            Err(error)
                if error.message == "directory metadata is temporarily unavailable"
                    && attempt < 4 =>
            {
                std::thread::sleep(std::time::Duration::from_millis(100 << attempt));
            }
            result => return result,
        }
    }
    Err(AccountError::new(
        "directory metadata is temporarily unavailable",
    ))
}

pub(crate) fn directory_snapshot_once(
    base: &Url,
    space: &str,
    path: &[String],
    token: &str,
    client: &Client,
) -> Result<DirectorySnapshot, AccountError> {
    directory_snapshot_timed(
        base,
        space,
        path,
        token,
        client,
        std::time::Duration::from_secs(15),
    )
}

pub(crate) fn directory_snapshot_timed(
    base: &Url,
    space: &str,
    path: &[String],
    token: &str,
    client: &Client,
    timeout: std::time::Duration,
) -> Result<DirectorySnapshot, AccountError> {
    if !valid_segment(space) || path.len() > 128 || path.iter().any(|part| !valid_segment(part)) {
        return Err(AccountError::new("invalid Space path"));
    }
    let mut url = base
        .join("/dav/spaces/")
        .map_err(|_| AccountError::new("invalid instance URL"))?;
    {
        let mut parts = url
            .path_segments_mut()
            .map_err(|_| AccountError::new("invalid instance URL"))?;
        parts.pop_if_empty().push(space);
        for part in path {
            parts.push(part);
        }
        parts.push("");
    }
    let wanted = segments(&url)?;
    let response = client
        .request(
            reqwest::Method::from_bytes(b"PROPFIND")
                .map_err(|_| AccountError::new("cannot prepare DAV request"))?,
            url.clone(),
        )
        .timeout(timeout)
        .bearer_auth(token)
        .header("Depth", "1")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/xml; charset=utf-8",
        )
        .body(REQUEST)
        .send()
        .map_err(|error| AccountError::request("directory request failed", &error))?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(AccountError::unauthorized());
    }
    if response.status().as_u16() != 207 {
        if matches!(response.status().as_u16(), 408 | 425 | 429 | 503) {
            return Err(AccountError::retryable_read(
                "directory service temporarily unavailable",
            ));
        }
        return Err(AccountError::new(
            "directory request did not return a DAV multistatus",
        ));
    }
    let media = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim);
    if !media.is_some_and(|v| {
        v.eq_ignore_ascii_case("application/xml") || v.eq_ignore_ascii_case("text/xml")
    }) {
        return Err(AccountError::new("directory endpoint did not return XML"));
    }
    let mut entries = DirectorySnapshot::empty()?;
    let mut found_self = false;
    listing::responses(response, |item| {
        let Response::Propstat {
            href,
            propstat,
            error,
            location,
            ..
        } = item
        else {
            return Err(AccountError::new(
                "directory resource has no property status",
            ));
        };
        if error.is_some() || location.is_some() {
            return Err(AccountError::new("directory resource reported an error"));
        }
        let href = url
            .join(&href.to_string())
            .map_err(|_| AccountError::new("invalid DAV href"))?;
        if href.origin() != base.origin()
            || href.scheme() != "https"
            || !href.username().is_empty()
            || href.password().is_some()
            || href.query().is_some()
            || href.fragment().is_some()
        {
            return Err(AccountError::new("untrusted DAV href"));
        }
        let target = segments(&href)?;
        let is_self = target == wanted;
        if !is_self && (target.len() != wanted.len() + 1 || !target.starts_with(&wanted)) {
            return Err(AccountError::new(
                "DAV href is outside the requested directory",
            ));
        }
        let mut resource_type = None;
        let mut size = None;
        let mut modified = None;
        let mut file_id = None;
        let mut etag = None;
        let mut checksums = None;
        let mut missing_size = false;
        let mut missing_etag = false;
        let mut missing_checksums = false;
        for stat in propstat {
            if stat.status.code.as_u16() == 404
                && stat.error.is_none()
                && stat.prop.resourcetype().is_none()
                && stat.prop.getlastmodified().is_none()
                && stat.prop.get::<FileId>().is_none()
                && (stat.prop.getcontentlength().is_some()
                    || stat.prop.get::<RawEtag>().is_some()
                    || stat.prop.get::<Checksums>().is_some())
            {
                if stat.prop.getcontentlength().is_some() {
                    if missing_size || size.is_some() {
                        return Err(AccountError::new("duplicate DAV content length"));
                    }
                    missing_size = true;
                }
                if stat.prop.get::<RawEtag>().is_some() {
                    if missing_etag || etag.is_some() {
                        return Err(AccountError::new("duplicate DAV ETag"));
                    }
                    missing_etag = true;
                }
                if stat.prop.get::<Checksums>().is_some() {
                    if missing_checksums || checksums.is_some() {
                        return Err(AccountError::new("duplicate DAV checksums"));
                    }
                    missing_checksums = true;
                }
                continue;
            }
            if stat.status.code.as_u16() != 200 || stat.error.is_some() {
                #[cfg(feature = "fault-injection")]
                if std::env::var_os("CIRRUS_TEST_DAV_DIAGNOSTICS").is_some() {
                    eprintln!(
                        "cirrus lab DAV propstat: status={} error={} type={} modified={} id={} size={} etag={} checksums={}",
                        stat.status.code.as_u16(),
                        stat.error.is_some(),
                        stat.prop.resourcetype().is_some(),
                        stat.prop.getlastmodified().is_some(),
                        stat.prop.get::<FileId>().is_some(),
                        stat.prop.getcontentlength().is_some(),
                        stat.prop.get::<RawEtag>().is_some(),
                        stat.prop.get::<Checksums>().is_some()
                    );
                }
                let properties = [
                    (stat.prop.resourcetype().is_some(), "resourcetype"),
                    (stat.prop.getlastmodified().is_some(), "getlastmodified"),
                    (stat.prop.get::<FileId>().is_some(), "fileid"),
                    (stat.prop.getcontentlength().is_some(), "getcontentlength"),
                    (stat.prop.get::<RawEtag>().is_some(), "getetag"),
                    (stat.prop.get::<Checksums>().is_some(), "checksums"),
                ]
                .into_iter()
                .filter_map(|(present, name)| present.then_some(name))
                .collect();
                return Err(AccountError::dav_properties(
                    stat.status.code.as_u16(),
                    properties,
                ));
            }
            if let Some(value) = stat.prop.resourcetype() {
                if resource_type.is_some() {
                    return Err(AccountError::new("duplicate DAV resource type"));
                }
                resource_type = Some(match value {
                    None => false,
                    Some(Ok(value)) => value.is_collection(),
                    Some(Err(_)) => return Err(AccountError::new("invalid DAV resource type")),
                });
            }
            if let Some(value) = stat.prop.getcontentlength() {
                if size.is_some() || missing_size {
                    return Err(AccountError::new("duplicate DAV content length"));
                }
                size = Some(match value {
                    Some(Ok(value)) => value.0,
                    _ => return Err(AccountError::new("invalid DAV content length")),
                });
            }
            if let Some(value) = stat.prop.getlastmodified() {
                if modified.is_some() {
                    return Err(AccountError::new("duplicate DAV modification time"));
                }
                modified = Some(match value {
                    Some(Ok(value)) => SystemTime::from(value.0),
                    _ => return Err(AccountError::new("invalid DAV modification time")),
                });
            }
            if let Some(value) = stat.prop.get::<FileId>() {
                if file_id.is_some() {
                    return Err(AccountError::new("duplicate DAV file ID"));
                }
                let id = match value {
                    Some(Ok(value)) => value.0,
                    _ => return Err(AccountError::new("invalid DAV file ID")),
                };
                if !valid_remote_id(&id) {
                    return Err(AccountError::new("invalid DAV file ID"));
                }
                file_id = Some(id);
            }
            if let Some(value) = stat.prop.get::<RawEtag>() {
                if etag.is_some() || missing_etag {
                    return Err(AccountError::new("duplicate DAV ETag"));
                }
                etag = Some(match value {
                    Some(Ok(value)) => value.0,
                    _ => return Err(AccountError::new("invalid DAV ETag")),
                });
            }
            if let Some(value) = stat.prop.get::<Checksums>() {
                if checksums.is_some() || missing_checksums {
                    return Err(AccountError::new("duplicate DAV checksums"));
                }
                checksums = Some(match value {
                    None => Vec::new(),
                    Some(Ok(value)) => value.0,
                    Some(Err(_)) => return Err(AccountError::new("invalid DAV checksums")),
                });
            }
        }
        let directory =
            resource_type.ok_or_else(|| AccountError::new("DAV resource type is missing"))?;
        let modified =
            modified.ok_or_else(|| AccountError::new("DAV modification time is missing"))?;
        let file_id = file_id.ok_or_else(|| AccountError::new("DAV file ID is missing"))?;
        if is_self {
            if found_self || !directory {
                return Err(AccountError::new("invalid DAV directory response"));
            }
            found_self = true;
            let etag = etag
                .filter(|value| strong_etag(value))
                .ok_or_else(|| AccountError::new("directory self strong ETag unavailable"))?;
            entries.set_remote_parent(&file_id, &etag)?;
        } else {
            if !directory && size.is_none() {
                return Err(AccountError::new("DAV file size is missing"));
            }
            let name = target
                .last()
                .ok_or_else(|| AccountError::new("invalid DAV child"))?
                .clone();
            let entry = Entry {
                name,
                directory,
                size: if directory { None } else { size },
                modified,
                id: file_id,
                etag: etag.filter(|value| strong_etag(value)),
                checksums: checksums.unwrap_or_default(),
            };
            entries.insert(&entry)?;
        }
        Ok(())
    })?;
    if !found_self {
        return Err(AccountError::new("DAV directory response is incomplete"));
    }
    #[cfg(feature = "fault-injection")]
    crate::wait_test_window("CIRRUS_TEST_NAMESPACE_SCRATCH_WINDOW")?;
    Ok(entries)
}

pub(crate) fn read_range(
    base: &Url,
    version: &FileVersion,
    start: u64,
    end: u64,
    token: &str,
    client: &Client,
) -> Result<Vec<u8>, AccountError> {
    let mut url = base
        .join("/dav/spaces/")
        .map_err(|_| AccountError::new("invalid instance URL"))?;
    {
        let mut parts = url
            .path_segments_mut()
            .map_err(|_| AccountError::new("invalid instance URL"))?;
        parts.pop_if_empty().push(&version.space);
        for part in &version.path {
            parts.push(part);
        }
    }
    let mut response = client
        .get(url)
        .bearer_auth(token)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .header(reqwest::header::RANGE, format!("bytes={start}-{end}"))
        .header(reqwest::header::IF_MATCH, &version.etag)
        .header(reqwest::header::IF_RANGE, &version.etag)
        .send()
        .map_err(|error| AccountError::request("range request failed", &error))?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(AccountError::unauthorized());
    }
    let headers = response.headers();
    if matches!(response.status().as_u16(), 408 | 425 | 429 | 503) {
        return Err(AccountError::retryable_read(
            "range service temporarily unavailable",
        ));
    }
    let expected_range = format!("bytes {start}-{end}/{}", version.size);
    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT
        || headers.get_all(reqwest::header::ETAG).iter().count() != 1
        || headers
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            != Some(version.etag.as_str())
        || headers
            .get_all(reqwest::header::CONTENT_RANGE)
            .iter()
            .count()
            != 1
        || headers
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            != Some(expected_range.as_str())
        || headers
            .get_all(reqwest::header::CONTENT_ENCODING)
            .iter()
            .count()
            > 1
        || headers
            .get(reqwest::header::CONTENT_ENCODING)
            .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(AccountError::new("invalid range response"));
    }
    let length = end - start + 1;
    let mut body = Vec::new();
    response
        .by_ref()
        .take(length + 1)
        .read_to_end(&mut body)
        .map_err(|_| AccountError::retryable_read("cannot read range response"))?;
    if body.len() as u64 != length {
        return Err(AccountError::new("invalid range response length"));
    }
    Ok(body)
}

pub(crate) fn put_file(
    base: &Url,
    space: &str,
    path: &[String],
    token: &str,
    client: &Client,
    body: reqwest::blocking::Body,
    etag: Option<&str>,
) -> Result<reqwest::StatusCode, AccountError> {
    if !valid_segment(space)
        || path.is_empty()
        || path.len() > 128
        || path.iter().any(|part| !valid_segment(part))
    {
        return Err(AccountError::new("invalid Space path"));
    }
    let mut url = base
        .join("/dav/spaces/")
        .map_err(|_| AccountError::new("invalid instance URL"))?;
    {
        let mut parts = url
            .path_segments_mut()
            .map_err(|_| AccountError::new("invalid instance URL"))?;
        parts.pop_if_empty().push(space);
        for part in path {
            parts.push(part);
        }
    }
    let mut request = client
        .put(url)
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream");
    request = if let Some(etag) = etag {
        request.header(reqwest::header::IF_MATCH, etag)
    } else {
        request.header(reqwest::header::IF_NONE_MATCH, "*")
    };
    request
        .body(body)
        .send()
        .map(|response| response.status())
        .map_err(|error| AccountError::uncertain_upload(&error))
}

pub(crate) fn namespace_request(
    base: &Url,
    space: &str,
    path: &[String],
    token: &str,
    client: &Client,
    mkdir: bool,
    etag: Option<&str>,
) -> Result<reqwest::StatusCode, AccountError> {
    if !valid_segment(space)
        || path.is_empty()
        || path.len() > 128
        || path.iter().any(|part| !valid_segment(part))
    {
        return Err(AccountError::new("invalid Space path"));
    }
    let mut url = base
        .join("/dav/spaces/")
        .map_err(|_| AccountError::new("invalid instance URL"))?;
    {
        let mut parts = url
            .path_segments_mut()
            .map_err(|_| AccountError::new("invalid instance URL"))?;
        parts.pop_if_empty().push(space);
        for part in path {
            parts.push(part);
        }
    }
    let method = if mkdir {
        reqwest::Method::from_bytes(b"MKCOL")
            .map_err(|_| AccountError::new("cannot prepare DAV request"))?
    } else {
        reqwest::Method::DELETE
    };
    let mut request = client.request(method, url).bearer_auth(token);
    request = if mkdir {
        request.header(reqwest::header::IF_NONE_MATCH, "*")
    } else {
        request.header(
            reqwest::header::IF_MATCH,
            etag.ok_or_else(|| AccountError::new("delete lacks a base ETag"))?,
        )
    };
    request
        .send()
        .map(|response| response.status())
        .map_err(|error| AccountError::request("namespace operation outcome is uncertain", &error))
}

pub(crate) fn move_directory(
    base: &Url,
    space: &str,
    paths: (&[String], &[String]),
    token: &str,
    client: &Client,
    etag: &str,
    replace: bool,
) -> Result<reqwest::StatusCode, AccountError> {
    let build = |path: &[String]| -> Result<Url, AccountError> {
        if !valid_segment(space)
            || path.is_empty()
            || path.len() > 128
            || path.iter().any(|part| !valid_segment(part))
        {
            return Err(AccountError::new("invalid Space path"));
        }
        let mut url = base
            .join("/dav/spaces/")
            .map_err(|_| AccountError::new("invalid instance URL"))?;
        {
            let mut parts = url
                .path_segments_mut()
                .map_err(|_| AccountError::new("invalid instance URL"))?;
            parts.pop_if_empty().push(space);
            for part in path {
                parts.push(part);
            }
        }
        Ok(url)
    };
    let source = build(paths.0)?;
    let destination = build(paths.1)?;
    let method = reqwest::Method::from_bytes(b"MOVE")
        .map_err(|_| AccountError::new("cannot prepare DAV request"))?;
    client
        .request(method, source)
        .bearer_auth(token)
        .header("Destination", destination.as_str())
        .header("Overwrite", if replace { "T" } else { "F" })
        .header(reqwest::header::IF_MATCH, etag)
        .send()
        .map(|response| response.status())
        .map_err(|error| AccountError::request("directory move outcome is uncertain", &error))
}

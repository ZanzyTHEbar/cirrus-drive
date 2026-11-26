use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use cirrus_runtime::RuntimeDir;
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, ResolveFlags},
    process, rand,
};
use serde::{Deserialize, Serialize};

use crate::{Mounted, RecoveryOwner, escape_mount_path};

const PREFIX: &str = "cirrus-drive.mount-";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    instance: String,
    space_id: String,
    space_name: String,
    path: String,
    mount_id: u64,
    source: String,
    namespace: u64,
    boot_id: String,
}

fn namespace() -> io::Result<u64> {
    Ok(std::fs::metadata("/proc/self/ns/mnt")?.ino())
}

fn boot_id() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

fn verify(fd: &OwnedFd) -> io::Result<()> {
    let stat = fs::fstat(fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unrecognized mount owner record",
        ));
    }
    Ok(())
}

fn open(runtime: &RuntimeDir, name: &str) -> io::Result<OwnedFd> {
    let fd = fs::openat2(
        runtime,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(io::Error::from)?;
    verify(&fd)?;
    Ok(fd)
}

fn read(fd: &OwnedFd) -> io::Result<Record> {
    let mut bytes = Vec::new();
    std::fs::File::from(fd.try_clone()?)
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mount owner record is too large",
        ));
    }
    let record: Record = serde_json::from_slice(&bytes)?;
    let valid_identity = record.version == 3
        && record.mount_id == 0
        && cirrus_account::Accounts::canonical_instance(&record.instance)
            .is_ok_and(|url| url == record.instance)
        && !record.space_id.is_empty()
        && !record.space_name.is_empty()
        && !record.space_id.chars().any(char::is_control)
        && !record.space_name.chars().any(char::is_control)
        && record
            .source
            .strip_prefix("cirrus-drive-")
            .is_some_and(|nonce| {
                nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
    if !valid_identity || !Path::new(&record.path).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mount owner record is invalid",
        ));
    }
    Ok(record)
}

fn records(runtime: &RuntimeDir) -> io::Result<Vec<(String, OwnedFd, Record)>> {
    runtime.revalidate()?;
    let mut entries = fs::Dir::read_from(runtime).map_err(io::Error::from)?;
    let mut records = Vec::new();
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if !bytes.starts_with(b"cirrus-drive.mount") {
            continue;
        }
        let name = std::str::from_utf8(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mount owner record name",
            )
        })?;
        let valid = name.strip_prefix(PREFIX).is_some_and(|nonce| {
            nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
        if !valid || records.len() >= 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid or excessive mount owner records",
            ));
        }
        let fd = open(runtime, name)?;
        let record = read(&fd)?;
        records.push((name.to_owned(), fd, record));
    }
    Ok(records)
}

fn find(runtime: &RuntimeDir, path: &Path) -> io::Result<Option<(String, OwnedFd, Record)>> {
    let mut matches = records(runtime)?
        .into_iter()
        .filter(|(_, _, record)| Path::new(&record.path) == path);
    let found = matches.next();
    if matches.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multiple owner records for mountpoint",
        ));
    }
    Ok(found)
}

// The mount owner must serialize this check and prepare for a given path.
pub(crate) fn ensure_available(runtime: &RuntimeDir, path: &Path) -> io::Result<()> {
    if find(runtime, path)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "mount owner record exists; recover or inspect it first",
        ));
    }
    Ok(())
}

pub(crate) fn owners(runtime: &RuntimeDir) -> io::Result<Vec<RecoveryOwner>> {
    Ok(records(runtime)?
        .into_iter()
        .map(|(_, _, record)| RecoveryOwner {
            instance: record.instance,
            space_id: record.space_id,
            space_name: record.space_name,
            path: record.path.into(),
            source: record.source,
        })
        .collect())
}

pub(crate) fn prepare(
    runtime: &RuntimeDir,
    path: &Path,
    instance: &str,
    space_id: &str,
    space_name: &str,
) -> io::Result<String> {
    runtime.revalidate()?;
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mount path must be UTF-8"))?;
    let mut random = [0u8; 16];
    let mut filled = 0;
    while filled < random.len() {
        let count = rand::getrandom(&mut random[filled..], rand::GetRandomFlags::empty())
            .map_err(io::Error::from)?;
        if count == 0 {
            return Err(io::Error::other("cannot generate mount identity"));
        }
        filled += count;
    }
    let nonce = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let source = format!("cirrus-drive-{nonce}");
    let name = format!("{PREFIX}{nonce}");
    let record = Record {
        version: 3,
        instance: instance.to_owned(),
        space_id: space_id.to_owned(),
        space_name: space_name.to_owned(),
        path: path.to_owned(),
        mount_id: 0,
        source: source.clone(),
        namespace: namespace()?,
        boot_id: boot_id()?,
    };
    let bytes = serde_json::to_vec(&record)?;
    if bytes.len() + 1 > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mount owner record is too large",
        ));
    }
    let fd = fs::openat(
        runtime,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(io::Error::from)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    runtime.revalidate()?;
    fs::linkat(&file, "", runtime, name.as_str(), AtFlags::EMPTY_PATH).map_err(io::Error::from)?;
    fs::fsync(runtime).map_err(io::Error::from)?;
    Ok(source)
}

fn remove(runtime: &RuntimeDir, name: &str, held: &OwnedFd) -> io::Result<()> {
    runtime.revalidate()?;
    let original = fs::fstat(held).map_err(io::Error::from)?;
    let current = open(runtime, name)?;
    let now = fs::fstat(&current).map_err(io::Error::from)?;
    if (original.st_dev, original.st_ino) != (now.st_dev, now.st_ino) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mount owner record changed",
        ));
    }
    fs::unlinkat(runtime, name, AtFlags::empty()).map_err(io::Error::from)?;
    fs::fsync(runtime).map_err(io::Error::from)
}

pub(crate) struct MountState {
    source_present: bool,
    path_mounted: bool,
    pub(crate) exact_id: Option<u64>,
}

struct MountEntry<'a> {
    id: &'a [u8],
    path: &'a [u8],
    kind: &'a [u8],
    source: &'a [u8],
}

impl MountEntry<'_> {
    fn cirrus_id(&self) -> Option<u64> {
        (self.kind == b"fuse.cirrus-drive")
            .then(|| std::str::from_utf8(self.id).ok()?.parse().ok())
            .flatten()
    }
}

fn mount_entries(info: &[u8]) -> impl Iterator<Item = MountEntry<'_>> {
    info.split(|b| *b == b'\n').filter_map(|line| {
        let mut fields = line.split(|b| *b == b' ');
        let mut fixed = [b"".as_slice(); 6];
        for field in &mut fixed {
            *field = fields.next()?;
        }
        if fixed.contains(&b"-".as_slice()) {
            return None;
        }
        let [id, _, _, _, path, _] = fixed;
        fields.find(|field| *field == b"-")?;
        Some(MountEntry {
            id,
            path,
            kind: fields.next()?,
            source: fields.next()?,
        })
    })
}

/// One mount namespace observation for read-only inspection of multiple FUSE mounts.
#[derive(Debug)]
pub struct MountTable {
    paths: HashMap<Vec<u8>, Option<(Vec<u8>, u64)>>,
    sources: HashMap<Vec<u8>, usize>,
}

impl MountTable {
    /// Reads and indexes `/proc/self/mountinfo` once, without opening mountpoints.
    ///
    /// # Errors
    /// Returns an error if the kernel mount table cannot be read.
    pub fn read() -> io::Result<Self> {
        let info = std::fs::read("/proc/self/mountinfo")?;
        let mut paths = HashMap::new();
        let mut sources = HashMap::new();
        for entry in mount_entries(&info) {
            *sources.entry(entry.source.to_vec()).or_insert(0) += 1;
            paths
                .entry(entry.path.to_vec())
                .and_modify(|mount| *mount = None)
                .or_insert_with(|| entry.cirrus_id().map(|id| (entry.source.to_vec(), id)));
        }
        Ok(Self { paths, sources })
    }

    pub(crate) fn exact_id(&self, path: &Path, source: &str) -> Option<u64> {
        let (mounted_source, id) = self.paths.get(&escape_mount_path(path))?.as_ref()?;
        (mounted_source == source.as_bytes() && self.sources.get(source.as_bytes()) == Some(&1))
            .then_some(*id)
    }
}

pub(crate) fn mount_state(path: &Path, source: &str) -> io::Result<MountState> {
    let info = std::fs::read("/proc/self/mountinfo")?;
    let path = escape_mount_path(path);
    let mut count = 0;
    let mut exact_id = None;
    let mut source_count = 0;
    for entry in mount_entries(&info) {
        let has_source = entry.source == source.as_bytes();
        if has_source {
            source_count += 1;
        }
        if entry.path == path {
            count += 1;
            if has_source && entry.kind == b"fuse.cirrus-drive" {
                exact_id = entry.cirrus_id();
            }
        }
    }
    Ok(MountState {
        source_present: source_count != 0,
        path_mounted: count != 0,
        exact_id: exact_id.filter(|_| count == 1 && source_count == 1),
    })
}

pub(crate) fn remove_owned(mount: &Mounted) -> io::Result<()> {
    let runtime = &mount.runtime;
    let path = mount.path();
    let (name, fd, record) = find(runtime, path)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "mount owner record not found"))?;
    if record.path != path.to_str().unwrap_or("")
        || record.source != mount.source()
        || record.instance != mount.instance()
        || record.space_id != mount.space_id()
        || record.space_name != mount.space_name()
        || record.source.strip_prefix("cirrus-drive-") != name.strip_prefix(PREFIX)
        || record.namespace != namespace()?
        || record.boot_id != boot_id()?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mount owner record does not match",
        ));
    }
    let state = mount_state(path, &record.source)?;
    if state.source_present || state.path_mounted {
        return Err(io::Error::other(
            "recorded mount or another mount is still present; owner record retained",
        ));
    }
    remove(runtime, &name, &fd)
}

/// Recovers a recorded stale mount in the current mount namespace.
pub(crate) fn recover(runtime: &RuntimeDir, path: &Path) -> io::Result<()> {
    runtime.revalidate()?;
    let (name, fd, record) = find(runtime, path)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "mount owner record not found"))?;
    if record.path != path.to_str().unwrap_or("")
        || record.namespace != namespace()?
        || record.boot_id != boot_id()?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "recorded mount does not match this path and namespace",
        ));
    }
    let state = mount_state(path, &record.source)?;
    if !state.source_present && state.path_mounted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "another mount occupies the recorded path",
        ));
    }
    if state.source_present {
        if state.exact_id.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "recorded mount identity is ambiguous",
            ));
        }
        let output = Command::new("fusermount3")
            .args(["-u", "-z", "--"])
            .arg(path)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                "fusermount3 could not recover the recorded mount",
            ));
        }
        let after = mount_state(path, &record.source)?;
        if after.source_present || after.path_mounted {
            return Err(io::Error::other(
                "recorded path or mount remains after recovery",
            ));
        }
    }
    remove(runtime, &name, &fd)
}

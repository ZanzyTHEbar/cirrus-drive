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

use crate::{RecoveryOwner, escape_mount_path};

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

pub(crate) fn pending(runtime: &RuntimeDir) -> io::Result<bool> {
    Ok(!records(runtime)?.is_empty())
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

fn mount_state(record: &Record) -> io::Result<(bool, bool, bool)> {
    let info = std::fs::read("/proc/self/mountinfo")?;
    let path = escape_mount_path(Path::new(&record.path));
    let mut count = 0;
    let mut matches = false;
    let mut id_present = false;
    let mut source_count = 0;
    for line in info.split(|b| *b == b'\n') {
        let fields: Vec<_> = line.split(|b| *b == b' ').collect();
        let Some(separator) = fields.iter().position(|field| *field == b"-") else {
            continue;
        };
        if fields.len() > separator + 2 && fields[separator + 2] == record.source.as_bytes() {
            id_present = true;
            source_count += 1;
        }
        if fields.len() > separator + 2 && fields.len() >= 5 && fields[4] == path {
            count += 1;
            matches |= fields[separator + 1] == b"fuse.cirrus-drive"
                && fields[separator + 2] == record.source.as_bytes();
        }
    }
    Ok((
        id_present,
        count == 1 && matches && source_count == 1,
        count != 0,
    ))
}

pub(crate) fn remove_owned(runtime: &RuntimeDir, path: &Path) -> io::Result<()> {
    let (name, fd, record) = find(runtime, path)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "mount owner record not found"))?;
    if record.path != path.to_str().unwrap_or("")
        || record.namespace != namespace()?
        || record.boot_id != boot_id()?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mount owner record does not match",
        ));
    }
    let (present, _, path_mounted) = mount_state(&record)?;
    if present || path_mounted {
        return Err(io::Error::other("owned mount is still present"));
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
    let (present, matches, path_mounted) = mount_state(&record)?;
    if !present && path_mounted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "another mount occupies the recorded path",
        ));
    }
    if present {
        if !matches {
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
        if mount_state(&record)?.0 {
            return Err(io::Error::other("recorded mount remains after recovery"));
        }
    }
    remove(runtime, &name, &fd)
}

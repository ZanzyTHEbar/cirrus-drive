//! Publication and flock admission beneath an already admitted state directory.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;

use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::process;

#[derive(Debug)]
pub(super) enum MarkerError {
    Failure(&'static str),
    Contended,
}

use MarkerError::Failure;

const PUBLISH_LOCK: &str = ".cirrus-marker-publish.lock";
const PUBLISH_TEMP: &str = ".cirrus-marker-publish";

// Callers supply only internal names (including validated namespace tokens).
// Reject the publication machinery's reserved names even on the fast path.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\0'])
        && name != PUBLISH_LOCK
        && name != PUBLISH_TEMP
}

fn open(directory: &OwnedFd, name: &str) -> rustix::io::Result<OwnedFd> {
    #[cfg(target_os = "linux")]
    {
        fs::openat2(
            directory,
            name,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            fs::ResolveFlags::NO_SYMLINKS | fs::ResolveFlags::NO_MAGICLINKS,
        )
    }
    #[cfg(target_os = "macos")]
    {
        fs::openat(
            directory,
            name,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
    }
}

pub(super) fn lock(
    directory: &OwnedFd,
    marker: &str,
    expected_content: &[u8],
    operation: fs::FlockOperation,
    create: bool,
) -> Result<OwnedFd, MarkerError> {
    if !valid_name(marker) {
        return Err(Failure("account coordination marker is unsafe"));
    }
    let fd = match open(directory, marker) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) if create => {
            publish(directory, marker, expected_content)?;
            open(directory, marker)
                .map_err(|_| Failure("cannot open account coordination marker"))?
        }
        Err(_) => return Err(Failure("account coordination marker is unsafe")),
    };
    let stat = fs::fstat(&fd).map_err(|_| Failure("cannot inspect account coordination marker"))?;
    if !safe(&stat) {
        return Err(Failure("account coordination marker is unsafe"));
    }
    check_content(&fd, expected_content)?;
    fs::flock(&fd, operation).map_err(|_| {
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_NAMESPACE_TRACE").is_some() {
            eprintln!("cirrus lab coordination contention: marker={marker}");
        }
        #[cfg(all(feature = "fault-injection", target_os = "linux"))]
        if std::env::var_os("CIRRUS_TEST_BLOCKER_TRACE").is_some() {
            let inode = format!(":{}", stat.st_ino);
            let locks = std::fs::read_to_string("/proc/locks").unwrap_or_default();
            let owners: Vec<_> = locks.lines().filter(|line| line.split_whitespace().nth(5).is_some_and(|key| key.ends_with(&inode))).collect();
            eprintln!("cirrus lab flock refusal: pid={} thread={:?} marker={marker} requested={operation:?} owners={owners:?}", std::process::id(), std::thread::current().id());
        }
        MarkerError::Contended
    })?;
    let current =
        open(directory, marker).map_err(|_| Failure("account coordination marker changed"))?;
    #[cfg(target_os = "macos")]
    super::darwin_acl::check_file(&fd).map_err(Failure)?;
    #[cfg(target_os = "macos")]
    super::darwin_acl::check_file(&current).map_err(Failure)?;
    let current = fs::fstat(current).map_err(|_| Failure("account coordination marker changed"))?;
    if (stat.st_dev, stat.st_ino) != (current.st_dev, current.st_ino) || current.st_nlink != 1 {
        return Err(Failure("account coordination marker changed"));
    }
    Ok(fd)
}

fn safe(stat: &fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == process::geteuid().as_raw()
        && stat.st_mode & 0o7777 == 0o600
        && stat.st_nlink == 1
}

fn check_content(fd: &OwnedFd, expected_content: &[u8]) -> Result<(), MarkerError> {
    #[cfg(target_os = "macos")]
    super::darwin_acl::check_file(fd).map_err(Failure)?;
    let mut content = Vec::new();
    std::fs::File::from(
        fd.try_clone()
            .map_err(|_| Failure("cannot inspect account coordination marker"))?,
    )
    .take((expected_content.len() + 1) as u64)
    .read_to_end(&mut content)
    .map_err(|_| Failure("cannot inspect account coordination marker"))?;
    if content != expected_content {
        return Err(Failure(
            "unrecognized account coordination marker; inspect it manually",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish(directory: &OwnedFd, marker: &str, expected_content: &[u8]) -> Result<(), MarkerError> {
    let tmp = fs::openat(
        directory,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| Failure("cannot create account coordination marker"))?;
    let mut tmp = std::fs::File::from(tmp);
    tmp.write_all(expected_content)
        .and_then(|()| tmp.sync_all())
        .map_err(|_| Failure("cannot persist account coordination marker"))?;
    match fs::linkat(&tmp, "", directory, marker, fs::AtFlags::EMPTY_PATH) {
        Ok(()) => fs::fsync(directory)
            .map_err(|_| Failure("cannot persist account coordination marker"))?,
        Err(rustix::io::Errno::EXIST) => (),
        Err(_) => return Err(Failure("cannot publish account coordination marker")),
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn checked_path(directory: &OwnedFd, name: &str, fd: &OwnedFd) -> Result<(), MarkerError> {
    let stat = fs::fstat(fd).map_err(|_| Failure("cannot inspect account coordination marker"))?;
    let current = open(directory, name)
        .and_then(fs::fstat)
        .map_err(|_| Failure("account coordination marker changed"))?;
    if !safe(&stat)
        || !safe(&current)
        || (stat.st_dev, stat.st_ino) != (current.st_dev, current.st_ino)
    {
        return Err(Failure("account coordination marker is unsafe"));
    }
    super::darwin_acl::check_file(fd).map_err(Failure)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_temp(directory: &OwnedFd, fd: &OwnedFd) -> Result<(), MarkerError> {
    checked_path(directory, PUBLISH_TEMP, fd)?;
    fs::unlinkat(directory, PUBLISH_TEMP, fs::AtFlags::empty())
        .map_err(|_| Failure("cannot publish account coordination marker"))
}

#[cfg(target_os = "macos")]
fn publish(directory: &OwnedFd, marker: &str, expected_content: &[u8]) -> Result<(), MarkerError> {
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    // Every publisher needs a distinct fileglob, not a dup of a borrowed lock.
    // This persistent empty inode is never truncated, replaced or unlinked.
    let publication = match fs::openat(
        directory,
        PUBLISH_LOCK,
        flags | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::EXIST) => open(directory, PUBLISH_LOCK)
            .map_err(|_| Failure("account coordination marker is unsafe"))?,
        Err(_) => return Err(Failure("cannot create account coordination marker")),
    };
    checked_path(directory, PUBLISH_LOCK, &publication)?;
    check_content(&publication, b"")?;
    fs::flock(&publication, fs::FlockOperation::LockExclusive)
        .map_err(|_| Failure("cannot publish account coordination marker"))?;
    checked_path(directory, PUBLISH_LOCK, &publication)?;
    // Reopen: dup would share the offset used by the pre-lock content check.
    check_content(
        &open(directory, PUBLISH_LOCK)
            .map_err(|_| Failure("account coordination marker changed"))?,
        b"",
    )?;

    // All cooperating creators hold this EX lock. Thus an admitted fixed temp
    // left by a dead publisher is abandoned, irrespective of its byte content.
    // Cleanup precedes even the existing-winner return; no age/PID guessing.
    match open(directory, PUBLISH_TEMP) {
        Ok(fd) => remove_temp(directory, &fd)?,
        Err(rustix::io::Errno::NOENT) => (),
        Err(_) => return Err(Failure("account coordination marker is unsafe")),
    }
    match open(directory, marker) {
        Ok(_) => return Ok(()),
        Err(rustix::io::Errno::NOENT) => (),
        Err(_) => return Err(Failure("account coordination marker is unsafe")),
    }
    let tmp = fs::openat(
        directory,
        PUBLISH_TEMP,
        flags | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| Failure("cannot create account coordination marker"))?;
    // No flock on the temp inode: it will become the principal inode.
    let mut output = std::fs::File::from(tmp);
    let result = (|| {
        super::darwin_acl::check_file(&output).map_err(Failure)?;
        output
            .write_all(expected_content)
            .and_then(|()| output.sync_all())
            .map_err(|_| Failure("cannot persist account coordination marker"))?;
        let fd = open(directory, PUBLISH_TEMP)
            .map_err(|_| Failure("account coordination marker changed"))?;
        // Compare to the actual writer, not merely two reopens of the name.
        let writer = fs::fstat(&output)
            .map_err(|_| Failure("cannot inspect account coordination marker"))?;
        let reader =
            fs::fstat(&fd).map_err(|_| Failure("cannot inspect account coordination marker"))?;
        if (writer.st_dev, writer.st_ino) != (reader.st_dev, reader.st_ino) || !safe(&writer) {
            return Err(Failure("account coordination marker changed"));
        }
        checked_path(directory, PUBLISH_TEMP, &fd)?;
        check_content(&fd, expected_content)?;
        match fs::renameat_with(
            directory,
            PUBLISH_TEMP,
            directory,
            marker,
            fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => fs::fsync(directory)
                .map_err(|_| Failure("cannot persist account coordination marker")),
            Err(rustix::io::Errno::EXIST) => remove_temp(directory, &fd),
            Err(_) => Err(Failure("cannot publish account coordination marker")),
        }
    })();
    if result.is_err() {
        // Preserve the primary error and never touch an uncertain final name.
        // An inherited ALLOW must refuse payload writes, but must not strand our
        // own exclusive temp. Compare the actual writer with the no-follow name;
        // do not reuse ACL-admitting abandoned-temp cleanup for this case.
        if let (Ok(writer), Ok(named)) = (
            fs::fstat(&output),
            fs::statat(directory, PUBLISH_TEMP, fs::AtFlags::SYMLINK_NOFOLLOW),
        ) && safe(&writer)
            && safe(&named)
            && (writer.st_dev, writer.st_ino) == (named.st_dev, named.st_ino)
        {
            let _ = fs::unlinkat(directory, PUBLISH_TEMP, fs::AtFlags::empty());
        }
    }
    // Publication EX ends here, BEFORE lock() acquires any requested flock.
    result
}

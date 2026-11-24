//! Narrow file operations for retained parents and newly created scratch files.

use rustix::fs;
use std::os::fd::AsFd;

/// Kernel entropy for private candidate basenames; no credential or RNG state.
#[cfg(target_os = "macos")]
pub(crate) fn random(bytes: &mut [u8]) -> rustix::io::Result<usize> {
    if bytes.len() > 256 {
        return Err(rustix::io::Errno::INVAL);
    }
    // SAFETY: getentropy writes at most this live slice's length (<=256).
    // Darwin reports either complete initialization or an error; no fallback.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } == -1 {
        return Err(
            rustix::io::Errno::from_io_error(&std::io::Error::last_os_error())
                .unwrap_or(rustix::io::Errno::IO),
        );
    }
    Ok(bytes.len())
}

/// Both callers own a new empty file and retain allocator/allowance ownership.
pub(crate) fn allocate(file: &impl AsFd, bytes: u64) -> rustix::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        fs::fallocate(file, fs::FallocateFlags::empty(), 0, bytes)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let length = i64::try_from(bytes).map_err(|_| rustix::io::Errno::FBIG)?;
        let before = fs::fstat(file)?;
        if fs::FileType::from_raw_mode(before.st_mode) != fs::FileType::RegularFile
            || before.st_size != 0
        {
            return Err(rustix::io::Errno::INVAL);
        }
        let mut store = libc::fstore_t {
            fst_flags: libc::F_ALLOCATEALL,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: length,
            fst_bytesalloc: 0,
        };
        // SAFETY: the borrowed live writable descriptor and correctly aligned
        // target-libc fstore_t remain valid throughout this synchronous fcntl.
        // XNU copies the result back; no fallback to sparse EOF on failure.
        if unsafe { libc::fcntl(file.as_fd().as_raw_fd(), libc::F_PREALLOCATE, &mut store) } == -1 {
            return Err(
                rustix::io::Errno::from_io_error(&std::io::Error::last_os_error())
                    .unwrap_or(rustix::io::Errno::IO),
            );
        }
        if store.fst_bytesalloc < length {
            return Err(rustix::io::Errno::NOSPC);
        }
        fs::ftruncate(file, bytes)?;
        let after = fs::fstat(file)?;
        if after.st_size != length
            || u64::try_from(after.st_blocks)
                .ok()
                .and_then(|n| n.checked_mul(512))
                .is_none_or(|allocated| allocated < bytes)
        {
            return Err(rustix::io::Errno::NOSPC);
        }
        Ok(())
    }
}

/// Arbitrary external paths are not private StorageRoot children. Walk each
/// physical directory without imposing private-owner policy on source ancestors.
#[cfg(target_os = "macos")]
pub(crate) fn open_absolute(
    path: &std::path::Path,
    flags: fs::OFlags,
) -> rustix::io::Result<std::os::fd::OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;
    if !path.is_absolute() {
        return Err(rustix::io::Errno::INVAL);
    }
    // Path::components normalizes interior dots; refuse traversal before that
    // normalization, and retain the final slash's directory requirement.
    let raw = path.as_os_str().as_bytes();
    if raw.split(|&b| b == b'/').any(|part| part == b"..") {
        return Err(rustix::io::Errno::INVAL);
    }
    let flags = if raw.ends_with(b"/") || raw.ends_with(b"/.") {
        flags | fs::OFlags::DIRECTORY
    } else {
        flags
    };
    let mut parts = path.components().peekable();
    if parts.next() != Some(Component::RootDir) {
        return Err(rustix::io::Errno::INVAL);
    }
    let directory_flags =
        fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC | fs::OFlags::NOFOLLOW;
    let mut parent = fs::openat(fs::CWD, "/", directory_flags, fs::Mode::empty())?;
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return Err(rustix::io::Errno::INVAL);
        };
        let final_part = parts.peek().is_none();
        let next = fs::openat(
            &parent,
            name,
            if final_part {
                flags | fs::OFlags::NOFOLLOW
            } else {
                directory_flags
            },
            fs::Mode::empty(),
        )?;
        parent = next;
    }
    // A bare root is only appropriate for destination-parent directory opens.
    if path == std::path::Path::new("/") && !flags.contains(fs::OFlags::DIRECTORY) {
        return Err(rustix::io::Errno::INVAL);
    }
    Ok(parent)
}

#[cfg(target_os = "macos")]
pub(crate) fn local_apfs(file: &impl AsFd) -> rustix::io::Result<bool> {
    let stat = fs::fstatfs(file)?;
    let name = &stat.f_fstypename;
    Ok(name.iter().position(|&byte| byte == 0) == Some(4)
        && name[..4]
            .iter()
            .copied()
            .eq(b"apfs".iter().map(|&b| b as libc::c_char))
        && stat.f_flags & libc::MNT_LOCAL as u32 != 0)
}

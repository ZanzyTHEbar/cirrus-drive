//! Descriptor-based admission for account coordination directories.

use std::os::fd::OwnedFd;
use std::path::{Component, Path};

#[cfg(target_os = "linux")]
use rustix::fs::ResolveFlags;
use rustix::fs::{self, Mode, OFlags};
use rustix::process;

// Linux filesystem magic values for local filesystems with kernel-managed locks.
#[cfg(target_os = "linux")]
const LOCAL_FILESYSTEMS: &[u64] = &[
    0xef53,     // ext2/3/4
    0x58465342, // XFS
    0x9123683e, // Btrfs
    0x01021994, // tmpfs
    0xf2f52010, // F2FS
    0x2fc12fc1, // ZFS
];

#[cfg(target_os = "linux")]
fn open_dir(parent: &OwnedFd, name: impl rustix::path::Arg) -> rustix::io::Result<OwnedFd> {
    fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
}

#[cfg(target_os = "macos")]
fn open_dir(parent: &OwnedFd, name: impl rustix::path::Arg) -> rustix::io::Result<OwnedFd> {
    // Callers pass a single normal component, never a multi-component path.
    fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

#[cfg(target_os = "linux")]
fn open_root() -> rustix::io::Result<OwnedFd> {
    fs::openat2(
        fs::CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
}

#[cfg(target_os = "macos")]
fn open_root() -> rustix::io::Result<OwnedFd> {
    fs::openat(
        fs::CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

fn checked_dir(parent: &OwnedFd, name: &str, private: bool) -> Result<OwnedFd, &'static str> {
    checked_dir_in(parent, name, private, true)
}

fn checked_dir_in(
    parent: &OwnedFd,
    name: &str,
    private: bool,
    create: bool,
) -> Result<OwnedFd, &'static str> {
    let open = || open_dir(parent, name);
    let fd = match open() {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) if create => {
            match fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => fs::fsync(parent)
                    .map_err(|_| "cannot persist account coordination directory")?,
                Err(rustix::io::Errno::EXIST) => (),
                Err(_) => return Err("cannot create account coordination directory"),
            }
            open().map_err(|_| "cannot open account coordination directory")?
        }
        Err(_) => return Err("account coordination directory is unsafe"),
    };
    let stat = fs::fstat(&fd).map_err(|_| "cannot inspect account coordination directory")?;
    if stat.st_uid != process::geteuid().as_raw()
        || stat.st_mode & 0o022 != 0
        || (private && stat.st_mode & 0o7777 != 0o700)
    {
        return Err("account coordination directory has unsafe ownership or permissions");
    }
    #[cfg(target_os = "macos")]
    super::darwin_acl::check_directory(&fd)?;
    Ok(fd)
}

fn check_local_filesystem(fd: &OwnedFd) -> Result<(), &'static str> {
    let filesystem = fs::fstatfs(fd).map_err(|_| "cannot inspect account lock filesystem")?;
    #[cfg(target_os = "linux")]
    let supported = LOCAL_FILESYSTEMS.contains(&(filesystem.f_type as u64));
    #[cfg(target_os = "macos")]
    let supported = {
        // Compare only within the fixed array, requiring an exact NUL-terminated name.
        let name = &filesystem.f_fstypename;
        name.iter().position(|&byte| byte == 0) == Some(4)
            && name[..4]
                .iter()
                .copied()
                .eq(b"apfs".iter().map(|&byte| byte as libc::c_char))
            && filesystem.f_flags & libc::MNT_LOCAL as u32 != 0
    };
    if !supported {
        return Err(
            "account coordination requires a supported local filesystem; inspect the system home",
        );
    }
    Ok(())
}

fn check_home_ancestors(path: &Path) -> Result<OwnedFd, &'static str> {
    let parent = path.parent().ok_or("account owner's home is unsafe")?;
    let mut fd = open_root().map_err(|_| "cannot inspect account home ancestors")?;
    // These are descriptor metadata snapshots, not a freeze of the mount namespace.
    for component in parent.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                fd = open_dir(&fd, name).map_err(|_| "cannot inspect account home ancestors")?;
            }
            _ => return Err("account home has unsafe path components"),
        }
        let stat = fs::fstat(&fd).map_err(|_| "cannot inspect account home ancestors")?;
        if (stat.st_uid != 0 && stat.st_uid != process::geteuid().as_raw())
            || (stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0)
        {
            return Err("account home has unsafe writable ancestors");
        }
        #[cfg(target_os = "macos")]
        super::darwin_acl::check_directory(&fd)?;
    }
    Ok(fd)
}

pub(crate) fn state_dir(path: &Path) -> Result<OwnedFd, &'static str> {
    state_dir_in(path, true)
}

/// Revalidates an existing home hierarchy without creating or repairing it.
pub(crate) fn existing_state_dir(path: &Path) -> Result<OwnedFd, &'static str> {
    state_dir_in(path, false)
}

fn state_dir_in(path: &Path, create: bool) -> Result<OwnedFd, &'static str> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().any(|p| p == Component::ParentDir)
    {
        return Err("account owner's system home directory is unsafe");
    }
    let parent = check_home_ancestors(path)?;
    #[cfg(target_os = "linux")]
    drop(parent);
    #[cfg(target_os = "linux")]
    let home = fs::openat2(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    );
    #[cfg(target_os = "macos")]
    let home = open_dir(
        &parent,
        path.file_name()
            .ok_or("account owner's system home directory is unsafe")?,
    );
    let home = home.map_err(|_| "cannot safely open account owner's system home directory")?;
    let stat = fs::fstat(&home).map_err(|_| "cannot inspect account owner's home")?;
    if stat.st_uid != process::geteuid().as_raw() || stat.st_mode & 0o022 != 0 {
        return Err("account owner's home has unsafe ownership or permissions");
    }
    #[cfg(target_os = "macos")]
    super::darwin_acl::check_directory(&home)?;
    check_local_filesystem(&home)?;
    let local = checked_dir_in(&home, ".local", false, create)?;
    check_local_filesystem(&local)?;
    let state = checked_dir_in(&local, "state", false, create)?;
    check_local_filesystem(&state)?;
    let directory = checked_dir_in(&state, "cirrus-drive", true, create)?;
    check_local_filesystem(&directory)?;
    Ok(directory)
}

pub(crate) fn staging_dir(path: &Path) -> Result<OwnedFd, &'static str> {
    let state = state_dir(path)?;
    let staging = checked_dir(&state, "staging", true)?;
    check_local_filesystem(&staging)?;
    Ok(staging)
}

pub(crate) fn directory_snapshots_dir(path: &Path) -> Result<OwnedFd, &'static str> {
    let state = state_dir(path)?;
    let directory = checked_dir(&state, "directory-snapshots", true)?;
    check_local_filesystem(&directory)?;
    Ok(directory)
}

/// Existing, physical, private container; never creates or repairs ancestors.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn existing_container(path: &Path) -> Result<OwnedFd, &'static str> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
    {
        return Err("account storage container has unsafe path components");
    }
    let parent = check_home_ancestors(path)?;
    let container = open_dir(
        &parent,
        path.file_name()
            .ok_or("invalid account storage container")?,
    )
    .map_err(|_| "cannot safely open account storage container")?;
    let stat = fs::fstat(&container).map_err(|_| "cannot inspect account storage container")?;
    if stat.st_uid != process::geteuid().as_raw() || stat.st_mode & 0o7777 != 0o700 {
        return Err("account storage container has unsafe ownership or permissions");
    }
    #[cfg(target_os = "macos")]
    super::darwin_acl::check_directory(&container)?;
    check_local_filesystem(&container)?;
    Ok(container)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn container_state(container: &OwnedFd, create: bool) -> Result<OwnedFd, &'static str> {
    let directory = if create {
        checked_dir(container, "cirrus-drive", true)?
    } else {
        let directory = open_dir(container, "cirrus-drive")
            .map_err(|_| "retained account storage directory is unavailable")?;
        let stat = fs::fstat(&directory).map_err(|_| "cannot inspect account storage directory")?;
        if stat.st_uid != process::geteuid().as_raw() || stat.st_mode & 0o7777 != 0o700 {
            return Err("account storage directory has unsafe ownership or permissions");
        }
        #[cfg(target_os = "macos")]
        super::darwin_acl::check_directory(&directory)?;
        directory
    };
    check_local_filesystem(&directory)?;
    Ok(directory)
}

pub(crate) fn root_child(parent: &OwnedFd, name: &str) -> Result<OwnedFd, &'static str> {
    if !matches!(name, "staging" | "directory-snapshots") {
        return Err("invalid account storage subdirectory");
    }
    let directory = checked_dir(parent, name, true)?;
    check_local_filesystem(&directory)?;
    Ok(directory)
}

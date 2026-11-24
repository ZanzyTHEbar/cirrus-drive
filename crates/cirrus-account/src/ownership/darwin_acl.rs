//! Conservative Darwin filesystem-object ACL snapshots, without opening paths.
//!
//! Public ABI: Apple Libc sys/acl.h and XNU sys/{fcntl,stat,cdefs}.h.
//! Import/iteration/flag semantics reviewed against Libc revision
//! 71bbe350ab79eef58113991d817ccc6165061a64. Composite flag queries are
//! implementation-coupled, not a documented future-library guarantee. Native
//! SDK/runtime qualification is still required; errors must remain refusals.

use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{self, NonNull};

// Positive-only C enums use unsigned C int; selectors/return values use int.
const FILESEC_ACL: c_uint = 5;
const ACL_EXTENDED_DENY: c_uint = 2;
const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = -1;
const ACL_MAX_ENTRIES: usize = 128;
const ACL_FLAG_NO_INHERIT: c_uint = 1 << 17;
const ACL_ENTRY_FLAGS: c_uint = (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8);

unsafe extern "C" {
    fn filesec_init() -> *mut c_void;
    fn filesec_free(filesec: *mut c_void);
    fn filesec_query_property(filesec: *mut c_void, property: c_uint, valid: *mut c_int) -> c_int;
    fn filesec_get_property(filesec: *mut c_void, property: c_uint, value: *mut c_void) -> c_int;
    // Modern stat uses INODE64 on x86_64, but no suffix on arm64.
    #[cfg_attr(target_arch = "x86_64", link_name = "fstatx_np$INODE64")]
    fn fstatx_np(fd: c_int, stat: *mut libc::stat, filesec: *mut c_void) -> c_int;
    #[cfg_attr(target_arch = "x86_64", link_name = "lstatx_np$INODE64")]
    fn lstatx_np(path: *const c_char, stat: *mut libc::stat, filesec: *mut c_void) -> c_int;
    fn acl_free(acl: *mut c_void) -> c_int;
    fn acl_get_entry(acl: *mut c_void, selector: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_uint) -> c_int;
    fn acl_get_flagset_np(object: *mut c_void, flags: *mut *mut c_void) -> c_int;
    fn acl_get_flag_np(flags: *mut c_void, mask: c_uint) -> c_int;
}

struct FileSecurity(NonNull<c_void>);

impl Drop for FileSecurity {
    fn drop(&mut self) {
        // SAFETY: uniquely owns the nonnull filesec_init allocation, exactly once.
        unsafe { filesec_free(self.0.as_ptr()) };
    }
}

struct Acl(NonNull<c_void>);

impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: uniquely owns the filesec_get_property allocated ACL clone;
        // neither null nor the removal sentinel can enter this owner.
        unsafe { acl_free(self.0.as_ptr()) };
    }
}

/// Refuses every ALLOW (including owner/inherit-only), unknown tag/flag or error.
/// Does not repair ACLs. Inherited ALLOWs on newly created directories also fail.
pub(crate) fn check_directory(fd: &OwnedFd) -> Result<(), &'static str> {
    checked_fd(fd).map(|_| ())
}

/// Borrows the caller's legitimate descriptor; never duplicates or closes it.
pub(crate) fn checked_fd(fd: &impl AsFd) -> Result<libc::stat, &'static str> {
    snapshot(|stat, security| {
        // SAFETY: borrowed live fd and snapshot-owned writable outputs.
        unsafe { fstatx_np(fd.as_fd().as_raw_fd(), stat, security) }
    })
}

/// Admission before private payload read/write, including inherited ACLs on
/// exclusively created 0600 files. The caller retains ownership/cleanup guards.
pub(crate) fn check_file(fd: &impl AsFd) -> Result<(), &'static str> {
    let stat = checked_fd(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err("private file has unsafe ownership or permissions");
    }
    Ok(())
}

/// Best-effort cleanup ONLY after our successful exclusive create, before any
/// payload write/allocation. Refusal may be caused by the inherited ACL itself,
/// so cleanup must not require ACL admission. Uncertain objects are left alone.
pub(crate) fn discard_unwritten_candidate(directory: &impl AsFd, name: &str, writer: &impl AsFd) {
    use rustix::{fs, process};

    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return;
    }
    let private_empty = |stat: &fs::Stat| {
        fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::RegularFile
            && stat.st_uid == process::geteuid().as_raw()
            && stat.st_mode & 0o7777 == 0o600
            && stat.st_nlink == 1
            && stat.st_size == 0
    };
    if let (Ok(held), Ok(named)) = (
        fs::fstat(writer),
        fs::statat(directory, name, fs::AtFlags::SYMLINK_NOFOLLOW),
    ) && private_empty(&held)
        && private_empty(&named)
        && (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
    {
        let _ = fs::unlinkat(directory, name, fs::AtFlags::empty());
    }
}

/// No-follow applies to the final component only. Callers must first validate
/// the physical, private ancestors and compare this metadata with held-dir statat.
pub(crate) fn checked_path(path: &Path) -> Result<libc::stat, &'static str> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "invalid ACL path")?;
    snapshot(|stat, security| {
        // SAFETY: NUL-admitted live path and snapshot-owned writable outputs.
        unsafe { lstatx_np(path.as_ptr(), stat, security) }
    })
}

fn snapshot(
    read: impl FnOnce(*mut libc::stat, *mut c_void) -> c_int,
) -> Result<libc::stat, &'static str> {
    // SAFETY: returns an opaque owned allocation or null, no arguments.
    let security = FileSecurity(
        NonNull::new(unsafe { filesec_init() }).ok_or("cannot allocate directory ACL snapshot")?,
    );
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    // Reserved fields start initialized; no stat is read before C success.
    if read(stat.as_mut_ptr(), security.0.as_ptr()) != 0 {
        return Err("cannot snapshot directory ACL");
    }
    validate_acl(&security)?;
    // SAFETY: successful public stat ABI call filled real target stat storage.
    Ok(unsafe { stat.assume_init() })
}

fn validate_acl(security: &FileSecurity) -> Result<(), &'static str> {
    let mut valid = 0;
    // SAFETY: live filesec from the successful snapshot and writable C int.
    if unsafe { filesec_query_property(security.0.as_ptr(), FILESEC_ACL, &mut valid) } != 0 {
        return Err("cannot query directory ACL snapshot");
    }
    // Apple's implementation returns a bitmask (FS_VALID_ACL = 32), not bool 1.
    // Only this successful snapshot/query can establish positive absence.
    if valid == 0 {
        return Ok(());
    }
    let mut raw = ptr::null_mut::<c_void>();
    // SAFETY: property writes an acl_t (pointer), allocating a separate clone via
    // acl_copy_int_native. It is not a borrow of filesec's raw buffer.
    if unsafe {
        filesec_get_property(
            security.0.as_ptr(),
            FILESEC_ACL,
            (&mut raw as *mut *mut c_void).cast(),
        )
    } != 0
    {
        return Err("cannot import directory ACL snapshot");
    }
    // Public fcntl.h _FILESEC_REMOVE_ACL is (void *)1, NOT (void *)-1.
    // Also refuse the -1 sentinel defensively; neither may be freed/dereferenced.
    if raw.is_null() || raw as usize == 1 || raw as usize == usize::MAX {
        return Err("invalid directory ACL snapshot");
    }
    let acl = Acl(NonNull::new(raw).ok_or("invalid directory ACL snapshot")?);
    check_flags(acl.0, ACL_FLAG_NO_INHERIT)?; // DEFER_INHERIT and unknown bits refuse.
    let mut selector = ACL_FIRST_ENTRY;
    for count in 0..=ACL_MAX_ENTRIES {
        let mut entry = ptr::null_mut();
        // SAFETY: valid untouched imported ACL; only FIRST then NEXT selectors.
        let result = unsafe { acl_get_entry(acl.0.as_ptr(), selector, &mut entry) };
        if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            // Apple importer validates magic and calls acl_init(count), which
            // bounds count to 128 and initializes iterator/entries. With this
            // owned, unmodified ACL and valid selectors, EINVAL is exhaustion,
            // including FIRST on an imported empty ACL; not retrieval fallback.
            return Ok(());
        }
        if result != 0 || count == ACL_MAX_ENTRIES {
            return Err("cannot enumerate directory ACL");
        }
        let entry = NonNull::new(entry).ok_or("invalid directory ACL entry")?;
        let mut tag = 0;
        // SAFETY: entry is borrowed from the live owned ACL, never freed/escaped.
        if unsafe { acl_get_tag_type(entry.as_ptr(), &mut tag) } != 0 || tag != ACL_EXTENDED_DENY {
            return Err("directory ACL grants access or has an unknown entry");
        }
        check_flags(entry, ACL_ENTRY_FLAGS)?;
        selector = ACL_NEXT_ENTRY;
    }
    Err("cannot enumerate directory ACL")
}

// Only called with a live ACL or one of its borrowed entries. Flagsets are
// borrowed and remain entirely inside this call; never acl_free them.
fn check_flags(object: NonNull<c_void>, allowed: c_uint) -> Result<(), &'static str> {
    let mut flags = ptr::null_mut();
    // SAFETY: live imported ACL/entry with initialized magic and pointer output.
    if unsafe { acl_get_flagset_np(object.as_ptr(), &mut flags) } != 0 || flags.is_null() {
        return Err("cannot inspect directory ACL flags");
    }
    // SAFETY: valid borrowed flagset. Apple acl_flag.c implements arbitrary mask
    // intersection, so the complement detects ALL bits outside this known set.
    // c_uint avoids invalid Rust enum discriminants. Future rejection fails closed.
    if unsafe { acl_get_flag_np(flags, !allowed) } != 0 {
        return Err("directory ACL has unsupported flags");
    }
    Ok(())
}

//! Private, synchronous retained-content ABI for the trusted in-process Swift adapter.
//! See macos/RetainedCore/include/CirrusRetained.h for pointer/thread contracts.

use std::ffi::{CString, c_char, c_void};
use std::io;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, ThreadId};

use core_foundation::{
    array::{CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex},
    base::{CFGetTypeID, CFRelease, CFTypeRef, TCFType},
    string::{CFString, CFStringGetTypeID},
};
use serde::Serialize;

use crate::{Accounts, FileVersion, MountBinding, account_storage};

mod application;
mod dispatcher;
mod mutation;

const OK: i32 = 0;
const INVALID: i32 = 1;
const CANCELLED: i32 = 2;
const UNAVAILABLE: i32 = 3;
const STALE: i32 = 4;
const CAPACITY: i32 = 5;
const INTERNAL: i32 = 6;
const PAGE_EXPIRED: i32 = 7;
const ANCHOR_EXPIRED: i32 = 8;
const SIGNIN_FINISHING: i32 = 9;
const RETAINED_SPACE_NOT_READY: i32 = 10;
const MUTATION_PENDING: i32 = 11;
const MUTATION_CONFLICT: i32 = 12;
const MUTATION_UNCERTAIN: i32 = 13;
const MUTATION_UNSUPPORTED: i32 = 14;
const CONFIRMED_DELETED: i32 = 15;
const MAX_TEXT: usize = 16 * 1024;
const MAX_PAGE: usize = 256 * 1024;
const CHUNK: u64 = 131_072;
type Result<T> = std::result::Result<T, i32>;

fn account_error(error: crate::AccountError) -> i32 {
    if error.is_staging_full() {
        CAPACITY
    } else {
        UNAVAILABLE
    }
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTaskCreateFromSelf(allocator: *const c_void) -> CFTypeRef;
    fn SecTaskCopyValueForEntitlement(
        task: CFTypeRef,
        entitlement: core_foundation::string::CFStringRef,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
}

unsafe extern "C" {
    // Fixed implementation in RetainedCore.swift, not a caller-supplied function
    // pointer/path. Rust independently checks both entitlements before this call.
    // This is a trusted same-process adapter boundary, not an IPC security boundary.
    fn cirrus_native_container_url(group: *const c_char, out: *mut u8, capacity: usize) -> usize;
}

struct CfOwned(CFTypeRef);
impl Drop for CfOwned {
    fn drop(&mut self) {
        // SAFETY: each instance owns a nonnull Create/Copy-rule CF object.
        unsafe { CFRelease(self.0) };
    }
}

fn entitlement_contains(task: &CfOwned, key: &str, expected: &str) -> bool {
    let key = CFString::new(key);
    // SAFETY: task/key are live framework objects; no CFError is requested.
    let value = unsafe {
        SecTaskCopyValueForEntitlement(task.0, key.as_concrete_TypeRef(), std::ptr::null_mut())
    };
    if value.is_null() {
        return false;
    }
    let value = CfOwned(value);
    // SAFETY: dynamically check types before using array/string APIs. The array
    // retains its borrowed elements until value drops.
    unsafe {
        if CFGetTypeID(value.0) != CFArrayGetTypeID() {
            return false;
        }
        let count = CFArrayGetCount(value.0.cast());
        if !(0..=1024).contains(&count) {
            return false;
        }
        for index in 0..count {
            let element = CFArrayGetValueAtIndex(value.0.cast(), index);
            if !element.is_null() && CFGetTypeID(element) == CFStringGetTypeID() {
                let string = CFString::wrap_under_get_rule(element.cast());
                if string.to_string() == expected {
                    return true;
                }
            }
        }
    }
    false
}

fn admitted_core(path: &Path, keychain: Option<&str>) -> Result<Arc<Core>> {
    let root =
        account_storage::StorageRoot::admit_app_group_directory(path).map_err(account_error)?;
    let runtime = cirrus_runtime::RuntimeDir::open(path).map_err(|_| UNAVAILABLE)?;
    let mut accounts = match keychain {
        Some(group) => Accounts::with_keychain(runtime, group).map_err(|_| INVALID)?,
        None => Accounts::new(runtime),
    };
    // Private crate capability integration, never a public arbitrary-path Mac API.
    accounts.storage = account_storage::StorageSelection::Explicit(root);
    Ok(Arc::new(Core { accounts }))
}

struct Core {
    accounts: Accounts,
}
struct Bound {
    core: Arc<Core>,
    binding: MountBinding,
}
#[cfg(test)]
struct Listing {
    bound: Arc<Bound>,
    snapshot: crate::DirectorySnapshot,
}
struct Version {
    bound: Arc<Bound>,
    version: FileVersion,
}
struct NativeRequest {
    cancelled: AtomicBool,
    background: std::sync::Mutex<Option<Arc<crate::sync::BackgroundAdmission>>>,
}
enum Value {
    Core(Arc<Core>),
    Bound(Arc<Bound>),
    #[cfg(test)]
    Listing(Listing),
    Version(Version),
    Catalog {
        bound: Arc<Bound>,
        catalog: crate::provider_catalog::Catalog,
    },
    Request(NativeRequest),
    SignIn(crate::SignIn),
    Spaces(Vec<(String, String)>),
    Dispatcher(dispatcher::Dispatcher),
}
struct Handle {
    owner: ThreadId,
    value: Value,
}
impl Handle {
    fn boxed(value: Value) -> *mut c_void {
        Box::into_raw(Box::new(Self {
            owner: thread::current().id(),
            value,
        }))
        .cast()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Text {
    data: *const u8,
    len: usize,
}

// Raw pointers must still satisfy the C contract: null/length checks cannot
// establish allocation provenance, liveness, alignment or exclusive access.
unsafe fn text<'a>(value: Text) -> Result<&'a str> {
    if value.len > MAX_TEXT || (value.len != 0 && value.data.is_null()) {
        return Err(INVALID);
    }
    let bytes = if value.len == 0 {
        &[]
    } else {
        // SAFETY: caller guarantees readable bytes for the duration of this call.
        unsafe { std::slice::from_raw_parts(value.data, value.len) }
    };
    let value = std::str::from_utf8(bytes).map_err(|_| INVALID)?;
    if value.chars().any(char::is_control) {
        return Err(INVALID);
    }
    Ok(value)
}

#[cfg(test)]
unsafe fn path(value: Text) -> Result<Vec<String>> {
    // SAFETY: forwarded unchanged from the ABI caller.
    let path: Vec<String> = serde_json::from_str(unsafe { text(value)? }).map_err(|_| INVALID)?;
    if path.len() > 128
        || path.iter().any(|s| {
            s.is_empty()
                || s == "."
                || s == ".."
                || s.contains('/')
                || s.chars().any(char::is_control)
        })
    {
        return Err(INVALID);
    }
    Ok(path)
}

unsafe fn handle<'a>(pointer: *mut c_void) -> Result<&'a Handle> {
    if pointer.is_null() {
        return Err(INVALID);
    }
    // SAFETY: caller supplies a live, aligned, unclosed handle from this library.
    let handle = unsafe { &*pointer.cast::<Handle>() };
    if handle.owner != thread::current().id() {
        return Err(INVALID);
    }
    Ok(handle)
}

unsafe fn check_request(pointer: *mut c_void) -> Result<()> {
    if pointer.is_null() {
        return Err(INVALID);
    }
    // SAFETY: only Request may be shared for concurrent cancellation; caller
    // keeps it alive until every use has joined, including cancel callers.
    match &unsafe { &*pointer.cast::<Handle>() }.value {
        Value::Request(request) if request.cancelled.load(Ordering::Acquire) => Err(CANCELLED),
        Value::Request(_) => Ok(()),
        _ => Err(INVALID),
    }
}

unsafe fn output(pointer: *mut *mut c_void, value: Value) -> Result<()> {
    if pointer.is_null() {
        return Err(INVALID);
    }
    // SAFETY: caller provides writable pointer storage, separate from all inputs.
    unsafe { *pointer = Handle::boxed(value) };
    Ok(())
}

fn boundary(body: impl FnOnce() -> Result<()>) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(Ok(())) => OK,
        Ok(Err(status)) => status,
        Err(_) => INTERNAL,
    }
}

fn catalog_error(error: crate::provider_catalog::Error) -> i32 {
    use crate::provider_catalog::Error;
    match error {
        Error::Unavailable => UNAVAILABLE,
        Error::RetainedSpaceNotReady => RETAINED_SPACE_NOT_READY,
        Error::PageExpired => PAGE_EXPIRED,
        Error::AnchorExpired => ANCHOR_EXPIRED,
        Error::VersionMismatch => STALE,
        Error::Capacity => CAPACITY,
        Error::Cancelled => CANCELLED,
        Error::Internal => INTERNAL,
        Error::Deleted => CONFIRMED_DELETED,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_catalog_resume(
    pointer: *mut c_void,
    domain: Text,
    out: *mut *mut c_void,
) -> i32 {
    // SAFETY: same owner-thread/handle/span/output contract as catalog_open.
    boundary(|| unsafe {
        if out.is_null() {
            return Err(INVALID);
        }
        *out = std::ptr::null_mut();
        let Value::Core(core) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        let domain = text(domain)?;
        let (bound, catalog) = resume_catalog(core, domain)?;
        output(out, Value::Catalog { bound, catalog })
    })
}

fn resume_catalog(
    core: &Arc<Core>,
    domain: &str,
) -> Result<(Arc<Bound>, crate::provider_catalog::Catalog)> {
    let root = core.accounts.storage_root().map_err(account_error)?;
    core.accounts
        .storage
        .validate(&root)
        .map_err(account_error)?;
    let (instance, issuer, subject, space, epoch) =
        crate::provider_catalog::Catalog::stored(&root, domain).map_err(catalog_error)?;
    // stored() CLOSED its connection before helpers reopen state.db.
    let binding = core
        .accounts
        .bind_offline_space_in(root, &instance, &space)
        .map_err(account_error)?;
    if (
        &binding.instance,
        &binding.issuer,
        &binding.subject,
        &binding.space,
    ) != (&instance, &issuer, &subject, &space)
    {
        return Err(UNAVAILABLE);
    }
    let catalog = crate::provider_catalog::Catalog::resume(&binding, domain, &epoch)
        .map_err(catalog_error)?;
    Ok((
        Arc::new(Bound {
            core: core.clone(),
            binding,
        }),
        catalog,
    ))
}

// One bounded copied JSON result, with explicit operation and typed status.
// Inputs contain only identifiers/tokens, never caller-authored item metadata.
#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_catalog_read(
    pointer: *mut c_void,
    operation: u32,
    identifier: Text,
    argument: Text,
    request: *mut c_void,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    // SAFETY: all spans are caller-owned and nonaliasing; only a live Request's
    // atomic cancellation may be concurrent. No borrowed engine bytes escape.
    boundary(|| unsafe {
        if buffer.is_null() || capacity != MAX_PAGE || written.is_null() {
            return Err(INVALID);
        }
        *written = 0;
        check_request(request)?;
        let Value::Catalog { bound, catalog } = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        bound
            .core
            .accounts
            .storage
            .validate(&bound.binding.root)
            .map_err(account_error)?;
        let identifier = text(identifier)?;
        let argument = text(argument)?;
        let bytes = std::slice::from_raw_parts_mut(buffer, capacity);
        let mut writer = io::Cursor::new(bytes);
        match operation {
            0 => {
                let token = catalog
                    .capture(identifier, argument, || check_request(request).is_err())
                    .map_err(catalog_error)?;
                serde_json::to_writer(&mut writer, &token).map_err(|_| CAPACITY)?;
            }
            1 => serde_json::to_writer(
                &mut writer,
                &catalog.page(identifier, argument).map_err(catalog_error)?,
            )
            .map_err(|_| CAPACITY)?,
            2 => serde_json::to_writer(
                &mut writer,
                &catalog.lookup(identifier).map_err(catalog_error)?,
            )
            .map_err(|_| CAPACITY)?,
            3 => serde_json::to_writer(
                &mut writer,
                &catalog
                    .changes(
                        if argument.is_empty() {
                            None
                        } else {
                            Some(argument)
                        },
                        || check_request(request).is_err(),
                    )
                    .map_err(catalog_error)?,
            )
            .map_err(|_| CAPACITY)?,
            _ => return Err(INVALID),
        }
        check_request(request)?;
        *written = writer.position() as usize;
        Ok(())
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_catalog_open_version(
    pointer: *mut c_void,
    id: Text,
    etag: Text,
    size: u64,
    request: *mut c_void,
    out: *mut *mut c_void,
) -> i32 {
    // SAFETY: caller retains all same-thread handles and input/output spans
    // through return. The returned child owns its binding and exact version.
    boundary(|| unsafe {
        if out.is_null() {
            return Err(INVALID);
        }
        *out = std::ptr::null_mut();
        check_request(request)?;
        let Value::Catalog { bound, catalog } = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        bound
            .core
            .accounts
            .storage
            .validate(&bound.binding.root)
            .map_err(account_error)?;
        let version = catalog
            .open_version(&bound.core.accounts, text(id)?, text(etag)?, size)
            .map_err(catalog_error)?;
        check_request(request)?;
        output(
            out,
            Value::Version(Version {
                bound: bound.clone(),
                version,
            }),
        )
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_open(
    group: Text,
    keychain: Text,
    out: *mut *mut c_void,
) -> i32 {
    boundary(|| {
        // SAFETY: all pointer accesses in this operation follow the header contract.
        unsafe {
            if out.is_null() {
                return Err(INVALID);
            }
            *out = std::ptr::null_mut();
            let group = text(group)?;
            let keychain = text(keychain)?;
            if group.is_empty() || keychain.is_empty() {
                return Err(INVALID);
            }
            let task = SecTaskCreateFromSelf(std::ptr::null());
            if task.is_null() {
                return Err(UNAVAILABLE);
            }
            let task = CfOwned(task);
            if !entitlement_contains(&task, "com.apple.security.application-groups", group)
                || !entitlement_contains(&task, "keychain-access-groups", keychain)
            {
                return Err(UNAVAILABLE);
            }
            let group = CString::new(group).map_err(|_| INVALID)?;
            let mut bytes = [0u8; 4096];
            let length =
                cirrus_native_container_url(group.as_ptr(), bytes.as_mut_ptr(), bytes.len());
            if length == 0 || length > bytes.len() {
                return Err(UNAVAILABLE);
            }
            let path = std::str::from_utf8(&bytes[..length]).map_err(|_| UNAVAILABLE)?;
            output(
                out,
                Value::Core(admitted_core(Path::new(path), Some(keychain))?),
            )
        }
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_request(out: *mut *mut c_void) -> i32 {
    boundary(|| {
        // SAFETY: caller supplies writable handle storage.
        unsafe {
            if out.is_null() {
                return Err(INVALID);
            }
            *out = std::ptr::null_mut();
            output(
                out,
                Value::Request(NativeRequest {
                    cancelled: AtomicBool::new(false),
                    background: std::sync::Mutex::new(None),
                }),
            )
        }
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_cancel(pointer: *mut c_void) -> i32 {
    boundary(|| {
        if pointer.is_null() {
            return Err(INVALID);
        }
        // SAFETY: caller shares only a live Request, never closes it concurrently.
        match &unsafe { &*pointer.cast::<Handle>() }.value {
            Value::Request(request) => {
                request.cancelled.store(true, Ordering::Release);
                if let Some(control) = request.background.lock().map_err(|_| INTERNAL)?.as_ref() {
                    control.pause(true);
                }
                Ok(())
            }
            _ => Err(INVALID),
        }
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_close(pointer: *mut c_void) -> i32 {
    boundary(|| {
        // SAFETY: close is exclusive and called once, on the creating OS thread.
        unsafe {
            handle(pointer)?;
            drop(Box::from_raw(pointer.cast::<Handle>()));
        }
        Ok(())
    })
}

// Test-only path adapter for the original native retained-content assertions.
// Production opens exact versions through the durable catalog.
#[cfg(test)]
#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_fixture_bind(
    pointer: *mut c_void,
    instance: Text,
    space: Text,
    out: *mut *mut c_void,
) -> i32 {
    boundary(|| {
        // SAFETY: header requires live same-thread handles and valid input/output spans.
        unsafe {
            if out.is_null() {
                return Err(INVALID);
            }
            *out = std::ptr::null_mut();
            let Value::Core(core) = &handle(pointer)?.value else {
                return Err(INVALID);
            };
            let binding = core
                .accounts
                .bind_offline_space(text(instance)?, text(space)?)
                .map_err(account_error)?;
            output(
                out,
                Value::Bound(Arc::new(Bound {
                    core: core.clone(),
                    binding,
                })),
            )
        }
    })
}

#[cfg(test)]
#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_fixture_list(
    pointer: *mut c_void,
    path_json: Text,
    request: *mut c_void,
    out: *mut *mut c_void,
) -> i32 {
    boundary(|| {
        // SAFETY: caller guarantees the pointer/handle contracts.
        unsafe {
            if out.is_null() {
                return Err(INVALID);
            }
            *out = std::ptr::null_mut();
            check_request(request)?;
            let Value::Bound(bound) = &handle(pointer)?.value else {
                return Err(INVALID);
            };
            let snapshot = bound
                .core
                .accounts
                .mount_directory(
                    &bound.binding.instance,
                    &bound.binding,
                    &path(path_json)?,
                    "",
                )
                .map_err(account_error)?;
            check_request(request)?;
            output(
                out,
                Value::Listing(Listing {
                    bound: bound.clone(),
                    snapshot,
                }),
            )
        }
    })
}

#[cfg(test)]
#[derive(Serialize)]
struct Metadata<'a> {
    cookie: u64,
    name: &'a str,
    id: &'a str,
    etag: Option<&'a str>,
    size: Option<u64>,
    directory: bool,
}

#[cfg(test)]
#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_fixture_page(
    pointer: *mut c_void,
    after: u64,
    request: *mut c_void,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
    next: *mut u64,
) -> i32 {
    boundary(|| {
        // SAFETY: caller provides distinct writable output spans and live handles.
        unsafe {
            if buffer.is_null() || capacity != MAX_PAGE || written.is_null() || next.is_null() {
                return Err(INVALID);
            }
            *written = 0;
            *next = after;
            check_request(request)?;
            let Value::Listing(listing) = &handle(pointer)?.value else {
                return Err(INVALID);
            };
            listing
                .bound
                .core
                .accounts
                .verify_offline_mount(&listing.bound.binding)
                .map_err(account_error)?;
            let page = listing.snapshot.page(after).map_err(account_error)?;
            let mut metadata = Vec::with_capacity(page.len());
            for (cookie, entry) in &page {
                if entry.name().len() > MAX_TEXT
                    || entry.id().len() > MAX_TEXT
                    || entry.etag().is_some_and(|s| s.len() > MAX_TEXT)
                {
                    return Err(UNAVAILABLE);
                }
                metadata.push(Metadata {
                    cookie: *cookie,
                    name: entry.name(),
                    id: entry.id(),
                    etag: entry.etag(),
                    size: entry.size(),
                    directory: entry.is_directory(),
                });
            }
            // Serialize into a bounded caller-owned buffer, never an unbounded
            // metadata Vec. serde IO errors here mean the fixed page did not fit.
            let output = std::slice::from_raw_parts_mut(buffer, capacity);
            let mut writer = io::Cursor::new(output);
            serde_json::to_writer(&mut writer, &metadata).map_err(|_| CAPACITY)?;
            check_request(request)?;
            *written = writer.position() as usize;
            *next = page.last().map_or(after, |(cookie, _)| *cookie);
            Ok(())
        }
    })
}

#[cfg(test)]
#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_fixture_version(
    pointer: *mut c_void,
    path_json: Text,
    id: Text,
    etag: Text,
    size: u64,
    request: *mut c_void,
    out: *mut *mut c_void,
) -> i32 {
    boundary(|| {
        // SAFETY: caller supplies live handles, readable spans, writable out.
        unsafe {
            if out.is_null() {
                return Err(INVALID);
            }
            *out = std::ptr::null_mut();
            check_request(request)?;
            let Value::Bound(bound) = &handle(pointer)?.value else {
                return Err(INVALID);
            };
            let version = bound
                .core
                .accounts
                .mount_open_file(
                    &bound.binding.instance,
                    &bound.binding,
                    &path(path_json)?,
                    text(id)?,
                )
                .map_err(account_error)?;
            if version.etag() != text(etag)? || version.size() != size {
                return Err(STALE);
            }
            check_request(request)?;
            output(
                out,
                Value::Version(Version {
                    bound: bound.clone(),
                    version,
                }),
            )
        }
    })
}

unsafe fn verified<'a>(pointer: *mut c_void, request: *mut c_void) -> Result<&'a Version> {
    // SAFETY: forwarded live handle contracts.
    unsafe {
        check_request(request)?;
        let Value::Version(version) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        version
            .bound
            .core
            .accounts
            .verify_file(&version.bound.binding, &version.version)
            .map_err(account_error)?;
        check_request(request)?;
        Ok(version)
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_verify(pointer: *mut c_void, request: *mut c_void) -> i32 {
    boundary(|| {
        // SAFETY: caller keeps both handles live.
        unsafe { verified(pointer, request)? };
        Ok(())
    })
}

fn write_error(error: io::Error) -> i32 {
    match error.raw_os_error() {
        Some(libc::ENOSPC | libc::EDQUOT | libc::EFBIG) => CAPACITY,
        _ => UNAVAILABLE,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_materialize(
    pointer: *mut c_void,
    fd: i32,
    request: *mut c_void,
) -> i32 {
    boundary(|| {
        // SAFETY: fd is caller-owned, exclusive and remains open throughout.
        // No File/OwnedFd takes ownership of it or closes an engine descriptor.
        unsafe {
            let version = verified(pointer, request)?;
            if fd < 0 {
                return Err(INVALID);
            }
            let borrowed = std::os::fd::BorrowedFd::borrow_raw(fd);
            // Reuse the existing conservative ACL snapshot without dup/open/
            // close. A newly inherited ALLOW is refused before private bytes.
            let stat =
                crate::ownership::darwin_acl::checked_fd(&borrowed).map_err(|_| UNAVAILABLE)?;
            if stat.st_mode & libc::S_IFMT != libc::S_IFREG
                || stat.st_size != 0
                || stat.st_nlink != 1
                || stat.st_uid != libc::geteuid()
                || stat.st_mode & 0o7777 != 0o600
                || version.version.size > i64::MAX as u64
            {
                return Err(INVALID);
            }
            let mut offset = 0;
            while offset < version.version.size {
                check_request(request)?;
                let length = CHUNK.min(version.version.size - offset) as u32;
                let bytes = version
                    .bound
                    .core
                    .accounts
                    .read_range(&version.bound.binding, &version.version, offset, length)
                    .map_err(account_error)?;
                if bytes.len() != length as usize {
                    return Err(UNAVAILABLE);
                }
                let mut written = 0;
                while written < bytes.len() {
                    check_request(request)?;
                    let count = libc::pwrite(
                        fd,
                        bytes[written..].as_ptr().cast(),
                        bytes.len() - written,
                        (offset + written as u64) as libc::off_t,
                    );
                    if count < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(write_error(error));
                    }
                    if count == 0 {
                        return Err(UNAVAILABLE);
                    }
                    written += count as usize;
                }
                offset += bytes.len() as u64;
            }
            // Empty files deliberately never request a zero-length engine range.
            if libc::fsync(fd) != 0 {
                return Err(write_error(io::Error::last_os_error()));
            }
            verified(pointer, request)?;
            Ok(())
        }
    })
}

#[cfg(test)]
mod acceptance;

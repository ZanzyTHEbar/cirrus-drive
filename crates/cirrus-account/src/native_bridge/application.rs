//! Authenticated application operations, separate from retained-only provider reads.
use super::*;

type OpenBrowser = unsafe extern "C" fn(*mut c_void, Text) -> i32;

struct Browser {
    callback: OpenBrowser,
    context: *mut c_void,
}
impl crate::browser::Browser for Browser {
    fn open(&self, url: &str) -> io::Result<()> {
        if url.len() > MAX_TEXT {
            return Err(io::Error::other("authorization URL exceeds native bound"));
        }
        // SAFETY: synchronous callback/context borrowed through connect only.
        // Never format, log, serialize or retain this one-time URL.
        let status = unsafe {
            (self.callback)(
                self.context,
                Text {
                    data: url.as_ptr(),
                    len: url.len(),
                },
            )
        };
        if status == OK {
            Ok(())
        } else {
            Err(io::Error::other("native browser unavailable"))
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_application_attempt(out: *mut *mut c_void) -> i32 {
    boundary(|| unsafe {
        if out.is_null() {
            return Err(INVALID);
        }
        *out = std::ptr::null_mut();
        output(out, Value::SignIn(crate::SignIn::default()))
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_application_cancel(pointer: *mut c_void) -> i32 {
    boundary(|| unsafe {
        if pointer.is_null() {
            return Err(INVALID);
        }
        // Only this SignIn's cancellation fence may cross threads. Owner holds
        // its lifetime until callers have joined, exactly like Request.
        let Value::SignIn(attempt) = &(*pointer.cast::<Handle>()).value else {
            return Err(INVALID);
        };
        if attempt.cancel_pending() {
            Ok(())
        } else {
            Err(SIGNIN_FINISHING)
        }
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_application_connect(
    pointer: *mut c_void,
    instance: Text,
    attempt: *mut c_void,
    callback: Option<OpenBrowser>,
    context: *mut c_void,
) -> i32 {
    boundary(|| unsafe {
        let Value::Core(core) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        let Value::SignIn(attempt) = &handle(attempt)?.value else {
            return Err(INVALID);
        };
        let browser = Browser {
            callback: callback.ok_or(INVALID)?,
            context,
        };
        attempt.check().map_err(|_| CANCELLED)?;
        let result = core
            .accounts
            .connect(text(instance)?, None, &browser, attempt);
        // A cancelled pending attempt is known, not inferred from an error string.
        if attempt.is_cancelled() {
            return Err(CANCELLED);
        }
        result.map_err(account_error)
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_application_spaces(
    pointer: *mut c_void,
    instance: Text,
    out: *mut *mut c_void,
) -> i32 {
    boundary(|| unsafe {
        if out.is_null() {
            return Err(INVALID);
        }
        *out = std::ptr::null_mut();
        let Value::Core(core) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        let spaces = core
            .accounts
            .spaces(text(instance)?)
            .map_err(account_error)?;
        // Engine bounds its remote response; additionally bound retained native
        // metadata independently. No unbounded Vec escapes to the consumer.
        if spaces.len() > 4096
            || spaces
                .iter()
                .any(|s| s.id.len() > MAX_TEXT || s.name.len() > MAX_TEXT)
        {
            return Err(CAPACITY);
        }
        output(
            out,
            Value::Spaces(spaces.into_iter().map(|s| (s.id, s.name)).collect()),
        )
    })
}

#[derive(Serialize)]
struct SpaceMetadata<'a> {
    id: &'a str,
    name: &'a str,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_application_space_page(
    pointer: *mut c_void,
    offset: usize,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
    next: *mut usize,
) -> i32 {
    boundary(|| unsafe {
        if written.is_null() || next.is_null() {
            return Err(INVALID);
        }
        *written = 0;
        *next = offset;
        if buffer.is_null() || capacity != MAX_PAGE {
            return Err(INVALID);
        }
        let Value::Spaces(spaces) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        if offset > spaces.len() {
            return Err(INVALID);
        }
        let mut page = Vec::new();
        for (id, name) in spaces.iter().skip(offset).take(32) {
            page.push(SpaceMetadata { id, name });
            if serde_json::to_vec(&page).map_err(|_| INTERNAL)?.len() > MAX_PAGE {
                page.pop();
                break;
            }
        }
        if page.is_empty() && offset < spaces.len() {
            return Err(CAPACITY);
        }
        let bytes = serde_json::to_vec(&page).map_err(|_| INTERNAL)?;
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
        *written = bytes.len();
        *next = offset + page.len();
        Ok(())
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_application_bind(
    pointer: *mut c_void,
    instance: Text,
    space: Text,
    out: *mut *mut c_void,
) -> i32 {
    boundary(|| unsafe {
        if out.is_null() {
            return Err(INVALID);
        }
        *out = std::ptr::null_mut();
        let Value::Core(core) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        let binding = core
            .accounts
            .bind_space(text(instance)?, text(space)?)
            .map_err(account_error)?;
        output(
            out,
            Value::Bound(Arc::new(Bound {
                core: core.clone(),
                binding,
            })),
        )
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_application_binding(
    pointer: *mut c_void,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    #[derive(Serialize)]
    struct Identity<'a> {
        instance: &'a str,
        space: &'a str,
        issuer: &'a str,
        subject: &'a str,
    }
    boundary(|| unsafe {
        if written.is_null() {
            return Err(INVALID);
        }
        *written = 0;
        if buffer.is_null() || capacity != MAX_PAGE {
            return Err(INVALID);
        }
        let Value::Bound(bound) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        if bound.binding.offline {
            return Err(UNAVAILABLE);
        }
        bound
            .core
            .accounts
            .storage
            .validate(&bound.binding.root)
            .map_err(account_error)?;
        let bytes = serde_json::to_vec(&Identity {
            instance: &bound.binding.instance,
            space: &bound.binding.space,
            issuer: &bound.binding.issuer,
            subject: &bound.binding.subject,
        })
        .map_err(|_| INTERNAL)?;
        if bytes.len() > capacity {
            return Err(CAPACITY);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
        *written = bytes.len();
        Ok(())
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_application_list(
    pointer: *mut c_void,
    path_json: Text,
    parent_id: Text,
    out: *mut *mut c_void,
) -> i32 {
    boundary(|| unsafe {
        if out.is_null() {
            return Err(INVALID);
        }
        *out = std::ptr::null_mut();
        let Value::Bound(bound) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        if bound.binding.offline {
            return Err(UNAVAILABLE);
        }
        let snapshot = bound
            .core
            .accounts
            .mount_directory(
                &bound.binding.instance,
                &bound.binding,
                &path(path_json)?,
                text(parent_id)?,
            )
            .map_err(account_error)?;
        output(
            out,
            Value::Listing(Listing {
                bound: bound.clone(),
                snapshot,
            }),
        )
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_application_domain_prepare(
    pointer: *mut c_void,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    #[derive(Serialize)]
    struct Descriptor {
        domain: String,
    }
    // SAFETY: caller owns live same-thread Bound and distinct output storage.
    boundary(|| unsafe {
        if written.is_null() {
            return Err(INVALID);
        }
        *written = 0;
        if buffer.is_null() || capacity != MAX_PAGE {
            return Err(INVALID);
        }
        let Value::Bound(bound) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        bound
            .core
            .accounts
            .storage
            .validate(&bound.binding.root)
            .map_err(account_error)?;
        let domain = prepare_domain(bound, true)?;
        let bytes = serde_json::to_vec(&Descriptor { domain }).map_err(|_| INTERNAL)?;
        if bytes.len() > capacity {
            return Err(CAPACITY);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
        *written = bytes.len();
        Ok(())
    })
}

fn prepare_domain(bound: &Bound, activate: bool) -> Result<String> {
    if bound.binding.offline {
        return Err(UNAVAILABLE);
    }
    bound
        .core
        .accounts
        .storage
        .validate(&bound.binding.root)
        .map_err(account_error)?;
    // Mount intent is consent for normal sync. Restoring an existing activation
    // must NOT reset its attention/backoff state on each launch.
    if activate {
        bound
            .core
            .accounts
            .activate_sync(&bound.binding)
            .map_err(account_error)?;
    }
    bound
        .core
        .accounts
        .mount_directory(&bound.binding.instance, &bound.binding, &[], "")
        .map_err(account_error)?;
    let domain = crate::provider_catalog::Catalog::prepare_authenticated(&bound.binding)
        .map_err(catalog_error)?;
    let (_, _, _, _, epoch) =
        crate::provider_catalog::Catalog::stored(&bound.binding.root, &domain)
            .map_err(catalog_error)?;
    let retained = bound
        .core
        .accounts
        .bind_offline_space_in(
            bound.binding.root.clone(),
            &bound.binding.instance,
            &bound.binding.space,
        )
        .map_err(account_error)?;
    let catalog = crate::provider_catalog::Catalog::resume(&retained, &domain, &epoch)
        .map_err(catalog_error)?;
    // Publish the observed root to the durable working set before registration.
    // Unobserved descendants are not invented or claimed indexed.
    catalog
        .capture("root", "name", || false)
        .map_err(catalog_error)?;
    Ok(domain)
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn cirrus_application_domains_restore(
    pointer: *mut c_void,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    // SAFETY: same owner-thread and copied-output contract as domain_prepare.
    boundary(|| unsafe {
        if written.is_null() {
            return Err(INVALID);
        }
        *written = 0;
        if buffer.is_null() || capacity != MAX_PAGE {
            return Err(INVALID);
        }
        let Value::Core(core) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        let intents = core.accounts.activated_spaces().map_err(account_error)?;
        let mut domains = Vec::new();
        let mut unavailable = 0;
        let root = core.accounts.storage_root().map_err(account_error)?;
        let saved =
            crate::provider_catalog::Catalog::stored_domains(&root).map_err(catalog_error)?;
        // Already-prepared mounts resume without credentials/network. Even an
        // invalid saved row reserves its original tuple: never allocate a new
        // domain to conceal a failed resume or foreign retained identity.
        for (domain, _, _) in &saved {
            match resume_catalog(core, domain) {
                Ok(_) => domains.push(serde_json::json!({"domain":domain})),
                Err(INTERNAL) => return Err(INTERNAL),
                Err(_) => unavailable += 1,
            }
        }
        for (instance, space) in intents {
            if saved.iter().any(|(_, i, s)| i == &instance && s == &space) {
                continue;
            }
            // Only previously requested persistent mount activations, never an
            // authenticated listing of all accessible Spaces. Each gets at most
            // one attempt per lifecycle event. No scheduler or retry loop here.
            let result = core
                .accounts
                .bind_space(&instance, &space)
                .map_err(account_error)
                .and_then(|binding| {
                    prepare_domain(
                        &Bound {
                            core: core.clone(),
                            binding,
                        },
                        false,
                    )
                });
            match result {
                Ok(domain) => domains.push(serde_json::json!({"domain":domain})),
                Err(INTERNAL) => return Err(INTERNAL),
                Err(_) => unavailable += 1,
            }
        }
        let bytes = serde_json::to_vec(&serde_json::json!({
            "domains":domains, "unavailable":unavailable
        }))
        .map_err(|_| INTERNAL)?;
        if bytes.len() > capacity {
            return Err(CAPACITY);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
        *written = bytes.len();
        Ok(())
    })
}

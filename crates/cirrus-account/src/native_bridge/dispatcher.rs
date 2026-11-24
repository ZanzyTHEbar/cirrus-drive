//! Root-elected, one-turn automatic execution on the native owner's OS thread.

use super::*;

pub(super) struct Dispatcher {
    core: Arc<Core>,
    election: crate::SchedulerGuard,
    after: std::cell::RefCell<Option<(String, String)>>,
    reconciliation: std::cell::RefCell<crate::provider_mutation::ReconciliationCursor>,
}

#[derive(Serialize)]
struct Turn {
    instance: Option<String>,
    space: Option<String>,
    progressed: bool,
    status: Option<crate::SyncStatus>,
    domains: Vec<String>,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_dispatcher_open(pointer: *mut c_void, out: *mut *mut c_void) -> i32 {
    boundary(|| unsafe {
        if out.is_null() {
            return Err(INVALID);
        }
        *out = std::ptr::null_mut();
        let core = match &handle(pointer)?.value {
            Value::Core(core) => core,
            Value::Catalog { bound, .. } => &bound.core,
            _ => return Err(INVALID),
        };
        let election = core.accounts.acquire_scheduler().map_err(account_error)?;
        output(
            out,
            Value::Dispatcher(Dispatcher {
                core: core.clone(),
                election,
                after: std::cell::RefCell::new(None),
                reconciliation: std::cell::RefCell::new(Default::default()),
            }),
        )
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_dispatcher_pause(pointer: *mut c_void, paused: i32) -> i32 {
    boundary(|| unsafe {
        if pointer.is_null() || !matches!(paused, 0 | 1) {
            return Err(INVALID);
        }
        // Like Request cancellation, ONLY the admission atomic may be accessed
        // across threads. The caller excludes close through its mailbox mutex.
        let Value::Dispatcher(dispatcher) = &(*pointer.cast::<Handle>()).value else {
            return Err(INVALID);
        };
        dispatcher.core.accounts.pause_background(paused != 0);
        Ok(())
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_dispatcher_turn(
    pointer: *mut c_void,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    boundary(|| unsafe {
        if written.is_null() {
            return Err(INVALID);
        }
        *written = 0;
        if buffer.is_null() || capacity != MAX_PAGE {
            return Err(INVALID);
        }
        handle(pointer)?;
        // Exclusive owner-thread operation; pause borrows only admission atomics.
        let Value::Dispatcher(dispatcher) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        let accounts = &dispatcher.core.accounts;
        let spaces = dispatcher
            .election
            .activated_spaces(accounts)
            .map_err(account_error)?;
        let after = dispatcher.after.borrow();
        let selected = after
            .as_ref()
            .and_then(|after| spaces.iter().find(|tuple| *tuple > after))
            .or_else(|| spaces.first())
            .cloned();
        drop(after);
        let turn = if let Some((instance, space)) = selected {
            // Advance fairness even when a turn fails or its Space needs attention.
            *dispatcher.after.borrow_mut() = Some((instance.clone(), space.clone()));
            let progressed = dispatcher
                .election
                .automatic_sync_turn(accounts, &instance, &space)
                .map_err(account_error)?;
            let status = dispatcher
                .election
                .sync_status(accounts, &instance, &space)
                .map_err(account_error)?;
            let domains = accounts.reconcile_provider_requests(
                dispatcher.election.retained_root(),
                &instance,
                &space,
                &mut dispatcher.reconciliation.borrow_mut(),
            );
            Turn {
                instance: Some(instance),
                space: Some(space),
                progressed,
                status: Some(status),
                domains,
            }
        } else {
            Turn {
                instance: None,
                space: None,
                progressed: false,
                status: None,
                domains: Vec::new(),
            }
        };
        let mut writer = io::Cursor::new(std::slice::from_raw_parts_mut(buffer, capacity));
        serde_json::to_writer(&mut writer, &turn).map_err(|_| CAPACITY)?;
        *written = writer.position() as usize;
        Ok(())
    })
}

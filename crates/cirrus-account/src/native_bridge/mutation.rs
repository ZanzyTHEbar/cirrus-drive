//! Exact retained operation observations; never infer completion from scheduler status.

use super::*;

struct CancelControl<'a> {
    request: &'a NativeRequest,
}
impl Drop for CancelControl<'_> {
    fn drop(&mut self) {
        if let Ok(mut control) = self.request.background.lock() {
            *control = None;
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_catalog_mutate(
    pointer: *mut c_void,
    descriptor: Text,
    source: Text,
    request: *mut c_void,
    progress: Option<unsafe extern "C" fn(*mut c_void, u64, u64)>,
    context: *mut c_void,
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
        check_request(request)?;
        let Value::Catalog { bound, catalog } = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        let Value::Request(control) = &handle(request)?.value else {
            return Err(INVALID);
        };
        let descriptor: crate::provider_mutation::Request =
            serde_json::from_str(text(descriptor)?).map_err(|_| INVALID)?;
        let source = text(source)?;
        {
            let mut background = control.background.lock().map_err(|_| INTERNAL)?;
            *background = Some(bound.core.accounts.background_admission.clone());
            bound
                .core
                .accounts
                .pause_background(control.cancelled.load(Ordering::Acquire));
        }
        let _control = CancelControl { request: control };
        let result = bound.core.accounts.mutate_catalog(
            catalog,
            &descriptor,
            if source.is_empty() {
                None
            } else {
                Some(Path::new(source))
            },
            &|| control.cancelled.load(Ordering::Acquire),
            &|done, total| {
                if let Some(progress) = progress {
                    progress(context, done, total);
                }
            },
        );
        use crate::provider_mutation::Error as E;
        let reply = result.map_err(|e| match e {
            E::Invalid => INVALID,
            E::Unavailable => UNAVAILABLE,
            E::Pending => MUTATION_PENDING,
            E::Conflict => MUTATION_CONFLICT,
            E::Uncertain => MUTATION_UNCERTAIN,
            E::Cancelled => CANCELLED,
            E::Capacity => CAPACITY,
            E::Unsupported => MUTATION_UNSUPPORTED,
        })?;
        // Cancellation after durable publication never removes staged bytes or
        // rewrites an uncertain journal claim. A retry resumes the stored IDs.
        check_request(request)?;
        let mut writer = io::Cursor::new(std::slice::from_raw_parts_mut(buffer, capacity));
        serde_json::to_writer(&mut writer, &reply).map_err(|_| CAPACITY)?;
        *written = writer.position() as usize;
        Ok(())
    })
}

#[derive(Serialize)]
struct Observation {
    operation: crate::OperationHandle,
    result: crate::OperationResult,
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_operation(
    pointer: *mut c_void,
    request: *mut c_void,
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
        check_request(request)?;
        let Value::Version(version) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        let accounts = &version.bound.core.accounts;
        let operation = accounts
            .staged_operation(&version.bound.binding, &version.version)
            .map_err(account_error)?;
        let result = accounts
            .operation_result(&version.bound.binding, &operation)
            .map_err(account_error)?;
        let observation = Observation { operation, result };
        let mut writer = io::Cursor::new(std::slice::from_raw_parts_mut(buffer, capacity));
        serde_json::to_writer(&mut writer, &observation).map_err(|_| CAPACITY)?;
        check_request(request)?;
        *written = writer.position() as usize;
        Ok(())
    })
}

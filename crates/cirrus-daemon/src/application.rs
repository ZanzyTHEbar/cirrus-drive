//! User-scoped application operations, foreground admission and shutdown.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use cirrus_account::{Accounts, PortalBrowser, SignIn};
use cirrus_fuse::Mounted;
use cirrus_runtime::RuntimeDir;

use crate::scheduler::Scheduler;
use crate::{DirectoryEntry, MountInfo, MountState};
use cirrus_api::{AccountReply, AccountRequest, MountMode, MountedSpace, SpaceInfo, SpacePath};

type ActiveSignIn = Arc<Mutex<Option<(String, Arc<SignIn>)>>>;

struct ActivityPermit(Arc<AtomicUsize>);

impl Drop for ActivityPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) enum MountRegistry {
    Available(Vec<Mounted>),
    Reserved,
}

impl MountRegistry {
    pub(crate) fn ready(&self) -> Result<&[Mounted], String> {
        match self {
            Self::Available(mounts) => Ok(mounts),
            Self::Reserved => Err("mount operation is in progress".to_owned()),
        }
    }

    fn ready_mut(&mut self) -> Result<&mut Vec<Mounted>, String> {
        match self {
            Self::Available(mounts) => Ok(mounts),
            Self::Reserved => Err("mount operation is in progress".to_owned()),
        }
    }

    fn has_mounts(&self) -> bool {
        match self {
            Self::Available(mounts) => !mounts.is_empty(),
            Self::Reserved => true,
        }
    }
}

struct MountOperation<'a> {
    registry: &'a Mutex<MountRegistry>,
    mounts: Vec<Mounted>,
}

impl<'a> MountOperation<'a> {
    fn begin(registry: &'a Mutex<MountRegistry>) -> Result<Self, String> {
        let mut state = registry
            .lock()
            .map_err(|_| "mount state is unavailable".to_owned())?;
        let mounts = std::mem::take(state.ready_mut()?);
        *state = MountRegistry::Reserved;
        Ok(Self { registry, mounts })
    }

    fn unmount(mut self, instance: &str, space: &str) -> Result<(), String> {
        let mounts = &mut self.mounts;
        let index = mounts
            .iter()
            .position(|mount| mount.instance() == instance && mount.space_id() == space)
            .ok_or_else(|| "Space is not mounted".to_owned())?;
        mounts[index].unmount().map_err(|error| error.to_string())?;
        mounts.remove(index);
        Ok(())
    }
}

impl Drop for MountOperation<'_> {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().expect("mount state lock poisoned");
        // Return the actual owners before foreground/reply admission is released.
        *registry = MountRegistry::Available(std::mem::take(&mut self.mounts));
    }
}

fn check_mount_owners(runtime: &RuntimeDir, mounts: &[Mounted]) -> Result<(), String> {
    let owners = cirrus_fuse::recovery_owners(runtime).map_err(|e| e.to_string())?;
    if owners.len() != mounts.len()
        || mounts.iter().any(|mount| {
            !mount.is_active().unwrap_or(false)
                || owners
                    .iter()
                    .filter(|owner| {
                        owner.path == mount.path()
                            && owner.source == mount.source()
                            && owner.instance == mount.instance()
                            && owner.space_id == mount.space_id()
                            && owner.space_name == mount.space_name()
                    })
                    .count()
                    != 1
        })
    {
        return Err("stale or ambiguous mount records require recovery or inspection".to_owned());
    }
    Ok(())
}

fn mount_statuses(runtime: &RuntimeDir, mounts: &[Mounted]) -> Result<Vec<MountInfo>, String> {
    let owners = cirrus_fuse::recovery_owners(runtime).map_err(|error| error.to_string())?;
    let mut paths = std::collections::HashSet::new();
    let mut spaces = std::collections::HashSet::new();
    let mut sources = std::collections::HashSet::new();
    for owner in &owners {
        if !paths.insert(&owner.path)
            || !spaces.insert((&owner.instance, &owner.space_id))
            || !sources.insert(&owner.source)
        {
            return Err("ambiguous mount owner records require inspection".to_owned());
        }
    }
    for mount in mounts {
        if (!mount.is_active().map_err(|e| e.to_string())?
            && !mount.is_disconnected().map_err(|e| e.to_string())?)
            || owners
                .iter()
                .filter(|owner| {
                    owner.path == mount.path()
                        && owner.source == mount.source()
                        && owner.instance == mount.instance()
                        && owner.space_id == mount.space_id()
                        && owner.space_name == mount.space_name()
                })
                .count()
                != 1
        {
            return Err("mountpoint identity changed or cannot be verified".to_owned());
        }
    }
    let mut result = Vec::with_capacity(owners.len());
    for owner in owners {
        let active = mounts
            .iter()
            .find(|mount| mount.path() == owner.path && mount.source() == owner.source);
        let active = match active {
            Some(mount) if !mount.is_disconnected().map_err(|e| e.to_string())? => Some(mount),
            _ => None,
        };
        let offline_read_only =
            active.map(|mount| mount.is_offline() && !mount.is_offline_writable());
        let offline_writable = active.map(Mounted::is_offline_writable);
        result.push(MountInfo {
            instance: owner.instance,
            space_id: owner.space_id,
            space_name: owner.space_name,
            path: owner.path.to_string_lossy().into_owned(),
            state: if active.is_some() {
                MountState::Mounted
            } else {
                MountState::RecoveryRequired
            },
            offline_read_only,
            offline_writable,
        });
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

struct SignInReservation(ActiveSignIn);

impl Drop for SignInReservation {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0.lock() {
            *active = None;
        }
    }
}

fn validate_space_paths(request: &AccountRequest) -> Result<(), &'static str> {
    let valid = |path: &SpacePath| {
        let parts = path.components();
        parts.len() <= 128
            && parts.iter().all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && !part.contains('/')
                    && !part.chars().any(char::is_control)
            })
    };
    let valid = match request {
        AccountRequest::DirectorySpace { path, .. }
        | AccountRequest::PinSpace { path, .. }
        | AccountRequest::UnpinSpace { path, .. }
        | AccountRequest::EvictSpace { path, .. }
        | AccountRequest::ExportPinCopy { path, .. }
        | AccountRequest::RetainedFiles { root: path, .. } => valid(path),
        AccountRequest::OfflineDirectory { path, .. } if !valid(path) => {
            return Err("invalid offline Space path");
        }
        AccountRequest::ExportRetained { root, path, .. } => valid(root) && valid(path),
        AccountRequest::StageFileSpace { path, .. }
        | AccountRequest::StageFileOfflineSpace { path, .. } => {
            valid(path) && !path.components().is_empty()
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err("invalid Space path")
    }
}

pub(crate) enum Shutdown {
    Complete,
    Busy,
    PendingCredentials,
    UnmountFailed(io::Error),
}

pub(crate) struct Application {
    runtime: RuntimeDir,
    automatic: bool,
    accounts: Arc<Accounts>,
    mount: Arc<Mutex<MountRegistry>>,
    scheduler: Scheduler,
    journal_readers: Arc<AtomicUsize>,
    storage_readers: Arc<AtomicUsize>,
    account_replies: Arc<AtomicUsize>,
    sign_in: ActiveSignIn,
}

impl Application {
    pub(crate) fn start(runtime: RuntimeDir, automatic: bool) -> io::Result<Self> {
        let busy = Arc::new(AtomicBool::new(false));
        let accounts = Arc::new(Accounts::new(runtime.try_clone()?));
        let mount = Arc::new(Mutex::new(MountRegistry::Available(Vec::new())));
        let scheduler = Scheduler::start(
            Arc::clone(&accounts),
            Arc::clone(&busy),
            Arc::clone(&mount),
            automatic,
        )?;
        let journal_readers = Arc::new(AtomicUsize::new(0));
        let account_replies = Arc::new(AtomicUsize::new(0));
        let storage_readers = Arc::new(AtomicUsize::new(0));
        let sign_in: ActiveSignIn = Arc::new(Mutex::new(None));
        Ok(Self {
            runtime,
            automatic,
            accounts,
            mount,
            scheduler,
            journal_readers,
            storage_readers,
            account_replies,
            sign_in,
        })
    }

    pub(crate) fn automatic_sync_enabled(&self) -> bool {
        self.scheduler.enabled()
    }

    // An adapter provides delivery; the application decides which operations can
    // proceed concurrently, how to hold admission, and when shutdown can drain.
    pub(crate) fn dispatch(
        &self,
        request: AccountRequest,
        reply: impl FnOnce(Result<AccountReply, String>) + Send + 'static,
    ) -> io::Result<()> {
        if let Err(error) = validate_space_paths(&request) {
            reply(Err(error.into()));
            return Ok(());
        }
        #[cfg(not(feature = "fault-injection"))]
        if matches!(request, AccountRequest::LabUploadStep { .. }) {
            reply(Err("unsupported request".into()));
            return Ok(());
        }
        if let Some(instance) = request.instance()
            && let Err(error) = Accounts::canonical_instance(instance)
        {
            reply(Err(error.to_string()));
            return Ok(());
        }
        let Self {
            runtime,
            automatic,
            accounts,
            mount,
            scheduler,
            journal_readers,
            storage_readers,
            account_replies,
            sign_in,
        } = self;
        let automatic = *automatic;
        let worker_enabled = scheduler.enabled();
        let read_pool = match &request {
            AccountRequest::Journal { .. } => Some((
                journal_readers,
                4,
                "cirrus-journal",
                "journal is busy; retry",
            )),
            AccountRequest::CleanCacheStatus | AccountRequest::SyncStatus { .. } => Some((
                journal_readers,
                4,
                "cirrus-cache-status",
                "local status is busy; retry",
            )),
            AccountRequest::StorageStatus
            | AccountRequest::StorageLimits
            | AccountRequest::SetStorageLimits { .. }
            | AccountRequest::ReleaseStorageReservation { .. } => Some((
                storage_readers,
                1,
                "cirrus-storage-status",
                "local status is busy; retry",
            )),
            _ => None,
        };
        if let Some((readers, limit, name, busy)) = read_pool {
            // A potentially slow storage scan does not share the journal/status pool.
            if readers
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < limit).then_some(count + 1)
                })
                .is_err()
            {
                reply(Err(busy.into()));
                return Ok(());
            }
            let permit = ActivityPermit(Arc::clone(readers));
            let accounts = Arc::clone(accounts);
            let _ = thread::Builder::new().name(name.into()).spawn(move || {
                let _permit = permit;
                let result = match request {
                    AccountRequest::Journal {
                        instance,
                        space,
                        before,
                    } => accounts
                        .journal(&instance, space.as_deref(), before)
                        .map(AccountReply::Journal),
                    AccountRequest::SyncStatus { instance, space } => {
                        accounts.sync_status(&instance, &space).map(|mut status| {
                            status.worker_enabled_here = Some(worker_enabled);
                            AccountReply::SyncStatus(status)
                        })
                    }
                    AccountRequest::SetStorageLimits { limits } => accounts
                        .configure_storage_limits(limits)
                        .map(AccountReply::StorageLimits),
                    AccountRequest::ReleaseStorageReservation { store, token } => accounts
                        .release_storage_reservation(store.as_str(), &token)
                        .map(|()| AccountReply::Done),
                    AccountRequest::StorageLimits => {
                        accounts.storage_limits().map(AccountReply::StorageLimits)
                    }
                    AccountRequest::StorageStatus => {
                        accounts.storage_status().map(AccountReply::StorageStatus)
                    }
                    AccountRequest::CleanCacheStatus => accounts
                        .clean_cache_status()
                        .map(AccountReply::CleanCacheStatus),
                    _ => unreachable!("only journal and storage operations use this pool"),
                };
                reply(result.map_err(|error| error.to_string()));
            });
            return Ok(());
        }
        if let AccountRequest::CancelConnect { attempt } = &request {
            let result = sign_in
                .lock()
                .map_err(|_| "sign-in state unavailable".to_owned())
                .and_then(|active| {
                    let (_, current) = active
                        .as_ref()
                        .filter(|(id, _)| id == attempt)
                        .ok_or_else(|| "sign-in is no longer active".to_owned())?;
                    current.cancel().map_err(|error| error.to_string())
                });
            reply(result.map(|()| AccountReply::Done));
            return Ok(());
        }
        if matches!(request, AccountRequest::Mounts) {
            let result = mount
                .try_lock()
                .map_err(|_| "mount operation is in progress".to_owned())
                .and_then(|mounts| mount_statuses(runtime, mounts.ready()?));
            reply(result.map(AccountReply::Mounts));
            return Ok(());
        }
        let mut admission = match scheduler.foreground() {
            Ok(admission) => admission,
            Err(error) => {
                reply(Err(error.to_string()));
                return Ok(());
            }
        };
        #[cfg(feature = "fault-injection")]
        if std::env::var_os("CIRRUS_TEST_PRIORITY_TRACE").is_some() {
            eprintln!("cirrus lab IPC foreground admitted");
        }
        let worker_runtime = runtime.try_clone()?;
        let accounts = Arc::clone(accounts);
        let mount = Arc::clone(mount);
        let active_sign_in = Arc::clone(sign_in);
        let attempt = if let AccountRequest::Connect { attempt, .. } = &request {
            if attempt.len() != 32 || !attempt.bytes().all(|b| b.is_ascii_hexdigit()) {
                drop(admission);
                reply(Err("invalid sign-in attempt".into()));
                return Ok(());
            }
            let control = Arc::new(SignIn::default());
            *sign_in
                .lock()
                .map_err(|_| io::Error::other("sign-in state unavailable"))? =
                Some((attempt.clone(), Arc::clone(&control)));
            Some(control)
        } else {
            None
        };
        account_replies.fetch_add(1, Ordering::AcqRel);
        let reply_permit = ActivityPermit(Arc::clone(account_replies));
        thread::spawn(move || {
            let _reply = reply_permit;
            // Drop the transport reply before releasing the shutdown permit,
            // including when foreground admission was cancelled.
            let reply = reply;
            // Keep the scoped foreground permit (so another account
            // command cannot race mount publication), but local-only
            // writable mount/unmount need not wait for background auth.
            let local_offline =
                matches!(&request, AccountRequest::WritableOfflineMountSpace { .. })
                    || mount.lock().is_ok_and(|registry| {
                        let Ok(mounts) = registry.ready() else {
                            return false;
                        };
                        match &request {
                            AccountRequest::UnmountSpace { instance, space } => {
                                Accounts::canonical_instance(instance).is_ok_and(|canonical| {
                                    mounts.iter().any(|mount| {
                                        mount.instance() == canonical
                                            && mount.space_id() == space
                                            && mount.is_offline_writable()
                                    })
                                })
                            }
                            _ => false,
                        }
                    });
            let sign_in_guard = attempt.as_ref().map(|_| SignInReservation(active_sign_in));
            if let Err(error) = if local_offline {
                Ok(())
            } else {
                admission.wait()
            } {
                reply(Err(error.to_string()));
                return;
            }
            // Operations from the control client can change the journal or
            // credentials without passing through the mounted filesystem.
            accounts.invalidate_mount_metadata();
            let mounted = mount
                .lock()
                .ok()
                .is_some_and(|registry| registry.has_mounts());
            let offline_writable =
                matches!(&request, AccountRequest::WritableOfflineMountSpace { .. });
            let result = match request {
                AccountRequest::Connect { .. } if mounted => {
                    Err("unmount all Spaces before changing account".to_owned())
                }
                AccountRequest::Connect {
                    instance, ca_pem, ..
                } => accounts
                    .connect(
                        &instance,
                        ca_pem.as_deref().map(str::as_bytes),
                        &PortalBrowser::default(),
                        attempt.as_ref().expect("connect has a sign-in fence"),
                    )
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::Spaces { instance } => accounts
                    .spaces(&instance)
                    .map(|spaces| {
                        AccountReply::Spaces(
                            spaces
                                .into_iter()
                                .map(|space| SpaceInfo {
                                    id: space.id().to_owned(),
                                    name: space.name().to_owned(),
                                })
                                .collect(),
                        )
                    })
                    .map_err(|e| e.to_string()),
                AccountRequest::DirectorySpace { .. } | AccountRequest::OfflineDirectory { .. } => {
                    (match &request {
                        AccountRequest::DirectorySpace {
                            instance,
                            space,
                            path,
                        } => accounts.directory_space(instance, space, path.components()),
                        AccountRequest::OfflineDirectory {
                            instance,
                            space,
                            path,
                        } => accounts.offline_directory(instance, space, path.components()),
                        _ => unreachable!(),
                    })
                    .map(|entries| {
                        AccountReply::Entries(
                            entries
                                .into_iter()
                                .map(|entry| DirectoryEntry {
                                    name: entry.name().to_owned(),
                                    directory: entry.is_directory(),
                                    size: entry.size(),
                                })
                                .collect(),
                        )
                    })
                    .map_err(|e| e.to_string())
                }
                AccountRequest::PinSpace {
                    instance,
                    space,
                    path,
                } => accounts
                    .pin_space(&instance, &space, path.components())
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::UnpinSpace {
                    instance,
                    space,
                    path,
                } => accounts
                    .unpin_space(&instance, &space, path.components())
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::PinsSpace { instance, space } => accounts
                    .pins_space(&instance, &space)
                    .map(AccountReply::Pins)
                    .map_err(|e| e.to_string()),
                AccountRequest::PinsSpaceCheckRemote { instance, space } => accounts
                    .pins_space_check_remote(&instance, &space)
                    .map(AccountReply::Pins)
                    .map_err(|e| e.to_string()),
                AccountRequest::EvictSpace {
                    instance,
                    space,
                    path,
                } => accounts
                    .evict_space(&instance, &space, path.components())
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::RetainedPins { instance, offset } => accounts
                    .retained_pins(&instance, offset)
                    .map(AccountReply::RetainedPins)
                    .map_err(|e| e.to_string()),
                AccountRequest::RetainedStaged { instance, offset } => accounts
                    .retained_staged(&instance, offset)
                    .map(AccountReply::RetainedStaged)
                    .map_err(|e| e.to_string()),
                AccountRequest::ExportStaged {
                    instance,
                    id,
                    selector,
                    destination,
                } => accounts
                    .export_staged(&instance, id, &selector, &destination)
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::PinCopies { instance, offset } => accounts
                    .pin_copies(&instance, offset)
                    .map(AccountReply::PinCopies)
                    .map_err(|e| e.to_string()),
                AccountRequest::PinCopyEntries {
                    instance,
                    space,
                    id,
                    offset,
                } => accounts
                    .pin_copy_entries(&instance, &space, id, offset)
                    .map(AccountReply::PinCopyEntries)
                    .map_err(|e| e.to_string()),
                AccountRequest::ExportPinCopy {
                    instance,
                    space,
                    id,
                    path,
                    selector,
                    destination,
                } => accounts
                    .export_pin_copy(
                        &instance,
                        &space,
                        id,
                        path.components(),
                        &selector,
                        &destination,
                    )
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::RemovePinCopy {
                    instance,
                    space,
                    id,
                } => accounts
                    .remove_pin_copy(&instance, &space, id)
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::RetainedFiles {
                    instance,
                    space,
                    root,
                    offset,
                } => accounts
                    .retained_files(&instance, &space, root.components(), offset)
                    .map(AccountReply::RetainedFiles)
                    .map_err(|e| e.to_string()),
                AccountRequest::ExportRetained {
                    instance,
                    space,
                    root,
                    path,
                    selector,
                    destination,
                } => accounts
                    .export_retained(
                        &instance,
                        &space,
                        (root.components(), path.components()),
                        &selector,
                        &destination,
                    )
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::StageFileSpace {
                    instance,
                    space,
                    path,
                    source,
                } => accounts
                    .stage_file_space(&instance, &space, path.components(), &source)
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::StageFileOfflineSpace {
                    instance,
                    space,
                    path,
                    source,
                } => accounts
                    .stage_file_offline_space(&instance, &space, path.components(), &source)
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::Journal { .. } => {
                    unreachable!("journal is handled before spawning")
                }
                AccountRequest::Sync { instance } => accounts
                    .sync_pending(&instance)
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::SyncSpace { instance, space } => accounts
                    .sync_space(&instance, &space)
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                #[cfg(feature = "fault-injection")]
                AccountRequest::LabUploadStep { instance, space } => accounts
                    .lab_upload_step(&instance, &space)
                    .map(AccountReply::LabUploadOutcome)
                    .map_err(|e| e.to_string()),
                #[cfg(not(feature = "fault-injection"))]
                AccountRequest::LabUploadStep { .. } => Err("unsupported request".to_owned()),
                AccountRequest::Acknowledge { instance, staged } => accounts
                    .acknowledge(&instance, &staged)
                    .map(|()| AccountReply::Done)
                    .map_err(|e| e.to_string()),
                AccountRequest::OfflineMountSpace {
                    instance,
                    space,
                    path,
                }
                | AccountRequest::WritableOfflineMountSpace {
                    instance,
                    space,
                    path,
                } => (|| {
                    if automatic && !offline_writable {
                        return Err(
                            "offline mounts require restarting the service with --no-auto-sync"
                                .to_owned(),
                        );
                    }
                    let mut operation = MountOperation::begin(&mount)?;
                    let slot = &mut operation.mounts;
                    check_mount_owners(&worker_runtime, slot)?;
                    let canonical =
                        Accounts::canonical_instance(&instance).map_err(|e| e.to_string())?;
                    let path_ref = path.as_path();
                    if slot.len() >= 64
                        || slot.iter().any(|mount| {
                            (mount.instance() == canonical && mount.space_id() == space)
                                || path_ref.starts_with(mount.path())
                                || mount.path().starts_with(path_ref)
                        })
                    {
                        return Err(
                            "Space already mounted, mountpoints overlap or mount limit reached"
                                .to_owned(),
                        );
                    }
                    let start = if offline_writable {
                        Mounted::start_writable_offline_space
                    } else {
                        Mounted::start_offline_space
                    };
                    let mounted = start(
                        Arc::clone(&accounts),
                        &canonical,
                        &space,
                        path_ref,
                        worker_runtime,
                    )
                    .map_err(|e| e.to_string())?;
                    let actual_path = mounted.path().to_string_lossy().into_owned();
                    slot.push(mounted);
                    Ok(AccountReply::Mounted(MountedSpace {
                        path: actual_path,
                        automatic_sync_enabled: worker_enabled,
                        mode: if offline_writable {
                            MountMode::OfflineWritable
                        } else {
                            MountMode::OfflineReadOnly
                        },
                    }))
                })(),
                AccountRequest::MountSpace {
                    instance,
                    space,
                    path,
                } => (|| {
                    let mut operation = MountOperation::begin(&mount)?;
                    let slot = &mut operation.mounts;
                    check_mount_owners(&worker_runtime, slot)?;
                    let canonical =
                        Accounts::canonical_instance(&instance).map_err(|e| e.to_string())?;
                    if slot
                        .iter()
                        .any(|mount| mount.instance() == canonical && mount.space_id() == space)
                    {
                        return Err("this Space is already mounted".to_owned());
                    }
                    if slot.len() >= 64 {
                        return Err("mount limit reached".to_owned());
                    }
                    if let Some(path) = path.as_deref() {
                        let path_ref = path;
                        if slot.iter().any(|mount| {
                            path_ref.starts_with(mount.path()) || mount.path().starts_with(path_ref)
                        }) {
                            return Err("mountpoints must not overlap".to_owned());
                        }
                    } else {
                        let home = std::env::var_os("HOME")
                            .ok_or_else(|| "HOME is unavailable".to_owned())?;
                        let home = std::fs::canonicalize(home).map_err(|e| e.to_string())?;
                        if slot.iter().any(|mount| home.starts_with(mount.path())) {
                            return Err("home directory is inside an existing mount".to_owned());
                        }
                    }
                    let mounted = Mounted::start_space(
                        Arc::clone(&accounts),
                        instance,
                        &space,
                        path.as_deref(),
                        worker_runtime,
                    )
                    .map_err(|e| e.to_string())?;
                    let actual_path = mounted.path().to_string_lossy().into_owned();
                    slot.push(mounted);
                    Ok(AccountReply::Mounted(MountedSpace {
                        path: actual_path,
                        automatic_sync_enabled: worker_enabled,
                        mode: MountMode::Online,
                    }))
                })(),
                AccountRequest::UnmountSpace { instance, space } => {
                    (|| {
                        if accounts.has_pending_credentials().unwrap_or(true) {
                            return Err("account credentials await keyring persistence".to_owned());
                        }
                        let canonical =
                            Accounts::canonical_instance(&instance).map_err(|e| e.to_string())?;
                        MountOperation::begin(&mount)?.unmount(&canonical, &space)?;
                        if accounts.has_pending_credentials().unwrap_or(true) {
                            return Err("Space unmounted, but account credentials await keyring persistence".to_owned());
                        }
                        Ok(AccountReply::Done)
                    })()
                }
                AccountRequest::RecoverMount { path } => (|| {
                    let mut operation = MountOperation::begin(&mount)?;
                    let slot = &mut operation.mounts;
                    if let Some(index) =
                        slot.iter().position(|mount| mount.path() == path.as_path())
                    {
                        slot[index]
                            .recover_disconnected()
                            .map_err(|e| e.to_string())?;
                        slot.remove(index);
                    } else {
                        cirrus_fuse::recover(&worker_runtime, path.as_path())
                            .map_err(|e| e.to_string())?;
                    }
                    Ok(AccountReply::Done)
                })(),
                AccountRequest::CleanCacheStatus
                | AccountRequest::StorageStatus
                | AccountRequest::StorageLimits
                | AccountRequest::SetStorageLimits { .. }
                | AccountRequest::ReleaseStorageReservation { .. }
                | AccountRequest::SyncStatus { .. }
                | AccountRequest::Mounts
                | AccountRequest::CancelConnect { .. } => {
                    unreachable!("status is handled before spawning")
                }
            };
            // Successful mounts don't change the journal or principal of a
            // published binding. Keep the new mount's preflight view usable.
            if !matches!(&result, Ok(AccountReply::Mounted(_))) {
                accounts.invalidate_mount_metadata();
            }
            drop(sign_in_guard);
            // Release account admission before replying as before, but
            // keep the reply counted until its bounded write finishes.
            drop(admission);
            reply(result);
        });
        Ok(())
    }

    pub(crate) fn shutdown(&mut self) -> io::Result<Shutdown> {
        let Self {
            accounts,
            mount,
            scheduler,
            account_replies,
            storage_readers,
            ..
        } = self;
        scheduler.pause();
        accounts.cancel();
        #[cfg(feature = "fault-injection")]
        if let Some(marker) = std::env::var_os("CIRRUS_TEST_CANCEL_VERIFY_MARKER") {
            let _ = std::fs::write(marker, b"cancelled");
        }
        let shutdown_deadline = Instant::now() + Duration::from_secs(30);
        // The storage pool also executes writes. Do not discard an admitted
        // limits update or reservation release midway through shutdown.
        let drained = || {
            scheduler.quiescent()
                && account_replies.load(Ordering::Acquire) == 0
                && storage_readers.load(Ordering::Acquire) == 0
        };
        while !drained() && Instant::now() < shutdown_deadline {
            thread::sleep(Duration::from_millis(20));
        }
        if !drained() {
            return Ok(Shutdown::Busy);
        }
        if accounts.has_pending_credentials().unwrap_or(true) {
            scheduler.resume();
            return Ok(Shutdown::PendingCredentials);
        }
        // STOP owns the accept loop; foreground/reply owners have drained
        // and paused scheduler admission excludes refresh. No IPC publisher
        // can observe this temporary transfer of the mount owners.
        let mut draining = {
            let mut slot = mount
                .lock()
                .map_err(|_| io::Error::other("mount state is unavailable"))?;
            std::mem::take(slot.ready_mut().map_err(io::Error::other)?)
        };
        let unmounted = (|| -> io::Result<()> {
            while !draining.is_empty() {
                draining[0].unmount()?;
                draining.remove(0);
            }
            Ok(())
        })();
        {
            let mut slot = mount
                .lock()
                .map_err(|_| io::Error::other("mount state is unavailable"))?;
            // Restore the failed owner and untouched suffix before resuming.
            slot.ready_mut()
                .map_err(io::Error::other)?
                .append(&mut draining);
        }
        if let Err(error) = unmounted {
            scheduler.resume();
            return Ok(Shutdown::UnmountFailed(error));
        }
        // A FUSE request can finish a token refresh during unmount. Check
        // again after joining the worker, before discarding account state.
        if accounts.has_pending_credentials().unwrap_or(true) {
            scheduler.resume();
            return Ok(Shutdown::PendingCredentials);
        }
        scheduler.join()?;
        Ok(Shutdown::Complete)
    }
}

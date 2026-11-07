//! Rune control window for the independently running Cirrus daemon.

mod settings;

use std::error::Error;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use cirrus_daemon::{
    CleanCacheStatus, Daemon, JournalPage, JournalSummary, MountInfo, MountState, RetainedPin,
    RetainedPinCopy, RetainedPinCopyEntry, RetainedPinFile, RetainedStaged,
};
use cirrus_runtime::RuntimeDir;
use rune::tok::{self, type_};
use rune::{
    App, AppSpec, Color, Cx, El, FileDialogOptions, ScrollSpec, TextEdit, Tx, Waker, col, el, row,
    text, text_input,
};

enum Action {
    Status,
    Connect {
        instance: String,
        ca: String,
        attempt: String,
    },
    Spaces(String),
    Mount {
        instance: String,
        space: String,
        path: Option<String>,
    },
    OpenFolder(String),
    Unmount {
        instance: String,
        space: String,
    },
    Recover {
        path: String,
    },
    Pin {
        instance: String,
        space: String,
        path: String,
    },
    Unpin {
        instance: String,
        space: String,
        path: String,
    },
    Evict {
        instance: String,
        space: String,
        path: String,
    },
    CacheStatus,
    Pins {
        instance: String,
        space: String,
    },
    Stage {
        instance: String,
        space: String,
        path: String,
        source: String,
    },
    Journal(String, Option<String>, Option<i64>),
    SyncStatus(String, String),
    Sync(String, Option<String>),
    Acknowledge {
        instance: String,
        staged: String,
    },
    RecoveryRoots {
        instance: String,
        offset: u32,
    },
    RecoveryCopies {
        instance: String,
        offset: u32,
    },
    RecoveryCopyEntries {
        instance: String,
        space: String,
        id: i64,
        offset: u32,
    },
    RemovePinCopy {
        instance: String,
        space: String,
        id: i64,
    },
    RecoveryFiles {
        instance: String,
        space: String,
        root: Vec<String>,
        offset: u32,
    },
    RecoveryStaged {
        instance: String,
        offset: u32,
    },
    RecoveryExport {
        instance: String,
        selection: RecoverySelection,
        destination: String,
    },
}

#[derive(Clone)]
enum RecoverySelection {
    Copy {
        space: String,
        id: i64,
        file: RetainedPinCopyEntry,
    },
    Pin {
        space: String,
        root: Vec<String>,
        file: RetainedPinFile,
    },
    Staged(RetainedStaged),
}

#[derive(Clone)]
enum RecoveryRow {
    Copy(RetainedPinCopy),
    CopyEntry {
        space: String,
        id: i64,
        entry: RetainedPinCopyEntry,
    },
    Root(RetainedPin),
    File {
        space: String,
        root: Vec<String>,
        file: RetainedPinFile,
    },
    Staged(RetainedStaged),
}

#[derive(Clone)]
enum RecoveryPage {
    Copies(u32),
    CopyEntries {
        space: String,
        id: i64,
        offset: u32,
    },
    Roots(u32),
    Files {
        space: String,
        root: Vec<String>,
        offset: u32,
    },
    Staged(u32),
}

enum ResultValue {
    Status(Result<Vec<MountInfo>, String>),
    Connected,
    Spaces(String, Vec<(String, String)>),
    Mounted(String),
    Unmounted,
    FolderOpened,
    Recovered,
    Pinned,
    Unpinned,
    Evicted,
    CacheStatus(CleanCacheStatus),
    Pins(String, Vec<(String, String)>),
    Staged,
    Journal(String, Option<String>, JournalPage),
    SyncStatus(cirrus_daemon::SyncStatus),
    Synced,
    Acknowledged,
    RecoveryRoots(String, u32, Vec<RetainedPin>),
    RecoveryFiles(String, String, Vec<String>, u32, Vec<RetainedPinFile>),
    RecoveryStaged(String, u32, Vec<RetainedStaged>),
    RecoveryExported,
    RecoveryCopies(String, u32, Vec<RetainedPinCopy>),
    RecoveryCopyEntries(String, String, i64, u32, Vec<RetainedPinCopyEntry>),
    PinCopyRemoved,
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Drive,
    Offline,
    Activity,
    Recovery,
}

struct State {
    page: Page,
    advanced: bool,
    edit_account: bool,
    show_mount_recovery: bool,
    service_running: bool,
    service_unavailable: bool,
    instance: TextEdit,
    ca: TextEdit,
    mountpoint: TextEdit,
    recovery_mountpoint: TextEdit,
    create_mountpoint: bool,
    accent: Option<Color>,
    accent_receiver: Receiver<Option<Color>>,
    accent_lifetime: Arc<()>,
    pin_path: TextEdit,
    cache_status: Option<CleanCacheStatus>,
    pins: Vec<(String, String)>,
    pins_instance: Option<String>,
    stage_path: TextEdit,
    stage_source: TextEdit,
    acknowledge_file: TextEdit,
    journal: Vec<(String, String)>,
    journal_instance: Option<String>,
    journal_space: Option<String>,
    journal_next: Option<i64>,
    journal_summary: Option<JournalSummary>,
    sync_status: Option<cirrus_daemon::SyncStatus>,
    sync_space_id: TextEdit,
    recovery_instance: Option<String>,
    recovery_page: Option<RecoveryPage>,
    recovery_rows: Vec<RecoveryRow>,
    recovery_selection: Option<RecoverySelection>,
    recovery_destination: TextEdit,
    pin_copy_remove: Option<(String, i64)>,
    spaces: Vec<(String, String)>,
    spaces_instance: Option<String>,
    selected: Option<String>,
    mounts: Vec<MountInfo>,
    mount_checked: bool,
    message: String,
    status_notice: Option<String>,
    error: bool,
    busy: bool,
    sign_in: Option<String>,
    sign_in_started: Option<Instant>,
    sign_in_seconds: u64,
    cancelling_sign_in: bool,
    cancel_sender: Sender<(String, Result<(), String>)>,
    cancel_receiver: Receiver<(String, Result<(), String>)>,
    wake: Option<Waker>,
    sender: Sender<(bool, Result<ResultValue, String>)>,
    receiver: Receiver<(bool, Result<ResultValue, String>)>,
}

impl Default for State {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        let (cancel_sender, cancel_receiver) = mpsc::channel();
        let (_, accent_receiver) = mpsc::channel();
        let accent_lifetime = Arc::new(());
        Self {
            page: Page::Drive,
            advanced: false,
            edit_account: true,
            show_mount_recovery: false,
            service_running: false,
            service_unavailable: false,
            instance: TextEdit::new(settings::server().unwrap_or_default()),
            ca: TextEdit::new(""),
            mountpoint: TextEdit::new(""),
            recovery_mountpoint: TextEdit::new(""),
            create_mountpoint: true,
            accent: None,
            accent_receiver,
            accent_lifetime,
            pin_path: TextEdit::new(""),
            cache_status: None,
            pins: Vec::new(),
            pins_instance: None,
            stage_path: TextEdit::new(""),
            stage_source: TextEdit::new(""),
            acknowledge_file: TextEdit::new(""),
            journal: Vec::new(),
            journal_instance: None,
            journal_space: None,
            journal_next: None,
            journal_summary: None,
            sync_status: None,
            sync_space_id: TextEdit::new(""),
            recovery_instance: None,
            recovery_page: None,
            recovery_rows: Vec::new(),
            recovery_selection: None,
            pin_copy_remove: None,
            recovery_destination: TextEdit::new(""),
            spaces: Vec::new(),
            spaces_instance: None,
            selected: None,
            mounts: Vec::new(),
            mount_checked: false,
            message: "Checking daemon…".into(),
            status_notice: None,
            error: false,
            busy: false,
            sign_in: None,
            sign_in_started: None,
            sign_in_seconds: 0,
            cancelling_sign_in: false,
            cancel_sender,
            cancel_receiver,
            wake: None,
            sender,
            receiver,
        }
    }
}

fn default_mountpoint(name: &str, spaces: &[(String, String)]) -> Result<String, &'static str> {
    if name.trim().is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.chars().any(char::is_control)
    {
        return Err("This Space name cannot be used as a folder name. Choose a location instead.");
    }
    if spaces.iter().filter(|(_, other)| other == name).count() != 1 {
        return Err("Multiple Spaces have this name. Choose a different location for each Space.");
    }
    let home = std::env::var_os("HOME")
        .and_then(|home| std::fs::canonicalize(home).ok())
        .filter(|home| home.is_dir())
        .ok_or("Cannot access your home directory. Choose a location instead.")?;
    let path = home.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => return Err("The default location already exists. Choose a different location."),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("Cannot check the default location. Choose a location instead."),
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or("The default location cannot be represented. Choose a location instead.")
}

impl State {
    fn use_default_mountpoint(&mut self) {
        let result = self
            .selected
            .as_ref()
            .and_then(|id| self.spaces.iter().find(|(space_id, _)| space_id == id))
            .ok_or("Choose a Space first.")
            .and_then(|(_, name)| default_mountpoint(name, &self.spaces));
        match result {
            Ok(path) => {
                self.mountpoint = TextEdit::new(&path);
                self.create_mountpoint = true;
                self.error = false;
                self.message = "A new default folder will be created when you mount.".into();
            }
            Err(message) => {
                self.mountpoint = TextEdit::new("");
                self.create_mountpoint = false;
                self.error = true;
                self.message = message.into();
            }
        }
    }

    fn start(&mut self, action: Action) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.error = false;
        if let Action::Connect { attempt, .. } = &action {
            self.sign_in = Some(attempt.clone());
            self.sign_in_started = Some(Instant::now());
            self.sign_in_seconds = 0;
            self.cancelling_sign_in = false;
        }
        let checking_status = matches!(action, Action::Status);
        if checking_status {
            self.service_unavailable = false;
        }
        if matches!(
            action,
            Action::Status | Action::Mount { .. } | Action::Unmount { .. } | Action::Recover { .. }
        ) {
            self.mount_checked = false;
        }
        // Sync can change journal entries even when it eventually returns an error.
        if matches!(action, Action::Sync(_, _)) {
            self.journal_instance = None;
        }
        if matches!(action, Action::CacheStatus | Action::Evict { .. }) {
            self.cache_status = None;
        }
        self.message = match action {
            Action::Connect { .. } => "Connecting or waiting for sign-in. Check your browser for errors; provider pages may not report errors to Cirrus. The browser response has a three-minute limit after the browser is requested.",
            Action::Spaces(_) => "Loading Spaces…",
            Action::Mount { .. } => "Mounting Space…",
            Action::OpenFolder(_) => "Opening your files…",
            Action::Unmount { .. } => "Unmounting Space…",
            Action::Recover { .. } => "Recovering the recorded mount…",
            Action::Status => "Checking daemon…",
            Action::Pin { .. } => "Verifying and pinning…",
            Action::Unpin { .. } => "Removing pin…",
            Action::Evict { .. } => "Removing clean cached ranges…",
            Action::CacheStatus => "Checking clean cache usage…",
            Action::Pins { .. } => "Checking pins…",
            Action::Stage { .. } => "Saving local copy…",
            Action::Journal(_, _, _) => "Checking journal…",
            Action::SyncStatus(_, _) => "Checking local automatic sync status…",
            Action::Sync(_, _) => "Checking pending work…",
            Action::Acknowledge { .. } => "Acknowledging inspected entry…",
            Action::RecoveryRoots { .. } => "Loading retained pin roots…",
            Action::RecoveryCopies { .. } => "Loading immutable displaced pin captures…",
            Action::RecoveryCopyEntries { .. } => "Reading captured identities and file versions…",
            Action::RemovePinCopy { .. } => "Removing only the named retained pin capture…",
            Action::RecoveryFiles { .. } => "Loading retained pin versions…",
            Action::RecoveryStaged { .. } => "Reading retained snapshots…",
            Action::RecoveryExport { .. } => "Validating and exporting local copy…",
        }
        .into();
        let sender = self.sender.clone();
        let wake = self.wake.clone();
        let ticking = self
            .sign_in
            .as_ref()
            .map(|_| Arc::new(AtomicBool::new(true)));
        if let (Some(ticking), Some(wake)) = (ticking.clone(), wake.clone()) {
            let lifetime = Arc::downgrade(&self.accent_lifetime);
            thread::spawn(move || {
                while ticking.load(Ordering::Acquire) && lifetime.upgrade().is_some() {
                    thread::sleep(Duration::from_secs(1));
                    if ticking.load(Ordering::Acquire) && lifetime.upgrade().is_some() {
                        wake();
                    }
                }
            });
        }
        thread::spawn(move || {
            let result = execute(action).map_err(|error| {
                if error.raw_os_error().is_some() {
                    "The operation couldn't access the service or a requested path. Check the service, paths and permissions".to_owned()
                } else {
                    error.to_string()
                }
            });
            if let Some(ticking) = ticking {
                ticking.store(false, Ordering::Release);
            }
            let _ = sender.send((checking_status, result));
            if let Some(wake) = wake {
                wake();
            }
        });
    }

    fn cancel_sign_in(&mut self) {
        let Some(attempt) = self.sign_in.clone().filter(|_| !self.cancelling_sign_in) else {
            return;
        };
        self.cancelling_sign_in = true;
        self.message = "Requesting cancellation…".into();
        let sender = self.cancel_sender.clone();
        let wake = self.wake.clone();
        thread::spawn(move || {
            let result = (|| {
                let path = std::env::var_os("XDG_RUNTIME_DIR")
                    .ok_or_else(|| std::io::Error::other("runtime directory unavailable"))?;
                let runtime = RuntimeDir::open(Path::new(&path))?;
                Daemon::new().cancel_connect(&runtime, &attempt)
            })()
            .map_err(|error| {
                if error.raw_os_error().is_some() {
                    "Could not reach the background service".to_owned()
                } else {
                    error.to_string()
                }
            });
            let _ = sender.send((attempt, result));
            if let Some(wake) = wake {
                wake();
            }
        });
    }
}

fn execute(action: Action) -> std::io::Result<ResultValue> {
    if let Action::OpenFolder(path) = action {
        let mut child = Command::new("xdg-open")
            .arg(path)
            .spawn()
            .map_err(|_| std::io::Error::other("Could not start the desktop folder opener"))?;
        thread::spawn(move || {
            let _ = child.wait();
        });
        return Ok(ResultValue::FolderOpened);
    }
    let path = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| std::io::Error::other("XDG_RUNTIME_DIR is not set"))?;
    let runtime = RuntimeDir::open(Path::new(&path))?;
    let daemon = Daemon::new();
    match action {
        Action::Status => {
            daemon.status(&runtime)?;
            Ok(ResultValue::Status(daemon.mounts(&runtime).map_err(
                |error| {
                    if error.raw_os_error().is_some() {
                        "Could not check the mount. Retry the service check.".to_owned()
                    } else {
                        error.to_string()
                    }
                },
            )))
        }
        Action::Connect {
            instance,
            ca,
            attempt,
        } => {
            let pem = if ca.is_empty() {
                None
            } else {
                let mut bytes = Vec::new();
                std::fs::File::open(ca)?
                    .take(65_537)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > 65_536 {
                    return Err(std::io::Error::other("CA certificate is too large"));
                }
                Some(
                    String::from_utf8(bytes)
                        .map_err(|_| std::io::Error::other("CA certificate must be PEM text"))?,
                )
            };
            daemon.connect_with_attempt(&runtime, &instance, pem, &attempt)?;
            Ok(ResultValue::Connected)
        }
        Action::Spaces(instance) => daemon
            .spaces(&runtime, &instance)
            .map(|spaces| ResultValue::Spaces(instance, spaces)),
        Action::Mount {
            instance,
            space,
            path,
        } => daemon
            .mount_space(&runtime, &instance, &space, path.as_deref())
            .map(ResultValue::Mounted),
        Action::OpenFolder(_) => unreachable!(),
        Action::Unmount { instance, space } => {
            daemon.unmount_space(&runtime, &instance, &space)?;
            Ok(ResultValue::Unmounted)
        }
        Action::Recover { path } => {
            daemon.recover_mount(&runtime, &path)?;
            Ok(ResultValue::Recovered)
        }
        Action::Pin {
            instance,
            space,
            path,
        } => {
            daemon.pin_space(&runtime, &instance, &space, space_path(&path))?;
            Ok(ResultValue::Pinned)
        }
        Action::Unpin {
            instance,
            space,
            path,
        } => {
            daemon.unpin_space(&runtime, &instance, &space, space_path(&path))?;
            Ok(ResultValue::Unpinned)
        }
        Action::Evict {
            instance,
            space,
            path,
        } => {
            daemon.evict_space(&runtime, &instance, &space, space_path(&path))?;
            Ok(ResultValue::Evicted)
        }
        Action::CacheStatus => daemon
            .clean_cache_status(&runtime)
            .map(ResultValue::CacheStatus),
        Action::Pins { instance, space } => daemon
            .pins_space(&runtime, &instance, &space)
            .map(|pins| ResultValue::Pins(instance, pins)),
        Action::Stage {
            instance,
            space,
            path,
            source,
        } => {
            daemon.stage_file_space(&runtime, &instance, &space, space_path(&path), &source)?;
            Ok(ResultValue::Staged)
        }
        Action::Journal(instance, space, before) => daemon
            .journal(&runtime, &instance, space.as_deref(), before)
            .map(|page| ResultValue::Journal(instance, space, page)),
        Action::SyncStatus(instance, space) => daemon
            .sync_status(&runtime, &instance, &space)
            .map(ResultValue::SyncStatus),
        Action::Sync(instance, space) => {
            if let Some(space) = space {
                daemon.sync_space(&runtime, &instance, &space)?;
            } else {
                daemon.sync_pending(&runtime, &instance)?;
            }
            Ok(ResultValue::Synced)
        }
        Action::Acknowledge { instance, staged } => {
            daemon.acknowledge(&runtime, &instance, &staged)?;
            Ok(ResultValue::Acknowledged)
        }
        Action::RecoveryCopies { instance, offset } => daemon
            .recovery_pin_copies(&runtime, &instance, offset)
            .map(|rows| ResultValue::RecoveryCopies(instance, offset, rows)),
        Action::RecoveryCopyEntries {
            instance,
            space,
            id,
            offset,
        } => daemon
            .recovery_pin_copy_entries(&runtime, &instance, &space, id, offset)
            .map(|rows| ResultValue::RecoveryCopyEntries(instance, space, id, offset, rows)),
        Action::RemovePinCopy {
            instance,
            space,
            id,
        } => daemon
            .remove_pin_copy(&runtime, &instance, &space, id)
            .map(|()| ResultValue::PinCopyRemoved),
        Action::RecoveryRoots { instance, offset } => daemon
            .recovery_pins(&runtime, &instance, offset)
            .map(|rows| ResultValue::RecoveryRoots(instance, offset, rows)),
        Action::RecoveryFiles {
            instance,
            space,
            root,
            offset,
        } => daemon
            .recovery_files(&runtime, &instance, &space, root.clone(), offset)
            .map(|rows| ResultValue::RecoveryFiles(instance, space, root, offset, rows)),
        Action::RecoveryStaged { instance, offset } => daemon
            .retained_staged(&runtime, &instance, offset)
            .map(|rows| ResultValue::RecoveryStaged(instance, offset, rows)),
        Action::RecoveryExport {
            instance,
            selection,
            destination,
        } => {
            match selection {
                RecoverySelection::Copy { space, id, file } => daemon.export_pin_copy(
                    &runtime,
                    &instance,
                    &space,
                    (id, file.path),
                    file.selector.as_deref().ok_or_else(|| {
                        std::io::Error::other("captured directory has no file payload")
                    })?,
                    &destination,
                )?,
                RecoverySelection::Pin { space, root, file } => daemon.export_retained(
                    &runtime,
                    &instance,
                    &space,
                    (root, file.path),
                    &file.selector,
                    &destination,
                )?,
                RecoverySelection::Staged(file) => daemon.export_staged(
                    &runtime,
                    &instance,
                    file.id,
                    file.selector
                        .as_deref()
                        .ok_or_else(|| std::io::Error::other("staged copy is unavailable"))?,
                    &destination,
                )?,
            }
            Ok(ResultValue::RecoveryExported)
        }
    }
}

fn same_instance(left: &str, right: &str) -> bool {
    match (
        Daemon::canonical_instance(left),
        Daemon::canonical_instance(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn space_path(path: &str) -> Vec<String> {
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').map(str::to_owned).collect()
    }
}

fn setup(state: &mut State, wake: Waker) {
    let (sender, receiver) = mpsc::channel();
    state.accent_receiver = receiver;
    let lifetime = Arc::downgrade(&state.accent_lifetime);
    let accent_wake = wake.clone();
    thread::spawn(move || {
        let mut previous = None;
        while lifetime.upgrade().is_some() {
            let accent = desktop_accent();
            if previous != Some(accent) {
                if sender.send(accent).is_err() {
                    break;
                }
                accent_wake();
                previous = Some(accent);
            }
            thread::sleep(Duration::from_secs(5));
        }
    });
    state.wake = Some(wake);
    state.start(Action::Status);
}

fn desktop_accent() -> Option<Color> {
    use zbus::zvariant::{OwnedValue, Value};
    let connection = zbus::blocking::Connection::session().ok()?;
    let portal = zbus::blocking::Proxy::new(
        &connection,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Settings",
    )
    .ok()?;
    let value: OwnedValue = portal
        .call("ReadOne", &("org.freedesktop.appearance", "accent-color"))
        .or_else(|_| portal.call("Read", &("org.freedesktop.appearance", "accent-color")))
        .ok()?;
    let mut value: &Value<'_> = &value;
    while let Value::Value(inner) = value {
        value = inner;
    }
    let Value::Structure(rgb) = value else {
        return None;
    };
    let [Value::F64(r), Value::F64(g), Value::F64(b)] = rgb.fields() else {
        return None;
    };
    if ![r, g, b]
        .iter()
        .all(|v| v.is_finite() && (0.0..=1.0).contains(*v))
    {
        return None;
    }
    Some(Color {
        r: rune::color::srgb_decode(*r as f32),
        g: rune::color::srgb_decode(*g as f32),
        b: rune::color::srgb_decode(*b as f32),
        a: 1.0,
    })
}

fn poll(state: &mut State, _: f64, _: &mut Tx) -> bool {
    let _keep_accent_worker_alive = &state.accent_lifetime;
    let mut accent_changed = false;
    if let Some(started) = state.sign_in_started {
        let seconds = started.elapsed().as_secs();
        if seconds != state.sign_in_seconds {
            state.sign_in_seconds = seconds;
            accent_changed = true;
        }
    }
    while let Ok(accent) = state.accent_receiver.try_recv() {
        if state.accent != accent {
            state.accent = accent;
            accent_changed = true;
        }
    }
    while let Ok((attempt, result)) = state.cancel_receiver.try_recv() {
        if state.sign_in.as_deref() == Some(attempt.as_str()) {
            match result {
                Ok(()) => {
                    state.message =
                        "Cancelling sign-in; waiting for the current request to finish…".into()
                }
                Err(error) => {
                    state.cancelling_sign_in = false;
                    state.error = true;
                    state.message = error;
                }
            }
            accent_changed = true;
        }
    }
    let Ok((checking_status, result)) = state.receiver.try_recv() else {
        return accent_changed;
    };
    state.busy = false;
    state.sign_in = None;
    state.sign_in_started = None;
    state.cancelling_sign_in = false;
    match result {
        Err(error) => {
            state.error = true;
            if checking_status {
                state.status_notice = None;
                state.service_running = false;
                state.service_unavailable = true;
                state.message =
                    "Cirrus couldn't reach its background service. Start the service, then retry."
                        .into();
            } else {
                state.message = if state.mount_checked {
                    format!("{error}. Check the details and try again.")
                } else {
                    format!("{error}. Refresh mount status before retrying.")
                };
            }
        }
        Ok(ResultValue::Status(Ok(mounts))) => {
            state.service_running = true;
            state.service_unavailable = false;
            state.mounts = mounts;
            state.mount_checked = true;
            state.message = state.status_notice.take().unwrap_or_else(||
                "Closing this window leaves the service running.".into());
        }
        Ok(ResultValue::Status(Err(error))) => {
            state.status_notice = None;
            state.service_running = true;
            state.service_unavailable = false;
            state.mount_checked = false;
            state.error = true;
            state.message = format!("Mount status could not be verified: {error}");
        }
        Ok(ResultValue::Connected) => {
            state.service_running = true;
            state.service_unavailable = false;
            state.pins_instance = None;
            state.journal_instance = None;
            state.spaces.clear();
            state.spaces_instance = None;
            state.selected = None;
            state.message = "Account connected. Loading Spaces…".into();
            if settings::save_server(&state.instance.text).is_err() {
                state.error = true;
                state.message =
                    "Account connected, but the server address could not be saved.".into();
            }
            state.start(Action::Spaces(state.instance.text.clone()));
        }
        Ok(ResultValue::Spaces(instance, spaces)) => {
            if state.spaces_instance.as_deref() != Some(instance.as_str()) {
                state.selected = None;
            }
            state.spaces_instance = Some(instance);
            let saved = settings::save_server(&state.instance.text).is_ok();
            state.spaces = spaces;
            state.edit_account = false;
            if state
                .selected
                .as_ref()
                .is_some_and(|id| !state.spaces.iter().any(|(space_id, _)| space_id == id))
            {
                state.selected = None;
            }
            state.message = if state.spaces.is_empty() {
                "No Spaces were returned"
            } else {
                "Choose a Space to configure its mount or offline work"
            }
            .into();
            if !saved {
                state.error = true;
                state.message = "Spaces loaded, but the server address could not be saved.".into();
            }
        }
        Ok(ResultValue::Mounted(path)) => {
            state.status_notice = Some(format!("Mounted at {path}."));
            state.start(Action::Status);
        }
        Ok(ResultValue::Unmounted) => {
            state.status_notice = Some("Space unmounted.".into());
            state.start(Action::Status);
        }
        Ok(ResultValue::FolderOpened) => {
            state.message = "Requested the desktop's default folder app. If a terminal opens instead, change the default app for folders in your desktop settings. A slow mount can delay folder contents.".into()
        }
        Ok(ResultValue::Recovered) => {
            state.status_notice = Some("Recorded stale mount recovered.".into());
            state.start(Action::Status);
        }
        Ok(ResultValue::Pinned) => {
            state.pins_instance = None;
            state.message = "Pin available offline. Refresh pins to view status.".into();
        }
        Ok(ResultValue::Unpinned) => {
            state.pins_instance = None;
            state.message = "Pin removed. Refresh pins to view status.".into();
        }
        Ok(ResultValue::Evicted) => {
            state.message = "Clean cached ranges removed. Pins and unsynced edits were kept.".into();
        }
        Ok(ResultValue::CacheStatus(status)) => {
            state.cache_status = Some(status);
            state.message = "Clean cache usage updated.".into();
        }
        Ok(ResultValue::Pins(instance, pins)) => {
            state.pins = pins;
            state.pins_instance = Some(instance);
            state.message = "Pin status updated".into();
        }
        Ok(ResultValue::Staged) => {
            state.journal_instance = None;
            state.message = "Saved locally. Check Journal status for pending changes or conflicts; upload is not yet confirmed.".into();
        }
        Ok(ResultValue::SyncStatus(status)) => {
            state.sync_status = Some(status);
            state.message = "Local sync observation updated; this is not a global cleanliness guarantee.".into();
        }
        Ok(ResultValue::Journal(instance, space, page)) => {
            state.journal_instance = Some(instance);
            state.journal_space = space;
            state.journal_next = page.next_before;
            state.journal_summary = Some(page.summary);
            state.journal = page
                .entries
                .into_iter()
                .map(|entry| {
                    let status = entry.status();
                    (entry.path, status)
                })
                .collect();
            state.message = "Journal status updated".into();
        }
        Ok(ResultValue::Synced) => {
            state.message = "Sync request finished. Check the journal for current pending work, conflicts, and retained copies.".into();
        }
        Ok(ResultValue::Acknowledged) => {
            state.journal_instance = None;
            state.message =
                "Acknowledged locally; remote outcome not asserted. Any staged copies are retained.".into();
        }
        Ok(ResultValue::RecoveryCopies(instance,offset,rows))=>{
            state.recovery_instance=Some(instance);state.recovery_page=Some(RecoveryPage::Copies(offset));state.recovery_rows=rows.into_iter().map(RecoveryRow::Copy).collect();state.recovery_selection=None;state.pin_copy_remove=None;
            state.message="Immutable displaced pin captures. Open an ID to inspect directories or export a selected file.".into();
        }
        Ok(ResultValue::RecoveryCopyEntries(instance,space,id,offset,rows))=>{
            state.recovery_instance=Some(instance);state.recovery_page=Some(RecoveryPage::CopyEntries{space:space.clone(),id,offset});state.recovery_rows=rows.into_iter().map(|entry|RecoveryRow::CopyEntry{space:space.clone(),id,entry}).collect();state.recovery_selection=None;state.pin_copy_remove=None;
            state.message="Captured directory IDs are metadata, not file payloads. Select a file version to export.".into();
        }
        Ok(ResultValue::PinCopyRemoved)=>{
            state.recovery_rows.clear();state.recovery_selection=None;state.pin_copy_remove=None;state.recovery_page=None;
            state.message="Removed only the named immutable pin capture. Active pins, other captures and dirty roots were not removed. Reload retained captures.".into();
        }
        Ok(ResultValue::RecoveryRoots(instance, offset, rows)) => {
            state.recovery_instance = Some(instance);
            state.recovery_page = Some(RecoveryPage::Roots(offset));
            state.recovery_rows = rows.into_iter().map(RecoveryRow::Root).collect();
            state.recovery_selection = None;
            state.message = "Retained pins may be stale; choose a pin root.".into();
        }
        Ok(ResultValue::RecoveryFiles(instance, space, root, offset, rows)) => {
            state.recovery_instance = Some(instance);
            state.recovery_page = Some(RecoveryPage::Files {
                space: space.clone(),
                root: root.clone(),
                offset,
            });
            state.recovery_rows = rows
                .into_iter()
                .map(|file| RecoveryRow::File {
                    space: space.clone(),
                    root: root.clone(),
                    file,
                })
                .collect();
            state.recovery_selection = None;
            state.message = "Retained versions may be stale; choose a file to export.".into();
        }
        Ok(ResultValue::RecoveryStaged(instance, offset, rows)) => {
            state.recovery_instance = Some(instance);
            state.recovery_page = Some(RecoveryPage::Staged(offset));
            state.recovery_rows = rows.into_iter().map(RecoveryRow::Staged).collect();
            state.recovery_selection = None;
            state.message = "Staged copies are local; their original hash was not recorded.".into();
        }
        Ok(ResultValue::RecoveryExported) => {
            state.message =
                "Exported local copy. It may be stale; remote outcome not asserted.".into();
        }
    }
    true
}

#[derive(Clone, Copy)]
struct Paint {
    theme: tok::Theme,
    accent: Color,
    accent_text: Color,
}

impl Paint {
    fn new(theme: tok::Theme, accent: Option<Color>) -> Self {
        let accent = accent.unwrap_or_else(|| rune::color::oklch(0.43, 0.12, 245.0));
        let luminance = 0.2126 * accent.r + 0.7152 * accent.g + 0.0722 * accent.b;
        let accent_text = if luminance > 0.179 {
            Color::BLACK
        } else {
            Color::WHITE
        };
        Self {
            theme,
            accent,
            accent_text,
        }
    }
}

fn button(
    paint: Paint,
    label: &str,
    key: String,
    enabled: bool,
    action: impl Fn(&mut State) + 'static,
) -> El {
    let theme = paint.theme;
    let button = el()
        .key(key)
        .label(label)
        .role("button")
        .focusable(enabled)
        .padding(10.0)
        .radius(6.0)
        .hover(theme.hover)
        .press(theme.press)
        .fill(if enabled {
            paint.accent
        } else {
            theme.control_off
        })
        .child(text(label.to_owned()).font(type_::LABEL).color(if enabled {
            paint.accent_text
        } else {
            theme.text_secondary
        }));
    if enabled {
        button.on_press(action)
    } else {
        button
    }
}

fn secondary_button(
    paint: Paint,
    label: &str,
    key: &str,
    action: impl Fn(&mut State) + 'static,
) -> El {
    let t = paint.theme;
    el().key(key)
        .label(label)
        .role("button")
        .focusable(true)
        .padding(10.0)
        .radius(6.0)
        .fill(t.card)
        .border(1.0, t.separator)
        .hover(t.hover)
        .press(t.press)
        .child(text(label.to_owned()).font(type_::LABEL).color(t.text))
        .on_press(action)
}

fn nav_button(paint: Paint, label: &'static str, page: Page, current: Page) -> El {
    el().key(format!("nav-{label}"))
        .label(label)
        .role("button")
        .focusable(true)
        .padding(10.0)
        .radius(5.0)
        .hover(paint.theme.hover)
        .fill(if page == current {
            paint.accent
        } else {
            paint.theme.card
        })
        .child(text(label).font(type_::TITLE).color(if page == current {
            paint.accent_text
        } else {
            paint.theme.text
        }))
        .on_press(move |s: &mut State| s.page = page)
}

fn view(state: &State, cx: &mut Cx<State>) -> El {
    let t = tok::theme(cx.system_dark());
    let paint = Paint::new(t, state.accent);
    let can_work = !state.busy;
    let known_mounted = state.mount_checked && !state.mounts.is_empty();
    let input = |field: &TextEdit,
                 key: &'static str,
                 hint: &'static str,
                 edit: fn(&mut State) -> &mut TextEdit| {
        let input = text_input(field, type_::BODY)
            .key(key)
            .label(match key {
                "instance" => "Server URL",
                "ca" => "Additional CA certificate path",
                "mountpoint" => "Mount directory",
                "recover-path" => "Original mount directory",
                "pin-path" => "Space path to pin",
                "stage-path" => "Destination Space path",
                "stage-source" => "Local source file",
                "acknowledge-file" => "Journal filename or operation token",
                "recovery-destination" => "New local destination",
                _ => hint,
            })
            .single_line()
            .w_full()
            .h(38.0)
            .px(10.0)
            .fill(t.card)
            .border(1.0, t.separator)
            .radius(5.0)
            .color(t.text)
            .placeholder(hint, t.text_secondary)
            .on_edit(edit);
        if can_work { input } else { input.inert() }
    };
    let mut spaces = col().key("spaces").gap(4.0);
    let current_spaces = state.spaces_instance.as_deref() == Some(state.instance.text.as_str());
    for (id, name) in state.spaces.iter().filter(|_| current_spaces) {
        let id = id.clone();
        let name = name.clone();
        let selected = state.selected.as_deref() == Some(id.as_str());
        let duplicate = state
            .spaces
            .iter()
            .filter(|(_, other)| other == &name)
            .count()
            > 1;
        let label = if duplicate {
            format!("{name} · {id}")
        } else {
            name
        };
        let mounted = state.mounts.iter().find(|mount| {
            same_instance(&mount.instance, &state.instance.text) && mount.space_id == id
        });
        let status = if !state.mount_checked {
            "Mount status unavailable; refresh the service check.".to_owned()
        } else if let Some(mount) = mounted {
            let description = match &mount.state {
                MountState::Mounted => "Mounted at",
                MountState::RecoveryRequired => "Recovery required at",
            };
            format!("{description} {}", mount.path)
        } else {
            "Not mounted".to_owned()
        };
        let choose_id = id.clone();
        let mut item = col()
            .w_full()
            .gap(6.0)
            .child(
                text(label)
                    .font(type_::TITLE)
                    .w_full()
                    .wrap_anywhere()
                    .color(t.text),
            )
            .child(
                text(status)
                    .font(type_::BODY)
                    .w_full()
                    .wrap_anywhere()
                    .color(t.text_secondary),
            )
            .child(row().child(button(
                paint,
                if selected { "Selected" } else { "Select" },
                format!("space-{id}"),
                can_work && !selected,
                move |s| {
                    s.selected = Some(choose_id.clone());
                    s.pins_instance = None;
                    if s.mounts.iter().any(|mount| {
                        same_instance(&mount.instance, &s.instance.text)
                            && mount.space_id == choose_id
                    }) {
                        s.mountpoint = TextEdit::new("");
                        s.error = false;
                        s.message = "Space selected for offline work.".into();
                    } else {
                        s.use_default_mountpoint();
                    }
                },
            )));
        if state.mount_checked
            && let Some(mount) = mounted
        {
            let path = mount.path.clone();
            let instance = mount.instance.clone();
            let space = mount.space_id.clone();
            let actions = match &mount.state {
                MountState::Mounted => {
                    let open_path = path.clone();
                    row()
                        .gap(8.0)
                        .child(button(
                            paint,
                            "Open folder",
                            format!("open-folder-{id}"),
                            can_work,
                            move |s| s.start(Action::OpenFolder(open_path.clone())),
                        ))
                        .child(button(
                            paint,
                            "Unmount",
                            format!("unmount-{id}"),
                            can_work,
                            move |s| {
                                s.start(Action::Unmount {
                                    instance: instance.clone(),
                                    space: space.clone(),
                                })
                            },
                        ))
                }
                MountState::RecoveryRequired => row().child(button(
                    paint,
                    "Recover stale mount",
                    format!("recover-{id}"),
                    can_work,
                    move |s| s.start(Action::Recover { path: path.clone() }),
                )),
            };
            item = item.child(actions);
        }
        spaces = spaces.child(item.padding(10.0));
    }
    if current_spaces && state.spaces.is_empty() {
        spaces = spaces.child(
            text("No Spaces were returned. Check access on your server, then try again.")
                .font(type_::BODY)
                .w_full()
                .wrap()
                .color(t.text_secondary),
        );
    }
    let current_recovery = state.recovery_instance.as_deref() == Some(state.instance.text.as_str());
    let mut recovery_rows = col().key("recovery-rows").gap(6.0);
    for (index, entry) in state
        .recovery_rows
        .iter()
        .enumerate()
        .filter(|_| current_recovery)
    {
        let (label, action_label, selectable) = match entry {
            RecoveryRow::Copy(copy) => (
                format!(
                    "Capture #{} · Space {} · original /{} · displaced /{} · target {} {}",
                    copy.id,
                    copy.space,
                    copy.root.join("/"),
                    copy.displaced_path.join("/"),
                    copy.target_id,
                    copy.target_etag
                ),
                "Inspect capture",
                true,
            ),
            RecoveryRow::CopyEntry { id, entry, .. } => (
                format!(
                    "Capture #{id} · /{} · {}{}",
                    entry.path.join("/"),
                    entry.kind,
                    entry
                        .id
                        .as_ref()
                        .map_or_else(String::new, |id| format!(" · ID {id}"))
                ),
                if entry.kind == "file" {
                    "Choose file"
                } else {
                    "Directory metadata"
                },
                entry.kind == "file" && entry.selector.is_some(),
            ),
            RecoveryRow::Root(pin) => (
                format!(
                    "Space {} · pin /{} · possibly stale",
                    pin.space,
                    pin.root.join("/")
                ),
                "Open pin",
                true,
            ),
            RecoveryRow::File { file, .. } => (
                format!(
                    "/{} · {} bytes · retained, possibly stale",
                    file.path.join("/"),
                    file.size
                        .map_or_else(|| "unknown".into(), |size| size.to_string())
                ),
                "Choose file",
                true,
            ),
            RecoveryRow::Staged(file) => (
                format!(
                    "Space {} · /{} · {} · {} bytes · journal {}",
                    file.space,
                    file.path.join("/"),
                    file.state,
                    file.size
                        .map_or_else(|| "unavailable".into(), |size| size.to_string()),
                    file.id
                ),
                "Choose copy",
                file.selector.is_some(),
            ),
        };
        let entry = entry.clone();
        recovery_rows = recovery_rows.child(
            row()
                .w_full()
                .center_y()
                .gap(8.0)
                .child(
                    text(label)
                        .font(type_::BODY)
                        .color(t.text)
                        .grow(1.0)
                        .shrink()
                        .wrap_anywhere(),
                )
                .child(button(
                    paint,
                    action_label,
                    format!("recovery-row-{index}"),
                    can_work && selectable,
                    move |s| match &entry {
                        RecoveryRow::Copy(copy)=>s.start(Action::RecoveryCopyEntries{instance:s.instance.text.clone(),space:copy.space.clone(),id:copy.id,offset:0}),
                        RecoveryRow::CopyEntry {space,id,entry}=>{
                            s.recovery_selection=Some(RecoverySelection::Copy{space:space.clone(),id:*id,file:entry.clone()});s.message="Selected immutable captured file version; export to a new absolute local path.".into();
                        }
                        RecoveryRow::Root(pin) => s.start(Action::RecoveryFiles {
                            instance: s.instance.text.clone(),
                            space: pin.space.clone(),
                            root: pin.root.clone(),
                            offset: 0,
                        }),
                        RecoveryRow::File { space, root, file } => {
                            s.recovery_selection = Some(RecoverySelection::Pin {
                                space: space.clone(),
                                root: root.clone(),
                                file: file.clone(),
                            });
                            s.message =
                                "Selected retained pin version; choose a new local destination."
                                    .into();
                        }
                        RecoveryRow::Staged(file) => {
                            s.recovery_selection = Some(RecoverySelection::Staged(file.clone()));
                            s.message =
                                "Selected staged copy; choose a new local destination.".into();
                        }
                    },
                )),
        );
    }
    if current_recovery && state.recovery_rows.is_empty() {
        recovery_rows = recovery_rows.child(
            text("No entries on this page. Reload from the beginning.")
                .font(type_::BODY)
                .color(t.text_secondary),
        );
    }
    let selected_recovery = if current_recovery {
        match &state.recovery_selection {
            Some(RecoverySelection::Copy { space, id, file }) => format!(
                "Selected immutable capture #{id} · Space {space} · /{} · {} bytes; not the current namespace",
                file.path.join("/"),
                file.size
                    .map_or_else(|| "unknown".into(), |size| size.to_string())
            ),
            Some(RecoverySelection::Pin { space, root, file }) => format!(
                "Selected retained pin: Space {space} · pin /{} · file /{}; possibly stale",
                root.join("/"),
                file.path.join("/")
            ),
            Some(RecoverySelection::Staged(file)) => format!(
                "Selected staged copy: Space {} · /{} · {} · journal {}",
                file.space,
                file.path.join("/"),
                file.state,
                file.id
            ),
            None => match &state.recovery_page {
                Some(RecoveryPage::CopyEntries { space, id, .. }) => format!(
                    "Browsing immutable capture #{id} · Space {space}. Directory rows expose captured IDs; only file rows can be exported."
                ),
                Some(RecoveryPage::Files { space, root, .. }) => format!(
                    "Browsing Space {space} · pin /{}; choose a retained file.",
                    root.join("/")
                ),
                _ => "Choose a retained copy before exporting.".to_owned(),
            },
        }
    } else {
        "Load retained copies for this account.".to_owned()
    };
    let account_context = if state.instance.text.is_empty() {
        "Enter an account URL in Drive setup first.".to_owned()
    } else {
        format!("Account: {}", state.instance.text)
    };
    let selected_context = if current_spaces {
        state
            .selected
            .as_ref()
            .and_then(|id| state.spaces.iter().find(|(space_id, _)| space_id == id))
            .map_or_else(
                || "Select a Space on the Drive page first.".to_owned(),
                |(id, name)| format!("Selected Space: {name} · {id}"),
            )
    } else {
        "Load Spaces and select one on the Drive page first.".to_owned()
    };
    let mut account = col().w_full().gap(10.0).child(
        text("OpenCloud account")
            .font(tok::TextStyle::new(16.0, 600.0))
            .color(t.text),
    );
    if state.edit_account || !current_spaces {
        if known_mounted {
            account = account.child(
                text("The last check showed a mounted Space. Unmount it before connecting an account; refresh if the mount has changed.")
                    .font(type_::BODY)
                    .w_full()
                    .wrap()
                    .color(t.text_secondary),
            );
        }
        account = account
            .child(
                text("Enter your server address. Sign-in opens in your browser.")
                    .font(type_::BODY)
                    .w_full()
                    .wrap()
                    .color(t.text_secondary),
            )
            .child(text("Server URL").font(type_::LABEL).color(t.text))
            .child(
                input(&state.instance, "instance", "https://cloud.example", |s| {
                    &mut s.instance
                })
                .max_w(480.0),
            );
        if state.advanced {
            account = account
                .child(
                    text("Additional CA certificate (PEM path)")
                        .font(type_::LABEL)
                        .color(t.text),
                )
                .child(
                    input(&state.ca, "ca", "Absolute certificate path", |s| &mut s.ca).max_w(480.0),
                )
                .child(
                    text("Certificate verification remains enabled.")
                        .font(type_::BODY)
                        .color(t.text_secondary),
                );
        }
        account = account
            .child(
                row()
                    .gap(8.0)
                    .child(button(
                        paint,
                        "Connect account",
                        "connect".into(),
                        can_work && !known_mounted && !state.instance.text.trim().is_empty(),
                        |s| match Daemon::sign_in_attempt() {
                            Ok(attempt) => s.start(Action::Connect {
                                instance: s.instance.text.clone(),
                                ca: s.ca.text.clone(),
                                attempt,
                            }),
                            Err(_) => {
                                s.error = true;
                                s.message =
                                    "Cannot start sign-in: system randomness is unavailable."
                                        .into();
                            }
                        },
                    ))
                    .child(button(
                        paint,
                        "Load Spaces",
                        "load-spaces".into(),
                        can_work && !state.instance.text.trim().is_empty(),
                        |s| s.start(Action::Spaces(s.instance.text.clone())),
                    )),
            )
            .child(
                text("Already connected? Load Spaces uses an existing account.")
                    .font(type_::BODY)
                    .w_full()
                    .wrap()
                    .color(t.text_secondary),
            )
            .child(row().child(secondary_button(
                paint,
                if state.advanced {
                    "Hide advanced settings"
                } else {
                    "Advanced settings"
                },
                "advanced",
                |s| s.advanced = !s.advanced,
            )));
    } else {
        account = account
            .child(
                text(state.instance.text.clone())
                    .font(type_::BODY)
                    .w_full()
                    .wrap_anywhere()
                    .color(t.text_secondary),
            )
            .child(
                row()
                    .gap(8.0)
                    .child(secondary_button(
                        paint,
                        "Change account",
                        "change-account",
                        |s| s.edit_account = true,
                    ))
                    .child(button(
                        paint,
                        "Refresh Spaces",
                        "load-spaces".into(),
                        can_work,
                        |s| s.start(Action::Spaces(s.instance.text.clone())),
                    )),
            );
    }
    let mut drive = col()
        .w_full()
        .gap(18.0)
        .child(
            text("Your drive")
                .font(tok::TextStyle::new(22.0, 600.0))
                .color(t.text),
        )
        .child(
            text("Access your Spaces from Linux applications without making a full local mirror.")
                .font(type_::BODY)
                .w_full()
                .wrap()
                .color(t.text_secondary),
        )
        .child(
            col()
                .w_full()
                .padding(20.0)
                .gap(10.0)
                .radius(8.0)
                .fill(t.card)
                .border(1.0, t.separator)
                .child(account),
        );
    if current_spaces {
        let space_section = col()
            .w_full()
            .gap(10.0)
            .child(
                text("Spaces")
                    .font(tok::TextStyle::new(16.0, 600.0))
                    .color(t.text),
            )
            .child(
                text("Select a Space to set its mount location or use it for offline work.")
                    .font(type_::BODY)
                    .w_full()
                    .wrap()
                    .color(t.text_secondary),
            )
            .child(spaces);
        drive = drive.child(
            col()
                .w_full()
                .padding(20.0)
                .radius(8.0)
                .fill(t.card)
                .border(1.0, t.separator)
                .child(space_section),
        );
    }
    let other_mounts: Vec<_> = state
        .mounts
        .iter()
        .filter(|mount| {
            !current_spaces
                || !same_instance(&mount.instance, &state.instance.text)
                || !state.spaces.iter().any(|(id, _)| id == &mount.space_id)
        })
        .collect();
    if state.mount_checked && !other_mounts.is_empty() {
        let mut section = col()
            .w_full()
            .padding(20.0)
            .gap(10.0)
            .radius(8.0)
            .fill(t.card)
            .border(1.0, t.separator)
            .child(
                text("Other recorded Spaces")
                    .font(tok::TextStyle::new(16.0, 600.0))
                    .color(t.text),
            );
        for mount in other_mounts {
            let instance = mount.instance.clone();
            let space = mount.space_id.clone();
            let path = mount.path.clone();
            let key = format!("{}-{}", instance, space);
            let description = match &mount.state {
                MountState::Mounted => "Mounted at",
                MountState::RecoveryRequired => "Recovery required at",
            };
            let mut entry = col()
                .w_full()
                .gap(6.0)
                .child(
                    text(format!("{} · {}", mount.space_name, instance))
                        .font(type_::TITLE)
                        .w_full()
                        .wrap_anywhere()
                        .color(t.text),
                )
                .child(
                    text(format!("{description} {path}"))
                        .font(type_::BODY)
                        .w_full()
                        .wrap_anywhere()
                        .color(t.text_secondary),
                );
            entry = match &mount.state {
                MountState::Mounted => entry.child(
                    row()
                        .gap(8.0)
                        .child(button(
                            paint,
                            "Open folder",
                            format!("open-other-{key}"),
                            can_work,
                            move |s| s.start(Action::OpenFolder(path.clone())),
                        ))
                        .child(button(
                            paint,
                            "Unmount",
                            format!("unmount-other-{key}"),
                            can_work,
                            move |s| {
                                s.start(Action::Unmount {
                                    instance: instance.clone(),
                                    space: space.clone(),
                                })
                            },
                        )),
                ),
                MountState::RecoveryRequired => entry.child(row().child(button(
                    paint,
                    "Recover stale mount",
                    format!("recover-other-{key}"),
                    can_work,
                    move |s| s.start(Action::Recover { path: path.clone() }),
                ))),
            };
            section = section.child(entry);
        }
        drive = drive.child(section);
    }
    let selected_space = state
        .selected
        .as_ref()
        .and_then(|id| state.spaces.iter().find(|(space_id, _)| space_id == id));
    let selected_has_mount = state.selected.as_ref().is_some_and(|id| {
        state.mounts.iter().any(|mount| {
            same_instance(&mount.instance, &state.instance.text) && &mount.space_id == id
        })
    });
    if current_spaces && selected_space.is_some() && !selected_has_mount {
        let selected_name = selected_space
            .map(|(_, name)| name.clone())
            .unwrap_or_default();
        drive = drive.child(col().w_full().padding(20.0).gap(10.0).radius(8.0).fill(t.card).border(1.0, t.separator)
            .child(text(format!("Mount {selected_name}")).font(tok::TextStyle::new(16.0, 600.0)).w_full().wrap_anywhere().color(t.text))
            .child(text("Your files will appear here:").font(type_::BODY).color(t.text_secondary))
            .child(text(if state.mountpoint.text.is_empty() { "Choose a location".to_owned() } else { state.mountpoint.text.clone() }).font(type_::BODY).w_full().wrap_anywhere().color(t.text))
            .child(text("By default Cirrus creates a new folder named after this Space in your home directory. If it already exists, choose another location. You may also choose an existing empty, user-owned folder with permissions 0700; Cirrus will not change its permissions.").font(type_::BODY).w_full().wrap().color(t.text_secondary))
            .child(row().gap(8.0).child(el().key("choose-mount-folder").label("Choose location").role("button").focusable(can_work).padding(10.0).radius(6.0).fill(t.card).border(1.0, t.separator).hover(t.hover).press(t.press)
                .child(text("Choose location").font(type_::LABEL).color(t.text))
                .on_press_tx(|s: &mut State, tx: &mut Tx| {
                    if s.busy { return; }
                    tx.open_folder(FileDialogOptions { title: "Choose the mount folder".into(), ..Default::default() }, |s: &mut State, result, _| match result {
                        Ok(Some(parent)) => match parent.canonicalize() {
                            Ok(folder) => match folder.to_str() {
                                Some(path) => { s.mountpoint = TextEdit::new(path); s.create_mountpoint = false; s.error = false; },
                                None => { s.error = true; s.message = "This location has a name Cirrus cannot represent. Choose another folder.".into(); }
                            },
                            Err(_) => { s.error = true; s.message = "Cannot access that folder. Choose another location.".into(); }
                        },
                        Ok(None) => {},
                        Err(error) => { s.error = true; s.message = format!("Folder picker unavailable: {error}. Check your desktop portal and retry."); }
                    });
                })).child(secondary_button(paint, "Use default", "default-mount-folder", |s| { if !s.busy { s.use_default_mountpoint(); } })))
            .child(row().child(button(paint, "Mount Space", "mount".into(), can_work && state.mount_checked && !state.mountpoint.text.is_empty(), |s| {
                if let Some(space) = s.selected.clone() {
                    s.start(Action::Mount { instance: s.instance.text.clone(), space, path: if s.create_mountpoint { None } else { Some(s.mountpoint.text.clone()) } });
                }
            })))
            .child(text("Mounting activates automatic uploads for this Space, independent of the selected Space or this window. Activation persists after unmount and daemon restart. Changes are saved locally first; fsync is not remote confirmation. Check Activity & sync for retries and attention. Server races and rename/open-handle restrictions remain.").font(type_::BODY).w_full().wrap().color(t.text_secondary)));
    }
    {
        drive = drive.child(row().child(secondary_button(
            paint,
            if state.show_mount_recovery {
                "Hide stale mount recovery"
            } else {
                "Recover a stale mount"
            },
            "toggle-recover",
            |s| s.show_mount_recovery = !s.show_mount_recovery,
        )));
        if state.show_mount_recovery {
            drive = drive.child(col().w_full().padding(20.0).gap(10.0).radius(8.0).fill(t.card).border(1.0, t.separator)
                .child(text("Recover a stale mount").font(tok::TextStyle::new(16.0, 600.0)).color(t.text))
                .child(text("After restarting the service, enter the original mount directory. Cirrus checks the recorded identity before recovery.").font(type_::BODY).w_full().wrap().color(t.text_secondary))
                .child(input(&state.recovery_mountpoint, "recover-path", "Original absolute mount directory", |s| &mut s.recovery_mountpoint).max_w(480.0))
                .child(row().child(button(paint, "Recover stale mount", "recover".into(), can_work && !state.recovery_mountpoint.text.is_empty(), |s| s.start(Action::Recover { path: s.recovery_mountpoint.text.clone() })) )));
        }
    }
    let activity = col()
        .w_full()
        .gap(12.0)
        .child(text("Activity & sync").font(tok::TextStyle::new(22.0, 600.0)).color(t.text))
        .child(text("Mounted Spaces activate daemon-owned automatic sync. Activation survives restart without remounting. Local saves are not remote confirmation; conflicts and ambiguous requests need attention.").font(type_::BODY).w_full().wrap().color(t.text_secondary))
        .child(input(&state.sync_space_id,"automatic-space-id","Space ID for local status (or use the selected Space)",|s| &mut s.sync_space_id).max_w(480.0))
        .child(row().child(button(paint,"Automatic sync status","automatic-sync-status".into(),can_work && (!state.sync_space_id.text.is_empty() || state.selected.is_some()),|s| {
            let space = if s.sync_space_id.text.trim().is_empty() { s.selected.clone() } else { Some(s.sync_space_id.text.trim().to_owned()) };
            if let Some(space) = space { s.start(Action::SyncStatus(s.instance.text.clone(),space)); }
        })))
        .child(text(if let Some(status) = state.sync_status.as_ref().filter(|status| status.instance == state.instance.text) {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0,|duration| duration.as_secs() as i64);
            let next = status.next_attempt.map_or_else(|| "none scheduled".into(),|time| if time>now { format!("in {}s",time-now) } else { "due; refresh status".into() });
            let last = status.last_verified.map_or_else(|| "none yet".into(),|time| format!("{}s ago (historical)",now.saturating_sub(time)));
            format!("Last local observation · Space {} · {:?}\nActivated {} · worker enabled here {}\n{} queued · {} uploading · {} verifying · {} ambiguous · {} conflicts · {} damaged\nRetry attempt {} · {} · cause {}\nLast verified mutation {} · new work {} · journal high-water {} (observed idle through {}). Not globally clean.",status.space,status.phase,status.activated,status.worker_enabled_here.unwrap_or(false),status.queued,status.uploading,status.verifying,status.uncertain,status.conflicts,status.damaged,status.retry_attempt,next,status.cause.as_deref().unwrap_or("none"),last,status.new_work,status.high_water,status.verified_through)
        } else { "Automatic sync status not checked for this Space. Refresh after new work or a service restart.".into() }).font(type_::BODY).w_full().wrap_anywhere().color(t.text_secondary))
        .child(text("Review pending changes, conflicts and errors in the journal. Sync now checks all Spaces; Sync selected Space checks only the selected Space.").font(type_::BODY).w_full().wrap().color(t.text_secondary))
        .child(text(account_context.clone()).font(type_::BODY).w_full().wrap_anywhere().color(t.text_secondary))
        .child(text(selected_context.clone()).font(type_::BODY).w_full().wrap_anywhere().color(t.text_secondary))
        .child(text("Server races can overwrite or delete remote changes. Inspect the journal and retained copies before acknowledging conflicts.").font(type_::BODY).w_full().wrap().color(t.text_secondary))
        .child(text("Local staging").font(type_::TITLE).color(t.text))
        .child(text("Destination Space path").font(type_::LABEL).color(t.text))
        .child(input(
            &state.stage_path,
            "stage-path",
            "Destination Space path",
            |s| &mut s.stage_path,
        ))
        .child(text("Local source file").font(type_::LABEL).color(t.text))
        .child(input(
            &state.stage_source,
            "stage-source",
            "Absolute local source file",
            |s| &mut s.stage_source,
        ))
        .child(
            row()
                .gap(8.0)
                .child(button(paint,
                    "Save locally",
                    "stage".into(),
                    can_work
                        && current_spaces && state.selected.is_some()
                        && !state.stage_path.text.is_empty()
                        && !state.stage_source.text.is_empty(),
                    |s| {
                        if let Some(space) = s.selected.clone() {
                            s.start(Action::Stage {
                                instance: s.instance.text.clone(), space,
                                path: s.stage_path.text.clone(),
                                source: s.stage_source.text.clone(),
                            });
                        }
                    },
                ))
                .child(button(paint, "Journal status", "journal".into(), can_work, |s| {
                    s.start(Action::Journal(s.instance.text.clone(), None, None))
                }))
                .child(button(paint, "Sync now", "sync".into(), can_work, |s| {
                    s.start(Action::Sync(s.instance.text.clone(), None))
                })),
        )
        .child(button(paint, "Sync selected Space", "sync-space".into(), can_work && current_spaces && state.selected.is_some(), |s| {
            if let Some(space) = s.selected.clone() {
                s.start(Action::Sync(s.instance.text.clone(), Some(space)));
            }
        }))
        .child(text("Remove cached data for this path without removing offline pins or unsynced edits.").font(type_::BODY).w_full().wrap().color(t.text_secondary))
        .child(button(paint, "Evict clean cache", "evict".into(), can_work && current_spaces && state.selected.is_some() && !state.pin_path.text.is_empty(), |s| {
            if let Some(space) = s.selected.clone() {
                s.start(Action::Evict { instance: s.instance.text.clone(), space, path: s.pin_path.text.clone() });
            }
        }))
        .child(text(
            if state.journal_instance.as_deref() == Some(state.instance.text.as_str()) {
                state.journal_summary.as_ref().map(|summary| format!(
                    "Last checked {} journal: {} pending · {} conflicts · {} uncertain or in progress · {} historically synced · {} resolved. Historical sync does not confirm the current remote state.",
                    state.journal_space.as_ref().map_or_else(|| "account".to_owned(), |space| format!("Space {space}")),
                    summary.pending, summary.conflict, summary.uncertain_or_in_progress, summary.synced, summary.resolved
                )).unwrap_or_else(|| "Journal summary unavailable; refresh.".to_owned())
            } else {
                "Account journal summary not checked yet.".to_owned()
            }
        ).font(type_::BODY).w_full().wrap_anywhere().color(t.text_secondary))
        .child(
            text(
                if state.journal_instance.as_deref() != Some(state.instance.text.as_str()) {
                    "Check journal status for pending changes, conflicts and errors.".to_owned()
                } else if state.journal.is_empty() {
                    "No journal entries were returned on this page. Check newest entries before acting."
                        .to_owned()
                } else {
                    let entries = state
                        .journal
                        .iter()
                        .map(|(path, status)| format!("{path}: {status}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    format!("Last checked journal page, newest first (refresh before acting):\n{entries}")
                },
            )
            .font(type_::BODY)
            .w_full()
            .wrap_anywhere()
            .color(t.text_secondary),
        )
        .child(row().gap(8.0)
            .child(button(paint, "Selected Space journal", "journal-space".into(), can_work && current_spaces && state.selected.is_some(), |s| {
                if let Some(space) = s.selected.clone() {
                    s.start(Action::Journal(s.instance.text.clone(), Some(space), None));
                }
            }))
            .child(button(paint, "Older journal entries", "journal-older".into(), can_work && state.journal_instance.as_deref() == Some(state.instance.text.as_str()) && state.journal_next.is_some(), |s| {
                if let Some(before) = s.journal_next {
                    s.start(Action::Journal(s.instance.text.clone(), s.journal_space.clone(), Some(before)));
                }
            })))
        .child(input(
            &state.acknowledge_file,
            "acknowledge-file",
            "Journal filename or operation token after inspection",
            |s| &mut s.acknowledge_file,
        ))
        .child(button(paint,
            "Acknowledge inspected conflict",
            "acknowledge".into(),
            can_work && !state.acknowledge_file.text.is_empty(),
            |s| {
                s.start(Action::Acknowledge {
                    instance: s.instance.text.clone(),
                    staged: s.acknowledge_file.text.clone(),
                })
            },
        ));
    let offline = col()
        .w_full()
        .gap(12.0)
        .child(text("Offline pins").font(tok::TextStyle::new(22.0, 600.0)).color(t.text))
        .child(text("Keep selected paths available offline. Pins are not a backup and retained copies may be stale.").font(type_::BODY).w_full().wrap().color(t.text_secondary))
        .child(text(account_context.clone()).font(type_::BODY).w_full().wrap_anywhere().color(t.text_secondary))
        .child(text(selected_context).font(type_::BODY).w_full().wrap_anywhere().color(t.text_secondary))
        .child(text("Space path").font(type_::TITLE).color(t.text))
        .child(input(
            &state.pin_path,
            "pin-path",
            "Space path, or / for the root",
            |s| &mut s.pin_path,
        ))
        .child(
            row()
                .gap(8.0)
                .child(button(paint,
                    "Pin",
                    "pin".into(),
                    can_work && current_spaces && state.selected.is_some() && !state.pin_path.text.is_empty(),
                    |s| {
                        if let Some(space) = s.selected.clone() {
                            s.start(Action::Pin { instance: s.instance.text.clone(), space, path: s.pin_path.text.clone() });
                        }
                    },
                ))
                .child(button(paint,
                    "Unpin",
                    "unpin".into(),
                    can_work && current_spaces && state.selected.is_some() && !state.pin_path.text.is_empty(),
                    |s| {
                        if let Some(space) = s.selected.clone() {
                            s.start(Action::Unpin { instance: s.instance.text.clone(), space, path: s.pin_path.text.clone() });
                        }
                    },
                ))
                .child(button(paint, "Pins", "pins".into(), can_work && current_spaces && state.selected.is_some(), |s| {
                    if let Some(space) = s.selected.clone() {
                        s.start(Action::Pins { instance: s.instance.text.clone(), space });
                    }
                })),
        )
        .child(
            text(
                if state.pins_instance.as_deref() != Some(state.instance.text.as_str()) {
                    "Select Pins to check offline status".to_owned()
                } else if state.pins.is_empty() {
                    "No pins listed".to_owned()
                } else {
                    state
                        .pins
                        .iter()
                        .map(|(path, status)| format!("{path}: {status}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                },
            )
            .font(type_::BODY)
            .w_full()
            .wrap_anywhere()
            .color(t.text_secondary),
        )
        .child(text("Clean cache").font(type_::TITLE).color(t.text))
        .child(text("Temporary ranges are shared across Spaces and may be evicted. They are not offline pins.").font(type_::BODY).w_full().wrap().color(t.text_secondary))
        .child(row().child(button(paint, "Check cache usage", "cache-status".into(), state.service_running && !state.busy, |s| s.start(Action::CacheStatus))))
        .child(text(match &state.cache_status {
            Some(status) => {
                let limit = if status.byte_limit.is_multiple_of(1024 * 1024) {
                    format!("{} MiB", status.byte_limit / (1024 * 1024))
                } else {
                    format!("{} bytes", status.byte_limit)
                };
                format!("Last checked: {} payload bytes of {limit} · {} of {} ranges. Excludes pins, unsynced edits and SQLite overhead; refresh for current usage.", status.bytes, status.ranges, status.range_limit)
            },
            None => "Cache usage has not been checked.".to_owned(),
        }).font(type_::BODY).w_full().wrap().color(t.text_secondary));
    let mut recovery = col()
        .w_full()
        .gap(12.0)
        .child(text("Recover a local copy").font(tok::TextStyle::new(22.0, 600.0)).color(t.text))
        .child(text("No server or keyring needed. Pins may be stale; staged copies have no recorded original hash. Export never overwrites.").font(type_::BODY).w_full().wrap().color(t.text_secondary))
        .child(text(account_context).font(type_::BODY).w_full().wrap_anywhere().color(t.text_secondary))
        .child(row().gap(8.0)
            .child(button(paint, "Retained pins", "recovery-pins".into(), can_work && !state.instance.text.is_empty(), |s| s.start(Action::RecoveryRoots { instance: s.instance.text.clone(), offset: 0 })))
            .child(button(paint, "Staged copies", "recovery-staged".into(), can_work && !state.instance.text.is_empty(), |s| s.start(Action::RecoveryStaged { instance: s.instance.text.clone(), offset: 0 })))
            .child(button(paint, "More", "recovery-more".into(), can_work && current_recovery && !state.recovery_rows.is_empty(), |s| {
                let next = s.recovery_rows.len() as u32;
                match s.recovery_page.clone() {
                    Some(RecoveryPage::Copies(offset))=>s.start(Action::RecoveryCopies{instance:s.instance.text.clone(),offset:offset.saturating_add(next)}),
                    Some(RecoveryPage::CopyEntries{space,id,offset})=>s.start(Action::RecoveryCopyEntries{instance:s.instance.text.clone(),space,id,offset:offset.saturating_add(next)}),
                    Some(RecoveryPage::Roots(offset)) => s.start(Action::RecoveryRoots { instance: s.instance.text.clone(), offset: offset.saturating_add(next) }),
                    Some(RecoveryPage::Staged(offset)) => s.start(Action::RecoveryStaged { instance: s.instance.text.clone(), offset: offset.saturating_add(next) }),
                    Some(RecoveryPage::Files { space, root, offset }) => s.start(Action::RecoveryFiles { instance: s.instance.text.clone(), space, root, offset: offset.saturating_add(next) }),
                    None => {}
                }
            })))
        .child(row().child(button(paint, "Displaced pin captures", "recovery-pin-copies".into(), can_work && !state.instance.text.is_empty(), |s| s.start(Action::RecoveryCopies { instance: s.instance.text.clone(), offset: 0 }))))
        .child(recovery_rows)
        .child(text(selected_recovery).font(type_::BODY).w_full().wrap_anywhere().color(t.text_secondary))
        .child(input(&state.recovery_destination, "recovery-destination", "New absolute local destination", |s| &mut s.recovery_destination))
        .child(button(paint, "Export selected copy", "recovery-export".into(), can_work && current_recovery && state.recovery_selection.is_some() && !state.recovery_destination.text.is_empty(), |s| {
            if let Some(selection) = s.recovery_selection.clone() {
                s.start(Action::RecoveryExport { instance: s.instance.text.clone(), selection, destination: s.recovery_destination.text.clone() });
            }
        }));

    if let Some(RecoveryPage::CopyEntries { space, id, .. }) =
        state.recovery_page.as_ref().filter(|_| current_recovery)
    {
        let space = space.clone();
        let id = *id;
        let confirmed = state.pin_copy_remove.as_ref() == Some(&(space.clone(), id));
        recovery=recovery
            .child(text(format!("Remove capture #{id} in Space {space} only. Its retained bytes will no longer be recoverable from this copy. Active pins, other captures and dirty roots remain." )).font(type_::BODY).w_full().wrap_anywhere().color(t.text_secondary))
            .child(button(paint,if confirmed {"Confirm removal of this capture"}else{"Remove this retained capture…"},"remove-pin-copy".into(),can_work,move|s|{
                if s.pin_copy_remove.as_ref()==Some(&(space.clone(),id)) {s.start(Action::RemovePinCopy{instance:s.instance.text.clone(),space:space.clone(),id});}
                else {s.pin_copy_remove=Some((space.clone(),id));s.message=format!("Review capture #{id} before confirming removal. This affects only that capture ID.");}
            }))
            .child(button(paint,"Cancel capture removal","cancel-pin-copy-removal".into(),can_work&&confirmed,|s|s.pin_copy_remove=None));
    }

    let page = match state.page {
        Page::Drive => drive,
        Page::Offline => offline,
        Page::Activity => activity,
        Page::Recovery => recovery,
    };
    let mount_status = if state.service_unavailable {
        "Background service unavailable".to_owned()
    } else if !state.service_running {
        "Checking background service…".to_owned()
    } else if !state.mount_checked {
        if state.error {
            "Service reached · mount status unavailable".to_owned()
        } else {
            "Service reachable · checking mount".to_owned()
        }
    } else {
        let mounted = state
            .mounts
            .iter()
            .filter(|mount| matches!(&mount.state, MountState::Mounted))
            .count();
        let recovery = state.mounts.len() - mounted;
        if recovery == 0 {
            format!("Service reachable · {mounted} mounted")
        } else {
            format!("Service reachable · {mounted} mounted · {recovery} need recovery")
        }
    };
    let status_message = if state.sign_in_started.is_some() {
        format!(
            "Sign-in active · {}:{:02} elapsed. {}",
            state.sign_in_seconds / 60,
            state.sign_in_seconds % 60,
            state.message
        )
    } else {
        state.message.clone()
    };
    let mut status = col().w_full().max_w(680.0).gap(8.0).child(
        row()
            .w_full()
            .center_y()
            .gap(12.0)
            .child(
                text(mount_status)
                    .font(type_::TITLE)
                    .color(t.text)
                    .grow(1.0)
                    .shrink()
                    .wrap_anywhere(),
            )
            .child(button(
                paint,
                if state.service_unavailable {
                    "Retry"
                } else {
                    "Refresh"
                },
                "refresh".into(),
                can_work,
                |s| s.start(Action::Status),
            )),
    );
    if state.sign_in.is_some() {
        status = status.child(row().child(button(
            paint,
            if state.cancelling_sign_in {
                "Cancelling…"
            } else {
                "Cancel sign-in"
            },
            "cancel-sign-in".into(),
            !state.cancelling_sign_in,
            |s| s.cancel_sign_in(),
        )));
    }
    if state.service_unavailable {
        status = status
            .child(
                text(status_message.clone())
                    .key("status")
                    .font(type_::BODY)
                    .w_full()
                    .wrap()
                    .color(if cx.system_dark() {
                        rune::color::oklch(0.78, 0.14, 25.0)
                    } else {
                        rune::color::oklch(0.45, 0.17, 25.0)
                    }),
            )
            .child(
                text("If installed as a user service, run this in a terminal, then retry:")
                    .font(type_::BODY)
                    .w_full()
                    .wrap()
                    .color(t.text_secondary),
            )
            .child(
                text("systemctl --user start cirrus-drive.service")
                    .font(type_::BODY)
                    .w_full()
                    .wrap_anywhere()
                    .color(t.text),
            )
            .child(
                text(
                    "Otherwise, start cirrus-daemon in a terminal. Cirrus does not start it here.",
                )
                .font(type_::BODY)
                .w_full()
                .wrap()
                .color(t.text_secondary),
            );
    } else {
        status = status.child(
            text(status_message)
                .key("status")
                .font(type_::BODY)
                .w_full()
                .wrap_anywhere()
                .color(if state.error {
                    if cx.system_dark() {
                        rune::color::oklch(0.78, 0.14, 25.0)
                    } else {
                        rune::color::oklch(0.45, 0.17, 25.0)
                    }
                } else {
                    t.text_secondary
                }),
        );
    }
    col()
        .w_full()
        .h_full()
        .fill(t.bg)
        .child(
            col()
                .w_full()
                .padding(16.0)
                .gap(12.0)
                .fill(t.card)
                .child(
                    row()
                        .w_full()
                        .center_y()
                        .gap(12.0)
                        .child(
                            text("Cirrus Drive")
                                .font(tok::TextStyle::new(18.0, 600.0))
                                .color(t.text)
                                .grow(1.0),
                        )
                        .child(
                            text("Your files, on demand")
                                .font(type_::LABEL)
                                .color(t.text_secondary),
                        ),
                )
                .child(
                    row()
                        .gap(4.0)
                        .child(nav_button(paint, "Drive", Page::Drive, state.page))
                        .child(nav_button(paint, "Offline", Page::Offline, state.page))
                        .child(nav_button(paint, "Activity", Page::Activity, state.page))
                        .child(nav_button(paint, "Recovery", Page::Recovery, state.page)),
                ),
        )
        .child(
            col()
                .w_full()
                .items_center()
                .padding(16.0)
                .fill(t.card)
                .child(status),
        )
        .child(
            col()
                .w_full()
                .grow(1.0)
                .padding(24.0)
                .items_center()
                .child(page.max_w(680.0))
                .scroll(ScrollSpec {
                    stick_bottom: false,
                }),
        )
}

/// The desktop entry point. Closing the window does not stop the daemon.
#[derive(Debug, Default)]
pub struct Ui;
impl Ui {
    /// Creates a desktop entry point without touching account state.
    pub fn new() -> Self {
        Self
    }
    /// Starts the Rune window or headless Rune tooling.
    ///
    /// # Errors
    /// Returns an error if the window or rendering backend cannot start.
    pub fn launch(&self) -> Result<(), UiUnavailable> {
        rune::set_app_id("org.cirrusdrive.App");
        let spec = AppSpec {
            setup: Some(setup),
            poll: Some(poll),
            min_size: Some((460.0, 580.0)),
            ..AppSpec::new("Cirrus Drive", (820.0, 740.0), State::default, view)
        };
        let app = App::new(spec).tab_visits_controls(true);
        let handle = app.handle();
        let finished = Arc::new(AtomicBool::new(false));
        let monitor_finished = Arc::clone(&finished);
        let monitor = thread::spawn(move || {
            while !monitor_finished.load(Ordering::Acquire) {
                if let Some(error) = handle.window_error() {
                    handle.quit();
                    return Some(error);
                }
                if handle.is_visible() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            None
        });
        let result = app.try_run();
        finished.store(true, Ordering::Release);
        let window_error = monitor
            .join()
            .map_err(|_| UiUnavailable("window startup monitor failed".into()))?;
        if let Some(error) = window_error {
            return Err(UiUnavailable(format!(
                "{error}; check the Vulkan driver and any VK_DRIVER_FILES or VK_ICD_FILENAMES overrides"
            )));
        }
        result.map_err(UiUnavailable)
    }
}

/// A Rune window or renderer failure.
#[derive(Debug)]
pub struct UiUnavailable(String);
impl fmt::Display for UiUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot start Rune UI: {}", self.0)
    }
}
impl Error for UiUnavailable {}

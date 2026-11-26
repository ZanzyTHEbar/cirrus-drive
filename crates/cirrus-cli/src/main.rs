#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use cirrus_client::{
    AccountReply, AccountRequest as Q, ClientError, CredentialPolicyRequest, MountMode, Operation,
    ReleaseRequest, Reply, SpacePath, StorageLimits,
};

const HELP: &str = "\
Usage: cirrus-daemon --help | --version | --check-runtime | --status | --stop
       cirrus-daemon --release-status | --mount-engines | --activate-release RELEASE_ID | --rollback-release
       cirrus-daemon --credential-policy | --activate-credential-policy RELEASE_ID | --rollback-credential-policy
       cirrus-daemon --discover HTTPS_URL [--ca-cert PEM_FILE]
       cirrus-daemon --connect HTTPS_URL [--ca-cert PEM_FILE]
       cirrus-daemon --spaces HTTPS_URL
       cirrus-daemon --ls-space HTTPS_URL SPACE_ID [SPACE_PATH]
       cirrus-daemon --ls-offline-space HTTPS_URL SPACE_ID SPACE_PATH
       cirrus-daemon --mount-space HTTPS_URL SPACE_ID [MOUNTPOINT]
       cirrus-daemon --mount-offline-space HTTPS_URL SPACE_ID MOUNTPOINT
       cirrus-daemon --mount-offline-writable-space HTTPS_URL SPACE_ID MOUNTPOINT
       cirrus-daemon --mounts | --unmount-space HTTPS_URL SPACE_ID | --recover-mount MOUNTPOINT
       cirrus-daemon --pin-space HTTPS_URL SPACE_ID SPACE_PATH | --unpin-space HTTPS_URL SPACE_ID SPACE_PATH
       cirrus-daemon --pins-space HTTPS_URL SPACE_ID [--check-remote]
       cirrus-daemon --stage-file-space HTTPS_URL SPACE_ID SPACE_PATH LOCAL_FILE
       cirrus-daemon --stage-file-offline-space HTTPS_URL SPACE_ID SPACE_PATH LOCAL_FILE
       cirrus-daemon --evict-space HTTPS_URL SPACE_ID SPACE_PATH
       cirrus-daemon --journal HTTPS_URL [BEFORE_ID] | --journal-space HTTPS_URL SPACE_ID [BEFORE_ID]
       cirrus-daemon --sync HTTPS_URL | --sync-space HTTPS_URL SPACE_ID | --sync-status HTTPS_URL SPACE_ID
       cirrus-daemon --acknowledge HTTPS_URL JOURNAL_TOKEN
       cirrus-daemon --cache-status | --storage-status | --storage-limits
       cirrus-daemon --set-storage-limits BUDGET_BYTES RESERVE_BYTES | --disable-storage-limits
       cirrus-daemon --release-storage-reservation state|cache|namespace TOKEN
       cirrus-daemon --retained-staged HTTPS_URL [OFFSET]
       cirrus-daemon --retained-pins HTTPS_URL [OFFSET] | --retained-files HTTPS_URL SPACE_ID PIN_ROOT [OFFSET]
       cirrus-daemon --pin-copies HTTPS_URL [OFFSET] | --pin-copy-entries HTTPS_URL SPACE_ID COPY_ID [OFFSET]
       cirrus-daemon --export-staged HTTPS_URL JOURNAL_ID SELECTOR ABSOLUTE_DESTINATION
       cirrus-daemon --export-retained HTTPS_URL SPACE_ID PIN_ROOT FILE_PATH SELECTOR ABSOLUTE_DESTINATION
       cirrus-daemon --export-pin-copy HTTPS_URL SPACE_ID COPY_ID FILE_PATH SELECTOR ABSOLUTE_DESTINATION
       cirrus-daemon --remove-pin-copy HTTPS_URL SPACE_ID COPY_ID

Start the service separately with cirrus-drive-service [--no-auto-sync].
An omitted online MOUNTPOINT defaults to ~/SPACE_NAME.
The read-only offline mount requires --no-auto-sync; writable offline mounts
use local retained identity and saved metadata and do not check the remote.";

#[derive(Default)]
struct Presentation {
    label: &'static str,
    done: &'static str,
    offline_directory: bool,
    remote_pins: bool,
    sync_warning: bool,
    journal_space: Option<String>,
}

impl Presentation {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            ..Self::default()
        }
    }

    fn done(mut self, text: &'static str) -> Self {
        self.done = text;
        self
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if let [flag] = args.as_slice() {
        if flag == "--version" {
            print!("cirrus-daemon {}", env!("CARGO_PKG_VERSION"));
            if let Ok(release) = env::var("CIRRUS_RUNNING_RELEASE") {
                print!(" (release {release})");
            }
            println!();
            return ExitCode::SUCCESS;
        }
        let info = match flag.to_str() {
            Some("--help") => Some(HELP),
            #[cfg(feature = "fault-injection")]
            Some("--lab-capabilities") => Some("cirrus-drive disposable account and mount lab v1"),
            _ => None,
        };
        if let Some(info) = info {
            println!("{info}");
            return ExitCode::SUCCESS;
        }
    }
    let (operation, output) = match parse(&args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{message}");
            // Keep the historical exits on the account path/mount/recovery groups.
            return if matches!(
                args.first().and_then(|arg| arg.to_str()),
                Some(
                    "--pin-space"
                        | "--unpin-space"
                        | "--pins-space"
                        | "--evict-space"
                        | "--ls-offline-space"
                        | "--stage-file-space"
                        | "--stage-file-offline-space"
                        | "--mounts"
                        | "--mount-space"
                        | "--mount-offline-space"
                        | "--mount-offline-writable-space"
                        | "--unmount-space"
                        | "--recover-mount"
                        | "--retained-pins"
                        | "--retained-files"
                        | "--retained-staged"
                        | "--pin-copies"
                        | "--pin-copy-entries"
                        | "--remove-pin-copy"
                        | "--export-pin-copy"
                        | "--export-retained"
                        | "--export-staged"
                )
            ) {
                ExitCode::FAILURE
            } else {
                ExitCode::from(2)
            };
        }
    };
    if output.sync_warning {
        eprintln!(
            "warning: server races can overwrite or delete remote changes despite ETag checks; staged copies are retained"
        );
    }
    let reply = match cirrus_client::execute(operation) {
        Ok(reply) => reply,
        Err(error) => {
            eprintln!("{}: {error}", output.label);
            return if matches!(error, ClientError::ShutdownBusy) {
                ExitCode::from(75)
            } else {
                ExitCode::FAILURE
            };
        }
    };
    if let Err(error) = render(reply, output) {
        eprintln!("cannot render reply: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn parse(args: &[OsString]) -> Result<(Operation, Presentation), &'static str> {
    let [flag, rest @ ..] = args else {
        return Err("no command; use --help (start the service with cirrus-drive-service)");
    };
    let flag = flag.to_str().ok_or("unknown option; use --help")?;
    match (flag, rest) {
        ("--no-auto-sync", []) => {
            return Err("start diagnostics with cirrus-drive-service --no-auto-sync");
        }
        ("--check-runtime", []) => {
            return Ok((
                Operation::CheckRuntime,
                Presentation::new("XDG_RUNTIME_DIR"),
            ));
        }
        ("--status", []) => {
            return Ok((Operation::Status, Presentation::new("local daemon")));
        }
        ("--stop", []) => {
            return Ok((Operation::Stop, Presentation::new("local daemon")));
        }
        ("--release-status", []) => {
            return Ok((Operation::Release(ReleaseRequest::Status), Presentation::new("release")));
        }
        ("--mount-engines", []) => {
            return Ok((Operation::MountEngines, Presentation::new("mounted read engine")));
        }
        ("--rollback-release", []) => {
            return Ok((Operation::Release(ReleaseRequest::Rollback), Presentation::new("release rollback")));
        }
        ("--activate-release", [id]) => {
            let release = id.to_str().filter(|id| !id.is_empty() && id.len() <= 64)
                .ok_or("invalid release ID")?.to_owned();
            return Ok((Operation::Release(ReleaseRequest::Activate { release }), Presentation::new("release activation")));
        }
        ("--credential-policy" | "--rollback-credential-policy", []) => {
            let request = if flag == "--credential-policy" {
                CredentialPolicyRequest::Status
            } else {
                CredentialPolicyRequest::Rollback
            };
            return Ok((
                Operation::CredentialPolicy(request),
                Presentation::new("credential policy"),
            ));
        }
        ("--activate-credential-policy", [id]) => {
            let release = id
                .to_str()
                .filter(|id| !id.is_empty() && id.len() <= 64)
                .ok_or("invalid release ID")?
                .to_owned();
            return Ok((
                Operation::CredentialPolicy(CredentialPolicyRequest::Activate { release }),
                Presentation::new("credential policy activation"),
            ));
        }
        ("--discover" | "--connect", _) => {
            let (instance, ca) = match rest {
                [instance] => (instance, None),
                [instance, option, path] if option == "--ca-cert" => {
                    (instance, Some(PathBuf::from(path)))
                }
                _ => return Err("expected HTTPS_URL [--ca-cert PEM_FILE]"),
            };
            let instance = instance
                .to_str()
                .ok_or("instance URL must be UTF-8")?
                .to_owned();
            return Ok(if flag == "--connect" {
                (
                    Operation::Connect { instance, ca },
                    Presentation::new("account").done("account connected"),
                )
            } else {
                (
                    Operation::Discover { instance, ca },
                    Presentation::new("discovery"),
                )
            });
        }
        _ => {}
    }
    let args = rest
        .iter()
        .map(|value| value.to_str().ok_or("arguments must be UTF-8"))
        .collect::<Result<Vec<_>, _>>()?;
    let args = args.as_slice();
    let text = str::to_owned;
    let path = SpacePath::from_slash_separated;
    let account = Presentation::new("account");
    let mount = Presentation::new("mount");
    let recovery = Presentation::new("recovery");
    let storage = Presentation::new("storage limits");
    let (operation, output) = match (flag, args) {
        ("--storage-status", []) => (Q::StorageStatus, Presentation::new("storage")),
        ("--cache-status", []) => (Q::CleanCacheStatus, Presentation::new("cache")),
        ("--storage-limits", []) => (Q::StorageLimits, storage),
        ("--disable-storage-limits", []) => (Q::SetStorageLimits { limits: None }, storage),
        ("--set-storage-limits", [budget, reserve]) => {
            let budget_bytes = decimal(budget)
                .filter(|value| *value > 0)
                .ok_or("invalid storage limit bytes (budget must be positive)")?;
            let free_space_reserve_bytes =
                decimal(reserve).ok_or("invalid storage reserve bytes")?;
            (
                Q::SetStorageLimits {
                    limits: Some(StorageLimits {
                        budget_bytes,
                        free_space_reserve_bytes,
                    }),
                },
                storage,
            )
        }
        ("--release-storage-reservation", [store @ ("state" | "cache" | "namespace"), token])
            if token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            (
                Q::ReleaseStorageReservation {
                    store: store.parse()?,
                    token: text(token),
                },
                Presentation::new("storage reservation").done("{}"),
            )
        }
        ("--release-storage-reservation", _) => {
            return Err(
                "--release-storage-reservation requires state|cache|namespace TOKEN from --storage-status",
            );
        }
        ("--mounts", []) => (Q::Mounts, mount),
        ("--mount-space", [instance, space, rest @ ..]) if rest.len() <= 1 => (
            Q::MountSpace {
                instance: text(instance),
                space: text(space),
                path: rest.first().map(PathBuf::from),
            },
            mount,
        ),
        ("--mount-offline-space", [instance, space, point]) => (
            Q::OfflineMountSpace {
                instance: text(instance),
                space: text(space),
                path: PathBuf::from(point),
            },
            mount,
        ),
        ("--mount-offline-writable-space", [instance, space, point]) => (
            Q::WritableOfflineMountSpace {
                instance: text(instance),
                space: text(space),
                path: PathBuf::from(point),
            },
            mount,
        ),
        ("--unmount-space", [instance, space]) => (
            Q::UnmountSpace {
                instance: text(instance),
                space: text(space),
            },
            mount.done("Space unmounted"),
        ),
        ("--recover-mount", [point]) => (
            Q::RecoverMount {
                path: PathBuf::from(point),
            },
            mount.done("recorded stale mount recovered"),
        ),
        ("--spaces", [instance]) => (
            Q::Spaces {
                instance: text(instance),
            },
            account,
        ),
        ("--ls-space", [instance, space, parts @ ..]) if parts.len() <= 1 => (
            Q::DirectorySpace {
                instance: text(instance),
                space: text(space),
                path: path(parts.first().copied().unwrap_or_default()),
            },
            account,
        ),
        ("--ls-space", [..]) if args.len() < 2 => {
            return Err("--ls-space requires a UTF-8 Space ID");
        }
        ("--ls-offline-space", [instance, space, item]) => (
            Q::OfflineDirectory {
                instance: text(instance),
                space: text(space),
                path: path(item),
            },
            Presentation {
                offline_directory: true,
                ..account
            },
        ),
        ("--pin-space", [instance, space, item]) => (
            Q::PinSpace {
                instance: text(instance),
                space: text(space),
                path: path(item),
            },
            account.done("available offline"),
        ),
        ("--unpin-space", [instance, space, item]) => (
            Q::UnpinSpace {
                instance: text(instance),
                space: text(space),
                path: path(item),
            },
            account.done("pin removed"),
        ),
        ("--evict-space", [instance, space, item]) => (
            Q::EvictSpace {
                instance: text(instance),
                space: text(space),
                path: path(item),
            },
            account.done("clean cached ranges evicted"),
        ),
        ("--pins-space", [instance, space]) => (
            Q::PinsSpace {
                instance: text(instance),
                space: text(space),
            },
            account,
        ),
        ("--pins-space", [instance, space, "--check-remote"]) => (
            Q::PinsSpaceCheckRemote {
                instance: text(instance),
                space: text(space),
            },
            Presentation {
                remote_pins: true,
                ..account
            },
        ),
        ("--pins-space", _) => return Err("expected HTTPS_URL SPACE_ID [--check-remote]"),
        ("--stage-file-space", [instance, space, item, source]) => (
            Q::StageFileSpace {
                instance: text(instance),
                space: text(space),
                path: path(item),
                source: PathBuf::from(source),
            },
            account.done("saved locally; upload pending"),
        ),
        ("--stage-file-offline-space", [instance, space, item, source]) => (
            Q::StageFileOfflineSpace {
                instance: text(instance),
                space: text(space),
                path: path(item),
                source: PathBuf::from(source),
            },
            account.done("saved locally; upload pending"),
        ),
        (
            "--pin-space"
            | "--unpin-space"
            | "--evict-space"
            | "--ls-offline-space"
            | "--stage-file-space"
            | "--stage-file-offline-space",
            _,
        ) => return Err("expected HTTPS_URL SPACE_ID [SPACE_PATH [LOCAL_FILE]]"),
        ("--journal", [instance, cursor @ ..]) if cursor.len() <= 1 => (
            Q::Journal {
                instance: text(instance),
                space: None,
                before: before(cursor)?,
            },
            account,
        ),
        ("--journal-space", [instance, space, cursor @ ..]) if cursor.len() <= 1 => (
            Q::Journal {
                instance: text(instance),
                space: Some(text(space)),
                before: before(cursor)?,
            },
            Presentation {
                journal_space: Some(text(space)),
                ..account
            },
        ),
        ("--sync", [instance]) => (
            Q::Sync {
                instance: text(instance),
            },
            sync_presentation(account),
        ),
        ("--sync-space", [instance, space]) => (
            Q::SyncSpace {
                instance: text(instance),
                space: text(space),
            },
            sync_presentation(account),
        ),
        ("--sync-status", [instance, space]) => (
            Q::SyncStatus {
                instance: text(instance),
                space: text(space),
            },
            account,
        ),
        ("--acknowledge", [instance, staged]) => (
            Q::Acknowledge {
                instance: text(instance),
                staged: text(staged),
            },
            account.done(
                "acknowledged locally; remote outcome not asserted; any staged copies retained",
            ),
        ),
        ("--retained-staged", [instance, rest @ ..]) if rest.len() <= 1 => (
            Q::RetainedStaged {
                instance: text(instance),
                offset: offset(rest)?,
            },
            recovery,
        ),
        ("--retained-pins", [instance, rest @ ..]) if rest.len() <= 1 => (
            Q::RetainedPins {
                instance: text(instance),
                offset: offset(rest)?,
            },
            recovery,
        ),
        ("--retained-files", [instance, space, root, rest @ ..]) if rest.len() <= 1 => (
            Q::RetainedFiles {
                instance: text(instance),
                space: text(space),
                root: path(root),
                offset: offset(rest)?,
            },
            recovery,
        ),
        ("--pin-copies", [instance, rest @ ..]) if rest.len() <= 1 => (
            Q::PinCopies {
                instance: text(instance),
                offset: offset(rest)?,
            },
            recovery,
        ),
        ("--pin-copy-entries", [instance, space, id, rest @ ..]) if rest.len() <= 1 => (
            Q::PinCopyEntries {
                instance: text(instance),
                space: text(space),
                id: numeric_id(id)?,
                offset: offset(rest)?,
            },
            recovery,
        ),
        ("--remove-pin-copy", [instance, space, id]) => (
            Q::RemovePinCopy {
                instance: text(instance),
                space: text(space),
                id: numeric_id(id)?,
            },
            recovery.done(
                "removed only the named retained pin copy; active pins and dirty roots unchanged",
            ),
        ),
        ("--export-pin-copy", [instance, space, id, item, selector, destination]) => (
            Q::ExportPinCopy {
                instance: text(instance),
                space: text(space),
                id: numeric_id(id)?,
                path: path(item),
                selector: text(selector),
                destination: PathBuf::from(destination),
            },
            recovery.done("exported immutable retained pin copy; remote not checked"),
        ),
        ("--export-retained", [instance, space, root, item, selector, destination]) => (
            Q::ExportRetained {
                instance: text(instance),
                space: text(space),
                root: path(root),
                path: path(item),
                selector: text(selector),
                destination: PathBuf::from(destination),
            },
            recovery.done("exported retained version; it may be stale"),
        ),
        ("--export-staged", [instance, id, selector, destination]) => (
            Q::ExportStaged {
                instance: text(instance),
                id: numeric_id(id)?,
                selector: text(selector),
                destination: PathBuf::from(destination),
            },
            recovery.done("exported retained staged copy; remote outcome not asserted"),
        ),
        (_, []) => return Err("unknown option; use --help"),
        _ => return Err("unexpected arguments; use --help"),
    };
    Ok((Operation::Account(operation), output))
}

fn numeric_id(value: &str) -> Result<i64, &'static str> {
    value.parse().map_err(|_| "invalid local ID")
}

fn before(args: &[&str]) -> Result<Option<i64>, &'static str> {
    args.first()
        .map(|value| {
            value
                .parse::<i64>()
                .ok()
                .filter(|id| *id != 0)
                .ok_or("journal cursor must be a nonzero integer ID")
        })
        .transpose()
}

fn offset(args: &[&str]) -> Result<u32, &'static str> {
    args.first()
        .map_or(Ok(0), |value| value.parse().map_err(|_| "invalid offset"))
}

fn decimal(value: &str) -> Option<u64> {
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

fn sync_presentation(account: Presentation) -> Presentation {
    Presentation { sync_warning: true, ..account.done("no pending operations in requested scope; inspect the journal for retained copies and acknowledged outcomes") }
}

fn print_json(value: &impl serde::Serialize) -> serde_json::Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

fn print_page<T>(
    page: cirrus_client::RetainedPage<T>,
    mut row: impl FnMut(T) -> serde_json::Result<()>,
) -> serde_json::Result<()> {
    for entry in page.entries {
        row(entry)?;
    }
    if let Some(next) = page.next_offset {
        eprintln!("next offset: {next}");
    }
    Ok(())
}

fn render(reply: Reply, output: Presentation) -> serde_json::Result<()> {
    use AccountReply as A;
    match reply {
        Reply::RuntimeChecked => println!(
            "runtime directory passed the current owner, mode and path checks; no service was started"
        ),
        Reply::Status(status) => println!("{status}"),
        Reply::Stopping => println!("daemon stopping"),
        Reply::Release(status) => println!("{}", serde_json::to_string(&status)?),
        Reply::CredentialPolicy(profile) => print_json(&profile)?,
        Reply::MountEngines(report) => println!("{}", serde_json::to_string(&report)?),
        Reply::Discovery(config) => println!(
            "issuer: {}\nclient ID: {}\nscopes: {}\nauthorization endpoint: {}\ntoken endpoint: {}\nJWKS URI: {}\ndynamic registration advertised: {} (not used by Cirrus)",
            config.issuer(),
            config.client_id(),
            config.scopes().join(" "),
            config.authorization_endpoint(),
            config.token_endpoint(),
            config.jwks_uri(),
            if config.registration_advertised() {
                "yes"
            } else {
                "no"
            }
        ),
        Reply::Account(reply) => match reply {
            A::Done => println!("{}", output.done),
            A::Spaces(spaces) => {
                for space in spaces {
                    println!("{}\t{}", space.id, space.name);
                }
            }
            A::Entries(entries) => {
                if output.offline_directory {
                    eprintln!(
                        "local saved metadata and pending entries; remote not checked; content availability not asserted"
                    );
                }
                for entry in entries {
                    if entry.directory {
                        println!("dir\t-\t{}", entry.name);
                    } else {
                        println!(
                            "file\t{}\t{}",
                            entry
                                .size
                                .map_or_else(|| "?".to_owned(), |size| size.to_string()),
                            entry.name
                        );
                    }
                }
            }
            A::Pins(pins) => {
                for pin in pins {
                    if output.remote_pins
                        && let Some(evidence) = pin.remote_diagnostic()
                    {
                        eprintln!("{}: {evidence}", pin.path);
                    }
                    println!("{}\t{}", pin.status(output.remote_pins), pin.path);
                }
            }
            A::Journal(page) => {
                let scope = output
                    .journal_space
                    .map_or_else(|| "account".to_owned(), |space| format!("Space {space}"));
                let s = page.summary;
                eprintln!(
                    "{scope} journal: {} pending, {} conflict, {} uncertain or in progress, {} historically synced, {} resolved",
                    s.pending, s.conflict, s.uncertain_or_in_progress, s.synced, s.resolved
                );
                if page.entries.is_empty() {
                    println!("no journal entries on this page");
                }
                for entry in page.entries {
                    println!("{}\t{}", entry.status(), entry.path);
                }
                if let Some(cursor) = page.next_before {
                    eprintln!("older entries: {cursor}");
                }
            }
            A::SyncStatus(status) => print_json(&status)?,
            A::CleanCacheStatus(status) => print_json(&status)?,
            A::StorageStatus(status) => print_json(&status)?,
            A::StorageLimits(view) => print_json(&view)?,
            A::Mounts(mounts) => {
                for mount in mounts {
                    print_json(&mount)?;
                }
            }
            A::Mounted(mount) => {
                let path = mount.path;
                let sync = if mount.automatic_sync_enabled {
                    "activated work can sync automatically with the original authenticated identity"
                } else {
                    "automatic sync is disabled; changes are local until explicit sync"
                };
                match mount.mode {
                    MountMode::Online => println!("Space mounted at {path} experimentally; {sync}"),
                    MountMode::OfflineReadOnly => println!(
                        "read-only offline Space mounted at {path}; retained local identity and metadata; remote not checked; content availability not asserted; writes unavailable"
                    ),
                    MountMode::OfflineWritable => println!(
                        "writable offline Space mounted at {path}; remote not checked by this mount; fsync is local only; supported local edits/namespace operations are queued; {sync}"
                    ),
                }
            }
            A::RetainedPins(page) => print_page(page, |entry| {
                print_json(&serde_json::json!({
                    "space":entry.space,"root":entry.root,"status":"retained; possibly stale"
                }))
            })?,
            A::RetainedFiles(page) => print_page(page, |entry| {
                print_json(&serde_json::json!({
                    "path":entry.path,"selector":entry.selector,"version":entry.version,"status":"retained; possibly stale; not yet verified for export"
                }))
            })?,
            A::RetainedStaged(page) => print_page(page, |entry| print_json(&entry))?,
            A::PinCopies(page) => print_page(page, |entry| print_json(&entry))?,
            A::PinCopyEntries(page) => print_page(page, |entry| {
                if entry.kind == "directory" {
                    print_json(
                        &serde_json::json!({"kind":entry.kind,"path":entry.path,"id":entry.id,"status":entry.status}),
                    )
                } else {
                    print_json(
                        &serde_json::json!({"kind":entry.kind,"path":entry.path,"size":entry.size,"version":entry.version,"selector":entry.selector}),
                    )
                }
            })?,
            A::LabUploadOutcome(outcome) => print_json(&outcome)?,
        },
    }
    Ok(())
}

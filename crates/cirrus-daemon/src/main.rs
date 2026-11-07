use std::env;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use cirrus_daemon::Daemon;
use cirrus_discovery::Discovery;
use cirrus_runtime::RuntimeDir;
use rustix::{fs::Mode, process};

fn runtime() -> io::Result<RuntimeDir> {
    let path = env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "XDG_RUNTIME_DIR is not set; a private user runtime directory is required",
        )
    })?;
    RuntimeDir::open(Path::new(&path))
}

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let arg = args.next();
    if arg
        .as_deref()
        .is_some_and(|value| value == "--release-storage-reservation")
    {
        let values: Vec<_> = args.collect();
        if values.len() != 2
            || !matches!(values[0].to_str(), Some("state" | "cache" | "namespace"))
            || values[1].to_str().is_none_or(|token| {
                token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            eprintln!(
                "--release-storage-reservation requires state|cache|namespace TOKEN from --storage-status"
            );
            return ExitCode::from(2);
        }
        return match runtime().and_then(|directory| {
            Daemon::new().release_storage_reservation(
                &directory,
                values[0].to_string_lossy().into_owned(),
                values[1].to_string_lossy().into_owned(),
            )
        }) {
            Ok(()) => {
                println!("{{}}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("storage reservation: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if arg.as_deref().is_some_and(|value| {
        matches!(
            value.to_str(),
            Some("--storage-limits" | "--set-storage-limits" | "--disable-storage-limits")
        )
    }) {
        let command = arg
            .as_deref()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let values = match args
            .map(|value| value.into_string())
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(values) => values,
            Err(_) => {
                eprintln!("storage limits require decimal byte arguments");
                return ExitCode::from(2);
            }
        };
        let setting = if command == "--set-storage-limits" {
            if values.len() != 2
                || values.iter().any(|value| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
                })
            {
                eprintln!("--set-storage-limits requires BUDGET_BYTES RESERVE_BYTES");
                return ExitCode::from(2);
            }
            match (values[0].parse::<u64>(), values[1].parse::<u64>()) {
                (Ok(budget_bytes), Ok(free_space_reserve_bytes)) if budget_bytes > 0 => {
                    Some(cirrus_daemon::StorageLimits {
                        budget_bytes,
                        free_space_reserve_bytes,
                    })
                }
                _ => {
                    eprintln!("invalid storage limit bytes (budget must be positive)");
                    return ExitCode::from(2);
                }
            }
        } else {
            if !values.is_empty() {
                eprintln!("{command} takes no arguments");
                return ExitCode::from(2);
            }
            None
        };
        let result = runtime().and_then(|directory| {
            let daemon = Daemon::new();
            let view = if command == "--storage-limits" {
                daemon.storage_limits(&directory)?
            } else {
                daemon.configure_storage_limits(&directory, setting)?
            };
            println!(
                "{}",
                serde_json::to_string(&view).map_err(io::Error::other)?
            );
            Ok(())
        });
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("storage limits: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if arg
        .as_deref()
        .is_some_and(|value| value == "--cache-status" || value == "--storage-status")
    {
        let storage = arg
            .as_deref()
            .is_some_and(|value| value == "--storage-status");
        if args.next().is_some() {
            eprintln!(
                "{} takes no arguments",
                if storage {
                    "--storage-status"
                } else {
                    "--cache-status"
                }
            );
            return ExitCode::from(2);
        }
        let result = runtime().and_then(|directory| {
            let status = if storage {
                serde_json::to_string(&Daemon::new().storage_status(&directory)?)
            } else {
                serde_json::to_string(&Daemon::new().clean_cache_status(&directory)?)
            }
            .map_err(io::Error::other)?;
            println!("{status}");
            Ok(())
        });
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{}: {error}", if storage { "storage" } else { "cache" });
                ExitCode::FAILURE
            }
        };
    }
    if arg.as_deref().is_some_and(|v| {
        v == "--pin-copies"
            || v == "--pin-copy-entries"
            || v == "--export-pin-copy"
            || v == "--remove-pin-copy"
            || v == "--retained-pins"
            || v == "--retained-files"
            || v == "--export-retained"
            || v == "--retained-staged"
            || v == "--export-staged"
    }) {
        let command = arg.as_deref().unwrap_or_default();
        let values = match args.map(|s| s.into_string()).collect::<Result<Vec<_>, _>>() {
            Ok(values) => values,
            Err(_) => {
                eprintln!("recovery arguments must be UTF-8");
                return ExitCode::from(2);
            }
        };
        let path = |value: &str| -> Vec<String> {
            let value = value.strip_prefix('/').unwrap_or(value);
            if value.is_empty() {
                Vec::new()
            } else {
                value.split('/').map(str::to_owned).collect()
            }
        };
        let directory = match runtime() {
            Ok(value) => value,
            Err(error) => {
                eprintln!("runtime: {error}");
                return ExitCode::FAILURE;
            }
        };
        let daemon = Daemon::new();
        let offset =
            |value: Option<&String>| -> Option<u32> { value.map_or(Some(0), |s| s.parse().ok()) };
        let result = if command == "--pin-copies" && (1..=2).contains(&values.len()) {
            offset(values.get(1))
                .ok_or_else(|| io::Error::other("invalid offset"))
                .and_then(|offset| daemon.pin_copies(&directory, &values[0], offset))
                .map(|rows| {
                    for (_, value) in rows {
                        println!("{}", value)
                    }
                })
        } else if command == "--pin-copy-entries" && (3..=4).contains(&values.len()) {
            values[2]
                .parse::<i64>()
                .map_err(io::Error::other)
                .and_then(|id| {
                    offset(values.get(3))
                        .ok_or_else(|| io::Error::other("invalid offset"))
                        .and_then(|offset| {
                            daemon.pin_copy_entries(&directory, &values[0], &values[1], id, offset)
                        })
                })
                .map(|rows| {
                    for (_, value) in rows {
                        println!("{}", value)
                    }
                })
        } else if command == "--export-pin-copy" && values.len() == 6 {
            values[2]
                .parse::<i64>()
                .map_err(io::Error::other)
                .and_then(|id| {
                    daemon.export_pin_copy(
                        &directory,
                        &values[0],
                        &values[1],
                        (id, path(&values[3])),
                        &values[4],
                        &values[5],
                    )
                })
                .map(|()| println!("exported immutable retained pin copy; remote not checked"))
        } else if command == "--remove-pin-copy" && values.len() == 3 {
            values[2].parse::<i64>().map_err(io::Error::other).and_then(|id|daemon.remove_pin_copy(&directory,&values[0],&values[1],id)).map(|()|println!("removed only the named retained pin copy; active pins and dirty roots unchanged"))
        } else if command == "--retained-staged" && (1..=2).contains(&values.len()) {
            if let Some(offset) = offset(values.get(1)) {
                daemon
                    .retained_staged(&directory, &values[0], offset)
                    .and_then(|rows| {
                        if !rows.is_empty() {
                            eprintln!("next offset: {}", offset.saturating_add(rows.len() as u32));
                        }
                        for row in rows {
                            println!("{}", serde_json::to_string(&row).map_err(io::Error::other)?);
                        }
                        Ok(())
                    })
            } else {
                Err(io::Error::other("invalid offset"))
            }
        } else if command == "--export-staged" && values.len() == 4 {
            if let Ok(id) = values[1].parse::<i64>() {
                daemon
                    .export_staged(&directory, &values[0], id, &values[2], &values[3])
                    .map(|()| {
                        println!("exported retained staged copy; remote outcome not asserted")
                    })
            } else {
                Err(io::Error::other("invalid journal ID"))
            }
        } else if command == "--retained-pins" && (1..=2).contains(&values.len()) {
            if let Some(offset) = offset(values.get(1)) {
                daemon.retained_pins(&directory, &values[0], offset).map(|rows| {
                    if !rows.is_empty() { eprintln!("next offset: {}", offset.saturating_add(rows.len() as u32)); }
                    for (space, root) in rows { println!("{}", serde_json::json!({"space": space, "root": serde_json::from_str::<serde_json::Value>(&root).unwrap_or(serde_json::Value::String(root)), "status": "retained; possibly stale"})); }
                })
            } else {
                Err(io::Error::other("invalid offset"))
            }
        } else if command == "--retained-files" && (3..=4).contains(&values.len()) {
            if let Some(offset) = offset(values.get(3)) {
                daemon.retained_files(&directory, &values[0], &values[1], path(&values[2]), offset).and_then(|rows| {
                    if !rows.is_empty() { eprintln!("next offset: {}", offset.saturating_add(rows.len() as u32)); }
                    for (path, value) in rows {
                        let (selector, version) = value.split_once('\n').ok_or_else(|| io::Error::other("invalid retained version response"))?;
                        println!("{}", serde_json::json!({"path": serde_json::from_str::<serde_json::Value>(&path).unwrap_or(serde_json::Value::String(path)), "selector": selector, "version": serde_json::from_str::<serde_json::Value>(version).unwrap_or(serde_json::Value::String(version.to_owned())), "status": "retained; possibly stale; not yet verified for export"}));
                    }
                    Ok(())
                })
            } else {
                Err(io::Error::other("invalid offset"))
            }
        } else if command == "--export-retained" && values.len() == 6 {
            daemon
                .export_retained(
                    &directory,
                    &values[0],
                    &values[1],
                    (path(&values[2]), path(&values[3])),
                    &values[4],
                    &values[5],
                )
                .map(|()| println!("exported retained version; it may be stale"))
        } else {
            Err(io::Error::other(
                "usage: --pin-copies URL [OFFSET] | --pin-copy-entries URL SPACE COPY_ID [OFFSET] | --export-pin-copy URL SPACE COPY_ID FILE SELECTOR ABSOLUTE_DESTINATION | --remove-pin-copy URL SPACE COPY_ID | --retained-staged URL [OFFSET] | --export-staged URL JOURNAL_ID SELECTOR ABSOLUTE_DESTINATION | --retained-pins URL [OFFSET] | --retained-files URL SPACE PIN_ROOT [OFFSET] | --export-retained URL SPACE PIN_ROOT FILE SELECTOR ABSOLUTE_DESTINATION",
            ))
        };
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("recovery: {error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(feature = "fault-injection")]
    if arg
        .as_deref()
        .is_some_and(|arg| arg == "--lab-capabilities")
        && args.next().is_none()
    {
        println!("cirrus-drive disposable account and mount lab v1");
        return ExitCode::SUCCESS;
    }
    if arg.as_deref().is_some_and(|arg| {
        arg == "--mount"
            || arg == "--mount-offline-space"
            || arg == "--mount-offline-writable-space"
            || arg == "--mount-space"
            || arg == "--unmount"
            || arg == "--unmount-space"
            || arg == "--mount-status"
            || arg == "--mounts"
            || arg == "--recover-mount"
    }) {
        let result = (|| -> io::Result<()> {
            let directory = runtime()?;
            let daemon = Daemon::new();
            if arg.as_deref().is_some_and(|arg| arg == "--mounts") {
                if args.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected arguments",
                    ));
                }
                for mount in daemon.mounts(&directory)? {
                    println!(
                        "{}",
                        serde_json::to_string(&mount).map_err(io::Error::other)?
                    );
                }
            } else if arg.as_deref().is_some_and(|arg| arg == "--unmount-space") {
                let instance = args.next().and_then(|s| s.into_string().ok());
                let space = args.next().and_then(|s| s.into_string().ok());
                let (Some(instance), Some(space)) = (instance, space) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--unmount-space requires HTTPS_URL SPACE_ID",
                    ));
                };
                if args.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected arguments",
                    ));
                }
                daemon.unmount_space(&directory, &instance, &space)?;
                println!("Space unmounted");
            } else if arg.as_deref().is_some_and(|arg| {
                arg == "--mount-offline-space" || arg == "--mount-offline-writable-space"
            }) {
                let instance = args.next().and_then(|s| s.into_string().ok());
                let space = args.next().and_then(|s| s.into_string().ok());
                let path = args.next().and_then(|s| s.into_string().ok());
                let (Some(instance), Some(space), Some(path)) = (instance, space, path) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--mount-offline-space requires HTTPS_URL SPACE_ID MOUNTPOINT",
                    ));
                };
                if args.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected arguments",
                    ));
                }
                if arg
                    .as_deref()
                    .is_some_and(|arg| arg == "--mount-offline-writable-space")
                {
                    let path = daemon
                        .mount_writable_offline_space(&directory, &instance, &space, &path)?;
                    println!(
                        "writable offline Space mounted at {path}; remote not checked by this mount; fsync is local only; supported local edits/namespace operations are queued; automatic sync uses authenticated original identity when enabled"
                    );
                } else {
                    let path = daemon.mount_offline_space(&directory, &instance, &space, &path)?;
                    println!(
                        "read-only offline Space mounted at {path}; retained local identity and metadata; remote not checked; content availability not asserted; writes unavailable"
                    );
                }
            } else if arg.as_deref().is_some_and(|arg| arg == "--mount-space") {
                let instance = args.next().and_then(|s| s.into_string().ok());
                let space = args.next().and_then(|s| s.into_string().ok());
                let path = args
                    .next()
                    .map(|s| {
                        s.into_string().map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "mount directory must be UTF-8",
                            )
                        })
                    })
                    .transpose()?;
                let (Some(instance), Some(space)) = (instance, space) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--mount-space requires HTTPS_URL SPACE_ID [MOUNTPOINT]",
                    ));
                };
                if args.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected arguments",
                    ));
                }
                let path = daemon.mount_space(&directory, &instance, &space, path.as_deref())?;
                println!(
                    "Space mounted at {path} experimentally; changes are local until explicit sync"
                );
            } else if arg.as_deref().is_some_and(|arg| arg == "--mount") {
                let instance = args
                    .next()
                    .and_then(|s| s.into_string().ok())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "--mount requires an HTTPS_URL")
                    })?;
                let path = args
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--mount requires an explicit MOUNTPOINT",
                        )
                    })?
                    .into_string()
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "mount directory must be UTF-8")
                    })?;
                if args.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected arguments",
                    ));
                }
                daemon.mount(&directory, &instance, &path)?;
                println!(
                    "Space mounted at {path} experimentally; changes are local until explicit sync; rename and open-handle restrictions apply"
                );
            } else if arg.as_deref().is_some_and(|arg| arg == "--recover-mount") {
                let path = args
                    .next()
                    .and_then(|s| s.into_string().ok())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--recover-mount requires a UTF-8 MOUNTPOINT",
                        )
                    })?;
                if args.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected arguments",
                    ));
                }
                daemon.recover_mount(&directory, &path)?;
                println!("recorded stale mount recovered");
            } else {
                if args.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected arguments",
                    ));
                }
                if arg.as_deref().is_some_and(|arg| arg == "--unmount") {
                    daemon.unmount(&directory)?;
                    println!("Space unmounted");
                } else {
                    match daemon.mount_status(&directory)? {
                        Some(path) => println!(
                            "mounted: {path}; experimental staged changes, explicit sync; rename and open-handle restrictions apply"
                        ),
                        None => println!("not mounted"),
                    }
                }
            }
            Ok(())
        })();
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("mount: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if arg.as_deref().is_some_and(|arg| {
        arg == "--pin-space"
            || arg == "--ls-offline-space"
            || arg == "--unpin-space"
            || arg == "--pins-space"
            || arg == "--evict-space"
            || arg == "--stage-file-space"
    }) {
        let result = (|| -> io::Result<()> {
            let values = args
                .map(|s| {
                    s.into_string().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "arguments must be UTF-8")
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            let command = arg.as_deref().unwrap_or_default();
            let expected = if command == "--pins-space" {
                2
            } else if command == "--stage-file-space" {
                4
            } else {
                3
            };
            if values.len() != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected HTTPS_URL SPACE_ID [SPACE_PATH [LOCAL_FILE]]",
                ));
            }
            let directory = runtime()?;
            let daemon = Daemon::new();
            let path = || {
                let value = values[2].strip_prefix('/').unwrap_or(&values[2]);
                if value.is_empty() {
                    Vec::new()
                } else {
                    value.split('/').map(str::to_owned).collect()
                }
            };
            if command == "--ls-offline-space" {
                let entries =
                    daemon.offline_directory(&directory, &values[0], &values[1], path())?;
                eprintln!(
                    "local saved metadata and pending entries; remote not checked; content availability not asserted"
                );
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
            } else if command == "--pins-space" {
                for (path, status) in daemon.pins_space(&directory, &values[0], &values[1])? {
                    println!("{status}\t{path}");
                }
            } else if command == "--pin-space" {
                daemon.pin_space(&directory, &values[0], &values[1], path())?;
                println!("available offline");
            } else if command == "--unpin-space" {
                daemon.unpin_space(&directory, &values[0], &values[1], path())?;
                println!("pin removed");
            } else if command == "--evict-space" {
                daemon.evict_space(&directory, &values[0], &values[1], path())?;
                println!("clean cached ranges evicted");
            } else {
                daemon.stage_file_space(&directory, &values[0], &values[1], path(), &values[3])?;
                println!("saved locally; upload pending");
            }
            Ok(())
        })();
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("account: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if arg.as_deref().is_some_and(|arg| {
        arg == "--connect"
            || arg == "--spaces"
            || arg == "--select-space"
            || arg == "--ls"
            || arg == "--pin"
            || arg == "--unpin"
            || arg == "--pins"
            || arg == "--stage-file"
            || arg == "--journal"
            || arg == "--journal-space"
            || arg == "--sync"
            || arg == "--sync-space"
            || arg == "--write-turn"
            || arg == "--sync-status"
            || arg == "--acknowledge"
    }) {
        let Some(instance) = args.next() else {
            eprintln!("account operation requires an HTTPS instance URL");
            return ExitCode::from(2);
        };
        let Some(instance) = instance.to_str() else {
            eprintln!("instance URL must be UTF-8");
            return ExitCode::from(2);
        };
        let command = arg.as_deref();
        let mut ca = None;
        let mut selected = None;
        let mut directory_path = None;
        let mut staging_source = None;
        let mut acknowledge = None;
        let mut journal_before = None;
        let mut journal_space = None;
        let mut sync_space = None;
        if command.is_some_and(|v| v == "--connect") {
            if let Some(option) = args.next() {
                if option != "--ca-cert" {
                    eprintln!("unknown account option; use --help");
                    return ExitCode::from(2);
                }
                let Some(path) = args.next() else {
                    eprintln!("--ca-cert requires a PEM file");
                    return ExitCode::from(2);
                };
                let mut bytes = Vec::new();
                if std::fs::File::open(path)
                    .and_then(|file| file.take(65_537).read_to_end(&mut bytes))
                    .is_err()
                {
                    eprintln!("cannot read CA certificate");
                    return ExitCode::FAILURE;
                }
                if bytes.len() > 65_536 {
                    eprintln!("CA certificate is too large");
                    return ExitCode::FAILURE;
                }
                ca = match String::from_utf8(bytes) {
                    Ok(pem) => Some(pem),
                    Err(_) => {
                        eprintln!("CA certificate must be PEM text");
                        return ExitCode::FAILURE;
                    }
                };
            }
        } else if command.is_some_and(|v| v == "--select-space") {
            let Some(id) = args.next() else {
                eprintln!("--select-space requires a Space ID");
                return ExitCode::from(2);
            };
            let Some(id) = id.to_str() else {
                eprintln!("Space ID must be UTF-8");
                return ExitCode::from(2);
            };
            selected = Some(id.to_owned());
        } else if command
            .is_some_and(|v| v == "--sync-space" || v == "--write-turn" || v == "--sync-status")
        {
            let Some(space) = args.next().and_then(|value| value.into_string().ok()) else {
                eprintln!("sync command requires a Space ID");
                return ExitCode::from(2);
            };
            sync_space = Some(space);
        } else if command.is_some_and(|v| v == "--acknowledge") {
            let Some(staged) = args.next().and_then(|value| value.into_string().ok()) else {
                eprintln!("--acknowledge requires the file name or operation token from --journal");
                return ExitCode::from(2);
            };
            acknowledge = Some(staged);
        } else if command.is_some_and(|v| v == "--journal" || v == "--journal-space") {
            if command.is_some_and(|v| v == "--journal-space") {
                let Some(space) = args.next().and_then(|value| value.into_string().ok()) else {
                    eprintln!("--journal-space requires a Space ID");
                    return ExitCode::from(2);
                };
                journal_space = Some(space);
            }
            if let Some(value) = args.next() {
                journal_before = value
                    .to_str()
                    .and_then(|value| value.parse::<i64>().ok())
                    .filter(|id| *id != 0);
                if journal_before.is_none() {
                    eprintln!("journal cursor must be a nonzero integer ID");
                    return ExitCode::from(2);
                }
            }
        } else if command
            .is_some_and(|v| v == "--ls" || v == "--pin" || v == "--unpin" || v == "--stage-file")
        {
            let path =
                if command.is_some_and(|v| v == "--pin" || v == "--unpin" || v == "--stage-file") {
                    let Some(path) = args.next() else {
                        eprintln!("pin operation requires a Space path");
                        return ExitCode::from(2);
                    };
                    path
                } else {
                    args.next().unwrap_or_default()
                };
            let Some(path) = path.to_str() else {
                eprintln!("Space path must be UTF-8");
                return ExitCode::from(2);
            };
            let path = path.strip_prefix('/').unwrap_or(path);
            directory_path = Some(if path.is_empty() {
                Vec::new()
            } else {
                path.split('/').map(str::to_owned).collect()
            });
            if command.is_some_and(|v| v == "--stage-file") {
                let Some(source) = args.next().and_then(|value| value.into_string().ok()) else {
                    eprintln!("--stage-file requires a UTF-8 local source path");
                    return ExitCode::from(2);
                };
                staging_source = Some(source);
            }
        }
        if args.next().is_some() {
            eprintln!("unexpected arguments; use --help");
            return ExitCode::from(2);
        }
        let directory = match runtime() {
            Ok(directory) => directory,
            Err(error) => {
                eprintln!("runtime: {error}");
                return ExitCode::FAILURE;
            }
        };
        let daemon = Daemon::new();
        let result = if command.is_some_and(|v| v == "--connect") {
            daemon
                .connect(&directory, instance, ca)
                .map(|()| println!("account connected"))
        } else if let Some(id) = selected {
            daemon
                .select_space(&directory, instance, &id)
                .map(|()| println!("Space selected"))
        } else if let Some(staged) = acknowledge {
            daemon.acknowledge(&directory, instance, &staged).map(|()| {
                println!(
                    "acknowledged locally; remote outcome not asserted; any staged copies retained"
                )
            })
        } else if let Some(source) = staging_source {
            daemon
                .stage_file(
                    &directory,
                    instance,
                    directory_path.unwrap_or_default(),
                    &source,
                )
                .map(|()| println!("saved locally; upload pending"))
        } else if command.is_some_and(|v| v == "--journal" || v == "--journal-space") {
            daemon.journal(&directory, instance, journal_space.as_deref(), journal_before).map(|page| {
                let scope = journal_space.as_deref().map_or_else(
                    || "account".to_owned(),
                    |space| format!("Space {space}"),
                );
                eprintln!(
                    "{scope} journal: {} pending, {} conflict, {} uncertain or in progress, {} historically synced, {} resolved",
                    page.summary.pending,
                    page.summary.conflict,
                    page.summary.uncertain_or_in_progress,
                    page.summary.synced,
                    page.summary.resolved
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
            })
        } else if command.is_some_and(|v| v == "--sync-status") {
            daemon
                .sync_status(
                    &directory,
                    instance,
                    sync_space.as_deref().expect("status has a Space ID"),
                )
                .and_then(|status| serde_json::to_string(&status).map_err(std::io::Error::other))
                .map(|status| println!("{status}"))
        } else if command.is_some_and(|v| v == "--write-turn") {
            daemon
                .write_turn(
                    &directory,
                    instance,
                    sync_space.as_deref().expect("write turn has a Space ID"),
                )
                .map(|outcome| println!("{outcome:?}"))
        } else if command.is_some_and(|v| v == "--sync" || v == "--sync-space") {
            eprintln!(
                "warning: server races can overwrite or delete remote changes despite ETag checks; staged copies are retained"
            );
            if let Some(space) = sync_space.as_deref() {
                daemon.sync_space(&directory, instance, space)
            } else {
                daemon.sync_pending(&directory, instance)
            }
            .map(|()| println!("no pending operations in requested scope; inspect the journal for retained copies and acknowledged outcomes"))
        } else if command.is_some_and(|v| v == "--pin") {
            daemon
                .pin(&directory, instance, directory_path.unwrap_or_default())
                .map(|()| println!("available offline"))
        } else if command.is_some_and(|v| v == "--unpin") {
            daemon
                .unpin(&directory, instance, directory_path.unwrap_or_default())
                .map(|()| println!("pin removed"))
        } else if command.is_some_and(|v| v == "--pins") {
            daemon.pins(&directory, instance).map(|pins| {
                for (path, status) in pins {
                    println!("{status}\t{path}");
                }
            })
        } else if let Some(path) = directory_path {
            daemon.directory(&directory, instance, path).map(|entries| {
                for entry in entries {
                    if entry.directory {
                        println!("dir\t-\t{}", entry.name);
                    } else {
                        let size = entry
                            .size
                            .map_or_else(|| "?".to_owned(), |size| size.to_string());
                        println!("file\t{}\t{}", size, entry.name);
                    }
                }
            })
        } else {
            daemon.spaces(&directory, instance).map(|spaces| {
                for (id, name) in spaces {
                    println!("{id}\t{name}");
                }
            })
        };
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("account: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if arg.as_deref().is_some_and(|arg| arg == "--discover") {
        let Some(instance) = args.next() else {
            eprintln!("--discover requires an HTTPS instance URL");
            return ExitCode::from(2);
        };
        let Some(instance) = instance.to_str() else {
            eprintln!("instance URL must be UTF-8");
            return ExitCode::from(2);
        };
        let ca = match args.next() {
            None => None,
            Some(option) if option == "--ca-cert" => match args.next() {
                Some(path) => Some(path),
                None => {
                    eprintln!("--ca-cert requires a PEM file");
                    return ExitCode::from(2);
                }
            },
            Some(_) => {
                eprintln!("unknown discovery option; use --help");
                return ExitCode::from(2);
            }
        };
        if args.next().is_some() {
            eprintln!("unexpected arguments; use --help");
            return ExitCode::from(2);
        }
        let client = match ca {
            None => Discovery::new(),
            Some(path) => {
                let mut pem = Vec::new();
                let result = std::fs::File::open(path)
                    .and_then(|file| file.take(65_537).read_to_end(&mut pem));
                if result.is_err() {
                    eprintln!("cannot read CA certificate");
                    return ExitCode::FAILURE;
                }
                Discovery::with_additional_ca(&pem)
            }
        };
        return match client.and_then(|client| client.discover(instance)) {
            Ok(config) => {
                println!(
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
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("discovery: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if args.next().is_some() {
        eprintln!("unexpected arguments; use --help");
        return ExitCode::from(2);
    }

    match arg.as_deref() {
        Some(arg) if arg == "--help" => {
            println!(
                "Usage: cirrus-daemon [--help | --version | --scaffold-status | --check-runtime | --status | --stop]\n       cirrus-daemon --discover HTTPS_URL [--ca-cert PEM_FILE]\n       cirrus-daemon --connect HTTPS_URL [--ca-cert PEM_FILE]\n       cirrus-daemon --spaces HTTPS_URL\n       cirrus-daemon --select-space HTTPS_URL SPACE_ID\n       cirrus-daemon --ls HTTPS_URL [SPACE_PATH]\n       cirrus-daemon --pin HTTPS_URL SPACE_PATH | --unpin HTTPS_URL SPACE_PATH | --pins HTTPS_URL\n       cirrus-daemon --retained-staged HTTPS_URL [OFFSET] | --export-staged HTTPS_URL JOURNAL_ID SELECTOR ABSOLUTE_DESTINATION\n       cirrus-daemon --retained-pins HTTPS_URL [OFFSET] | --retained-files HTTPS_URL SPACE_ID PIN_ROOT [OFFSET]\n       cirrus-daemon --export-retained HTTPS_URL SPACE_ID PIN_ROOT FILE_PATH SELECTOR ABSOLUTE_DESTINATION\n       cirrus-daemon --stage-file HTTPS_URL SPACE_PATH LOCAL_FILE | --journal HTTPS_URL | --sync HTTPS_URL\n       cirrus-daemon --acknowledge HTTPS_URL JOURNAL_TOKEN\n       cirrus-daemon --mount HTTPS_URL MOUNTPOINT\n       cirrus-daemon --mount-space HTTPS_URL SPACE_ID MOUNTPOINT\n       cirrus-daemon --recover-mount MOUNTPOINT | --unmount | --mount-status\n\nWithout an option, run the foreground local service."
            );
            println!(
                "       cirrus-daemon --journal HTTPS_URL [BEFORE_ID]  (newest first; cursor for older entries)"
            );
            println!("       cirrus-daemon --journal-space HTTPS_URL SPACE_ID [BEFORE_ID]");
            println!(
                "       cirrus-daemon --pin-copies HTTPS_URL [OFFSET] | --pin-copy-entries HTTPS_URL SPACE_ID COPY_ID [OFFSET]\n       cirrus-daemon --export-pin-copy HTTPS_URL SPACE_ID COPY_ID FILE_PATH SELECTOR ABSOLUTE_DESTINATION\n       cirrus-daemon --remove-pin-copy HTTPS_URL SPACE_ID COPY_ID  (only the named immutable retained copy)"
            );
            println!("       cirrus-daemon --sync-space HTTPS_URL SPACE_ID");
            println!("       cirrus-daemon --write-turn HTTPS_URL SPACE_ID");
            println!("       cirrus-daemon --sync-status HTTPS_URL SPACE_ID");
            println!("       cirrus-daemon --no-auto-sync  (diagnostics; explicit sync only)");
            println!("       cirrus-daemon --mounts | --unmount-space HTTPS_URL SPACE_ID");
            println!(
                "       cirrus-daemon --pin-space HTTPS_URL SPACE_ID SPACE_PATH | --unpin-space HTTPS_URL SPACE_ID SPACE_PATH | --pins-space HTTPS_URL SPACE_ID\n       cirrus-daemon --ls-offline-space HTTPS_URL SPACE_ID SPACE_PATH"
            );
            println!(
                "       cirrus-daemon --stage-file-space HTTPS_URL SPACE_ID SPACE_PATH LOCAL_FILE"
            );
            println!("       cirrus-daemon --evict-space HTTPS_URL SPACE_ID SPACE_PATH");
            println!("       cirrus-daemon --cache-status");
            println!("       cirrus-daemon --storage-status");
            println!(
                "       cirrus-daemon --storage-limits | --set-storage-limits BUDGET_BYTES RESERVE_BYTES | --disable-storage-limits"
            );
            println!(
                "       cirrus-daemon --release-storage-reservation state|cache|namespace TOKEN"
            );
            println!("       --mount-space accepts an omitted MOUNTPOINT to create ~/SPACE_NAME.");
            println!(
                "       cirrus-daemon --mount-offline-space HTTPS_URL SPACE_ID MOUNTPOINT\n       Read-only retained data, no credentials/network; requires service --no-auto-sync; remote not checked."
            );
            println!(
                "       cirrus-daemon --mount-offline-writable-space HTTPS_URL SPACE_ID MOUNTPOINT\n       Explicit retained-principal local edits/namespace operations; works with automatic sync; fsync local only, remote not checked by the mount."
            );
            ExitCode::SUCCESS
        }
        Some(arg) if arg == "--version" => {
            println!("cirrus-daemon {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(arg) if arg == "--scaffold-status" => {
            println!("{}", Daemon::new().scaffold_status());
            ExitCode::SUCCESS
        }
        Some(arg) if arg == "--check-runtime" => match runtime() {
            Ok(_directory) => {
                println!(
                    "runtime directory passed the current owner, mode and path checks; no service was started"
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("XDG_RUNTIME_DIR: {error}");
                ExitCode::FAILURE
            }
        },
        Some(arg) if arg == "--status" || arg == "--stop" => {
            let result = runtime().and_then(|directory| {
                if arg == "--status" {
                    Daemon::new()
                        .status(&directory)
                        .map(|status| println!("{status}"))
                } else {
                    Daemon::new()
                        .stop(&directory)
                        .map(|()| println!("daemon stopping"))
                }
            });
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("local daemon: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(arg) if arg == "--no-auto-sync" => {
            match runtime().and_then(|directory| {
                process::umask(Mode::from_raw_mode(0o077));
                Daemon::new().run_without_automatic_sync(&directory)
            }) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(_) => {
            eprintln!("unknown option; use --help");
            ExitCode::from(2)
        }
        None => match runtime().and_then(|directory| {
            // The CLI is single-threaded here; do not expose a process-wide umask change in the library.
            process::umask(Mode::from_raw_mode(0o077));
            Daemon::new().run(&directory)
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
    }
}

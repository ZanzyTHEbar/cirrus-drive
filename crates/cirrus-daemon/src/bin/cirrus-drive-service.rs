use std::env;
use std::io;
use std::path::Path;
use std::process::ExitCode;

use cirrus_daemon::Daemon;
use cirrus_runtime::RuntimeDir;
use rustix::{fs::Mode, process};

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if let [flag, root, role, bootstrap, rest @ ..] = args.as_slice()
        && flag == "--launch-client"
        && let Some(role @ ("cli" | "ui")) = role.to_str()
    {
        return report(Daemon::launch_client(
            Path::new(root),
            role,
            Path::new(bootstrap),
            rest,
        ));
    }
    if let [flag, confirmed] = args.as_slice()
        && flag == "--prepare-state"
        && confirmed == "--legacy-writers-stopped"
    {
        process::umask(Mode::from_raw_mode(0o077));
        return report(
            runtime_dir()
                .and_then(|runtime| Daemon::prepare_state_after_stopping_writers(&runtime)),
        );
    }
    let (manual, release_root) = match args.as_slice() {
        [] => (false, None),
        [flag] if flag == "--no-auto-sync" => (true, None),
        [flag, root] if flag == "--release-root" => (false, Some(Path::new(root))),
        [flag, root, manual] if flag == "--release-root" && manual == "--no-auto-sync" => {
            (true, Some(Path::new(root)))
        }
        [flag] if flag == "--help" => {
            println!("Usage: cirrus-drive-service [--release-root DIRECTORY] [--no-auto-sync]");
            println!("       cirrus-drive-service --prepare-state --legacy-writers-stopped");
            println!("Stop all Cirrus writers and unmount before preparing State.");
            return ExitCode::SUCCESS;
        }
        [flag] if flag == "--version" => {
            println!("cirrus-drive-service {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        #[cfg(feature = "fault-injection")]
        [flag] if flag == "--lab-capabilities" => {
            println!("cirrus-drive disposable account and mount lab v1");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("unknown service option; use --help");
            return ExitCode::from(2);
        }
    };
    // This entrypoint is still single-threaded; the setting is process-wide.
    process::umask(Mode::from_raw_mode(0o077));
    let result = runtime_dir().and_then(|runtime| {
        if let Some(root) = release_root {
            Daemon::new().run_managed(&runtime, root, !manual)
        } else if manual {
            Daemon::new().run_without_automatic_sync(&runtime)
        } else {
            Daemon::new().run(&runtime)
        }
    });
    report(result)
}

fn runtime_dir() -> io::Result<RuntimeDir> {
    env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "XDG_RUNTIME_DIR is not set; a private user runtime directory is required",
            )
        })
        .and_then(|path| RuntimeDir::open(path.as_ref()))
}

fn report(result: io::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

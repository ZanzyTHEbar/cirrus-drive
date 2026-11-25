use std::env;
use std::io;
use std::process::ExitCode;

use cirrus_daemon::Daemon;
use cirrus_runtime::RuntimeDir;
use rustix::{fs::Mode, process};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let argument = args.next();
    let manual = match (
        argument.as_deref().and_then(|value| value.to_str()),
        args.next(),
    ) {
        (None, None) if argument.is_none() => false,
        (Some("--no-auto-sync"), None) => true,
        (Some("--help"), None) => {
            println!("Usage: cirrus-drive-service [--no-auto-sync | --help | --version]");
            return ExitCode::SUCCESS;
        }
        (Some("--version"), None) => {
            println!("cirrus-drive-service {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        #[cfg(feature = "fault-injection")]
        (Some("--lab-capabilities"), None) => {
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
    let result = env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "XDG_RUNTIME_DIR is not set; a private user runtime directory is required",
            )
        })
        .and_then(|path| RuntimeDir::open(path.as_ref()))
        .and_then(|runtime| {
            if manual {
                Daemon::new().run_without_automatic_sync(&runtime)
            } else {
                Daemon::new().run(&runtime)
            }
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

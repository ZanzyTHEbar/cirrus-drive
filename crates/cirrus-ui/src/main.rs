use std::env;
use std::process::ExitCode;

use cirrus_ui::Ui;

// A stale Vulkan loader override can prevent Rune from creating any surface.
// Only discard a list when every entry is an absolute path known not to exist;
// leave usable, relative, empty, or inaccessible settings to the Vulkan loader.
#[cfg(target_os = "linux")]
fn retry_without_missing_vulkan_overrides() -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let missing: Vec<_> = ["VK_DRIVER_FILES", "VK_ICD_FILENAMES", "VK_ADD_DRIVER_FILES"]
        .into_iter()
        .filter(|name| {
            let Some(value) = env::var_os(name) else {
                return false;
            };
            let paths: Vec<_> = env::split_paths(&value).collect();
            !paths.is_empty()
                && paths.iter().all(|path| {
                    path.is_absolute()
                        && matches!(path.metadata(), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
                })
        })
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut command = Command::new(env::current_exe()?);
    command.args(env::args_os().skip(1));
    for name in missing {
        command.env_remove(name);
    }
    Err(command.exec())
}

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let arg = args.next();
    match arg.as_deref() {
        Some(arg) if arg == "--help" => {
            println!(
                "Usage: cirrus-ui [--help | --version | Rune headless options]\n\nWithout an option, opens the daemon control window."
            );
            ExitCode::SUCCESS
        }
        Some(arg) if arg == "--version" => {
            println!("cirrus-ui {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            #[cfg(target_os = "linux")]
            if let Err(error) = retry_without_missing_vulkan_overrides() {
                eprintln!("cirrus-ui: could not restart with usable Vulkan settings: {error}");
                return ExitCode::FAILURE;
            }
            match Ui::new().launch() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

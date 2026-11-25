#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("link"));
        let _ = fs::remove_file(self.0.join("runtime").join("marker"));
        let _ = fs::remove_file(self.0.join("cirrus-drive.sock"));
        let _ = fs::remove_file(self.0.join("fixture.pem"));
        let _ = fs::remove_dir(self.0.join("runtime"));
        let _ = fs::remove_dir(&self.0);
    }
}

#[test]
fn distinguishes_rejection_incompatibility_and_lost_mutation_reply() {
    use std::time::Duration;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("cd-{}-{unique:x}", std::process::id()));
    fs::create_dir(&path).unwrap();
    let fixture = Fixture(path);
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = fixture.0.join("cirrus-drive.sock");
    let directory = fs::File::open(&fixture.0).unwrap();
    let bind_path = format!("/proc/self/fd/{}/cirrus-drive.sock", directory.as_raw_fd());
    let listener = UnixListener::bind(bind_path).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
    for (response, expected) in [
        (
            Some(r#"CIRRUS/3 {"error":"Space is not mounted","reply":null}"#),
            "mount: Space is not mounted",
        ),
        (
            Some("CIRRUS/2 ERROR unsupported request"),
            "incompatible daemon protocol",
        ),
        (None, "request submitted but outcome unknown"),
    ] {
        let mut child = command()
            .env("XDG_RUNTIME_DIR", &fixture.0)
            .args(["--unmount-space", "https://unused.invalid", "space"])
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // Accept only from the child against this private test socket.
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        child.try_wait().unwrap().is_none(),
                        "client exited before submission"
                    );
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("client did not connect to the private socket");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("could not accept private test connection: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut sent = String::new();
        BufReader::new(&mut stream).read_line(&mut sent).unwrap();
        assert_eq!(
            sent,
            "CIRRUS/3 {\"operation\":\"UnmountSpace\",\"instance\":\"https://unused.invalid\",\"space\":\"space\"}\n"
        );
        if let Some(response) = response {
            writeln!(stream, "{response}").unwrap();
        }
        drop(stream);
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert!(diagnostic.contains(expected), "{diagnostic}");
        assert_eq!(diagnostic.contains("outcome unknown"), response.is_none());
    }
}

#[test]
fn runtime_check_accepts_private_directory_and_rejects_symlink() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("cirrus-runtime-{}-{unique}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let fixture = Fixture(root);
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = fixture.0.join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(runtime.join("marker"), b"unchanged").unwrap();
    symlink(&runtime, fixture.0.join("link")).unwrap();

    let check = |path: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_cirrus-daemon"))
            .arg("--check-runtime")
            .env("XDG_RUNTIME_DIR", path)
            .output()
            .unwrap()
    };
    let valid = check(&runtime);
    assert!(
        valid.status.success(),
        "valid directory rejected: {valid:?}"
    );
    let link = check(&fixture.0.join("link"));
    assert!(
        !link.status.success(),
        "symlink unexpectedly accepted: {link:?}"
    );
    assert_eq!(fs::read(runtime.join("marker")).unwrap(), b"unchanged");

    // A caller-relative CA path is resolved before contacting any daemon.
    fs::write(fixture.0.join("fixture.pem"), vec![b'x'; 65_537]).unwrap();
    let ca = command()
        .current_dir(&fixture.0)
        .args([
            "--connect",
            "https://unused.invalid",
            "--ca-cert",
            "fixture.pem",
        ])
        .output()
        .unwrap();
    assert_eq!(ca.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&ca.stderr).contains("CA certificate is too large"));
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cirrus-daemon"));
    command.env_remove("XDG_RUNTIME_DIR");
    command
}

#[test]
fn arguments_are_parsed_before_runtime_or_ca_access() {
    let help = command().arg("--help").output().unwrap();
    assert!(help.status.success(), "{help:?}");
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(!help.split_whitespace().any(|arg| arg == "--mount"));
    assert!(help.split_whitespace().any(|arg| arg == "--mount-space"));
    assert!(!help.split_whitespace().any(|arg| arg == "--unmount"));
    assert!(help.split_whitespace().any(|arg| arg == "--unmount-space"));
    assert!(!help.split_whitespace().any(|arg| arg == "--ls"));
    assert!(help.split_whitespace().any(|arg| arg == "--ls-space"));
    assert!(!help.split_whitespace().any(|arg| arg == "--select-space"));

    let legacy_unmount = command().arg("--unmount").output().unwrap();
    assert_eq!(legacy_unmount.status.code(), Some(2), "{legacy_unmount:?}");
    assert!(
        String::from_utf8_lossy(&legacy_unmount.stderr).contains("unknown option; use --help"),
        "{legacy_unmount:?}"
    );

    let bad_listing = command()
        .args(["--ls-space", "https://instance.invalid"])
        .output()
        .unwrap();
    assert_eq!(bad_listing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad_listing.stderr).contains("requires a UTF-8 Space ID"));

    let missing_pin_path = command()
        .args(["--pin-space", "https://instance.invalid", "space"])
        .output()
        .unwrap();
    assert_eq!(missing_pin_path.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&missing_pin_path.stderr)
            .contains("expected HTTPS_URL SPACE_ID [SPACE_PATH [LOCAL_FILE]]")
    );

    for args in [
        &["--mount", "https://instance.invalid", "/never-mount"][..],
        &[
            "--stage-file",
            "http://instance.invalid",
            "/dir/draft",
            "/never-open",
        ][..],
        &["--pins", "https://instance.invalid"][..],
        &["--pin", "https://instance.invalid", "/dir"][..],
        &["--unpin", "https://instance.invalid", "/dir"][..],
        &["--ls", "https://instance.invalid", "/dir"][..],
        &["--select-space", "https://instance.invalid", "space"][..],
    ] {
        let legacy = command().args(args).output().unwrap();
        assert_eq!(legacy.status.code(), Some(2), "{args:?}: {legacy:?}");
        assert!(
            String::from_utf8_lossy(&legacy.stderr).contains("unexpected arguments; use --help")
        );
    }

    let bad_pins_option = command()
        .args([
            "--pins-space",
            "https://instance.invalid",
            "space",
            "--unknown",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_pins_option.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&bad_pins_option.stderr)
            .contains("expected HTTPS_URL SPACE_ID [--check-remote]")
    );

    for args in [
        &[
            "--connect",
            "https://unused.invalid",
            "--ca-cert",
            "does-not-exist",
            "extra",
        ][..],
        &[
            "--discover",
            "https://unused.invalid",
            "--ca-cert",
            "does-not-exist",
            "extra",
        ][..],
    ] {
        let result = command().args(args).output().unwrap();
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(!String::from_utf8_lossy(&result.stderr).contains("cannot read CA"));
    }
    let empty = command().output().unwrap();
    assert_eq!(empty.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&empty.stderr).contains("cirrus-drive-service"));
}

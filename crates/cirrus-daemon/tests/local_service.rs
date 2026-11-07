#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Fixture {
    dir: PathBuf,
    child: Option<Child>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_file(self.dir.join("cirrus-drive.sock"));
        let _ = fs::remove_file(self.dir.join("cirrus-drive.owner"));
        let _ = fs::remove_file(self.dir.join("marker"));
        let _ = fs::remove_dir(&self.dir);
    }
}

impl Fixture {
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cirrus-daemon"));
        command.env("XDG_RUNTIME_DIR", &self.dir);
        command
    }

    fn start(&mut self) {
        self.child = Some(
            self.command()
                .arg("--no-auto-sync")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if self
                .command()
                .arg("--status")
                .output()
                .unwrap()
                .status
                .success()
            {
                break;
            }
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "daemon exited before readiness"
            );
            assert!(Instant::now() < deadline, "daemon did not become ready");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(&mut self) {
        let result = self.command().arg("--stop").output().unwrap();
        assert!(result.status.success(), "stop failed: {result:?}");
        assert!(self.child.take().unwrap().wait().unwrap().success());
    }
}

#[test]
fn status_service_recovers_and_preserves_unrelated_objects() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("cirrus-service-{}-{unique}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut fixture = Fixture { dir, child: None };
    let unrelated_lock = fs::File::open(&fixture.dir).unwrap();
    rustix::fs::flock(
        &unrelated_lock,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
    fixture.start();

    let status = fixture.command().arg("--status").output().unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8(status.stdout).unwrap().contains(
        "running; automatic sync available for activated Spaces; local staging is not remote confirmation; rename and open-handle restrictions apply"
    ));
    let duplicate = fixture.command().output().unwrap();
    assert!(
        !duplicate.status.success(),
        "duplicate daemon unexpectedly started"
    );
    let socket = fixture.dir.join("cirrus-drive.sock");
    assert_eq!(
        fs::symlink_metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(b"CIRRUS/9 STATUS\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert_eq!(response, "CIRRUS/2 ERROR unsupported request\n");
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(b"CIRRUS/1 STATUS\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert_eq!(response, "CIRRUS/2 ERROR unsupported request\n");

    fixture.stop();
    assert!(!socket.exists(), "socket remains after clean stop");
    fixture.start();
    let mut child = fixture.child.take().unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(socket.exists(), "crash did not leave a socket for recovery");
    fixture.start();
    fixture.stop();

    assert!(!socket.exists());
    let foreign = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
    drop(foreign);
    assert!(!fixture.command().output().unwrap().status.success());
    assert!(
        fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_socket()
    );
    fs::remove_file(&socket).unwrap();
    fs::write(&socket, b"unrelated file").unwrap();
    assert!(!fixture.command().output().unwrap().status.success());
    assert_eq!(fs::read(&socket).unwrap(), b"unrelated file");
    fs::remove_file(&socket).unwrap();
    let marker = fixture.dir.join("marker");
    fs::write(&marker, b"unchanged").unwrap();
    symlink(&marker, &socket).unwrap();
    assert!(!fixture.command().output().unwrap().status.success());
    assert!(
        !fixture
            .command()
            .arg("--status")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(&marker).unwrap(), b"unchanged");
    fs::remove_file(&socket).unwrap();
    let owner = fixture.dir.join("cirrus-drive.owner");
    fs::remove_file(&owner).unwrap();
    fs::write(&owner, b"unrelated owner file").unwrap();
    assert!(!fixture.command().output().unwrap().status.success());
    assert_eq!(fs::read(&owner).unwrap(), b"unrelated owner file");
}

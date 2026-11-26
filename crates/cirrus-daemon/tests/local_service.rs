#![cfg(target_os = "linux")]

use cirrus_client::{self as ipc, AccountReply, AccountRequest as Q};
use cirrus_runtime::RuntimeDir;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt, symlink};
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_cirrus-drive-service"));
        command.env("XDG_RUNTIME_DIR", &self.dir);
        command
    }

    fn runtime(&self) -> RuntimeDir {
        RuntimeDir::open(&self.dir).expect("open private fixture runtime")
    }

    fn endpoint<T>(&self, operation: impl FnOnce(&str) -> T) -> T {
        let runtime = self.runtime();
        operation(&format!(
            "/proc/self/fd/{}/cirrus-drive.sock",
            runtime.as_fd().as_raw_fd()
        ))
    }

    fn connect(&self) -> UnixStream {
        self.endpoint(|path| UnixStream::connect(path).unwrap())
    }

    fn start(&mut self) {
        self.child = Some(
            self.command()
                .arg("--no-auto-sync")
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let error = match ipc::status(&self.runtime()) {
                Ok(_) => break,
                Err(error) => error,
            };
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "daemon exited before readiness"
            );
            assert!(
                Instant::now() < deadline,
                "daemon did not become ready: {error}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(&mut self) {
        ipc::stop(&self.runtime()).expect("stop disposable service");
        assert!(self.child.take().unwrap().wait().unwrap().success());
    }
}

#[test]
fn explicit_space_import_rpc() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("cd-cli-{}-{unique}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let mut fixture = Fixture { dir, child: None };
    fixture.start();

    for request in [
        "CIRRUS/3 {\"operation\":\"Mount\",\"instance\":\"https://instance.invalid\",\"path\":\"/never-mount\"}\n",
        "CIRRUS/3 {\"operation\":\"Unmount\"}\n",
        "CIRRUS/3 {\"operation\":\"StageFile\",\"instance\":\"http://instance.invalid\",\"path\":[\"dir\",\"draft\"],\"source\":\"/never-open\"}\n",
        "CIRRUS/3 {\"operation\":\"Pins\",\"instance\":\"https://instance.invalid\"}\n",
        "CIRRUS/3 {\"operation\":\"Pin\",\"instance\":\"https://instance.invalid\",\"path\":[\"dir\"]}\n",
        "CIRRUS/3 {\"operation\":\"Unpin\",\"instance\":\"https://instance.invalid\",\"path\":[\"dir\"]}\n",
        "CIRRUS/3 {\"operation\":\"Directory\",\"instance\":\"https://instance.invalid\",\"path\":[\"dir\"]}\n",
        "CIRRUS/3 {\"operation\":\"DirectorySpace\",\"instance\":\"https://instance.invalid\",\"path\":[\"dir\"]}\n",
        "CIRRUS/3 {\"operation\":\"SelectSpace\",\"instance\":\"https://instance.invalid\",\"id\":\"space\"}\n",
    ] {
        let mut stream = fixture.connect();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert_eq!(
            response, "CIRRUS/3 ERROR unsupported request\n",
            "{request}"
        );
    }

    let runtime = fixture.runtime();
    let missing_space = ipc::account(
        &runtime,
        Q::UnmountSpace {
            instance: "https://instance.invalid".into(),
            space: "missing-space".into(),
        },
    )
    .unwrap_err();
    assert_eq!(missing_space.to_string(), "Space is not mounted");

    let instance = "http://instance.invalid".to_owned();
    let space = "space".to_owned();
    for (request, expected) in [
        (
            Q::StageFileSpace {
                instance: instance.clone(),
                space: space.clone(),
                path: ipc::SpacePath::from_slash_separated("/dir/../draft"),
                source: "/never-open".into(),
            },
            "invalid Space path",
        ),
        (
            Q::StageFileOfflineSpace {
                instance: instance.clone(),
                space: space.clone(),
                path: ipc::SpacePath::from_slash_separated("/dir/draft"),
                source: "/never-open".into(),
            },
            "instance URL must be HTTPS",
        ),
        (
            Q::DirectorySpace {
                instance: instance.clone(),
                space: space.clone(),
                path: ipc::SpacePath::default(),
            },
            "instance URL must be HTTPS",
        ),
        (
            Q::PinsSpace {
                instance: instance.clone(),
                space: space.clone(),
            },
            "instance URL must be HTTPS",
        ),
        (
            Q::PinsSpaceCheckRemote {
                instance: instance.clone(),
                space: space.clone(),
            },
            "instance URL must be HTTPS",
        ),
        (
            Q::UnpinSpace {
                instance,
                space,
                path: ipc::SpacePath::from_slash_separated("/dir"),
            },
            "instance URL must be HTTPS",
        ),
    ] {
        let error = ipc::account(&runtime, request).unwrap_err();
        assert!(matches!(&error, ipc::ClientError::Rejected(_)), "{error:?}");
        assert!(error.to_string().contains(expected), "{error:?}");
    }

    fixture.stop();
}

#[test]
fn status_service_recovers_and_preserves_unrelated_objects() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("cd-svc-{}-{unique}", std::process::id()));
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

    assert_eq!(
        ipc::status(&fixture.runtime()).unwrap(),
        ipc::ServiceStatus::ManualSync
    );
    let mut fragment = fixture.connect();
    fragment.set_read_timeout(Some(ipc::wire::TIMEOUT)).unwrap();
    fragment.write_all(b"CIRRUS/3 STA").unwrap();
    assert_eq!(
        ipc::status(&fixture.runtime()).expect("STATUS while another request is incomplete"),
        ipc::ServiceStatus::ManualSync,
    );
    fragment
        .write_all(b"TUS\n")
        .expect("complete the first request after the second received its reply");
    let mut reply = Vec::new();
    fragment
        .read_to_end(&mut reply)
        .expect("fragmented STATUS reply");
    assert_eq!(reply, ipc::wire::MANUAL_STATUS_RESPONSE);

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
    let mut stream = fixture.connect();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(b"CIRRUS/9 STATUS\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert_eq!(response, "CIRRUS/3 ERROR unsupported request\n");
    let mut stream = fixture.connect();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(b"CIRRUS/1 STATUS\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert_eq!(response, "CIRRUS/3 ERROR unsupported request\n");
    let mut stream = fixture.connect();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"CIRRUS/3 {\"operation\":\"MountStatus\"}\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert_eq!(response, "CIRRUS/3 ERROR unsupported request\n");

    for legacy in [
        b"CIRRUS/2 STOP\n".as_slice(),
        b"CIRRUS/2 {\"operation\":\"Mounts\"}\n",
    ] {
        let mut stream = fixture.connect();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.write_all(legacy).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert_eq!(
            response,
            "CIRRUS/3 ERROR incompatible client protocol; use matching binaries and restart the service\n"
        );
    }
    assert!(
        matches!(ipc::account(&fixture.runtime(), Q::Mounts).unwrap(), AccountReply::Mounts(rows) if rows.is_empty())
    );

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
    fixture.endpoint(|path| drop(UnixListener::bind(path).unwrap()));
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
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
    assert!(ipc::status(&fixture.runtime()).is_err());
    assert_eq!(fs::read(&marker).unwrap(), b"unchanged");
    fs::remove_file(&socket).unwrap();
    let owner = fixture.dir.join("cirrus-drive.owner");
    fs::remove_file(&owner).unwrap();
    fs::write(&owner, b"unrelated owner file").unwrap();
    assert!(!fixture.command().output().unwrap().status.success());
    assert_eq!(fs::read(&owner).unwrap(), b"unrelated owner file");
}

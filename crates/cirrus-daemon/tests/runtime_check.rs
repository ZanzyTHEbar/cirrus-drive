#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("link"));
        let _ = fs::remove_file(self.0.join("runtime").join("marker"));
        let _ = fs::remove_dir(self.0.join("runtime"));
        let _ = fs::remove_dir(&self.0);
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
}

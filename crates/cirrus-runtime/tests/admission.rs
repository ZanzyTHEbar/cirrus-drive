#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::{SystemTime, UNIX_EPOCH};

use cirrus_runtime::RuntimeDir;

#[test]
fn admission_and_revalidation_stay_attached_to_the_opened_directory() {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "cirrus-admission-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir(&root).unwrap();
    let path = root.join("runtime");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = RuntimeDir::open(&path).unwrap();
    let clone = runtime.try_clone().unwrap();
    let original = rustix::fs::fstat(runtime.as_fd()).unwrap();

    // A symlink ancestor must not admit even an otherwise valid directory.
    let alias = root.join("alias");
    symlink(&root, &alias).unwrap();
    assert!(RuntimeDir::open(&alias.join("runtime")).is_err());

    let moved = root.join("moved");
    fs::rename(&path, &moved).unwrap();
    fs::write(&path, b"replacement is not the held directory").unwrap();
    assert!(RuntimeDir::open(&path).is_err());
    runtime.revalidate().unwrap();
    clone.revalidate().unwrap();
    let held = rustix::fs::fstat(clone.as_fd()).unwrap();
    assert_eq!(
        (held.st_dev, held.st_ino),
        (original.st_dev, original.st_ino)
    );

    fs::set_permissions(&moved, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(runtime.revalidate().is_err());
    assert!(clone.try_clone().is_err());
    assert!(RuntimeDir::open(&moved).is_err());
    fs::remove_file(&alias).unwrap();
    fs::remove_file(&path).unwrap();
    fs::remove_dir(&moved).unwrap();
    fs::remove_dir(&root).unwrap();
}

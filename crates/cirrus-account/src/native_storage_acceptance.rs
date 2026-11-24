//! Bounded native filesystem acceptance, not OS App Group entitlement acceptance.
//! Run only with a new owned 0700 CIRRUS_NATIVE_ACCEPTANCE_DIR on local APFS.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::{Entry, account_storage::StorageRoot, directory::DirectorySnapshot, offline, storage};

const TEST: &str = "native_storage_acceptance::native_storage_persistence_and_isolation";
const PAYLOAD: &[u8] = b"native APFS payload retained exactly";

struct Writer(Child);
impl Drop for Writer {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

fn child(path: &Path, role: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--nocapture"])
        .env("CIRRUS_NATIVE_ACCEPTANCE_DIR", path)
        .env("CIRRUS_NATIVE_ACCEPTANCE_ROLE", role);
    command
}

fn journal_value(conn: &rusqlite::Connection) -> String {
    conn.query_row(
        "SELECT staged_file FROM operation_journal WHERE instance='native-acceptance' AND id=1",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn child_role(path: &Path, role: &str) {
    let root = StorageRoot::admit_app_group_directory(&path.join("container")).unwrap();
    let conn = offline::database_in(&root).unwrap();
    match role {
        "writer" => {
            conn.execute_batch("BEGIN IMMEDIATE; INSERT INTO operation_journal(id,instance,space,path,op_type,staged_file,state,updated_at) VALUES(1,'native-acceptance','space','/draft','write','exact-native-journal-payload','pending',1);").unwrap();
            // This is the critical POSIX boundary: product metadata/ACL admission,
            // another real product connection close, and accounting must not
            // release this process's existing writer locks.
            drop(offline::database_in(&root).unwrap());
            storage::status_in(&root).unwrap();
            std::fs::write(path.join("writer-ready"), b"ready").unwrap();
            std::io::stdin().read_exact(&mut [0]).unwrap();
            conn.execute_batch("COMMIT").unwrap();
        }
        "contender" => {
            conn.busy_timeout(Duration::ZERO).unwrap();
            let error = conn.execute_batch("BEGIN IMMEDIATE").unwrap_err();
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
        }
        "persisted" => {
            assert_eq!(journal_value(&conn), "exact-native-journal-payload");
            offline::verify_identity_in(&root, "native-acceptance", "issuer", "subject").unwrap();
        }
        _ => panic!("unknown child role"),
    }
    println!("native child {role}: PASS");
}

#[test]
fn native_storage_persistence_and_isolation() {
    let path = std::env::var_os("CIRRUS_NATIVE_ACCEPTANCE_DIR")
        .expect("native acceptance requires an explicit new private job fixture");
    let path = Path::new(&path);
    let pid = std::process::id();
    let start = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .output()
        .unwrap();
    assert!(start.status.success());
    println!(
        "native process pid={pid} role={} start={}",
        std::env::var("CIRRUS_NATIVE_ACCEPTANCE_ROLE").unwrap_or_else(|_| "parent".into()),
        String::from_utf8(start.stdout).unwrap().trim()
    );
    if let Ok(role) = std::env::var("CIRRUS_NATIVE_ACCEPTANCE_ROLE") {
        child_role(path, &role);
        return;
    }
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir() && metadata.mode() & 0o7777 == 0o700);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    let container = path.join("container");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&container)
        .unwrap();
    let root = StorageRoot::admit_app_group_directory(&container).unwrap();
    assert!(crate::ownership::file_ops::local_apfs(root.directory()).unwrap());
    offline::bind_identity_in(&root, "native-acceptance", "issuer", "subject").unwrap();
    let mut writer = Writer(child(path, "writer").stdin(Stdio::piped()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.join("writer-ready").exists() {
        assert!(writer.0.try_wait().unwrap().is_none(), "writer failed");
        assert!(Instant::now() < deadline, "writer readiness timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(child(path, "contender").status().unwrap().success());
    writer.0.stdin.take().unwrap().write_all(b"commit").unwrap();
    assert!(writer.0.wait().unwrap().success());
    assert!(child(path, "persisted").status().unwrap().success());

    // One realistic listing retains its anonymous disk and namespace allowance
    // until the final reader drops, not merely until its producer disappears.
    storage::limits::set_in(
        &root,
        Some(storage::StorageLimits {
            budget_bytes: 256 * 1024 * 1024,
            free_space_reserve_bytes: 0,
        }),
    )
    .unwrap();
    let mut snapshot = DirectorySnapshot::empty_in(&root).unwrap();
    snapshot
        .insert(&Entry::staged_directory("draft".into(), 1))
        .unwrap();
    let reader = snapshot.clone();
    drop(snapshot);
    assert_eq!(reader.page(0).unwrap()[0].1.name(), "draft");
    let live = storage::status_in(&root).unwrap();
    assert_eq!(live.namespace_reservations.len(), 1);
    assert!(live.daemon_directory_scratch.allocated_bytes > 0);
    println!(
        "native snapshot live: reservations={} allocated={}",
        live.namespace_reservations.len(),
        live.daemon_directory_scratch.allocated_bytes
    );
    drop(reader);
    let released = storage::status_in(&root).unwrap();
    assert!(released.namespace_reservations.is_empty());
    assert_eq!(released.daemon_directory_scratch.objects, 0);
    assert!(
        std::fs::read_dir(container.join("cirrus-drive/directory-snapshots"))
            .unwrap()
            .next()
            .is_none()
    );

    // Real product staging performs F_PREALLOCATE, write, sync and reservation
    // drop. Inspect allocated blocks as well as EOF; sparse success is not enough.
    let overlay =
        offline::overlay::Overlay::import_in(&root, &mut &PAYLOAD[..], PAYLOAD.len() as u64)
            .unwrap();
    let staging = container.join("cirrus-drive/staging");
    let entries: Vec<_> = std::fs::read_dir(&staging)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    let held = std::fs::File::open(&entries[0]).unwrap();
    let allocated = held.metadata().unwrap();
    assert!(allocated.blocks() * 512 >= PAYLOAD.len() as u64);
    assert_eq!(std::fs::read(&entries[0]).unwrap(), PAYLOAD);
    assert!(offline::storage_reservations_in(&root).unwrap().is_empty());
    println!(
        "native staged payload: dev={} ino={} size={} blocks={} uid={} mode={:o} nlink={}",
        allocated.dev(),
        allocated.ino(),
        allocated.size(),
        allocated.blocks(),
        allocated.uid(),
        allocated.mode(),
        allocated.nlink()
    );
    drop(overlay);
    let named = std::fs::symlink_metadata(&entries[0]).unwrap();
    assert_eq!(
        (named.dev(), named.ino()),
        (allocated.dev(), allocated.ino())
    );
    rustix::fs::unlinkat(
        root.staging_dir().unwrap(),
        entries[0].file_name().unwrap(),
        rustix::fs::AtFlags::empty(),
    )
    .unwrap();
    held.sync_all().unwrap();
    rustix::fs::fsync(root.staging_dir().unwrap()).unwrap();

    // One real native ALLOW ACL must fail closed before SQLite payload access,
    // preserving all preexisting bytes. Never modify ancestors or user policy.
    let db = container.join("cirrus-drive/state.db");
    let bytes = std::fs::read(&db).unwrap();
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&db)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("/bin/ls")
            .arg("-lne")
            .arg(&db)
            .status()
            .unwrap()
            .success()
    );
    assert!(offline::database_in(&root).is_err());
    assert_eq!(std::fs::read(&db).unwrap(), bytes);
    println!("native private-container persistence/isolation/scratch/ACL: PASS");
}

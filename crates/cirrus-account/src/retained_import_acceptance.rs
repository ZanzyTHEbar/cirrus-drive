use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, FileExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use cirrus_runtime::RuntimeDir;
use rusqlite::params;

use crate::{
    Accounts, DirectoryIdentity, DirectorySnapshot, Entry, FileVersion, StorageLimits, StorageRoot,
    offline, ownership,
};

#[test]
fn retained_file_import_preserves_exact_evidence_and_publishes_latest_durable_head() {
    const INSTANCE: &str = "https://instance.invalid/";
    const ISSUER: &str = "https://issuer.invalid/";
    const SPACE: &str = "retained-space";
    const CONTENT: &[u8] = b"entire local file";

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("retained-import-{}-{nonce}", std::process::id()));
    DirBuilder::new().mode(0o700).create(&path).unwrap();
    let fixture = Fixture(path);
    let runtime = fixture.0.join("runtime");
    DirBuilder::new().mode(0o700).create(&runtime).unwrap();
    let root = StorageRoot::open_container(&fixture.0).unwrap();
    let runtime = RuntimeDir::open(&runtime).unwrap();
    let accounts = Accounts::with_storage(runtime.try_clone().unwrap(), root.clone());
    let source = fixture.0.join("source");
    fs::write(&source, CONTENT).unwrap();
    let target = ["subdir".to_owned(), "draft".to_owned()];
    let import = |space: &str| accounts.stage_file_offline_space(INSTANCE, space, &target, &source);

    offline::bind_identity_in(&root, INSTANCE, ISSUER, "owner").unwrap();
    let conn = offline::database_in(&root).unwrap();
    conn.execute("INSERT INTO sync_spaces(instance,space,issuer,subject,phase,failures,next_at,verified_through) VALUES (?1,?2,?3,'other','Queued',0,0,0)", params![INSTANCE, SPACE, ISSUER]).unwrap();
    assert!(
        import(SPACE)
            .unwrap_err()
            .to_string()
            .contains("matching retained account")
    );
    conn.execute(
        "UPDATE sync_spaces SET subject='owner' WHERE space=?1",
        [SPACE],
    )
    .unwrap();
    assert!(
        import("other-space")
            .unwrap_err()
            .to_string()
            .contains("verified Space activation")
    );

    let entry = |name: &str, id: &str, directory: bool| {
        serde_json::from_value::<Entry>(serde_json::json!({
            "name": name, "id": id, "directory": directory,
            "size": if directory { None } else { Some(3) },
            "modified": {"secs_since_epoch": 0, "nanos_since_epoch": 0},
            "etag": "\"v1\"", "checksums": []
        }))
        .unwrap()
    };
    let save = |path: &[String], id: &str, child: Entry| {
        let mut snapshot = DirectorySnapshot::empty_in(&root).unwrap();
        snapshot.set_remote_parent(id, "\"v1\"").unwrap();
        snapshot.insert(&child).unwrap();
        assert!(
            offline::save_directory_snapshot(
                offline::begin_snapshot_in(&root).unwrap(),
                INSTANCE,
                SPACE,
                path,
                &snapshot,
            )
            .unwrap()
        );
    };
    save(&[], "root-id", entry("subdir", "subdir-id", true));
    assert!(
        import(SPACE)
            .unwrap_err()
            .to_string()
            .contains("metadata is unavailable")
    );
    save(&target[..1], "subdir-id", entry("draft", "draft-id", false));
    accounts
        .configure_storage_limits(Some(StorageLimits {
            budget_bytes: 512 * 1024 * 1024,
            free_space_reserve_bytes: 0,
        }))
        .unwrap();

    let competitor = ownership::acquire_offline_exclusive_in(&root, &runtime).unwrap();
    assert!(
        import(SPACE).is_err(),
        "import bypassed principal ownership"
    );
    drop(competitor);

    // Retained imports join the same principal's shared staging window.
    let _shared = ownership::acquire_offline_in(&root, &runtime).unwrap();
    let pending = |root| offline::pending_writes(root, INSTANCE, Some(SPACE), 0, i64::MAX).unwrap();
    let read = |root, staged, bytes: &[u8]| {
        let staged = offline::StagedSnapshot::open_at(root, staged).unwrap();
        assert_eq!(staged.len(), bytes.len() as u64);
        assert_eq!(staged.range(0, bytes.len() as u32).unwrap(), bytes);
    };
    import(SPACE).unwrap();
    let original = pending(&root).pop().unwrap();
    read(&root, &original.staged, CONTENT);

    conn.execute_batch(
        "CREATE TRIGGER refuse_replacement BEFORE UPDATE OF error_msg ON operation_journal
         WHEN NEW.error_msg GLOB 'local publication recovery:*'
         BEGIN SELECT RAISE(ABORT, 'test abort after root CAS'); END;",
    )
    .unwrap();
    fs::write(&source, b"must not replace prior root").unwrap();
    assert!(import(SPACE).is_err());
    assert_eq!(pending(&root), [original.clone()]);
    read(&root, &original.staged, CONTENT);
    conn.execute_batch("DROP TRIGGER refuse_replacement")
        .unwrap();

    // A newer observation of the underlying file is not a new PUT base for
    // this already acknowledged local edit.
    save(&target[..1], "subdir-id", entry("draft", "other-id", false));
    let input = fs::File::create(&source).unwrap();
    let tail = 64 * 1024 * 1024 + 1;
    input.write_all_at(b"large tail", tail).unwrap();
    drop(input);
    import(SPACE).unwrap();
    let reopened = StorageRoot::open_container(&fixture.0).unwrap();
    let writes = pending(&reopened);
    assert_eq!(writes.len(), 1);
    let replacement = &writes[0];
    assert_eq!(replacement.id, original.id);
    assert_ne!(replacement.staged, original.staged);
    assert_eq!(replacement.space, SPACE);
    assert_eq!(replacement.path, target);
    assert_eq!(replacement.base_id.as_deref(), Some("draft-id"));
    assert_eq!(replacement.base_etag.as_deref(), Some("\"v1\""));
    assert_eq!(
        replacement.parents,
        [DirectoryIdentity::Remote("subdir-id".to_owned())]
    );
    let staged = offline::StagedSnapshot::open_at(&reopened, &replacement.staged).unwrap();
    assert_eq!(staged.len(), tail + 10);
    assert_eq!(staged.range(tail - 1, 11).unwrap(), b"\0large tail");

    fs::write(&source, b"in-flight").unwrap();
    import(SPACE).unwrap();
    let predecessor = pending(&reopened).pop().unwrap();
    offline::set_write_state(
        &reopened,
        INSTANCE,
        &predecessor,
        "pending",
        "uncertain",
        Some("upload started"),
    )
    .unwrap();
    let sent = offline::StagedSnapshot::open_at(&reopened, &predecessor.staged).unwrap();
    offline::UploadVerification::record(
        &reopened,
        INSTANCE,
        &predecessor,
        sent.digest().unwrap(),
        sent.len(),
    )
    .unwrap();
    fs::write(&source, b"first waiting edit").unwrap();
    import(SPACE).unwrap();
    fs::write(&source, b"latest waiting edit").unwrap();
    // Authenticated import uses the same admitted path and head as retained
    // import. Exercise the account-side kernel without live DAV or keyring.
    offline::stage_file(
        &root,
        (INSTANCE, SPACE),
        &target,
        &source,
        offline::ImportEvidence::Online {
            issuer: ISSUER,
            subject: "owner",
        },
        &accounts.cancelled,
    )
    .unwrap();
    let reopened = StorageRoot::open_container(&fixture.0).unwrap();
    assert!(
        pending(&reopened).is_empty(),
        "waiting edit became sendable"
    );
    let receipt = offline::upload_verifications(&reopened, INSTANCE, Some(SPACE), 0).unwrap();
    assert_eq!(receipt.len(), 1);
    assert_eq!(receipt[0].operation, predecessor);
    read(&reopened, &predecessor.staged, b"in-flight");
    let entries = accounts
        .offline_directory(INSTANCE, SPACE, &target[..1])
        .unwrap();
    let visible = entries
        .iter()
        .find(|entry| entry.name() == "draft")
        .unwrap();
    let (local, name) = offline::staged_version(&reopened, INSTANCE, SPACE, &target, visible.id())
        .unwrap()
        .unwrap();
    read(&reopened, &name, b"latest waiting edit");

    // This exercises the durable confirmation transition, not a live PUT.
    offline::confirm_write(
        &reopened,
        INSTANCE,
        &predecessor,
        &FileVersion {
            instance: INSTANCE.to_owned(),
            space: SPACE.to_owned(),
            path: target.to_vec(),
            id: "verified-id".to_owned(),
            etag: "\"verified-etag\"".to_owned(),
            size: sent.len(),
            checksums: Vec::new(),
        },
    )
    .unwrap();
    let writes = pending(&reopened);
    assert_eq!(writes.len(), 1);
    let successor = &writes[0];
    assert_eq!(local.id, format!("cirrus-staged:{}", successor.id));
    assert_eq!(successor.base_id.as_deref(), Some("verified-id"));
    assert_eq!(successor.base_etag.as_deref(), Some("\"verified-etag\""));
    assert_eq!(successor.parents, original.parents);
    read(&reopened, &successor.staged, b"latest waiting edit");

    offline::set_write_state(&root, INSTANCE, successor, "pending", "uncertain", None).unwrap();
    fs::write(&source, b"save during rejected upload").unwrap();
    import(SPACE).unwrap();
    offline::set_write_state(
        &root,
        INSTANCE,
        successor,
        "uncertain",
        "pending",
        Some("precondition rejected"),
    )
    .unwrap();
    assert!(
        pending(&reopened).is_empty(),
        "rejection requeued obsolete bytes"
    );
    offline::acknowledge(&reopened, INSTANCE, &successor.staged).unwrap();
    assert!(
        pending(&reopened).is_empty(),
        "acknowledgement enabled unknown replay"
    );
    let entries = accounts
        .offline_directory(INSTANCE, SPACE, &target[..1])
        .unwrap();
    let visible = entries
        .iter()
        .find(|entry| entry.name() == "draft")
        .unwrap();
    let (_, name) = offline::staged_version(&reopened, INSTANCE, SPACE, &target, visible.id())
        .unwrap()
        .unwrap();
    read(&reopened, &name, b"save during rejected upload");

    let absent = [target[0].clone(), "new".to_owned()];
    accounts
        .stage_file_offline_space(INSTANCE, SPACE, &absent, &source)
        .unwrap();
    let writes = pending(&reopened);
    assert_eq!(writes.len(), 1);
    let write = &writes[0];
    assert_eq!(write.path, absent);
    assert_eq!(write.base_id, None);
    assert_eq!(write.base_etag, None);
    let entries = accounts
        .offline_directory(INSTANCE, SPACE, &target[..1])
        .unwrap();
    assert_eq!(
        entries.iter().map(Entry::name).collect::<Vec<_>>(),
        ["draft", "new"]
    );
    assert_eq!(
        accounts.activated_spaces().unwrap(),
        [(INSTANCE.to_owned(), SPACE.to_owned())]
    );
}

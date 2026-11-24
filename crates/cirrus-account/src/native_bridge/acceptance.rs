//! Fixture-only initializer. Never present in the ordinary production staticlib.
//! Compile this actual crate with --cfg test into a separately named artifact.

use super::*;

const INSTANCE: &str = "https://retained-bridge.example/";
const SIZE: usize = 3 * 131_072 + 17;

/// Exercise the shared allocator using real retained fixture state, NOT an
/// authenticated online binding. Never qualify the production auth path here.
#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_catalog_fixture_prepare(
    pointer: *mut c_void,
    buffer: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    boundary(|| unsafe {
        if written.is_null() {
            return Err(INVALID);
        }
        *written = 0;
        if buffer.is_null() || capacity != MAX_PAGE {
            return Err(INVALID);
        }
        let Value::Core(core) = &handle(pointer)?.value else {
            return Err(INVALID);
        };
        let binding = core
            .accounts
            .bind_offline_space(INSTANCE, "space")
            .map_err(account_error)?;
        // Real retained account guards refuse foreign-principal adoption while
        // staged originals/journal exist. Do not rewrite any identity/fp_* rows.
        assert!(
            crate::offline::bind_identity_in(
                &binding.root,
                INSTANCE,
                "foreign-issuer",
                "foreign-subject",
            )
            .is_err()
        );
        assert!(
            core.accounts
                .bind_offline_space(INSTANCE, "foreign-space")
                .is_err()
        );
        // Ordinary production preparation must not accept this offline fixture.
        assert!(matches!(
            crate::provider_catalog::Catalog::prepare_authenticated(&binding),
            Err(crate::provider_catalog::Error::Unavailable)
        ));
        let domain =
            crate::provider_catalog::Catalog::prepare_fixture(&binding).map_err(catalog_error)?;
        let mut restored = vec![0; MAX_PAGE];
        let mut count = 0;
        assert_eq!(
            super::application::cirrus_application_domains_restore(
                pointer,
                restored.as_mut_ptr(),
                restored.len(),
                &mut count,
            ),
            OK
        );
        let restored: serde_json::Value =
            serde_json::from_slice(&restored[..count]).map_err(|_| INTERNAL)?;
        assert_eq!(
            restored,
            serde_json::json!({"domains":[{"domain":domain}],"unavailable":0})
        );
        let mut absent = std::ptr::null_mut();
        let unknown = "unregistered-domain";
        assert_eq!(
            cirrus_catalog_resume(
                pointer,
                Text {
                    data: unknown.as_ptr(),
                    len: unknown.len()
                },
                &mut absent
            ),
            UNAVAILABLE
        );
        assert!(absent.is_null());
        let bytes =
            serde_json::to_vec(&serde_json::json!({"domain":domain})).map_err(|_| INTERNAL)?;
        if bytes.len() > capacity {
            return Err(CAPACITY);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
        *written = bytes.len();
        Ok(())
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_retained_fixture(path_text: Text, out: *mut *mut c_void) -> i32 {
    boundary(|| {
        // SAFETY: acceptance consumer follows the same validated-span contracts.
        unsafe {
            if out.is_null() {
                return Err(INVALID);
            }
            *out = std::ptr::null_mut();
            let path = Path::new(text(path_text)?);
            // Existing new private fixture only: caller creates it in this job.
            let core = admitted_core(path, None)?;
            let root = core.accounts.storage_root().map_err(|_| UNAVAILABLE)?;
            let conn = crate::offline::database_in(&root).map_err(|_| UNAVAILABLE)?;
            crate::offline::bind_identity_in(&root, INSTANCE, "issuer", "subject")
                .map_err(|_| UNAVAILABLE)?;
            // Product DDL, only retained identity/activation/observation data.
            conn.execute("INSERT INTO sync_spaces VALUES(?1,'space','issuer','subject','observed-idle',0,0,NULL,1,0,NULL)", [INSTANCE]).map_err(|_| UNAVAILABLE)?;
            conn.execute("INSERT INTO snapshots VALUES(?1,'space','[]','[]',1,'root-id','\"root-etag\"',NULL,'issuer','subject')", [INSTANCE]).map_err(|_| UNAVAILABLE)?;
            drop(conn);
            let mut binding = core
                .accounts
                .bind_offline_space(INSTANCE, "space")
                .map_err(|_| UNAVAILABLE)?;
            binding.offline_writable = true;
            // Actual product Overlay/persistence publication. No auth/network,
            // schema copy, manual payload files, or substitute account engine.
            let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
            let (staged, operation) = core
                .accounts
                .stage_mount_mutation_operation(
                    INSTANCE,
                    &binding,
                    &["retained.bin".into()],
                    crate::DirtyMutation::Write {
                        offset: 0,
                        bytes: &payload,
                    },
                    None,
                    &[],
                )
                .map_err(|_| UNAVAILABLE)?;
            // Actual product publication/result boundary, not seeded synced
            // rows or a simulated remote receipt. The operation is still pending.
            let encoded = serde_json::to_vec(&operation).map_err(|_| INTERNAL)?;
            let restored: crate::OperationHandle =
                serde_json::from_slice(&encoded).map_err(|_| INTERNAL)?;
            assert_eq!(operation, restored);
            assert_eq!(
                core.accounts
                    .staged_operation(&binding, &staged)
                    .map_err(account_error)?,
                operation
            );
            assert_eq!(
                core.accounts
                    .operation_result(&binding, &restored)
                    .map_err(account_error)?,
                crate::OperationResult::Pending
            );
            let reopened = admitted_core(path, None)?;
            let reopened_binding = reopened
                .accounts
                .bind_offline_space(INSTANCE, "space")
                .map_err(account_error)?;
            assert_eq!(
                reopened
                    .accounts
                    .operation_result(&reopened_binding, &restored)
                    .map_err(account_error)?,
                crate::OperationResult::Pending
            );
            let election = core.accounts.acquire_scheduler().map_err(account_error)?;
            assert!(reopened.accounts.acquire_scheduler().is_err());
            assert_eq!(
                election
                    .activated_spaces(&core.accounts)
                    .map_err(account_error)?,
                vec![(INSTANCE.to_owned(), "space".to_owned())]
            );
            drop(election);
            drop(
                reopened
                    .accounts
                    .acquire_scheduler()
                    .map_err(account_error)?,
            );
            output(out, Value::Core(core))
        }
    })
}

/// Real persisted observation fixture for the single catalog restart scenario.
/// The old staged initializer above and every original assertion stay intact.
/// This initializer is idempotent across fresh processes and never exported by
/// an ordinary production archive.
#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_catalog_fixture(path_text: Text, out: *mut *mut c_void) -> i32 {
    // SAFETY: the acceptance consumer keeps readable text and distinct writable
    // output storage live through this synchronous owner-thread initializer.
    boundary(|| unsafe {
        use rusqlite::params;
        use sha2::{Digest, Sha256};
        if out.is_null() {
            return Err(INVALID);
        }
        *out = std::ptr::null_mut();
        let core = admitted_core(Path::new(text(path_text)?), None)?;
        let root = core.accounts.storage_root().map_err(account_error)?;
        crate::offline::bind_identity_in(&root, INSTANCE, "issuer", "subject")
            .map_err(account_error)?;
        let mut conn = crate::offline::database_in(&root).map_err(account_error)?;
        let seeded:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM snapshots s,json_each(s.entries) e WHERE s.instance=?1 AND s.space='space' AND json_extract(e.value,'$.id')='catalog-remote-0')",[INSTANCE],|r|r.get(0)).map_err(|_|UNAVAILABLE)?;
        if !seeded {
            let tx = conn.transaction().map_err(|_| UNAVAILABLE)?;
            tx.execute("INSERT OR IGNORE INTO sync_spaces VALUES(?1,'space','issuer','subject','observed-idle',0,0,NULL,1,0,NULL)",[INSTANCE]).map_err(|_|UNAVAILABLE)?;
            let entries: Vec<crate::Entry> = (0..40)
                .map(|i| {
                    serde_json::from_value(serde_json::json!({
                        "name":format!("{i:03}.bin"),"id":format!("catalog-remote-{i}"),
                        "directory":false,"size":if i==0 {SIZE}else{0},
                        "etag":"\"catalog-v1\"","checksums":[],
                        "modified":{"secs_since_epoch":1,"nanos_since_epoch":0}
                    }))
                    .expect("valid persisted fixture entry")
                })
                .collect();
            let json = serde_json::to_string(&entries).map_err(|_| INTERNAL)?;
            tx.execute("INSERT INTO snapshots VALUES(?1,'space','[]',?2,1,'root-id','\"root-etag\"',NULL,'issuer','subject') ON CONFLICT(instance,space,path) DO UPDATE SET entries=excluded.entries",params![INSTANCE,json]).map_err(|_|UNAVAILABLE)?;
            let version = FileVersion {
                instance: INSTANCE.into(),
                space: "space".into(),
                path: vec!["000.bin".into()],
                id: "catalog-remote-0".into(),
                etag: "\"catalog-v1\"".into(),
                size: SIZE as u64,
                checksums: vec![],
            };
            let version_json = serde_json::to_string(&version).map_err(|_| INTERNAL)?;
            let path = "[\"000.bin\"]";
            tx.execute(
                "INSERT INTO pins VALUES(?1,'space',?2,0,'[]',?3)",
                params![
                    INSTANCE,
                    path,
                    serde_json::to_string(&vec![&version]).map_err(|_| INTERNAL)?
                ],
            )
            .map_err(|_| UNAVAILABLE)?;
            tx.execute(
                "INSERT INTO files VALUES(?1,'space',?2,?2,?3,1)",
                params![INSTANCE, path, version_json],
            )
            .map_err(|_| UNAVAILABLE)?;
            for offset in (0..SIZE).step_by(CHUNK as usize) {
                let bytes: Vec<u8> = (offset..(offset + CHUNK as usize).min(SIZE))
                    .map(|i| (i % 251) as u8)
                    .collect();
                let digest = format!("{:x}", Sha256::digest(&bytes));
                tx.execute(
                    "INSERT INTO chunks VALUES(?1,'space',?2,?2,?3,?4,?5)",
                    params![INSTANCE, path, offset as i64, bytes, digest],
                )
                .map_err(|_| UNAVAILABLE)?;
            }
            tx.commit().map_err(|_| UNAVAILABLE)?;
        }
        drop(conn);
        output(out, Value::Core(core))
    })
}

/// Additional inputs for the same real catalog scenario, in a separate owned
/// fixture. Only retained observations/content locations change, never fp_* rows.
#[unsafe(no_mangle)]
unsafe extern "C" fn cirrus_catalog_move_observations(path_text: Text, moved: u8) -> i32 {
    boundary(|| unsafe {
        use rusqlite::params;
        let mut raw = std::ptr::null_mut();
        let status = cirrus_catalog_fixture(path_text, &mut raw);
        if status != OK {
            return Err(status);
        }
        let result = (|| {
            let Value::Core(core) = &handle(raw)?.value else {
                return Err(INTERNAL);
            };
            let root = core.accounts.storage_root().map_err(account_error)?;
            let mut conn = crate::offline::database_in(&root).map_err(account_error)?;
            let tx = conn.transaction().map_err(|_| UNAVAILABLE)?;
            let text: String = tx.query_row("SELECT entries FROM snapshots WHERE instance=?1 AND space='space' AND path='[]'",[INSTANCE],|r|r.get(0)).map_err(|_|UNAVAILABLE)?;
            let mut entries: Vec<crate::Entry> =
                serde_json::from_str(&text).map_err(|_| INTERNAL)?;
            if entries.iter().any(|e| e.id() == "catalog-directory-B") != (moved != 0) {
                return Err(INVALID);
            }
            entries.retain(|e| e.id() != "catalog-directory-B");
            let x = entries.first().ok_or(INTERNAL)?.clone();
            if moved != 0 {
                entries.remove(0);
            }
            entries.push(serde_json::from_value(serde_json::json!({
                "name":"B","id":"catalog-directory-B","directory":true,
                "size":null,"etag":if moved==0 {"\"b1\""}else{"\"b2\""},
                "checksums":[],"modified":{"secs_since_epoch":if moved==0 {1}else{2},"nanos_since_epoch":0}
            })).map_err(|_|INTERNAL)?);
            let children = if moved == 0 { vec![] } else { vec![x] };
            tx.execute(
                "UPDATE snapshots SET entries=?2 WHERE instance=?1 AND space='space' AND path='[]'",
                params![
                    INSTANCE,
                    serde_json::to_string(&entries).map_err(|_| INTERNAL)?
                ],
            )
            .map_err(|_| UNAVAILABLE)?;
            tx.execute("INSERT INTO snapshots VALUES(?1,'space','[\"B\"]',?2,1,'catalog-directory-B',?3,NULL,'issuer','subject') ON CONFLICT(instance,space,path) DO UPDATE SET entries=excluded.entries,self_etag=excluded.self_etag",
                params![INSTANCE,serde_json::to_string(&children).map_err(|_|INTERNAL)?,if moved==0 {"\"b1\""}else{"\"b2\""}]).map_err(|_|UNAVAILABLE)?;
            if moved != 0 {
                // Real persisted exact-version bytes now live at the observed
                // destination. No catalog identity/version is supplied as oracle.
                let old = "[\"000.bin\"]";
                let new = "[\"B\",\"000.bin\"]";
                let value: String = tx
                    .query_row(
                        "SELECT version FROM files WHERE instance=?1 AND space='space' AND path=?2",
                        params![INSTANCE, old],
                        |r| r.get(0),
                    )
                    .map_err(|_| UNAVAILABLE)?;
                let mut version: FileVersion =
                    serde_json::from_str(&value).map_err(|_| INTERNAL)?;
                version.path = vec!["B".into(), "000.bin".into()];
                tx.execute("UPDATE files SET path=?3,root=?3,version=?4 WHERE instance=?1 AND space='space' AND path=?2",params![INSTANCE,old,new,serde_json::to_string(&version).map_err(|_|INTERNAL)?]).map_err(|_|UNAVAILABLE)?;
                tx.execute("UPDATE chunks SET path=?3,root=?3 WHERE instance=?1 AND space='space' AND path=?2",params![INSTANCE,old,new]).map_err(|_|UNAVAILABLE)?;
                tx.execute("UPDATE pins SET root=?3,manifest=?4 WHERE instance=?1 AND space='space' AND root=?2",params![INSTANCE,old,new,serde_json::to_string(&vec![version]).map_err(|_|INTERNAL)?]).map_err(|_|UNAVAILABLE)?;
            }
            tx.commit().map_err(|_| UNAVAILABLE)?;
            Ok(())
        })();
        let closed = cirrus_retained_close(raw);
        result?;
        if closed != OK {
            return Err(closed);
        }
        Ok(())
    })
}

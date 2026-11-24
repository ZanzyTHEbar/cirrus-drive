//! Pipe adapter for the private real OpenCloud recovery acceptance, not OIDC.
use std::io::{BufRead, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

fn prove_bus() {
    let bus = std::env::var("CIRRUS_TEST_USER_BUS_DIR").unwrap();
    assert_eq!(
        std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap(),
        format!("unix:path={bus}/bus")
    );
    let directory = std::fs::symlink_metadata(&bus).unwrap();
    let uid = rustix::process::getuid().as_raw();
    assert!(directory.is_dir() && directory.mode() & 0o777 == 0o700);
    assert_eq!(directory.uid(), uid);
    let socket = std::fs::symlink_metadata(format!("{bus}/bus")).unwrap();
    assert!(socket.file_type().is_socket() && socket.uid() == uid);
    let output = std::process::Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.GetConnectionUnixProcessID",
            "org.freedesktop.DBus",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!(
            "(uint32 {},)",
            std::env::var("CIRRUS_CLEANUP_BUS_PID").unwrap()
        )
    );
}

#[test]
#[ignore = "requires owned private bus and pinned real OpenCloud acceptance fixture"]
fn real_recovery_flow() {
    prove_bus();
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap();
    let accounts =
        crate::Accounts::new(cirrus_runtime::RuntimeDir::open(Path::new(&runtime)).unwrap());
    let mut cursor = super::provider_mutation::ReconciliationCursor::default();
    println!("CLEANUP_READY");
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        prove_bus();
        let input: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let output = match input["op"].as_str() {
            Some("prepare") => {
                let binding = accounts
                    .bind_space(
                        input["instance"].as_str().unwrap(),
                        input["space"].as_str().unwrap(),
                    )
                    .unwrap();
                serde_json::json!({"domain": accounts.prepare_provider_domain(&binding).unwrap()})
            }
            Some("observe") => match accounts.provider_fixture_observe(
                input["domain"].as_str().unwrap(),
                input["container"].as_str().unwrap(),
            ) {
                Ok(items) => serde_json::json!({"items": items}),
                Err(e) => serde_json::json!({"error": format!("{e:?}")}),
            },
            Some("reconcile") => {
                let election = accounts.acquire_scheduler().unwrap();
                let domains = accounts.reconcile_provider_requests(
                    election.retained_root(),
                    input["instance"].as_str().unwrap(),
                    input["space"].as_str().unwrap(),
                    &mut cursor,
                );
                serde_json::json!({"domains": domains})
            }
            Some("manual-sync") => {
                accounts
                    .sync_space(
                        input["instance"].as_str().unwrap(),
                        input["space"].as_str().unwrap(),
                    )
                    .unwrap();
                serde_json::json!({"synced": true})
            }
            _ => {
                let request = serde_json::from_value(input["request"].clone()).unwrap();
                match accounts.provider_mutation(
                    input["domain"].as_str().unwrap(),
                    &request,
                    input["source"].as_str().map(Path::new),
                    || false,
                ) {
                    Ok(reply) => serde_json::json!({"reply": reply}),
                    Err(e) => serde_json::json!({"error": format!("{e:?}")}),
                }
            }
        };
        println!("{output}");
        std::io::stdout().flush().unwrap();
    }
}

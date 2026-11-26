use std::fs::{self, DirBuilder};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::thread;

use rusqlite::params;

use super::*;

const SPACE: &str = "space";
const LISTED: &str = r#"{"value":[{"id":"space","name":"My Space"}]}"#;

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn loopback(scheme: &str) -> (Url, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = Url::parse(&format!("{scheme}://{}/", listener.local_addr().unwrap())).unwrap();
    (base, listener)
}

fn reply_once(listener: TcpListener, reply: String) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        drop(listener); // A subsequent wire request receives a connection refusal.
        connection
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = BufReader::new(&mut connection);
        let mut line = String::new();
        request.read_line(&mut line).unwrap();
        assert!(line.starts_with("GET /graph/v1.0/me/drives "));
        loop {
            line.clear();
            assert_ne!(request.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
        }
        connection.write_all(reply.as_bytes()).unwrap();
    })
}

fn response(status: u16, body: &str, declared_length: usize) -> String {
    format!(
        "HTTP/1.1 {status} test\r\nContent-Type: application/json\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n{body}"
    )
}

fn no_refresh(_: &mut ReadSession) -> Result<(), AccountError> {
    panic!("this startup must not request a refresh");
}

fn reply_invalid_tls_once(listener: TcpListener) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        connection.read_exact(&mut [0; 5]).unwrap();
        connection.write_all(b"not a TLS record\r\n").unwrap();
    })
}

#[test]
fn explicit_mount_start_requires_initial_transport_and_exact_retained_proof() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let path = std::env::temp_dir().join(format!("ms-{}-{}", std::process::id(), now.as_nanos()));
    DirBuilder::new().mode(0o700).create(&path).unwrap();
    let fixture = Fixture(path);
    let runtime = fixture.0.join("rt");
    DirBuilder::new().mode(0o700).create(&runtime).unwrap();
    let root = StorageRoot::open_container(&fixture.0).unwrap();
    let accounts = Accounts::with_storage(RuntimeDir::open(&runtime).unwrap(), root.clone());

    let (base, listener) = loopback("https");
    drop(listener);
    let instance = base.as_str();
    let mut session = ReadSession {
        root: root.clone(),
        base: base.clone(),
        account: AccountData {
            instance: instance.into(),
            issuer: instance.into(),
            client_id: "client".into(),
            token_endpoint: base.join("/token").unwrap().into(),
            subject: "owner".into(),
            ca_pem: None,
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            expires_at: now.as_secs() + 600,
            refresh_in_progress: false,
        },
        client: http::client(None).unwrap(),
    };
    let failure = |session: &mut ReadSession, space| {
        accounts
            .mount_start(session, space, no_refresh)
            .err()
            .expect("startup must refuse")
    };
    offline::bind_identity_in(&root, instance, instance, "owner").unwrap();
    assert!(
        failure(&mut session, SPACE)
            .to_string()
            .contains("no verified local activation")
    );
    let conn = offline::database_in(&root).unwrap();
    conn.execute(
        "INSERT INTO sync_spaces(instance,space,issuer,subject,phase,failures,next_at,cause,last_verified,verified_through,attention_stamp) VALUES (?1,?2,?1,'owner','Backoff',4,123,'transport',99,17,'stamp')",
        params![instance, SPACE],
    ).unwrap();
    assert!(
        failure(&mut session, SPACE)
            .to_string()
            .contains("metadata is unavailable")
    );

    let mut snapshot = DirectorySnapshot::empty_in(&root).unwrap();
    snapshot.set_remote_parent("root-id", "\"v1\"").unwrap();
    assert!(
        offline::save_directory_snapshot(
            offline::begin_snapshot_in(&root).unwrap(),
            instance,
            SPACE,
            &[],
            &snapshot,
        )
        .unwrap()
    );
    let activation = || {
        conn.query_row(
            "SELECT json_array(instance,space,issuer,subject,phase,failures,next_at,cause,last_verified,verified_through,attention_stamp) FROM sync_spaces",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap()
    };
    let before = activation();
    let fresh = now.as_secs() + 600;
    *accounts.read_session.lock().unwrap() = Some(Arc::new(session.clone()));
    assert_eq!(
        accounts
            .bind_space(instance, SPACE)
            .err()
            .unwrap()
            .to_string(),
        "Space request failed"
    );
    for expiry in [fresh, now.as_secs() + 10, 0] {
        session.account.expires_at = expiry;
        let (binding, startup) = accounts
            .mount_start(&mut session, SPACE, no_refresh)
            .unwrap();
        assert!(matches!(startup, MountStartup::Resumed));
        assert!(!binding.is_offline() && !binding.is_offline_writable());
        assert_eq!(bound_space(&session, &binding).unwrap(), SPACE);
        assert_eq!(binding.unique_name(), None);
        assert_eq!(activation(), before);
    }
    assert!(
        failure(&mut session, "another-space")
            .to_string()
            .contains("no verified local activation")
    );
    session.account.refresh_in_progress = true;
    assert!(
        failure(&mut session, SPACE)
            .to_string()
            .contains("interrupted")
    );
    session.account.refresh_in_progress = false;
    let refresh = std::mem::take(&mut session.account.refresh_token);
    assert!(
        failure(&mut session, SPACE)
            .to_string()
            .contains("incomplete")
    );
    session.account.refresh_token = refresh;
    session.account.subject = "other".into();
    assert!(
        failure(&mut session, SPACE)
            .to_string()
            .contains("identity changed")
    );
    session.account.subject = "owner".into();
    conn.execute("UPDATE snapshots SET subject='other'", [])
        .unwrap();
    assert!(
        failure(&mut session, SPACE)
            .to_string()
            .contains("metadata is unavailable")
    );
    conn.execute("UPDATE snapshots SET subject='owner'", [])
        .unwrap();

    let later_page = http::space_page(
        &session.client,
        &base.join("/graph/v1.0/me/drives").unwrap(),
        "access",
        1,
        &accounts.cancelled,
    );
    assert!(matches!(later_page, Err(GraphListingError::Other(_))));

    // HTTP or protocol responses never trigger resume, even when the next
    // request would reach an unavailable port. The test client permits plain
    // loopback HTTP so these fixtures do not need a certificate or keyring.
    for (status, body, length, expiry, renew, expected) in [
        (403, "", 0, fresh, false, "denied access"),
        (401, "", 0, fresh, true, "Space request failed"),
        (503, "", 0, fresh, false, "Space request failed"),
        (200, "{}", 100, fresh, false, "cannot read"),
        (200, "{}", 2, fresh, false, "invalid Space listing"),
        (200, r#"{"value":[]}"#, 12, fresh, false, "not in"),
        (200, LISTED, LISTED.len(), 0, true, "Space request failed"),
    ] {
        let (http_base, listener) = loopback("http");
        offline::bind_identity_in(&root, http_base.as_str(), instance, "owner").unwrap();
        let server = reply_once(listener, response(status, body, length));
        session.base = http_base;
        session.account.expires_at = expiry;
        session.client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let mut renewed = false;
        let error = accounts
            .mount_start(&mut session, SPACE, |session| {
                assert_eq!(session.account.expires_at, 0);
                renewed = true;
                Ok(())
            })
            .err()
            .expect("HTTP failure must refuse startup");
        server.join().unwrap();
        assert_eq!(renewed, renew, "{status}: {error}");
        assert!(error.to_string().contains(expected), "{status}: {error}");
    }

    // A listening socket speaks invalid TLS rather than being unreachable.
    let (tls_base, listener) = loopback("https");
    let server = reply_invalid_tls_once(listener);
    session.base = tls_base;
    session.client = http::client(None).unwrap();
    let error = failure(&mut session, SPACE);
    server.join().unwrap();
    assert_eq!(error.to_string(), "Space request failed");
    assert_eq!(activation(), before);
}

#[test]
fn denied_parent_blocks_speculative_cache_hit_but_not_foreground_verification() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let path = std::env::temp_dir().join(format!("ra-{}-{}", std::process::id(), now.as_nanos()));
    DirBuilder::new().mode(0o700).create(&path).unwrap();
    let fixture = Fixture(path);
    let runtime = fixture.0.join("rt");
    DirBuilder::new().mode(0o700).create(&runtime).unwrap();
    let root = StorageRoot::open_container(&fixture.0).unwrap();
    let accounts = Accounts::with_storage(RuntimeDir::open(&runtime).unwrap(), root.clone());

    let (base, listener) = loopback("https");
    let instance = base.to_string();
    let session = Arc::new(ReadSession {
        root: root.clone(),
        base: base.clone(),
        account: AccountData {
            instance: instance.clone(),
            issuer: instance.clone(),
            client_id: "client".into(),
            token_endpoint: base.join("/token").unwrap().into(),
            subject: "owner".into(),
            ca_pem: None,
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            expires_at: now.as_secs() + 600,
            refresh_in_progress: false,
        },
        client: http::client(None).unwrap(),
    });
    offline::bind_identity_in(&root, &instance, &instance, "owner").unwrap();
    let binding = explicit_space_binding(&session, SPACE, None);
    let parent = ["parent".to_owned()];
    let parent_id = "parent-id";
    let version = FileVersion {
        instance,
        space: SPACE.into(),
        path: vec![parent[0].clone(), "file".into()],
        id: "file-id".into(),
        etag: "\"v1\"".into(),
        size: 5,
        checksums: Vec::new(),
    };
    cache::store(
        &session,
        &version,
        0,
        b"cache",
        cache::generation_in(&root).unwrap(),
    )
    .unwrap();
    assert_eq!(
        cache::read(&session, &version, 0, 5).unwrap().as_deref(),
        Some(&b"cache"[..])
    );
    *accounts.read_session.lock().unwrap() = Some(session);

    let generation = accounts.metadata_generation();
    binding.record_directory_denial(&parent, parent_id);
    assert!(
        accounts
            .read_range_ahead(&binding, &version, 0, 5, parent_id)
            .is_err_and(|error| error.is_directory_forbidden())
    );
    assert_eq!(accounts.metadata_generation(), generation);
    listener.set_nonblocking(true).unwrap();
    assert!(
        listener
            .accept()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
    );

    listener.set_nonblocking(false).unwrap();
    let server = reply_invalid_tls_once(listener);
    assert_eq!(
        accounts
            .read_range(&binding, &version, 0, 5)
            .unwrap_err()
            .message,
        "directory request failed"
    );
    server.join().unwrap();
}

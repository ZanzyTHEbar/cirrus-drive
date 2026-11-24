use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use crate::{SignIn, callback::Listener};

#[test]
fn cancel_waiting_sign_in_after_rejected_loopback_callback() {
    let listener = Listener::bind().unwrap();
    let address = listener
        .redirect_uri()
        .strip_prefix("http://")
        .unwrap()
        .to_owned();
    let attempt = Arc::new(SignIn::default());
    let waiting_attempt = Arc::clone(&attempt);
    let waiting = thread::spawn(move || {
        listener.wait(
            "expected-state",
            "https://issuer.example/",
            false,
            &AtomicBool::new(false),
            &waiting_attempt,
        )
    });
    let mut callback = TcpStream::connect(&address).unwrap();
    callback
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        callback,
        "GET /?state=wrong-state&code=unused HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    callback.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));

    attempt.cancel().unwrap();
    attempt.cancel().unwrap();
    assert_eq!(
        waiting.join().unwrap().unwrap_err().to_string(),
        "sign-in cancelled; you can try again"
    );
}

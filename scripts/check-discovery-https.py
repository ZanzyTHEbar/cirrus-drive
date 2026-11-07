#!/usr/bin/env python3
"""Exercise the real discovery CLI against a disposable loopback TLS server."""

import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


binary = Path("target/debug/cirrus-daemon").resolve()
if not binary.is_file():
    raise SystemExit("build the daemon first: cargo build --workspace --locked")


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


with tempfile.TemporaryDirectory(prefix="cirrus-discovery-") as directory:
    root = Path(directory)
    ca, ca_key = root / "ca.pem", root / "ca.key"
    cert, key, csr, extensions = root / "server.pem", root / "server.key", root / "server.csr", root / "extensions"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca), "-subj", "/CN=cirrus-lab-ca", "-days", "1")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost")
    extensions.write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "1", "-extfile", str(extensions))

    state = {"mode": "valid", "redirect_followed": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            origin = f"https://localhost:{self.server.server_port}"
            target = urlsplit(self.path)
            if target.path == "/redirect-target":
                state["redirect_followed"] = True
                self.send_error(500)
                return
            if target.path == "/.well-known/webfinger":
                query = parse_qs(target.query)
                if query.get("platform") != ["desktop"] or query.get("rel") != ["http://openid.net/specs/connect/1.0/issuer"]:
                    self.send_error(400)
                    return
                if state["mode"] == "redirect":
                    self.send_response(302)
                    self.send_header("Location", origin + "/redirect-target")
                    self.end_headers()
                    return
                data = {"subject": query["resource"][0], "links": [{"rel": "http://openid.net/specs/connect/1.0/issuer", "href": origin + "/issuer"}], "properties": {"http://opencloud.eu/ns/oidc/client_id": "desktop", "http://opencloud.eu/ns/oidc/scopes": ["openid", "profile"]}}
                media = "application/jrd+json"
            elif target.path == "/issuer/.well-known/openid-configuration":
                issuer = origin + ("/wrong" if state["mode"] == "mismatch" else "/issuer")
                data = {"issuer": issuer, "authorization_endpoint": origin + "/authorize", "token_endpoint": origin + "/token", "jwks_uri": origin + "/jwks"}
                if state["mode"] == "foreign":
                    data["token_endpoint"] = "https://other.invalid/token"
                media = "application/json"
            else:
                self.send_error(404)
                return
            body = json.dumps(data).encode()
            if state["mode"] == "oversize":
                body += b" " * 70000
            self.send_response(200)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://localhost:{server.server_port}"

    def discover(*args):
        return subprocess.run([str(binary), "--discover", url, *args], capture_output=True, text=True, timeout=20)

    try:
        untrusted = discover()
        assert untrusted.returncode != 0, "untrusted TLS certificate was accepted"
        valid = discover("--ca-cert", str(ca))
        assert valid.returncode == 0 and "client ID: desktop" in valid.stdout, valid.stderr
        for mode in ("redirect", "mismatch", "foreign", "oversize"):
            state["mode"] = mode
            result = discover("--ca-cert", str(ca))
            assert result.returncode != 0, f"{mode} response was accepted"
        assert not state["redirect_followed"], "client followed a redirect"
        print("discovery HTTPS acceptance: trusted success; untrusted TLS, redirect, issuer mismatch, foreign endpoint and oversized response rejected")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

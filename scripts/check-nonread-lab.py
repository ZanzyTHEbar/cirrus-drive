#!/usr/bin/env python3
"""Exercise credential recovery and experimental file reads in a disposable local lab.

Requires a built daemon, dbus-run-session, GNOME Keyring, secret-tool, gdbus,
OpenSSL and FUSE. No real accounts or remote writes.
"""

import json
import errno
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
if not TARGET.is_absolute():
    TARGET = ROOT / TARGET
BINARY = TARGET / "debug/cirrus-daemon"
UI = BINARY.with_name("cirrus-ui")
PASSWORD = "cirrus-disposable-keyring"


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)


def require(result, context):
    if result.returncode:
        raise RuntimeError(f"{context}: {result.stderr.strip()}")
    return result


def keyring_start():
    process = subprocess.Popen(
        ["gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
         "--control-directory=" + os.environ["GNOME_KEYRING_CONTROL"]],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    process.stdin.write((PASSWORD + "\n").encode())
    process.stdin.close()
    for _ in range(150):
        result = run(["gdbus", "call", "--session", "--dest", "org.freedesktop.DBus",
                      "--object-path", "/org/freedesktop/DBus", "--method",
                      "org.freedesktop.DBus.GetConnectionUnixProcessID", "org.freedesktop.secrets"])
        owner = re.search(r"uint32 (\d+)", result.stdout)
        if result.returncode == 0 and owner and int(owner.group(1)) == process.pid:
            return process
        if process.poll() is not None:
            raise RuntimeError("disposable keyring exited before acquiring its bus name")
        time.sleep(0.02)
    process.terminate()
    process.wait(timeout=5)
    raise RuntimeError("disposable keyring did not start")


def stop_process(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    if process:
        process.wait(timeout=5)


def openssl(*args):
    require(run(["openssl", *map(str, args)]), "creating disposable TLS certificate")


def child(root):
    global BINARY, UI
    BINARY = root / "cirrus-daemon"
    UI = root / "cirrus-ui"
    keyring = None
    server = None
    thread = None
    daemons = {}
    session_buses = {}
    mountpoint = Path(os.environ["CIRRUS_LAB_MOUNT"])
    runtime_root = Path(os.environ["CIRRUS_LAB_RUNTIME"])
    state = {"lock_on_refresh": True, "dir_name": "folder", "dir_id": "folder-1",
             "file_present": True, "refreshes": 0, "bulk": None, "dav_error": False,
             "crash_refresh": False, "content": b"abcdefg" * 30000,
             "etag": '"version-1"', "etag_present": True, "range_fault": None,
             "range_requests": 0, "range_log": [], "propfind_requests": 0, "mutate_during_get": False,
             "checksum_override": None, "block_range": None, "fail_range_once": None, "space_visible": True, "space_status": 200,
             "space_throttled": 0, "space_retry_after": "1", "space_requests": 0, "space_partial": False,
             "access_token": "lab-access-rotated", "reject_old_access": False, "reject_second_access": False,
             "reject_propfind_token": None, "reject_range_token": None, "reject_range_barrier": None,
             "allow_second_refresh": False, "second_space": False, "other_dav_requests": 0,
             "other_space_name": "Other"}
    refresh_entered = threading.Event()
    refresh_continue = threading.Event()
    range_entered = threading.Event()
    range_continue = threading.Event()

    def cli(runtime, *args):
        env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime_root / runtime),
                   DBUS_SESSION_BUS_ADDRESS=session_buses.get(runtime, session_buses["two"])[1])
        return run([str(BINARY), *map(str, args)], env=env)

    def start_daemon(runtime, fault=None, bus_dir=None):
        env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime_root / runtime),
                   DBUS_SESSION_BUS_ADDRESS=session_buses.get(runtime, session_buses["two"])[1])
        if fault:
            env["CIRRUS_TEST_MOUNT_STOP"] = fault
        if bus_dir:
            env["CIRRUS_TEST_USER_BUS_DIR"] = str(bus_dir)
        with (root / (runtime + "-daemon.log")).open("w") as log:
            process = subprocess.Popen([str(BINARY)], env=env, stdout=subprocess.DEVNULL, stderr=log)
        daemons[runtime] = process
        for _ in range(150):
            if cli(runtime, "--status").returncode == 0:
                return process
            if process.poll() is not None:
                raise RuntimeError("disposable daemon exited during startup")
            time.sleep(0.02)
        raise RuntimeError("disposable daemon did not become ready")

    def lock_collection():
        prefix = ["gdbus", "call", "--session", "--dest", "org.freedesktop.secrets",
                  "--object-path", "/org/freedesktop/secrets", "--method"]
        alias = require(run(prefix + ["org.freedesktop.Secret.Service.ReadAlias", "default"]),
                        "finding disposable collection")
        path = alias.stdout.split("'")[1]
        require(run(prefix + ["org.freedesktop.Secret.Service.Lock",
                              "[objectpath '" + path + "']"]), "locking disposable collection")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send_body(self, status, media, data):
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            token = form.get("refresh_token")
            if self.path != "/token" or not (token == ["lab-refresh"] or
                                              (state["allow_second_refresh"] and token in (["lab-refresh-rotated"], ["lab-refresh-second"], ["lab-refresh-third"], ["lab-refresh-fourth"], ["lab-refresh-fifth"]))):
                self.send_error(400)
                return
            state["refreshes"] += 1
            if state["crash_refresh"]:
                refresh_entered.set()
                refresh_continue.wait(timeout=15)
            if state["lock_on_refresh"]:
                lock_collection()
                state["lock_on_refresh"] = False
            if token == ["lab-refresh-rotated"]:
                state["access_token"] = "lab-access-second"
            if token == ["lab-refresh-second"]:
                state["access_token"] = "lab-access-third"
            if token == ["lab-refresh-third"]:
                state["access_token"] = "lab-access-fourth"
            if token == ["lab-refresh-fourth"]:
                state["access_token"] = "lab-access-fifth"
            if token == ["lab-refresh-fifth"]:
                state["access_token"] = "lab-access-sixth"
            body = json.dumps({"access_token": state["access_token"],
                               "refresh_token": {"lab-refresh": "lab-refresh-rotated", "lab-refresh-rotated": "lab-refresh-second", "lab-refresh-second": "lab-refresh-third", "lab-refresh-third": "lab-refresh-fourth", "lab-refresh-fourth": "lab-refresh-fifth", "lab-refresh-fifth": "lab-refresh-sixth"}[token[0]],
                               "token_type": "Bearer", "expires_in": 3600}).encode()
            try:
                self.send_body(200, "application/json", body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

        def do_GET(self):
            if self.headers.get("Authorization") != "Bearer " + state["access_token"]:
                self.send_error(403)
                return
            if state["space_partial"] and self.path == "/graph/v1.0/me/drives?cursor=2":
                self.close_connection = True
                return
            if self.path == "/graph/v1.0/me/drives":
                state["space_requests"] += 1
                if ((state["reject_old_access"] and state["access_token"] == "lab-access-rotated") or
                        (state["reject_second_access"] and state["access_token"] == "lab-access-second")):
                    self.send_error(401)
                    return
                if state["space_throttled"]:
                    state["space_throttled"] -= 1
                    self.send_response(429)
                    self.send_header("Retry-After", state["space_retry_after"])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if state["space_status"] != 200:
                    self.send_error(state["space_status"])
                    return
                rows = [{"id": "space", "name": "Lab"}] if state["space_visible"] else []
                if state["second_space"]:
                    rows.append({"id": "other-space", "name": state["other_space_name"]})
                body = {"value": rows}
                if state["space_partial"]:
                    body["@odata.nextLink"] = "/graph/v1.0/me/drives?cursor=2"
                self.send_body(200, "application/json", json.dumps(body).encode())
                return
            if self.path == "/dav/spaces/other-space/other.txt":
                data = b"other Space content"
                match = re.fullmatch(r"bytes=(\d+)-(\d+)", self.headers.get("Range", ""))
                if not match or self.headers.get("If-Match") != state["etag"]:
                    self.send_error(412)
                    return
                start, end = map(int, match.groups())
                if start > end or end >= len(data):
                    self.send_error(416)
                    return
                self.send_response(206)
                self.send_header("ETag", state["etag"])
                self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
                self.send_header("Content-Length", str(end - start + 1))
                self.end_headers()
                self.wfile.write(data[start:end + 1])
                return
            if self.path != "/dav/spaces/space/item.txt":
                self.send_error(404)
                return
            if state["access_token"] == state["reject_range_token"]:
                if state["reject_range_barrier"]:
                    state["reject_range_barrier"].wait(timeout=10)
                self.send_error(401)
                return
            state["range_requests"] += 1
            etag, data = state["etag"], state["content"]
            if self.headers.get("If-Match") != etag or self.headers.get("If-Range") != etag:
                self.send_error(412)
                return
            match = re.fullmatch(r"bytes=(\d+)-(\d+)", self.headers.get("Range", ""))
            if not match:
                self.send_error(416)
                return
            start, end = map(int, match.groups())
            state["range_log"].append((start, end))
            if start > end or end >= len(data):
                self.send_error(416)
                return
            if state["block_range"] == (start, end):
                range_entered.set()
                range_continue.wait(timeout=15)
            if state["fail_range_once"] == (start, end):
                state["fail_range_once"] = None
                self.send_error(503)
                return
            fault = state["range_fault"]
            if fault in ("412", "416"):
                self.send_error(int(fault))
                return
            body = data[start:end + 1]
            self.send_response(200 if fault == "full" else 206)
            self.send_header("ETag", 'W/' + etag if fault == "weak" else etag)
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(data) + (fault == 'range')}")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if state["mutate_during_get"]:
                state["mutate_during_get"] = False
                state["content"] = b"during-read-change" * 14000
                state["etag"] = '"version-during-read"'
            self.wfile.write(body[:-1] if fault == "short" else body)
            self.close_connection = True

        def do_PROPFIND(self):
            state["propfind_requests"] += 1
            self.rfile.read(int(self.headers["Content-Length"]))
            if self.headers.get("Authorization") != "Bearer " + state["access_token"]:
                self.send_error(403)
                return
            if state["access_token"] == state["reject_propfind_token"]:
                self.send_error(401)
                return
            path = urlsplit(self.path).path
            if path.startswith("/dav/spaces/other-space/"):
                state["other_dav_requests"] += 1
            base = "/dav/spaces/space/"
            if state["dav_error"]:
                self.send_error(503)
                return
            if path == "/dav/spaces/other-space/":
                rows = [(path, True, "other-root"), (path + "other.txt", False, "other-file")]
            elif path == base:
                rows = [(base, True, "root")]
                if state["bulk"] is not None:
                    rows.extend((base + f"entry-{state['bulk']}-{i}", False,
                                 f"bulk-{state['bulk']}-{i}") for i in range(1000))
                else:
                    rows.append((base + state["dir_name"] + "/", True, state["dir_id"]))
                    if state["file_present"]:
                        rows.append((base + "item.txt", False, "file-1"))
            elif path == base + state["dir_name"] + "/":
                rows = [(path, True, state["dir_id"]), (path + "child.txt", False, "child-1")]
            else:
                self.send_error(404)
                return
            responses = []
            for href, directory, resource_id in rows:
                kind = "<d:collection/>" if directory else ""
                size = "" if directory else f"<d:getcontentlength>{len(state['content']) if resource_id == 'file-1' else len(b'other Space content') if resource_id == 'other-file' else 7}</d:getcontentlength>"
                etag = (f"<d:getetag>{escape(state['etag'])}</d:getetag>"
                        if not directory and state["etag_present"] else "")
                checksum = (state["checksum_override"] or
                            "SHA1:" + hashlib.sha1(state["content"]).hexdigest())
                checksums = (f"<oc:checksums><oc:checksum>{checksum}</oc:checksum></oc:checksums>"
                             if resource_id == "file-1" else "")
                missing = ('<d:propstat><d:prop><d:getcontentlength/></d:prop>'
                           '<d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>') if directory else ""
                responses.append(f'<d:response><d:href>{escape(href)}</d:href><d:propstat>'
                                 f'<d:prop><d:resourcetype>{kind}</d:resourcetype>{size}{etag}{checksums}'
                                 '<d:getlastmodified>Wed, 21 Oct 2015 07:28:00 GMT</d:getlastmodified>'
                                 f'<oc:fileid>{resource_id}</oc:fileid></d:prop>'
                                 f'<d:status>HTTP/1.1 200 OK</d:status></d:propstat>{missing}</d:response>')
            xml = ('<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" '
                   'xmlns:oc="http://owncloud.org/ns">' + ''.join(responses) + '</d:multistatus>')
            self.send_body(207, "application/xml", xml.encode())

    try:
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "ca.key",
                "-out", root / "ca.pem", "-subj", "/CN=cirrus-lab-ca", "-days", "1")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "tls.key",
                "-out", root / "tls.csr", "-subj", "/CN=localhost")
        (root / "ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
        openssl("x509", "-req", "-in", root / "tls.csr", "-CA", root / "ca.pem", "-CAkey", root / "ca.key",
                "-CAcreateserial", "-out", root / "tls.pem", "-days", "1", "-extfile", root / "ext")
        keyring = keyring_start()
        for name in ("one", "two"):
            address = "unix:path=" + str(runtime_root / name / "session-bus")
            bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--address=" + address,
                                    "--print-address=1"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True)
            actual = bus.stdout.readline().strip()
            if not actual:
                raise RuntimeError("disposable independent session bus did not start")
            session_buses[name] = (bus, actual)
        assert session_buses["one"][1] != session_buses["two"][1]
        assert all(address != os.environ["DBUS_SESSION_BUS_ADDRESS"] for _, address in session_buses.values())
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "tls.pem", root / "tls.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        url = f"https://localhost:{server.server_port}/"
        account = dict(instance=url, issuer=url + "issuer", client_id="lab", token_endpoint=url + "token",
                       subject="lab", ca_pem=(root / "ca.pem").read_text(), access_token="lab-access",
                       refresh_token="lab-refresh", expires_at=0, refresh_in_progress=False, selected_space="space")
        require(run(["secret-tool", "store", "--label=cirrus-lab", "application", "cirrus-drive",
                     "instance", url], input=json.dumps(account)), "saving disposable account")
        start_daemon("one")
        start_daemon("two")
        marker_dir = runtime_root / "home" / ".local" / "state" / "cirrus-drive"
        for directory in (marker_dir.parent.parent, marker_dir.parent, marker_dir):
            directory.mkdir(mode=0o700)
        marker = marker_dir / "account.lock"
        marker.write_text("unrelated marker")
        marker.chmod(0o600)
        rejected = cli("one", "--spaces", url)
        assert rejected.returncode and "unrecognized account coordination marker" in rejected.stderr, rejected.stderr
        assert marker.read_text() == "unrelated marker"
        marker.unlink()
        target = root / "marker-target"
        target.write_text("unchanged")
        marker.symlink_to(target)
        assert cli("one", "--spaces", url).returncode != 0
        assert target.read_text() == "unchanged"
        marker.unlink()
        first = cli("one", "--spaces", url)
        assert first.returncode and "awaiting keyring persistence" in first.stderr, first.stderr
        second = cli("two", "--spaces", url)
        assert second.returncode and "another account operation" in second.stderr, second.stderr
        cache_status = json.loads(require(cli("one", "--cache-status"), "checking cache with locked keyring").stdout)
        assert cache_status == {"bytes": 0, "ranges": 0, "byte_limit": 64 * 1024 * 1024, "range_limit": 1024}, cache_status
        stopped = cli("one", "--stop")
        assert stopped.returncode and "await keyring persistence" in stopped.stderr, stopped.stderr
        print("PASS: unknown markers preserved; independent-bus peer blocked during unsaved rotation", flush=True)

        # GNOME Keyring's PAM-style --unlock unlocks the login collection on startup;
        # invoking it against the already-running locked collection does not unlock it.
        stop_process(keyring)
        keyring = keyring_start()
        require(cli("one", "--spaces", url), "retrying after keyring restart and unlock")
        stored = require(run(["secret-tool", "lookup", "application", "cirrus-drive", "instance", url]),
                         "checking persisted disposable account")
        assert json.loads(stored.stdout)["refresh_token"] == "lab-refresh-rotated"
        require(cli("two", "--spaces", url), "checking account lock release")
        owner = require(run(["gdbus", "call", "--session", "--dest", "org.freedesktop.DBus",
                             "--object-path", "/org/freedesktop/DBus", "--method",
                             "org.freedesktop.DBus.NameHasOwner", "org.cirrusdrive.AccountOperation"]),
                        "checking user-bus account name")
        assert "false" in owner.stdout, owner.stdout
        locker = subprocess.Popen([sys.executable, "-c",
                                   "import fcntl,signal,sys; f=open(sys.argv[1],'r+'); "
                                   "fcntl.flock(f,fcntl.LOCK_EX); print('locked',flush=True); signal.pause()",
                                   str(marker)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            assert locker.stdout.readline().strip() == "locked"
            blocked = cli("two", "--spaces", url)
            assert blocked.returncode and "another account operation" in blocked.stderr, blocked.stderr
            locker.kill()
            locker.wait(timeout=5)
            require(cli("two", "--spaces", url), "checking orphaned filesystem lock release")
        finally:
            stop_process(locker)
        start_daemon("three", bus_dir=runtime_root / "missing-bus")
        denied = cli("three", "--spaces", url)
        assert denied.returncode and "standard per-user bus is unavailable" in denied.stderr, denied.stderr
        require(cli("three", "--stop"), "stopping daemon with unavailable canonical bus")
        daemons["three"].wait(timeout=5)
        print("PASS: filesystem-only lock blocks, dead locker releases, missing user bus fails closed", flush=True)
        require(cli("one", "--stop"), "stopping first daemon")
        daemons["one"].wait(timeout=5)
        start_daemon("one")
        require(cli("one", "--spaces", url), "authenticating after daemon restart")
        assert state["refreshes"] == 1
        print("PASS: unlocked retry persisted rotation; lock released; daemon restart authenticated", flush=True)

        saved_account = json.loads(stored.stdout)
        expired_account = dict(saved_account, access_token="lab-access", refresh_token="lab-refresh", expires_at=0)
        require(run(["secret-tool", "store", "--label=cirrus-lab", "application", "cirrus-drive",
                     "instance", url], input=json.dumps(expired_account)), "preparing crash fixture")
        state["crash_refresh"] = True
        refresh_client = subprocess.Popen([str(BINARY), "--spaces", url],
                                         env=dict(os.environ, XDG_RUNTIME_DIR=str(runtime_root / "one"),
                                                  DBUS_SESSION_BUS_ADDRESS=session_buses["one"][1]),
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            assert refresh_entered.wait(timeout=10), "refresh did not reach disposable server"
            daemons["one"].kill()
            daemons["one"].wait(timeout=5)
            refresh_client.wait(timeout=10)
            refresh_continue.set()
            start_daemon("one")
            for runtime in ("one", "two"):
                blocked = cli(runtime, "--spaces", url)
                assert blocked.returncode and "previous token refresh was interrupted" in blocked.stderr, blocked.stderr
            assert state["refreshes"] == 2, "interrupted token was retried"
        finally:
            refresh_continue.set()
            stop_process(refresh_client)
        # Restore the disposable fixture as a fresh login would, without a browser.
        require(run(["secret-tool", "store", "--label=cirrus-lab", "application", "cirrus-drive",
                     "instance", url], input=json.dumps(saved_account)), "restoring disposable account")
        state["crash_refresh"] = False
        require(cli("one", "--spaces", url), "using restored disposable account")
        rejected = cli("one", "--ls", url)
        assert rejected.returncode and "reselect your Space" in rejected.stderr
        require(cli("one", "--select-space", url, "space"), "reselecting user-scoped Space")
        print("PASS: independent buses and runtimes share ownership; dead-owner fence blocked stale token", flush=True)

        listing = require(cli("one", "--ls", url), "browsing disposable DAV metadata")
        assert "folder" in listing.stdout and "item.txt" in listing.stdout
        state["space_visible"] = False
        assert cli("one", "--ls", url).returncode == 0, "fixture must still allow DAV"
        rejected = cli("one", "--mount", url, mountpoint)
        assert rejected.returncode and "no longer in the signed-in user's listing" in rejected.stderr
        assert not mountpoint.is_mount()
        state["space_visible"] = True
        state["space_status"] = 403
        rejected = cli("one", "--mount", url, mountpoint)
        assert rejected.returncode and "denied access to Spaces" in rejected.stderr
        assert not mountpoint.is_mount()
        state["space_status"] = 200
        state["space_partial"] = True
        rejected = cli("one", "--mount", url, mountpoint)
        assert rejected.returncode and "listing was interrupted" in rejected.stderr
        assert not mountpoint.is_mount()
        state["space_partial"] = False
        state["space_throttled"] = 1
        requests_before = state["space_requests"]
        started = time.monotonic()
        require(cli("one", "--spaces", url), "retrying a rate-limited Space listing")
        assert state["space_requests"] == requests_before + 2
        assert time.monotonic() - started >= 0.9, "retried before Retry-After"
        state["space_retry_after"] = "3"
        state["space_throttled"] = 2
        requests_before = state["space_requests"]
        rejected = cli("one", "--spaces", url)
        assert rejected.returncode and "rate limiting" in rejected.stderr
        assert state["space_requests"] == requests_before + 1, "retried before long Retry-After"
        state["space_throttled"] = 0
        unsafe = root / "nonempty"
        unsafe.mkdir(mode=0o700)
        (unsafe / "keep").write_text("unrelated")
        assert cli("one", "--mount", url, unsafe).returncode != 0
        assert (unsafe / "keep").read_text() == "unrelated"
        assert cli("one", "--mount", url).returncode != 0
        assert not (root / "cirrus").exists(), "CLI created an implicit mountpoint"
        require(cli("one", "--mount", url, mountpoint), "mounting disposable metadata fixture")
        assert "mounted:" in require(cli("one", "--mount-status"), "mount status").stdout
        assert set(os.listdir(mountpoint)) == {"folder", "item.txt"}
        # A separate daemon can change shared account selection. The existing
        # mount must keep routing both reads and mutations to its original Space.
        state["second_space"] = True
        require(cli("two", "--select-space", url, "other-space"), "selecting another disposable Space")
        require(cli("one", "--spaces", url), "refreshing mounted daemon account state")
        assert (mountpoint / "item.txt").read_bytes() == state["content"]
        os.mkdir(mountpoint / "still-original")
        assert (mountpoint / "still-original").is_dir()
        with open(mountpoint / "still-original" / "edit.txt", "wb", buffering=0) as output:
            output.write(b"retained in the original Space")
            os.fsync(output.fileno())
        assert (mountpoint / "still-original" / "edit.txt").read_bytes() == b"retained in the original Space"
        os.unlink(mountpoint / "still-original" / "edit.txt")
        os.rmdir(mountpoint / "still-original")
        assert state["other_dav_requests"] == 0, "mount contacted the newly selected Space"
        stored = require(run(["secret-tool", "lookup", "application", "cirrus-drive", "instance", url]),
                         "reading disposable account for identity-change check")
        saved = json.loads(stored.stdout)
        identity_file = mountpoint / "identity-fence"
        identity_fd = os.open(identity_file, os.O_CREAT | os.O_RDWR, 0o600)
        os.write(identity_fd, b"original")
        os.fsync(identity_fd)
        database = marker_dir / "state.db"
        with sqlite3.connect(database) as db:
            db.execute("DELETE FROM account_identities WHERE instance=?", (url,))
        try:
            rejected = cli("one", "--sync", url)
            assert rejected.returncode and "offline account identity is missing" in rejected.stderr, rejected.stderr
            require(cli("two", "--spaces", url), "refreshing the account with missing offline identity")
            rejected = cli("two", "--ls", url)
            assert rejected.returncode and "offline account identity is missing" in rejected.stderr, rejected.stderr
        finally:
            with sqlite3.connect(database) as db:
                db.execute("INSERT INTO account_identities(instance,issuer,subject) VALUES (?,?,?)",
                           (url, saved["issuer"], saved["subject"]))
        changed = dict(saved, subject="different-disposable-user")
        require(run(["secret-tool", "store", "--label=cirrus-lab", "application", "cirrus-drive",
                     "instance", url], input=json.dumps(changed)), "changing disposable account identity")
        try:
            os.pwrite(identity_fd, b"wrong user", 0)
            raise AssertionError("an open mount wrote using a stale account identity")
        except OSError as error:
            assert error.errno == errno.EIO, error
        rejected = cli("one", "--sync", url)
        assert rejected.returncode and "offline state belongs to another account" in rejected.stderr, rejected.stderr
        require(cli("two", "--spaces", url), "refreshing replacement account in second daemon")
        rejected = cli("two", "--ls", url)
        assert rejected.returncode and "offline state belongs to another account" in rejected.stderr, rejected.stderr
        require(run(["secret-tool", "store", "--label=cirrus-lab", "application", "cirrus-drive",
                     "instance", url], input=json.dumps(saved)), "restoring disposable account identity")
        assert os.pread(identity_fd, 8, 0) == b"original"
        os.close(identity_fd)
        os.unlink(identity_file)
        require(run(["secret-tool", "store", "--label=cirrus-lab", "application", "cirrus-drive",
                     "instance", url], input=json.dumps(changed)), "changing disposable account identity")
        require(cli("one", "--spaces", url), "refreshing changed account identity")
        try:
            os.listdir(mountpoint)
            raise AssertionError("mount accepted a different account identity")
        except OSError as error:
            assert error.errno == errno.EIO, error
        assert "mounted account identity changed" in (root / "one-daemon.log").read_text()
        require(run(["secret-tool", "store", "--label=cirrus-lab", "application", "cirrus-drive",
                     "instance", url], input=json.dumps(saved)), "restoring disposable account identity")
        require(cli("one", "--spaces", url), "refreshing restored account identity")
        require(cli("two", "--select-space", url, "space"), "restoring disposable Space selection")
        require(cli("one", "--spaces", url), "refreshing restored account state")
        assert set(os.listdir(mountpoint)) == {"folder", "item.txt"}
        second_mountpoint = root / "second-mount"
        second_mountpoint.mkdir(mode=0o700)
        denied = cli("one", "--mount-space", url, "missing-space", second_mountpoint)
        assert denied.returncode and "not in the authenticated listing" in denied.stderr
        assert not second_mountpoint.is_mount()
        require(cli("one", "--mount-space", url, "other-space", second_mountpoint), "mounting a second Space")
        mounted_rows = [json.loads(line) for line in require(cli("one", "--mounts"), "listing both mounts").stdout.splitlines()]
        assert {(row["space_id"], row["path"]) for row in mounted_rows} == {
            ("space", str(mountpoint)), ("other-space", str(second_mountpoint))}
        assert set(os.listdir(mountpoint)) == {"folder", "item.txt"}
        assert os.listdir(second_mountpoint) == ["other.txt"]
        assert (second_mountpoint / "other.txt").read_bytes() == b"other Space content"
        for directory, content in ((mountpoint, b"first Space"), (second_mountpoint, b"second Space")):
            with open(directory / "both.txt", "wb", buffering=0) as output:
                output.write(content)
                os.fsync(output.fileno())
        assert (mountpoint / "both.txt").read_bytes() == b"first Space"
        assert (second_mountpoint / "both.txt").read_bytes() == b"second Space"
        require(cli("one", "--pin-space", url, "other-space", "/other.txt"), "pinning the second Space")
        pins = require(cli("one", "--pins-space", url, "other-space"), "listing second Space pins").stdout
        assert "available offline\t/other.txt" in pins, pins
        assert "/other.txt" not in require(cli("one", "--pins", url), "checking selected Space pins").stdout
        require(cli("one", "--unpin-space", url, "other-space", "/other.txt"), "unpinning the second Space")
        source = root / "explicit-stage-source"
        source.write_bytes(b"explicit Space staging")
        require(cli("one", "--stage-file-space", url, "other-space", "/explicit-staged.txt", source), "staging into the second Space")
        assert (second_mountpoint / "explicit-staged.txt").read_bytes() == b"explicit Space staging"
        assert not (mountpoint / "explicit-staged.txt").exists()
        os.unlink(second_mountpoint / "explicit-staged.txt")
        with sqlite3.connect(marker_dir / "state.db") as db:
            rows = db.execute("SELECT space FROM operation_journal WHERE path=? AND op_type='write' AND state='pending'", ('["both.txt"]',)).fetchall()
        assert {row[0] for row in rows} == {"space", "other-space"}, rows
        os.unlink(mountpoint / "both.txt")
        os.unlink(second_mountpoint / "both.txt")
        assert cli("one", "--mount-space", url, "other-space", second_mountpoint).returncode != 0
        assert cli("one", "--unmount-space", url, "missing-space").returncode != 0
        assert mountpoint.is_mount() and second_mountpoint.is_mount()
        assert cli("one", "--unmount").returncode != 0, "ambiguous unmount succeeded"
        require(cli("one", "--unmount-space", url, "other-space"), "unmounting only the second Space")
        assert not second_mountpoint.is_mount() and mountpoint.is_mount()
        assert [json.loads(line)["space_id"] for line in require(cli("one", "--mounts"), "listing remaining mount").stdout.splitlines()] == ["space"]
        require(cli("one", "--mount-space", url, "other-space", second_mountpoint), "remounting second Space before crash")
        daemons["one"].kill()
        daemons["one"].wait(timeout=5)
        start_daemon("one")
        stale = [json.loads(line) for line in require(cli("one", "--mounts"), "listing crashed mounts").stdout.splitlines()]
        assert {(row["space_id"], row["path"], row["state"]) for row in stale} == {
            ("space", str(mountpoint), "RecoveryRequired"),
            ("other-space", str(second_mountpoint), "RecoveryRequired")}
        events = [{"t": 1.0, "key": "refresh"}]
        (root / "ui-stale-events.json").write_text(json.dumps(events))
        ui_env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime_root / "one"),
                      DBUS_SESSION_BUS_ADDRESS=session_buses["one"][1])
        require(run([str(UI), "--script", str(root / "ui-stale-events.json"),
                     "--tree", str(root / "ui-stale-tree.json"), "--size", "900x1600", "--at", "5"], env=ui_env),
                "showing stale mounts in Rune")
        ui_tree = (root / "ui-stale-tree.json").read_text()
        assert f"Recovery required at {mountpoint}" in ui_tree
        assert f"Recovery required at {second_mountpoint}" in ui_tree
        require(cli("one", "--recover-mount", mountpoint), "recovering first crashed Space")
        stale = [json.loads(line) for line in require(cli("one", "--mounts"), "listing remaining crashed mount").stdout.splitlines()]
        assert [(row["space_id"], row["state"]) for row in stale] == [("other-space", "RecoveryRequired")]
        assert any(line.split()[4] == str(second_mountpoint) for line in Path("/proc/self/mountinfo").read_text().splitlines()), "recovering first mount removed second"
        blocked = cli("one", "--mount-space", url, "space", mountpoint)
        assert blocked.returncode and "stale or ambiguous" in blocked.stderr, blocked.stderr
        require(cli("one", "--recover-mount", second_mountpoint), "recovering second crashed Space")
        require(cli("one", "--mount", url, mountpoint), "remounting after two-Space crash recovery")
        assert "folder" in require(cli("one", "--ls", url), "checking unchanged selection").stdout
        cache_events = [{"t": 1.0, "key": "nav-Offline"}, {"t": 2.0, "key": "cache-status"}]
        (root / "ui-cache-events.json").write_text(json.dumps(cache_events))
        require(run([str(UI), "--script", str(root / "ui-cache-events.json"),
                     "--tree", str(root / "ui-cache-tree.json"), "--size", "900x1600", "--at", "5"], env=ui_env),
                "checking clean cache usage in Rune")
        ui_cache_tree = (root / "ui-cache-tree.json").read_text()
        assert "Last checked:" in ui_cache_tree and "payload bytes" in ui_cache_tree, ui_cache_tree
        state["other_space_name"] = "Lab"
        duplicate = cli("one", "--mount-space", url, "other-space")
        assert duplicate.returncode and "duplicated" in duplicate.stderr, duplicate.stderr
        assert not (root / "Lab").exists()
        state["other_space_name"] = "../unsafe"
        unsafe_name = cli("one", "--mount-space", url, "other-space")
        assert unsafe_name.returncode and "unsafe Space name" in unsafe_name.stderr, unsafe_name.stderr
        state["other_space_name"] = "Other"
        default_mountpoint = root / "Other"
        require(cli("one", "--mount-space", url, "other-space"), "mounting at daemon-created default")
        assert default_mountpoint.is_mount()
        assert (default_mountpoint / "other.txt").read_bytes() == b"other Space content"
        require(cli("one", "--unmount-space", url, "other-space"), "unmounting default path")
        assert default_mountpoint.is_dir() and not default_mountpoint.is_mount()
        collision = cli("one", "--mount-space", url, "other-space")
        assert collision.returncode and "will not be reused" in collision.stderr, collision.stderr
        assert default_mountpoint.is_dir() and not default_mountpoint.is_mount()
        state["second_space"] = False
        print("PASS: daemon default mountpoint, unsafe names, duplicate names, collisions and Space-specific pins/staging", flush=True)
        print("PASS: independent simultaneous Space mounts, targeted unmount and account identity fence", flush=True)
        records = list((runtime_root / "one").glob("cirrus-drive.mount-*"))
        assert len(records) == 1, records
        other_mountpoint = root / "other-recovery-mount"
        other_mountpoint.mkdir(mode=0o700)
        other_record = json.loads(records[0].read_text())
        other_record["path"] = str(other_mountpoint)
        other_record["space_id"] = "other-space"
        other_record["space_name"] = "Other"
        other_nonce = "f" * 32 if other_record["source"] != "cirrus-drive-" + "f" * 32 else "0" * 32
        other_record["source"] = "cirrus-drive-" + other_nonce
        other_record_path = runtime_root / "one" / ("cirrus-drive.mount-" + other_nonce)
        other_record_path.write_text(json.dumps(other_record))
        other_record_path.chmod(0o600)
        daemons["one"].kill()
        daemons["one"].wait(timeout=5)
        start_daemon("one")
        stale = [json.loads(line) for line in require(cli("one", "--mounts"), "listing independent owner records").stdout.splitlines()]
        assert {row["space_id"] for row in stale} == {"space", "other-space"}
        assert all(row["state"] == "RecoveryRequired" for row in stale)
        original_record = records[0].read_text()
        altered_record = json.loads(original_record)
        altered_record["source"] = "cirrus-drive-" + ("1" * 32 if altered_record["source"] == "cirrus-drive-" + "0" * 32 else "0" * 32)
        records[0].write_text(json.dumps(altered_record))
        try:
            rejected = cli("one", "--recover-mount", mountpoint)
            assert rejected.returncode and "another mount" in rejected.stderr, rejected.stderr
            assert records[0].exists() and other_record_path.exists()
        finally:
            records[0].write_text(original_record)
        require(cli("one", "--recover-mount", mountpoint), "recovering the first of two owner records")
        assert other_record_path.exists(), "recovery removed another mount's owner record"
        assert not records[0].exists(), "recovered mount's owner record remains"
        events = [{"t": 1.0, "key": "refresh"},
                  {"t": 2.5, "key": f"recover-other-{url}-other-space"}]
        (root / "ui-recover-space-events.json").write_text(json.dumps(events))
        require(run([str(UI), "--script", str(root / "ui-recover-space-events.json"),
                     "--tree", str(root / "ui-recover-space-tree.json"), "--size", "900x1600", "--at", "6"], env=ui_env),
                "recovering a Space from Rune")
        assert not other_record_path.exists()
        require(cli("one", "--mount", url, mountpoint), "remounting after independent recovery")
        print("PASS: recovery removes only the matching mount owner record", flush=True)
        file_path = mountpoint / "item.txt"
        # Use a fresh representation so earlier mounts cannot satisfy the network-fault probes from disk.
        state["etag"] = '"range-lab-version-1"'
        fd = os.open(file_path, os.O_RDONLY)
        try:
            original = state["content"]
            assert os.read(fd, 13) == original[:13]
            ranges, properties = state["range_requests"], state["propfind_requests"]
            assert os.pread(fd, 13, 0) == original[:13]
            assert state["range_requests"] == ranges, "cache hit fetched the range again"
            assert state["propfind_requests"] > properties, "cache hit skipped version validation"
            state["block_range"] = (50000, 50015)
            concurrent = {}
            def delayed_read(offset, length):
                try:
                    concurrent[(offset, length)] = os.pread(fd, length, offset)
                except OSError as error:
                    concurrent[(offset, length)] = error
            before = state["range_requests"]
            workers = [threading.Thread(target=delayed_read, args=range_) for range_ in ((50000, 16), (50008, 16))]
            workers[0].start()
            try:
                assert range_entered.wait(timeout=10), "slow range did not start"
                workers[1].start()
                assert os.pread(fd, 17, 70000) == original[70000:70017]
                assert os.stat(mountpoint / "folder").st_mode
                time.sleep(0.2)
            finally:
                range_continue.set()
                for worker in workers:
                    if worker.ident is not None:
                        worker.join(timeout=20)
                state["block_range"] = None
            assert all(not worker.is_alive() for worker in workers), "concurrent read hung"
            assert concurrent == {(50000, 16): original[50000:50016], (50008, 16): original[50008:50024]}, concurrent
            assert state["range_requests"] == before + 3, "unexpected requests for partially overlapping reads"
            assert (50016, 50023) in state["range_log"] and (50008, 50023) not in state["range_log"], "overlap was downloaded twice"
            range_entered.clear()
            range_continue.clear()
            state["block_range"] = (132768, 198303)
            prefetched = {}
            def read_prefetched():
                try:
                    prefetched["bytes"] = os.pread(fd, 4096, 140000)
                except OSError as error:
                    prefetched["error"] = error
            worker = threading.Thread(target=read_prefetched)
            try:
                assert os.pread(fd, 16384, 100000) == original[100000:116384]
                assert os.pread(fd, 16384, 116384) == original[116384:132768]
                assert range_entered.wait(timeout=10), "read-ahead did not start"
                worker.start()
                time.sleep(0.2)
                assert (140000, 144095) not in state["range_log"], "foreground read duplicated in-flight read-ahead"
            finally:
                range_continue.set()
                if worker.ident is not None:
                    worker.join(timeout=20)
                state["block_range"] = None
            assert not worker.is_alive() and prefetched.get("bytes") == original[140000:144096], prefetched
            range_entered.clear()
            range_continue.clear()
            state["block_range"] = state["fail_range_once"] = (32768, 98303)
            prefetched.clear()
            def read_after_failed_prefetch():
                try:
                    prefetched["bytes"] = os.pread(fd, 4096, 40000)
                except OSError as error:
                    prefetched["error"] = error
            worker = threading.Thread(target=read_after_failed_prefetch)
            try:
                assert os.pread(fd, 16384, 0) == original[:16384]
                assert os.pread(fd, 16384, 16384) == original[16384:32768]
                assert range_entered.wait(timeout=10), "failing read-ahead did not start"
                worker.start()
                time.sleep(0.2)
                assert (40000, 44095) not in state["range_log"], "foreground did not join read-ahead"
            finally:
                range_continue.set()
                if worker.ident is not None:
                    worker.join(timeout=20)
                state["block_range"] = state["fail_range_once"] = None
            assert not worker.is_alive() and prefetched.get("bytes") == original[40000:44096], prefetched
            assert (40000, 44095) in state["range_log"], "foreground did not retry failed read-ahead"
            for offset in range(200, 265):
                assert os.pread(fd, 1, offset) == original[offset:offset + 1]
            ranges = state["range_requests"]
            assert os.pread(fd, 1, 200) == original[200:201]
            assert state["range_requests"] == ranges, "persistent cache did not retain the evicted memory range"
            assert os.pread(fd, 13, 0) == original[:13]
            os.lseek(fd, 0, os.SEEK_SET)
            first = os.read(fd, 150000)
            assert first == original[:len(first)] and len(first) == 128 * 1024
            assert os.read(fd, 19000) == original[len(first):len(first) + 19000]
            assert os.pread(fd, 500, 130000) == original[130000:130500]
            assert os.pread(fd, 100, len(original) - 10) == original[-10:]
            assert os.pread(fd, 1, len(original)) == b""
            state["content"] = b"new version!" * 19000
            state["etag"] = '"version-2"'
            try:
                os.pread(fd, 13, 0)
            except OSError as error:
                assert error.errno == errno.EIO, error
            else:
                raise AssertionError("cached range hid a changed representation")
            try:
                os.pread(fd, 10, 0)
            except OSError as error:
                assert error.errno == errno.EIO, error
            else:
                raise AssertionError("changed representation was read through old handle")
        finally:
            os.close(fd)
        with open(file_path, "rb", buffering=0) as opened:
            assert opened.read(20) == state["content"][:20]
        for fault in ("full", "range", "weak", "short", "412", "416"):
            fd = os.open(file_path, os.O_RDONLY)
            try:
                state["range_fault"] = fault
                try:
                    os.pread(fd, 8, 80000)
                except OSError as error:
                    assert error.errno == errno.EIO, (fault, error)
                else:
                    raise AssertionError(f"invalid range response accepted: {fault}")
                state["range_fault"] = None
                try:
                    os.pread(fd, 8, 80000)
                except OSError as error:
                    assert error.errno == errno.EIO, (fault, error)
                else:
                    raise AssertionError(f"failed handle became readable: {fault}")
            finally:
                state["range_fault"] = None
                os.close(fd)
        saved_content, saved_etag = state["content"], state["etag"]
        fd = os.open(file_path, os.O_RDONLY)
        try:
            state["mutate_during_get"] = True
            try:
                os.pread(fd, 17, 40000)
            except OSError as error:
                assert error.errno == errno.EIO, error
            else:
                raise AssertionError("read published bytes after in-flight metadata change")
            assert not state["mutate_during_get"], "fixture GET was not reached"
        finally:
            os.close(fd)
            state["mutate_during_get"] = False
            state["content"], state["etag"] = saved_content, saved_etag
        fd = os.open(file_path, os.O_RDONLY)
        try:
            assert os.pread(fd, 19, 80000) == saved_content[80000:80019]
            state["checksum_override"] = "SHA1:" + "0" * 40
            try:
                os.pread(fd, 19, 80000)
            except OSError as error:
                assert error.errno == errno.EIO, error
            else:
                raise AssertionError("changed checksum metadata was ignored on a cache hit")
        finally:
            os.close(fd)
            state["checksum_override"] = None
        state["etag"] = 'W/"version-2"'
        try:
            try:
                os.open(file_path, os.O_RDONLY)
            except OSError as error:
                assert error.errno == errno.EIO, error
            else:
                raise AssertionError("weak metadata ETag accepted")
        finally:
            state["etag"] = '"version-2"'
        state["etag_present"] = False
        try:
            try:
                os.open(file_path, os.O_RDONLY)
            except OSError as error:
                assert error.errno == errno.EIO, error
            else:
                raise AssertionError("missing metadata ETag accepted")
        finally:
            state["etag_present"] = True
        content = state["content"]
        state["content"] = b""
        state["etag"] = '"empty"'
        try:
            with open(file_path, "rb", buffering=0) as opened:
                assert opened.read(1) == b""
        finally:
            state["content"] = content
            state["etag"] = '"version-2"'
        try:
            os.rename(mountpoint / "folder", mountpoint / "unsupported-rename")
        except OSError as error:
            assert error.errno == errno.EOPNOTSUPP, error
        else:
            raise AssertionError("unsupported rename unexpectedly succeeded")
        print("PASS: range reads, overlapping read-ahead, speculative failure retry, seek, EOF, mutation, reopen and invalid responses", flush=True)
        old_fd = os.open(mountpoint / "folder", os.O_RDONLY | os.O_DIRECTORY)
        snapshot_fd = os.open(mountpoint, os.O_RDONLY | os.O_DIRECTORY)
        try:
            assert os.listdir(old_fd) == ["child.txt"]
            old_ino = os.stat(mountpoint / "folder").st_ino
            state["dir_name"] = "renamed"
            state["file_present"] = False
            assert set(os.listdir(mountpoint)) == {"renamed"}
            assert set(os.listdir(snapshot_fd)) == {"folder", "item.txt"}
            assert os.stat(mountpoint / "renamed").st_ino != old_ino
            try:
                os.stat("child.txt", dir_fd=old_fd)
            except OSError as error:
                assert error.errno in (errno.ENOENT, errno.ESTALE), error
            else:
                raise AssertionError("stale directory handle resolved a removed path")
            assert os.listdir(mountpoint / "renamed") == ["child.txt"]
            previous = os.stat(mountpoint / "renamed").st_ino
            state["dir_id"] = "folder-2"
            assert os.stat(mountpoint / "renamed").st_ino != previous
        finally:
            os.close(old_fd)
            os.close(snapshot_fd)
        for reserved in ("cirrus-dir:1", "cirrus-staged:1"):
            state["dir_id"] = reserved
            try:
                os.listdir(mountpoint)
            except OSError as error:
                assert error.errno == errno.EIO, error
            else:
                raise AssertionError(f"remote DAV ID used reserved local identity {reserved}")
        state["dir_id"] = "folder-2"
        assert os.listdir(mountpoint) == ["renamed"]
        state["dav_error"] = True
        try:
            os.listdir(mountpoint)
        except OSError:
            pass
        else:
            raise AssertionError("failed DAV scan returned a successful listing")
        state["dav_error"] = False
        for generation in range(18):
            state["bulk"] = generation
            assert len(os.listdir(mountpoint)) == 1000
        state["bulk"] = None
        assert os.listdir(mountpoint) == ["renamed"]
        require(cli("one", "--unmount"), "normal unmount")
        assert not list((runtime_root / "one").glob("cirrus-drive.mount-*"))
        require(cli("one", "--mount", url, mountpoint), "remounting disposable fixture")
        daemons["one"].send_signal(signal.SIGKILL)
        daemons["one"].wait(timeout=5)
        start_daemon("one")
        assert cli("one", "--recover-mount", unsafe).returncode != 0
        assert (unsafe / "keep").read_text() == "unrelated"
        records = list((runtime_root / "one").glob("cirrus-drive.mount-*"))
        assert len(records) == 1, records
        record_path = records[0]
        original_record = record_path.read_text()
        foreign_record = json.loads(original_record)
        foreign_record["source"] = "cirrus-drive-" + (
            "1" * 32 if foreign_record["source"] == "cirrus-drive-" + "0" * 32 else "0" * 32
        )
        record_path.write_text(json.dumps(foreign_record))
        try:
            rejected = cli("one", "--recover-mount", mountpoint)
            assert rejected.returncode and "another mount" in rejected.stderr, rejected.stderr
            assert record_path.exists()
        finally:
            record_path.write_text(original_record)
        require(cli("one", "--recover-mount", mountpoint), "recovering crashed mount")
        assert not list((runtime_root / "one").glob("cirrus-drive.mount-*"))
        require(cli("one", "--mount", url, mountpoint), "mounting after crash recovery")
        daemons["one"].kill()
        daemons["one"].wait(timeout=5)
        start_daemon("one")
        events = [{"t": 1.0, "type": "wheel", "x": 300, "y": 400, "dy": -5000},
                  {"t": 1.4, "key": "toggle-recover"},
                  {"t": 1.7, "type": "wheel", "x": 300, "y": 400, "dy": -5000},
                  {"t": 2.0, "key": "recover-path"},
                  {"t": 2.2, "paste": str(mountpoint)},
                  {"t": 2.5, "key": "recover"}]
        (root / "ui-events.json").write_text(json.dumps(events))
        env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime_root / "one"),
                   DBUS_SESSION_BUS_ADDRESS=session_buses["one"][1])
        require(run([str(UI), "--script", str(root / "ui-events.json"), "--tree", str(root / "ui-tree.json"),
                     "--size", "460x580", "--at", "5"], env=env), "Rune recovery flow")
        assert "Recorded stale mount recovered" in (root / "ui-tree.json").read_text()
        assert not list((runtime_root / "one").glob("cirrus-drive.mount-*"))
        require(cli("one", "--mount", url, mountpoint), "mounting after Rune recovery")
        require(cli("one", "--stop"), "normal stop with mount")
        daemons["one"].wait(timeout=5)
        if os.environ.get("CIRRUS_LAB_FAULT") == "1":
            for stage, resume in (("prepared", True), ("prepared", False), ("mounted", False)):
                start_daemon("one", fault=stage)
                mount_client = subprocess.Popen(
                    [str(BINARY), "--mount", url, str(mountpoint)],
                    env=dict(os.environ, XDG_RUNTIME_DIR=str(runtime_root / "one"),
                             DBUS_SESSION_BUS_ADDRESS=session_buses["one"][1]),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    for _ in range(500):
                        status = Path(f"/proc/{daemons['one'].pid}/status").read_text()
                        if "State:\tT" in status:
                            break
                        if mount_client.poll() is not None:
                            raise RuntimeError("fault-injection mount exited before stop point")
                        time.sleep(0.01)
                    else:
                        raise RuntimeError("fault-injection mount did not reach stop point")
                    records = list((runtime_root / "one").glob("cirrus-drive.mount-*"))
                    assert len(records) == 1, records
                    record = json.loads(records[0].read_text())
                    assert record["version"] == 3 and record["mount_id"] == 0
                    assert f"cirrus lab mount stop: {stage}" in (root / "one-daemon.log").read_text()
                    if resume:
                        (mountpoint / "keep").write_text("unchanged")
                        daemons["one"].send_signal(signal.SIGCONT)
                        output, errors = mount_client.communicate(timeout=10)
                        assert mount_client.returncode != 0, (
                            f"late content mount succeeded: {output} {errors}; "
                            f"daemon log: {(root / 'one-daemon.log').read_text()}"
                        )
                        assert (mountpoint / "keep").read_text() == "unchanged"
                        assert not list((runtime_root / "one").glob("cirrus-drive.mount-*"))
                        (mountpoint / "keep").unlink()
                        require(cli("one", "--stop"), "stopping after rejected mount")
                        daemons["one"].wait(timeout=5)
                        continue
                    daemons["one"].kill()
                    daemons["one"].wait(timeout=5)
                    mount_client.wait(timeout=10)
                    if stage == "prepared":
                        (mountpoint / "keep").write_text("unchanged")
                    start_daemon("one")
                    require(cli("one", "--recover-mount", mountpoint), "recovering pre-identity crash")
                    if stage == "prepared":
                        assert (mountpoint / "keep").read_text() == "unchanged"
                        (mountpoint / "keep").unlink()
                    require(cli("one", "--mount", url, mountpoint), "mounting after pre-identity recovery")
                    require(cli("one", "--stop"), "stopping after pre-identity recovery")
                    daemons["one"].wait(timeout=5)
                finally:
                    stop_process(mount_client)
            print("PASS: late content rejected; deterministic pre/post-mount crashes recovered", flush=True)
        state["reject_old_access"] = True
        state["allow_second_refresh"] = True
        refreshes_before = state["refreshes"]
        require(cli("two", "--spaces", url), "refreshing a rejected but unexpired account session")
        assert state["refreshes"] == refreshes_before + 1
        refreshed = require(run(["secret-tool", "lookup", "application", "cirrus-drive", "instance", url]),
                            "checking rejected-session token persistence")
        assert json.loads(refreshed.stdout)["refresh_token"] == "lab-refresh-second"
        require(cli("two", "--spaces", url), "reusing the refreshed account session")
        assert state["refreshes"] == refreshes_before + 1, "repeated token rotation after successful refresh"
        state["reject_second_access"] = True
        require(cli("two", "--sync", url), "refreshing a rejected account session before sync")
        assert state["refreshes"] == refreshes_before + 2
        refreshed = require(run(["secret-tool", "lookup", "application", "cirrus-drive", "instance", url]),
                            "checking sync token persistence")
        assert json.loads(refreshed.stdout)["refresh_token"] == "lab-refresh-third"
        state["file_present"] = True
        state["reject_propfind_token"] = "lab-access-third"
        listing = require(cli("two", "--ls", url), "refreshing rejected DAV directory credentials")
        assert "item.txt" in listing.stdout
        assert state["refreshes"] == refreshes_before + 3
        state["etag"] = '"refresh-range-test"'  # Force actual range requests rather than cached hits.
        require(cli("two", "--mount", url, mountpoint), "mounting for rejected range credentials")
        try:
            with open(mountpoint / "item.txt", "rb", buffering=0) as file:
                state["reject_range_token"] = "lab-access-fourth"
                assert file.read(17) == state["content"][:17]
            assert state["refreshes"] == refreshes_before + 4
            with open(mountpoint / "item.txt", "rb", buffering=0) as file:
                state["reject_range_token"] = "lab-access-fifth"
                state["reject_range_barrier"] = threading.Barrier(2)
                results = {}
                def read_rejected(offset):
                    try:
                        results[offset] = os.pread(file.fileno(), 16, offset)
                    except OSError as error:
                        results[offset] = error
                workers = [threading.Thread(target=read_rejected, args=(offset,)) for offset in (31000, 41000)]
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join(timeout=30)
                state["reject_range_barrier"] = None
                assert all(not worker.is_alive() for worker in workers), "rejected concurrent reads hung"
                assert results == {offset: state["content"][offset:offset + 16] for offset in (31000, 41000)}, results
                assert state["refreshes"] == refreshes_before + 5, "concurrent rejections rotated the token more than once"
        finally:
            require(cli("two", "--unmount"), "unmounting after rejected range credentials")
        refreshed = require(run(["secret-tool", "lookup", "application", "cirrus-drive", "instance", url]),
                            "checking DAV token persistence")
        assert json.loads(refreshed.stdout)["refresh_token"] == "lab-refresh-sixth"
        print("PASS: rejected selection, Retry-After, sync and concurrent DAV token refresh", flush=True)
        require(cli("two", "--stop"), "stopping second daemon")
        daemons["two"].wait(timeout=5)
        print("PASS: mount safety, metadata snapshots, churn, errors, unmount and CLI/Rune crash recovery", flush=True)
    finally:
        for daemon in daemons.values():
            stop_process(daemon)
        for bus, _ in session_buses.values():
            stop_process(bus)
        # Only the fixture's fresh, private directory can have been mounted by this lab.
        # Use the recorded mount identity and FUSE source before any emergency cleanup.
        for record_path in (runtime_root / "one").glob("cirrus-drive.mount-*"):
            record = json.loads(record_path.read_text())
            fields = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
            for parts in fields:
                identity = "-" in parts and parts[parts.index("-") + 2] == record.get("source")
                if (identity and parts[4] in (str(mountpoint), str(root / "second-mount"), str(root / "Other"))
                        and "-" in parts and parts[parts.index("-") + 1:parts.index("-") + 3]
                        == ["fuse.cirrus-drive", record.get("source")]):
                    require(run(["fusermount3", "-u", "-z", "--", parts[4]]), "cleaning lab mount")
        if server and thread:
            server.shutdown()
        if server:
            server.server_close()
        if thread:
            thread.join(timeout=5)
        stop_process(keyring)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        child(Path(sys.argv[2]))
        return
    if not BINARY.is_file() or not UI.is_file():
        raise SystemExit("build first: cargo build --workspace --locked")
    capability = run([str(BINARY), "--lab-capabilities"])
    if capability.returncode or capability.stdout.strip() != "cirrus-drive disposable account and mount lab v1":
        raise SystemExit("build the disposable lab binary first: cargo build --locked -p cirrus-daemon --features fault-injection")
    if sys.argv[1:] not in ([], ["--fault-injection"]):
        raise SystemExit("usage: check-nonread-lab.py [--fault-injection]")
    # The runtime requires O_TMPFILE, which is unavailable on some project filesystems.
    root = Path(tempfile.mkdtemp(prefix="cirrus-read-lab-"))
    os.chmod(root, 0o700)
    runtime_root = Path(tempfile.mkdtemp(prefix="cdr-fixture-", dir="/dev/shm"))
    mountpoint = root / "mount"
    for name in ("data", "config", "mount"):
        (root / name).mkdir(mode=0o700)
    for name in ("runtime", "control", "home", "one", "two", "three", "missing-bus"):
        (runtime_root / name).mkdir(mode=0o700)
    env = dict(os.environ, HOME=str(root), XDG_DATA_HOME=str(root / "data"),
               XDG_CONFIG_HOME=str(root / "config"), XDG_RUNTIME_DIR=str(runtime_root / "runtime"),
               GNOME_KEYRING_CONTROL=str(runtime_root / "control"),
               CIRRUS_LAB_MOUNT=str(mountpoint),
               CIRRUS_LAB_RUNTIME=str(runtime_root),
               CIRRUS_TEST_ACCOUNT_HOME=str(runtime_root / "home"),
               CIRRUS_TEST_USER_BUS_DIR=str(runtime_root / "runtime"))
    env.pop("DBUS_SESSION_BUS_ADDRESS", None)
    env.pop("DBUS_SESSION_BUS_PID", None)
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    if sys.argv[1:] == ["--fault-injection"]:
        env["CIRRUS_LAB_FAULT"] = "1"
    try:
        shutil.copy2(BINARY, root / "cirrus-daemon")
        shutil.copy2(UI, root / "cirrus-ui")
        copied = run([str(root / "cirrus-daemon"), "--lab-capabilities"])
        if copied.returncode or copied.stdout.strip() != "cirrus-drive disposable account and mount lab v1":
            raise RuntimeError("copied daemon lacks disposable lab isolation")
        config = root / "user-bus.conf"
        config.write_text('<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" '
                          '"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">'
                          '<busconfig><type>session</type><listen>unix:path=' + str(runtime_root / "runtime" / "bus") +
                          '</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/>'
                          '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>')
        result = subprocess.run(["dbus-run-session", "--config-file=" + str(config), "--", sys.executable,
                                 __file__, "--child", str(root)], env=env)
        if result.returncode:
            for log in sorted(root.glob("*-daemon.log")):
                lines = log.read_text(errors="replace").splitlines()
                if lines:
                    print(f"{log.name} (last 50 lines):\n" + "\n".join(lines[-50:]), file=sys.stderr)
            raise SystemExit(result.returncode)
    finally:
        # Do not recurse into a mount if cleanup could not prove ownership.
        mounts = Path("/proc/self/mountinfo").read_text().splitlines()
        if any(line.split()[4] in (str(mountpoint), str(root / "second-mount"), str(root / "Other")) for line in mounts):
            print(f"lab mount remains; inspect {root} and {runtime_root}", file=sys.stderr)
        else:
            shutil.rmtree(root)
            shutil.rmtree(runtime_root)


if __name__ == "__main__":
    main()

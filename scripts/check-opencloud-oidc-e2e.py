#!/usr/bin/env python3
"""Disposable OpenCloud OIDC, private keyring, daemon IPC and writable FUSE lab.

The loopback listener forwards raw TLS bytes to a network-disabled container; it
does not translate authentication. Requires Python dbus/gi/websockets and Chrome.
"""

import errno
import http.client
import json
import os
from pathlib import Path
import queue
import secrets
import signal
import shutil
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from importlib.machinery import SourceFileLoader
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

sys.dont_write_bytecode = True
lab = SourceFileLoader("opencloud_lab", str(Path(__file__).with_name("check-opencloud-read-lab.py"))).load_module()
fixture = lab.fixture
URL = "https://localhost:9200/"


class Tunnel(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, container):
        self.container = container
        self.lock = threading.Lock()
        self.online = True
        self.connections = set()
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(("127.0.0.1", 9200), TunnelHandler)

    def set_online(self, online):
        with self.lock:
            self.online = online
            if not online:
                for connection in tuple(self.connections):
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass


class TunnelHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if not self.server.slots.acquire(blocking=False):
            return
        with self.server.lock:
            if not self.server.online:
                self.server.slots.release()
                return
            self.server.connections.add(self.request)
        try:
            process = subprocess.Popen(["docker", "exec", "-i", self.server.container, "nc", "127.0.0.1", "9200"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        except OSError:
            with self.server.lock:
                self.server.connections.discard(self.request)
            self.server.slots.release()
            return

        def upstream():
            try:
                while data := self.request.recv(65536):
                    remaining = memoryview(data)
                    while remaining:
                        written = process.stdin.write(remaining)
                        if not written:
                            return
                        remaining = remaining[written:]
            except OSError:
                pass
            finally:
                process.stdin.close()

        worker = threading.Thread(target=upstream, daemon=True)
        worker.start()
        try:
            while data := process.stdout.read(65536):
                self.request.sendall(data)
        except OSError:
            pass
        finally:
            try:
                self.request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            worker.join(timeout=2)
            with self.server.lock:
                self.server.connections.discard(self.request)
            self.server.slots.release()


def child(root, runtime, container, password):
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
    from websockets.sync.client import connect

    fixture.BINARY = root / "cirrus-daemon"
    keyring = daemon = browser = tunnel = thread = loop = None
    mounted = False
    mountpoint = root / "mount"
    chosen_mount = None
    requests = queue.Queue(maxsize=1)

    class Portal(dbus.service.Object):
        @dbus.service.method("org.freedesktop.portal.OpenURI", in_signature="ssa{sv}", out_signature="o")
        def OpenURI(self, _parent, uri, _options):
            requests.put_nowait(str(uri))
            return dbus.ObjectPath("/org/freedesktop/portal/desktop/request/cirrus/lab")

    def cli(*args):
        return fixture.run([str(fixture.BINARY), *map(str, args)], env=os.environ)

    def retained_staged_rows():
        rows = []
        offset = 0
        while True:
            page = [json.loads(line) for line in fixture.require(cli("--retained-staged", URL, offset), "listing retained staged copies").stdout.splitlines()]
            if not page:
                return rows
            rows.extend(page)
            offset += len(page)

    def start_daemon():
        with (root / "daemon.log").open("a") as log:
            process = subprocess.Popen([str(fixture.BINARY)], env=os.environ, stdout=subprocess.DEVNULL, stderr=log)
        for _ in range(150):
            if cli("--status").returncode == 0:
                return process
            if process.poll() is not None:
                raise RuntimeError("lab daemon exited during startup")
            time.sleep(0.02)
        fixture.stop_process(process)
        raise RuntimeError("lab daemon did not start")

    try:
        tunnel = Tunnel(container)
        thread = threading.Thread(target=tunnel.serve_forever, daemon=True)
        thread.start()
        for _ in range(60):
            try:
                certificate = ssl.get_server_certificate(("127.0.0.1", 9200), timeout=2)
                break
            except (OSError, ssl.SSLError):
                time.sleep(1)
        else:
            raise RuntimeError("disposable OpenCloud HTTPS did not become ready")
        (root / "server.pem").write_text(certificate)
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(root / "server.pem"))))
        for _ in range(60):
            try:
                with opener.open(URL + ".well-known/openid-configuration", timeout=3) as response:
                    metadata = json.load(response)
                if metadata.get("issuer", "").rstrip("/") == URL.rstrip("/"):
                    break
            except (OSError, ValueError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError("disposable OpenCloud OIDC metadata did not become ready with TLS verification")
        keyring = fixture.keyring_start()
        DBusGMainLoop(set_as_default=True)
        bus = dbus.SessionBus()
        name = dbus.service.BusName("org.freedesktop.portal.Desktop", bus=bus, do_not_queue=True)
        portal = Portal(bus, "/org/freedesktop/portal/desktop")
        loop = GLib.MainLoop()
        threading.Thread(target=loop.run, daemon=True).start()
        daemon = start_daemon()
        discovery = fixture.require(cli("--discover", URL, "--ca-cert", root / "server.pem"), "checking registration diagnostic")
        advertised = "yes" if (metadata.get("registration_endpoint") or "").strip() else "no"
        assert f"dynamic registration advertised: {advertised} (not used by Cirrus)" in discovery.stdout
        print(f"PASS: disposable provider dynamic registration advertised: {advertised}", flush=True)
        # Cancel a real browser authorization before callback, then retry normally.
        import socket as net_socket
        def account_ipc(request):
            with net_socket.socket(net_socket.AF_UNIX, net_socket.SOCK_STREAM) as client:
                client.settimeout(30)
                client.connect(str(runtime / "daemon" / "cirrus-drive.sock"))
                client.sendall(b"CIRRUS/2 " + json.dumps(request).encode() + b"\n")
                response = bytearray()
                while not response.endswith(b"\n"):
                    chunk = client.recv(65536)
                    if not chunk:
                        raise RuntimeError("daemon closed the sign-in request")
                    response.extend(chunk)
                return json.loads(response.removeprefix(b"CIRRUS/2 "))

        def callback_page(authorization, params, heading):
            redirect = urlsplit(parse_qs(urlsplit(authorization).query)["redirect_uri"][0])
            connection = http.client.HTTPConnection(redirect.hostname, redirect.port, timeout=5)
            try:
                connection.request("GET", "/?" + urlencode(params))
                response = connection.getresponse()
                body = response.read().decode("utf-8")
                assert response.status == 400
                assert response.getheader("Content-Type") == "text/html; charset=utf-8"
                assert response.getheader("Cache-Control") == "no-store"
                assert response.getheader("Referrer-Policy") == "no-referrer"
                assert response.getheader("Content-Security-Policy") == "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                assert heading in body and "Return to Cirrus Drive" in body
                assert all(value not in body for value in params.values())
            finally:
                connection.close()

        cancelled_attempt = "1" * 32
        cancelled_result = queue.Queue(maxsize=1)
        def cancelled_connect():
            try:
                cancelled_result.put(account_ipc({"operation": "Connect", "instance": URL,
                                                  "ca_pem": (root / "server.pem").read_text(),
                                                  "attempt": cancelled_attempt}))
            except Exception as error:
                cancelled_result.put(error)
        cancelled_worker = threading.Thread(target=cancelled_connect)
        cancelled_worker.start()
        try:
            for _ in range(900):
                try:
                    cancelled_url = requests.get(timeout=0.1)
                    break
                except queue.Empty:
                    if not cancelled_worker.is_alive():
                        raise RuntimeError("disposable sign-in ended before requesting the browser")
            else:
                raise RuntimeError("disposable sign-in did not request the browser")
            redirect = urlsplit(parse_qs(urlsplit(cancelled_url).query)["redirect_uri"][0])
            callback_page(cancelled_url, {"state": "invalid-state-marker", "code": "secret-code-marker"},
                          "Authorization response rejected")
            response = account_ipc({"operation": "CancelConnect", "attempt": cancelled_attempt})
            assert response["error"] is None
            result = cancelled_result.get(timeout=10)
            assert isinstance(result, dict) and "cancelled" in (result.get("error") or "")
            with net_socket.socket(net_socket.AF_INET, net_socket.SOCK_STREAM) as late:
                late.settimeout(1)
                assert late.connect_ex((redirect.hostname, redirect.port)) != 0
            assert fixture.run(["secret-tool", "lookup", "application", "cirrus-drive", "instance", URL], env=os.environ).returncode != 0
        finally:
            cancelled_worker.join(timeout=35)
        assert not cancelled_worker.is_alive()
        ui_env = dict(os.environ, XDG_CONFIG_HOME=str(root / "ui-cancel-config"))
        events = [{"t": 1.0, "key": "instance"}, {"t": 1.2, "paste": URL},
                  {"t": 1.5, "key": "advanced"}, {"t": 1.8, "key": "ca"},
                  {"t": 2.0, "paste": str(root / "server.pem")}, {"t": 2.5, "key": "connect"},
                  {"t": 30.0, "key": "cancel-sign-in"}]
        (root / "ui-cancel-events.json").write_text(json.dumps(events))
        ui_cancel = subprocess.Popen([str(root / "cirrus-ui"), "--script", str(root / "ui-cancel-events.json"),
                                      "--tree", str(root / "ui-cancel-tree.json"), "--size", "900x1600", "--at", "45"],
                                     env=ui_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(900):
                try:
                    requests.get(timeout=0.1)
                    break
                except queue.Empty:
                    if ui_cancel.poll() is not None:
                        raise RuntimeError("Rune sign-in ended before opening the browser")
            else:
                raise RuntimeError("Rune sign-in did not request the browser")
            if ui_cancel.wait(timeout=60):
                raise RuntimeError("Rune cancel sign-in flow failed")
            ui_tree = json.loads((root / "ui-cancel-tree.json").read_text())
            assert "sign-in cancelled; you can try again" in json.dumps(ui_tree)
            assert any(e.get("key") == "connect" and e.get("focusable") for e in ui_tree["elements"])
        finally:
            fixture.stop_process(ui_cancel)
        print("PASS: cancelled browser sign-in, rejected late callback, and Rune retry control", flush=True)
        denied_client = subprocess.Popen([str(fixture.BINARY), "--connect", URL, "--ca-cert", str(root / "server.pem")],
                                         env=os.environ, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            denied_url = requests.get(timeout=90)
            state = parse_qs(urlsplit(denied_url).query)["state"][0]
            callback_page(denied_url, {"state": state, "error": "access_denied", "iss": metadata["issuer"]},
                          "Authorization was not granted")
            _, stderr = denied_client.communicate(timeout=30)
            assert denied_client.returncode != 0 and b"denied authorization" in stderr
        finally:
            fixture.stop_process(denied_client)
        print("PASS: rejected and denied callback pages, security headers, and no reflected parameters", flush=True)
        connect_client = subprocess.Popen([str(fixture.BINARY), "--connect", URL, "--ca-cert", str(root / "server.pem")],
                                          env=os.environ, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            authorization = None
            for _ in range(900):
                try:
                    authorization = requests.get(timeout=0.1)
                    break
                except queue.Empty:
                    if connect_client.poll() is not None:
                        _, stderr = connect_client.communicate()
                        raise RuntimeError("OIDC discovery failed: " + stderr.decode(errors="replace").strip())
            if authorization is None:
                raise RuntimeError("authorization portal was not called")
            assert "prompt" not in parse_qs(urlsplit(authorization).query)
            assert account_ipc({"operation": "CancelConnect", "attempt": cancelled_attempt})["error"] == "sign-in is no longer active"
            chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
            if not chrome:
                raise RuntimeError("Chrome or Chromium is required")
            profile = root / "browser-profile"
            profile.mkdir(mode=0o700)
            browser = subprocess.Popen([chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
                                        "--disable-background-networking", "--no-first-run", "--no-default-browser-check",
                                        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1",
                                        "--disable-component-update", "--disable-sync",
                                        "--ignore-certificate-errors", "--remote-debugging-address=127.0.0.1",
                                        "--remote-debugging-port=0", "--remote-allow-origins=http://localhost",
                                        "--user-data-dir=" + str(profile), "about:blank"],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            active = profile / "DevToolsActivePort"
            for _ in range(200):
                if active.exists():
                    lines = active.read_text().splitlines()
                    if len(lines) >= 2 and lines[0] and lines[1]:
                        break
                if browser.poll() is not None:
                    raise RuntimeError("disposable browser did not start")
                time.sleep(0.05)
            else:
                raise RuntimeError("browser debugging endpoint did not start")
            port, endpoint = lines[:2]
            ws = f"ws://127.0.0.1:{port}{endpoint}"
            sequence = 0
            with connect(ws, origin="http://localhost", open_timeout=10) as socket:
                def call(method, params=None, session=None):
                    nonlocal sequence
                    sequence += 1
                    message = {"id": sequence, "method": method, "params": params or {}}
                    if session:
                        message["sessionId"] = session
                    socket.send(json.dumps(message))
                    while True:
                        reply = json.loads(socket.recv(timeout=30))
                        if reply.get("id") == sequence:
                            if "error" in reply:
                                raise RuntimeError("browser automation request failed")
                            return reply.get("result", {})
                target = call("Target.createTarget", {"url": authorization})["targetId"]
                session = call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
                script = """(() => {
                    const u = document.querySelector('input[autocomplete=username],input[name=username],input[name=login],input[type=text],input[type=email]');
                    const p = document.querySelector('input[type=password]');
                    if (!u || !p) return false;
                    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                    set.call(u, 'admin'); u.dispatchEvent(new Event('input', {bubbles:true}));
                    set.call(p, PASSWORD); p.dispatchEvent(new Event('input', {bubbles:true}));
                    u.dispatchEvent(new Event('change', {bubbles:true})); p.dispatchEvent(new Event('change', {bubbles:true}));
                    const form = p.closest('form'); if (!form) return false;
                    form.requestSubmit(); return true;
                })()""".replace("PASSWORD", json.dumps(password))
                submitted = False
                consented = False
                for _ in range(200):
                    if connect_client.poll() is not None:
                        break
                    if not submitted:
                        value = call("Runtime.evaluate", {"expression": script, "returnByValue": True}, session)
                        submitted = value.get("result", {}).get("value") is True
                    elif not consented:
                        expression = """(() => {
                            if (document.querySelector('input[type=password]')) return false;
                            const choices = [...document.querySelectorAll('button,input[type=submit]')];
                            const yes = choices.find(e => /allow|accept|approve|authori[sz]e|grant|continue/i.test(e.innerText || e.value || ''));
                            if (!yes) return false; yes.click(); return true;
                        })()"""
                        value = call("Runtime.evaluate", {"expression": expression, "returnByValue": True}, session)
                        consented = value.get("result", {}).get("value") is True
                    time.sleep(0.1)
                if not submitted:
                    raise RuntimeError("disposable browser did not find the OpenCloud login form")
                for _ in range(50):
                    page = call("Runtime.evaluate", {"expression": "document.querySelector('h1')?.textContent || ''", "returnByValue": True}, session)
                    if page.get("result", {}).get("value") == "Authorization received":
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("browser did not show the Cirrus authorization callback")
                page = call("Runtime.evaluate", {"expression": "document.body.innerText", "returnByValue": True}, session)
                assert "Return to Cirrus Drive to finish connecting your account." in page.get("result", {}).get("value", "")
                if connect_client.poll() is None:
                    info = call("Runtime.evaluate", {"expression": "JSON.stringify({callback:location.hostname==='127.0.0.1',password:!!document.querySelector('input[type=password]'),error:!!document.querySelector('[role=alert],.error,.alert-danger'),forms:document.forms.length,buttons:document.querySelectorAll('button,input[type=submit]').length})", "returnByValue": True}, session)
                    print("OIDC browser state:", info.get("result", {}).get("value", "unavailable"), flush=True)
            stdout, stderr = connect_client.communicate(timeout=90)
            if connect_client.returncode:
                raise RuntimeError("real OIDC connect failed: " + stderr.decode(errors="replace").strip())
            if b"account connected" not in stdout:
                raise RuntimeError("OIDC connect did not report success")
        finally:
            fixture.stop_process(connect_client)
        spaces = fixture.require(cli("--spaces", URL), "listing OIDC Spaces").stdout.splitlines()
        if not spaces:
            raise RuntimeError("OIDC account has no Space")
        saved = fixture.require(fixture.run(["secret-tool", "lookup", "application", "cirrus-drive", "instance", URL], env=os.environ), "loading disposable OIDC identity")
        token = json.loads(saved.stdout)["access_token"]
        with opener.open(Request(URL + "graph/v1.0/me/drives", headers={"Authorization": "Bearer " + token}), timeout=15) as response:
            drives = json.load(response)["value"]
        personal = [drive["id"] for drive in drives if drive.get("driveType") == "personal"]
        if len(personal) != 1 or personal[0] not in [line.split("\t", 1)[0] for line in spaces]:
            raise RuntimeError("OIDC account has no unique personal Space")
        space = personal[0]
        fixture.require(cli("--select-space", URL, space), "selecting OIDC Space")
        ui_env = dict(os.environ, XDG_CONFIG_HOME=str(root / "ui-config"))
        parent = root / "chosen-parent"
        parent.mkdir(mode=0o700)
        chosen_mount = parent
        events = [{"t": 1.0, "key": "instance"}, {"t": 1.2, "paste": URL},
                  {"t": 1.5, "key": "load-spaces"}, {"t": 8.0, "key": f"space-{space}"},
                  {"t": 30.0, "key": "choose-mount-folder"},
                  {"t": 30.5, "type": "file-dialog", "path": str(parent)},
                  {"t": 31.0, "key": "mount"}]
        (root / "ui-mount-events.json").write_text(json.dumps(events))
        fixture.require(fixture.run([str(root / "cirrus-ui"), "--script", str(root / "ui-mount-events.json"),
                                     "--tree", str(root / "ui-mount-tree.json"), "--size", "900x1200", "--at", "45"], env=ui_env),
                        "choosing and mounting a Rune location")
        assert f"Mounted at {chosen_mount}" in (root / "ui-mount-tree.json").read_text()
        assert "Mounted directory" in (root / "ui-mount-tree.json").read_text()
        assert chosen_mount.is_mount()
        fixture.require(cli("--unmount"), "unmounting chosen Rune location")
        fixture.require(fixture.run([str(root / "cirrus-ui"), "--tree", str(root / "ui-restart-tree.json"),
                                     "--size", "900x2000", "--at", "2"], env=ui_env), "restarting Rune")
        assert URL in (root / "ui-restart-tree.json").read_text()
        fixture.require(cli("--mount", URL), "mounting the default location")
        assert (root / "cirrus").is_mount()
        fixture.require(cli("--unmount"), "unmounting the default location")
        existing = root / "cirrus" / "keep"
        existing.write_text("do not cover")
        assert cli("--mount", URL).returncode != 0
        assert existing.read_text() == "do not cover"
        existing.unlink()
        isolation = SourceFileLoader("opencloud_isolation_lab", str(Path(__file__).with_name("opencloud-isolation-lab.py"))).load_module()
        isolation.run(root, runtime, URL, token, space, opener, requests, ws, fixture)
        fixture.require(cli("--mount", URL, mountpoint), "mounting OIDC Space")
        mounted = True
        events = [{"t": 1.0, "key": "refresh"}]
        (root / "ui-events.json").write_text(json.dumps(events))
        fixture.require(fixture.run([str(root / "cirrus-ui"), "--script", str(root / "ui-events.json"),
                                     "--tree", str(root / "ui-tree.json"), "--size", "460x580", "--at", "4"],
                                    env=os.environ), "Rune OIDC mount status")
        tree = (root / "ui-tree.json").read_text()
        assert "running;" in fixture.require(cli("--status"), "checking OIDC daemon status").stdout
        assert f"Mounted at {mountpoint}" in tree and "Mounted directory" in tree
        (root / "ui-nav-events.json").write_text(json.dumps([{"t": 1.0, "key": "nav-Recovery"}]))
        fixture.require(fixture.run([str(root / "cirrus-ui"), "--script", str(root / "ui-nav-events.json"),
                                     "--tree", str(root / "ui-nav-tree.json"), "--size", "460x580", "--at", "4"],
                                    env=os.environ), "Rune recovery navigation")
        recovery_tree = (root / "ui-nav-tree.json").read_text()
        assert "Recover a local copy" in recovery_tree and "Staged copies" in recovery_tree
        os.mkdir(mountpoint / "oidc-dir")
        with open(mountpoint / "oidc-dir" / ".temp", "wb", buffering=0) as file:
            file.write(b"authenticated writable mount\n")
            os.fsync(file.fileno())
        os.replace(mountpoint / "oidc-dir" / ".temp", mountpoint / "oidc-dir" / "file")
        initial_sync = cli("--sync", URL)
        if initial_sync.returncode:
            print("\n".join(line for line in (root / "daemon.log").read_text().splitlines() if "cirrus lab DAV propstat:" in line), file=sys.stderr)
        fixture.require(initial_sync, "syncing authenticated mounted edits")
        fixture.require(cli("--unmount"), "unmounting authenticated Space")
        mounted = False
        fixture.require(cli("--mount", URL, mountpoint), "remounting authenticated Space")
        mounted = True
        assert (mountpoint / "oidc-dir" / "file").read_bytes() == b"authenticated writable mount\n"
        os.unlink(mountpoint / "oidc-dir" / "file")
        os.rmdir(mountpoint / "oidc-dir")
        deletion_sync = cli("--sync", URL)
        if deletion_sync.returncode:
            with sqlite3.connect(runtime / "home/.local/state/cirrus-drive/state.db") as db:
                states = db.execute("SELECT op_type,state,error_msg FROM operation_journal WHERE state IN ('pending','conflict','uncertain') ORDER BY id").fetchall()
            print("OIDC deletion states:", states, file=sys.stderr)
        fixture.require(deletion_sync, "syncing authenticated deletions")
        os.listdir(mountpoint)
        tunnel.set_online(False)
        tunnel.shutdown()
        tunnel.server_close()
        thread.join(timeout=5)
        tunnel = thread = None
        with open(mountpoint / "oidc-offline", "wb", buffering=0) as file:
            file.write(b"offline after OIDC login\n")
            os.fsync(file.fileno())
        fixture.require(cli("--unmount"), "unmounting OIDC Space offline")
        mounted = False
        fixture.require(cli("--stop"), "stopping OIDC daemon offline")
        daemon.wait(timeout=5)
        daemon = start_daemon()
        fixture.require(cli("--mount", URL, mountpoint), "remounting OIDC Space offline")
        mounted = True
        assert (mountpoint / "oidc-offline").read_bytes() == b"offline after OIDC login\n"
        tunnel = Tunnel(container)
        thread = threading.Thread(target=tunnel.serve_forever, daemon=True)
        thread.start()
        fixture.require(cli("--sync", URL), "syncing OIDC offline edit")
        vim = shutil.which("vim")
        if not vim:
            raise RuntimeError("Vim is required for the OIDC editor scenario")
        with open(mountpoint / "oidc-vim", "wb", buffering=0) as file:
            file.write(b"before\n")
        fixture.require(cli("--sync", URL), "syncing OIDC editor base")
        edited = subprocess.run([vim, "-Nu", "NONE", "-i", "NONE", "-n", "-es", "-c", "%s/before/after/", "-c", "wq", str(mountpoint / "oidc-vim")], capture_output=True, timeout=60)
        if edited.returncode:
            raise RuntimeError("headless default-backup Vim edit failed")
        assert (mountpoint / "oidc-vim").read_bytes() == b"after\n"
        assert not (mountpoint / "oidc-vim~").exists(), "Vim did not remove its temporary backup"
        fixture.require(cli("--sync", URL), "syncing OIDC editor save")
        database = runtime / "home/.local/state/cirrus-drive/state.db"
        with sqlite3.connect(database) as db:
            backup = db.execute("SELECT staged_file FROM operation_journal WHERE path=? AND error_msg='backup retained after source recreation'", ('["oidc-vim~"]',)).fetchone()
        assert backup and (database.parent / "staging" / backup[0]).read_bytes() == b"before\n", "Vim backup was not retained"
        with opener.open(Request(URL + "dav/spaces/" + quote(space, safe="") + "/oidc-vim", headers={"Authorization": "Bearer " + token}), timeout=15) as response:
            assert response.read() == b"after\n", "synced Vim replacement is missing or changed"
        fixture.require(cli("--pin", URL, "/oidc-vim"), "pinning OIDC file before rename")
        os.rename(mountpoint / "oidc-vim", mountpoint / "oidc-vim-renamed")
        assert (mountpoint / "oidc-vim-renamed").read_bytes() == b"after\n"
        assert "/oidc-vim-renamed" in fixture.require(cli("--pins", URL), "listing relocated file pin").stdout
        assert cli("--pin", URL, "/oidc-vim-renamed").returncode != 0, "repin ignored the pending file rename"
        tunnel.set_online(False)
        tunnel.shutdown()
        tunnel.server_close()
        thread.join(timeout=5)
        tunnel = thread = None
        fixture.require(cli("--unmount"), "unmounting pending pinned file rename")
        mounted = False
        fixture.require(cli("--stop"), "stopping with pending pinned file rename")
        daemon.wait(timeout=5)
        daemon = start_daemon()
        fixture.require(cli("--mount", URL, mountpoint), "remounting pending pinned file rename offline")
        mounted = True
        assert (mountpoint / "oidc-vim-renamed").read_bytes() == b"after\n"
        assert "/oidc-vim-renamed" in fixture.require(cli("--pins", URL), "listing relocated file pin after restart").stdout
        tunnel = Tunnel(container)
        thread = threading.Thread(target=tunnel.serve_forever, daemon=True)
        thread.start()
        fixture.require(cli("--sync", URL), "syncing pinned OIDC file rename")
        pins = fixture.require(cli("--pins", URL), "checking moved historical file pin").stdout
        assert "stale\t/oidc-vim-renamed" in pins, pins
        fixture.require(cli("--pin", URL, "/oidc-vim-renamed"), "repinning renamed OIDC file")
        assert "available offline\t/oidc-vim-renamed" in fixture.require(cli("--pins", URL), "checking repinned file").stdout
        with open(mountpoint / "pin-replace-source", "wb", buffering=0) as file:
            file.write(b"keep both versions\n")
        try:
            os.rename(mountpoint / "pin-replace-source", mountpoint / "oidc-vim-renamed")
        except OSError as error:
            assert error.errno == errno.EBUSY, error
        else:
            raise AssertionError("rename replaced an independently pinned destination")
        assert (mountpoint / "pin-replace-source").read_bytes() == b"keep both versions\n"
        assert (mountpoint / "oidc-vim-renamed").read_bytes() == b"after\n"
        os.unlink(mountpoint / "pin-replace-source")
        os.mkdir(mountpoint / "oidc-tree")
        os.mkdir(mountpoint / "oidc-tree" / "nested")
        with open(mountpoint / "oidc-tree" / "nested" / "file", "wb", buffering=0) as file:
            file.write(b"remote tree base\n")
        with open(mountpoint / "oidc-tree" / "nested" / "unmodified", "wb", buffering=0) as file:
            file.write(b"open remote version\n")
        os.mkdir(mountpoint / "oidc-tree-target")
        fixture.require(cli("--sync", URL), "syncing OIDC tree fixtures")
        fixture.require(cli("--pin", URL, "/oidc-tree"), "pinning OIDC tree")
        fixture.require(cli("--pin", URL, "/oidc-tree/nested/unmodified"), "pinning overlapping OIDC file")
        with open(mountpoint / "oidc-tree" / "nested" / "file", "r+b", buffering=0) as writer, \
             open(mountpoint / "oidc-tree" / "nested" / "file", "rb", buffering=0) as reader, \
             open(mountpoint / "oidc-tree" / "nested" / "unmodified", "rb", buffering=0) as remote_reader, \
             os.scandir(mountpoint / "oidc-tree") as directory:
            writer.seek(0)
            writer.write(b"staged before move\n")
            writer.truncate()
            os.rename(mountpoint / "oidc-tree", mountpoint / "oidc-tree-target")
            reader.seek(0)
            assert reader.read() == b"staged before move\n"
            assert remote_reader.read() == b"open remote version\n"
            writer.seek(0, os.SEEK_END)
            writer.write(b"through open handle\n")
            os.fsync(writer.fileno())
            assert "nested" in [entry.name for entry in directory]
        with open(mountpoint / "oidc-tree-target" / "nested" / "new", "wb", buffering=0) as file:
            file.write(b"created after move\n")
        tunnel.set_online(False)
        tunnel.shutdown()
        tunnel.server_close()
        thread.join(timeout=5)
        tunnel = thread = None
        fixture.require(cli("--unmount"), "unmounting pending OIDC tree move")
        mounted = False
        fixture.require(cli("--stop"), "stopping with pending OIDC tree move")
        daemon.wait(timeout=5)
        daemon = start_daemon()
        fixture.require(cli("--mount", URL, mountpoint), "remounting pending OIDC tree move")
        mounted = True
        assert not (mountpoint / "oidc-tree").exists()
        assert (mountpoint / "oidc-tree-target" / "nested" / "file").read_bytes() == b"staged before move\nthrough open handle\n"
        assert (mountpoint / "oidc-tree-target" / "nested" / "new").read_bytes() == b"created after move\n"
        assert (mountpoint / "oidc-tree-target" / "nested" / "unmodified").read_bytes() == b"open remote version\n"
        pins = fixture.require(cli("--pins", URL), "listing offline relocated pins").stdout
        assert "/oidc-tree-target" in pins and "/oidc-tree-target/nested/unmodified" in pins, pins
        assert "\t/oidc-tree\n" not in pins, pins
        tunnel = Tunnel(container)
        thread = threading.Thread(target=tunnel.serve_forever, daemon=True)
        thread.start()
        fixture.require(cli("--sync", URL), "syncing OIDC tree move")
        assert (mountpoint / "oidc-tree-target" / "nested" / "file").read_bytes() == b"staged before move\nthrough open handle\n"
        assert not (mountpoint / "oidc-tree").exists()
        edited = subprocess.run([vim, "-Nu", "NONE", "-i", "NONE", "-n", "-es", "-c", "%s/staged/edited/", "-c", "wq", str(mountpoint / "oidc-tree-target" / "nested" / "file")], capture_output=True, timeout=60)
        if edited.returncode:
            raise RuntimeError("Vim edit inside renamed directory failed")
        assert (mountpoint / "oidc-tree-target" / "nested" / "file").read_bytes() == b"edited before move\nthrough open handle\n"
        fixture.require(cli("--sync", URL), "syncing editor save inside renamed OIDC tree")
        os.mkdir(mountpoint / "oidc-tree-conflict")
        with open(mountpoint / "oidc-tree-conflict" / "file", "wb", buffering=0) as file:
            file.write(b"remote tree conflict base\n")
        with open(mountpoint / "oidc-tree-conflict" / "pinned", "wb", buffering=0) as file:
            file.write(b"pinned conflict base\n")
        with open(mountpoint / "oidc-conflict", "wb", buffering=0) as file:
            file.write(b"conflict base\n")
        fixture.require(cli("--sync", URL), "syncing OIDC tree conflict base")
        fixture.require(cli("--pin", URL, "/oidc-tree-conflict"), "pinning conflict tree")
        with open(mountpoint / "oidc-conflict", "wb", buffering=0) as file:
            file.write(b"local conflict edit\n")
        remote = URL + "dav/spaces/" + quote(space, safe="") + "/oidc-conflict"
        request = Request(remote, data=b"remote conflict edit\n", method="PUT", headers={"Authorization": "Bearer " + token})
        with opener.open(request, timeout=15) as response:
            assert response.status in (200, 201, 204)
        assert cli("--sync", URL).returncode != 0, "OIDC write conflict was not reported"
        with opener.open(Request(remote, headers={"Authorization": "Bearer " + token}), timeout=15) as response:
            assert response.read() == b"remote conflict edit\n"
        assert (mountpoint / "oidc-conflict").read_bytes() == b"local conflict edit\n"
        assert "conflict" in fixture.require(cli("--journal", URL), "checking OIDC conflict journal").stdout
        with open(mountpoint / "oidc-tree-conflict" / "file", "wb", buffering=0) as file:
            file.write(b"retained tree edit\n")
        os.rename(mountpoint / "oidc-tree-conflict", mountpoint / "oidc-tree-conflict-target")
        conflict_target = URL + "dav/spaces/" + quote(space, safe="") + "/oidc-tree-conflict-target"
        with opener.open(Request(conflict_target, method="MKCOL", headers={"Authorization": "Bearer " + token}), timeout=15) as response:
            assert response.status == 201
        assert cli("--sync", URL).returncode != 0, "OIDC tree conflict was not reported"
        assert cli("--pin", URL, "/oidc-tree-conflict-target").returncode != 0, "repin ignored the conflicted tree move"
        conflict_source = URL + "dav/spaces/" + quote(space, safe="") + "/oidc-tree-conflict/file"
        with opener.open(Request(conflict_source, headers={"Authorization": "Bearer " + token}), timeout=15) as response:
            assert response.read() == b"remote tree conflict base\n"
        assert (mountpoint / "oidc-tree-conflict-target" / "file").read_bytes() == b"retained tree edit\n"
        assert (mountpoint / "oidc-tree-conflict-target" / "pinned").read_bytes() == b"pinned conflict base\n"
        assert "stale\t/oidc-tree-conflict-target" in fixture.require(cli("--pins", URL), "checking conflicted tree pin").stdout
        with sqlite3.connect(runtime / "home/.local/state/cirrus-drive/state.db") as db:
            tree_operation = db.execute("SELECT staged_file,state FROM operation_journal WHERE op_type='move-tree' AND state='conflict'").fetchone()
        assert tree_operation is not None and tree_operation[1] == "conflict"
        fixture.require(cli("--acknowledge", URL, tree_operation[0]), "acknowledging inspected tree conflict")
        with sqlite3.connect(runtime / "home/.local/state/cirrus-drive/state.db") as db:
            pinned = db.execute("SELECT count(*) FROM chunks WHERE path=?", ('["oidc-tree-conflict-target","pinned"]',)).fetchone()[0]
        assert pinned > 0, "acknowledging the tree conflict discarded pinned content"
        prior_staged = next(row for row in retained_staged_rows() if row["path"] == ["oidc-conflict"] and row["state"] == "conflict")
        fixture.require(cli("--unmount"), "unmounting OIDC lab")
        mounted = False
        fixture.require(cli("--stop"), "stopping OIDC daemon")
        daemon.wait(timeout=5)
        tunnel.shutdown()
        tunnel.server_close()
        thread.join(timeout=5)
        tunnel = thread = None
        fixture.stop_process(keyring)
        keyring = None
        daemon = start_daemon()
        roots = [json.loads(line) for line in fixture.require(cli("--retained-pins", URL), "listing retained pins offline").stdout.splitlines()]
        assert any(row["space"] == space and row["root"] == ["oidc-tree-conflict-target"] for row in roots), roots
        files = [json.loads(line) for line in fixture.require(cli("--retained-files", URL, space, "/oidc-tree-conflict-target"), "listing retained versions offline").stdout.splitlines()]
        pinned_file = next(row for row in files if row["path"] == ["oidc-tree-conflict-target", "pinned"])
        assert "possibly stale" in pinned_file["status"]
        destination = runtime / "recovery"
        destination.mkdir(mode=0o700)
        staged = next(row for row in retained_staged_rows() if row["path"] == ["oidc-conflict"] and row["state"] == "conflict")
        assert staged["id"] == prior_staged["id"] and staged["selector"] == prior_staged["selector"]
        staged_source = runtime / "home/.local/state/cirrus-drive/staging" / staged["staged_file"]
        assert staged_source.read_bytes() == b"local conflict edit\n"
        staged_args = ("--export-staged", URL, staged["id"], staged["selector"])
        staged_source.write_bytes(b"changed conflict edit\n")
        changed_staged = cli(*staged_args, destination / "changed-staged")
        assert changed_staged.returncode != 0 and "changed" in changed_staged.stderr
        assert not (destination / "changed-staged").exists()
        staged_source.write_bytes(b"local conflict edit\n")
        staged_existing = destination / "staged-existing"
        staged_existing.write_bytes(b"do not overwrite staged")
        assert cli(*staged_args, staged_existing).returncode != 0
        assert staged_existing.read_bytes() == b"do not overwrite staged"
        staged_link = root / "staged-recovery-link"
        staged_link.symlink_to(destination, target_is_directory=True)
        assert cli(*staged_args, staged_link / "escape").returncode != 0
        assert not (destination / "escape").exists()
        assert cli(*staged_args[:-1], "0" * 64, destination / "wrong-staged").returncode != 0
        assert not (destination / "wrong-staged").exists()
        fixture.require(cli(*staged_args, destination / "staged-conflict"), "exporting conflict offline")
        assert (destination / "staged-conflict").read_bytes() == b"local conflict edit\n"
        assert staged_source.read_bytes() == b"local conflict edit\n"
        first_page = [json.loads(line) for line in fixture.require(cli("--retained-staged", URL), "listing Rune staged page").stdout.splitlines()]
        first_index = next(i for i, row in enumerate(first_page) if row["selector"] is not None)
        first_copy = first_page[first_index]
        expected_ui = (runtime / "home/.local/state/cirrus-drive/staging" / first_copy["staged_file"]).read_bytes()
        ui_destination = destination / "rune-staged"
        events = [{"t": 1.0, "key": "instance"}, {"t": 1.2, "paste": URL},
                  {"t": 1.5, "key": "nav-Recovery"}, {"t": 1.8, "key": "recovery-staged"},
                  {"t": 3.5, "key": f"recovery-row-{first_index}"},
                  {"t": 4.0, "key": "recovery-destination"}, {"t": 4.2, "paste": str(ui_destination)},
                  {"t": 4.6, "key": "recovery-export"}]
        (root / "ui-recovery-events.json").write_text(json.dumps(events))
        fixture.require(fixture.run([str(root / "cirrus-ui"), "--script", str(root / "ui-recovery-events.json"), "--tree", str(root / "ui-recovery-tree.json"), "--size", "900x4000", "--at", "8"], env=os.environ), "Rune staged export")
        assert "Exported local copy" in (root / "ui-recovery-tree.json").read_text()
        assert ui_destination.read_bytes() == expected_ui
        compact_destination = destination / "rune-compact"
        events = [{"t": 1.0, "key": "instance"}, {"t": 1.2, "paste": URL},
                  {"t": 1.5, "key": "nav-Recovery"},
                  {"t": 1.8, "type": "wheel", "x": 300, "y": 400, "dy": -5000},
                  {"t": 2.2, "key": "recovery-staged"}, {"t": 4.0, "key": f"recovery-row-{first_index}"},
                  {"t": 4.5, "type": "wheel", "x": 300, "y": 400, "dy": -5000},
                  {"t": 5.0, "key": "recovery-destination"}, {"t": 5.2, "paste": str(compact_destination)},
                  {"t": 5.6, "key": "recovery-export"}]
        (root / "ui-compact-events.json").write_text(json.dumps(events))
        fixture.require(fixture.run([str(root / "cirrus-ui"), "--script", str(root / "ui-compact-events.json"), "--tree", str(root / "ui-compact-tree.json"), "--size", "460x580", "--at", "9"], env=os.environ), "Rune compact staged export")
        assert "Exported local copy" in (root / "ui-compact-tree.json").read_text()
        assert compact_destination.read_bytes() == expected_ui
        root_index = next(i for i, row in enumerate(roots) if row["space"] == space and row["root"] == ["oidc-tree-conflict-target"])
        file_index = next(i for i, row in enumerate(files) if row["path"] == pinned_file["path"])
        ui_pin = destination / "rune-pin"
        events = [{"t": 1.0, "key": "instance"}, {"t": 1.2, "paste": URL},
                  {"t": 1.5, "key": "nav-Recovery"}, {"t": 1.8, "key": "recovery-pins"},
                  {"t": 3.5, "key": f"recovery-row-{root_index}"},
                  {"t": 5.0, "key": f"recovery-row-{file_index}"}, {"t": 5.5, "key": "recovery-destination"},
                  {"t": 5.7, "paste": str(ui_pin)}, {"t": 6.1, "key": "recovery-export"}]
        (root / "ui-pin-events.json").write_text(json.dumps(events))
        fixture.require(fixture.run([str(root / "cirrus-ui"), "--script", str(root / "ui-pin-events.json"), "--tree", str(root / "ui-pin-tree.json"), "--size", "900x4000", "--at", "9"], env=os.environ), "Rune pin export")
        pin_tree = (root / "ui-pin-tree.json").read_text()
        assert "Exported local copy" in pin_tree and "pin /oidc-tree-conflict-target" in pin_tree
        assert ui_pin.read_bytes() == b"pinned conflict base\n"
        args = ("--export-retained", URL, space, "/oidc-tree-conflict-target", "/oidc-tree-conflict-target/pinned", pinned_file["selector"])
        assert cli(*args[:-1], "0" * 64, destination / "wrong-version").returncode != 0
        assert not (destination / "wrong-version").exists()
        existing = destination / "existing"
        existing.write_bytes(b"do not overwrite")
        assert cli(*args, existing).returncode != 0
        assert existing.read_bytes() == b"do not overwrite"
        alias = root / "recovery-link"
        alias.symlink_to(destination, target_is_directory=True)
        assert cli(*args, alias / "linked").returncode != 0
        assert not (destination / "linked").exists()
        assert cli(*args, str(destination) + "/../escaped").returncode != 0
        assert not (runtime / "escaped").exists()
        db_path = runtime / "home/.local/state/cirrus-drive/state.db"
        with sqlite3.connect(db_path) as db:
            saved = db.execute("SELECT rowid,digest FROM chunks WHERE path=? LIMIT 1", ('["oidc-tree-conflict-target","pinned"]',)).fetchone()
            assert saved is not None
            db.execute("UPDATE chunks SET digest='corrupt' WHERE rowid=?", (saved[0],))
        changed = cli(*args, destination / "changed")
        assert changed.returncode != 0 and "changed" in changed.stderr
        assert not (destination / "changed").exists()
        corrupt_files = [json.loads(line) for line in fixture.require(cli("--retained-files", URL, space, "/oidc-tree-conflict-target"), "listing damaged pin").stdout.splitlines()]
        corrupt_selector = next(row["selector"] for row in corrupt_files if row["path"] == pinned_file["path"])
        assert cli(*args[:-1], corrupt_selector, destination / "corrupt").returncode != 0
        assert not (destination / "corrupt").exists()
        with sqlite3.connect(db_path) as db:
            db.execute("UPDATE chunks SET digest=? WHERE rowid=?", (saved[1], saved[0]))
            pin_row = db.execute("SELECT rowid,manifest FROM pins WHERE space=? AND root=?", (space, '["oidc-tree-conflict-target"]')).fetchone()
            file_row = db.execute("SELECT rowid,version FROM files WHERE space=? AND root=? AND path=?", (space, '["oidc-tree-conflict-target"]', '["oidc-tree-conflict-target","pinned"]')).fetchone()
            manifest = json.loads(pin_row[1])
            version = json.loads(file_row[1])
            version["checksums"] = ["SHA256:" + "0" * 64]
            for i, item in enumerate(manifest):
                if item["path"] == version["path"]:
                    manifest[i] = version
            db.execute("UPDATE pins SET manifest=? WHERE rowid=?", (json.dumps(manifest), pin_row[0]))
            db.execute("UPDATE files SET version=? WHERE rowid=?", (json.dumps(version), file_row[0]))
        checksum_files = [json.loads(line) for line in fixture.require(cli("--retained-files", URL, space, "/oidc-tree-conflict-target"), "listing altered pin metadata").stdout.splitlines()]
        checksum_selector = next(row["selector"] for row in checksum_files if row["path"] == pinned_file["path"])
        assert cli(*args[:-1], checksum_selector, destination / "bad-checksum").returncode != 0
        assert not (destination / "bad-checksum").exists()
        with sqlite3.connect(db_path) as db:
            db.execute("UPDATE pins SET manifest=? WHERE rowid=?", (pin_row[1], pin_row[0]))
            db.execute("UPDATE files SET version=? WHERE rowid=?", (file_row[1], file_row[0]))
            db.execute("UPDATE pins SET manifest='[]' WHERE rowid=?", (pin_row[0],))
        assert cli(*args, destination / "bad-manifest").returncode != 0
        assert not (destination / "bad-manifest").exists()
        with sqlite3.connect(db_path) as db:
            db.execute("UPDATE pins SET manifest=? WHERE rowid=?", (pin_row[1], pin_row[0]))
        fixture.require(cli(*args, destination / "pinned"), "exporting retained pin offline")
        assert (destination / "pinned").read_bytes() == b"pinned conflict base\n"
        assert (destination / "pinned").stat().st_mode & 0o177 == 0
        file_pin = [json.loads(line) for line in fixture.require(cli("--retained-files", URL, space, "/oidc-vim-renamed"), "listing retained file pin").stdout.splitlines()]
        assert len(file_pin) == 1
        fixture.require(cli("--export-retained", URL, space, "/oidc-vim-renamed", "/oidc-vim-renamed", file_pin[0]["selector"], destination / "file-pin"), "exporting retained file pin")
        assert (destination / "file-pin").read_bytes() == b"after\n"
        fixture.require(cli("--stop"), "stopping offline recovery daemon")
        daemon.wait(timeout=5)
        print("PASS: acknowledged conflict pin exported offline without keyring; unsafe destinations, corrupt chunk, checksum and manifest refused", flush=True)
        print("PASS: OpenCloud OIDC/PKCE, private keyring, daemon IPC, Rune, writable FUSE, offline restart and conflict", flush=True)
        _ = (name, portal)
    finally:
        if daemon and daemon.poll() is None:
            status = cli("--mount-status")
            owned = [p for p in (chosen_mount, root / "cirrus") if p is not None]
            if status.returncode == 0 and any(status.stdout.startswith(f"mounted: {path};") for path in owned):
                fixture.require(cli("--unmount"), "unmounting lab location during cleanup")
        if mounted and daemon and daemon.poll() is None:
            cli("--unmount")
        fixture.stop_process(daemon)
        for record_path in (runtime / "daemon").glob("cirrus-drive.mount-*"):
            record = json.loads(record_path.read_text())
            for line in Path("/proc/self/mountinfo").read_text().splitlines():
                parts = line.split()
                if ("-" in parts and parts[4] == str(mountpoint)
                        and parts[parts.index("-") + 1:parts.index("-") + 3]
                        == ["fuse.cirrus-drive", record.get("source")]):
                    fixture.require(fixture.run(["fusermount3", "-u", "-z", "--", str(mountpoint)]), "cleaning OIDC lab mount")
        if browser and browser.poll() is None:
            try:
                os.killpg(browser.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        fixture.stop_process(browser)
        if loop:
            loop.quit()
        fixture.stop_process(keyring)
        if tunnel:
            tunnel.shutdown()
            tunnel.server_close()
        if thread:
            thread.join(timeout=5)


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        password = sys.stdin.readline().rstrip("\n")
        child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], password)
        return
    if sys.argv[1:]:
        raise SystemExit("usage: check-opencloud-oidc-e2e.py")
    capability = fixture.run([str(fixture.BINARY), "--lab-capabilities"])
    if capability.returncode or capability.stdout.strip() != "cirrus-drive disposable account and mount lab v1":
        raise SystemExit("build the disposable fault-injection daemon first")
    version = lab.docker("image", "inspect", lab.IMAGE, "--format", '{{index .Config.Labels "org.opencontainers.image.version"}}').decode().strip()
    if version != "9.0.0":
        raise SystemExit("pinned lab image does not identify as OpenCloud 9.0.0")
    root = Path(tempfile.mkdtemp(prefix="cirrus-oidc-"))
    runtime = Path(tempfile.mkdtemp(prefix="cdo-", dir="/dev/shm"))
    container = None
    launcher = None
    password = secrets.token_urlsafe(24)
    try:
        shutil.copy2(fixture.BINARY, root / "cirrus-daemon")
        if not fixture.UI.is_file():
            raise RuntimeError("build the Rune UI before running the OIDC lab")
        shutil.copy2(fixture.UI, root / "cirrus-ui")
        for name in ("data", "config", "mount"):
            (root / name).mkdir(mode=0o700)
        for name in ("bus", "control", "home", "daemon"):
            (runtime / name).mkdir(mode=0o700)
        startup = 'IFS= read -r p; ADMIN_PASSWORD="$p" opencloud init --quiet --insecure true >/dev/null 2>&1 && exec opencloud server >/dev/null 2>&1'
        container = lab.docker("create", "-i", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
                               "--security-opt", "no-new-privileges", "--no-healthcheck", "--log-driver", "none", "--pids-limit", "256",
                               "--memory", "768m", "--cpus", "1", "--tmpfs", "/etc/opencloud:rw,nosuid,nodev,noexec,size=32m,uid=1000,gid=1000,mode=0700",
                               "--tmpfs", "/var/lib/opencloud:rw,nosuid,nodev,noexec,size=512m,uid=1000,gid=1000,mode=0700",
                               "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000,mode=0700",
                               "--env", "OC_URL=https://localhost:9200", "--entrypoint", "/bin/sh", lab.IMAGE, "-c", startup).decode().strip()
        launcher = subprocess.Popen(["docker", "start", "-ai", container], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        launcher.stdin.write((password + "\n").encode())
        launcher.stdin.flush()
        config = runtime / "bus.conf"
        config.write_text('<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" '
                          '"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">'
                          '<busconfig><type>session</type><listen>unix:path=' + str(runtime / "bus" / "bus") +
                          '</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/>'
                          '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>')
        env = dict(os.environ, HOME=str(root), XDG_DATA_HOME=str(root / "data"), XDG_CONFIG_HOME=str(root / "config"),
                   XDG_RUNTIME_DIR=str(runtime / "daemon"), GNOME_KEYRING_CONTROL=str(runtime / "control"),
                   CIRRUS_TEST_ACCOUNT_HOME=str(runtime / "home"), CIRRUS_TEST_USER_BUS_DIR=str(runtime / "bus"),
                   CIRRUS_TEST_DAV_DIAGNOSTICS="1")
        for name in ("DBUS_SESSION_BUS_ADDRESS", "DBUS_SESSION_BUS_PID", "DISPLAY", "WAYLAND_DISPLAY"):
            env.pop(name, None)
        result = subprocess.run(["dbus-run-session", "--config-file=" + str(config), "--", sys.executable,
                                 __file__, "--child", str(root), str(runtime), container],
                                input=password + "\n", text=True, env=env, timeout=300)
        if result.returncode:
            raise SystemExit(result.returncode)
    finally:
        if container:
            lab.docker("rm", "-f", container)
        fixture.stop_process(launcher)
        if any(line.split()[4] == str(root) or line.split()[4].startswith(str(root) + "/") for line in Path("/proc/self/mountinfo").read_text().splitlines()):
            print(f"lab mount remains; inspect {root} and {runtime}", file=sys.stderr)
        else:
            shutil.rmtree(root)
            shutil.rmtree(runtime)


if __name__ == "__main__":
    main()

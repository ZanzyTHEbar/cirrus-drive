"""Two independent Cirrus accounts against an already-running disposable OpenCloud lab."""

import json
import os
import queue
import re
import secrets
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import Request

from websockets.sync.client import connect


def sign_in(ws, authorization, client, username, password):
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
                        raise RuntimeError("disposable browser request failed")
                    return reply.get("result", {})

        context = call("Target.createBrowserContext")["browserContextId"]
        try:
            target = call("Target.createTarget", {"url": authorization, "browserContextId": context})["targetId"]
            session = call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
            script = """(() => {
                const u = document.querySelector('input[autocomplete=username],input[name=username],input[name=login],input[type=text],input[type=email]');
                const p = document.querySelector('input[type=password]');
                if (!u || !p) return false;
                const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                set.call(u, USERNAME); u.dispatchEvent(new Event('input', {bubbles:true}));
                set.call(p, PASSWORD); p.dispatchEvent(new Event('input', {bubbles:true}));
                u.dispatchEvent(new Event('change', {bubbles:true})); p.dispatchEvent(new Event('change', {bubbles:true}));
                const form = p.closest('form'); if (!form) return false;
                form.requestSubmit(); return true;
            })()""".replace("USERNAME", json.dumps(username)).replace("PASSWORD", json.dumps(password))
            submitted = consented = False
            for _ in range(300):
                if client.poll() is not None:
                    break
                if not submitted:
                    result = call("Runtime.evaluate", {"expression": script, "returnByValue": True}, session)
                    submitted = result.get("result", {}).get("value") is True
                elif not consented:
                    expression = """(() => {
                        if (document.querySelector('input[type=password]')) return false;
                        const yes = [...document.querySelectorAll('button,input[type=submit]')].find(e => /allow|accept|approve|authori[sz]e|grant|continue/i.test(e.innerText || e.value || ''));
                        if (!yes) return false; yes.click(); return true;
                    })()"""
                    result = call("Runtime.evaluate", {"expression": expression, "returnByValue": True}, session)
                    consented = result.get("result", {}).get("value") is True
                time.sleep(0.1)
            if not submitted:
                raise RuntimeError("second disposable login form was not presented")
            stdout, stderr = client.communicate(timeout=90)
            if client.returncode or b"account connected" not in stdout:
                raise RuntimeError("second disposable OIDC login failed: " + stderr.decode(errors="replace").strip())
        finally:
            call("Target.disposeBrowserContext", {"browserContextId": context})


def run(root, runtime, url, admin_token, admin_space, opener, requests, ws, fixture):
    """Use a separate bus, keyring, daemon and OIDC identity; never touch host accounts."""
    password = secrets.token_urlsafe(24)
    user = {"onPremisesSamAccountName": "cirrus-isolation", "displayName": "Cirrus Isolation",
            "mail": "cirrus-isolation@example.invalid", "passwordProfile": {"password": password}}
    request = Request(url + "graph/v1.0/users", data=json.dumps(user).encode(), method="POST",
                      headers={"Authorization": "Bearer " + admin_token, "Content-Type": "application/json"})
    with opener.open(request, timeout=15) as response:
        if response.status != 201:
            raise RuntimeError("cannot create the second disposable OpenCloud user")
    request = Request(url + "graph/v1.0/drives", data=json.dumps({"name": "Cirrus Shared", "driveType": "project"}).encode(),
                      method="POST", headers={"Authorization": "Bearer " + admin_token, "Content-Type": "application/json"})
    with opener.open(request, timeout=15) as response:
        shared_space = json.load(response)["id"]

    bus_dir = runtime / "second-bus"
    home = runtime / "second-home"
    daemon_dir = runtime / "second-daemon"
    control = runtime / "second-control"
    mount = root / "second-mount"
    desktop_home = root / "second-user"
    data = desktop_home / "data"
    config = desktop_home / "config"
    for path in (bus_dir, home, daemon_dir, control, mount, desktop_home, data, config):
        path.mkdir(mode=0o700)
    bus = keyring = daemon = client = None
    env = dict(os.environ, HOME=str(desktop_home), XDG_DATA_HOME=str(data), XDG_CONFIG_HOME=str(config),
               XDG_RUNTIME_DIR=str(daemon_dir), CIRRUS_TEST_ACCOUNT_HOME=str(home),
               CIRRUS_TEST_USER_BUS_DIR=str(bus_dir))
    keyring_env = dict(env, DBUS_SESSION_BUS_ADDRESS="unix:path=" + str(bus_dir / "bus"),
                       GNOME_KEYRING_CONTROL=str(control))

    def cli(*args):
        return fixture.run([str(fixture.BINARY), *map(str, args)], env=env)

    try:
        bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--address=unix:path=" + str(bus_dir / "bus")],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(150):
            if (bus_dir / "bus").exists():
                break
            if bus.poll() is not None:
                raise RuntimeError("second disposable user bus exited")
            time.sleep(0.02)
        else:
            raise RuntimeError("second disposable user bus did not start")
        keyring = subprocess.Popen(["gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
                                    "--control-directory=" + str(control)], stdin=subprocess.PIPE,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=keyring_env)
        keyring.stdin.write(b"cirrus-second-keyring\n")
        keyring.stdin.close()
        for _ in range(150):
            owner = fixture.run(["gdbus", "call", "--session", "--dest", "org.freedesktop.DBus",
                                 "--object-path", "/org/freedesktop/DBus", "--method",
                                 "org.freedesktop.DBus.GetConnectionUnixProcessID", "org.freedesktop.secrets"], env=keyring_env)
            match = re.search(r"uint32 (\d+)", owner.stdout)
            if owner.returncode == 0 and match and int(match.group(1)) == keyring.pid:
                break
            if keyring.poll() is not None:
                raise RuntimeError("second disposable keyring exited")
            time.sleep(0.02)
        else:
            raise RuntimeError("second disposable keyring did not acquire its bus name")

        daemon = subprocess.Popen([str(fixture.BINARY)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(150):
            if cli("--status").returncode == 0:
                break
            if daemon.poll() is not None:
                raise RuntimeError("second disposable daemon exited")
            time.sleep(0.02)
        else:
            raise RuntimeError("second disposable daemon did not start")
        client = subprocess.Popen([str(fixture.BINARY), "--connect", url, "--ca-cert", str(root / "server.pem")],
                                  env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        authorization = None
        for _ in range(900):
            try:
                authorization = requests.get(timeout=0.1)
                break
            except queue.Empty:
                if client.poll() is not None:
                    _, stderr = client.communicate()
                    raise RuntimeError("second disposable login could not start: " + stderr.decode(errors="replace").strip())
        if authorization is None:
            raise RuntimeError("second disposable login did not open the browser")
        if "prompt" in parse_qs(urlsplit(authorization).query):
            raise RuntimeError("second disposable login unexpectedly forced a prompt")
        sign_in(ws, authorization, client, "cirrus-isolation", password)
        token = json.loads(fixture.require(fixture.run(["secret-tool", "lookup", "application", "cirrus-drive",
                                                       "instance", url], env=keyring_env), "loading second disposable identity").stdout)["access_token"]
        spaces = fixture.require(cli("--spaces", url), "listing second user's Spaces").stdout.splitlines()
        ids = {line.split("\t", 1)[0] for line in spaces}
        if not ids or admin_space in ids:
            raise RuntimeError("second user's listing exposed the other user's private Space")
        if cli("--select-space", url, admin_space).returncode == 0:
            raise RuntimeError("second user could select the other user's private Space")
        dav = url + "dav/spaces/" + quote(admin_space, safe="") + "/"
        for method in ("PROPFIND", "PUT"):
            request = Request(dav if method == "PROPFIND" else dav + "cirrus-isolation-probe",
                              data=None if method == "PROPFIND" else b"disposable probe", method=method,
                              headers={"Authorization": "Bearer " + token, "Depth": "0"})
            try:
                with opener.open(request, timeout=15):
                    raise RuntimeError("server allowed another user to access a private Space")
            except HTTPError as error:
                if error.code not in (403, 404):
                    raise RuntimeError(f"unexpected cross-user {method} status: {error.code}") from error
        with opener.open(Request(url + "graph/v1.0/me/drives", headers={"Authorization": "Bearer " + token}), timeout=15) as response:
            own = [drive["id"] for drive in json.load(response)["value"] if drive.get("driveType") == "personal"]
        if len(own) != 1 or own[0] not in ids:
            raise RuntimeError("second user has no unique accessible personal Space")
        fixture.require(cli("--select-space", url, own[0]), "selecting second user's Space")
        fixture.require(cli("--mount", url, mount), "mounting second user's Space")
        (mount / "isolation.txt").write_bytes(b"second user only\n")
        fixture.require(cli("--sync", url), "syncing second user's file")
        fixture.require(cli("--unmount"), "unmounting second user's Space")
        ocs = url + "ocs/v2.php/apps/files_sharing/api/v1/shares"
        share = urlencode({"space_ref": shared_space, "shareType": 7, "shareWith": "cirrus-isolation", "role": "editor"}).encode()
        headers = {"Authorization": "Bearer " + admin_token, "OCS-APIRequest": "true", "Content-Type": "application/x-www-form-urlencoded"}
        with opener.open(Request(ocs, data=share, method="POST", headers=headers), timeout=15) as response:
            if response.status != 200:
                raise RuntimeError("cannot grant the second user the disposable shared Space")
        for _ in range(30):
            listed = fixture.require(cli("--spaces", url), "listing shared Spaces").stdout.splitlines()
            if shared_space in {line.split("\t", 1)[0] for line in listed}:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("shared Space did not appear for the second user")
        fixture.require(cli("--select-space", url, shared_space), "selecting shared Space")
        fixture.require(cli("--mount", url, mount), "mounting shared Space")
        staged = mount / "retained-after-revocation.txt"
        staged.write_bytes(b"retain this local edit after access is revoked\n")
        revoke = ocs + "/" + quote(shared_space, safe="") + "?" + urlencode({"shareWith": "cirrus-isolation"})
        with opener.open(Request(revoke, method="DELETE", headers={"Authorization": "Bearer " + admin_token, "OCS-APIRequest": "true"}), timeout=15) as response:
            if response.status != 200:
                raise RuntimeError("cannot revoke the disposable Space grant")
        for _ in range(30):
            listed = fixture.require(cli("--spaces", url), "checking revoked Space").stdout.splitlines()
            if shared_space not in {line.split("\t", 1)[0] for line in listed}:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("revoked Space remains in the second user's listing")
        result = cli("--sync", url)
        if result.returncode == 0:
            raise RuntimeError("sync succeeded after access was revoked")
        rows = [json.loads(line) for line in fixture.require(cli("--retained-staged", url), "listing the retained revoked edit").stdout.splitlines()]
        retained = next((row for row in rows if row["space"] == shared_space and row["path"] == [staged.name] and row["selector"]), None)
        if not retained:
            raise RuntimeError("the revoked local edit is not available for recovery")
        destination = runtime / "recovered-revoked-edit"
        fixture.require(cli("--export-staged", url, retained["id"], retained["selector"], destination), "recovering the revoked edit")
        if destination.read_bytes() != b"retain this local edit after access is revoked\n":
            raise RuntimeError("the recovered revoked edit did not match")
        fixture.require(cli("--unmount"), "unmounting the revoked Space")
        rejected = cli("--mount", url, mount)
        if rejected.returncode == 0 or "no longer in the signed-in user's listing" not in rejected.stderr:
            raise RuntimeError("mount did not reject the revoked selection")
        fixture.require(cli("--stop"), "stopping second disposable daemon")
        daemon.wait(timeout=5)
        print("PASS: two OIDC identities, private isolation, shared access and revoked pending-edit recovery", flush=True)
    finally:
        fixture.stop_process(client)
        try:
            if daemon and daemon.poll() is None:
                status = cli("--mount-status")
                if status.returncode == 0 and status.stdout.startswith(f"mounted: {mount};"):
                    result = cli("--unmount")
                    if result.returncode:
                        print("second disposable mount could not be unmounted; lab data will be preserved", flush=True)
        finally:
            fixture.stop_process(daemon)
            fixture.stop_process(keyring)
            fixture.stop_process(bus)

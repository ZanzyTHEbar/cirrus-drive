#!/usr/bin/env python3
"""Exercise Cirrus reads against a network-isolated, disposable OpenCloud 9.0.0.

The loopback TLS bridge translates the fixture bearer token to disposable Basic
auth inside the container; DAV requests and bodies are served by OpenCloud.
"""

import errno
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

from importlib.machinery import SourceFileLoader

sys.dont_write_bytecode = True
fixture = SourceFileLoader("fixture", str(Path(__file__).with_name("check-nonread-lab.py"))).load_module()
IMAGE = "opencloudeu/opencloud-rolling@sha256:bd57f039d0dd3df510fb25f178beefdf0b1f049097285feead607824460e6506"


def docker(*args, data=None, timeout=30):
    result = subprocess.run(["docker", *args], input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed (exit {result.returncode})")
    return result.stdout


def upstream(container, method, path, body=b"", headers=()):
    args = ["exec", "-i", container, "curl", "--silent", "--show-error", "--include",
            "--http1.1", "--noproxy", "*", "--max-time", "15", "--config",
            "/etc/opencloud/lab-curl.conf", "--request", method, "--header", "Expect:"]
    for name, value in headers:
        args.extend(["--header", f"{name}: {value}"])
    if method in ("PROPFIND", "PUT", "POST"):
        args.extend(["--data-binary", "@-"])
    args.append("https://localhost:9200" + path)
    raw = docker(*args, data=body)
    header, separator, payload = raw.partition(b"\r\n\r\n")
    if not separator:
        raise RuntimeError("invalid upstream HTTP response")
    lines = header.split(b"\r\n")
    status = int(lines[0].split()[1])
    fields = []
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if sep and name.lower() in (b"content-type", b"content-range", b"etag"):
            fields.append((name.decode("ascii"), value.strip().decode("latin-1")))
    return status, fields, payload


def child(root, runtime, container):
    fixture.BINARY = root / "cirrus-daemon"
    keyring = daemon = server = thread = None
    mountpoint = root / "mount"
    mounted = False
    range_requests = [0]
    propfind_requests = [0]
    deny_directory = [False]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def forward(self):
            if self.headers.get("Authorization") != "Bearer cirrus-lab-token":
                self.send_error(403)
                return
            if not (self.path == "/graph/v1.0/me/drives" or self.path.startswith("/dav/spaces/")):
                self.send_error(404)
                return
            if self.command == "PROPFIND":
                propfind_requests[0] += 1
                if os.environ.get("CIRRUS_TEST_FUSE_PERF"):
                    time.sleep(0.05)
                if deny_directory[0] and self.path.rstrip("/").endswith("/listing-fixture"):
                    self.send_error(403)
                    return
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1024 * 1024:
                self.send_error(413)
                return
            headers = [(name, self.headers[name]) for name in
                       ("Depth", "Content-Type", "Range", "If-Match", "If-Range", "Accept-Encoding")
                       if name in self.headers]
            if self.command == "GET" and "Range" in self.headers:
                range_requests[0] += 1
            try:
                status, fields, body = upstream(container, self.command, self.path,
                                                self.rfile.read(length), headers)
                self.send_response(status)
                for name, value in fields:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
            except (RuntimeError, OSError, subprocess.TimeoutExpired):
                self.send_error(502)

        do_GET = forward
        do_PROPFIND = forward

    def cli(*args):
        return fixture.run([str(fixture.BINARY), *map(str, args)], env=os.environ)

    try:
        fixture.openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "ca.key",
                        "-out", root / "ca.pem", "-subj", "/CN=cirrus-opencloud-lab-ca", "-days", "1")
        fixture.openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "tls.key",
                        "-out", root / "tls.csr", "-subj", "/CN=localhost")
        (root / "ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
        fixture.openssl("x509", "-req", "-in", root / "tls.csr", "-CA", root / "ca.pem", "-CAkey", root / "ca.key",
                        "-CAcreateserial", "-out", root / "tls.pem", "-days", "1", "-extfile", root / "ext")
        keyring = fixture.keyring_start()
        status, _, data = upstream(container, "GET", "/graph/v1.0/me/drives")
        assert status == 200, f"OpenCloud drive listing: {status}"
        drives = json.loads(data)["value"]
        assert drives, "OpenCloud returned no disposable Space"
        personal = [drive for drive in drives if drive.get("driveType") == "personal"]
        assert len(personal) == 1, "expected one disposable personal Space"
        space = personal[0]["id"]
        path = "/dav/spaces/" + quote(space, safe="") + "/cirrus-read-fixture.bin"
        original = b"old-version-0123456789" * 10000
        changed = b"new-version-9876543210" * 11000
        status, _, failure = upstream(container, "PUT", path, original)
        assert status in (201, 204), f"creating disposable file: {status}, {failure[:400]!r}; drive types: {[drive.get('driveType') for drive in drives]}"
        folder = "/dav/spaces/" + quote(space, safe="") + "/listing-fixture"
        status, _, _ = upstream(container, "MKCOL", folder)
        assert status == 201, f"creating disposable directory: {status}"
        for index in range(12):
            status, _, _ = upstream(container, "PUT", f"{folder}/file-{index:02d}", b"fixture")
            assert status in (201, 204), f"creating disposable listing entry: {status}"

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "tls.pem", root / "tls.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        url = f"https://localhost:{server.server_port}/"
        account = dict(instance=url, issuer=url + "issuer", client_id="lab", token_endpoint=url + "token",
                       subject="disposable-admin", ca_pem=(root / "ca.pem").read_text(),
                       access_token="cirrus-lab-token", refresh_token="unused-lab-token",
                       expires_at=int(time.time()) + 3600, refresh_in_progress=False, selected_space=space)
        fixture.require(fixture.run(["secret-tool", "store", "--label=cirrus-opencloud-lab", "application",
                                    "cirrus-drive", "instance", url], input=json.dumps(account)), "saving lab account")
        with (root / "daemon.log").open("w") as log:
            daemon = subprocess.Popen([str(fixture.BINARY)], env=os.environ, stdout=subprocess.DEVNULL, stderr=log)
        for _ in range(150):
            if cli("--status").returncode == 0:
                break
            if daemon.poll() is not None:
                raise RuntimeError("lab daemon exited during startup")
            time.sleep(0.02)
        else:
            raise RuntimeError("lab daemon did not start")
        fixture.require(cli("--select-space", url, space), "selecting user-scoped lab Space")
        fixture.require(cli("--mount", url, mountpoint), "mounting OpenCloud lab")
        mounted = True
        local_folder = mountpoint / "listing-fixture"
        before = propfind_requests[0]
        started = time.monotonic()
        names = os.listdir(local_folder)
        assert len(names) == 12, f"incomplete listing: {names!r}"
        for name in names:
            assert (local_folder / name).stat().st_size == 7
        count = propfind_requests[0] - before
        elapsed = time.monotonic() - started
        assert count <= 5, f"directory lookup amplification: {count} PROPFIND requests"
        print(f"PASS: 12-entry listing and stat: {count} PROPFIND, {elapsed:.3f}s", flush=True)

        with (local_folder / "local-edit").open("wb") as saved:
            saved.write(b"local bytes")
        assert (local_folder / "local-edit").stat().st_size == 11, "local change not visible"

        status, _, _ = upstream(container, "PUT", f"{folder}/remote-new", b"remote")
        assert status in (201, 204), f"creating remote listing entry: {status}"
        time.sleep(2.2)
        assert (local_folder / "remote-new").stat().st_size == 6, "remote change remained stale"
        deny_directory[0] = True
        time.sleep(2.2)
        try:
            os.listdir(local_folder)
        except OSError as error:
            assert error.errno == errno.EIO, error
        else:
            raise AssertionError("expired listing concealed permission failure")
        deny_directory[0] = False
        file = mountpoint / "cirrus-read-fixture.bin"
        # The bridge must not inherit an open FUSE fd: spawning docker would
        # close its copy, issuing FLUSH while the sole FUSE worker awaits it.
        reader_process = subprocess.Popen([sys.executable, __file__, "--reader", str(file)],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          text=True, env=os.environ)
        try:
            assert reader_process.stdout.readline().strip() == "ready", "read fixture did not become ready"
            assert range_requests[0] == 4, f"unexpected OpenCloud range count: {range_requests[0]}"
            status, _, _ = upstream(container, "PUT", path, changed)
            assert status == 204, f"changing disposable file: {status}"
            reader_process.stdin.write("changed\n")
            reader_process.stdin.flush()
            assert reader_process.wait(timeout=60) == 0, "OpenCloud FUSE read scenario failed"
        finally:
            fixture.stop_process(reader_process)
        fixture.require(cli("--unmount"), "unmounting OpenCloud lab")
        mounted = False
        fixture.require(cli("--stop"), "stopping OpenCloud lab daemon")
        daemon.wait(timeout=5)
        print("PASS: OpenCloud 9.0.0 FUSE read, cache, seek, EOF, mutation, EIO and reopen", flush=True)
    finally:
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
                    fixture.require(fixture.run(["fusermount3", "-u", "-z", "--", str(mountpoint)]), "cleaning lab mount")
        if server and thread:
            server.shutdown()
        if server:
            server.server_close()
        if thread:
            thread.join(timeout=5)
        fixture.stop_process(keyring)


def reader(file):
    original = b"old-version-0123456789" * 10000
    changed = b"new-version-9876543210" * 11000
    fd = os.open(file, os.O_RDONLY)
    try:
        assert os.read(fd, 64) == original[:64]
        assert os.read(fd, 64) == original[64:128]
        assert os.pread(fd, 64, 0) == original[:64]
        os.lseek(fd, 100000, os.SEEK_SET)
        assert os.read(fd, 1000) == original[100000:101000]
        assert os.pread(fd, 100, len(original) - 10) == original[-10:]
        assert os.pread(fd, 1, len(original)) == b""
        print("ready", flush=True)
        assert sys.stdin.readline().strip() == "changed"
        try:
            os.pread(fd, 64, 0)
        except OSError as error:
            assert error.errno == errno.EIO, error
        else:
            raise AssertionError("cached old handle did not fail after OpenCloud modification")
    finally:
        os.close(fd)
    with open(file, "rb", buffering=0) as opened:
        assert opened.read(64) == changed[:64]


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--reader":
        reader(Path(sys.argv[2]))
        return
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        child(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
        return
    if sys.argv[1:]:
        raise SystemExit("usage: check-opencloud-read-lab.py")
    capability = fixture.run([str(fixture.BINARY), "--lab-capabilities"])
    if capability.returncode or capability.stdout.strip() != "cirrus-drive disposable account and mount lab v1":
        raise SystemExit("build first: cargo build --locked -p cirrus-daemon --features fault-injection")
    version = docker("image", "inspect", IMAGE, "--format",
                     '{{index .Config.Labels "org.opencontainers.image.version"}}').decode().strip()
    if version != "9.0.0":
        raise SystemExit("pinned lab image does not identify as OpenCloud 9.0.0")
    root = Path(tempfile.mkdtemp(prefix="cirrus-opencloud-"))
    runtime = Path(tempfile.mkdtemp(prefix="cdr-", dir="/dev/shm"))
    container = None
    try:
        shutil.copy2(fixture.BINARY, root / "cirrus-daemon")
        copied = fixture.run([str(root / "cirrus-daemon"), "--lab-capabilities"])
        if copied.returncode or copied.stdout.strip() != "cirrus-drive disposable account and mount lab v1":
            raise RuntimeError("copied daemon lacks disposable lab isolation")
        for name in ("data", "config", "mount", "tmp"):
            (root / name).mkdir(mode=0o700)
        for name in ("bus", "control", "home", "daemon"):
            (runtime / name).mkdir(mode=0o700)
        startup = ('p=$(cat /proc/sys/kernel/random/uuid); '
                   'ADMIN_PASSWORD="$p" opencloud init --quiet --insecure true >/dev/null 2>&1 && '
                   'printf "user = \\\"admin:%s\\\"\\ninsecure\\n" "$p" > /etc/opencloud/lab-curl.conf && '
                   'exec opencloud server >/dev/null 2>&1')
        # The long-name mutation lab creates thousands of real server objects;
        # one 768 MiB run was killed during setup (exit 137). This is only the
        # disposable server budget, never a client/storage policy override.
        memory = "1g" if os.environ.get("CIRRUS_TEST_NAMESPACE_MUTATIONS") else "768m"
        container = docker("create", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
                           "--security-opt", "no-new-privileges", "--no-healthcheck", "--log-driver", "none",
                           "--pids-limit", "256", "--memory", memory, "--cpus", "1",
                           "--tmpfs", "/etc/opencloud:rw,nosuid,nodev,noexec,size=32m,uid=1000,gid=1000,mode=0700",
                           "--tmpfs", "/var/lib/opencloud:rw,nosuid,nodev,noexec,size=512m,uid=1000,gid=1000,mode=0700",
                           "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000,mode=0700",
                           "--env", "OC_URL=https://localhost:9200", "--env", "PROXY_ENABLE_BASIC_AUTH=true",
                           "--env", "HTTP_PROXY=", "--env", "HTTPS_PROXY=", "--env", "ALL_PROXY=",
                           "--env", "NO_PROXY=*", "--entrypoint", "/bin/sh", IMAGE, "-c", startup).decode().strip()
        docker("start", container)
        for _ in range(60):
            try:
                status, _, _ = upstream(container, "GET", "/graph/v1.0/me/drives")
                if status == 200:
                    break
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
            time.sleep(1)
        else:
            raise RuntimeError("isolated OpenCloud did not become ready")
        bus_config = runtime / "bus.conf"
        bus_config.write_text('<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" '
                              '"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">'
                              '<busconfig><type>session</type><listen>unix:path=' + str(runtime / "bus" / "bus") +
                              '</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/>'
                              '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>')
        # Vim's default backupskip includes $TMPDIR/*; keep the mount outside it.
        env = dict(os.environ, HOME=str(root), TMPDIR=str(root / "tmp"), XDG_DATA_HOME=str(root / "data"), XDG_CONFIG_HOME=str(root / "config"),
                   XDG_RUNTIME_DIR=str(runtime / "daemon"), GNOME_KEYRING_CONTROL=str(runtime / "control"),
                   CIRRUS_TEST_ACCOUNT_HOME=str(runtime / "home"), CIRRUS_TEST_USER_BUS_DIR=str(runtime / "bus"))
        for name in ("DBUS_SESSION_BUS_ADDRESS", "DBUS_SESSION_BUS_PID", "DISPLAY", "WAYLAND_DISPLAY"):
            env.pop(name, None)
        result = subprocess.run(["dbus-run-session", "--config-file=" + str(bus_config), "--", sys.executable,
                                 __file__, "--child", str(root), str(runtime), container], env=env)
        if result.returncode:
            raise SystemExit(result.returncode)
    finally:
        if container:
            docker("rm", "-f", container)
        mounts = Path("/proc/self/mountinfo").read_text().splitlines()
        if any(line.split()[4] == str(root) or line.split()[4].startswith(str(root) + "/") for line in mounts):
            print(f"lab mount remains; inspect {root} and {runtime}", file=sys.stderr)
        else:
            shutil.rmtree(root)
            shutil.rmtree(runtime)


if __name__ == "__main__":
    main()

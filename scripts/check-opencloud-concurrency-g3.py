#!/usr/bin/env python3
"""Characterize pinned DAV limitations, NOT certify concurrent-write safety.

HTTP only: no daemon, keyring, mount, host port, or existing server. Assertions
freeze the reviewed image's known behavior and stop on the first discrepancy.
Successful output is evidence of limitations, never a release-safety token.
"""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from importlib.machinery import SourceFileLoader
from urllib.parse import quote

sys.dont_write_bytecode = True
lab = SourceFileLoader("g3_http", str(Path(__file__).with_name("check-opencloud-read-lab.py"))).load_module()
REVISION = "b8d51b27abf8ac54c91ff231a13fa168bec8268a"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def event(**values):
    print(json.dumps(values, sort_keys=True), flush=True)


def scratch_preflight():
    def output(*args):
        return subprocess.check_output(args, text=True).strip()

    scratch = Path("/workspaces/.ubuntu-disposable-scratch")
    uuid = "34fdd390-a0dc-49fc-abdf-3ecc56912b05"
    require(output("findmnt", "-rn", "-M", "/workspaces", "-o", "UUID,FSTYPE") == uuid + " ext4", "scratch mount mismatch")
    info = scratch.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "scratch owner/mode/type mismatch")
    require(output("findmnt", "-rn", "-T", str(scratch), "-o", "TARGET,UUID") == "/workspaces " + uuid, "scratch backing mount mismatch")
    return scratch


def characterize(container):
    def request(method, path, body=b"", headers=()):
        return lab.upstream(container, method, path, body, headers)

    status, _, body = request("GET", "/graph/v1.0/me/drives")
    require(status == 200, "personal Space listing failed")
    spaces = [s for s in json.loads(body)["value"] if s.get("driveType") == "personal"]
    require(len(spaces) == 1, "expected one disposable personal Space")
    base = "/dav/spaces/" + quote(spaces[0]["id"], safe="") + "/g3-"

    def put(path, body, headers=()):
        status, _, _ = request("PUT", path, body, headers)
        require(status in (201, 204), "fixture PUT failed: " + str(status))
        return status

    def get(path, expected):
        status, fields, body = request("GET", path)
        tags = [v for k, v in fields if k.lower() == "etag"]
        require(status == 200 and body == expected and len(tags) == 1 and tags[0].startswith('"'), "fixture bytes/strong validator mismatch")
        return tags[0]

    path = base + "file"
    put(path, b"original")
    old = get(path, b"original")
    put(path, b"new-body")
    new = get(path, b"new-body")
    require(old != new, "fixture validator did not change")
    status, _, _ = request("PUT", path, b"must-not-land", [("If-Match", old)])
    require(status == 412, "stale PUT did not reject")
    require(get(path, b"new-body") == new, "stale PUT changed version")
    event(case="stale-put-positive-control", status=status, bytes_preserved=True)

    status, fields, body = request("GET", path, headers=[("Range", "bytes=0-3"), ("If-Match", old), ("If-Range", old), ("Accept-Encoding", "identity")])
    require(status == 206 and body == b"new-" and [v for k, v in fields if k.lower() == "etag"] == [new], "stale range behavior differs from reviewed limitation")
    event(case="stale-range", status=status, returned_current_bytes=True, returned_current_etag=True, safe_version_condition=False)

    status = put(path, b"create-overwrite", [("If-None-Match", "*")])
    get(path, b"create-overwrite")
    require(status == 204, "create-only behavior differs from reviewed limitation")
    event(case="create-only", status=status, overwritten=True, safe_create=False)

    status, _, _ = request("DELETE", path, headers=[("If-Match", old)])
    require(status == 204 and request("GET", path)[0] == 404, "stale DELETE behavior differs from reviewed limitation")
    event(case="stale-delete", status=status, newer_deleted=True, safe_delete=False)

    source, target = base + "source", base + "target"
    require(request("MKCOL", source)[0] == 201, "source collection creation failed")
    put(source + "/child", b"move-source")
    require(request("MKCOL", target)[0] == 201, "target collection creation failed")
    put(target + "/child", b"move-target")
    destination = "https://localhost:9200" + target
    headers = [("Destination", destination), ("Overwrite", "F"), ("If-Match", '"g3-nonexistent-validator"')]
    status, _, _ = request("MOVE", source, headers=headers)
    require(status == 412, "occupied no-overwrite MOVE did not reject")
    get(source + "/child", b"move-source")
    get(target + "/child", b"move-target")
    event(case="move-existing-positive-control", status=status, both_preserved=True)

    # Same stale source condition, now an absent destination. This is the
    # actual directory MOVE operation shape used by the current client.
    destination = "https://localhost:9200" + base + "moved"
    headers[0] = ("Destination", destination)
    status, _, _ = request("MOVE", source, headers=headers)
    require(status == 201, "stale directory MOVE behavior differs from reviewed limitation")
    get(base + "moved/child", b"move-source")
    require(request("GET", source + "/child")[0] == 404, "moved source still exists")
    event(case="stale-directory-move", status=status, moved_despite_false_condition=True, safe_source_condition=False)


def main():
    require(len(sys.argv) == 1, "no arguments accepted; existing servers are forbidden")
    scratch = scratch_preflight()
    image = json.loads(lab.docker("image", "inspect", lab.IMAGE))[0]
    labels = image["Config"]["Labels"]
    require(image["Id"] == lab.IMAGE.split("@", 1)[1] and labels["org.opencontainers.image.version"] == "9.0.0" and labels["org.opencontainers.image.revision"] == REVISION, "cached image provenance mismatch")
    event(image=image["Id"], version="9.0.0", revision=REVISION)
    container = None
    with tempfile.TemporaryDirectory(prefix="g3-http-", dir=scratch) as job:
        Path(job, "tmp").mkdir(mode=0o700)
        if "TMPDIR" not in os.environ:
            os.environ["TMPDIR"] = str(Path(job, "tmp"))
        event(job=job, runner_pid=os.getpid(), runner_start_ticks=Path("/proc/self/stat").read_text().split()[21], host_ports=[])
        try:
            startup = ('p=$(cat /proc/sys/kernel/random/uuid); '
                       'ADMIN_PASSWORD="$p" opencloud init --quiet --insecure true >/dev/null 2>&1 && '
                       'printf "user = \\\"admin:%s\\\"\\ninsecure\\n" "$p" > /etc/opencloud/lab-curl.conf && '
                       'exec opencloud server >/dev/null 2>&1')
            # Use the already-reviewed read-lab startup literal, with generated
            # disposable credentials never emitted to logs or the host.
            container = lab.docker("create", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--no-healthcheck", "--log-driver", "none", "--pids-limit", "256", "--memory", "768m", "--cpus", "1", "--tmpfs", "/etc/opencloud:rw,nosuid,nodev,noexec,size=32m,uid=1000,gid=1000,mode=0700", "--tmpfs", "/var/lib/opencloud:rw,nosuid,nodev,noexec,size=512m,uid=1000,gid=1000,mode=0700", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,uid=1000,gid=1000,mode=0700", "--env", "OC_URL=https://localhost:9200", "--env", "PROXY_ENABLE_BASIC_AUTH=true", "--env", "HTTP_PROXY=", "--env", "HTTPS_PROXY=", "--env", "ALL_PROXY=", "--env", "NO_PROXY=*", "--entrypoint", "/bin/sh", lab.IMAGE, "-c", startup).decode().strip()
            event(container_created=container)
            lab.docker("start", container)
            state = json.loads(lab.docker("inspect", container))[0]
            event(container_pid=state["State"]["Pid"], started_at=state["State"]["StartedAt"], network=state["HostConfig"]["NetworkMode"], host_ports=state["HostConfig"]["PortBindings"])
            binary_version = lab.docker("exec", container, "opencloud", "version", "--skip-services").decode().strip()
            require("Version: 9.0.0" in binary_version, "binary version mismatch")
            event(binary_version=binary_version)
            for _ in range(60):
                try:
                    if lab.upstream(container, "GET", "/graph/v1.0/me/drives")[0] == 200:
                        break
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                require(json.loads(lab.docker("inspect", container))[0]["State"]["Running"], "owned container exited during startup")
                time.sleep(1)
            else:
                raise RuntimeError("owned service readiness timed out")
            characterize(container)
        finally:
            if container:
                lab.docker("rm", "-f", container)
                remaining = lab.docker("ps", "-aq", "--no-trunc", "--filter", "id=" + container).decode().strip()
                require(not remaining, "owned container remains")
                event(container_retired=container, absent=True)
    require(not Path(job).exists(), "owned scratch remains")
    event(scratch_retired=job, absent=True)
    print("G3_PINNED_LIMITATIONS_CHARACTERIZED_NOT_SAFETY_QUALIFIED", flush=True)


if __name__ == "__main__":
    main()

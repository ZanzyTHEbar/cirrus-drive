#!/usr/bin/env python3
"""Probe conflict-sensitive DAV writes on the disposable OpenCloud read-lab server.

This is a safety gate, not an application write test. It exits nonzero if the
server overwrites an existing target on create or deletes a newer version when
given a stale validator. All changes are confined to the isolated container.
"""

import json
from pathlib import Path
import sys
from importlib.machinery import SourceFileLoader
from urllib.parse import quote

sys.dont_write_bytecode = True
lab = SourceFileLoader("opencloud_lab", str(Path(__file__).with_name("check-opencloud-read-lab.py"))).load_module()


def child(container):
    status, _, body = lab.upstream(container, "GET", "/graph/v1.0/me/drives")
    if status != 200:
        raise RuntimeError("cannot list disposable Spaces")
    spaces = [space for space in json.loads(body)["value"] if space.get("driveType") == "personal"]
    if len(spaces) != 1:
        raise RuntimeError("expected one disposable personal Space")
    path = "/dav/spaces/" + quote(spaces[0]["id"], safe="") + "/cirrus-write-safety-probe"
    original = b"cirrus-original-disposable-version"
    changed = b"cirrus-newer-disposable-version"
    status, _, _ = lab.upstream(container, "PUT", path, original)
    if status not in (201, 204):
        raise RuntimeError(f"cannot create disposable fixture: HTTP {status}")
    status, headers, body = lab.upstream(container, "GET", path)
    etag = next((value for name, value in headers if name.lower() == "etag"), None)
    if status != 200 or body != original or not etag or etag.startswith("W/"):
        raise RuntimeError("cannot capture disposable fixture and strong ETag")

    create_status, _, _ = lab.upstream(container, "PUT", path, changed, [("If-None-Match", "*")])
    status, _, body = lab.upstream(container, "GET", path)
    safe_create = create_status == 412 and status == 200 and body == original
    print(f"conditional create: HTTP {create_status}; existing bytes preserved: {status == 200 and body == original}", flush=True)

    # Ensure the delete validator is stale even on servers that reject the
    # preceding create. This remains inside the disposable container.
    status, _, _ = lab.upstream(container, "PUT", path, changed)
    if status not in (200, 201, 204):
        raise RuntimeError(f"cannot update disposable fixture: HTTP {status}")
    status, headers, body = lab.upstream(container, "GET", path)
    newer = next((value for name, value in headers if name.lower() == "etag"), None)
    if status != 200 or body != changed or not newer or newer == etag:
        raise RuntimeError("cannot establish a distinct newer fixture version")
    delete_status, _, _ = lab.upstream(container, "DELETE", path, headers=[("If-Match", etag)])
    status, _, body = lab.upstream(container, "GET", path)
    safe_delete = delete_status == 412 and status == 200 and body == changed
    print(f"conditional delete: HTTP {delete_status}; newer bytes preserved: {status == 200 and body == changed}", flush=True)
    if not safe_create or not safe_delete:
        raise SystemExit("FAIL: server does not provide the required conditional write safety")
    print("PASS: conditional create and stale conditional delete preserved both targets", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        child(sys.argv[4])
    else:
        lab.__file__ = __file__
        lab.main()

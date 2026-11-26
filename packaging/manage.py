#!/usr/bin/env python3
"""Install/remove known user artifacts; never recursively remove user state."""

import hashlib
import fcntl
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import pwd
import re
import secrets
import stat
import subprocess
import sys
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RELEASE_FILES = ("cirrus-drive-service", "cirrus-control-worker", "cirrus-daemon", "cirrus-ui")


def absolute(name, value):
    if not value or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value):
        raise ValueError(f"{name} must be an absolute path without spaces or special characters")
    path = Path(value)
    if ".." in path.parts or path == Path("/"):
        raise ValueError(f"unsafe {name}")
    return path


def locations():
    home = absolute("HOME", os.environ.get("HOME", ""))
    prefix = absolute("PREFIX", os.environ.get("PREFIX", str(home / ".local")))
    dest = os.environ.get("DESTDIR", "")
    dest = absolute("DESTDIR", dest) if dest else None
    def physical(path):
        return dest / path.relative_to("/") if dest else path
    targets = {
        "daemon": physical(prefix / "bin/cirrus-daemon"),
        "service_binary": physical(prefix / "bin/cirrus-drive-service"),
        "ui": physical(prefix / "bin/cirrus-ui"),
        "service": physical(home / ".config/systemd/user/cirrus-drive.service"),
        "desktop": physical(prefix / "share/applications/cirrus-drive.desktop"),
    }
    return home, prefix, dest, physical, targets, physical(prefix / "share/cirrus-drive/install.json")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while block := file.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def notice_name(name):
    path = PurePosixPath(name)
    if (not re.fullmatch(r"[A-Za-z0-9._+@/-]+", name) or path.is_absolute()
            or path.as_posix() != name or ".." in path.parts
            or (name not in ("LICENSE", "THIRD_PARTY_NOTICES.md") and not name.startswith("LICENSES/"))):
        raise ValueError("unsafe notice path")
    return name


def notice_bundle():
    checksum_file = ROOT / "LICENSES/SHA256SUMS"
    contents = {}
    for line in checksum_file.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("invalid notice checksum manifest")
        checksum, name = match.groups()
        notice_name(name)
        if name in contents or name == "LICENSES/SHA256SUMS":
            raise ValueError("duplicate or self-referencing notice checksum")
        path = ROOT / name
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != ROOT and ROOT in parent.parents):
            raise ValueError("notice source contains a symlink")
        data = path.read_bytes()
        if digest(data) != checksum:
            raise ValueError(f"notice source changed: {name}")
        contents[name] = data
    if not {"LICENSE", "THIRD_PARTY_NOTICES.md", "LICENSES/inventory.json", "LICENSES/INDEX.md", "LICENSES/review.json"} <= contents.keys():
        raise ValueError("notice bundle is incomplete")
    contents["LICENSES/SHA256SUMS"] = checksum_file.read_bytes()
    return contents


def notice_targets(prefix, physical, names):
    base = physical(prefix / "share/licenses/cirrus-drive")
    result = {}
    for name in names:
        path = base / notice_name(name)
        current = path.parent
        while current != physical(prefix).parent:
            if current.is_symlink():
                raise ValueError("notice destination contains a symlink")
            current = current.parent
        result["notice:" + name] = path
    return result


def regular(path):
    info = path.lstat()
    return stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1


def create(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        raise


def release_locations(prefix, physical):
    root = physical(prefix / "share/cirrus-drive/releases-v1")
    bootstrap = prefix / "libexec/cirrus-drive"
    return root, {
        "release_trust": root / "trust.ed25519",
        "bootstrap_cli": physical(bootstrap / "cirrus-daemon"),
        "bootstrap_ui": physical(bootstrap / "cirrus-ui"),
    }


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install(args):
    trust = None
    if len(args) == 2 and args[0] == "--trust-key":
        with open(args[1], "rb") as key:
            trust = key.read(33)
        if len(trust) != 32:
            raise ValueError("expected a raw 32-byte Ed25519 public key")
    elif args:
        raise ValueError("usage: install.sh [--trust-key RAW_ED25519_PUBLIC_KEY]")
    _, prefix, _, physical, targets, manifest = locations()
    notices = notice_bundle()
    targets.update(notice_targets(prefix, physical, notices))
    bindir = Path(os.environ.get("CIRRUS_BIN_DIR", str(ROOT / "target/debug")))
    sources = {key: bindir / targets[key].name for key in ("daemon", "service_binary", "ui")}
    if not all(path.is_file() and os.access(path, os.X_OK) for path in sources.values()):
        raise ValueError("build cirrus-daemon, cirrus-drive-service and cirrus-ui before installing")
    for key in ("daemon", "service_binary"):
        capability = subprocess.run([str(sources[key]), "--lab-capabilities"], capture_output=True, text=True, timeout=10)
        if capability.returncode != 2:
            raise ValueError("refusing fault-injection or incompatible Cirrus executable; rebuild without the feature")
    service = (HERE / "cirrus-drive.service").read_text()
    daemon = str(prefix / "bin/cirrus-daemon")
    start = f"{prefix}/bin/cirrus-drive-service"
    desktop = (HERE / "cirrus-drive.desktop").read_text().replace("Exec=cirrus-ui\n", f"Exec={prefix}/bin/cirrus-ui\n")
    contents = {key: path.read_bytes() for key, path in sources.items()}
    modes = {key: 0o755 for key in sources}
    release_root = None
    if trust is not None:
        release_root, added = release_locations(prefix, physical)
        if os.path.lexists(release_root) or release_root.resolve() != release_root:
            raise ValueError("managed release root already exists or has a symlink ancestor")
        targets.update(added)
        logical_root, bootstrap = release_locations(prefix, lambda path: path)
        contents.update(bootstrap_cli=contents["daemon"], bootstrap_ui=contents["ui"], release_trust=trust)
        modes.update(bootstrap_cli=0o755, bootstrap_ui=0o755, release_trust=0o400)
        for role, key in (("cli", "daemon"), ("ui", "ui")):
            contents[key] = (f'#!/bin/sh\nexec {start} --launch-client {logical_root} {role} '
                             f'{bootstrap["bootstrap_" + role]} "$@"\n').encode()
        start += f" --release-root {logical_root}"
        # Stopping must not depend on the health or presence of a selected CLI.
        daemon = str(bootstrap["bootstrap_cli"])
    service = service.replace("ExecStart=cirrus-drive-service\n", f"ExecStart={start}\n")
    service = service.replace("cirrus-daemon --stop", f"{daemon} --stop")
    contents.update(service=service.encode(), desktop=desktop.encode())
    contents.update({"notice:" + name: data for name, data in notices.items()})
    if manifest.exists() or manifest.is_symlink() or any(path.exists() or path.is_symlink() for path in targets.values()):
        raise ValueError("installation target already exists; no existing files were replaced")
    written = []
    release_dirs = []
    try:
        if release_root is not None:
            release_root.parent.mkdir(parents=True, exist_ok=True)
            for path in (release_root, release_root / "releases"):
                path.mkdir(mode=0o700)
                release_dirs.append(path)
                sync_directory(path.parent)
        for key, path in targets.items():
            create(path, contents[key], modes.get(key, 0o644))
            written.append(path)
        record = {key: digest(contents[key]) for key in targets}
        create(manifest, (json.dumps(record, sort_keys=True) + "\n").encode(), 0o600)
    except BaseException:
        for path in reversed(written):
            try:
                path.unlink()
            except OSError:
                pass
        for path in reversed(release_dirs):
            path.rmdir()
        raise
    print("installed user artifacts; enable the user service explicitly if desired")


def stage_release(source, directory):
    def open_input(name):
        fd = os.open(source / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError(f"release input is not a regular file: {name}")
        return os.fdopen(fd, "rb")

    with open_input("manifest.json") as file:
        manifest = file.read(8193)
    with open_input("manifest.sig") as file:
        signature = file.read(65)
    if len(manifest) > 8192 or len(signature) != 64:
        raise ValueError("invalid release metadata size")
    payload = json.loads(manifest)
    release = payload.get("release") if isinstance(payload, dict) else None
    if not isinstance(release, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", release):
        raise ValueError("invalid release ID")
    destination = directory / release
    temporary = directory / (".upload-" + secrets.token_hex(16))
    temporary.mkdir(mode=0o700)
    written = []
    try:
        for name, content in (("manifest.json", manifest), ("manifest.sig", signature)):
            path = temporary / name
            written.append(path)
            create(path, content, 0o400)
        if payload.get("format") == 2:
            with open_input("cirrus-read-engine.json") as file:
                program = file.read(1025)
            if len(program) > 1024:
                raise ValueError("mounted read engine exceeds limit")
            path = temporary / "cirrus-read-engine.json"
            written.append(path)
            create(path, program, 0o400)
        for name in RELEASE_FILES:
            path = temporary / name
            with open_input(name) as file:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
                written.append(path)
                with os.fdopen(fd, "wb") as out:
                    size = 0
                    while data := file.read(1024 * 1024):
                        size += len(data)
                        if size > 1024**3:
                            raise ValueError(f"release artifact exceeds limit: {name}")
                        out.write(data)
                    out.flush()
                    os.fsync(out.fileno())
        temporary.chmod(0o500)
        sync_directory(temporary)
        fd = os.open(directory, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if os.path.lexists(destination):
                raise ValueError(f"release ID already staged: {release}; never replaced")
            os.rename(temporary, destination)
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary.exists():
            temporary.chmod(0o700)
            for path in written:
                path.unlink(missing_ok=True)
            temporary.rmdir()
    return release


def release(args, *, activate=True):
    if len(args) != 1:
        command = "release" if activate else "stage-release"
        raise ValueError(f"usage: manage.py {command} SIGNED_BUNDLE_DIRECTORY")
    _, prefix, dest, physical, targets, manifest = locations()
    root, managed = release_locations(prefix, physical)
    if dest or not regular(manifest) or root.resolve() != root:
        raise ValueError("live release requires an installed, signed user-managed prefix")
    record = json.loads(manifest.read_text())
    if not isinstance(record, dict):
        raise ValueError("unrecognized installation manifest")
    targets.update(managed)
    for key in ("release_trust", "bootstrap_cli", "daemon", "service_binary", "ui", "service"):
        path = targets[key]
        if not regular(path) or file_digest(path) != record.get(key):
            raise ValueError(f"installed {key} is unmanaged or changed; no release activated")
    for path in (root, root / "releases"):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("release root is not a private installation directory")
    cli = managed["bootstrap_cli"]
    status = subprocess.run([cli, "--release-status"], capture_output=True, text=True, timeout=10)
    if status.returncode:
        raise ValueError(f"resident did not negotiate live activation: {status.stderr.strip()}")
    status = json.loads(status.stdout)
    info = root.stat()
    if not status["managed"] or status["installation"] != f"{info.st_dev}:{info.st_ino}":
        raise ValueError("running resident belongs to a different or unmanaged installation")
    candidate = stage_release(Path(args[0]), root / "releases")
    if not activate:
        print(f"staged {candidate}; no resident selection changed")
        return
    print(f"staged {candidate}; asking resident to verify and activate", file=sys.stderr, flush=True)
    result = subprocess.run([cli, "--activate-release", candidate], timeout=125)
    if result.returncode:
        raise ValueError("activation not confirmed; inspect --release-status (no service restart attempted)")


def verify_mount_inventory(output):
    """Check the installed daemon's JSON Lines MountInfo inventory."""
    if not output:
        return  # The CLI prints nothing for an empty inventory.

    unverifiable = "cannot verify mount inventory; daemon and files preserved"
    required = {"instance", "space_id", "space_name", "path", "state"}
    optional = {"offline_read_only", "offline_writable"}
    paths, spaces = set(), set()

    def unique_fields(pairs):
        row = dict(pairs)
        if len(row) != len(pairs):
            raise ValueError("duplicate JSON field")
        return row

    for line in output.removesuffix("\n").split("\n"):
        try:
            row = json.loads(line, object_pairs_hook=unique_fields)
            if (not isinstance(row, dict) or not required <= row.keys()
                    or row.keys() - required - optional
                    or any(not isinstance(row[key], str) or not row[key] or "\0" in row[key]
                           for key in required)
                    or any(type(row[key]) is not bool for key in optional & row.keys())):
                raise ValueError("invalid mount row")
            url = row["instance"]
            instance = urlsplit(url)
            # Rust treats repeated leading slashes as the same absolute path.
            path = Path(re.sub(r"^/+", "/", row["path"]))
            space = (url, row["space_id"])
            if (instance.scheme != "https" or not instance.hostname
                    or instance.username is not None or re.search(r"[\s?#\\]", url)
                    or not path.is_absolute() or ".." in path.parts
                    or path in paths or space in spaces
                    or (row.get("offline_read_only") and row.get("offline_writable"))):
                raise ValueError("invalid or ambiguous mount identity")
        except (ValueError, RecursionError):
            raise ValueError(unverifiable) from None
        if row["state"] == "RecoveryRequired":
            raise ValueError("mount recovery required; inspect it before uninstalling")
        if row["state"] != "Mounted":
            raise ValueError(unverifiable)
        paths.add(path)
        spaces.add(space)


def stop_daemon(daemon, dest, home):
    if dest or home != Path(pwd.getpwuid(os.geteuid()).pw_dir):
        return
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        raise ValueError("XDG_RUNTIME_DIR is required to verify daemon and mount state")
    runtime = absolute("XDG_RUNTIME_DIR", runtime)
    socket = "cirrus-drive.sock"
    # Check entry names without following symlinks, and propagate listing errors.
    entries = {path.name for path in runtime.iterdir()}
    if socket in entries:
        if not regular(daemon) or not os.access(daemon, os.X_OK):
            raise ValueError("cannot verify or stop the running daemon")
        status = subprocess.run([str(daemon), "--mounts"], capture_output=True, encoding="utf-8", timeout=20)
        if status.returncode or status.stderr:
            raise ValueError("cannot verify mount inventory; daemon and files preserved")
        verify_mount_inventory(status.stdout)
        stop = subprocess.run([str(daemon), "--stop"], capture_output=True, text=True, timeout=40)
        if stop.returncode:
            raise ValueError("daemon did not stop safely; files preserved")
        entries = {path.name for path in runtime.iterdir()}
        if socket in entries:
            raise ValueError("daemon did not stop safely; files preserved")
    # The daemon reserves this prefix, including the legacy singleton name.
    if any(name.startswith("cirrus-drive.mount") for name in entries):
        raise ValueError("mount recovery record exists; inspect it before uninstalling")


def uninstall(args):
    if args:
        raise ValueError("usage: uninstall.sh")
    home, prefix, dest, physical, targets, manifest = locations()
    if not regular(manifest):
        raise ValueError("installation manifest is missing or unsafe")
    record = json.loads(manifest.read_text())
    if not isinstance(record, dict):
        raise ValueError("unrecognized installation manifest")
    # Use installed ownership, not the current checkout's possibly newer bundle.
    # Historical four-file installs remain removable without claiming notices.
    if "service_binary" not in record:
        targets.pop("service_binary")
    if "release_trust" in record:
        _, managed = release_locations(prefix, physical)
        targets.update(managed)
    targets.update(notice_targets(prefix, physical, [key.removeprefix("notice:") for key in record if key.startswith("notice:")]))
    if set(record) != set(targets):
        raise ValueError("unrecognized installation manifest")
    for key, path in targets.items():
        if not regular(path) or digest(path.read_bytes()) != record[key]:
            raise ValueError(f"installed {key} changed or is missing; no files removed")
    stop_daemon(targets.get("bootstrap_cli", targets["daemon"]), dest, home)
    for path in targets.values():
        path.unlink()
    manifest.unlink()
    print("removed installed artifacts; state and keyring preserved")
    if "release_trust" in record:
        print("versioned release files preserved; archive the old release directory before reinstalling")


if __name__ == "__main__":
    try:
        commands = {
            "install": install,
            "uninstall": uninstall,
            "release": release,
            "stage-release": lambda args: release(args, activate=False),
        }
        if len(sys.argv) < 2 or sys.argv[1] not in commands:
            raise ValueError("expected install, uninstall, release or stage-release")
        commands[sys.argv[1]](sys.argv[2:])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"cirrus packaging: {error}", file=sys.stderr)
        raise SystemExit(1)

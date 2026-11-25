#!/usr/bin/env python3
"""Exercise install and conservative uninstall in a disposable DESTDIR."""

import os
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def check_daemon_shutdown(packaging, root, home, daemon):
    stop_daemon = runpy.run_path(str(packaging / "manage.py"))["stop_daemon"]
    runtime = root / "shutdown-runtime"
    runtime.mkdir(mode=0o700)
    socket = runtime / "cirrus-drive.sock"
    mounts_cmd, stop_cmd = [str(daemon), "--mounts"], [str(daemon), "--stop"]
    active = {"instance": "https://cloud.invalid/", "space_id": "one", "space_name": "One",
              "path": "/mnt/one", "state": "Mounted", "offline_read_only": False, "offline_writable": False}
    second = dict(active, space_id="two", space_name="Two", path="/mnt/two")

    def inventory(*rows):
        return "".join(json.dumps(row) + "\n" for row in rows)

    def refused(message):
        try:
            stop_daemon(daemon, None, home)
        except ValueError as error:
            assert message in str(error), error
        else:
            raise AssertionError("unsafe daemon shutdown accepted")

    def stop(command, **kwargs):
        assert command == stop_cmd
        socket.unlink()
        return subprocess.CompletedProcess(command, 0, "", "")

    with (patch.dict(os.environ, XDG_RUNTIME_DIR=str(runtime)),
          patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(home))),
          patch("subprocess.run") as run):
        for output in ("", inventory(active, second)):
            socket.touch()
            run.reset_mock(side_effect=True)
            run.side_effect = lambda command, **kwargs: (
                subprocess.CompletedProcess(command, 0, output, "") if command == mounts_cmd
                else stop(command, **kwargs))
            stop_daemon(daemon, None, home)
            assert [call.args[0] for call in run.call_args_list] == [mounts_cmd, stop_cmd]
            assert not socket.exists()

        socket.touch()
        recovery = dict(active, state="RecoveryRequired")
        for code, output, message in (
            (0, inventory(second, recovery), "mount recovery required"),
            (0, inventory(active) + "not JSON\n", "cannot verify mount inventory"),
            (0, inventory(active, dict(second, path=active["path"])), "cannot verify mount inventory"),
            (1, "", "cannot verify mount inventory"),
        ):
            run.reset_mock(side_effect=True)
            run.return_value = subprocess.CompletedProcess(mounts_cmd, code, output, "")
            refused(message)
            assert [call.args[0] for call in run.call_args_list] == [mounts_cmd]
            assert socket.exists()

        run.reset_mock()
        run.side_effect = [subprocess.CompletedProcess(mounts_cmd, 0, inventory(active), ""),
                           subprocess.CompletedProcess(stop_cmd, 0, "", "")]
        refused("daemon did not stop safely")
        assert [call.args[0] for call in run.call_args_list] == [mounts_cmd, stop_cmd]
        socket.unlink()

        run.reset_mock()
        legacy = runtime / "cirrus-drive.mount"
        per_mount = runtime / ("cirrus-drive.mount-" + "0" * 32)
        legacy.write_text("preserve")
        refused("mount recovery record exists")
        assert legacy.read_text() == "preserve"
        legacy.unlink()
        per_mount.symlink_to(runtime / "missing")
        refused("mount recovery record exists")
        assert per_mount.readlink() == runtime / "missing"
        run.assert_not_called()
    print("PASS: mocked daemon inventory, managed shutdown, and recovery guard")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notice-fixtures", action="store_true", help="test packaging only with explicitly disposable shell binaries, not a qualified release pair")
    parser.add_argument("--bin-dir", type=Path, help="explicit real normal service/CLI/UI builds, including notice recipe-image staging")
    args = parser.parse_args()
    if args.notice_fixtures and args.bin_dir:
        parser.error("select disposable fixtures or an explicit real pair, not both")
    notice_fixtures = args.notice_fixtures
    # Respect the caller's TMPDIR; host-specific admission belongs to the caller.
    with tempfile.TemporaryDirectory(prefix="cirrus-packaging-") as temp:
        root = Path(temp)
        if args.notice_fixtures or args.bin_dir:
            (root / "tmp").mkdir(mode=0o700)
            print(f"OWNED NOTICE PACKAGING: root={root}; binaries={'disposable fixtures' if args.notice_fixtures else 'explicit normal pair'}; no services", flush=True)
        home = "/home/cirrus-lab"
        env = dict(os.environ, HOME=home, PREFIX=home + "/.local", DESTDIR=str(root / "image"))
        if args.notice_fixtures or args.bin_dir:
            env["TMPDIR"] = str(root / "tmp")
        env.pop("CIRRUS_BIN_DIR", None)
        if os.environ.get("CARGO_TARGET_DIR"):
            target = Path(os.environ["CARGO_TARGET_DIR"])
            env["CIRRUS_BIN_DIR"] = str((target if target.is_absolute() else ROOT / target) / "debug")
        if args.bin_dir:
            env["CIRRUS_BIN_DIR"] = str(args.bin_dir.resolve(strict=True))
        packaging = ROOT / "packaging"
        if args.notice_fixtures:
            if os.environ.get("CIRRUS_TEST_PACKAGING_INPUT_LEASE"):
                raise ValueError("notice fixtures do not support the native input-lease diagnostic")
            fixture = root / "fixture-repo"
            shutil.copytree(ROOT / "packaging", fixture / "packaging", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(ROOT / "LICENSES", fixture / "LICENSES")
            for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
                shutil.copy2(ROOT / name, fixture / name)
            packaging = fixture / "packaging"
            binaries = root / "fixture-binaries"
            binaries.mkdir()
            for name in ("cirrus-daemon", "cirrus-drive-service", "cirrus-ui"):
                binary = binaries / name
                binary.write_text('#!/bin/sh\n# Disposable packaging-contract fixture; not Cirrus.\nexit 2\n')
                binary.chmod(0o700)
            env["CIRRUS_BIN_DIR"] = str(binaries)

        evidence = os.environ.get("CIRRUS_TEST_PACKAGING_EVIDENCE")
        output = Path(evidence) / root.name if evidence else None
        if output:
            output.mkdir(mode=0o700, parents=True, exist_ok=False)
        sequence = 0
        timeout_release = None

        def proc_state(pid):
            result = {"pid": pid}
            for name in ("stat", "status", "wchan", "syscall", "stack", "cmdline", "task/" + str(pid) + "/children"):
                try:
                    with (Path("/proc") / str(pid) / name).open("rb") as file:
                        result[name] = file.read(32768).decode(errors="replace").replace("\0", " ")
                except OSError as error:
                    result[name] = {"errno": error.errno}
            if isinstance(result.get("stat"), str):
                result["start_ticks"] = result["stat"].rsplit(")", 1)[1].split()[19]
            result["fds"] = {}
            try:
                for descriptor in (Path("/proc") / str(pid) / "fd").iterdir():
                    try:
                        result["fds"][descriptor.name] = os.readlink(descriptor)
                    except OSError as error:
                        result["fds"][descriptor.name] = {"errno": error.errno}
            except OSError as error:
                result["fd_error"] = error.errno
            return result

        def filesystem_state():
            # Fixed, fixture-owned paths only; never inspect a user's live home.
            base = root / "image" / home.lstrip("/")
            names = (".local/bin/cirrus-daemon", ".local/bin/cirrus-drive-service", ".local/bin/cirrus-ui",
                     ".config/systemd/user/cirrus-drive.service",
                     ".local/share/applications/cirrus-drive.desktop",
                     ".local/share/cirrus-drive/install.json",
                     ".local/state/cirrus-drive/state.db", ".local/state/cirrus-drive/cache.db",
                     ".local/share/keyrings/keep")
            result = {}
            for name in names:
                path = base / name
                try:
                    stat = path.lstat()
                    row = {"size": stat.st_size, "mode": stat.st_mode, "inode": stat.st_ino,
                           "mtime_ns": stat.st_mtime_ns}
                    # Large executable hashes could themselves block timeout capture.
                    if path.is_file() and stat.st_size <= 1024 * 1024:
                        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    result[name] = row
                except FileNotFoundError:
                    result[name] = None
            return result

        def run(name, *args):
            nonlocal sequence
            command = [str(packaging / name), *args]
            if output is None:
                started = time.monotonic()
                result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
                if notice_fixtures:
                    print(f"NOTICE FIXTURE STEP: {name} {' '.join(args)} exit={result.returncode} elapsed={time.monotonic() - started:.2f}s", flush=True)
                return result
            sequence += 1
            started = time.monotonic()
            record = {"command": command, "root": str(root), "time_ns": time.time_ns(),
                      "before": filesystem_state()}
            with subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) as process:
                record["launched"] = proc_state(process.pid)
                print(f"OWNED packaging: root={root} pid={process.pid} start_ticks={record['launched'].get('start_ticks')} step={sequence} command={name}", flush=True)
                try:
                    stdout, stderr = process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    record["timeout_process"] = proc_state(process.pid)
                    children = record["timeout_process"].get("task/" + str(process.pid) + "/children")
                    if isinstance(children, str):
                        record["timeout_children"] = [proc_state(int(pid)) for pid in children.split()]
                    record["timeout_files"] = filesystem_state()
                    record["timeout_elapsed"] = time.monotonic() - started
                    process.kill()
                    if timeout_release is not None:
                        # Retire the controlled kernel barrier before waiting
                        # for the killed owner; never make cleanup await itself.
                        timeout_release()
                    stdout, stderr = process.communicate()
                    record["stdout"], record["stderr"] = stdout, stderr
                    raise
                finally:
                    record["elapsed"] = time.monotonic() - started
                    record["returncode"] = process.returncode
                    record["after"] = filesystem_state()
                    (output / f"{sequence:02}-{name}.json").write_text(json.dumps(record, indent=2))
                return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

        def success(result):
            if result.returncode:
                raise RuntimeError(result.stderr)

        if args.notice_fixtures:
            fixture_daemon = binaries / "cirrus-drive-service"
            normal_fixture = fixture_daemon.read_bytes()
            fixture_daemon.write_text('#!/bin/sh\necho "cirrus-drive disposable account and mount lab v1"\nexit 0\n')
            assert run("install.sh").returncode != 0, "fault-capability fixture accepted"
            fixture_daemon.write_bytes(normal_fixture)
            source_notice = next((fixture / "LICENSES/texts").iterdir())
            original = source_notice.read_bytes()
            source_notice.unlink()
            assert run("install.sh").returncode != 0, "missing source notice accepted"
            source_notice.write_bytes(b"corrupt notice\n")
            assert run("install.sh").returncode != 0, "corrupt source notice accepted"
            source_notice.write_bytes(original)
            assert not (root / "image" / home.lstrip("/") / ".local/bin/cirrus-daemon").exists()

        success(run("install.sh"))
        base = root / "image" / home.lstrip("/")
        daemon = base / ".local/bin/cirrus-daemon"
        service = base / ".config/systemd/user/cirrus-drive.service"
        assert daemon.is_file() and os.access(daemon, os.X_OK)
        assert "ExecStart=/home/cirrus-lab/.local/bin/cirrus-drive-service" in service.read_text().splitlines()
        assert os.access(base / ".local/bin/cirrus-drive-service", os.X_OK)
        notice_dir = base / ".local/share/licenses/cirrus-drive"
        expected_notices = {name: (ROOT / name).read_bytes() for name in ("LICENSE", "THIRD_PARTY_NOTICES.md")}
        expected_notices.update({"LICENSES/" + p.relative_to(ROOT / "LICENSES").as_posix(): p.read_bytes()
                                 for p in (ROOT / "LICENSES").rglob("*") if p.is_file()})
        for name, data in expected_notices.items():
            assert (notice_dir / name).read_bytes() == data, name
        installed = json.loads((base / ".local/share/cirrus-drive/install.json").read_text())
        assert {key.removeprefix("notice:") for key in installed if key.startswith("notice:")} == set(expected_notices)
        if args.notice_fixtures:
            check_daemon_shutdown(packaging, root, base, daemon)
            installed_notice = notice_dir / "THIRD_PARTY_NOTICES.md"
            original = installed_notice.read_bytes()
            installed_notice.write_text("changed by user")
            assert run("uninstall.sh").returncode != 0 and daemon.exists(), "modified installed notice was removed"
            installed_notice.write_bytes(original)
            # A later checkout must not strand an older installed notice inventory.
            sums = fixture / "LICENSES/SHA256SUMS"
            original_sums = sums.read_bytes()
            sums.write_bytes(b"later checkout (not used by uninstall)\n")
            success(run("uninstall.sh"))
            assert all(not (notice_dir / name).exists() for name in expected_notices)
            sums.write_bytes(original_sums)
            success(run("install.sh"))
            unknown_notice = notice_dir / "user-owned.keep"
            unknown_notice.write_text("preserve")
            # Existing notice collision must refuse even if the install manifest is gone.
            manifest = base / ".local/share/cirrus-drive/install.json"
            manifest_bytes = manifest.read_bytes()
            manifest.unlink()
            assert run("install.sh").returncode != 0
            manifest.write_bytes(manifest_bytes)
            manifest.chmod(0o600)
        if args.notice_fixtures or args.bin_dir:
            arch_notices = check_arch_notice_fixture(root, env)
            verified = subprocess.run(["python3", str(ROOT / "scripts/check-third-party-notices.py"), "--packaging-content",
                                       "--user-notices-dir", str(notice_dir), "--arch-notices-dir", str(arch_notices)],
                                      capture_output=True, text=True, timeout=60, env=dict(os.environ, TMPDIR=str(root / "tmp")))
            success(verified)
            print(verified.stdout.strip())
            if output:
                summary = {
                    "qualification": "disposable shell binaries and actual recipe image; not makepkg or a normal release" if args.notice_fixtures else "explicit normal binaries and actual recipe image; not makepkg or broad release qualification",
                    "root": str(root), "user_notices": str(notice_dir), "arch_notices": str(arch_notices),
                    "notice_contents_verified": True, "state_preservation_suite_passed": False,
                    "notice_file_count": len(expected_notices),
                    "source_archive_sha256": hashlib.sha256((root / "arch-source/cirrus-notices.tar.gz").read_bytes()).hexdigest(),
                    "recipe_image_archive_sha256": hashlib.sha256((root / "arch-recipe-image.tar.gz").read_bytes()).hexdigest(),
                    "fixture_binaries" if args.notice_fixtures else "normal_binaries": {
                        name: hashlib.sha256((Path(env["CIRRUS_BIN_DIR"]) / name).read_bytes()).hexdigest()
                        for name in ("cirrus-daemon", "cirrus-drive-service", "cirrus-ui")},
                    "inputs": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                               ("packaging/manage.py", "packaging/arch/PKGBUILD", "scripts/check-packaging-lab.py",
                                "scripts/check-third-party-notices.py", "LICENSES/inventory.json", "LICENSES/SHA256SUMS")},
                }
                (output / "notice-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        before = daemon.read_bytes()
        assert run("install.sh").returncode != 0 and daemon.read_bytes() == before
        keyring = base / ".local/share/keyrings/keep"
        keyring.parent.mkdir(parents=True)
        state = base / ".local/state/cirrus-drive"
        state.mkdir(parents=True, mode=0o700)
        sentinels = {state / "state.db": b"preserve state", state / "cache.db": b"preserve cache",
                     keyring: b"preserve keyring"}
        for path, data in sentinels.items():
            path.write_bytes(data)

        installed_state = filesystem_state()
        refused = run("uninstall.sh", "--purge-clean-state")
        assert refused.returncode != 0 and "usage: uninstall.sh" in refused.stderr, refused.stderr
        assert filesystem_state() == installed_state, "rejected uninstall changed install/state/keyring files"

        success(run("uninstall.sh"))
        for path, data in sentinels.items():
            assert path.read_bytes() == data, f"uninstall changed {path.name}"
        assert all(row is None for name, row in filesystem_state().items() if base / name not in sentinels), "owned artifacts remain after uninstall"
        assert all(not (notice_dir / name).exists() for name in expected_notices), "owned notices remain after uninstall"
        if args.notice_fixtures:
            assert unknown_notice.read_text() == "preserve", "unrecognized notice file removed"

        if os.environ.get("CIRRUS_TEST_PACKAGING_INPUT_LEASE") == "1":
            if output is None:
                raise RuntimeError("controlled input lease requires private packaging evidence")
            # Only complete copies of the actual matching binaries, never a fake
            # executable or a lease on the repository/installed target.
            source = Path(env.get("CIRRUS_BIN_DIR", ROOT / "target/debug"))
            bindir = root / "leased-binaries"
            bindir.mkdir(mode=0o700)
            for name in ("cirrus-daemon", "cirrus-drive-service", "cirrus-ui"):
                shutil.copy2(source / name, bindir / name)
            previous_bindir = env.get("CIRRUS_BIN_DIR")
            env["CIRRUS_BIN_DIR"] = str(bindir)
            break_requested = threading.Event()
            previous_handler = signal.signal(signal.SIGIO, lambda *_: break_requested.set())
            preserved = filesystem_state()
            try:
                with (bindir / "cirrus-ui").open("r+b") as leased:
                    fcntl.fcntl(leased, fcntl.F_SETOWN, os.getpid())
                    fcntl.fcntl(leased, fcntl.F_SETLEASE, fcntl.F_WRLCK)
                    lease_held = [True]
                    def release_lease():
                        if lease_held[0]:
                            fcntl.fcntl(leased, fcntl.F_SETLEASE, fcntl.F_UNLCK)
                            lease_held[0] = False
                    timeout_release = release_lease
                    try:
                        try:
                            run("install.sh")
                        except subprocess.TimeoutExpired:
                            assert break_requested.is_set(), "timeout was not at the owned input lease"
                        else:
                            raise AssertionError("installer bypassed a real write lease on its UI input")
                        assert filesystem_state() == preserved, "input-read timeout changed install/state/keyring files"
                    finally:
                        release_lease()
            finally:
                timeout_release = None
                signal.signal(signal.SIGIO, previous_handler)
                if previous_bindir is None:
                    env.pop("CIRRUS_BIN_DIR", None)
                else:
                    env["CIRRUS_BIN_DIR"] = previous_bindir
            print("PASS CONTROL: actual owned UI input lease causes the unchanged 30s installer timeout before output creation; state and keyring sentinels unchanged; child reaped and lease released (not attribution of historical timeout)", flush=True)
        if args.notice_fixtures or args.bin_dir:
            if output:
                summary["state_preservation_suite_passed"] = True
                (output / "notice-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print("NOTICE PACKAGING FIXTURES VERIFIED (not normal binaries or makepkg qualification)" if args.notice_fixtures else
                  "NORMAL BINARIES NOTICE PACKAGING VERIFIED (not makepkg or broad release qualification)")
        print("PASS: isolated install and uninstall; state and keyring preserved")


def check_arch_notice_fixture(root, env):
    """Run the actual package() function, archive/extract its image; no makepkg substitute claim."""
    source = root / "arch-source"
    source.mkdir()
    for name in ("cirrus-daemon", "cirrus-drive-service", "cirrus-ui"):
        shutil.copy2(Path(env["CIRRUS_BIN_DIR"]) / name, source / name)
    for name in ("cirrus-drive.service", "cirrus-drive.desktop"):
        shutil.copy2(ROOT / "packaging" / name, source / name)
    archive = source / "cirrus-notices.tar.gz"
    subprocess.run(["python3", str(ROOT / "scripts/check-third-party-notices.py"), "--archive", str(archive)], check=True, timeout=60,
                   env=dict(os.environ, TMPDIR=str(root / "tmp")))
    with tarfile.open(archive) as tar:
        tar.extractall(source, filter="data")
    recipe_env = dict(env, CIRRUS_GLIBC_MIN=os.environ.get("CIRRUS_GLIBC_MIN", "0"), srcdir=str(source), pkgdir=str(root / "arch-image"))
    for variable, name in (("DAEMON", "cirrus-daemon"), ("SERVICE_BINARY", "cirrus-drive-service"), ("UI", "cirrus-ui"), ("SERVICE", "cirrus-drive.service"),
                           ("DESKTOP", "cirrus-drive.desktop"), ("NOTICES", "cirrus-notices.tar.gz")):
        recipe_env[f"CIRRUS_{variable}_SHA256"] = hashlib.sha256((source / name).read_bytes()).hexdigest()
    script = '''set -euo pipefail
error() { printf '%s\\n' "$*" >&2; }
source "$1"
for ((i=0; i<${#source[@]}; i++)); do
  actual=$(sha256sum "$srcdir/${source[$i]}")
  [[ ${actual%% *} == "${sha256sums[$i]}" ]] || exit 1
done
package
'''
    def package():
        return subprocess.run(["bash", "-c", script, "cirrus-notice-fixture", str(ROOT / "packaging/arch/PKGBUILD")],
                              env=recipe_env, capture_output=True, text=True, timeout=30)
    damaged = source / "cirrus-notices/THIRD_PARTY_NOTICES.md"
    original = damaged.read_bytes()
    damaged.unlink()
    assert package().returncode != 0, "Arch recipe accepted omitted notice"
    damaged.write_bytes(b"corrupt notice\n")
    assert package().returncode != 0, "Arch recipe accepted corrupted notice"
    damaged.write_bytes(original)
    result = package()
    if result.returncode:
        raise RuntimeError(result.stderr)
    image_archive = root / "arch-recipe-image.tar.gz"
    with tarfile.open(image_archive, "w:gz") as tar:
        tar.add(root / "arch-image", arcname=".")
    extraction = root / "arch-extracted"
    with tarfile.open(image_archive) as tar:
        tar.extractall(extraction, filter="data")
    print("ARCH RECIPE IMAGE: actual package() staging archived/extracted; makepkg not run; image sha256=" +
          hashlib.sha256(image_archive.read_bytes()).hexdigest())
    return extraction / "usr/share/licenses/cirrus-drive"


if __name__ == "__main__":
    main()

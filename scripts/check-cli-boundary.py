#!/usr/bin/env python3
"""Ensure the terminal package cannot link the service or account/FUSE owners."""

import json
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parent.parent
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"],
        cwd=root,
    ))
    packages = {package["name"]: package for package in metadata["packages"]}

    def local_dependencies(name):
        return {
            dep["name"] for dep in packages[name]["dependencies"]
            if dep.get("path") is not None and dep["kind"] != "dev"
        }

    assert local_dependencies("cirrus-cli") == {"cirrus-client"}
    assert local_dependencies("cirrus-client") == {"cirrus-api", "cirrus-discovery", "cirrus-runtime"}
    for name in ("cirrus-api", "cirrus-discovery", "cirrus-runtime"):
        assert not local_dependencies(name), name

    for package, binaries in (
        ("cirrus-cli", {"cirrus-daemon"}),
        ("cirrus-daemon", {"cirrus-drive-service", "cirrus-control-worker"}),
    ):
        targets = {target["name"] for target in packages[package]["targets"] if "bin" in target["kind"]}
        assert targets == binaries, (package, targets)
    print("CLI dependency boundary and separate service entrypoint verified")


if __name__ == "__main__":
    main()

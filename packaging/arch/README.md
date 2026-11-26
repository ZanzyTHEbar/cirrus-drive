# Experimental Arch package

This recipe packages **locally built release binaries**, not a source release.
It is intended for the same machine or an ABI-compatible machine; a package
built against a newer glibc can fail on an older system. Use only disposable
data: Cirrus is not production-safe. The package does not start or enable the
service and never removes account state, pins, journal entries or credentials.
The recipe includes a checksum-pinned third-party notice bundle. Distribution
qualification is still incomplete: resolve `LICENSES/review.json`, establish
the matching release binaries' build/linkage provenance and verify real package
contents before distributing. Disposable packaging fixtures do not qualify a
release, and the notice inventory is not a legal compatibility guarantee.

Build `cirrus-daemon`, `cirrus-drive-service`, and `cirrus-ui` in release mode with `--locked` and
without fault-injection features. In a new private build directory, copy this
`PKGBUILD`, those executables, and the project's `cirrus-drive.service`
and `cirrus-drive.desktop` templates. From the matching reviewed source checkout,
create the notice source (the output must not already exist):

```sh
python3 scripts/check-third-party-notices.py --archive cirrus-notices.tar.gz
```

Copy `cirrus-notices.tar.gz` into the build directory too. It contains the
public notice bundle, not private gate reports. Verify the binaries on the destination
with `ldd -r` and `--version` before packaging. Record checksums from the
trusted build, then run `makepkg` with these variables set to the corresponding
SHA-256 hex digests: `CIRRUS_DAEMON_SHA256`, `CIRRUS_SERVICE_BINARY_SHA256`, `CIRRUS_UI_SHA256`,
`CIRRUS_SERVICE_SHA256`, `CIRRUS_DESKTOP_SHA256`, and `CIRRUS_NOTICES_SHA256`
(the notice archive digest reported by the command). The recipe verifies all
six sources, checks the bundle's internal file digests, installs notices under
`/usr/share/licenses/cirrus-drive/`, and rejects a fault-injection daemon.
Set `CIRRUS_GLIBC_MIN` to
the highest `GLIBC_` version required by any binary, as shown by
`readelf --version-info`; this becomes the package's minimum glibc dependency.

Inspect the package contents and dependencies before installing with
`sudo pacman -U /path/to/cirrus-drive-0.1.0-4-x86_64.pkg.tar.zst`.
Before upgrading or removing the package, follow the unmount and stop steps in
[Stop, uninstall or upgrade](../../README.md#stop-uninstall-or-upgrade) using the
installed client that matches the running service. Use pacman, not the user-local
uninstall script, to remove the package.
The packaged unit does not opt in to user-managed release activation. Cirrus
does not replace package-owned artifacts or restart the unit for live updates.
Pacman cannot manage a previous per-user install. In particular,
`~/.local/bin/cirrus-*`, a user unit in `~/.config/systemd/user`, and a desktop
file in `~/.local/share/applications` take precedence over the packaged files.
Do not remove or replace those files unless their ownership and contents are
known and the daemon and mounts are safely stopped. Preserve the user's state
and keyring. Resolve such a prior installation before using this package.

After installation and resolving any older user unit, run
`systemctl --user daemon-reload` and explicitly start or enable the service as
desired. Use a disposable server, account, files and empty mountpoint when
testing; starting the service does not itself set up an account.

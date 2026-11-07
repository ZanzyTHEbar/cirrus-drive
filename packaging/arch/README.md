# Experimental Arch package

This recipe packages **locally built release binaries**, not a source release.
It is intended for the same machine or an ABI-compatible machine; a package
built against a newer glibc can fail on an older system. Use only disposable
data: Cirrus is not production-safe. The package does not start or enable the
service and never removes account state, pins, journal entries or credentials.
The recipe does not yet include a complete set of third-party license notices;
review and supply the required notices before distributing the package.

Build `cirrus-daemon` and `cirrus-ui` in release mode with `--locked` and
without fault-injection features. In a new private build directory, copy this
`PKGBUILD`, those two executables, and the project's `cirrus-drive.service`
and `cirrus-drive.desktop` templates. Verify the binaries on the destination
with `ldd -r` and `--version` before packaging. Record checksums from the
trusted build, then run `makepkg` with these variables set to the corresponding
SHA-256 hex digests: `CIRRUS_DAEMON_SHA256`, `CIRRUS_UI_SHA256`,
`CIRRUS_SERVICE_SHA256`, and `CIRRUS_DESKTOP_SHA256`. The recipe verifies all
four sources and rejects a fault-injection daemon. Set `CIRRUS_GLIBC_MIN` to
the highest `GLIBC_` version required by either binary, as shown by
`readelf --version-info`; this becomes the package's minimum glibc dependency.

Inspect the package contents and dependencies before installing with
`sudo pacman -U /path/to/cirrus-drive-0.1.0-2-x86_64.pkg.tar.zst`.
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

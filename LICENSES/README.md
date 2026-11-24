# License bundle maintenance

Ship the project's `LICENSE`, `THIRD_PARTY_NOTICES.md` and the entire
`LICENSES/` directory together.
The [index](INDEX.md) links upstream texts; [inventory.json](inventory.json)
records their origins, checksums and dependency roles. Texts are unmodified;
source-header and XML copyright excerpts retain the original bytes. Duplicate
texts share a content-addressed file. Rust's HTML notice and companion
`licenses/` files retain their toolchain layout. No SPDX identifier is used as
a substitute for license text.

## Offline checks

With Python 3.11+, the pinned Rust toolchain and cached locked sources:

```sh
python3 scripts/check-third-party-notices.py --verify
python3 scripts/check-third-party-notices.py --complete
```

These commands do not compile or download dependencies. Verification compares
the graph, manifests, lockfile and retained texts to cached sources. Registry
archives must match `Cargo.lock`; copied source texts must match those archives.
Git texts must match the pinned revision. Missing cached inputs fail closed.
Generated-input provenance uses published source revisions, recorded immutable
upstream tree entries/submodule pins and exact compressed source bytes. The
offline check verifies published generated outputs against that snapshot and
extracts notices from the recorded inputs; it does not rerun the generators.
`native-linkage.json` is explicitly historical-only. It binds its binary hashes to
their project-file content hashes, ELF/link-map observations and original
installed-package copyright/license documents. It separates actual ELF
dependencies from possible runtime loaders; it is not an inference that every
archive member or available shared library is used. Verification fails if the
historical record or native license text bytes change, using the independent
`review.json` historical-native SHA-256 anchor. Historical project hashes are
not compared to today's checkout and are never renewed by `--refresh`.
No system shared
libraries are included in the notice archive.
`--complete` and `--packaging` reject historical-only native evidence even if
review flags are set and blockers are cleared. Selected-candidate/native
qualification is not implemented by this source checker. Mechanical text
presence does not establish legal sufficiency.

After a dependency change, inspect the new upstream terms and run `--refresh`.
It validates all sources before writing generated inventory/index/texts, refuses
missing text rather than generating placeholders, and does not remove stale
texts. Review and remove only unreferenced generated files before re-verifying.
Pinned upstream supplements in `upstream.json` use the published crate's
`.cargo_vcs_info.json` revision and an independently recorded Git blob hash.
They are retained locally; refresh never fetches them.

## Packaging

The per-user installer installs the notices and `LICENSES/` under
`$PREFIX/share/licenses/cirrus-drive/`, with every installed file recorded in
its ownership/checksum manifest and handled by its existing rollback/removal
rules. It refuses missing/corrupt sources, existing destinations and changed
installed files. Uninstall uses the installed inventory, not a newer checkout,
and removes only recorded files, never unrecognized files or directories.

Create the checksum-pinned Arch source archive with:

```sh
python3 scripts/check-third-party-notices.py --archive cirrus-notices.tar.gz
```

The command refuses to replace an existing output. Supply its reported digest
as `CIRRUS_NOTICES_SHA256` alongside the binary/template checksums. The archive
contains only the public notice tree and its `LICENSES/SHA256SUMS`, not private
gate reports. The Arch recipe installs the same layout under
`/usr/share/licenses/cirrus-drive/`. Keep the incomplete-review warning until
the reviewed bundle and actual release package contents pass verification. Binary
digests, build target/features, toolchain and native linkage records must
correspond to that release, not merely a later source checkout.

For packaging-only checks before release qualification, `--packaging-content`
compares all bytes without asserting binary provenance or legal completeness.
Current release qualification additionally needs explicitly selected candidate
bytes, compilation provenance and actual native observations; changing review
flags alone cannot supply them. The following release-completeness command
remains blocked by historical-only evidence. Its directory arguments must be populated by the real
installer and extracted real Arch package (not manually assembled fixtures):

```sh
python3 scripts/check-third-party-notices.py --packaging \
  --user-notices-dir USER_STAGING/share/licenses/cirrus-drive \
  --arch-notices-dir ARCH_EXTRACTION/usr/share/licenses/cirrus-drive
```

This compares every retained bundle file byte-for-byte. It does not build,
install, extract or run a package, establish the provenance of those directory
arguments, or replace independent linkage and redistribution review.

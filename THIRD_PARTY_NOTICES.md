# Third-party notices

License and copyright texts are retained in [LICENSES](LICENSES/INDEX.md).
The [inventory](LICENSES/inventory.json) identifies exact versions, source
revisions, enabled features, notice origins and SHA-256 digests. Upstream
license expressions describe those packages; they do not replace license texts.

## Scope

This bundle inventories the pinned `x86_64-unknown-linux-gnu` daemon and UI
source graph with workspace default features, without fault injection.
`runtime-candidate` means reachable through normal dependencies, not proof
that every crate survives linking. `build-tool` means build dependencies or
procedural macros and their dependencies; these are retained conservatively
because tools can contribute generated code. Packages can have both roles.
Development edges are excluded. Unselected target/feature lock entries are
listed separately, not represented as distributed code. Cargo metadata's
feature union is not an exact compilation-unit or binary inventory.

Generated-input records bind the published SPIR-V, Vulkan and XCB bindings
to their upstream source snapshots, generation recipes and pinned input
schemas/headers. Their original per-input copyright notices and license
texts are retained, including Vulkan video headers. Compressed exact inputs
are included for offline provenance verification, not as additional runtime
dependencies. This records upstream generation provenance; it does not
claim to reproduce generation byte-for-byte.

The bundle includes original license/notice documents and additional grants
from Wayland protocol XML and ring source headers. Some documents cover
unselected files as well; retaining them does not assert those files are used.
Rust standard-library copyright notices and their referenced license files
are included separately from Cargo dependencies.

### Rune and fonts

Rune, rune-motion and rune-staging use revision
`f401bce5a9658413b559760c0c6774c4421324a9` of
<https://github.com/anomalyco/rune>. Their MIT license is retained in the index.
Rune embeds Inter Regular, Medium and SemiBold in native builds, under the
included SIL Open Font License 1.1 notice. Its IBM Plex Mono notice is also
retained; that embedded font is selected for WebAssembly, not this Linux target.
System fallback fonts are not bundled by this source inventory.

### Native and data components

- `libsqlite3-sys` selects bundled SQLite 3.50.2, whose copyright disclaimer
  is retained alongside the Rust wrapper's license. SQLCipher is not selected;
  its upstream license document is retained conservatively.
- `ring` includes native cryptography and assembly, with ISC, Apache and
  component-specific grants retained. BLAKE3's native implementation is
  covered by its retained upstream license alternatives.
- Wayland protocol-generated bindings have per-protocol notices in addition
  to their Rust wrapper licenses. Unicode data and TLS root data retain their
  upstream Unicode and CDLA license texts respectively.
- Wayland, XKB, Vulkan and C/C++ runtime libraries may be system-linked or
  loaded at runtime. `fuser` selects its pure-Rust Linux mount implementation;
  a system FUSE helper is not the same as bundled libfuse code. Exact native
  library versions and static-link exceptions require the release artifact's
  linkage record. System libraries or fonts redistributed separately require
  their own notices and any other applicable materials.

## Distribution status

**Distribution qualification is incomplete.** [Open review items](LICENSES/review.json)
cover release-specific build/linkage and package qualification. The installer
and Arch recipe include the retained bundle using per-file ownership and
checksum-pinned inputs. Do not distribute a package as notice-complete until
the remaining review items are resolved and actual release package contents
have been verified. Disposable packaging fixtures are not release binaries.
This inventory is not a
legal compatibility or redistribution-permission guarantee.

The [historical Linux binary linkage](LICENSES/native-linkage.json) distinguishes
actual ELF dependencies and linker-map inputs from source-declared runtime
loaders for the binary hashes recorded there, not the current release candidate.
That historical pair needs glibc 2.43 or newer. GNU C/GCC runtime package notices
and license texts are retained; the system shared libraries themselves are
not redistributed. Rust standard-library and compiler-builtins inputs are
covered by the retained toolchain notices, not inferred from `ldd`.

The historical daemon includes `libc_nonshared.a(pthread_atfork.oS)` and startup
objects. The applicable exception or LGPL source/relink requirements for
these exact objects remain unresolved; retaining license texts alone does
not close that distribution obligation. Desktop/GPU-loaded libraries and
drivers remain environment-dependent and were not exercised by ELF inspection.
Source verification and archive/content checks do not qualify current native
linkage; historical evidence cannot pass release-completeness checks.

See [verification and packaging requirements](LICENSES/README.md).

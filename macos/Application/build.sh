#!/bin/sh
# Plain unsigned Mach-O and Swift module only. No .app, signing or installation.
set -eu
: "${CIRRUS_ACCOUNT_ARCHIVE:?explicit production libcirrus_account.a required}"
: "${CIRRUS_APPLICATION_OUTPUT:?explicit new output directory required}"
: "${CIRRUS_MODULE_CACHE:?explicit job-local module cache required}"
: "${CIRRUS_SWIFT_TARGET:?explicit Apple deployment target required}"
sdk=$(/usr/bin/xcrun --sdk macosx --show-sdk-path)
swiftc=$(/usr/bin/xcrun --sdk macosx --find swiftc)
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$swiftc" -j 1 \
  -swift-version 6 -strict-concurrency=complete -sdk "$sdk" \
  -target "$CIRRUS_SWIFT_TARGET" -module-cache-path "$CIRRUS_MODULE_CACHE" \
  -I "$here/../RetainedCore/include" \
  "$here/../RetainedCore/RetainedCore.swift" "$here/AccountApplication.swift" \
  "$here/Configuration.swift" "$here/ApplicationWorker.swift" "$here/FinderRegistration.swift" "$here/main.swift" \
  "$CIRRUS_ACCOUNT_ARCHIVE" -framework AppKit -framework FileProvider -framework Security \
  -framework CoreFoundation -liconv -emit-executable -emit-module \
  -module-name CirrusApplication \
  -emit-module-path "$CIRRUS_APPLICATION_OUTPUT/CirrusApplication.swiftmodule" \
  -o "$CIRRUS_APPLICATION_OUTPUT/CirrusApplication"

#!/bin/sh
# Compile/link source only. No signing, bundle, registration or installation.
set -eu
: "${CIRRUS_ACCOUNT_ARCHIVE:?explicit production libcirrus_account.a required}"
: "${CIRRUS_MODULE_OUTPUT:?explicit new output directory required}"
: "${CIRRUS_MODULE_CACHE:?explicit job-local module cache required}"
: "${CIRRUS_SWIFT_TARGET:?explicit Apple deployment target required}"
sdk=$(/usr/bin/xcrun --sdk macosx --show-sdk-path)
swiftc=$(/usr/bin/xcrun --sdk macosx --find swiftc)
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$swiftc" -j 1 \
  -swift-version 6 -strict-concurrency=complete -sdk "$sdk" \
  -target "$CIRRUS_SWIFT_TARGET" -module-cache-path "$CIRRUS_MODULE_CACHE" \
  -I "$here/../RetainedCore/include" \
  "$here/../RetainedCore/RetainedCore.swift" "$here/../RetainedCore/RetainedCatalog.swift" \
  "$here/SwiftProviderWorker.swift" "$here/ProviderItem.swift" \
  "$here/ProviderEnumerator.swift" "$here/ReplicatedExtension.swift" \
  "$CIRRUS_ACCOUNT_ARCHIVE" -framework FileProvider -framework UniformTypeIdentifiers \
  -framework Security -framework CoreFoundation -liconv \
  -emit-library -emit-module -module-name CirrusReadOnlyProvider \
  -emit-module-path "$CIRRUS_MODULE_OUTPUT/CirrusReadOnlyProvider.swiftmodule" \
  -o "$CIRRUS_MODULE_OUTPUT/libCirrusReadOnlyProvider.dylib"

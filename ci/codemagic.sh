#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
project="DUMP.xcodeproj"
scheme="DUMP"
derived="$(pwd)/build/DerivedData"
packages="$(pwd)/build/SourcePackages"
mkdir -p build/logs build/results build/artifacts

case "${1:-}" in
  prepare)
    test -f "$project/project.pbxproj" || { echo "Missing Xcode project." >&2; exit 1; }
    test -f "$project/xcshareddata/xcschemes/$scheme.xcscheme" || { echo "Missing shared DUMP scheme." >&2; exit 1; }
    test -f DUMP/DUMP/Info.plist || { echo "Missing app Info.plist." >&2; exit 1; }
    test -f DUMPTests/SecurityTests.swift || { echo "Missing security tests." >&2; exit 1; }
    xcodebuild -version
    plutil -lint DUMP/DUMP/Info.plist
    xcodebuild -resolvePackageDependencies -project "$project" -scheme "$scheme" \
      -clonedSourcePackagesDirPath "$packages" 2>&1 | tee build/logs/dependencies.log
    ;;
  test)
    xcrun simctl list devices available --json > build/simulators.json
    simulator_id="$(python3 ci/select-simulator.py build/simulators.json)"
    # Boot only if necessary; do not hide a real simctl boot error.
    if ! xcrun simctl list devices booted | grep -Fq "$simulator_id"; then
      xcrun simctl boot "$simulator_id"
    fi
    xcrun simctl bootstatus "$simulator_id" -b
    xcodebuild test -project "$project" -scheme "$scheme" \
      -configuration Debug -sdk iphonesimulator \
      -destination "platform=iOS Simulator,id=$simulator_id" \
      -destination-timeout 120 \
      -derivedDataPath "$derived" \
      -clonedSourcePackagesDirPath "$packages" \
      -resultBundlePath "build/results/DUMP-${CM_BUILD_ID:-local-$(date +%s)}.xcresult" \
      -parallel-testing-enabled NO \
      ONLY_ACTIVE_ARCH=YES CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
      2>&1 | tee build/logs/tests.log
    ;;
  package)
    app="$derived/Build/Products/Debug-iphonesimulator/DUMP.app"
    test -d "$app" || { echo "Simulator build did not produce DUMP.app." >&2; exit 1; }
    ditto -c -k --sequesterRsrc --keepParent "$app" build/artifacts/DUMP-simulator.zip
    ;;
  *)
    echo "Usage: bash ci/codemagic.sh prepare|test|package" >&2
    exit 2
    ;;
esac

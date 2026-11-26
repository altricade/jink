#!/bin/bash
# The macOS app's checks: the package's tests, the app's build (warnings
# are errors), and the String Catalog against the strings the code uses.
set -euo pipefail
cd "$(dirname "$0")"
(cd JinkKit && swift test --quiet)
xcodegen --quiet
xcodebuild -project Jink.xcodeproj -scheme Jink -configuration Debug -destination "platform=macOS,arch=$(uname -m)" -derivedDataPath build build -quiet
./check-strings.py
echo "macOS app: all checks passed"

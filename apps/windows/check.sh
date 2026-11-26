#!/bin/sh
# The Windows app's gate: format, build with every analyzer as an error,
# and the tests. On macOS the app (Jink.App) is compiled and analyzed but not
# packed; CI runs this on Windows too, where it is.
set -eu
cd "$(dirname "$0")"
DOTNET="${DOTNET:-dotnet}"
command -v "$DOTNET" >/dev/null 2>&1 || DOTNET="$HOME/.dotnet/dotnet"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
"$DOTNET" format --verify-no-changes
"$DOTNET" build --nologo
"$DOTNET" test --no-build
echo "Windows app: all checks passed"

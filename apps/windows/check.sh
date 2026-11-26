#!/bin/sh
# The Windows app's gate (the parts that build on any OS): format, build with
# every analyzer as an error, and the tests. CI runs it on Windows too, where
# the app itself (Jink.App) is built as well.
set -eu
cd "$(dirname "$0")"
DOTNET="${DOTNET:-dotnet}"
command -v "$DOTNET" >/dev/null 2>&1 || DOTNET="$HOME/.dotnet/dotnet"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
"$DOTNET" format --verify-no-changes
"$DOTNET" build --nologo
"$DOTNET" test --no-build
echo "Windows app core: all checks passed"

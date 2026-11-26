#!/bin/bash
# Xcode build step: builds the Rust `jink` command and puts it in the app
# (Contents/Helpers/jink), signed, with its version in the Info.plist.
set -euo pipefail

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
root="$SRCROOT/../.."
if [ "$CONFIGURATION" = "Release" ]; then
  cargo build --manifest-path "$root/Cargo.toml" -p jink-cli --release
  built="$root/target/release/jink"
else
  cargo build --manifest-path "$root/Cargo.toml" -p jink-cli
  built="$root/target/debug/jink"
fi

helpers="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Helpers"
mkdir -p "$helpers"
cp "$built" "$helpers/jink"
codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY:--}" "$helpers/jink"

version="$("$helpers/jink" --version | awk '{print $2}')"
/usr/libexec/PlistBuddy -c "Set :JinkServiceVersion $version" "$TARGET_BUILD_DIR/$INFOPLIST_PATH"

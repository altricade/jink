#!/bin/bash
# Makes every image the project uses from the SVG sources here: the PNGs in
# png/, the macOS app icon set, and the menu-bar icons of the macOS app.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
swiftc -O "$here/render.swift" -o "$work/render"
render() { "$work/render" "$here/$1" "$2" "$3" "$4"; }

mkdir -p "$here/png"
render jink-mark.svg "$here/png/jink-mark-512.png" 512 512
render jink-banner.svg "$here/png/jink-banner.png" 1280 640
render jink-logo-light.svg "$here/png/jink-logo-light.png" 912 400
render jink-logo-dark.svg "$here/png/jink-logo-dark.png" 912 400

icons="$root/apps/macos/Jink/Assets.xcassets/AppIcon.appiconset"
mkdir -p "$icons"
for size in 16 32 64 128 256 512 1024; do
  render jink-icon.svg "$icons/icon-$size.png" "$size" "$size"
done
cat > "$icons/Contents.json" <<'JSON'
{
  "images" : [
    { "filename" : "icon-16.png", "idiom" : "mac", "scale" : "1x", "size" : "16x16" },
    { "filename" : "icon-32.png", "idiom" : "mac", "scale" : "2x", "size" : "16x16" },
    { "filename" : "icon-32.png", "idiom" : "mac", "scale" : "1x", "size" : "32x32" },
    { "filename" : "icon-64.png", "idiom" : "mac", "scale" : "2x", "size" : "32x32" },
    { "filename" : "icon-128.png", "idiom" : "mac", "scale" : "1x", "size" : "128x128" },
    { "filename" : "icon-256.png", "idiom" : "mac", "scale" : "2x", "size" : "128x128" },
    { "filename" : "icon-256.png", "idiom" : "mac", "scale" : "1x", "size" : "256x256" },
    { "filename" : "icon-512.png", "idiom" : "mac", "scale" : "2x", "size" : "256x256" },
    { "filename" : "icon-512.png", "idiom" : "mac", "scale" : "1x", "size" : "512x512" },
    { "filename" : "icon-1024.png", "idiom" : "mac", "scale" : "2x", "size" : "512x512" }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
JSON
printf '{\n  "info" : { "author" : "xcode", "version" : 1 }\n}\n' > "$root/apps/macos/Jink/Assets.xcassets/Contents.json"

media="$root/apps/macos/JinkKit/Sources/JinkUI/Resources/Media.xcassets"
mkdir -p "$media"
printf '{\n  "info" : { "author" : "xcode", "version" : 1 }\n}\n' > "$media/Contents.json"
for state in off busy on trouble; do
  set="$media/menubar-$state.imageset"
  mkdir -p "$set"
  cp "$here/menubar-$state.svg" "$set/"
  cat > "$set/Contents.json" <<JSON
{
  "images" : [ { "filename" : "menubar-$state.svg", "idiom" : "universal" } ],
  "info" : { "author" : "xcode", "version" : 1 },
  "properties" : { "preserves-vector-representation" : true, "template-rendering-intent" : "template" }
}
JSON
done
echo "made: assets/brand/png, the app icon set, the menu-bar icons"

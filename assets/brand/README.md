# jink brand

The mark is an arrow that **jinks**: it steps sideways over a block at the
last moment, as jink's traffic slips past the filter. In the name, the dot
of the i jinks out of line too.

## Files

| File | Use |
|---|---|
| `jink-icon.svg` | The macOS app icon (Apple's grid: an 824 px body in 1024, with its shadow) |
| `jink-mark.svg` | The mark edge to edge: avatars (GitHub crops it to a circle or rounded square), small icons, the Windows icon |
| `jink-logo-light.svg`, `jink-logo-dark.svg` | Icon and name, for light and dark backgrounds |
| `jink-banner.svg` | The README's banner |
| `menubar-off/busy/on/trouble.svg` | The menu-bar icon per state, as templates (black; macOS tints them) |
| `png/` | Made from the SVGs: `jink-banner.png` (1280×640, GitHub's social preview), `jink-mark-512.png` (avatar), the logos |

`./export.sh` makes every PNG from the SVGs with AppKit (macOS only, no other
tools): the files in `png/`, the macOS app icon set
(`apps/macos/Jink/Assets.xcassets`) and the menu-bar icons
(`apps/macos/JinkKit/Sources/JinkUI/Resources/Media.xcassets`). Change an
SVG, then run it.

## Colors

| | Hex | Use |
|---|---|---|
| Night | `#0F1B2D` (icon body `#15253C` → `#0B1524`) | Icon ground, the name on light |
| Mint | `#34E3A5` | The arrow; the i dot on dark |
| Deep mint | `#1FC98E` | The i dot on light (contrast on white) |
| Slate | `#3B4E6E` | The block |
| Snow | `#F3F6FA` | The name on dark |

The name is drawn, not typeset: rounded strokes as thick as the arrow's, the
j's tail bent at the arrow's angle. Text beside it is Inter (or the system
font).

## On GitHub

- Social preview: repository Settings → General → Social preview → upload
  `png/jink-banner.png`.
- Avatar (an organization or account for jink): `png/jink-mark-512.png`.

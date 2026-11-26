#!/usr/bin/env python3
"""Checks the app's String Catalog against the strings the code uses: after
a build (`xcodebuild ... -derivedDataPath build`), every key the compiler
extracted from JinkUI must be in the catalog, and the catalog must have no
keys the code no longer uses."""
import glob
import json
import sys
from pathlib import Path

here = Path(__file__).parent
catalog = json.loads((here / "JinkKit/Sources/JinkUI/Resources/Localizable.xcstrings").read_text())
used = set()
for data in glob.glob(str(here / "build/**/JinkUI-t.build/**/*.stringsdata"), recursive=True):
    for table in json.loads(Path(data).read_text()).get("tables", {}).values():
        used.update(entry["key"] for entry in table)
if not used:
    sys.exit("no extracted strings: build the app first")
known = set(catalog["strings"])
missing, unused = sorted(used - known), sorted(known - used)
for key in missing:
    print(f"not in the catalog: {key!r}")
for key in unused:
    print(f"no longer used: {key!r}")
sys.exit(1 if missing or unused else 0)

# Test fixtures

The `*.bin` files are the decoy payloads shipped in `bin/` of
zapret-discord-youtube 1.10.4 (Flowseal), which builds on zapret by bol-van.
They are used unmodified as real-world parser inputs. MIT-licensed; see
`LICENSE-zapret-discord-youtube.txt`.

`lists/` holds the domain and IP lists from `lists/` of the same release:
`ipset-all.txt` is the shipped placeholder (one TEST-NET-3 address), and
`ipset-all-full.txt` is the shipped `ipset-all.txt.backup` (the real list that
`service.bat` swaps in).

`strategies/` holds the 22 unmodified `general*.bat` strategy files of the same
release, used to test importing zapret command lines.

# jink's built-in data

Compiled into jink (see `src/catalog`), so jink needs no zapret folder.

`lists/` and `payloads/` come unmodified from zapret-discord-youtube 1.10.4
(Flowseal), which builds on zapret by bol-van; MIT-licensed, see
`LICENSE-zapret-discord-youtube.txt`.

- `lists/ipset-all.txt` is the bundle's full IP list (its
  `ipset-all.txt.backup`, the "loaded" list of `service.bat`).
- `payloads/` holds only the fakes the built-in strategies send. The bundle's
  swappable `ACTIVE_DISCORD_UDP.bin` and `ACTIVE_GAME_UDP.bin` are copies of
  `quic_initial_steamcommunity_com.bin` and `quic_initial_4pda_to.bin`, and
  are used under those names.

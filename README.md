<p align="center">
  <img src="assets/brand/jink-banner.svg" alt="jink: unblocks YouTube and Discord on macOS and Windows" width="100%">
</p>

# jink

A cross-platform DPI-desync engine in Rust, built by studying zapret
(bol-van) as shipped in zapret-discord-youtube 1.10.4.

## Status

`crates/jink-core` (no OS-specific code) is implemented and tested:

| Area | Module | Notes |
|---|---|---|
| Packet dissection | `packet` | IPv4/IPv6, TCP/UDP, TCP options |
| Protocols | `l7` | TLS ClientHello (partial too), QUIC v1/v2 Initial decryption and CRYPTO reassembly, HTTP, STUN, Discord |
| Lists and rules | `lists`, `rules` | zapret hostlist/ipset semantics, first-match rules |
| Configuration | `config` | typed model, zapret `winws` argument parser, `.bat` strategy importer, platform checks |
| Desync | `desync` | fakes (UDP, TCP with `ts`/`badseq`/`md5sig`), `multisplit` with `seqovl`, `fakedsplit`, `hostfakesplit`, packet building |
| Flow engine | `engine` | flow tracking (zapret timeouts), rule re-search on discovery, `cutoff`, packet-mode driver with TLS/QUIC hello reassembly (hold and replay) |

`crates/jink-windivert` is the Windows backend (WinDivert capture loop and
filter), `crates/jink-macos` the macOS backend (utun interface, userspace
TCP/IP stack, relay through sockets pinned to the physical interface, BPF
handshake capture, raw-socket fakes and split writes for TCP, decoys for UDP) and `crates/jink-cli` the `jink` command.

Not implemented yet (reported as explicit errors, never silently skipped):
`fake-tls-mod`, zapret's built-in TLS fake, `multidisorder`, `syndata`,
`hostfakesplit` without `host=`. On macOS: IPv6.

On macOS (utun + raw sockets) `seqovl`, `syndata`, `multidisorder` and
`hostfakesplit` with `altorder=1` cannot be done (they need the kernel's own
segments shifted or reordered); `config::platform` rejects them at load time.
Fakes can go anywhere between jink's own writes, so `fakedsplit` and
`hostfakesplit` work.

## Running on Windows

For a step-by-step guide that assumes no developer setup, see
[docs/testing-windows.md](docs/testing-windows.md).

1. Install Rust from <https://rustup.rs>; its installer offers the Visual
   Studio C++ build tools, which are needed.
2. Stop zapret first, so two programs don't rewrite the same packets: run
   zapret-discord-youtube's `service.bat` and remove its service, or close
   `winws.exe`.
3. Build:

   ```bat
   scripts\build-windows.cmd
   ```

   This sets `WINDIVERT_STATIC=1`, which compiles WinDivert's user-mode
   library (2.2) into `jink.exe`, and downloads the signed
   `WinDivert64.sys` (WinDivert 2.2.2, checked against its published
   SHA-256) next to it in `dist`. GitHub Actions builds the same `dist` on
   every push (`.github/workflows/windows.yml`), runs the tests there, and
   tries the result as a service (`scripts/windows-smoke.ps1`).
4. From a terminal opened **as Administrator**:

   ```bat
   dist\jink.exe check "C:\path\to\zapret-discord-youtube\general.bat"
   dist\jink.exe run   "C:\path\to\zapret-discord-youtube\general.bat"
   ```

   `--game-filter on` matches service.bat's game filter. Ctrl+C stops jink;
   traffic then flows normally again. `run` refuses strategies that use
   techniques jink cannot perform yet unless `--allow-partial` is given.

Strategies jink can fully run on Windows today: `general.bat`, ALT, ALT2,
ALT4, ALT6, ALT9, ALT10, ALT11, ALT12, ALT13, SIMPLE FAKE, SIMPLE FAKE ALT,
SIMPLE FAKE ALT2. On macOS: ALT, ALT4, ALT8, ALT9, ALT10, FAKE TLS AUTO ALT,
SIMPLE FAKE, SIMPLE FAKE ALT, SIMPLE FAKE ALT2 (others with
`--allow-partial`).

## Running on macOS

```sh
cargo build --release -p jink-cli
sudo target/release/jink run "$HOME/path/to/zapret-discord-youtube/general (ALT4).bat"
```

jink creates a utun interface and routes `0.0.0.0/1` and `128.0.0.0/1`
through it; every new IPv4 connection is then relayed by jink. Ctrl+C stops it
and deletes the routes; if jink is killed, the kernel deletes them along with
the interface. Connections open before jink started are dropped.
`--allow-partial` lets strategies with rules macOS cannot perform (seqovl,
e.g. `general.bat`) run; those rules then pass traffic unchanged. `ping` does
not work while jink runs (ICMP is not relayed); test with a browser or `curl`.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The Windows check from macOS needs Windows' C headers (the TLS code
compiles some C): install [cargo-xwin](https://github.com/rust-cross/cargo-xwin)
and LLVM once (`brew install llvm lld`, `cargo install cargo-xwin --locked`;
the first run downloads Microsoft's CRT and SDK, accepting their license), then:

```sh
PATH="$HOME/.cargo/bin:/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:$PATH" \
  WINDIVERT_PATH=/any/empty/dir \
  cargo xwin clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
```

The macOS app (`apps/macos`) has its own checks, `apps/macos/check.sh`: the
JinkKit package's tests (Swift 6, warnings are errors), the app's build
(XcodeGen and Xcode), and its String Catalog against the code.

Lints in `Cargo.toml` deny `unsafe`, `unwrap`/`expect`/`panic`, unchecked
indexing, unchecked arithmetic and `as` casts.

Test fixtures under `crates/jink-core/tests/fixtures` come from
zapret-discord-youtube (MIT); see the README there.

## License

GPL-3.0-or-later.

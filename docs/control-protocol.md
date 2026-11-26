# jink control protocol

How the jink apps (macOS, Windows) talk to the jink daemon, the background
service that runs the engine. The Rust types are in
`crates/jink-daemon/src/protocol.rs`; this page is the contract for app
code, and [`contract/`](../contract/README.md) has an example of every
message, which the daemon's tests and the apps' tests both check.

## Connection

| | Where | Who may connect |
|---|---|---|
| macOS | Unix socket `/var/run/jink.sock` | the Mac's users (group `staff`) |
| Windows | named pipe `\\.\pipe\jink` | signed-in users |

Each message is one JSON object on one line (UTF-8, ending in `\n`). An app
sends a request and reads exactly one reply, in order; it can send any
number of requests on one connection. After `watch`, the connection only
carries updates.

## Requests

| Request | Reply |
|---|---|
| `{"cmd":"status"}` | `status` |
| `{"cmd":"strategies"}` | `strategies` |
| `{"cmd":"start"}` or `{"cmd":"start","strategy":"alt13"}` | `done` |
| `{"cmd":"stop"}` | `done` |
| `{"cmd":"settings"}` | `settings` |
| `{"cmd":"update_settings","settings":{…}}` | `done` |
| `{"cmd":"set_start_at_boot","on":true}` | `done` |
| `{"cmd":"find"}` | `done` (at once; progress and result come in `status`) |
| `{"cmd":"cancel_find"}` | `done` |
| `{"cmd":"watch"}` | `status` now, then `status` at every change, and `notice`s |

- `start` without a strategy uses the one used last; with one, it switches
  to it (restarting if desync is on). The choice is saved.
- `update_settings` replaces all settings. If any entry is invalid, nothing
  changes and the reply lists every invalid entry. If desync is on, the new
  settings apply at once.
- `find` tries every strategy and keeps the one that gets through best (see
  [Finding a strategy](#finding-a-strategy)). A second `find` while finding
  changes nothing. `cancel_find` ends it and puts desync back as it was;
  `start` and `stop` end it too and then do what they say.
- Any request can be answered with an `error` instead.

## Replies and updates

Every message has a `type`.

```json
{"type":"status","status":{
  "engine":{"state":"on","network":{"state":"online","uplink":"en0","ipv6":false}},
  "strategy":"alt","start_at_boot":true,"version":"0.1.0","found":null}}
```

`version` is the daemon's; an app that bundles a different one offers to
reinstall the background service.

`engine.state` is one of:

- `off`
- `starting`
- `on`, with `network.state`:
  - `checking`: just started
  - `online`: with `uplink` (the interface traffic leaves through) and `ipv6`
    (the network has IPv6, which jink turns away so that apps use IPv4)
  - `offline`: no network; jink waits for one
  - `bypassed`: jink cannot work on this network and traffic goes around it;
    with a `problem`
- `failed`: stopped by itself or could not start; with a `problem`
- `finding`: finding a strategy, at `step` of `of`, trying `strategy`
  (`null` at step 1, which checks the sites without jink)

`found` is what the last finding found, or `null` (none since the daemon
started, or one is running); see below.

A `problem` is `{"code":"…","detail":"…"}`. Apps show a text for the
`code` in their own language; `detail` is the system's English text, for
diagnosis.

```json
{"type":"strategies","strategies":[
  {"id":"alt","name":"ALT","variant_of":null,"support":"full"},
  {"id":"alt6","name":"ALT6","variant_of":"general","support":"partial"}]}
```

`variant_of` names the main strategy a variant belongs to (show variants
under it). `support` is `full`, or `partial` when some of the strategy's
rules cannot run on this computer and pass traffic unchanged.

```json
{"type":"settings","settings":{
  "my_sites":["youtube.com"],"my_ips":["203.0.113.0/24"],
  "excluded_sites":[],"excluded_ips":[],
  "gaming":{"mode":"off","tcp_ports":"1024-65535","udp_ports":"1024-65535"},
  "ip_list":"off"}}
```

- `my_sites` and `excluded_sites`: domains. A pasted link is accepted; the
  daemon keeps its domain, and the settings it sends back are normalized.
- `my_ips` and `excluded_ips`: addresses or networks (`1.2.3.0/24`).
- `gaming.mode`: `off`, `tcp`, `udp` or `both`; ports as `from-to` or one
  port. Gaming mode covers the IPs of the IP list and `my_ips` only, so the
  app's gaming switch should also set `ip_list` to `built_in`.
- `ip_list`: `off`, `built_in` or `all`.

```json
{"type":"done"}
{"type":"notice","notice":{"code":"…","detail":"…"}}
```

## Finding a strategy

The daemon checks 8 Discord and YouTube sites (`discord.com`,
`gateway.discord.gg`, `cdn.discordapp.com`, `updates.discord.com`,
`www.youtube.com`, `youtu.be`, `i.ytimg.com`,
`redirector.googlevideo.com`), each over TLS 1.2 and over TLS 1.3: 16
checks. A check passes when the site completes a handshake with a
certificate the computer trusts and sends an HTTP reply, within 5 seconds.

1. It stops desync and checks the sites without jink.
2. If all pass, nothing is blocked; if none could even be looked up or
   reached, there is no network. Either way it stops there.
3. Otherwise it runs each strategy in turn (those this computer runs fully
   first, main ones before variants), waits up to 10 seconds for it to come
   online, and checks the sites.
4. The strategy with the most passed checks is kept (of equals, the first
   tried), if it passes more than none did: it is saved and turned on.
   Otherwise desync goes back to how it was.

It takes about one to two minutes. Discord voice and YouTube over QUIC
(UDP) are not checked.

```json
"found":{"result":"kept","strategy":"alt4","checks":16,
  "without":{"passed":4,"failed":[
    {"host":"cdn.discordapp.com","tls":"1.2","outcome":"cut"}, …]},
  "tried":[
    {"strategy":"alt","passed":10,"failed":[…],"problem":null},
    {"strategy":"alt2","passed":0,"failed":[],
     "problem":{"code":"routes_taken","detail":"…"}}, …]}
```

| `result` | Meaning | Desync after |
|---|---|---|
| `kept` | `strategy` got through best | on, with `strategy` (saved) |
| `nothing_blocked` | every check passed without jink | as before |
| `none_helped` | no strategy passed more checks than none | as before |
| `no_network` | no site could be looked up or reached | as before |

A `tried` entry with a `problem` never came online (its sites were not
checked): `offline`, `not_online` (not within 10 seconds), a `bypassed`
problem code, or the code of why the engine failed.

| `outcome` of a failed check | Meaning |
|---|---|
| `no_address` | the name does not resolve |
| `unreachable` | no address takes a connection |
| `cut` | the connection was cut (or garbled) during the handshake |
| `certificate` | the certificate is not the site's (a block page, usually) |
| `no_reply` | handshake done, but no HTTP reply |
| `timed_out` | no answer within 5 seconds |

## Errors

```json
{"type":"error","error":{"code":"invalid_settings","problems":[
  {"field":"my_sites","index":2,"code":"no_dot"}]}}
```

| `error.code` | Extra fields |
|---|---|
| `bad_request` | `detail` |
| `unknown_strategy` | `strategy` |
| `invalid_settings` | `problems`: `field`, `index` (position in the list; `null` for ports), `code` |
| `failed` | `detail` |

Settings problem codes:

| Code | Meaning |
|---|---|
| `empty` | empty entry |
| `ip_address` | an IP address in a site list: it belongs in the IPs |
| `not_ascii` | a non-Latin domain: enter its `xn--` form |
| `no_dot` | a domain without its ending (`youtube` for `youtube.com`) |
| `invalid_site` | not a domain name |
| `invalid_ip` | not an address or network |
| `invalid_ports` | not a port range |

# jink control protocol

How the jink apps (macOS, Windows) talk to the jink daemon, the background
service that runs the engine. The Rust types are in
`crates/jink-daemon/src/protocol.rs`; this page is the contract for app
code.

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
| `{"cmd":"watch"}` | `status` now, then `status` at every change, and `notice`s |

- `start` without a strategy uses the one used last; with one, it switches
  to it (restarting if desync is on). The choice is saved.
- `update_settings` replaces all settings. If any entry is invalid, nothing
  changes and the reply lists every invalid entry. If desync is on, the new
  settings apply at once.
- Any request can be answered with an `error` instead.

## Replies and updates

Every message has a `type`.

```json
{"type":"status","status":{
  "engine":{"state":"on","network":{"state":"online","uplink":"en0","ipv6":false}},
  "strategy":"alt","start_at_boot":true}}
```

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

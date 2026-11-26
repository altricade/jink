# Control protocol contract

Examples of every kind of message on the control channel
([docs/control-protocol.md](../docs/control-protocol.md)), checked from both
sides:

- `messages/*.json`: what the daemon sends. The daemon's tests
  (`crates/jink-daemon/tests/contract.rs`) build each one and check that it
  serializes to exactly this; the apps' tests decode each one.
- `requests.jsonl`: what the apps send, one per line. The apps' tests encode
  each one and compare; the daemon's tests parse each one.

A change to the protocol changes these files, and both sides' tests say what
else must change.

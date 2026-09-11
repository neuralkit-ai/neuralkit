# neuralkit

The terminal client for the Neuralkit platform: real-time EEG acquisition, streaming and
visualization — and the platform's identity surface — in one Rust binary.

```
npm install -g neuralkit
```

The npm package is a thin harness; the binary itself ships as a platform package
(`@neuralkit-ai/cli-darwin-arm64`, `…-x64`) that npm's own resolver picks at install time.
No postinstall, no download scripts.

## The EEG dashboard

```
neuralkit                       # connect to a headset and stream
neuralkit --synthetic           # no hardware — synthesized 512 Hz signal, real pacing
neuralkit --sub                 # subscribe: view a live stream instead of producing one
```

Ingest is a NeuroSky headset speaking ThinkGear over a serial device node at 57600 baud.
The port is the first positional argument and its default is hardcoded to one specific
machine's device node — pass your own:

```
neuralkit /dev/cu.<your-headset>
```

The TUI (ratatui) draws the raw wave (auto-scaled, zoomable), a bands oscilloscope,
attention/meditation eSense gauges, and relative band powers, with live latency
instrumentation: real connect-RTT, signed EEG latency, and interarrival jitter.

Keys: `P` freezes the wave · `R` force-reconnects a subscriber · `M` opens the settings
menu, where relay and transport switch live · `Q` quits.

## Streaming

Publishing rides MoQ (draft-16) via `phaze-moq` on Cloudflare's `moq-transport`, over
WebTransport or raw QUIC — pick in the `M` menu. Two tracks go out: the full `NeuroPacket`,
and a deliberately minimal FlatBuffer `eeg-track` twin that the neuralkit web dashboards
decode unchanged.

```
neuralkit -u https://127.0.0.1:4443     # default: the local phaze-relay
neuralkit -u https://relay.cloudflare.mediaoverquic.com
```

## Signing in

```
neuralkit auth login
```

Four ways in, offered only when they can work: scan a QR with your phone, open the browser
on this machine, an authenticator code, or an emailed code. Every path registers the
machine as it goes, so the second sign-in is faster than the first — a registered machine
holds its own passkey and signs in with one call, no browser, no phone.

A successful sign-in enters an interactive session over a sealed channel (ML-KEM key
minted at login, Ed25519-verified frames). `dash` opens the EEG dashboard from inside it
— `Q` returns to the prompt. `logout` ends the session; `auth unregister` makes the
machine forget itself entirely.

```
neuralkit auth passkey            # show this machine's credential, and prove it asserts
neuralkit auth passkey register   # bind it to the signed-in account
neuralkit auth passkey login      # sign in with it
neuralkit auth totp setup         # enrol an authenticator app
neuralkit tray                    # a menu-bar presence — opt-in, alive only while it runs
```

### Hardware-backed keys

By default the machine's key is a software key on disk. On macOS it can live in the Secure
Enclave behind a person — Apple Watch or Touch ID — which requires the signed `.app`
bundle (`phaze native build --bundles app,dmg`; an access control on a persisted key needs an
entitlement only a provisioning profile in a bundle can carry). The tray's checkbox
chooses the gate; it applies at the next sign-in and changes which key signs, so
re-register after flipping it.

## State on disk

```
~/.config/neuralkit/credentials.json   # the SESSION — token, identity, deadline; dies on logout/expiry
~/.config/neuralkit/passkey.json       # the MACHINE — credential, device id, gate, tray choice; outlives sessions
```

Two files because they answer different questions: who is signed in now, and what this
machine durably is. `auth unregister` is what removes the second.

## Development

```
cargo run                          # the dashboard (synthetic: cargo run -- --synthetic)
cargo run -- auth login            # the full flows work from a dev build
cargo run -- tray
```

The one exception: enclave-gated keys need the signed bundle — `cargo run` builds a bare
binary that cannot satisfy the gate. `phaze native bundle` wraps a built binary in the
entitled, signed `.app` from `[package.metadata.native]` in Cargo.toml; `phaze native build`
builds the panel and the binary first.

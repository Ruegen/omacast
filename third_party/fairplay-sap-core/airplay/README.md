# `airplay/` — pairing and the live-device probe

A **separate Go module** implementing the HomeKit-style pairing an AirPlay 2
receiver requires before it will route `POST /fp-setup`, plus `ap2probe`, the
tool that put this project's FairPlay response in front of real hardware.

This is where every network call and the single external dependency live. The
root module stays zero-dependency and genuinely network-free — nothing under
`fpbridge/`, `fpsapcore/`, `fairplayhash/` or `cmd/fpsap` imports `net` or
anything external, and `go install .../cmd/fpsap@latest` is unaffected by
anything here.

## What it proved

On 2026-08-04, three HomePod-family units on firmware `23L471` **accepted the
response the core module computes and rejected every deliberately corrupted
one** — a single flipped bit is refused.

Every other FairPlay-capable receiver on the same network refused earlier in the
flow and returned no verdict: both Apple TVs (`470` at pair-setup, or a uniform
`403` on every m3) and both Macs (`403` at pair-setup). Full matrix and method:
[`docs/12-pairing.md`](../docs/12-pairing.md).

## Layout

| Package | What it does |
|---|---|
| [`tlv8/`](tlv8) | the TLV8 codec, including the >255-byte fragmentation every real message hits |
| [`srp/`](srp) | SRP-6a client, group and hash parameterised so the algebra can be checked against RFC 5054 |
| [`pairing/`](pairing) | transient pair-setup, and the ChaCha20-Poly1305 control channel |
| [`rtsp/`](rtsp) | minimal RTSP client whose transport can be swapped for the encrypted stream |
| [`cmd/ap2probe/`](cmd/ap2probe) | the probe |

## Using the probe

```sh
go build -o ap2probe ./cmd/ap2probe

./ap2probe info     lind.local        # /info, plaintext
./ap2probe pair     melba.local       # transient pair-setup only
./ap2probe fp-setup patti.local:7000  # pair, then one FairPlay exchange
./ap2probe control  anderson.local    # THE ONE THAT MATTERS — see below
```

`<host>` may omit the port; 7000 is assumed. `AP2_PASSWORD=...` overrides the
SRP password. (The example hostnames are a dedication — see the comment at the
top of the [root README](../README.md).)

**`control` is the only subcommand whose result means anything.** It sends a
correct response *and* deliberately wrong ones, and reports success only if the
receiver **accepts the right answer and rejects the wrong ones**. An acceptance
on its own proves nothing: Shairport Sync returns `200 OK` to a response with a
flipped byte, because it has no FairPlay to check against. This is the same
discipline [`docs/07-conformance.md`](../docs/07-conformance.md) applies to the
vectors — sensitivity is not discrimination.

## Two headers do all the work

Both were found by experiment and both fail in misleading ways if omitted:

- **Pairing needs `X-Apple-HKP: 4`.** With `3` you still get a well-formed M2
  and then a proof rejection at M4 that looks like a crypto bug. The
  `/pair-pin-start` call this code also makes turns out **not** to be required —
  isolating the two showed the header is necessary and sufficient.
- **`/fp-setup` needs `X-Apple-ET: 32`.** Without it the receiver answers with a
  FairPlay v2.5 record and refuses every response, correct or not.

## Tests

```sh
go test ./...
```

Offline only — nothing here talks to a device. The tests cover what fails
silently: TLV8 fragmentation at the 255-byte boundary, SRP against RFC 5054's
published `k`, `x`, `v` and `A` plus a client/server cross-check by
algebraically independent routes, AEAD tag enforcement, and nonce advancement.

## Licensing

Blue Oak 1.0.0 — independently written. Depends on `golang.org/x/crypto` for
ChaCha20-Poly1305 and HKDF, and on the root module for `fpbridge`. Note that
importing the root module pulls in LGPL-3.0 code; see [`NOTICE.md`](../NOTICE.md).

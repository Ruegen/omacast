# Limitations

This page is deliberately blunt. A cryptography project that hides its limits is
worse than useless. The handshake is now confirmed against real hardware, which
makes it *more* important to be exact about how narrow that confirmation is.
None of this is softened elsewhere in the docs, and it should not be softened
here.

## 1. Hardware validation: HomePods only

**Confirmed on 2026-08-04.** Three HomePod-family units — two HomePod minis
(`AudioAccessory5,1`) and a HomePod (`AudioAccessory6,1`), all on firmware
`23L471` / `sourceVersion 950.7.1` — accept the 20-byte response this project
computes and **reject every deliberately corrupted one**; a single flipped bit
is enough to be refused. That discrimination is what makes it evidence rather
than a rubber stamp.

**Every other FairPlay-capable device tested refuses before the check.** Two
Apple TVs and two Macs never evaluate a response at all, so they neither confirm
nor contradict the result.

Reproduce it with `ap2probe control <host>` from the [`airplay/`](../airplay)
module; the method and full result table are in [Pairing](12-pairing.md).
Twelve of those accepted exchanges are recorded in
`testdata/hardware_attested.csv` and replay offline as a regression corpus — see
[Conformance](07-conformance.md).

**Be precise about the scope, because "hardware tested" invites over-reading:**

- Three devices, **one product family**, one firmware build, one day. Nothing
  here generalises to Apple TVs, Macs, or third-party receivers — and that is
  not speculation, it was measured.
- **Both Apple TVs refuse.** `AppleTV11,1` fails at pair-setup M1 with `470`;
  the older `AppleTV6,2` completes pairing and then refuses *every* `/fp-setup`
  m3 identically, correct or corrupt. Both advertise `OneTimePairingRequired`.
  Whether either would accept a correct response after full HomeKit pairing is
  **untested**.
- **Both Macs refuse transient pair-setup outright** with `403`, so macOS never
  reaches FairPlay either.
- **Third-party MFi receivers do not implement FairPlay SAP at all.** The Denon
  AVRs tested advertise `et=0,4` with feature bit 14 clear and return `404` on
  `/fp-setup`; they authenticate over `/auth-setup` instead. This project is
  irrelevant to them.
- Reaching the check at all requires the pairing layer and the `X-Apple-ET: 32`
  header. Without the header the same HomePod offers a v2.5 record and refuses
  everything — see [Pairing](12-pairing.md), which also records the wrong
  conclusion that was drawn from that before the header was found.

What is now established is narrow and real: **on these devices, the golden
vectors correspond to what the hardware actually accepts.** That closes the gap
between "142/142 against archived captures" and "a real receiver agrees" — for
these devices.

## 2. It answers FairPlay message mode 3 only

FairPlay defines four message modes (0–3). The receiver selects one in byte 13 of
its m2, and **the mode changes the answer**: the same 128-byte challenge produces
four entirely different responses under modes 0, 1, 2, and 3, because the mode
picks both the CBC IV and the AES round keys.

This implementation is white-box AES over baked T-boxes, and those tables encode
**mode 3's key schedule alone** — there is no runtime parameter that could select
another (see [White-box cryptography](05-whitebox-crypto.md)). So:

- An m2 selecting any mode other than 3 is **rejected with an error naming the
  mode**, not answered. Returning bytes from the wrong key schedule would be worse
  than a refusal.
- Every exchange this project has ever observed used mode 3, and that now
  includes live challenges from three HomePods, which all selected mode 3.
  Whether clearing capability bits in m1 reliably *steers* a receiver to mode 3
  remains **not established** — the mapping is undocumented and every device seen
  so far chose mode 3 unprompted. A receiver that selects a different mode is
  still worth reporting.

## 3. Frozen m3 is a replay; use a session

There are two ways to produce the m3 record, and one of them does not work against
strict receivers:

- **Frozen** (`FPSAPExchangeM3`, `fpsap m3 --frozen`) replays a local SAP captured
  once from an emulator snapshot. Every m3 it emits is byte-identical. Receivers
  that validate the body reject the replay — the documented symptom is
  `RTSP/1.0 466 Key Management Error`.
- **Session-aware** (`NewFPSAPSession` → `ExchangeM3`, the `fpsap m3` default)
  generates a fresh local SAP per session and encrypts it into the body, so no two
  frames are identical.

Use the session-aware path for anything talking to a device. The frozen path is a
reference for permissive mode-3 receivers only.

## What this is not

- **Not FairPlay Streaming DRM.** This is an authentication handshake. It decrypts
  no content and extracts no content keys.
- **Not a network client.** The `fpsap` tool and the library compute bytes. They
  do not speak RTSP, open sockets, or manage an AirPlay connection. Wiring the
  bytes into a live exchange is the caller's job.
- **Not reducible below the tables.** The white-box tables are Apple-derived
  *data* and cannot be shrunk further; they will always be part of this.

See also the [FAQ](11-faq.md) and the repository [`NOTICE.md`](../NOTICE.md).

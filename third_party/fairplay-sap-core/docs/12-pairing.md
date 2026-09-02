# Pairing: reaching `/fp-setup` on a real receiver

The core module computes a FairPlay SAP response that satisfies 142 golden
vectors. Getting a **real receiver** to confirm it is a separate problem. This
page documents how that was solved: the pairing layer works end to end, and
three HomePods have now confirmed the response. It also records, honestly, the
four devices that refuse before the check is even reached.

Everything here was measured against live devices on 2026-08-04. Where something
is unverified it says so.

## The short version

To put a FairPlay response in front of a real Apple receiver you must first
complete a HomeKit-style **pair-setup**, because `/fp-setup` is not routable
until then. That pairing layer is implemented in the separate
[`airplay/`](../airplay) module — SRP-6a, TLV8, RTSP and the encrypted channel —
and it **works**: transient pair-setup completes against a real HomePod mini with
the receiver's own SRP proof verified, the control channel comes up encrypted,
and `/fp-setup` returns a genuine 142-byte FairPlay challenge.

And the handshake **validates**. Three HomePods accept the response this project
computes and reject every deliberately corrupted one. Apple TVs and Macs refuse
earlier in the flow and return no FairPlay verdict at all. See
[Limitations](09-limitations.md) for exactly what that does and does not cover.

## Not every AirPlay 2 receiver speaks FairPlay

This is the first thing to check, and it is easy to get wrong — we did. Two
fields in a receiver's mDNS advertisement decide whether it is even a candidate:

- **`et`** — the encryption types it accepts. `et=0,3,5` includes FairPlay;
  `et=0,4` is MFi only.
- **feature bit 14** (`FPSAPv2.5`) — whether it implements FairPlay SAP at all.

Measured across one network:

| Device | `et` | bit 14 FairPlay | `/fp-setup` |
|---|---|---|---|
| Apple TV (`AppleTV6,2`, `AppleTV11,1`) | `0,3,5` | **set** | `403` — exists, gated |
| HomePod / HomePod mini (`AudioAccessory5,1`, `6,1`) | `0,3,5` | **set** | gated |
| Mac (`Mac16,10`, `Mac16,12`) | `0,3,5` | **set** | gated |
| **Denon AVR-X2500H / CEOL** | `0,4` | **clear** | **`404` — not implemented** |
| Shairport Sync 5.0.4 | `0,1` | **clear** | `200`, but accepts anything |

Two consequences worth stating plainly:

- **A third-party MFi AVR is the wrong test target.** The Denons return `404` on
  `/fp-setup` not because it is gated but because they never implement it; they
  authenticate over `/auth-setup` (MFi) instead. No amount of pairing changes
  that.
- **Shairport Sync is worse than useless as a target.** It answers `/fp-setup`
  with `200` — and answers a *deliberately corrupted* response with `200` too.
  It has no FairPlay to validate with, so its acceptance carries no information.

The distinction matters because `404` and `403` look equally like failure but
mean opposite things: `404` is "this device has no FairPlay", `403` is "you are
not paired yet".

### Decoding the bits yourself

```sh
# from the mDNS TXT record: ft=0x445F8A00,0x1C340  ->  (low32, high32)
python3 -c '
lo,hi = 0x445F8A00, 0x1C340
f = (hi<<32)|lo
for b,n in ((14,"FPSAPv2.5"),(27,"LegacyPairing"),(46,"HKPairingAndAccessControl"),(48,"TransientPairing")):
    print(("SET  " if f>>b&1 else "clear"), n)'
```

Also read `sf` (status flags): bit 6 `OneTimePairingRequired` means the device
wants a one-time PIN. Both Apple TVs had it set (`sf=0x18644`); the HomePods
(`sf=0x98404`) and Macs (`sf=0x204`) did not. It predicts the Apple TV failures
below, but not the Mac ones — the Macs refuse for their own reasons.

## The pairing flow that works

Every element below was established by experiment; getting any one of them wrong
still produces a well-formed-looking exchange that fails later, which is what
made this take several attempts.

1. **`X-Apple-HKP: 4`.** This is the one that matters, and it is the whole
   difference between a working exchange and a baffling one. With `3` the
   receiver still returns a **perfectly well-formed M2** — salt, server public
   key, correct framing — and only refuses at M4 with
   `kTLVError_Authentication`. That failure looks like a credential or SRP-maths
   problem, which is where it sends you looking.
2. **`POST /pair-pin-start` is *not* required.** An earlier revision of this
   page said it was, and said its absence was "invisible". That was wrong, and
   the way it was wrong is worth recording: the call was added in the same
   change that fixed the HKP value, both were credited, and neither was
   isolated. Measured separately against a HomePod (`AudioAccessory5,1`, fw
   `23L471`) on 2026-08-06:

   | `X-Apple-HKP` | `/pair-pin-start` | result |
   |---|---|---|
   | 4 | called | **succeeds** |
   | 4 | skipped | **succeeds** |
   | 3 | called | `kTLVError_Authentication` at M4 |
   | 3 | skipped | `kTLVError_Authentication` at M4 |

   The header is necessary and sufficient; the call changes nothing. The code
   still makes it, because a real sender does and it may matter on a
   PIN-requiring receiver — but that is a hedge, not a finding.
3. **M1 field order `Method, State, Flags`**, with **`Flags` as a single
   big-endian byte** `0x10`, not four little-endian bytes.
4. **SRP-6a**, 3072-bit group, SHA-512, username `Pair-Setup`, password `3939`.
5. **M3 is `State, PublicKey, Proof`** — no flags echoed.
6. **The channel becomes encrypted immediately after M4.** Send a plaintext
   request next and the receiver resets the connection rather than answering.
   Keys are HKDF-SHA512 over the SRP session key with salt `Control-Salt` and
   info `Control-Write-Encryption-Key` / `Control-Read-Encryption-Key`; frames
   are a 2-byte little-endian length (used as AEAD associated data), the
   ChaCha20-Poly1305 ciphertext, and a 16-byte tag, with an independent 64-bit
   counter nonce per direction.

Confirmed against three HomePod-family units: pair-setup completes, the
receiver's own M4 proof verifies, and `/fp-setup` answers. It does **not** work
on Macs or Apple TVs — see the matrix below.

## The `X-Apple-ET: 32` header, and a retracted conclusion

An earlier revision of this page concluded that real receivers speak FairPlay SAP
v2.5 while this project implements v3, and that this was a fundamental
incompatibility. **That was wrong, and it is worth explaining how**, because the
evidence for it looked strong.

Without an `X-Apple-ET` header, a HomePod answers `/fp-setup` with a v2.5 record:

```
46504c59 02 01 02 00 00000082 02 03 <128-byte challenge>
         ^^ version 0x02
```

and then refuses every m3 with `403`. The refusal is identical for a correct
response and for deliberately corrupted ones, which is genuinely consistent with
"this receiver rejects the record before evaluating it" — the conclusion drawn at
the time. What that reasoning missed is that a *third* explanation fits equally
well: the request was being refused for a reason that had nothing to do with the
FairPlay bytes at all.

Adding one header settles it:

```
X-Apple-ET: 32
```

With it, the *same device* offers **version byte `0x03`** — the version this
project implements — and accepts a correct response. The encryption type is
something the sender asks for; the version difference was a consequence of not
asking, not a property of the hardware.

The lesson generalises: a control that rejects every variant, including ones you
expect to be rejected, has not localised the fault. It is consistent with "we are
being judged and failing" *and* with "we are not being judged at all". Only a
variant that *succeeds* distinguishes them.

## Hardware validation

Run 2026-08-04 across every FairPlay-capable receiver on one network. Each trial
pairs on a fresh connection, gets a real challenge, and sends one response.

### Where it works

| Device | Firmware | correct | 1 bit flipped | zeroed | randomised |
|---|---|---|---|---|---|
| HomePod mini (`AudioAccessory5,1`) | `23L471` | **`200` + m4** | `403` | `403` | `403` |
| HomePod mini (`AudioAccessory5,1`, 2nd unit) | `23L471` | **`200` + m4** | `403` | `403` | — |
| HomePod (`AudioAccessory6,1`) | `23L471` | **`200` + m4** | `403` | `403` | `403` |

**Three units, all HomePod-family, all pass the control.** A single flipped bit
is refused, so the receiver is genuinely checking the 20 bytes — this is
discrimination, not a rubber stamp.

### Where it does not get that far

These are not FairPlay failures. In every case the exchange is refused *before*
any response is evaluated, so they say nothing about whether the computation is
correct:

| Device | Firmware | Fails at | Symptom |
|---|---|---|---|
| Apple TV 4K (`AppleTV11,1`) | `23L471` | pair-setup M1 | `470 Connection Authorization Required` |
| Apple TV (`AppleTV6,2`) | `23L243` | `/fp-setup` m3 | `403` for **every** response, correct or corrupt |
| Mac Studio (`Mac14,9`) | `25F84` | pair-setup M1 | `403 Forbidden` |
| Mac mini (`Mac16,10`) | `25F80` | pair-setup M1 | `403 Forbidden` |

Reading these:

- **Both Macs refuse transient pair-setup outright.** macOS gates its AirPlay
  receiver behind an "Allow AirPlay for" setting and, depending on
  configuration, an on-screen accept. Transient pairing does not satisfy it.
- **Both Apple TVs advertise `OneTimePairingRequired`** (`sf` bit 6), which the
  HomePods do not. `AppleTV11,1` refuses at M1; the older `AppleTV6,2` completes
  pairing and then refuses every `/fp-setup` m3 identically. The uniform
  rejection is the tell: a device that was actually checking the response would
  distinguish the correct one.
- **Nothing here contradicts the HomePod result.** These devices decline to
  reach the check; they do not fail it.

Clearing either case needs full PIN-based HomeKit pairing, which this project
does not implement. That is the obvious next contribution.

## Reproducing

```sh
cd airplay
go build -o ap2probe ./cmd/ap2probe

./ap2probe pair     callas.local          # transient pair-setup
./ap2probe fp-setup tebaldi.local:7000    # pair, then one FairPlay exchange
./ap2probe control  sutherland.local      # correct + corrupted responses
```

`X-Apple-HKP: 4` (pairing) and `X-Apple-ET: 32` (fp-setup) are applied
automatically. The `/pair-pin-start` call is made too, though it is not required
— see above.

`AP2_PASSWORD=... ./ap2probe pair <host>` overrides the SRP password.

`control` is the one that matters. It sends a correct response *and* two
knowingly wrong ones, and only reports success if the receiver **accepts the
right answer and rejects both wrong ones**. An acceptance that a corrupted
response would also have earned proves nothing — the same discipline
[Conformance](07-conformance.md) applies to the vectors.

## Why this lives in a separate module

`airplay/` is its own Go module with its own `go.mod`. The core module keeps its
zero-dependency, network-free guarantee: nothing in `fpbridge`, `fpsapcore`,
`fairplayhash` or `cmd/fpsap` imports `net` or anything external, and
`go install .../cmd/fpsap@latest` is unaffected. All network code and the one
external dependency (`golang.org/x/crypto`, for ChaCha20-Poly1305) are confined
here.

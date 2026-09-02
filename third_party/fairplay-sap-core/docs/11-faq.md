# FAQ

## Is this legal?

This is defensive interoperability research: a clean-room reimplementation of an
**authentication handshake**, published so that non-Apple software can interoperate
with AirPlay 2 receivers. It contains no Apple source code and executes no Apple
instructions. The white-box tables are recovered *data*, not code (see
[White-box cryptography](05-whitebox-crypto.md)).

It is **not** FairPlay Streaming DRM: it decrypts no protected content and
extracts no content keys, so it is not a circumvention tool for accessing media.
Interoperability is a recognised purpose in several jurisdictions, but the legal
picture varies by country and by use. This is not legal advice — if you plan to
ship a product on top of it, get your own.

## Will this work on my Apple TV / HomePod / AirPlay speaker?

**On a HomePod, yes — confirmed on three of them.** As of 2026-08-04 two
HomePod minis and a HomePod accept the response this project computes and reject
deliberately corrupted ones. You need the pairing layer in
[`airplay/`](../airplay) to get there; `ap2probe control <host>` reproduces it.

**On an Apple TV or a Mac, no — measured, not guessed.** Both Apple TVs and both
Macs tested refuse before any response is evaluated: the Macs reject transient
pair-setup with `403`, `AppleTV11,1` returns `470` at M1, and `AppleTV6,2` pairs
but then refuses every m3 identically. Clearing those needs full PIN-based
HomeKit pairing, which is not implemented. Third-party MFi receivers (e.g. Denon
AVRs) do not implement FairPlay SAP at all and return `404`. Full matrix in
[Pairing](12-pairing.md).

## Why only mode 3?

The cipher is white-box: the key schedule is baked into lookup tables, one mode
per set of tables. These tables encode mode 3, which is the mode every observed
exchange used. There is no runtime switch for another mode because the key is not
a parameter — it *is* the table contents. See
[White-box cryptography](05-whitebox-crypto.md).

## Does this let me stream *from* an Apple TV, or decrypt AirPlay audio?

No. This is the sender-side authentication handshake only. It proves a sender is
legitimate so a receiver will accept a connection. It has nothing to do with
decrypting a stream, capturing content, or acting as a receiver's DRM.

## Why is the repo still ~500 KB if it's "just an algorithm"?

Most of the code *is* a small algorithm — the bridge and Phase 2 collapsed from
7.2 MB of generated code to about 633 lines. What remains large is the white-box
AES table data, which is Apple-derived and irreducible: the tables are the cipher.
Everything reducible was reduced (135,168 bytes of tables down to 5,168, and so
on). See [White-box cryptography](05-whitebox-crypto.md).

## Which language should I use?

- **Go** is the complete, drop-in implementation — challenge in, response out,
  plus the m1/m2/m3 framing and a session. Use it if you can.
- **C, Rust, C#, Kotlin, Python** are single-file portable cores for the Phase-1
  bridge, meant to be vendored into an existing codebase. They need the 128-byte
  GP buffer as input, which only the Go module's Phase 1 produces. See the
  [API reference](08-api-reference.md) and [`ports/README.md`](../ports/README.md).

## How do I contribute?

The most useful contributions, roughly in order:

1. **A hardware report from a device we have not tried.** Three HomePods pass;
   Apple TVs and Macs refuse before the check. A receiver outside those families
   — or an Apple TV reached through full HomeKit pairing — would genuinely extend
   the evidence. Run `ap2probe control <host>` and report the verdict either way;
   a rejection is as useful as an acceptance.
2. **A new-language port.** Follow the [Porting guide](06-porting-guide.md) and
   validate against [Conformance](07-conformance.md). A port that passes 40/40
   SAP-hash and 30/30 bridge vectors, and is tested where its language is weakest,
   is a real addition.
3. **A mode other than 3.** Evidence of a receiver selecting a different mode, or
   recovered tables for one, would be the first reason to support more than mode 3.

Open an issue or a pull request. Keep the honesty standard: no claim ships without
a check that could have failed.

## Where did this come from?

It was reverse engineered from Apple's FairPlay SAP, starting from an emulator
replay and ending as a compact algorithm, with every step pinned to an independent
implementation. The full story is [How this was derived](10-history.md).

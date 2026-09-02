# What is this?

## AirPlay, in one paragraph

AirPlay is Apple's protocol for streaming audio and video from one device to
another — your phone to an Apple TV, a HomePod, or a third-party speaker that
licensed AirPlay. AirPlay 2 is the current generation. When a **sender** (the
thing with the media) wants to talk to a **receiver** (the speaker or TV), it
opens an RTSP connection and, before anything streams, has to get past an
authentication step.

## FairPlay SAP, and why it blocks you

That authentication step is **FairPlay SAP** (Secure Association Protocol). It is
a challenge–response handshake: the receiver sends the sender a random challenge,
and the sender must compute exactly the right answer to prove it is a legitimate
AirPlay sender. Get the answer wrong and the receiver refuses to continue —
concretely, you see `RTSP/1.0 error` on the `POST /fp-setup` exchange and the
stream never starts.

The problem for anyone building an AirPlay sender is that computing the right
answer requires Apple's cipher. Historically the only way to produce it was to
run **Apple's own compiled binary** (about 1.07 MB) inside an **ARM64 emulator**,
because nobody had the algorithm — only the machine code that implemented it.
That is a large, awkward, architecture-specific dependency to carry just to say
hello.

## What this project is

This repository is that handshake, **reimplemented from scratch as an algorithm**,
in six languages — Go, C, Rust, C#, Kotlin, and Python. It replaces the 1.07 MB
Apple binary and the emulator with roughly 500 KB of portable code that builds
with an ordinary toolchain. Feed it the receiver's 128-byte challenge and it
returns the 20-byte response, in about 5 microseconds, allocating nothing.

The algorithm was recovered by reverse engineering, and its correctness is pinned
by 142 golden vectors and byte-for-byte agreement with two independent emulator-
based implementations. See [How this was derived](10-history.md) for that story.

## What this project is *not*

This is worth stating plainly, because the words "FairPlay" and "Apple" carry a
lot of baggage:

- **It is not FairPlay Streaming DRM.** It decrypts no protected content and
  extracts no content keys. It is an *authentication* handshake — a way for a
  sender to prove who it is — and nothing more.
- **It is confirmed on HomePods, and nothing else.** Three of them accept the
  response and reject corrupted ones. Apple TVs and Macs refuse before ever
  evaluating a response, and third-party MFi receivers do not implement FairPlay
  SAP at all. Do not read "hardware validated" more broadly than that. See
  [Limitations](09-limitations.md).
- **It answers one message mode.** FairPlay defines four message modes; this
  implementation handles mode 3, which is the one every observed exchange used.

## Where to go next

- Just want it running? → [Quickstart](02-quickstart.md)
- Want to see the wire flow? → [The handshake](03-the-handshake.md)
- Porting it? → [Porting guide](06-porting-guide.md)

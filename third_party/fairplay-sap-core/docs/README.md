# Documentation

A wiki for the FairPlay SAP authentication handshake — the exchange an AirPlay 2
**sender** completes to prove itself to a receiver. The pages run shallow to deep;
read top to bottom, or jump to what you need.

| # | Page | For you if… |
|---|------|-------------|
| 01 | [What is this?](01-what-is-this.md) | you've heard of AirPlay but not "FairPlay SAP", and want the lay of the land |
| 02 | [Quickstart](02-quickstart.md) | you just want the `fpsap` binary running and self-checking |
| 03 | [The handshake](03-the-handshake.md) | you want the m1→m2→m3→m4 wire flow and the byte layouts |
| 04 | [Architecture](04-architecture.md) | you want to know what Phase 1, the bridge, and Phase 2 each own |
| 05 | [White-box cryptography](05-whitebox-crypto.md) | you want to know why the tables *are* the cipher |
| 06 | [Porting guide](06-porting-guide.md) | **you are porting this to another language — start here** |
| 07 | [Conformance](07-conformance.md) | you want to validate a port against the shared corpora |
| 08 | [API reference](08-api-reference.md) | you want the entry point in Go or any of the five ports |
| 09 | [Limitations](09-limitations.md) | you're deciding whether to trust this in your project |
| 10 | [How this was derived](10-history.md) | you want the reverse-engineering origin story |
| 11 | [FAQ](11-faq.md) | legality, "will it work on my Apple TV", contributing |
| 12 | [Pairing](12-pairing.md) | you want to reach `/fp-setup` on a real device, or see the hardware results |

## The three pages to read first

- **[Porting guide](06-porting-guide.md)** is the highest-value page in the repo.
  It documents the `uint32` underflow trap and the handful of primitives that
  break silently across languages — knowledge that exists nowhere else.
- **[Limitations](09-limitations.md)** is non-negotiable: the hardware evidence
  covers three HomePods and nothing else, and it answers FairPlay mode 3 only.
- **[Conformance](07-conformance.md)** is how you *prove* a port is right rather
  than merely plausible.

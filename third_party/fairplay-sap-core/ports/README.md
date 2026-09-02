# Ports

Single-file, dependency-free implementations of the FairPlay SAP **Phase-1
bridge** in five languages. Drop the file into your project, no build system
required. Each computes `bridge_x9_head_for_sap(local_sap, gp) → 20 bytes`: given
the 128-byte Phase-1 output buffer (`gp`) and a 128-byte local SAP, it returns the
20 payload-dependent bytes Phase 2 consumes.

These are cores, not complete responders. Phase 1 (white-box AES) needs baked
T-box tables that live only in the Go module, so a port takes the GP buffer as
input — produce it with the Go `fpbridge.GPBuffer`, or from your own Phase-1
tables. The complete, drop-in implementation is the **Go module at the repository
root** (`fpbridge` / `fpsapcore` / `fairplayhash`); the ports here are for
vendoring the core into another language. See the
[API reference](../docs/08-api-reference.md).

## Layout

| Directory | Core | Bridge primitive | Tests |
|---|---|---|---|
| [`c/`](c/) | `fairplay_sapcore.{c,h}` | `fairplay_bridge.{c,h}` | `*_test.c` |
| [`rust/`](rust/) | `fairplay_sapcore.rs` | `fairplaycore.rs` | in-file `#[test]` |
| [`csharp/`](csharp/) | `FairPlaySapCore.cs` | `FairPlayBridge.cs` | `*Test.cs` |
| [`kotlin/`](kotlin/) | `FairPlaySapCore.kt` | `FairPlayBridge.kt` | `*Test.kt` |
| [`python/`](python/) | `fairplay_sapcore.py` | `fairplay_bridge.py` | `test_fairplay_sapcore.py` |

The sixth language, **Go**, is the root module rather than a single-file port.

## Status

Every port passes the shared corpora: **40/40** SAP-hash vectors and **30/30**
bridge vectors from [`../conformance/`](../conformance/). Those corpora were
generated from the Go reference, and that reference is now confirmed against
real hardware — three HomePods accept its response and reject corrupted ones (see
[Limitations](../docs/09-limitations.md)). So a port that reproduces the corpora
is reproducing numbers a real receiver has agreed with, rather than only numbers
this project agrees with itself about. No port has been driven against a device
directly.

Each port is additionally checked where its language is weakest — the build that
turns the algorithm's deliberate unsigned wraps into hard failures:

| Language | Also checked under |
|---|---|
| C | `-Wpedantic -Wconversion`, and UBSan + ASan |
| Rust | **debug** build (overflow checks on) |
| C# | **`<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>`** |
| Kotlin | all arithmetic in `Int`; `ByteArray` only at the API boundary |
| Python | asserts the corpus *rejects* three specific porting mistakes |

## Before you port

**Read the [Porting guide](../docs/06-porting-guide.md) first.** It documents the
`uint32` underflow in the ring-index derivation — which is wrong in three different
ways across these languages and produces a plausible-looking hash on every input
when you get it wrong — plus `rotateOrZero`, `wideSeed`, Go's `&^` operator, and
the 8-bit-modular, order-sensitive byte circuit. Then validate against the
[Conformance](../docs/07-conformance.md) corpora.

## Running the tests

Rough per-language commands (adjust toolchain versions as needed):

```sh
# C
cc -Wall -Wpedantic -Wconversion -fsanitize=undefined,address \
   c/fairplay_sapcore.c c/fairplay_bridge.c c/fairplay_sapcore_test.c -o /tmp/ctest && /tmp/ctest

# Rust (debug, overflow checks on)
rustc --test rust/fairplay_sapcore.rs -o /tmp/rstest && /tmp/rstest

# Python
python3 python/test_fairplay_sapcore.py

# C# and Kotlin: compile the core + its *Test file with your dotnet / kotlinc toolchain.
```

The conformance corpora these tests read live in [`../conformance/`](../conformance/).

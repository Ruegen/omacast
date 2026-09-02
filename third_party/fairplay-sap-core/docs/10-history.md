# How this was derived

This page is the origin story of a from-scratch reimplementation of Apple's FairPlay SAP authentication handshake — the exchange an AirPlay 2 sender performs to prove itself to a receiver before streaming. It began as a faithful replay of Apple's own compiled code and ended as a compact, allocation-free algorithm that runs in microseconds. The path between those two points was reverse engineering, and every step was held to one standard: a result was trusted only when an independent implementation agreed with it byte for byte.

## The starting point: a replay, not an algorithm

The first published version worked, but not in a way anyone would call an implementation. It reproduced the handshake by replaying an **18.8 MB** instruction-by-instruction transliteration of Apple's ARM64 bridge against a **190 KB** baked image of Apple's memory. In effect, the project shipped Apple's code and a snapshot of Apple's RAM, and stepped through them.

That worked and it was verifiable, but it answered the wrong question. It could tell you *what* Apple's code did on a given input; it could not tell you *why*, and it carried nearly 19 MB of machine-level baggage to do so. The rest of this story is the process of replacing the replay with an understanding — and shrinking the artifact, in stages, from that 18.8 MB down to a final **460 KB**.

## Cross-checking against independent implementations

Before touching the internals, the exchange core was pinned against work that shared nothing with it. Two other AirPlay projects — `nored/airfry` and `omarroth/doubletake` — compute the same exchange by emulating Apple's binary, neither of them derived from this research, and both publish golden vectors. This implementation reproduces all eight of them byte for byte: airfry's `CORE_IN` ramp vector plus all seven of doubletake's.

This became the load-bearing check for everything that followed, because it is the only kind of test that cannot fool you: it does not share an implementation with the thing it validates. Alongside it, a corpus of **142 golden vectors** captured the full input space of the handshake. Every transformation described below had to keep all 142 passing and all 8 independent vectors matching — no exceptions.

## From a replay to an algorithm

The reduction started with a measurement rather than a rewrite. The question was how much of the 18.8 MB transliteration the second phase of the handshake actually depended on. The answer was startling:

- The 16 KB scratch window handed to Phase 2 is **never read** — zero it and every golden vector still passes.
- The initial MD5 words, three of the four vector registers, and 44 of the 64 key-schedule bytes are constants.
- Everything else collapses to a single **20-byte digest** that depends only on the 128-byte input buffer.

So 18.8 MB of transliterated Apple code existed to produce twenty bytes. That finding justified the first real port: the transliteration and the memory image were deleted, and the bridge was reconstructed as generated functions derived by partial evaluation of an execution trace. The `fpbridge` package went from **18 MB to 368 KB** with the public API unchanged and 142/142 golden vectors still passing.

This is also where the project learned to distrust its own tooling. Two bugs in the code generator were invisible to its co-simulator, because the co-simulator validated the generated output by *re-running the reference semantics* — it never actually executed the code it emitted. One bug rendered a vector lane-insert as a write to the wrong register; another started generation thousands of instructions before the digest had settled, producing code that reproduced exactly one payload and no other. The generalization stuck: **a validator that shares an implementation with the thing it validates proves nothing.** It resurfaces, in new disguises, throughout this history.

## Shrinking the generated code

The generated layers were correct but bloated — machine-emitted straight-line code, full of repeated idioms and dead work. A sequence of generator-level passes reduced them without changing a single output byte:

- **Idiom re-encoding.** Byte-at-a-time memory access became word operations, constant right-hand sides were folded at generation time, and the pervasive 32-bit conversion arithmetic was named in a small runtime helper. `complete-go/` dropped from **17,404 KB to 10,964 KB**.
- **Dead-store elimination.** A backward liveness pass over the parts in call order removed **69,505 of 278,369 statements (25%)** — chiefly arithmetic chains whose results were overwritten on the next line — taking the tree from **10,964 KB to 8,376 KB**.

The dead-store pass is a small case study in doing this soundly. A naive first attempt claimed 42.6% dead and broke every vector, because some sites index memory through computed expressions the analysis could not resolve, so it wrongly declared their targets dead. The sound version eliminates **register writes only**: each generated file exposes a checkpoint entry point that can hash any range of scratch memory after any part, so no memory store is ever safely dead, and any line reading a register — even inside an index expression it cannot otherwise resolve — counts as a read. The golden vectors caught the unsound version loudly, which is exactly why they exist.

Around the same time, a related claim got corrected honestly. The generated layers had been described as containing no Apple-derived data, then more carefully as carrying baked table pages and code-segment addresses. Careful measurement — sliding the whole shared-cache window, zeroing the address-shaped values, inverting baked bytes as a control — showed the addresses were inherited from the trace, not the algorithm: none of them reach the result, and all were removed. The defensible claim is narrow and true: **no Apple instruction is executed or reproduced.**

## The closed form

The generated layers, even trimmed, were still 7.2 MB of straight-line code standing in for something the authors did not yet understand. The breakthrough came not from further compressing that code but from diffing against `omarroth/doubletake`. Its 29-line `fpsapDescriptorForSAP` computes exactly what the 7.2 MB of generated code computed — the same 20 bytes, big-endian per word where the generated code was little-endian, with the input buffer being doubletake's decrypted body XORed with `0x0f` uniformly across all 128 bytes. Verified over 2,000 random payloads before anything was adopted, the generated layers were deleted and replaced by a readable `fpsapcore` package: **633 lines** where there had been 7.2 MB.

Honesty demands a footnote here. An earlier prediction had held that reducing the layers to compact formulas was possible but unfinished. It was right that the compact form existed and wrong about where it would come from — it was not derived from the generated code at all, but recovered by reading an independent implementation and confirming agreement.

The white-box tables fell the same way. Every 256-entry byte table turned out to be an XOR-affine image of one of a few bases — `T[v] == base[v ^ inXor] ^ outXor` — the representation doubletake encodes explicitly. **135,168 bytes of table data collapsed to 5,168.** The stragglers followed: a MixColumns matrix that is block-diagonal with four identical blocks, T-boxes whose 16 byte lanes reduce to 4 bases, and an entire 12.9 KB table for a stage that had no callers at all.

## Making it fast

Comparing against doubletake was, in the end, about speed as much as size. Once the algorithm was understood, three profile-directed findings — each from a measurement, not a guess — transformed the numbers:

| stage | before | after |
| --- | --- | --- |
| MixColumns | 11,000 ns | 12.9 ns |
| Phase 2 | 102 µs | 2.22 µs |
| bridge | 185 µs | 3.50 µs |
| **full exchange** | **290 µs** | **7.40 µs** |

MixColumns had been applying a fixed 128×128 GF(2) matrix bit by bit — 16,384 branchy iterations, 89% of all Phase-2 time — when read by column it is just 32 nibble lookups. The generated layers had been hex-decoding 128 KB of baked pages on *every* exchange. And the 256-round scramble at the tail of the hash is entirely GF(2)-linear, so it collapses to a single matrix multiply.

Two concurrency bugs surfaced and were fixed along the way: a one-time calibration guarded by an unsynchronized boolean (a data race the instant two exchanges ran at once), and a silent Go initialization-order hazard where a table built in one `init()` read as zero from another. Both replacements keep a reference implementation and a test against it.

A later profile-directed pass — unrolling the MD5 loops so a round computes one value and moves nothing, keeping the AES state in its permuted order to erase per-round lookups, and hoisting bounds checks out of the hottest loop — brought a single exchange down further, to roughly **5 µs**. Not everything worked: masking index tables to make bounds checks provable was 205 ns *slower* than a perfectly predicted branch, and was reverted. That episode taught a measurement discipline worth stating: running two builds back to back gives confidently wrong numbers, because code alignment shifts under unrelated edits. Every reported figure was re-taken by building one test binary per revision and **alternating** between them across many rounds. Measured that way, this exchange runs at **5.19 µs with zero allocations**; doubletake, re-measured in the same interleaved session, runs at **24.96 µs** — a ratio of about **4.97×**.

## Getting the framing right

Speed and a correct core are not the whole handshake, and two framing defects were found and fixed by reading rather than fuzzing.

The first was a mode bug. The exchange had only ever answered for one of the four FairPlay message modes — mode 3 — but never checked which mode a message requested, so it returned mode 3's answer to all of them. doubletake implements all four, and for a single payload it produces four entirely different responses; this implementation matched mode 3's byte for byte and none of the others. Because the two sides reach that output by different constructions — an inverse-AES loop with per-mode round keys against white-box T-boxes over baked tables — the match is evidence, not tautology. The fix is a refusal, not a feature: the exchange validates the whole record and returns an error for any mode but 3, because the tables bake a single key schedule and emitting bytes from the wrong one is worse than saying no. The bug had hidden for so long because the tests built their own messages and filled only the bytes the code happened to read — a validator sharing an *omission* with the thing it validated.

The second was a frozen session. The original m3 message spliced in a 144-byte prefix captured once from an emulator snapshot, so every message it emitted replayed the same local session — which strict receivers reject. Fixing it required the one primitive the module had never carried: **forward AES**, to encrypt the sender's own local session material into the message body. The validation cost nothing, because the oracle was already in the tree: a captured ciphertext and its known plaintext, sitting in the same session, agreed on the first try — and three independently sourced constants (a frame capture, the descriptor solve, and doubletake's round keys) all had to line up for it to pass. The session-aware path then reproduced the captured message across all 142 golden vectors and matched doubletake across the full 164-byte frame.

## What this is, and what it is not

The final artifact is a **460 KB** module — `fairplayhash`, `fpbridge`, and the closed-form `fpsapcore` in about 1,000 lines across ten files — with no interpreter, no generated layers, no Apple instructions, and no residual Apple addresses. It runs an exchange in about **5 µs with zero allocations**, roughly five times faster than the emulator-based implementation it was cross-checked against, and the whole module cold-builds in around 1.5 seconds. When it was contributed upstream to replace a **2,711-line ARM64 interpreter and a ~1.07 MB embedded Apple binary**, every claim was re-verified from a clean tree and driven through hundreds of differential comparisons against that interpreter *before* it was deleted, since that opportunity does not return.

Two honest limits belong on this page. First, this is **authentication only** — the SAP handshake that lets an AirPlay 2 sender establish itself with a receiver. It is **not** FairPlay Streaming DRM, and it decrypts no protected content. Second, the hardware evidence is **narrow**. For most of this history no physical device had ever answered one of these frames, and correctness rested entirely on byte-for-byte agreement with independent implementations and on the 142 golden vectors. On 2026-08-04 that changed: a HomePod mini and a HomePod accepted the computed response and rejected deliberately corrupted ones. That is two devices, one firmware, one day — it confirms the vectors correspond to reality on that hardware, and it does not generalise further. The habit of trusting independent cross-checks above internal tests is what made the result meaningful when it arrived.

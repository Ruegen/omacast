# API reference

This project is one FairPlay SAP authentication handshake reimplemented across six languages. The **Go module** is the complete, drop-in implementation: given a receiver's 128-byte challenge it produces the exact 20-byte response, and it frames that response into the FairPlay SAP records (m1/m2/m3) a real exchange needs. The Go packages are `fpbridge` (records, exchange, session), `fpsapcore` (message-body encryption), and `fairplayhash` (the recovered MD5-family primitives).

The **other five ports** (C, Rust, C#, Kotlin, Python) are single-file portable cores meant to be **vendored** — drop the file in, no build system, no dependencies. They are not complete payload-to-response implementations: Phase 1 (White-Box AES) needs the baked T-box tables that live only in the Go module, so each port's primary entry point is the **Phase-1 bridge / SAP core**, which takes the 128-byte Phase-1 output buffer (`gp`) plus a 128-byte local SAP and returns the 20 payload-dependent bytes Phase 2 consumes. Each port also exposes the bridge MD5 primitive underneath it.

Only FairPlay message **mode 3** is answered anywhere; see the closing note.

## Go

Import path `github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpbridge`. Sizes: the challenge payload is 128 bytes and the response is 20 bytes; m1 is 16 bytes, m2 is 142 bytes, and m3 is 164 bytes.

```go
func FPExchangeBlobless(payload [128]byte) [20]byte
```
Computes the full 20-byte SAP m3 response from the 128-byte m2 challenge, with no Apple blob — Phase 1 (white-box AES) → bridge → Phase 2, all algorithmic. This is the well-tested core (142/142 golden vectors plus eight emulator vectors).

```go
func GPBuffer(payload [128]byte) [128]byte
```
Returns the Phase-1 white-box AES output (the 128-byte "GP buffer") for a payload. Exposed because it is the `gp` input the other-language ports need to run their own Phase 2.

```go
func NewFPSAPM1(capabilities byte) []byte
```
Builds the 16-byte m1 record that opens an exchange. `capabilities` is a bit mask (use `FPSAPFullCapabilities`, `byte(3)`), not a mode.

```go
func FPSAPExchangeM3(m2 []byte) ([]byte, error)
```
Computes the full 164-byte m3 (144-byte constant prefix + 20-byte response) for a receiver's m2. Rejects any m2 that selects a mode other than 3. The constant prefix replays one captured local SAP, so strict receivers that validate the body reject it — use a session for those.

```go
func ParseFPSAPM2(m2 []byte) ([128]byte, error)
```
Validates a 142-byte m2 record (framing + mode check) and returns its 128-byte challenge, for callers that want the 20-byte response without a full m3 frame.

```go
func NewFPSAPM2(mode byte, challenge [128]byte) []byte
```
Builds a well-formed 142-byte m2 carrying a given challenge, for tests and captured-payload drivers.

```go
const SupportedFPSAPMode = 3
```
The only FairPlay message mode this package can answer; Phase 1's baked tables encode mode 3's key schedule alone.

```go
func NewFPSAPSession(entropy io.Reader) (*FPSAPSession, error)
```
Creates a session with a per-session local SAP drawn from `entropy` (use `crypto/rand.Reader`). Unlike `FPSAPExchangeM3`, each session's m3 is unique, so it is accepted by receivers that check the m3 body.

```go
func (s *FPSAPSession) ExchangeM3(m2 []byte) ([]byte, error)
```
Computes the 164-byte m3 for a receiver's m2 using this session's own local SAP encrypted into the body.

```go
func (s *FPSAPSession) LocalSAP() [128]byte
```
Returns this session's 128-byte local SAP.

## C

Two freestanding headers (`<stdint.h>`/`<string.h>` only, reentrant). `fairplay_sapcore.h` is the primary surface; `fairplay_bridge.h` is the MD5 primitive it sits on.

```c
/* Primary: 20 payload-dependent bytes Phase 2 consumes, for a per-session SAP.
 * gp is Phase 1's 128-byte output buffer. */
void fp_bridge_x9_head_for_sap(const uint8_t local_sap[128],
                               const uint8_t gp[128],
                               uint8_t out[20]);

void fp_sap_hash(const uint8_t block[64], uint8_t out[16]);
void fp_sap_descriptor_for_sap(const uint8_t m3_sap[128],
                               const uint8_t m2_sap[128],
                               uint8_t out[20]);
void fp_build_ring_indices(uint8_t x[840], uint8_t y[840],
                           uint8_t z[840], uint8_t w[840]);
uint8_t fp_rotate_or_zero(uint8_t value, uint8_t count);
uint8_t fp_wide_seed(uint8_t value, uint8_t count);
```

The bridge primitive (`fairplay_bridge.h`):

```c
typedef enum { BRIDGE_MUTATION_KDF = 0, BRIDGE_MUTATION_CYCLE = 1 } bridge_mutation_t;
void bridge_md5_init(uint32_t state[4]);
void bridge_md5_compress(uint32_t state[4], uint32_t message[16],
                         uint32_t offset, bridge_mutation_t variant);
```

`fp_bridge_x9_head_for_sap` is the equivalent of the Go Phase-1 bridge: `(local_sap, gp) → 20 bytes`.

## Rust

Two standalone `no_std`-friendly files, no crates. `fairplay_sapcore.rs` holds the primary entry point; `fairplaycore.rs` holds the recovered MD5-family primitives.

```rust
// Primary: (local_sap, gp) -> 20 bytes. gp is Phase 1's 128-byte output buffer.
pub fn bridge_x9_head_for_sap(local_sap: &[u8; 128], gp: &[u8; 128]) -> [u8; 20]

pub fn fairplay_sap_hash(block: &[u8; 64]) -> [u8; 16]
pub fn fpsap_descriptor_for_sap(m3_sap: &[u8; 128], m2_sap: &[u8; 128]) -> [u8; 20]
pub fn fairplay_md5_compress(state: [u32; 4], block: &[u8; 64], mutation: Mutation) -> [u32; 4]
pub fn build_ring_indices() -> ([u8; 840], [u8; 840], [u8; 840], [u8; 840])
pub fn rotate_or_zero(value: u8, count: u8) -> u8
pub fn wide_seed(value: u8, count: u8) -> u8
pub fn apply_scramble(out: &mut [u8; 16])
pub enum Mutation { Swap, Cycle, Kdf }
```

The bridge primitive and NEON prologue (`fairplaycore.rs`):

```rust
pub fn bridge_md5_compress(state: &mut [u32; 4], msg: &mut [u32; 16],
                           offset: u32, variant: BridgeMutation)
pub fn round_c_md5_plain(state: &mut [u32; 4], hidden_g0: &[u32; 16],
                         hidden_g2: Option<&[u32; 16]>)
pub fn compute_hidden_words(ns: &NeonState, x9_data: &[u8], round: usize) -> [u32; 16]
pub fn neon_block(v0_lo: u64, v0_hi: u64, xor_mask: [u64; 2],
                  and_mask: [u64; 2], add_bias: [u64; 2]) -> [u32; 4]
pub enum BridgeMutation { Kdf, Cycle }
```

`bridge_x9_head_for_sap` is the equivalent of the Go Phase-1 bridge.

## C#

Two `static class`es in `namespace FairPlay`. `FairPlaySapCore` carries the primary entry point; `FairPlayBridge` carries the primitive.

```csharp
// Primary: (localSap, gp) -> 20 bytes. gp is Phase 1's 128-byte output buffer.
public static byte[] BridgeX9HeadForSap(byte[] localSap, byte[] gp);

public static byte[] SapHash(byte[] block);
public static byte[] DescriptorForSap(byte[] m3Sap, byte[] m2Sap);
public static void BuildRingIndices(/* x, y, z, w out arrays */);
public static byte RotateOrZero(byte value, byte count);
public static byte WideSeed(byte value, byte count);
public static void ApplyScramble(byte[] outBytes);
```

The bridge primitive (`FairPlayBridge`):

```csharp
public enum BridgeMutation { Kdf, Cycle }
public static readonly uint[] InitialState; // recovered bridge IV
public static void Compress(uint[] state, uint[] message, uint offset, BridgeMutation variant);
```

`BridgeX9HeadForSap` is the equivalent of the Go Phase-1 bridge.

## Kotlin

Two `object` singletons. `FairPlaySapCore` carries the primary entry point; `FairPlayBridge` carries the primitive.

```kotlin
// Primary: (localSap, gp) -> 20 bytes. gp is Phase 1's 128-byte output buffer.
fun bridgeX9HeadForSap(localSap: ByteArray, gp: ByteArray): ByteArray

fun sapHash(block: ByteArray): ByteArray
fun descriptorForSap(m3Sap: ByteArray, m2Sap: ByteArray): ByteArray
fun buildRingIndices(): Array<IntArray>
fun rotateOrZero(value: Int, count: Int): Int
fun wideSeed(value: Int, count: Int): Int
fun applyScramble(out: IntArray)
```

The bridge primitive (`FairPlayBridge`):

```kotlin
enum class BridgeMutation { KDF, CYCLE }
fun initialState(): IntArray                 // fresh state at the recovered bridge IV
fun compress(state: IntArray, message: IntArray, offset: Int, variant: BridgeMutation)
```

`bridgeX9HeadForSap` is the equivalent of the Go Phase-1 bridge.

## Python

Two module-level files, standard-library only. `fairplay_sapcore.py` carries the primary entry point; `fairplay_bridge.py` carries the primitive.

```python
# Primary: (local_sap, gp) -> 20 bytes. gp is Phase 1's 128-byte output buffer.
def bridge_x9_head_for_sap(local_sap, gp): ...

def fairplay_sap_hash(block): ...
def fpsap_descriptor_for_sap(m3_sap, m2_sap): ...
def fairplay_md5_compress(state, block, mutation): ...
def wide_seed(value, count): ...
def rotate_or_zero(value, count): ...
def apply_scramble(out): ...
```

The bridge primitive (`fairplay_bridge.py`):

```python
BRIDGE_HASH1_OFFSET = 0xB36309E4
BRIDGE_HASH1_FINAL_OFFSET = 0x00000000
BRIDGE_HASH2_OFFSET = 0xD68864C0
BRIDGE_MUTATION_KDF = "kdf"      # Hash1's blocks
BRIDGE_MUTATION_CYCLE = "cycle"  # Hash2's blocks

def bridge_md5_compress(state, message, offset, variant): ...
```

`bridge_x9_head_for_sap` is the equivalent of the Go Phase-1 bridge.

## Notes

- **Mode 3 only.** Every entry point here answers FairPlay message mode 3, because Phase 1's tables bake that mode's key schedule and there is no parameter to select another. The Go `FPSAPExchangeM3` / `ExchangeM3` reject any m2 that selects a different mode rather than returning wrong bytes.
- **Computation, not transport.** These are pure computation entry points. Nothing here opens sockets, speaks RTSP, or manages an AirPlay connection — you feed in the challenge (or the Phase-1 `gp` buffer plus a local SAP for the single-file ports) and get bytes back. Wiring those bytes into a live exchange is the caller's job.

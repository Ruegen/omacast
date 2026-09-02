# Porting guide

**This is the highest-value page in the repository.** If you are porting the SAP
core to another language, read it before you write a line, then validate against
[Conformance](07-conformance.md). Every trap below produces a *plausible-looking*
hash when you get it wrong — the code runs, the output looks random, and it is
wrong on every input. None of them are caught by "does it change when the payload
changes" tests. They are caught by the corpora, and only by the corpora.

## The order to port in

1. **`ring_indices`** — the four index tables. Get these wrong and everything
   downstream is silently wrong. Validate against `conformance/ring_indices.csv`
   or the four SHA-256 digests *before* touching the hash.
2. **The SAP hash** — the 840-step ring loop plus the byte circuit. This is where
   almost all the difficulty lives. Validate against `conformance/sap_hash.csv`
   (40 vectors).
3. **The bridge** — MD5 family, descriptor, output encoding. Validate against
   `conformance/bridge_x9head.csv` (30 vectors).

If the SAP hash passes 40/40 and the bridge passes 30/30, the hard part is done.

## Trap 1: the `uint32` underflow in the ring indices

This is the one that fails silently on every input. The scramble reads its
210-byte work buffer through four index sequences, derived once per hash for `i`
in `[0, 840)`:

```
x[i] = (i - 155) % 210
y[i] = (i -  57) % 210
z[i] = (i -  13) % 210
w[i] = (i      ) % 210
```

`i` is a **32-bit unsigned** counter. For `i < 155` the first subtraction
**underflows and wraps through 2³² before the modulo runs**. So `(i-155) % 210`
is *not* `(i+55) % 210` as ordinary signed reasoning suggests. It is
`(i + 101) % 210`, because 2³² mod 210 = 46 and 55 + 46 = 101.

The damage is exactly the first 155 entries of `x`, 57 of `y`, and 13 of `z`; `w`
never underflows.

| | correct | naive `(i+55) % 210` |
|---|---|---|
| `x[0]` | **101** | 55 |
| `x[154]` | **45** | 209 |
| `x[155]` | 0 | 0 — the sequences agree from here on |

Ask each language for `(i - 155) % 210` at `i = 0`, where the answer must be
**101**, and you get six different behaviours:

| language | type | result | note |
|---|---|---|---|
| C | `uint32_t` | **101** | correct, and the least fussy |
| Go | `uint32` | **101** | correct |
| C# | `uint` | **101** | correct |
| Kotlin | `Int` → `.toUInt()` | **101** | correct |
| Rust | `u32`, plain `-` | **panics in debug, 101 in release** | see below |
| Python | `int` | 55 | **wrong** |
| Kotlin/Java | `Int` | −155 | **wrong, and negative** |
| C# | `int` | −155 | **wrong, and negative** |

Three different wrong answers plus a crash. A port that gets 55 produces a
plausible hash on every input. A port that gets −155 indexes a 210-byte buffer at
−155 and either crashes or reads garbage — at least that one is loud.

Spell the wrap out explicitly:

```rust
let x = (i.wrapping_sub(155) % 210) as u8;    // Rust: no plain `-`, it panics in debug
```
```python
x = ((i - 155) % (1 << 32)) % 210             # Python
```
```kotlin
val x = ((i - 155).toUInt() % 210u).toInt()   // Kotlin: via UInt
```

**Rust is the odd one out and the most dangerous**: plain `i - 155` on a `u32`
does not wrap — it *panics in debug builds* (`attempt to subtract with overflow`)
and wraps to the correct 101 only in release. The code is right in the build you
ship and crashes in the build you test. Always use `wrapping_sub`.

**Go and C# refuse to compile the *constant* form.** `uint32(0) - 155` is a
compile error in Go and `CS0220` in C#. The loop compiles fine because `i` is a
variable, so the guard fires where you write a test and not where the bug lives.

## Trap 2: `rotateOrZero` is not `rotl`

The SAP circuit uses a rotate that is **zero, not identity, at count 0**:

```go
func rotateOrZero(input, count byte) byte {
	if count == 0 {
		return 0            // NOT `return input`
	}
	return bits.RotateLeft8(input, int(count))
}
```

A library `rotl(x, 0)` returns `x`. This function returns `0`. The count often
arrives as `-something & 7`, so 0 is a common, live case — get it wrong and a
whole family of vectors drifts. Port the branch, not the rotate.

## Trap 3: `wideSeed` is not `rotl` either

Same shape, different constant at count 0:

```go
func wideSeed(input, count byte) byte {
	if count == 0 {
		return sapSeed[0]   // a specific seed byte, not input, not 0
	}
	return sapSeed[(int(input)<<count | int(input)>>(8-count)) % len(sapSeed)]
}
```

Two things to preserve: the count-0 branch returns `sapSeed[0]`, and the index is
computed on **widened** integers (`int`, not `byte`) so the `<<count` does not
truncate before the modulo. Do the shift in a type wide enough to hold it.

## Trap 4: Go's `&^` is AND-NOT (bit clear)

The circuit is full of `a &^ b`. That is Go's **bit-clear** operator:
`a &^ b == a & ^b == a & ~b` — clear in `a` the bits set in `b`. It is **not** XOR
and not a typo. Translate it as:

```
a & ~b      // C, Rust, C#, Kotlin, Python
```

Watch precedence when you do: `&^` has the same precedence as `&` and `*` in Go
(higher than `+`/`-`). An expression like `aux[3] &^ 0x20 | work[110]>>1 & 0x20`
groups as `((aux[3] &^ 0x20) | ((work[110]>>1) & 0x20))`. When you rewrite `&^` as
`& ~`, keep the grouping with parentheses or you will change the meaning.

## Trap 5: everything is 8-bit modular, and statement order is load-bearing

The byte circuit is ~110 lines of `work[...] += ...`, `hash[...] ^= ...`,
`matrix[...] = ...`. Two things to hold onto:

- **All arithmetic is mod 256.** `+`, `-`, `*` on bytes wrap. In languages whose
  default integer is wider (Python, Kotlin `Int`, C# `int`), mask every
  intermediate back to a byte (`& 0xff`) or you will carry bits that should have
  fallen off. Note `square(v) = v*v` and `cube(v) = v*v*v` are also mod 256.
- **The statement order is part of the algorithm.** Many lines read a cell that an
  earlier line just wrote. Reordering "independent-looking" statements, or
  computing a right-hand side eagerly and reusing it, changes the result. Port the
  lines in the exact order they appear.

Also mind unary-minus precedence in the shift counts: Go's `-s(190) & 7` is
`(-s(190)) & 7`, the low three bits of the two's-complement negation of a byte —
`((256 - s(190)) & 7)` in byte arithmetic. Reproduce that, not `-(s(190) & 7)`.

## How to know you got it right

Do **not** generate your expected indices with the same expression you are
testing — that proves nothing (this repo has shipped that mistake more than once).
Compare against the shared corpora in `conformance/`, which were generated by a
separate program:

- `ring_indices.csv` (or the four digests) — the index tables
- `sap_hash.csv` — 40 SAP-hash vectors
- `bridge_x9head.csv` — 30 whole-bridge vectors

And test where your language is weakest: **Rust in debug** (overflow checks on)
and **C# with `<CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>`** both
turn the deliberate unsigned wraps into hard failures unless every one is spelled
out. A port that only runs in release or unchecked mode has not been tested where
it is weakest. See [Conformance](07-conformance.md) for the full procedure.

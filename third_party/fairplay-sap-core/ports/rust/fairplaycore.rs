// SPDX-License-Identifier: BlueOak-1.0.0
// fairplaycore.rs — the complete recovered cryptographic core of Apple's
// FairPlay SAP handshake, in ONE standalone file. No crates, no build scripts,
// `no_std`-friendly (only wrapping integer arithmetic). Drop it in anywhere.
//
// ─── WHAT THIS IS ────────────────────────────────────────────────────────────
// FairPlay SAP is the authentication handshake an AirPlay sender must complete
// to stream to a HomePod / Apple TV: the receiver sends a 128-byte challenge and
// the sender must return the exact 20-byte response produced by an obfuscated,
// Apple-only function (~1.66M ARM64 instructions, ~93% obfuscation).
//
// Reverse engineering reduced it to two primitives plus a bridge. THIS FILE has
// the portable, language-agnostic cryptographic core of that result:
//
//   round_c_md5_plain     the custom "RoundC" White-Box MD5 compression used by
//                         Phase 2 — standard MD5 structure with recovered
//                         add-constants / rotations / message schedule, plus the
//                         round-17 anomaly and the state-dependent Group-1→2
//                         shuffle. The white-box "affine bijection" provably
//                         collapses to XOR, so this de-obfuscated form is
//                         bit-identical to Apple's encoded one.
//   compute_hidden_words / neon_block
//                         the NEON prologue deriving each round's 16 message
//                         ("hidden") words.
//   bridge_md5_compress   the Phase-1 bridge hash: a STANDARD MD5 compression —
//                         standard schedule, rotations, and the RFC 1321 MD5 K
//                         table plus a per-hash-instance additive offset — with
//                         one extra step: right after round 31, the message
//                         array is permuted in place (one of two
//                         nibble-indexed swap patterns), and rounds 32-63
//                         continue against the permuted array. Runs as two
//                         hashes (5+4 blocks) from IV = round8InitialState.
//                         This was the hardest-won result of the whole effort
//                         — recovered by single-stepping the obfuscated ARX,
//                         where each sub-round's rotate exposes the
//                         pre-rotate accumulator so every constant drops out
//                         — and the round-31 permutation was the hardest part
//                         of that: it was initially missed because the first
//                         extraction pass only validated against a
//                         payload-independent block.
//
// ─── WHAT THIS IS NOT ────────────────────────────────────────────────────────
// Not a complete payload→hash. FairPlay is WHITE-BOX crypto, which has an
// irreducible DATA floor that no amount of cleverness removes:
//
//   • Phase 1 (White-Box AES) needs ~319 KB of T-box tables. Verified: it does
//     NOT reduce to a standard AES call, even though the key was recovered
//     (c251c048e6a027945e178067df8ae466) — the tables fold in the XOR chain and
//     a per-block permutation.
//   • The Phase-1→Phase-2 bridge needs a fixed table-driven program plus ~94 KB
//     of constants (only ~5 KB of which is bridge-specific).
//
// Those are large data companions. This file is the small, reusable LOGIC.
//
// ─── ETHICS ──────────────────────────────────────────────────────────────────
// Defensive interoperability research: reimplementing a documented
// AUTHENTICATION handshake so open-source software can talk to hardware you own.
// No DRM is circumvented and no content keys are extracted.
//
// Verified: the `tests` module below asserts the SAME known-answer vectors as
// the Go port, so the two agree bit-for-bit with the reference implementation.

#![allow(clippy::needless_range_loop)]

// ─── Phase-2 RoundC constant tables (recovered) ──────────────────────────────

const ADD_CONSTS: [u32; 64] = [
    0x9695377e, 0xa7f24a5c, 0xe34b03e1, 0x80e861f4, 0xb4a6a2b5, 0x06b25930, 0x675ad919, 0xbc712807,
    0x28ab2bde, 0x4a6f8ab5, 0xbf29eeb7, 0x48876ac4, 0x2abaa428, 0xbcc30499, 0x65a3d694, 0x08de9b27,
    0xb548b868, 0x86940647, 0xe588ed57, 0xa8e15ab0, 0x9559a363, 0xc16ea759, 0x97cc7987, 0xa6fe8ece,
    0xe10c60ec, 0x82619adc, 0xb3ffa08d, 0x0484a7f3, 0x690e7c0b, 0xbc1a36fe, 0x269995df, 0x4c54df90,
    0xbf24cc48, 0x469c8987, 0x2cc7f428, 0xbd0fcb12, 0x63e97d4a, 0x0b0962af, 0xb5e5de66, 0x7dea4f76,
    0xe7c611cc, 0xa9cbbb00, 0x9419c38b, 0xc3b2b00b, 0x98ff633f, 0xa6062ceb, 0xdecd0ffe, 0x83d6e96b,
    0xb353b54a, 0x0255929d, 0x6abeb6ad, 0xbbbe333f, 0x2485ecc9, 0x4e375f98, 0xbf1a8783, 0x44aef0d7,
    0x2ed31155, 0xbd5779e6, 0x622bd61a, 0x0d32a4a7, 0xb67e1188, 0x7c65853b, 0xea0265c1, 0xaab16697,
];

const OUT_BIASES: [u32; 64] = [
    0x1597aaf6, 0x4afee74e, 0x00a29db4, 0x28f24e7a, 0x6823fe3e, 0x1e57a66c, 0x5f620c23, 0x7799deed,
    0x53b05079, 0x18ce4458, 0x71f50e9a, 0x1e97e2bd, 0x4cb53c72, 0xf8d73fff, 0x40d9b2a2, 0x79fa6a78,
    0x3a2bf366, 0x483b376d, 0x6a883a49, 0x0a9e770c, 0x7429c0e8, 0x0d0e4be5, 0x54df4cee, 0x26d52560,
    0x158c11bb, 0x0507ad81, 0x2a6f27d6, 0x67a96b8d, 0x60707d13, 0x5a6e8346, 0x2cdf0deb, 0x6042060d,
    0x7b1c618c, 0x303b17fa, 0x2d9a7b6a, 0x664b944a, 0x0bdccf3e, 0x10086643, 0x19aef3f8, 0x2efba790,
    0x06471876, 0x55064565, 0x6e3dd970, 0x2344baed, 0x16c8e4af, 0x0cdb4428, 0x1fdada1f, 0x0e0a772d,
    0x0340f8af, 0x04ef307d, 0x7345d54b, 0x568a3ca9, 0x6407b56c, 0x5ba36840, 0x77df87c0, 0x3fb93ddc,
    0x11686a25, 0x36ac9c46, 0x2203aab4, 0x1df07d7b, 0x72624929, 0x7fb4b8eb, 0x46cedb6b, 0x00000000,
];

const ROR_AMOUNTS: [u32; 64] = [
    25, 20, 15, 10, 25, 20, 15, 10,
    25, 20, 15, 10, 25, 20, 15, 10,
    27, 23, 18, 12, 27, 23, 18, 12,
    27, 23, 18, 12, 27, 23, 18, 12,
    28, 21, 16, 9, 28, 21, 16, 9,
    28, 21, 16, 9, 28, 21, 16, 9,
    26, 22, 17, 11, 26, 22, 17, 11,
    26, 22, 17, 11, 26, 22, 17, 11,
];

const MSG_SCHEDULE: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4,
    9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10,
    13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1,
    8, 15, 6, 13, 4, 11, 2, 9,
];

const G2_SHUFFLE_XOR: [u32; 29] = [
    3, 0xd, 0xb, 6, 1, 0, 0xe, 4,
    2, 3, 0, 1, 1, 2, 28, 31,
    4, 31, 32, 16, 16, 4, 0, 8,
    4, 4, 0xf, 4, 0xf,
];

/// Standard RFC 1321 MD5 per-round additive constant table. The bridge
/// hash's real per-round constant is `STD_MD5_K[i] + offset`, where `offset`
/// depends only on which hash-instance a block belongs to (see the
/// `BRIDGE_HASH*_OFFSET` constants below) — NOT a bespoke 64-entry table.
const STD_MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Per-hash-instance additive offsets, added to `STD_MD5_K[i]` for every
/// round of every block in that group.
/// Applies to Hash1's non-final blocks (its first 4 of 5 blocks).
pub const BRIDGE_HASH1_OFFSET: u32 = 0xb36309e4;
/// Applies to Hash1's final (5th) block — plain `STD_MD5_K` with NO offset.
pub const BRIDGE_HASH1_FINAL_OFFSET: u32 = 0x00000000;
/// Applies to all 4 of Hash2's blocks.
pub const BRIDGE_HASH2_OFFSET: u32 = 0xd68864c0;

/// Selects which round-31-boundary message permutation a block uses.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BridgeMutation {
    /// `swap(msg[a&15],msg[b&15]); swap(msg[c&15],msg[d&15]);` then for
    /// shift in {4,8,12}: `swap(msg[(a>>shift)&15], msg[(b>>shift)&15])`.
    /// Used by Hash1's blocks.
    Kdf,
    /// Save `first = msg[idx[0]]`, then `msg[idx[i]] = msg[idx[i+1]]` for
    /// i=0..6, then `msg[idx[7]] = first`, where
    /// `idx = [a&15,b&15,c&15,d&15,(a>>4)&15,(b>>4)&15,(c>>4)&15,(d>>4)&15]`.
    /// Used by Hash2's blocks.
    Cycle,
}

fn apply_bridge_mutation(msg: &mut [u32; 16], variant: BridgeMutation, a: u32, b: u32, c: u32, d: u32) {
    match variant {
        BridgeMutation::Kdf => {
            msg.swap((a & 15) as usize, (b & 15) as usize);
            msg.swap((c & 15) as usize, (d & 15) as usize);
            for shift in [4u32, 8, 12] {
                msg.swap(((a >> shift) & 15) as usize, ((b >> shift) & 15) as usize);
            }
        }
        BridgeMutation::Cycle => {
            let idx: [usize; 8] = [
                (a & 15) as usize, (b & 15) as usize, (c & 15) as usize, (d & 15) as usize,
                ((a >> 4) & 15) as usize, ((b >> 4) & 15) as usize, ((c >> 4) & 15) as usize, ((d >> 4) & 15) as usize,
            ];
            let first = msg[idx[0]];
            for i in 0..idx.len() - 1 {
                msg[idx[i]] = msg[idx[i + 1]];
            }
            msg[idx[idx.len() - 1]] = first;
        }
    }
}

const BRIDGE_ROT: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22,
    7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20,
    5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23,
    4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21,
    6, 10, 15, 21, 6, 10, 15, 21,
];

const BRIDGE_SCHEDULE: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4,
    9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10,
    13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1,
    8, 15, 6, 13, 4, 11, 2, 9,
];

// ─── Phase-2 RoundC White-Box MD5 compression ────────────────────────────────

const ANOMALY_SUBROUND: usize = 17; // sub-round carrying the extra OutBias term
const ANOMALY_ENC_ROUND: usize = ANOMALY_SUBROUND - 4;
const SHUFFLE_SUBROUND: usize = 32; // Group 1->2 boundary (consumes encoded state)

/// Add-constants with the sub-round-17 anomaly folded in, so the inner loop is
/// branch-free apart from the F-function selector.
#[inline]
fn plain_add_const(i: usize) -> u32 {
    let k = ADD_CONSTS[i];
    if i == ANOMALY_SUBROUND {
        k.wrapping_add(OUT_BIASES[ANOMALY_ENC_ROUND])
    } else {
        k
    }
}

/// State-dependent Fisher–Yates shuffle at the Group 1->2 boundary. The four
/// arguments are the ENCODED state words from sub-rounds 28..31.
pub fn shuffle_hidden_g2(g0: &[u32; 16], a_enc: u32, b_enc: u32, c_enc: u32, d_enc: u32) -> [u32; 16] {
    let mut h = *g0;
    let regs = [a_enc, b_enc, c_enc, d_enc];
    for i in 0..8 {
        let reg = regs[i % 4];
        let nibble = if i < 4 { reg & 0xf } else { (reg >> 4) & 0xf };
        let j = (nibble ^ G2_SHUFFLE_XOR[i]) as usize;
        h.swap(i, j);
    }
    h
}

/// One White-Box MD5 ("RoundC") compression with the white-box encoding layer
/// removed; bit-identical to Apple's encoded form.
///
/// `hidden_g2 = None` triggers the state-dependent Group-1->2 shuffle, matching
/// the ARM64 implementation.
pub fn round_c_md5_plain(state: &mut [u32; 4], hidden_g0: &[u32; 16], hidden_g2: Option<&[u32; 16]>) {
    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    // Declared up front so the shuffle result outlives the loop iteration.
    let g2_buf: &mut [u32; 16] = &mut [0; 16];
    let mut have_g2 = hidden_g2.is_some();

    for i in 0..64 {
        if i == SHUFFLE_SUBROUND && !have_g2 {
            // The shuffle reads the ENCODED state words; at i==32 the encoding
            // rounds are a:28 b:31 c:30 d:29.
            *g2_buf = shuffle_hidden_g2(
                hidden_g0,
                a ^ OUT_BIASES[SHUFFLE_SUBROUND - 4],
                b ^ OUT_BIASES[SHUFFLE_SUBROUND - 1],
                c ^ OUT_BIASES[SHUFFLE_SUBROUND - 2],
                d ^ OUT_BIASES[SHUFFLE_SUBROUND - 3],
            );
            have_g2 = true;
        }

        let f = match i >> 4 {
            0 => d ^ (b & (c ^ d)),
            1 => c ^ (d & (b ^ c)),
            2 => b ^ c ^ d,
            _ => c ^ (b | !d),
        };

        let msg = if i >= 32 {
            match hidden_g2 {
                Some(g2) => g2[MSG_SCHEDULE[i]],
                None => g2_buf[MSG_SCHEDULE[i]],
            }
        } else {
            hidden_g0[MSG_SCHEDULE[i]]
        };

        let tmp = a
            .wrapping_add(msg)
            .wrapping_add(f)
            .wrapping_add(plain_add_const(i))
            .rotate_right(ROR_AMOUNTS[i]);

        let new_b = tmp.wrapping_add(b);
        a = d;
        d = c;
        c = b;
        b = new_b;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

// ─── NEON prologue: hidden-word derivation ───────────────────────────────────

pub const NEON_XOR_CONST: u32 = 0x7efd6cfa; // vreg[1]: XOR mask
pub const NEON_AND_CONST: u32 = 0xfdfad9f4; // vreg[3]: AND mask after SHL
pub const NEON_ADD_CONST: u32 = 0xc1d80000; // vreg[2]: final ADD bias

/// Phase-1 NEON register state consumed by the prologue.
#[derive(Clone, Copy, Default)]
pub struct NeonState {
    /// Payload-dependent Phase-1 AES output; used directly for round 0 block 0.
    pub vreg0: [u64; 2],
    /// Phase-1 vreg[1..3]; used for round 0 only (rounds 1+ use the constants).
    pub vreg1: [u64; 2],
    pub vreg2: [u64; 2],
    pub vreg3: [u64; 2],
}

#[inline]
fn dup32(v: u32) -> [u64; 2] {
    let lane = (v as u64) | ((v as u64) << 32);
    [lane, lane]
}
#[inline]
fn shl32_lanes(v: u64, shift: u32) -> u64 {
    let lo = ((v & 0xFFFF_FFFF) << shift) & 0xFFFF_FFFF;
    let hi = ((((v >> 32) << shift) & 0xFFFF_FFFF) as u64) << 32;
    lo | hi
}
#[inline]
fn add32_lanes(a: u64, b: u64) -> u64 {
    let lo = ((a & 0xFFFF_FFFF).wrapping_add(b & 0xFFFF_FFFF)) & 0xFFFF_FFFF;
    let hi = (((a >> 32).wrapping_add(b >> 32)) & 0xFFFF_FFFF) << 32;
    lo | hi
}

/// The NEON prologue transform on one 128-bit block:
///   temp = data ^ xor; data = (data << 1) & and; data = temp + data; data += add
/// All adds are lane-wise 32-bit.
pub fn neon_block(v0_lo: u64, v0_hi: u64, xor_mask: [u64; 2], and_mask: [u64; 2], add_bias: [u64; 2]) -> [u32; 4] {
    let xor_lo = v0_lo ^ xor_mask[0];
    let xor_hi = v0_hi ^ xor_mask[1];
    let and_lo = shl32_lanes(v0_lo, 1) & and_mask[0];
    let and_hi = shl32_lanes(v0_hi, 1) & and_mask[1];
    let res_lo = add32_lanes(add32_lanes(xor_lo, and_lo), add_bias[0]);
    let res_hi = add32_lanes(add32_lanes(xor_hi, and_hi), add_bias[1]);
    [res_lo as u32, (res_lo >> 32) as u32, res_hi as u32, (res_hi >> 32) as u32]
}

#[inline]
fn le_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Produce the 16 hidden (message) words for one White-Box MD5 round.
///
/// `x9_data` is the 64-byte block at x[9] from Phase 1. Round 0 uses the Phase-1
/// vreg state; rounds 1+ use the hardcoded NEON constants.
pub fn compute_hidden_words(ns: &NeonState, x9_data: &[u8], round: usize) -> [u32; 16] {
    let mut hidden = [0u32; 16];
    let (xor_mask, and_mask, add_bias) = if round == 0 {
        (ns.vreg1, ns.vreg3, ns.vreg2)
    } else {
        (dup32(NEON_XOR_CONST), dup32(NEON_AND_CONST), dup32(NEON_ADD_CONST))
    };

    if round == 0 {
        hidden[0] = ns.vreg0[0] as u32;
        hidden[1] = (ns.vreg0[0] >> 32) as u32;
        hidden[2] = ns.vreg0[1] as u32;
        hidden[3] = (ns.vreg0[1] >> 32) as u32;
    } else {
        let h = neon_block(le_u64(&x9_data[0..]), le_u64(&x9_data[8..]), xor_mask, and_mask, add_bias);
        hidden[0..4].copy_from_slice(&h);
    }
    for (blk, base) in [(0x10usize, 4usize), (0x20, 8), (0x30, 12)] {
        let h = neon_block(le_u64(&x9_data[blk..]), le_u64(&x9_data[blk + 8..]), xor_mask, and_mask, add_bias);
        hidden[base..base + 4].copy_from_slice(&h);
    }

    // Per-round counter injected into the MSB of word 5.
    let counter: u32 = if round <= 7 {
        round as u32
    } else if (10..=18).contains(&round) {
        (round - 10) as u32
    } else {
        0
    };
    hidden[5] = hidden[5].wrapping_add(counter << 24);
    hidden
}

// ─── Phase-1 bridge hash (the headline recovered result) ─────────────────────
//
// How the nine blocks fit together. Read this before wiring
// `bridge_md5_compress` into anything, because the obvious assumption is wrong.
//
// The bridge runs two hash instances over the 128-byte Phase-1 GP buffer:
// Hash1 (blocks B1..B5) then Hash2 (blocks C1..C4). Each block compresses a
// 64-byte message with the offset and mutation variant its group calls for
// (see the `BRIDGE_HASH*_OFFSET` constants and `BridgeMutation` below).
//
// It is NOT plain Merkle-Damgard. A block's input state is the previous
// block's output plus a per-block delta, added as four independent u32 lanes:
//
// ```text
// state = prev_output + delta          // four lane-wise 32-bit adds
// bridge_md5_compress(&mut state, &mut msg, offset, variant)
// ```
//
// B1 and C1 start from `BRIDGE_MD5_IV` instead of a previous output. Chain the
// blocks without the delta add and every payload will hash incorrectly, with
// nothing in the primitive to indicate why.
//
// Of the deltas, only two vary with the payload, and they alias across the two
// instances: `delta(B4) == delta(C3)`, a function of `gp[0..47]`;
// `delta(B5) == delta(C4)`, a function of `gp[47..111]`. The rest are constants.
//
// The messages do NOT alias, which is the easy mistake to make once you notice
// the deltas do. B1, B2, C1 and C2 take constant messages. The other five are
// five distinct functions -- B3 and C3 read the identical GP slice and are
// still different functions:
//
// ```text
// B3 = f(gp[0..47])     B4 = f(gp[47..111])    B5 = f(gp[111..128])
// C3 = f(gp[0..47])     C4 = f(gp[47..111])
// ```
//
// What this file does not give you: those five message functions, the
// per-block deltas, and the output encoding that turns the final digest into
// `x9Data`. Those exist only as large generated code in the repository's
// `layer{a,b,c}`. This file is the primitive they call, not a
// complete exchange. See the docs/ directory.
//
// One simplification worth having if you are porting the far side: Phase 2
// reads exactly 20 payload-dependent bytes. It never reads the 16 KB scratch
// window that older integration notes told porters to carry.

/// IV of the bridge hash == round8InitialState in standard MD5 LE word layout.
pub const BRIDGE_MD5_IV: [u32; 4] = [0xb9f3dcdc, 0xfbdc740b, 0x60f77f86, 0x51907216];

/// One 64-round block of the bridge hash: standard MD5 structure with
/// `STD_MD5_K[i]+offset`, and a message permutation applied right after
/// round 31 (before round 32 consumes the message array). `state` is
/// updated in place (Merkle–Damgård add-back). `msg` is mutated in place by
/// the round-31 permutation.
pub fn bridge_md5_compress(state: &mut [u32; 4], msg: &mut [u32; 16], offset: u32, variant: BridgeMutation) {
    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    for i in 0..64 {
        let f = match i >> 4 {
            0 => (b & c) | (!b & d),
            1 => (d & b) | (!d & c),
            2 => b ^ c ^ d,
            _ => c ^ (b | !d),
        };
        let tmp = a
            .wrapping_add(f)
            .wrapping_add(msg[BRIDGE_SCHEDULE[i]])
            .wrapping_add(STD_MD5_K[i])
            .wrapping_add(offset);
        let new_b = b.wrapping_add(tmp.rotate_left(BRIDGE_ROT[i]));
        a = d;
        d = c;
        c = b;
        b = new_b;
        if i == 31 {
            apply_bridge_mutation(msg, variant, a, b, c, d);
        }
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

// ─── Known-answer tests ──────────────────────────────────────────────────────
// Identical vectors to the Go port; both were generated from the verified
// reference implementation, so a pass here proves all three agree bit-for-bit.

#[cfg(test)]
mod tests {
    use super::*;

    const KAT_G0: [u32; 16] = [
        1967335287, 635173569, 2229145243, 3926884741, 2788193791, 545108617, 1131168163, 2986742221,
        1267701127, 2573099857, 1929958827, 2136386325, 3432687119, 2573020441, 511699635, 3460459869,
    ];
    const KAT_G2: [u32; 16] = [
        3442499178, 1264358700, 3802821438, 4073751840, 2177862482, 1733597780, 872430246, 1859815624,
        3799799098, 1421165692, 1991700238, 4044161392, 1978293282, 2375234468, 2884382838, 3681980184,
    ];
    const KAT_MSG: [u32; 16] = [
        2546976663, 960577546, 1698508769, 1855391692, 3391201467, 2557583070, 3274602661, 1912197568,
        191961631, 1855758578, 4196764585, 2306695412, 2755794883, 994892358, 790883565, 349006184,
    ];
    const STD_MD5_IV: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    #[test]
    fn kat_a_roundc_explicit_g2() {
        let mut s = STD_MD5_IV;
        round_c_md5_plain(&mut s, &KAT_G0, Some(&KAT_G2));
        assert_eq!(s, [0xefbcb02b, 0x909e55b2, 0x12b10f9c, 0xd444bbf5]);
    }

    #[test]
    fn kat_b_roundc_state_shuffle() {
        let mut s = STD_MD5_IV;
        round_c_md5_plain(&mut s, &KAT_G0, None);
        assert_eq!(s, [0xba2c62a9, 0xfe15d225, 0x3275e8a7, 0x96e6d0a4]);
    }

    #[test]
    fn kat_c_compute_hidden_words() {
        let ns = NeonState { vreg0: [0x1122334455667788, 0x99aabbccddeeff00], ..Default::default() };
        let x9: Vec<u8> = (0..64u32).map(|i| (i.wrapping_mul(11).wrapping_add(5)) as u8).collect();
        let got = compute_hidden_words(&ns, &x9, 3);
        assert_eq!(
            got,
            [
                1727036671, 2468129067, 3209221463, 3950313859, 396438959, 1187863003, 1861780743,
                2602873139, 3343965535, 4085057931, 531183031, 1272275427, 1996524815, 2737617211,
                3478709607, 4219802003
            ]
        );
    }

    #[test]
    fn kat_d_bridge_md5() {
        let mut s = BRIDGE_MD5_IV;
        let mut m = KAT_MSG;
        bridge_md5_compress(&mut s, &mut m, BRIDGE_HASH1_OFFSET, BridgeMutation::Kdf);
        assert_eq!(s, [0x3295ab96, 0xea9e90eb, 0x908160bd, 0x2261d759]);
    }

    #[test]
    fn kat_e_bridge_md5_chained() {
        let mut s = BRIDGE_MD5_IV;
        let mut m = KAT_MSG;
        bridge_md5_compress(&mut s, &mut m, BRIDGE_HASH1_OFFSET, BridgeMutation::Kdf);
        bridge_md5_compress(&mut s, &mut m, BRIDGE_HASH1_OFFSET, BridgeMutation::Kdf);
        assert_eq!(s, [0x1d33f647, 0xa89e2c45, 0xd174fa6c, 0xb859f083]);
    }

    #[test]
    fn bridge_iv_is_round8_initial_state() {
        assert_eq!(BRIDGE_MD5_IV, [0xb9f3dcdc, 0xfbdc740b, 0x60f77f86, 0x51907216]);
    }

    // ─── Ground-truth vectors, captured from Apple's own code ───────────────
    //
    // The vectors above were generated from this project's own reference
    // implementation, so they prove the ports agree with each other -- not that
    // any of them is right. An earlier version of this file shipped a bespoke
    // 64-entry constant table that passed every self-generated KAT and was
    // still wrong, because the single block those KATs exercised has a
    // payload-independent message and never triggers the round-31 permutation.
    //
    // These five are different in kind: each is a (state, message, result)
    // triple lifted from a trace of Apple's real bridge hash. Between them they
    // span all three per-hash offsets, both mutation variants, and three blocks
    // whose message genuinely varies with the payload. Same vectors as
    // fairplayhash/bridge_md5_test.go.
    #[allow(clippy::type_complexity)]
    const HARDWARE_KATS: &[(&str, u32, BridgeMutation, [u32; 4], [u32; 16], [u32; 4])] = &[
        ("B1", BRIDGE_HASH1_OFFSET, BridgeMutation::Kdf,
         [0xb9f3dcdc, 0xfbdc740b, 0x60f77f86, 0x51907216],
         [0x4739a369, 0x98051ca8, 0xcc907eb5, 0x2b2f24b1,
          0x6a9cf800, 0x307a5e9e, 0xe083f082, 0x05f89a33,
          0xb5827de2, 0xac11f834, 0x4bb8d831, 0x907269ea,
          0x47a571ef, 0xbaa9597f, 0x10651a4b, 0x9759f089],
         [0xf20bb0af, 0x2d1ce261, 0xe8e91068, 0xec7e94db]),
        ("B3", BRIDGE_HASH1_OFFSET, BridgeMutation::Kdf,
         [0xae98150b, 0xcab5b264, 0x5800b818, 0xcd8094af],
         [0xec44bb2f, 0x6d4b9c49, 0x75e66e88, 0xd4012450,
          0x0758a421, 0x019ee7e0, 0xd437cbea, 0x7d8def76,
          0xc91e3235, 0xe57a6ce0, 0x43b44a7e, 0x6e1ce5ed,
          0x42ed3697, 0x84f0cfd9, 0x34c43487, 0xe05a1a5a],
         [0xa5cdff64, 0xef81680a, 0x9ea37b66, 0x3f794376]),
        ("B5", BRIDGE_HASH1_FINAL_OFFSET, BridgeMutation::Kdf,
         [0xcce8dabc, 0xdf507ee8, 0x5cea1ef2, 0xe7174fa7],
         [0xc629579b, 0xd9b6360a, 0xc8701f59, 0xfbe19fe3,
          0x4fec4e27, 0x5efdf2e8, 0x3097ae70, 0xfbe0003f,
          0x1c398000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x10090000, 0x00000000],
         [0x367c7f22, 0x37dde99e, 0xc0c00053, 0x1247390a]),
        ("C1", BRIDGE_HASH2_OFFSET, BridgeMutation::Cycle,
         [0xd39b6229, 0x9ae94dd0, 0x8c31d460, 0xeb9bd436],
         [0xc9bc378d, 0x335c58bf, 0x983d6c0c, 0x5f154286,
          0xa3779d24, 0x0d5503c2, 0xbd5e95a6, 0xe2d33f57,
          0x925d2306, 0x88ec9d58, 0x28937d55, 0x6d4d0f0e,
          0x24801713, 0x9783fea3, 0xed3fbf6f, 0x743495ad],
         [0xc6bf6e93, 0x542728dc, 0xe90f673c, 0x5ae9bfa5]),
        ("C2", BRIDGE_HASH2_OFFSET, BridgeMutation::Cycle,
         [0xd1dd1548, 0xefd049ca, 0x68e33ee6, 0x3d31dc46],
         [0x8f831b50, 0x5b78ef45, 0x14c24b8d, 0x03f28b33,
          0xb972d234, 0xf91c2a4b, 0x870a4976, 0x68e04f99,
          0x4f338181, 0x642e5904, 0xc006efcd, 0x4b5e1860,
          0x1b08c6a8, 0x4a5cda50, 0x3d457ddd, 0x20aca5db],
         [0xd30fe3ad, 0x8670fb82, 0xc1ebdda2, 0x3fb07aa8]),
    ];

    #[test]
    fn kat_f_bridge_md5_against_hardware() {
        for &(name, offset, variant, state, msg, want) in HARDWARE_KATS {
            let mut s = state;
            let mut m = msg;
            bridge_md5_compress(&mut s, &mut m, offset, variant);
            assert_eq!(s, want, "hardware KAT {} failed", name);
        }
    }

    // Control for the test above. STD_MD5_K is a `const` and cannot be
    // perturbed at runtime the way the Go port does, so instead this asserts
    // that the two things the old, broken implementation got wrong -- the
    // per-hash offset and the round-31 permutation -- actually change the
    // result. A port that hardcodes one offset, or silently skips the
    // permutation, cannot pass both this and the KATs above.
    #[test]
    fn kat_g_offset_and_mutation_are_load_bearing() {
        for &(name, offset, variant, state, msg, want) in HARDWARE_KATS {
            let wrong_offset = offset.wrapping_add(1);
            let mut s = state;
            let mut m = msg;
            bridge_md5_compress(&mut s, &mut m, wrong_offset, variant);
            assert_ne!(s, want, "{}: offset is not load-bearing", name);

            let flipped = match variant {
                BridgeMutation::Kdf => BridgeMutation::Cycle,
                BridgeMutation::Cycle => BridgeMutation::Kdf,
            };
            let mut s = state;
            let mut m = msg;
            bridge_md5_compress(&mut s, &mut m, offset, flipped);
            assert_ne!(s, want, "{}: mutation variant is not load-bearing", name);
        }
    }
}

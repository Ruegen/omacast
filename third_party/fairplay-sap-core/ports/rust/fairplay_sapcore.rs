// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f, via
// fpsapcore. See ../../NOTICE.md.
//
// fairplay_sapcore.rs — the FairPlay SAP Phase-1 bridge, in ONE standalone
// file. No crates, no build scripts, `no_std`-friendly. Drop it in anywhere.
//
// ─── WHAT THIS IS ────────────────────────────────────────────────────────────
// fairplaycore.rs in this directory has the bridge *primitive*. This has the
// functions that feed it, so the two together are a complete responder:
//
//     bridge_x9_head_for_sap(local_sap, gp) -> [u8; 20]
//
// `gp` is Phase 1's 128-byte output buffer. The 20 bytes out are the only
// payload-dependent input Phase 2 consumes.
//
// ─── THREE THINGS THAT WILL BITE A PORT ──────────────────────────────────────
// Each is silent, and each fails 30+ of the 40 vectors in ../../conformance/.
//
// 1. The ring index derivation underflows a u32 on purpose. In Rust plain
//    `i - 155` PANICS in debug and wraps only in release, so it is written
//    `wrapping_sub` here. See ../../conformance/README.md.
// 2. `rotate_or_zero` returns 0 for a zero count, not the input. It is not a
//    rotate.
// 3. `wide_seed`'s index is computed WIDER than a byte. Masking it to 8 bits
//    changes the answer.
//
// Every other arithmetic operation is byte-wide and wraps, hence the
// `wrapping_*` calls throughout. They are load-bearing, not defensive.

#![allow(clippy::needless_range_loop)]

// ─── byte helpers ────────────────────────────────────────────────────────────

/// Rotate a byte left. Matches Go's `bits.RotateLeft8`.
#[inline]
fn rotl8(v: u8, n: u32) -> u8 {
    v.rotate_left(n & 7)
}

/// Go's `rotateOrZero`: a count of 0 yields 0, NOT the input.
///
/// This is the one rotate in the algorithm that is not a rotate. Porting it as
/// an ordinary rotation is silent and wrong.
#[inline]
pub fn rotate_or_zero(value: u8, count: u8) -> u8 {
    if count == 0 {
        0
    } else {
        rotl8(value, count as u32)
    }
}

#[inline]
fn majority(a: u8, b: u8, c: u8) -> u8 {
    a ^ ((a ^ b) & (a ^ c))
}

#[inline]
fn select_bits(mask: u8, if_set: u8, if_clear: u8) -> u8 {
    if_clear ^ ((if_set ^ if_clear) & mask)
}

#[inline]
fn square(v: u8) -> u8 {
    v.wrapping_mul(v)
}

#[inline]
fn cube(v: u8) -> u8 {
    v.wrapping_mul(v).wrapping_mul(v)
}

/// Go's `&^` (AND NOT / bit clear). Rust has no operator for it.
#[inline]
fn and_not(a: u8, b: u8) -> u8 {
    a & !b
}

// ─── constants ───────────────────────────────────────────────────────────────

pub const SAP_SEED: [u8; 21] = [
    0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02, 0xA2, 0xA9, 0x11, 0x00,
    0x0C, 0xB3, 0x52, 0xC0, 0xBD, 0xE3, 0x1B, 0x49, 0xC7,
];

const SAP_INITIAL_HASH: [u8; 20] = [
    0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18, 0xDF, 0xBE, 0xB2, 0xF8,
    0x38, 0x62, 0xEC, 0x22, 0x93, 0xD1, 0x20, 0x8F,
];

const SAP_INITIAL_MATRIX: [u8; 35] = [
    0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3, 0x9A, 0x56, 0xF6, 0x1C,
    0x14, 0x3F, 0x0C, 0x1D, 0x3B, 0x36, 0x83, 0xB1, 0x39, 0x51, 0x4A, 0xAA,
    0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE, 0xC3, 0x20, 0x9D, 0x42, 0xB8,
];

const FAIRPLAY_INITIAL_SESSION_KEY: [u8; 16] = [
    0xDC, 0xDC, 0xF3, 0xB9, 0x0B, 0x74, 0xDC, 0xFB, 0x86, 0x7F, 0xF7, 0x60,
    0x16, 0x72, 0x90, 0x51,
];

const FPSAP_DESCRIPTOR_PREFIX: [u8; 17] = [
    0xA0, 0x44, 0x9C, 0x4D, 0x09, 0xE4, 0xBD, 0x7F, 0x6E, 0xC5, 0xD0, 0xCC,
    0x35, 0x9D, 0xA7, 0x46, 0x7A,
];

const FPSAP_DESCRIPTOR_SUFFIX: [u8; 17] = [
    0x97, 0xB5, 0x0F, 0x84, 0xE2, 0x15, 0x5A, 0x9C, 0x24, 0x99, 0x1C, 0xF4,
    0x3A, 0x09, 0x63, 0x55, 0x47,
];

/// The white-box output encoding Phase 1 leaves on the GP buffer: one XOR
/// constant across all 128 bytes. Measured, not assumed.
pub const GP_OUTPUT_MASK: u8 = 0x0F;

/// Go's `wideSeed`.
///
/// The index is computed in a WIDER type than a byte: `value << count` is
/// allowed to exceed 255 before the modulo. Masking it to 8 bits changes the
/// result, so the `u32` here is deliberate.
#[inline]
pub fn wide_seed(value: u8, count: u8) -> u8 {
    if count == 0 {
        return SAP_SEED[0];
    }
    let wide = ((value as u32) << count) | ((value as u32) >> (8 - count));
    SAP_SEED[(wide % SAP_SEED.len() as u32) as usize]
}

// ─── the ring index tables ───────────────────────────────────────────────────

/// The four index sequences, built once.
///
/// `wrapping_sub` is load-bearing. Plain `i - 155` panics in debug builds and
/// wraps only in release — so the naive form gives a binary that is correct in
/// the build you ship and crashes in the build you test.
pub fn build_ring_indices() -> ([u8; 840], [u8; 840], [u8; 840], [u8; 840]) {
    let mut x = [0u8; 840];
    let mut y = [0u8; 840];
    let mut z = [0u8; 840];
    let mut w = [0u8; 840];
    for i in 0..840u32 {
        x[i as usize] = (i.wrapping_sub(155) % 210) as u8;
        y[i as usize] = (i.wrapping_sub(57) % 210) as u8;
        z[i as usize] = (i.wrapping_sub(13) % 210) as u8;
        w[i as usize] = (i % 210) as u8;
    }
    (x, y, z, w)
}

/// `work` is three copies of the permuted block plus its first 18 bytes.
fn fill_work(block: &[u8; 64]) -> [u8; 210] {
    let mut p = [0u8; 64];
    for i in 0..64 {
        p[i] = block[i ^ 3];
    }
    let mut work = [0u8; 210];
    work[0..64].copy_from_slice(&p);
    work[64..128].copy_from_slice(&p);
    work[128..192].copy_from_slice(&p);
    work[192..210].copy_from_slice(&p[..18]);
    work
}

// ─── the SAP hash ────────────────────────────────────────────────────────────

/// FairPlay's proprietary SAP hash of one 64-byte block. Not a standard hash.
pub fn fairplay_sap_hash(block: &[u8; 64]) -> [u8; 16] {
    let (rx, ry, rz, rw) = build_ring_indices();

    let mut hash = SAP_INITIAL_HASH;
    let mut matrix = SAP_INITIAL_MATRIX;
    let mut aux = [0u8; 10];
    let mut work = fill_work(block);

    for i in 0..840usize {
        let xv = work[rx[i] as usize];
        let yv = work[ry[i] as usize];
        let zv = work[rz[i] as usize];
        let wi = rw[i] as usize;
        work[wi] = rotl8(yv, 5)
            .wrapping_add(rotl8(zv, 3) ^ work[wi])
            .wrapping_sub(rotl8(xv, 7));
    }

    nonlinear_circuit(&mut hash, &mut matrix, &mut aux, &mut work);

    let mut out = [0u8; 16];
    // Go: copy(out[:], aux[:3]) then copy(out[4:], aux[3:]) — 3 then 7 bytes.
    out[0..3].copy_from_slice(&aux[0..3]);
    out[4..11].copy_from_slice(&aux[3..10]);
    for b in out.iter_mut() {
        *b = b.wrapping_add(0xE1);
    }
    out[3] = 0x3D;
    out[11] = 0x3C;
    out[10] ^= aux[3] ^ 133;

    for i in 0..20usize {
        out[i & 15] ^= work[i] ^ matrix[i] ^ hash[i];
    }
    for i in 20..35usize {
        out[i & 15] ^= work[i] ^ matrix[i];
    }
    for i in 35..210usize {
        out[i & 15] ^= work[i];
    }

    apply_scramble(&mut out);
    out
}

/// 256 rounds of XOR-and-rotate, in place over 16 bytes.
///
/// Every operation is GF(2)-linear, so this collapses to a 128x128 binary
/// matrix — which is what the Go version ships for speed. The loop is kept
/// here because a snippet is for reading, and the matrix is 2 KB of opaque data
/// that says nothing about what it does.
pub fn apply_scramble(out: &mut [u8; 16]) {
    for i in 0..256usize {
        out[i & 15] ^= rotl8(out[i.wrapping_sub(7) & 15], 1)
            ^ rotl8(out[i.wrapping_sub(5) & 15], 6)
            ^ rotl8(out[i.wrapping_sub(1) & 15], 5);
    }
}

/// The straight-line byte circuit. Statement order is load-bearing throughout:
/// several lines assign to a cell a later line reads, and `matrix[12]` is
/// written three times. Reordering for tidiness breaks it.
///
/// Go reads through small closures; Rust's borrow checker will not allow those
/// alongside the mutations, so they are macros that expand inline instead.
fn nonlinear_circuit(
    hash: &mut [u8; 20],
    matrix: &mut [u8; 35],
    aux: &mut [u8; 10],
    work: &mut [u8; 210],
) {
    macro_rules! hi { ($i:expr) => { hash[($i) as usize % 20] } }
    macro_rules! si { ($i:expr) => { SAP_SEED[($i) as usize % 21] } }
    macro_rules! h  { ($i:expr) => { hi!(work[$i]) } }
    macro_rules! m  { ($i:expr) => { matrix[work[$i] as usize % 35] } }
    macro_rules! s  { ($i:expr) => { si!(work[$i]) } }
    macro_rules! ma { ($i:expr) => { matrix[aux[$i] as usize % 35] } }

    matrix[12] = 0x14u8.wrapping_add(
        select_bits(92, work[64], work[99] / 3) & wide_seed(s!(206), 4),
    );
    work[4] = 2u8.wrapping_mul(square(work[99] / 5));
    work[153] ^= square(m!(203)).wrapping_mul(work[190]);
    hash[3] = 0x13 ^ ((s!(205) >> 1) & 0x10);
    work[33] = work[33].wrapping_sub(and_not(s!(36), 9));
    aux[5] = (and_not(m!(67), 2) | 1 | ((h!(181) >> 6) & 2) | (hash[3] & 0x10)).wrapping_sub(15);
    matrix[12] = 0x07;
    work[2] = work[2].wrapping_sub(64);
    hash[19] = s!(58);
    aux[4] = 92u8.wrapping_sub(m!(32));
    aux[9] = m!(15).wrapping_add(0x9E);
    work[34] = work[34].wrapping_add(si!(aux[9]) / 5);
    hash[19] = hash[19].wrapping_add(0xE6 ^ ((hi!(aux[9]) >> 1) & 0x66));
    work[15] ^= 3u8
        .wrapping_mul(rotate_or_zero(work[72], s!(190).wrapping_neg() & 7))
        .wrapping_sub(9u8.wrapping_mul(s!(126)));
    hash[15] ^= cube(m!(181));
    matrix[4] ^= work[202] / 3;
    matrix[1] = matrix[1].wrapping_add(cube(majority(
        92u8.wrapping_sub(hi!(aux[4])),
        !work[105],
        0xC6,
    )));
    // int math, then truncate
    hash[19] ^= (((224 | (s!(92) & 27)) as u32 * m!(41) as u32) / 3) as u8;
    work[140] = work[140].wrapping_add(rotate_or_zero(92, work[5].wrapping_neg() & 7));
    matrix[12] = matrix[12].wrapping_add(majority(!work[4] ^ m!(12), work[182], 192));
    work[36] = work[36].wrapping_add(125);
    work[124] = rotl8(majority(majority(work[138], hash[15], 74), h!(43), 95), 4);
    let aux_hash = hi!(aux[9]);
    aux[1] = and_not(0x4C, aux_hash & (s!(68) << 1));
    aux[2] = 222u8.wrapping_sub(majority(
        ((work[177] as u32 + s!(79) as u32) >> 1) as u8,
        ((3 * work[148] as u32) / 5) as u8,
        matrix[1],
    ));
    matrix[16] = matrix[16].wrapping_add(
        (and_not(ma!(4), 0x60) | aux_hash | 8).wrapping_sub(rotl8(work[33], 2) | 128),
    );
    hash[14] ^= ma!(2);
    work[19] = work[19].wrapping_add(majority(
        rotate_or_zero(si!(h!(201)), (m!(112) << 1) & 6),
        (and_not(h!(208), 0x7C) | (h!(164) & 0x7C)) / 5,
        37,
    ));
    matrix[8] = rotate_or_zero(140, square(s!(45)).wrapping_neg() & 7) ^ aux[4];
    work[190] = 56;
    work[53] = !((h!(83) | 204) / 5);
    hash[13] = hash[13].wrapping_add(h!(41));
    hash[10] = majority(ma!(4), work[2], aux[2]) / 15;
    aux[3] = 92u8.wrapping_sub(square(0x28 | (ma!(1) & (0x12 | (s!(2) & 4)))));
    let seed_bits = si!(aux[4]);
    matrix[13] ^= seed_bits;
    aux[6] = 92u8.wrapping_add(square(majority(m!(179).wrapping_sub(38), aux[2], 177)));
    let expansion_bits = majority(aux[3].wrapping_add(aux[4] & 74), !seed_bits, 121);
    work[47] ^= m!(89).wrapping_add(majority(expansion_bits ^ 0xA6, aux[4], 4));
    aux[7] = (seed_bits / 3)
        .wrapping_sub(ma!(9))
        .wrapping_sub(0x14 | (work[151] & ((aux[4] & 0x88) | 0x62)) | (aux[4] & 0x22));
    let expanded_selector = expansion_bits ^ ((aux[4] & 0xCA) >> 1) ^ 75;
    aux[9] = aux[9].wrapping_add(
        0x80 | (majority(aux[7], work[151], 0x20) & 0x64) | (seed_bits & 0x44) | (ma!(9) & 0x1B),
    );
    matrix[33] ^= work[26];
    matrix[30] = (aux[9] / 3).wrapping_sub(and_not(aux[4], 8) | 0x13) ^ h!(122);
    work[22] = (m!(90) & 0x1B) | 0x44;
    let wide = select_bits(71, matrix[expanded_selector as usize % 35], si!(aux[5])) as u32;
    // int math, then truncate
    matrix[18] = matrix[18].wrapping_add(((wide * wide * wide) >> 1) as u8);
    matrix[5] = matrix[5].wrapping_sub(s!(92));
    matrix[18] ^= select_bits(aux[3], ma!(3), select_bits(16, m!(183), work[41]))
        .wrapping_mul(select_bits(expanded_selector, h!(59), work[17]));
    matrix[22] = majority(
        select_bits(hash[14] | 28, (work[7] & 28) | 0x82, h!(93)),
        rotate_or_zero(ma!(4), rotate_or_zero(work[11], m!(28).wrapping_neg() & 7) & 7),
        matrix[33],
    )
    .wrapping_add(74);
    hash[15] = hash[15].wrapping_sub(majority(
        majority(aux[3], aux[4], 214),
        si!(h!(39) ^ 217),
        aux[6],
    ));

    let hash9 = hi!(aux[9]);
    let indexed_hash = hi!((aux[4] / 3).wrapping_sub(aux[9] | work[22])
        ^ aux[6]
        ^ (((m!(57) | hash9) & (0x52 | (aux[9] & 0x0D)))
            | (((m!(57) & hash9) | aux[9]) & 0x20)));
    aux[6] = square(square(h!(99))) | ma!(9);
    aux[1] = aux[1]
        .wrapping_add(rotate_or_zero(h!(151) | s!(202), h!(50) & 7))
        .wrapping_add(majority(
            h!(4),
            ((select_bits(matrix[16], indexed_hash, m!(138)) as u32
                + select_bits(17, work[33], s!(39)) as u32)
                / 5) as u8,
            147,
        ));
    aux[0] = select_bits(
        hash[10] & 7,
        ma!(6) & h!(209),
        select_bits(0x47, rotate_or_zero(s!(127), ma!(6) & 7), si!(ma!(5)) << 1),
    );
    let selected_square = select_bits(198, square(m!(14)), h!(145) ^ aux[0]);
    let seed9 = si!(aux[9]);
    let hash3 = hi!(aux[3]);
    matrix[2] = matrix[2]
        .wrapping_add(((hash3 << 1) & ((work[25] & 0x96) | (seed9 & 8))) | (seed9 & 0x40));
    matrix[14] =
        matrix[14].wrapping_sub(select_bits(34, work[97], ma!(3) & (aux[0] ^ m!(100))));
    work[23] ^= majority(majority(s!(17), hash3, aux[0]), work[50] / 3, 0x76) << 1;
    hash[17] = 115;
    hash[13] = ((majority(hi!(aux[7]), work[10], 82) >> 1) & 0x68) | (h!(39) & 0x17);
    matrix[33] = matrix[33].wrapping_sub(work[113] & 9);
    matrix[28] = matrix[28].wrapping_sub(and_not(aux[3], 0x20) | ((work[110] >> 1) & 0x20));
    work[95] = si!(aux[3]);
    hash[15] = majority(work[95].wrapping_sub(48), !work[184], 189)
        & cube(majority(aux[7], si!(aux[1]), 0xAA));
    matrix[22] = matrix[22].wrapping_add(work[183]);
    aux[4] ^= 3u8.wrapping_mul(s!(1));
    aux[5] = aux[5].wrapping_add(
        198u8
            .wrapping_mul(majority(s!(178), ma!(1), 209))
            .wrapping_mul(h!(13))
            .wrapping_mul(s!(26) >> 1),
    );
    aux[8] = select_bits(10, ma!(3), ma!(9));
    matrix[18] = matrix[18].wrapping_sub(select_bits(
        hash[15],
        aux[5] / 15,
        cube(hi!(aux[6]) | 81),
    ));
    aux[1] = aux[1].wrapping_add(si!(hi!(aux[1])) / 3).wrapping_sub(h!(160));
    hash[16] = 147u8.wrapping_sub(majority(
        aux[0],
        majority(
            s!(69),
            work[172],
            aux[2].wrapping_sub(selected_square).wrapping_add(77),
        ),
        0xC2 | (aux[0] & 5),
    ));
    hash[3] = hash[3].wrapping_sub(wide_seed(
        majority(s!(155), work[105], 141),
        majority(s!(168), h!(29), 6) & 7,
    ));
    work[5] = rotate_or_zero(0x38, (h!(61) / 5).wrapping_neg() & 7) ^ (!ma!(8) / 5);
    work[198] = work[198].wrapping_add(work[3]);
    let wide = (162 | ma!(9)) as u32;
    // int math, then truncate
    work[164] = work[164].wrapping_add(((wide * wide) / 5) as u8);
    aux[2] = majority(rotate_or_zero(139, aux[5].wrapping_neg() & 6), hi!(aux[3]), 12)
        | select_bits(95, cube(seed9), hi!(aux[7]));
    matrix[12] = matrix[12]
        .wrapping_add((16 | ((work[103] | 60) & (aux[2] | (work[103] & 32)))) / 3);
    work[143] = work[143].wrapping_sub(
        0x12 | (select_bits(
            aux[9],
            select_bits(matrix[8], work[35], aux[7]),
            aux[8] / 3,
        ) & (0x4D | ((work[172] >> 1) & 0x20))),
    );
    matrix[29] = 162;
    hash[15] = hash[15].wrapping_add(majority(
        m!(149) ^ square(work[43]),
        select_bits(95, h!(125), si!(aux[1])) >> 1,
        115,
    ));
    aux[9] = aux[9].wrapping_sub(hi!(aux[7]));
    hash[7] = hash[7].wrapping_sub(square(rotate_or_zero(
        ma!(5),
        m!(17).wrapping_mul(m!(17) & 1).wrapping_neg(),
    )));
    matrix[8] = matrix[8].wrapping_add(cube(s!(202))).wrapping_sub(work[184]);
    hash[16] = (m!(102) << 1) & 0x84;
    aux[6] ^= si!(aux[7]) >> 1;
    hash[7] = hash[7]
        .wrapping_sub(h!(191))
        .wrapping_add(select_bits(177, si!(si!(aux[1])), s!(80) << 1));
    hash[6] = h!(119);
    hash[12] = (hi!(aux[8]) ^ m!(71).wrapping_add(m!(15)))
        & majority(and_not(work[118], 0x2C) | 2, square(hi!(aux[9])), 27);
    let digest_index = select_bits(
        0xA9,
        s!(57).wrapping_mul(231),
        majority(work[32], ma!(1), 23),
    ) / 5;
    let seed_sample = si!(aux[6]);
    aux[5] = majority(
        (seed_sample & 0x1C) | (h!(82) & 0xA2) | (si!(digest_index) & 0x41),
        majority(cube(hi!(aux[7])), work[82], 92),
        192,
    ) ^ digest_index;
    matrix[25] ^= 2u8
        .wrapping_mul(hi!(aux[9]))
        .wrapping_mul(work[5])
        .wrapping_sub(rotate_or_zero(aux[4], seed_sample & 7) & aux[3].wrapping_add(110));
}

// ─── the FairPlay MD5 family ─────────────────────────────────────────────────

const FAIRPLAY_MD5_SHIFT: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4,
    11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6,
    10, 15, 21,
];

const FAIRPLAY_MD5_CONSTANT: [u32; 64] = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A,
    0xA8304613, 0xFD469501, 0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821, 0xF61E2562, 0xC040B340,
    0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8,
    0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, 0x289B7EC6, 0xEAA127FA,
    0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92,
    0xFFEFF47D, 0x85845DD1, 0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    Swap,
    Cycle,
    Kdf,
}

/// Standard MD5 rounds and constants, but big-endian message words and a
/// message-schedule mutation after round 31. A stock MD5 cannot do this.
pub fn fairplay_md5_compress(state: [u32; 4], block: &[u8; 64], mutation: Mutation) -> [u32; 4] {
    let mut message = [0u32; 16];
    for i in 0..16 {
        message[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    for round in 0..64usize {
        let (f, word) = if round < 16 {
            ((b & c) | (!b & d), round)
        } else if round < 32 {
            ((d & b) | (!d & c), (5 * round + 1) & 15)
        } else if round < 48 {
            (b ^ c ^ d, (3 * round + 5) & 15)
        } else {
            (c ^ (b | !d), (7 * round) & 15)
        };

        let next_b = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(FAIRPLAY_MD5_CONSTANT[round])
                .wrapping_add(message[word])
                .rotate_left(FAIRPLAY_MD5_SHIFT[round]),
        );
        // Go writes this as a, b, c, d = d, next_b, b, c -- one simultaneous
        // rotation of the roles, not four sequential moves.
        (a, b, c, d) = (d, next_b, b, c);

        if round == 31 {
            mutate_message(&mut message, a, b, c, d, mutation);
        }
    }

    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
    ]
}

fn mutate_message(message: &mut [u32; 16], a: u32, b: u32, c: u32, d: u32, mutation: Mutation) {
    match mutation {
        Mutation::Swap | Mutation::Cycle => {
            let idx = [
                (a & 15) as usize,
                (b & 15) as usize,
                (c & 15) as usize,
                (d & 15) as usize,
                ((a >> 4) & 15) as usize,
                ((b >> 4) & 15) as usize,
                ((c >> 4) & 15) as usize,
                ((d >> 4) & 15) as usize,
            ];
            if mutation == Mutation::Swap {
                for (i, &j) in idx.iter().enumerate() {
                    message.swap(i, j);
                }
            } else {
                let first = message[idx[0]];
                for i in 0..idx.len() - 1 {
                    message[idx[i]] = message[idx[i + 1]];
                }
                message[idx[idx.len() - 1]] = first;
            }
        }
        Mutation::Kdf => {
            message.swap((a & 15) as usize, (b & 15) as usize);
            message.swap((c & 15) as usize, (d & 15) as usize);
            for shift in [4u32, 8, 12] {
                message.swap(((a >> shift) & 15) as usize, ((b >> shift) & 15) as usize);
            }
        }
    }
}

// ─── the descriptor and the bridge ───────────────────────────────────────────

/// The 20-byte descriptor over prefix || m3SAP || m2SAP || suffix.
pub fn fpsap_descriptor_for_sap(m3_sap: &[u8; 128], m2_sap: &[u8; 128]) -> [u8; 20] {
    let mut padded = [0u8; 320];
    let mut off = 0usize;
    for chunk in [
        &FPSAP_DESCRIPTOR_PREFIX[..],
        &m3_sap[..],
        &m2_sap[..],
        &FPSAP_DESCRIPTOR_SUFFIX[..],
    ] {
        padded[off..off + chunk.len()].copy_from_slice(chunk);
        off += chunk.len();
    }
    padded[off] = 0x80;
    let bits = (off as u64) * 8;
    padded[312..320].copy_from_slice(&bits.to_le_bytes());

    let mut state = [0u32; 4];
    for i in 0..4 {
        state[i] = u32::from_le_bytes([
            FAIRPLAY_INITIAL_SESSION_KEY[i * 4],
            FAIRPLAY_INITIAL_SESSION_KEY[i * 4 + 1],
            FAIRPLAY_INITIAL_SESSION_KEY[i * 4 + 2],
            FAIRPLAY_INITIAL_SESSION_KEY[i * 4 + 3],
        ]);
    }
    let mut first_final = [0u32; 4];

    let mut block_off = 0usize;
    while block_off < 320 {
        let mut block = [0u8; 64];
        block.copy_from_slice(&padded[block_off..block_off + 64]);
        let add = fairplay_sap_hash(&block);
        for i in 0..4 {
            state[i] = state[i].wrapping_add(u32::from_le_bytes([
                add[i * 4],
                add[i * 4 + 1],
                add[i * 4 + 2],
                add[i * 4 + 3],
            ]));
        }
        state = fairplay_md5_compress(state, &block, Mutation::Cycle);
        if block_off == 320 - 64 {
            first_final = state;
            state = fairplay_md5_compress(state, &block, Mutation::Cycle);
        }
        block_off += 64;
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&first_final[0].to_be_bytes());
    for i in 0..4 {
        out[4 + i * 4..8 + i * 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

/// The 20 payload-dependent bytes Phase 2 consumes, for a per-session SAP.
///
/// `gp` is Phase 1's 128-byte output buffer.
pub fn bridge_x9_head_for_sap(local_sap: &[u8; 128], gp: &[u8; 128]) -> [u8; 20] {
    let mut body = [0u8; 128];
    for i in 0..128 {
        body[i] = gp[i] ^ GP_OUTPUT_MASK;
    }
    let d = fpsap_descriptor_for_sap(local_sap, &body);
    // The descriptor emits big-endian words; x9Data is little-endian.
    let mut out = [0u8; 20];
    for w in 0..5 {
        for b in 0..4 {
            out[w * 4 + b] = d[w * 4 + 3 - b];
        }
    }
    out
}

// ─── tests ───────────────────────────────────────────────────────────────────
//
// Self-contained: the three vectors below come from ../../conformance/sap_hash.csv,
// which was generated by the Go reference, not by this file. For the full
// corpus (40 SAP-hash + 30 bridge vectors) drive this module from that
// directory; these three are here so `rustc --test fairplay_sapcore.rs` alone
// still proves something.
//
// Run in DEBUG, not just release. Debug turns on overflow checks, so a missing
// `wrapping_*` panics instead of silently doing the right thing.
#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_HASH: &str = "43c47c142dbc88badb51f54d3ff1e1ec";
    const FF_HASH: &str = "63a4497a24b707a249c808e787d446d1";
    const RANDOM_BLOCK: &str = "6b0e5fa4de6f3da9261e7ce6206afb7a2fcdb8ae902802b45cc50403d8b91de3\
906c57dfed135adbf059e2b112e28bb679c5b3b8a392e574609fec87ba56b25c";
    const RANDOM_HASH: &str = "d069f3b6c6e477ca8be5ee66055e1cc9";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn block(s: &str) -> [u8; 64] {
        let mut b = [0u8; 64];
        b.copy_from_slice(&hex(s));
        b
    }

    #[test]
    fn sap_hash_matches_reference() {
        assert_eq!(to_hex(&fairplay_sap_hash(&[0u8; 64])), ZERO_HASH);
        assert_eq!(to_hex(&fairplay_sap_hash(&[0xFFu8; 64])), FF_HASH);
        assert_eq!(to_hex(&fairplay_sap_hash(&block(RANDOM_BLOCK))), RANDOM_HASH);
    }

    #[test]
    fn ring_index_underflow_boundary() {
        let (x, _, _, _) = build_ring_indices();
        // 2^32 mod 210 == 46, and 55 + 46 == 101.
        assert_eq!(x[0], 101, "the u32 underflow was not reproduced");
        assert_eq!(x[154], 45);
        // From 155 on the wrapping and non-wrapping forms agree, which is why
        // a spot check that starts past the boundary catches nothing.
        assert_eq!(x[155], 0);
        assert_eq!(x[156], 1);
    }

    #[test]
    fn rotate_or_zero_is_not_a_rotate() {
        // The whole point: a zero count yields 0, not the input.
        assert_eq!(rotate_or_zero(0xAB, 0), 0);
        assert_ne!(rotate_or_zero(0xAB, 0), 0xAB);
        assert_eq!(rotate_or_zero(0x81, 1), 0x03);
    }

    #[test]
    fn wide_seed_index_is_wider_than_a_byte() {
        // If the index were masked to 8 bits these would collide. They do not,
        // and that difference is what a naive port loses.
        let masked_index = |v: u8, c: u8| -> u8 {
            let wide = ((v as u32) << c) | ((v as u32) >> (8 - c));
            SAP_SEED[((wide & 0xFF) % SAP_SEED.len() as u32) as usize]
        };
        let mut differs = 0;
        for v in 0..=255u8 {
            for c in 1..8u8 {
                if wide_seed(v, c) != masked_index(v, c) {
                    differs += 1;
                }
            }
        }
        assert!(differs > 0, "masking to 8 bits made no difference; check wide_seed");
    }

    #[test]
    fn the_all_zero_block_proves_nothing() {
        // A ring loop over an all-zero buffer stays all-zero whichever cells it
        // reads, so this vector passes even with a completely wrong index
        // table. It is the reason a smoke test is not a test here.
        let (x, y, z, w) = build_ring_indices();
        let naive: Vec<u8> = (0..840u32).map(|i| ((i + 55) % 210) as u8).collect();
        assert_ne!(&x[..], &naive[..], "the naive form should differ");

        let mut work = fill_work(&[0u8; 64]);
        for i in 0..840usize {
            let wi = w[i] as usize;
            work[wi] = rotl8(work[y[i] as usize], 5)
                .wrapping_add(rotl8(work[z[i] as usize], 3) ^ work[wi])
                .wrapping_sub(rotl8(work[naive[i] as usize], 7));
        }
        assert!(work.iter().all(|&b| b == 0), "zeros in, zeros out regardless of indices");
    }
}

/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Derived from github.com/omarroth/doubletake at 8ccea5f, via
 * fpsapcore. See ../../NOTICE.md.
 */

#include "fairplay_sapcore.h"

#include <string.h>

/* --- byte helpers ------------------------------------------------------- */

/* Rotate a byte left. Matches Go's bits.RotateLeft8. */
static uint8_t rotl8(uint8_t v, unsigned n)
{
    n &= 7u;
    if (n == 0u) {
        return v;
    }
    return (uint8_t)((v << n) | (v >> (8u - n)));
}

/* Go's rotateOrZero: a count of 0 yields 0, NOT the input.
 * This is the one rotate in the algorithm that is not a rotate. */
uint8_t fp_rotate_or_zero(uint8_t value, uint8_t count)
{
    if (count == 0u) {
        return 0u;
    }
    return rotl8(value, count);
}

static uint8_t majority(uint8_t a, uint8_t b, uint8_t c)
{
    return (uint8_t)(a ^ ((a ^ b) & (a ^ c)));
}

static uint8_t select_bits(uint8_t mask, uint8_t if_set, uint8_t if_clear)
{
    return (uint8_t)(if_clear ^ ((if_set ^ if_clear) & mask));
}

static uint8_t square(uint8_t v) { return (uint8_t)(v * v); }
static uint8_t cube(uint8_t v)   { return (uint8_t)(v * v * v); }

/* Go's &^ (AND NOT / bit clear). C has no operator for it. */
static uint8_t and_not(uint8_t a, uint8_t b) { return (uint8_t)(a & (uint8_t)~b); }

/* --- constants ---------------------------------------------------------- */

static const uint8_t SAP_SEED[21] = {
    0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02, 0xA2, 0xA9, 0x11,
    0x00, 0x0C, 0xB3, 0x52, 0xC0, 0xBD, 0xE3, 0x1B, 0x49, 0xC7
};

static const uint8_t SAP_INITIAL_HASH[20] = {
    0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18, 0xDF, 0xBE,
    0xB2, 0xF8, 0x38, 0x62, 0xEC, 0x22, 0x93, 0xD1, 0x20, 0x8F
};

static const uint8_t SAP_INITIAL_MATRIX[35] = {
    0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3, 0x9A, 0x56,
    0xF6, 0x1C, 0x14, 0x3F, 0x0C, 0x1D, 0x3B, 0x36, 0x83, 0xB1,
    0x39, 0x51, 0x4A, 0xAA, 0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE,
    0xC3, 0x20, 0x9D, 0x42, 0xB8
};

static const uint8_t FAIRPLAY_INITIAL_SESSION_KEY[16] = {
    0xDC, 0xDC, 0xF3, 0xB9, 0x0B, 0x74, 0xDC, 0xFB,
    0x86, 0x7F, 0xF7, 0x60, 0x16, 0x72, 0x90, 0x51
};

static const uint8_t FPSAP_DESCRIPTOR_PREFIX[17] = {
    0xA0, 0x44, 0x9C, 0x4D, 0x09, 0xE4, 0xBD, 0x7F, 0x6E,
    0xC5, 0xD0, 0xCC, 0x35, 0x9D, 0xA7, 0x46, 0x7A
};

static const uint8_t FPSAP_DESCRIPTOR_SUFFIX[17] = {
    0x97, 0xB5, 0x0F, 0x84, 0xE2, 0x15, 0x5A, 0x9C, 0x24,
    0x99, 0x1C, 0xF4, 0x3A, 0x09, 0x63, 0x55, 0x47
};

/* The white-box output encoding Phase 1 leaves on the GP buffer: one XOR
 * constant across all 128 bytes. Measured, not assumed. */
#define GP_OUTPUT_MASK 0x0Fu

/* Go's wideSeed. The index is computed in uint32_t, WIDER than a byte:
 * value << count is allowed to exceed 255 before the modulo. Masking it to
 * 8 bits changes the result. */
uint8_t fp_wide_seed(uint8_t value, uint8_t count)
{
    uint32_t wide;
    if (count == 0u) {
        return SAP_SEED[0];
    }
    wide = ((uint32_t)value << count) | ((uint32_t)value >> (8u - count));
    return SAP_SEED[wide % 21u];
}

/* --- the ring index tables ---------------------------------------------- */

/* i is uint32_t and the subtraction wraps for i below the subtrahend. That is
 * defined behaviour in C, so nothing special is needed here -- unlike Rust,
 * where the same expression panics in debug builds. */
void fp_build_ring_indices(uint8_t x[840], uint8_t y[840],
                           uint8_t z[840], uint8_t w[840])
{
    uint32_t i;
    for (i = 0u; i < 840u; i++) {
        x[i] = (uint8_t)((i - 155u) % 210u);
        y[i] = (uint8_t)((i - 57u) % 210u);
        z[i] = (uint8_t)((i - 13u) % 210u);
        w[i] = (uint8_t)(i % 210u);
    }
}

/* work is three copies of the permuted block plus its first 18 bytes. */
static void fill_work(const uint8_t block[64], uint8_t work[210])
{
    uint8_t p[64];
    int i;
    for (i = 0; i < 64; i++) {
        p[i] = block[i ^ 3];
    }
    memcpy(work, p, 64);
    memcpy(work + 64, p, 64);
    memcpy(work + 128, p, 64);
    memcpy(work + 192, p, 18);
}

/* --- the nonlinear circuit ---------------------------------------------- */

/* Go reads through small closures. C has none, so these are macros that expand
 * inline against the locals below. Statement order is load-bearing throughout:
 * several lines assign to a cell a later line reads, and matrix[12] is written
 * three times. Reordering for tidiness breaks it. */
static void nonlinear_circuit(uint8_t *hash, uint8_t *matrix,
                              uint8_t *aux, uint8_t *work)
{
#define HI(i) hash[(uint8_t)(i) % 20u]
#define SI(i) SAP_SEED[(uint8_t)(i) % 21u]
#define H(i)  HI(work[(i)])
#define M(i)  matrix[work[(i)] % 35u]
#define S(i)  SI(work[(i)])
#define MA(i) matrix[aux[(i)] % 35u]

    uint8_t aux_hash, seed_bits, expansion_bits, expanded_selector;
    uint8_t hash9, indexed_hash, selected_square, seed9, hash3;
    uint8_t digest_index, seed_sample;
    uint32_t wide;

    matrix[12] = (uint8_t)(0x14 + (select_bits(92, work[64], (uint8_t)(work[99] / 3))
                                   & fp_wide_seed(S(206), 4)));
    work[4] = (uint8_t)(2 * square((uint8_t)(work[99] / 5)));
    work[153] ^= (uint8_t)(square(M(203)) * work[190]);
    hash[3] = (uint8_t)(0x13 ^ ((S(205) >> 1) & 0x10));
    work[33] = (uint8_t)(work[33] - and_not(S(36), 9));
    aux[5] = (uint8_t)((and_not(M(67), 2) | 1 | ((H(181) >> 6) & 2)
                        | (hash[3] & 0x10)) - 15);
    matrix[12] = 0x07;
    work[2] = (uint8_t)(work[2] - 64);
    hash[19] = S(58);
    aux[4] = (uint8_t)(92 - M(32));
    aux[9] = (uint8_t)(M(15) + 0x9E);
    work[34] = (uint8_t)(work[34] + SI(aux[9]) / 5);
    hash[19] = (uint8_t)(hash[19] + (0xE6 ^ ((HI(aux[9]) >> 1) & 0x66)));
    work[15] ^= (uint8_t)(3 * fp_rotate_or_zero(work[72], (uint8_t)(-S(190) & 7))
                          - 9 * S(126));
    hash[15] ^= cube(M(181));
    matrix[4] ^= (uint8_t)(work[202] / 3);
    matrix[1] = (uint8_t)(matrix[1] + cube(majority((uint8_t)(92 - HI(aux[4])),
                                                    (uint8_t)~work[105], 0xC6)));
    /* int math, then truncate */
    hash[19] ^= (uint8_t)(((uint32_t)(224 | (S(92) & 27)) * (uint32_t)M(41)) / 3u);
    work[140] = (uint8_t)(work[140] + fp_rotate_or_zero(92, (uint8_t)(-work[5] & 7)));
    matrix[12] = (uint8_t)(matrix[12] + majority((uint8_t)(~work[4] ^ M(12)),
                                                 work[182], 192));
    work[36] = (uint8_t)(work[36] + 125);
    work[124] = rotl8(majority(majority(work[138], hash[15], 74), H(43), 95), 4);
    aux_hash = HI(aux[9]);
    aux[1] = and_not(0x4C, (uint8_t)(aux_hash & (uint8_t)(S(68) << 1)));
    aux[2] = (uint8_t)(222 - majority(
        (uint8_t)(((uint32_t)work[177] + (uint32_t)S(79)) >> 1),
        (uint8_t)(3u * (uint32_t)work[148] / 5u),
        matrix[1]));
    matrix[16] = (uint8_t)(matrix[16] + ((and_not(MA(4), 0x60) | aux_hash | 8)
                                         - (rotl8(work[33], 2) | 128)));
    hash[14] ^= MA(2);
    work[19] = (uint8_t)(work[19] + majority(
        fp_rotate_or_zero(SI(H(201)), (uint8_t)((M(112) << 1) & 6)),
        (uint8_t)((and_not(H(208), 0x7C) | (H(164) & 0x7C)) / 5),
        37));
    matrix[8] = (uint8_t)(fp_rotate_or_zero(140, (uint8_t)(-square(S(45)) & 7)) ^ aux[4]);
    work[190] = 56;
    work[53] = (uint8_t)~((uint8_t)((H(83) | 204) / 5));
    hash[13] = (uint8_t)(hash[13] + H(41));
    hash[10] = (uint8_t)(majority(MA(4), work[2], aux[2]) / 15);
    aux[3] = (uint8_t)(92 - square((uint8_t)(0x28 | (MA(1) & (0x12 | (S(2) & 4))))));
    seed_bits = SI(aux[4]);
    matrix[13] ^= seed_bits;
    aux[6] = (uint8_t)(92 + square(majority((uint8_t)(M(179) - 38), aux[2], 177)));
    expansion_bits = majority((uint8_t)(aux[3] + (aux[4] & 74)),
                              (uint8_t)~seed_bits, 121);
    work[47] ^= (uint8_t)(M(89) + majority((uint8_t)(expansion_bits ^ 0xA6), aux[4], 4));
    aux[7] = (uint8_t)(seed_bits / 3 - MA(9)
                       - (0x14 | (work[151] & ((aux[4] & 0x88) | 0x62))
                          | (aux[4] & 0x22)));
    expanded_selector = (uint8_t)(expansion_bits ^ ((aux[4] & 0xCA) >> 1) ^ 75);
    aux[9] = (uint8_t)(aux[9] + (0x80 | (majority(aux[7], work[151], 0x20) & 0x64)
                                 | (seed_bits & 0x44) | (MA(9) & 0x1B)));
    matrix[33] ^= work[26];
    matrix[30] = (uint8_t)((uint8_t)(aux[9] / 3 - (and_not(aux[4], 8) | 0x13)) ^ H(122));
    work[22] = (uint8_t)((M(90) & 0x1B) | 0x44);
    wide = (uint32_t)select_bits(71, matrix[expanded_selector % 35u], SI(aux[5]));
    /* int math, then truncate */
    matrix[18] = (uint8_t)(matrix[18] + (uint8_t)((wide * wide * wide) >> 1));
    matrix[5] = (uint8_t)(matrix[5] - S(92));
    matrix[18] ^= (uint8_t)(select_bits(aux[3], MA(3),
                                        select_bits(16, M(183), work[41]))
                            * select_bits(expanded_selector, H(59), work[17]));
    matrix[22] = (uint8_t)(majority(
        select_bits((uint8_t)(hash[14] | 28), (uint8_t)((work[7] & 28) | 0x82), H(93)),
        fp_rotate_or_zero(MA(4),
            (uint8_t)(fp_rotate_or_zero(work[11], (uint8_t)(-M(28) & 7)) & 7)),
        matrix[33]) + 74);
    hash[15] = (uint8_t)(hash[15] - majority(majority(aux[3], aux[4], 214),
                                             SI((uint8_t)(H(39) ^ 217)), aux[6]));

    hash9 = HI(aux[9]);
    indexed_hash = HI((uint8_t)((uint8_t)(aux[4] / 3 - (aux[9] | work[22]))
        ^ aux[6]
        ^ (((M(57) | hash9) & (0x52 | (aux[9] & 0x0D)))
           | (((M(57) & hash9) | aux[9]) & 0x20))));
    aux[6] = (uint8_t)(square(square(H(99))) | MA(9));
    aux[1] = (uint8_t)(aux[1]
        + fp_rotate_or_zero((uint8_t)(H(151) | S(202)), (uint8_t)(H(50) & 7))
        + majority(H(4),
                   (uint8_t)(((uint32_t)select_bits(matrix[16], indexed_hash, M(138))
                              + (uint32_t)select_bits(17, work[33], S(39))) / 5u),
                   147));
    aux[0] = select_bits((uint8_t)(hash[10] & 7),
                         (uint8_t)(MA(6) & H(209)),
                         select_bits(0x47,
                             fp_rotate_or_zero(S(127), (uint8_t)(MA(6) & 7)),
                             (uint8_t)(SI(MA(5)) << 1)));
    selected_square = select_bits(198, square(M(14)), (uint8_t)(H(145) ^ aux[0]));
    seed9 = SI(aux[9]);
    hash3 = HI(aux[3]);
    matrix[2] = (uint8_t)(matrix[2] + ((((uint8_t)(hash3 << 1))
                                        & ((work[25] & 0x96) | (seed9 & 8)))
                                       | (seed9 & 0x40)));
    matrix[14] = (uint8_t)(matrix[14] - select_bits(34, work[97],
                              (uint8_t)(MA(3) & (aux[0] ^ M(100)))));
    work[23] ^= (uint8_t)(majority(majority(S(17), hash3, aux[0]),
                                   (uint8_t)(work[50] / 3), 0x76) << 1);
    hash[17] = 115;
    hash[13] = (uint8_t)(((majority(HI(aux[7]), work[10], 82) >> 1) & 0x68)
                         | (H(39) & 0x17));
    matrix[33] = (uint8_t)(matrix[33] - (work[113] & 9));
    matrix[28] = (uint8_t)(matrix[28] - (and_not(aux[3], 0x20)
                                         | ((work[110] >> 1) & 0x20)));
    work[95] = SI(aux[3]);
    hash[15] = (uint8_t)(majority((uint8_t)(work[95] - 48), (uint8_t)~work[184], 189)
                         & cube(majority(aux[7], SI(aux[1]), 0xAA)));
    matrix[22] = (uint8_t)(matrix[22] + work[183]);
    aux[4] ^= (uint8_t)(3 * S(1));
    aux[5] = (uint8_t)(aux[5] + 198 * majority(S(178), MA(1), 209) * H(13)
                       * (S(26) >> 1));
    aux[8] = select_bits(10, MA(3), MA(9));
    matrix[18] = (uint8_t)(matrix[18] - select_bits(hash[15], (uint8_t)(aux[5] / 15),
                              cube((uint8_t)(HI(aux[6]) | 81))));
    aux[1] = (uint8_t)(aux[1] + SI(HI(aux[1])) / 3 - H(160));
    hash[16] = (uint8_t)(147 - majority(aux[0],
        majority(S(69), work[172], (uint8_t)(aux[2] - selected_square + 77)),
        (uint8_t)(0xC2 | (aux[0] & 5))));
    hash[3] = (uint8_t)(hash[3] - fp_wide_seed(majority(S(155), work[105], 141),
                          (uint8_t)(majority(S(168), H(29), 6) & 7)));
    work[5] = (uint8_t)(fp_rotate_or_zero(0x38, (uint8_t)(-(uint8_t)(H(61) / 5) & 7))
                        ^ (uint8_t)((uint8_t)~MA(8) / 5));
    work[198] = (uint8_t)(work[198] + work[3]);
    wide = (uint32_t)(162 | MA(9));
    /* int math, then truncate */
    work[164] = (uint8_t)(work[164] + (uint8_t)((wide * wide) / 5u));
    aux[2] = (uint8_t)(majority(fp_rotate_or_zero(139, (uint8_t)(-aux[5] & 6)),
                                HI(aux[3]), 12)
                       | select_bits(95, cube(seed9), HI(aux[7])));
    matrix[12] = (uint8_t)(matrix[12] + (uint8_t)((16 | ((work[103] | 60)
                              & (aux[2] | (work[103] & 32)))) / 3));
    work[143] = (uint8_t)(work[143] - (0x12 | (select_bits(aux[9],
                              select_bits(matrix[8], work[35], aux[7]),
                              (uint8_t)(aux[8] / 3))
                          & (0x4D | ((work[172] >> 1) & 0x20)))));
    matrix[29] = 162;
    hash[15] = (uint8_t)(hash[15] + majority((uint8_t)(M(149) ^ square(work[43])),
                              (uint8_t)(select_bits(95, H(125), SI(aux[1])) >> 1),
                              115));
    aux[9] = (uint8_t)(aux[9] - HI(aux[7]));
    hash[7] = (uint8_t)(hash[7] - square(fp_rotate_or_zero(MA(5),
                              (uint8_t)(-(uint8_t)(M(17) * (M(17) & 1))))));
    matrix[8] = (uint8_t)(matrix[8] + cube(S(202)) - work[184]);
    hash[16] = (uint8_t)((M(102) << 1) & 0x84);
    aux[6] ^= (uint8_t)(SI(aux[7]) >> 1);
    hash[7] = (uint8_t)(hash[7] - H(191)
                        + select_bits(177, SI(SI(aux[1])), (uint8_t)(S(80) << 1)));
    hash[6] = H(119);
    hash[12] = (uint8_t)((HI(aux[8]) ^ (uint8_t)(M(71) + M(15)))
                         & majority((uint8_t)(and_not(work[118], 0x2C) | 2),
                                    square(HI(aux[9])), 27));
    digest_index = (uint8_t)(select_bits(0xA9, (uint8_t)(S(57) * 231),
                                         majority(work[32], MA(1), 23)) / 5);
    seed_sample = SI(aux[6]);
    aux[5] = (uint8_t)(majority((uint8_t)((seed_sample & 0x1C) | (H(82) & 0xA2)
                                          | (SI(digest_index) & 0x41)),
                                majority(cube(HI(aux[7])), work[82], 92), 192)
                       ^ digest_index);
    matrix[25] ^= (uint8_t)(2 * HI(aux[9]) * work[5]
                            - (fp_rotate_or_zero(aux[4], (uint8_t)(seed_sample & 7))
                               & (uint8_t)(aux[3] + 110)));

#undef HI
#undef SI
#undef H
#undef M
#undef S
#undef MA
}

/* --- the scramble ------------------------------------------------------- */

/* 256 rounds of XOR-and-rotate. Every operation is GF(2)-linear, so this
 * collapses to a 128x128 binary matrix -- which is what the Go version ships
 * for speed. The loop is kept here because a snippet is for reading, and the
 * matrix is 2 KB of opaque data that says nothing about what it does. */
static void apply_scramble(uint8_t out[16])
{
    int i;
    for (i = 0; i < 256; i++) {
        out[i & 15] = (uint8_t)(out[i & 15]
            ^ rotl8(out[(i - 7) & 15], 1)
            ^ rotl8(out[(i - 5) & 15], 6)
            ^ rotl8(out[(i - 1) & 15], 5));
    }
}

/* --- the SAP hash ------------------------------------------------------- */

void fp_sap_hash(const uint8_t block[64], uint8_t out[16])
{
    uint8_t rx[840], ry[840], rz[840], rw[840];
    uint8_t hash[20], matrix[35], aux[10], work[210];
    int i;

    fp_build_ring_indices(rx, ry, rz, rw);
    memcpy(hash, SAP_INITIAL_HASH, 20);
    memcpy(matrix, SAP_INITIAL_MATRIX, 35);
    memset(aux, 0, 10);
    fill_work(block, work);

    for (i = 0; i < 840; i++) {
        uint8_t xv = work[rx[i]];
        uint8_t yv = work[ry[i]];
        uint8_t zv = work[rz[i]];
        uint8_t wi = rw[i];
        work[wi] = (uint8_t)(rotl8(yv, 5) + (rotl8(zv, 3) ^ work[wi]) - rotl8(xv, 7));
    }

    nonlinear_circuit(hash, matrix, aux, work);

    memset(out, 0, 16);
    /* Go: copy(out[:], aux[:3]) then copy(out[4:], aux[3:]) -- 3 then 7 bytes. */
    memcpy(out, aux, 3);
    memcpy(out + 4, aux + 3, 7);
    for (i = 0; i < 16; i++) {
        out[i] = (uint8_t)(out[i] + 0xE1);
    }
    out[3] = 0x3D;
    out[11] = 0x3C;
    out[10] ^= (uint8_t)(aux[3] ^ 133);

    for (i = 0; i < 20; i++) {
        out[i & 15] ^= (uint8_t)(work[i] ^ matrix[i] ^ hash[i]);
    }
    for (i = 20; i < 35; i++) {
        out[i & 15] ^= (uint8_t)(work[i] ^ matrix[i]);
    }
    for (i = 35; i < 210; i++) {
        out[i & 15] ^= work[i];
    }

    apply_scramble(out);
}

/* --- the FairPlay MD5 family -------------------------------------------- */

static const unsigned FAIRPLAY_MD5_SHIFT[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static const uint32_t FAIRPLAY_MD5_CONSTANT[64] = {
    0xD76AA478u, 0xE8C7B756u, 0x242070DBu, 0xC1BDCEEEu,
    0xF57C0FAFu, 0x4787C62Au, 0xA8304613u, 0xFD469501u,
    0x698098D8u, 0x8B44F7AFu, 0xFFFF5BB1u, 0x895CD7BEu,
    0x6B901122u, 0xFD987193u, 0xA679438Eu, 0x49B40821u,
    0xF61E2562u, 0xC040B340u, 0x265E5A51u, 0xE9B6C7AAu,
    0xD62F105Du, 0x02441453u, 0xD8A1E681u, 0xE7D3FBC8u,
    0x21E1CDE6u, 0xC33707D6u, 0xF4D50D87u, 0x455A14EDu,
    0xA9E3E905u, 0xFCEFA3F8u, 0x676F02D9u, 0x8D2A4C8Au,
    0xFFFA3942u, 0x8771F681u, 0x6D9D6122u, 0xFDE5380Cu,
    0xA4BEEA44u, 0x4BDECFA9u, 0xF6BB4B60u, 0xBEBFBC70u,
    0x289B7EC6u, 0xEAA127FAu, 0xD4EF3085u, 0x04881D05u,
    0xD9D4D039u, 0xE6DB99E5u, 0x1FA27CF8u, 0xC4AC5665u,
    0xF4292244u, 0x432AFF97u, 0xAB9423A7u, 0xFC93A039u,
    0x655B59C3u, 0x8F0CCC92u, 0xFFEFF47Du, 0x85845DD1u,
    0x6FA87E4Fu, 0xFE2CE6E0u, 0xA3014314u, 0x4E0811A1u,
    0xF7537E82u, 0xBD3AF235u, 0x2AD7D2BBu, 0xEB86D391u
};

#define MUT_CYCLE 1

static uint32_t rotl32(uint32_t v, unsigned n)
{
    n &= 31u;
    if (n == 0u) {
        return v;
    }
    return (uint32_t)((v << n) | (v >> (32u - n)));
}

static void mutate_message(uint32_t message[16], uint32_t a, uint32_t b,
                           uint32_t c, uint32_t d)
{
    /* Only the cycle mutation is reachable from the descriptor; the swap and
     * KDF variants live in the Go reference. */
    unsigned idx[8];
    uint32_t first;
    int i;
    idx[0] = (unsigned)(a & 15u);
    idx[1] = (unsigned)(b & 15u);
    idx[2] = (unsigned)(c & 15u);
    idx[3] = (unsigned)(d & 15u);
    idx[4] = (unsigned)((a >> 4) & 15u);
    idx[5] = (unsigned)((b >> 4) & 15u);
    idx[6] = (unsigned)((c >> 4) & 15u);
    idx[7] = (unsigned)((d >> 4) & 15u);
    first = message[idx[0]];
    for (i = 0; i < 7; i++) {
        message[idx[i]] = message[idx[i + 1]];
    }
    message[idx[7]] = first;
}

/* Standard MD5 rounds and constants, but big-endian message words and a
 * message-schedule mutation after round 31. A stock MD5 cannot do this. */
static void fairplay_md5_compress(uint32_t state[4], const uint8_t block[64])
{
    uint32_t message[16];
    uint32_t a, b, c, d;
    int i, round;

    for (i = 0; i < 16; i++) {
        message[i] = ((uint32_t)block[i * 4] << 24)
                   | ((uint32_t)block[i * 4 + 1] << 16)
                   | ((uint32_t)block[i * 4 + 2] << 8)
                   | (uint32_t)block[i * 4 + 3];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];

    for (round = 0; round < 64; round++) {
        uint32_t f, next_b, prev_b, prev_c;
        int word;
        if (round < 16) {
            f = (b & c) | (~b & d);
            word = round;
        } else if (round < 32) {
            f = (d & b) | (~d & c);
            word = (5 * round + 1) & 15;
        } else if (round < 48) {
            f = b ^ c ^ d;
            word = (3 * round + 5) & 15;
        } else {
            f = c ^ (b | ~d);
            word = (7 * round) & 15;
        }

        next_b = b + rotl32(a + f + FAIRPLAY_MD5_CONSTANT[round] + message[word],
                            FAIRPLAY_MD5_SHIFT[round]);
        /* Go: a, b, c, d = d, next_b, b, c -- one simultaneous rotation. */
        prev_b = b;
        prev_c = c;
        a = d;
        d = prev_c;
        c = prev_b;
        b = next_b;

        if (round == 31) {
            mutate_message(message, a, b, c, d);
        }
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/* --- the descriptor and the bridge -------------------------------------- */

void fp_sap_descriptor_for_sap(const uint8_t m3_sap[128],
                               const uint8_t m2_sap[128],
                               uint8_t out[20])
{
    uint8_t padded[320];
    uint32_t state[4];
    uint32_t first_final[4];
    uint64_t bits;
    size_t off = 0;
    int i, block_off;

    memset(padded, 0, sizeof padded);
    memcpy(padded + off, FPSAP_DESCRIPTOR_PREFIX, 17); off += 17;
    memcpy(padded + off, m3_sap, 128);                 off += 128;
    memcpy(padded + off, m2_sap, 128);                 off += 128;
    memcpy(padded + off, FPSAP_DESCRIPTOR_SUFFIX, 17); off += 17;
    padded[off] = 0x80;
    bits = (uint64_t)off * 8u;
    for (i = 0; i < 8; i++) {
        padded[312 + i] = (uint8_t)(bits >> (8 * i));   /* little endian */
    }

    for (i = 0; i < 4; i++) {
        state[i] = ((uint32_t)FAIRPLAY_INITIAL_SESSION_KEY[i * 4])
                 | ((uint32_t)FAIRPLAY_INITIAL_SESSION_KEY[i * 4 + 1] << 8)
                 | ((uint32_t)FAIRPLAY_INITIAL_SESSION_KEY[i * 4 + 2] << 16)
                 | ((uint32_t)FAIRPLAY_INITIAL_SESSION_KEY[i * 4 + 3] << 24);
    }
    memset(first_final, 0, sizeof first_final);

    for (block_off = 0; block_off < 320; block_off += 64) {
        uint8_t add[16];
        fp_sap_hash(padded + block_off, add);
        for (i = 0; i < 4; i++) {
            state[i] += ((uint32_t)add[i * 4])
                      | ((uint32_t)add[i * 4 + 1] << 8)
                      | ((uint32_t)add[i * 4 + 2] << 16)
                      | ((uint32_t)add[i * 4 + 3] << 24);
        }
        fairplay_md5_compress(state, padded + block_off);
        if (block_off == 320 - 64) {
            memcpy(first_final, state, sizeof state);
            fairplay_md5_compress(state, padded + block_off);
        }
    }

    out[0] = (uint8_t)(first_final[0] >> 24);
    out[1] = (uint8_t)(first_final[0] >> 16);
    out[2] = (uint8_t)(first_final[0] >> 8);
    out[3] = (uint8_t)(first_final[0]);
    for (i = 0; i < 4; i++) {
        out[4 + i * 4]     = (uint8_t)(state[i] >> 24);
        out[4 + i * 4 + 1] = (uint8_t)(state[i] >> 16);
        out[4 + i * 4 + 2] = (uint8_t)(state[i] >> 8);
        out[4 + i * 4 + 3] = (uint8_t)(state[i]);
    }
}

void fp_bridge_x9_head_for_sap(const uint8_t local_sap[128],
                               const uint8_t gp[128],
                               uint8_t out[20])
{
    uint8_t body[128];
    uint8_t d[20];
    int i, w, b;

    for (i = 0; i < 128; i++) {
        body[i] = (uint8_t)(gp[i] ^ GP_OUTPUT_MASK);
    }
    fp_sap_descriptor_for_sap(local_sap, body, d);
    /* The descriptor emits big-endian words; x9Data is little-endian. */
    for (w = 0; w < 5; w++) {
        for (b = 0; b < 4; b++) {
            out[w * 4 + b] = d[w * 4 + 3 - b];
        }
    }
}

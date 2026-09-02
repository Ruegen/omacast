/* SPDX-License-Identifier: BlueOak-1.0.0 */
/*
 * fairplay_bridge.c - standalone C99 FairPlay SAP bridge hash.
 *
 * This is standard MD5's four-round compression structure, standard message
 * schedule, and the standard RFC 1321 K table plus a per-hash-instance
 * additive offset -- with one extra step: right after round 31, the message
 * array is permuted in place, and rounds 32-63 continue against the
 * permuted array. It is intentionally self-contained: only <stdint.h> and
 * the sibling header are required.
 *
 * The function is one portable piece of the handshake. It is not a complete
 * payload-to-m3 implementation. Full SAP still needs the recovered Phase-1
 * White-Box AES tables and fixed bridge data tables. This is authentication
 * interoperability code, not FairPlay Streaming DRM code.
 */

#include "fairplay_bridge.h"

static const uint32_t BRIDGE_MD5_IV[4] = {
    0xb9f3dcdc, 0xfbdc740b, 0x60f77f86, 0x51907216,
};

/* Standard RFC 1321 MD5 per-round additive constant table. The bridge
 * hash's real per-round constant is STD_MD5_K[i] + offset, where offset
 * depends only on which hash-instance a block belongs to (see the
 * BRIDGE_HASH*_OFFSET macros in the header) -- NOT a bespoke 64-entry
 * table. */
static const uint32_t STD_MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const uint8_t BRIDGE_MD5_ROT[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static const uint8_t BRIDGE_MD5_SCHEDULE[64] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
};

static uint32_t rotate_left(uint32_t value, uint8_t amount) {
    return (value << amount) | (value >> (32u - amount));
}

static void swap_words(uint32_t message[16], int i, int j) {
    uint32_t tmp = message[i];
    message[i] = message[j];
    message[j] = tmp;
}

/* Applies the round-31-boundary message permutation in place, using the
 * working state (a,b,c,d) immediately after round 31. */
static void apply_bridge_mutation(uint32_t message[16], bridge_mutation_t variant,
                                   uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    if (variant == BRIDGE_MUTATION_KDF) {
        swap_words(message, a & 15u, b & 15u);
        swap_words(message, c & 15u, d & 15u);
        for (int shift = 4; shift <= 12; shift += 4) {
            swap_words(message, (a >> shift) & 15u, (b >> shift) & 15u);
        }
    } else {
        int idx[8] = {
            (int)(a & 15u), (int)(b & 15u), (int)(c & 15u), (int)(d & 15u),
            (int)((a >> 4) & 15u), (int)((b >> 4) & 15u), (int)((c >> 4) & 15u), (int)((d >> 4) & 15u),
        };
        uint32_t first = message[idx[0]];
        for (int i = 0; i < 7; ++i) {
            message[idx[i]] = message[idx[i + 1]];
        }
        message[idx[7]] = first;
    }
}

void bridge_md5_init(uint32_t state[4]) {
    for (int i = 0; i < 4; ++i) {
        state[i] = BRIDGE_MD5_IV[i];
    }
}

void bridge_md5_compress(uint32_t state[4], uint32_t message[16],
                          uint32_t offset, bridge_mutation_t variant) {
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    for (int i = 0; i < 64; ++i) {
        uint32_t function;
        if (i < 16) {
            function = (b & c) | (~b & d);
        } else if (i < 32) {
            function = (d & b) | (~d & c);
        } else if (i < 48) {
            function = b ^ c ^ d;
        } else {
            function = c ^ (b | ~d);
        }

        uint32_t mixed = a + function +
            message[BRIDGE_MD5_SCHEDULE[i]] + STD_MD5_K[i] + offset;
        uint32_t next_b = b + rotate_left(mixed, BRIDGE_MD5_ROT[i]);

        a = d;
        d = c;
        c = b;
        b = next_b;

        if (i == 31) {
            apply_bridge_mutation(message, variant, a, b, c, d);
        }
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

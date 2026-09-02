# SPDX-License-Identifier: LGPL-3.0-or-later
# Derived from github.com/omarroth/doubletake at 8ccea5f, via
# fpsapcore. See ../../NOTICE.md.
"""FairPlay SAP Phase-1 bridge: the closed form, in portable Python.

This is the piece the other snippets in this directory do not carry. They
implement the bridge *primitive*; this implements the functions that feed it,
so the two together are a complete responder.

    BridgeX9HeadForSAP(local_sap, gp) -> 20 bytes

`gp` is the 128-byte Phase-1 output buffer. The 20 bytes it returns are the
only payload-dependent input Phase 2 consumes.

Every value here is a byte and wraps at 256. Python integers do not, so every
arithmetic result is masked. Where the Go original promotes to a wider type
before dividing or indexing, the mask is deliberately *absent* and a comment
says so -- those are not oversights, and removing the distinction breaks the
output. See ../../conformance/README.md for the trap that motivates this file.
"""

# --- byte helpers -----------------------------------------------------------

M8 = 0xFF


def _rotl8(v, n):
    """Rotate a byte left. n is taken mod 8, matching Go's bits.RotateLeft8."""
    n &= 7
    return ((v << n) | (v >> (8 - n))) & M8 if n else v & M8


def rotate_or_zero(value, count):
    """Go's rotateOrZero: a count of 0 yields 0, not the input.

    This is the one rotate in the algorithm that is not a rotate. Porting it as
    an ordinary rotation is silent and wrong.
    """
    count &= M8
    if count == 0:
        return 0
    return _rotl8(value & M8, count)


def majority(a, b, c):
    return (a ^ ((a ^ b) & (a ^ c))) & M8


def select_bits(mask, if_set, if_clear):
    return (if_clear ^ ((if_set ^ if_clear) & mask)) & M8


def square(v):
    return (v * v) & M8


def cube(v):
    return (v * v * v) & M8


def and_not(a, b):
    """Go's &^ (AND NOT / bit clear). Python has no operator for it."""
    return a & (~b & M8)


def _not(v):
    """Go's ^v on a byte is a bitwise NOT, not an XOR."""
    return (~v) & M8


# --- constants --------------------------------------------------------------

SAP_SEED = bytes([
    0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02, 0xA2, 0xA9, 0x11,
    0x00, 0x0C, 0xB3, 0x52, 0xC0, 0xBD, 0xE3, 0x1B, 0x49, 0xC7,
])

SAP_INITIAL_HASH = bytes([
    0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18, 0xDF, 0xBE,
    0xB2, 0xF8, 0x38, 0x62, 0xEC, 0x22, 0x93, 0xD1, 0x20, 0x8F,
])

SAP_INITIAL_MATRIX = bytes([
    0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3, 0x9A, 0x56,
    0xF6, 0x1C, 0x14, 0x3F, 0x0C, 0x1D, 0x3B, 0x36, 0x83, 0xB1,
    0x39, 0x51, 0x4A, 0xAA, 0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE,
    0xC3, 0x20, 0x9D, 0x42, 0xB8,
])

FAIRPLAY_INITIAL_SESSION_KEY = bytes([
    0xDC, 0xDC, 0xF3, 0xB9, 0x0B, 0x74, 0xDC, 0xFB,
    0x86, 0x7F, 0xF7, 0x60, 0x16, 0x72, 0x90, 0x51,
])

FPSAP_DESCRIPTOR_PREFIX = bytes([
    0xA0, 0x44, 0x9C, 0x4D, 0x09, 0xE4, 0xBD, 0x7F, 0x6E,
    0xC5, 0xD0, 0xCC, 0x35, 0x9D, 0xA7, 0x46, 0x7A,
])

FPSAP_DESCRIPTOR_SUFFIX = bytes([
    0x97, 0xB5, 0x0F, 0x84, 0xE2, 0x15, 0x5A, 0x9C, 0x24,
    0x99, 0x1C, 0xF4, 0x3A, 0x09, 0x63, 0x55, 0x47,
])

# The white-box output encoding Phase 1 leaves on the GP buffer: one XOR
# constant across all 128 bytes. Measured, not assumed.
GP_OUTPUT_MASK = 0x0F


def wide_seed(value, count):
    """Go's wideSeed.

    Note the index expression is computed in *int*, not in a byte: `value <<
    count` is allowed to exceed 255 before the modulo. Masking it to 8 bits
    here changes the result.
    """
    count &= M8
    if count == 0:
        return SAP_SEED[0]
    wide = (value << count) | (value >> (8 - count))  # deliberately unmasked
    return SAP_SEED[wide % len(SAP_SEED)]


# --- the ring index tables --------------------------------------------------

def _build_ring_indices():
    """The four index sequences.

    The subtraction is 32-bit unsigned and wraps for i below the subtrahend,
    so the explicit % 2**32 is load-bearing. Without it Python returns a
    non-negative but wrong value -- 55 instead of 101 at i=0 -- and the hash
    is wrong on every input while still looking deterministic.
    """
    m32 = 1 << 32
    x = bytearray(840)
    y = bytearray(840)
    z = bytearray(840)
    w = bytearray(840)
    for i in range(840):
        x[i] = ((i - 155) % m32) % 210
        y[i] = ((i - 57) % m32) % 210
        z[i] = ((i - 13) % m32) % 210
        w[i] = (i % m32) % 210
    return bytes(x), bytes(y), bytes(z), bytes(w)


RING_X, RING_Y, RING_Z, RING_W = _build_ring_indices()


def _fill_work(block):
    """work is three copies of the permuted block plus its first 18 bytes."""
    p = bytes(block[i ^ 3] for i in range(64))
    return bytearray(p + p + p + p[:18])


# --- the SAP hash -----------------------------------------------------------

def fairplay_sap_hash(block):
    """FairPlay's proprietary SAP hash of one 64-byte block. Not a standard hash."""
    if len(block) != 64:
        raise ValueError("block must be 64 bytes, got %d" % len(block))

    hash_ = bytearray(SAP_INITIAL_HASH)
    matrix = bytearray(SAP_INITIAL_MATRIX)
    aux = bytearray(10)
    work = _fill_work(block)

    for i in range(840):
        xv = work[RING_X[i]]
        yv = work[RING_Y[i]]
        zv = work[RING_Z[i]]
        wi = RING_W[i]
        work[wi] = (_rotl8(yv, 5) + (_rotl8(zv, 3) ^ work[wi]) - _rotl8(xv, 7)) & M8

    _nonlinear_circuit(hash_, matrix, aux, work)

    out = bytearray(16)
    # Go: copy(out[:], aux[:3]) then copy(out[4:], aux[3:]) -- 3 then 7 bytes.
    out[0:3] = aux[0:3]
    out[4:11] = aux[3:10]
    for i in range(16):
        out[i] = (out[i] + 0xE1) & M8
    out[3] = 0x3D
    out[11] = 0x3C
    out[10] ^= (aux[3] ^ 133) & M8

    for i in range(20):
        out[i & 15] ^= work[i] ^ matrix[i] ^ hash_[i]
    for i in range(20, 35):
        out[i & 15] ^= work[i] ^ matrix[i]
    for i in range(35, 210):
        out[i & 15] ^= work[i]

    apply_scramble(out)
    return bytes(out)


def apply_scramble(out):
    """256 rounds of XOR-and-rotate, in place over 16 bytes.

    Every operation is GF(2)-linear, so this collapses to a 128x128 binary
    matrix -- which is what the Go version ships for speed. The loop is kept
    here because a snippet is for reading, and the matrix is 2 KB of opaque
    data that says nothing about what it does.
    """
    for i in range(256):
        out[i & 15] ^= (
            _rotl8(out[(i - 7) & 15], 1)
            ^ _rotl8(out[(i - 5) & 15], 6)
            ^ _rotl8(out[(i - 1) & 15], 5)
        )


def _nonlinear_circuit(hash_, matrix, aux, work):
    """The straight-line byte circuit. Order is load-bearing throughout.

    Several lines assign to a cell that a later line reads, and a few assign
    twice (matrix[12] is written three times). Reordering for tidiness breaks
    it.
    """
    def hi(i):
        return hash_[i % 20]

    def si(i):
        return SAP_SEED[i % 21]

    def h(i):
        return hi(work[i])

    def m(i):
        return matrix[work[i] % 35]

    def s(i):
        return si(work[i])

    def ma(i):
        return matrix[aux[i] % 35]

    matrix[12] = (0x14 + (select_bits(92, work[64], work[99] // 3) & wide_seed(s(206), 4))) & M8
    work[4] = (2 * square(work[99] // 5)) & M8
    work[153] ^= (square(m(203)) * work[190]) & M8
    hash_[3] = 0x13 ^ ((s(205) >> 1) & 0x10)
    work[33] = (work[33] - and_not(s(36), 9)) & M8
    aux[5] = ((and_not(m(67), 2) | 1 | ((h(181) >> 6) & 2) | (hash_[3] & 0x10)) - 15) & M8
    matrix[12] = 0x07
    work[2] = (work[2] - 64) & M8
    hash_[19] = s(58)
    aux[4] = (92 - m(32)) & M8
    aux[9] = (m(15) + 0x9E) & M8
    work[34] = (work[34] + si(aux[9]) // 5) & M8
    hash_[19] = (hash_[19] + (0xE6 ^ ((hi(aux[9]) >> 1) & 0x66))) & M8
    work[15] ^= (3 * rotate_or_zero(work[72], (-s(190)) & 7) - 9 * s(126)) & M8
    hash_[15] ^= cube(m(181))
    matrix[4] ^= work[202] // 3
    matrix[1] = (matrix[1] + cube(majority((92 - hi(aux[4])) & M8, _not(work[105]), 0xC6))) & M8
    hash_[19] ^= ((224 | (s(92) & 27)) * m(41) // 3) & M8  # int math, then truncate
    work[140] = (work[140] + rotate_or_zero(92, (-work[5]) & 7)) & M8
    matrix[12] = (matrix[12] + majority(_not(work[4]) ^ m(12), work[182], 192)) & M8
    work[36] = (work[36] + 125) & M8
    work[124] = _rotl8(majority(majority(work[138], hash_[15], 74), h(43), 95), 4)
    aux_hash = hi(aux[9])
    aux[1] = and_not(0x4C, (aux_hash & ((s(68) << 1) & M8)))
    aux[2] = (222 - majority(((work[177] + s(79)) >> 1) & M8, (3 * work[148] // 5) & M8, matrix[1])) & M8
    matrix[16] = (matrix[16] + ((and_not(ma(4), 0x60) | aux_hash | 8) - (_rotl8(work[33], 2) | 128))) & M8
    hash_[14] ^= ma(2)
    work[19] = (work[19] + majority(
        rotate_or_zero(si(h(201)), (m(112) << 1) & 6),
        (and_not(h(208), 0x7C) | (h(164) & 0x7C)) // 5, 37)) & M8
    matrix[8] = rotate_or_zero(140, (-square(s(45))) & 7) ^ aux[4]
    work[190] = 56
    work[53] = _not((h(83) | 204) // 5)
    hash_[13] = (hash_[13] + h(41)) & M8
    hash_[10] = majority(ma(4), work[2], aux[2]) // 15
    aux[3] = (92 - square(0x28 | (ma(1) & (0x12 | (s(2) & 4))))) & M8
    seed_bits = si(aux[4])
    matrix[13] ^= seed_bits
    aux[6] = (92 + square(majority((m(179) - 38) & M8, aux[2], 177))) & M8
    expansion_bits = majority((aux[3] + (aux[4] & 74)) & M8, _not(seed_bits), 121)
    work[47] ^= (m(89) + majority(expansion_bits ^ 0xA6, aux[4], 4)) & M8
    aux[7] = (seed_bits // 3 - ma(9)
              - (0x14 | (work[151] & ((aux[4] & 0x88) | 0x62)) | (aux[4] & 0x22))) & M8
    expanded_selector = expansion_bits ^ ((aux[4] & 0xCA) >> 1) ^ 75
    aux[9] = (aux[9] + (0x80 | (majority(aux[7], work[151], 0x20) & 0x64)
                        | (seed_bits & 0x44) | (ma(9) & 0x1B))) & M8
    matrix[33] ^= work[26]
    matrix[30] = ((aux[9] // 3 - (and_not(aux[4], 8) | 0x13)) & M8) ^ h(122)
    work[22] = (m(90) & 0x1B) | 0x44
    wide = select_bits(71, matrix[expanded_selector % 35], si(aux[5]))
    matrix[18] = (matrix[18] + ((wide * wide * wide) >> 1)) & M8  # int math, then truncate
    matrix[5] = (matrix[5] - s(92)) & M8
    matrix[18] ^= (select_bits(aux[3], ma(3), select_bits(16, m(183), work[41]))
                   * select_bits(expanded_selector, h(59), work[17])) & M8
    matrix[22] = (majority(
        select_bits(hash_[14] | 28, (work[7] & 28) | 0x82, h(93)),
        rotate_or_zero(ma(4), rotate_or_zero(work[11], (-m(28)) & 7) & 7),
        matrix[33]) + 74) & M8
    hash_[15] = (hash_[15] - majority(majority(aux[3], aux[4], 214), si(h(39) ^ 217), aux[6])) & M8

    hash9 = hi(aux[9])
    indexed_hash = hi((((aux[4] // 3) - (aux[9] | work[22])) & M8) ^ aux[6]
                      ^ (((m(57) | hash9) & (0x52 | (aux[9] & 0x0D)))
                         | (((m(57) & hash9) | aux[9]) & 0x20)))
    aux[6] = square(square(h(99))) | ma(9)
    aux[1] = (aux[1] + rotate_or_zero(h(151) | s(202), h(50) & 7)
              + majority(h(4),
                         ((select_bits(matrix[16], indexed_hash, m(138))
                           + select_bits(17, work[33], s(39))) // 5) & M8,
                         147)) & M8
    aux[0] = select_bits(hash_[10] & 7, ma(6) & h(209),
                         select_bits(0x47, rotate_or_zero(s(127), ma(6) & 7),
                                     (si(ma(5)) << 1) & M8))
    selected_square = select_bits(198, square(m(14)), h(145) ^ aux[0])
    seed9 = si(aux[9])
    hash3 = hi(aux[3])
    matrix[2] = (matrix[2] + ((((hash3 << 1) & M8) & ((work[25] & 0x96) | (seed9 & 8)))
                              | (seed9 & 0x40))) & M8
    matrix[14] = (matrix[14] - select_bits(34, work[97], ma(3) & (aux[0] ^ m(100)))) & M8
    work[23] ^= (majority(majority(s(17), hash3, aux[0]), work[50] // 3, 0x76) << 1) & M8
    hash_[17] = 115
    hash_[13] = (((majority(hi(aux[7]), work[10], 82) >> 1) & 0x68) | (h(39) & 0x17))
    matrix[33] = (matrix[33] - (work[113] & 9)) & M8
    matrix[28] = (matrix[28] - (and_not(aux[3], 0x20) | ((work[110] >> 1) & 0x20))) & M8
    work[95] = si(aux[3])
    hash_[15] = majority((work[95] - 48) & M8, _not(work[184]), 189) & cube(
        majority(aux[7], si(aux[1]), 0xAA))
    matrix[22] = (matrix[22] + work[183]) & M8
    aux[4] ^= (3 * s(1)) & M8
    aux[5] = (aux[5] + 198 * majority(s(178), ma(1), 209) * h(13) * (s(26) >> 1)) & M8
    aux[8] = select_bits(10, ma(3), ma(9))
    matrix[18] = (matrix[18] - select_bits(hash_[15], aux[5] // 15, cube(hi(aux[6]) | 81))) & M8
    aux[1] = (aux[1] + si(hi(aux[1])) // 3 - h(160)) & M8
    hash_[16] = (147 - majority(aux[0],
                                majority(s(69), work[172], (aux[2] - selected_square + 77) & M8),
                                0xC2 | (aux[0] & 5))) & M8
    hash_[3] = (hash_[3] - wide_seed(majority(s(155), work[105], 141),
                                     majority(s(168), h(29), 6) & 7)) & M8
    work[5] = rotate_or_zero(0x38, (-(h(61) // 5)) & 7) ^ (_not(ma(8)) // 5)
    work[198] = (work[198] + work[3]) & M8
    wide = 162 | ma(9)
    work[164] = (work[164] + (wide * wide // 5)) & M8  # int math, then truncate
    aux[2] = (majority(rotate_or_zero(139, (-aux[5]) & 6), hi(aux[3]), 12)
              | select_bits(95, cube(seed9), hi(aux[7])))
    matrix[12] = (matrix[12] + (16 | ((work[103] | 60) & (aux[2] | (work[103] & 32)))) // 3) & M8
    work[143] = (work[143] - (0x12 | (select_bits(aux[9],
                                                  select_bits(matrix[8], work[35], aux[7]),
                                                  aux[8] // 3)
                                      & (0x4D | ((work[172] >> 1) & 0x20))))) & M8
    matrix[29] = 162
    hash_[15] = (hash_[15] + majority(m(149) ^ square(work[43]),
                                      select_bits(95, h(125), si(aux[1])) >> 1, 115)) & M8
    aux[9] = (aux[9] - hi(aux[7])) & M8
    hash_[7] = (hash_[7] - square(rotate_or_zero(ma(5), (-(m(17) * (m(17) & 1))) & M8))) & M8
    matrix[8] = (matrix[8] + cube(s(202)) - work[184]) & M8
    hash_[16] = (m(102) << 1) & 0x84
    aux[6] ^= si(aux[7]) >> 1
    hash_[7] = (hash_[7] - h(191) + select_bits(177, si(si(aux[1])), (s(80) << 1) & M8)) & M8
    hash_[6] = h(119)
    hash_[12] = (hi(aux[8]) ^ ((m(71) + m(15)) & M8)) & majority(
        and_not(work[118], 0x2C) | 2, square(hi(aux[9])), 27)
    digest_index = select_bits(0xA9, (s(57) * 231) & M8, majority(work[32], ma(1), 23)) // 5
    seed_sample = si(aux[6])
    aux[5] = majority((seed_sample & 0x1C) | (h(82) & 0xA2) | (si(digest_index) & 0x41),
                      majority(cube(hi(aux[7])), work[82], 92), 192) ^ digest_index
    matrix[25] ^= (2 * hi(aux[9]) * work[5]
                   - (rotate_or_zero(aux[4], seed_sample & 7) & ((aux[3] + 110) & M8))) & M8


# --- the FairPlay MD5 family ------------------------------------------------

FAIRPLAY_MD5_SHIFT = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]

FAIRPLAY_MD5_CONSTANT = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
]

M32 = 0xFFFFFFFF

FPSAP_SWAP_MUTATION = 0
FPSAP_CYCLE_MUTATION = 1
FAIRPLAY_KDF_MUTATION = 2


def _rotl32(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & M32 if n else v & M32


def fairplay_md5_compress(state, block, mutation):
    """Standard MD5 rounds and constants, but big-endian message words and a
    message-schedule mutation after round 31. hashlib cannot do this."""
    message = [int.from_bytes(block[i * 4:i * 4 + 4], "big") for i in range(16)]
    a, b, c, d = state

    for rnd in range(64):
        if rnd < 16:
            f = (b & c) | (~b & d)
            word = rnd
        elif rnd < 32:
            f = (d & b) | (~d & c)
            word = (5 * rnd + 1) & 15
        elif rnd < 48:
            f = b ^ c ^ d
            word = (3 * rnd + 5) & 15
        else:
            f = c ^ (b | (~d & M32))
            word = (7 * rnd) & 15
        f &= M32

        a, b, c, d = (
            d,
            (b + _rotl32((a + f + FAIRPLAY_MD5_CONSTANT[rnd] + message[word]) & M32,
                         FAIRPLAY_MD5_SHIFT[rnd])) & M32,
            b,
            c,
        )

        if rnd == 31:
            _mutate_message(message, a, b, c, d, mutation)

    return [(state[0] + a) & M32, (state[1] + b) & M32,
            (state[2] + c) & M32, (state[3] + d) & M32]


def _mutate_message(message, a, b, c, d, mutation):
    if mutation in (FPSAP_SWAP_MUTATION, FPSAP_CYCLE_MUTATION):
        idx = [a & 15, b & 15, c & 15, d & 15,
               (a >> 4) & 15, (b >> 4) & 15, (c >> 4) & 15, (d >> 4) & 15]
        if mutation == FPSAP_SWAP_MUTATION:
            for i, j in enumerate(idx):
                message[i], message[j] = message[j], message[i]
        else:
            first = message[idx[0]]
            for i in range(len(idx) - 1):
                message[idx[i]] = message[idx[i + 1]]
            message[idx[-1]] = first
    elif mutation == FAIRPLAY_KDF_MUTATION:
        def swap(i, j):
            message[i], message[j] = message[j], message[i]
        swap(a & 15, b & 15)
        swap(c & 15, d & 15)
        for shift in (4, 8, 12):
            swap((a >> shift) & 15, (b >> shift) & 15)


# --- the descriptor and the bridge ------------------------------------------

def fpsap_descriptor_for_sap(m3_sap, m2_sap):
    """The 20-byte descriptor over prefix || m3SAP || m2SAP || suffix."""
    padded = bytearray(320)
    off = 0
    for chunk in (FPSAP_DESCRIPTOR_PREFIX, m3_sap, m2_sap, FPSAP_DESCRIPTOR_SUFFIX):
        padded[off:off + len(chunk)] = chunk
        off += len(chunk)
    padded[off] = 0x80
    padded[-8:] = (off * 8).to_bytes(8, "little")

    state = [int.from_bytes(FAIRPLAY_INITIAL_SESSION_KEY[i * 4:i * 4 + 4], "little")
             for i in range(4)]
    first_final = None

    for block_off in range(0, len(padded), 64):
        block = bytes(padded[block_off:block_off + 64])
        add = fairplay_sap_hash(block)
        state = [(state[i] + int.from_bytes(add[i * 4:i * 4 + 4], "little")) & M32
                 for i in range(4)]
        state = fairplay_md5_compress(state, block, FPSAP_CYCLE_MUTATION)
        if block_off == len(padded) - 64:
            first_final = list(state)
            state = fairplay_md5_compress(state, block, FPSAP_CYCLE_MUTATION)

    out = bytearray(20)
    out[0:4] = first_final[0].to_bytes(4, "big")
    for i in range(4):
        out[4 + i * 4:8 + i * 4] = state[i].to_bytes(4, "big")
    return bytes(out)


def bridge_x9_head_for_sap(local_sap, gp):
    """The 20 payload-dependent bytes Phase 2 consumes, for a per-session SAP.

    `gp` is Phase 1's 128-byte output buffer.
    """
    if len(local_sap) != 128 or len(gp) != 128:
        raise ValueError("local_sap and gp must both be 128 bytes")
    body = bytes(v ^ GP_OUTPUT_MASK for v in gp)
    d = fpsap_descriptor_for_sap(bytes(local_sap), body)
    # The descriptor emits big-endian words; x9Data is little-endian.
    out = bytearray(20)
    for w in range(5):
        out[w * 4:w * 4 + 4] = d[w * 4:w * 4 + 4][::-1]
    return bytes(out)

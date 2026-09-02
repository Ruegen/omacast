# SPDX-License-Identifier: BlueOak-1.0.0
"""
Standalone Python FairPlay SAP bridge adapter.

This implements the recovered bridge compression primitive using only Python's
standard library. It is intended for AirPlay 2 receiver/controller projects
such as openairplay/airplay2-receiver.

The function is not a complete payload-to-m3 implementation. The remaining
White-Box AES data and fixed bridge tables are documented in impact.md.
This is authentication interoperability logic, not FairPlay Streaming DRM.
"""

BRIDGE_MD5_IV = (0xB9F3DCDC, 0xFBDC740B, 0x60F77F86, 0x51907216)
MASK32 = 0xFFFFFFFF

# Standard RFC 1321 MD5 per-round additive constant table. The bridge hash's
# real per-round constant is STD_MD5_K[i] + offset, where offset depends only
# on which hash-instance a block belongs to (see the BRIDGE_HASH*_OFFSET
# constants below) -- NOT a bespoke 64-entry table.
STD_MD5_K = (
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
)

# Per-hash-instance additive offsets, added to STD_MD5_K[i] for every round
# of every block in that group.
BRIDGE_HASH1_OFFSET = 0xB36309E4  # Hash1's non-final blocks (first 4 of 5)
BRIDGE_HASH1_FINAL_OFFSET = 0x00000000  # Hash1's final (5th) block: no offset
BRIDGE_HASH2_OFFSET = 0xD68864C0  # all 4 of Hash2's blocks

# Which round-31-boundary message permutation a block uses.
BRIDGE_MUTATION_KDF = "kdf"      # Hash1's blocks
BRIDGE_MUTATION_CYCLE = "cycle"  # Hash2's blocks

ROTATIONS = (
    (7, 12, 17, 22) * 4
    + (5, 9, 14, 20) * 4
    + (4, 11, 16, 23) * 4
    + (6, 10, 15, 21) * 4
)
SCHEDULE = (
    tuple(range(16))
    + tuple((5 * i + 1) % 16 for i in range(16))
    + tuple((3 * i + 5) % 16 for i in range(16))
    + tuple((7 * i) % 16 for i in range(16))
)


def _rotate_left(value, amount):
    value &= MASK32
    return ((value << amount) | (value >> (32 - amount))) & MASK32


def _apply_bridge_mutation(message, variant, a, b, c, d):
    """Permute message in place, using the working state right after round 31."""
    if variant == BRIDGE_MUTATION_KDF:
        for i, j in ((a & 15, b & 15), (c & 15, d & 15)):
            message[i], message[j] = message[j], message[i]
        for shift in (4, 8, 12):
            i, j = (a >> shift) & 15, (b >> shift) & 15
            message[i], message[j] = message[j], message[i]
    else:
        idx = [
            a & 15, b & 15, c & 15, d & 15,
            (a >> 4) & 15, (b >> 4) & 15, (c >> 4) & 15, (d >> 4) & 15,
        ]
        first = message[idx[0]]
        for i in range(len(idx) - 1):
            message[idx[i]] = message[idx[i + 1]]
        message[idx[-1]] = first


def bridge_md5_compress(state, message, offset, variant):
    """Update a four-word state using one sixteen-word message block.

    message is mutated in place by the round-31 permutation.
    """
    if len(state) != 4 or len(message) != 16:
        raise ValueError("state must have 4 words and message must have 16")

    a, b, c, d = state
    for index in range(64):
        if index < 16:
            function = (b & c) | ((~b) & d)
        elif index < 32:
            function = (d & b) | ((~d) & c)
        elif index < 48:
            function = b ^ c ^ d
        else:
            function = c ^ (b | (~d))

        mixed = (
            a + (function & MASK32)
            + message[SCHEDULE[index]]
            + STD_MD5_K[index]
            + offset
        ) & MASK32
        next_b = (b + _rotate_left(mixed, ROTATIONS[index])) & MASK32
        a, b, c, d = d, next_b, b, c
        if index == 31:
            _apply_bridge_mutation(message, variant, a, b, c, d)

    state[0] = (state[0] + a) & MASK32
    state[1] = (state[1] + b) & MASK32
    state[2] = (state[2] + c) & MASK32
    state[3] = (state[3] + d) & MASK32


# --- Ground-truth vectors, captured from Apple's own code --------------------
#
# The self-generated KAT below proves this file agrees with the other ports, not
# that any of them is right. An earlier version shipped a bespoke 64-entry
# constant table that passed every self-generated KAT and was still wrong: the
# one block those KATs exercised has a payload-independent message and never
# triggers the round-31 permutation.
#
# Each vector here is a (state, message, result) triple lifted from a trace of
# Apple's real bridge hash. Together they span all three per-hash offsets, both
# mutation variants, and three blocks whose message genuinely varies with the
# payload.
BRIDGE_HARDWARE_KATS = [
    ("B1", BRIDGE_HASH1_OFFSET, BRIDGE_MUTATION_KDF,
     [0xB9F3DCDC, 0xFBDC740B, 0x60F77F86, 0x51907216],
     [0x4739A369, 0x98051CA8, 0xCC907EB5, 0x2B2F24B1,
      0x6A9CF800, 0x307A5E9E, 0xE083F082, 0x05F89A33,
      0xB5827DE2, 0xAC11F834, 0x4BB8D831, 0x907269EA,
      0x47A571EF, 0xBAA9597F, 0x10651A4B, 0x9759F089],
     [0xF20BB0AF, 0x2D1CE261, 0xE8E91068, 0xEC7E94DB]),
    ("B3", BRIDGE_HASH1_OFFSET, BRIDGE_MUTATION_KDF,
     [0xAE98150B, 0xCAB5B264, 0x5800B818, 0xCD8094AF],
     [0xEC44BB2F, 0x6D4B9C49, 0x75E66E88, 0xD4012450,
      0x0758A421, 0x019EE7E0, 0xD437CBEA, 0x7D8DEF76,
      0xC91E3235, 0xE57A6CE0, 0x43B44A7E, 0x6E1CE5ED,
      0x42ED3697, 0x84F0CFD9, 0x34C43487, 0xE05A1A5A],
     [0xA5CDFF64, 0xEF81680A, 0x9EA37B66, 0x3F794376]),
    ("B5", BRIDGE_HASH1_FINAL_OFFSET, BRIDGE_MUTATION_KDF,
     [0xCCE8DABC, 0xDF507EE8, 0x5CEA1EF2, 0xE7174FA7],
     [0xC629579B, 0xD9B6360A, 0xC8701F59, 0xFBE19FE3,
      0x4FEC4E27, 0x5EFDF2E8, 0x3097AE70, 0xFBE0003F,
      0x1C398000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x10090000, 0x00000000],
     [0x367C7F22, 0x37DDE99E, 0xC0C00053, 0x1247390A]),
    ("C1", BRIDGE_HASH2_OFFSET, BRIDGE_MUTATION_CYCLE,
     [0xD39B6229, 0x9AE94DD0, 0x8C31D460, 0xEB9BD436],
     [0xC9BC378D, 0x335C58BF, 0x983D6C0C, 0x5F154286,
      0xA3779D24, 0x0D5503C2, 0xBD5E95A6, 0xE2D33F57,
      0x925D2306, 0x88EC9D58, 0x28937D55, 0x6D4D0F0E,
      0x24801713, 0x9783FEA3, 0xED3FBF6F, 0x743495AD],
     [0xC6BF6E93, 0x542728DC, 0xE90F673C, 0x5AE9BFA5]),
    ("C2", BRIDGE_HASH2_OFFSET, BRIDGE_MUTATION_CYCLE,
     [0xD1DD1548, 0xEFD049CA, 0x68E33EE6, 0x3D31DC46],
     [0x8F831B50, 0x5B78EF45, 0x14C24B8D, 0x03F28B33,
      0xB972D234, 0xF91C2A4B, 0x870A4976, 0x68E04F99,
      0x4F338181, 0x642E5904, 0xC006EFCD, 0x4B5E1860,
      0x1B08C6A8, 0x4A5CDA50, 0x3D457DDD, 0x20ACA5DB],
     [0xD30FE3AD, 0x8670FB82, 0xC1EBDDA2, 0x3FB07AA8]),
]


def run_self_test():
    """Run every known-answer test. Returns the number of failures.

    Deliberately does not use `assert`: assertions are stripped under
    `python3 -O`, and a KAT that silently disappears in a release run is worse
    than no KAT at all.
    """
    failures = 0

    message = [
        2546976663, 960577546, 1698508769, 1855391692,
        3391201467, 2557583070, 3274602661, 1912197568,
        191961631, 1855758578, 4196764585, 2306695412,
        2755794883, 994892358, 790883565, 349006184,
    ]
    state = list(BRIDGE_MD5_IV)
    bridge_md5_compress(state, message, BRIDGE_HASH1_OFFSET, BRIDGE_MUTATION_KDF)
    if state != [0x3295AB96, 0xEA9E90EB, 0x908160BD, 0x2261D759]:
        print("FAIL: self-generated bridge KAT: got %s" % [hex(w) for w in state])
        failures += 1

    for name, offset, variant, start, msg, want in BRIDGE_HARDWARE_KATS:
        state = list(start)
        bridge_md5_compress(state, list(msg), offset, variant)
        if state != want:
            print("FAIL: hardware KAT %s: got %s want %s"
                  % (name, [hex(w) for w in state], [hex(w) for w in want]))
            failures += 1

        # Control: both the per-hash offset and the round-31 permutation must
        # change the result. A port that hardcodes one offset, or skips the
        # permutation, would otherwise slip through on some blocks.
        state = list(start)
        bridge_md5_compress(state, list(msg), (offset + 1) & 0xFFFFFFFF, variant)
        if state == want:
            print("FAIL: %s: offset is not load-bearing" % name)
            failures += 1

        flipped = (BRIDGE_MUTATION_CYCLE if variant == BRIDGE_MUTATION_KDF
                   else BRIDGE_MUTATION_KDF)
        state = list(start)
        bridge_md5_compress(state, list(msg), offset, flipped)
        if state == want:
            print("FAIL: %s: mutation variant is not load-bearing" % name)
            failures += 1

    return failures


if __name__ == "__main__":
    import sys

    n = run_self_test()
    if n:
        print("FAILED: %d check(s)" % n)
        sys.exit(1)
    print("FairPlay bridge KATs passed (5 hardware blocks, 3 offsets, 2 variants)")

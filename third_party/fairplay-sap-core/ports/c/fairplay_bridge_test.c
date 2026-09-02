/* SPDX-License-Identifier: BlueOak-1.0.0 */
/* Minimal C99 known-answer test for fairplay_bridge.c.
 *
 * Build and run:
 *     cc -O2 -std=c99 -o bridge_test fairplay_bridge.c fairplay_bridge_test.c
 *     ./bridge_test        # prints PASS/FAIL, exit status 0 on success
 *
 * The checks are deliberately NOT assert() based: assert() compiles away under
 * -DNDEBUG, which would make this test silently "pass" on wrong data in a
 * release build. It reports explicitly and returns a non-zero exit status on
 * mismatch so CI can detect failures.
 */

#include "fairplay_bridge.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>


/* --- Ground-truth vectors, captured from Apple's own code -----------------
 *
 * The KAT above was generated from this project's own reference
 * implementation, so it proves the ports agree with each other -- not that
 * any of them is right. An earlier version of this code shipped a bespoke
 * 64-entry constant table that passed every self-generated KAT and was still
 * wrong, because the single block those KATs exercised has a
 * payload-independent message and never triggers the round-31 permutation.
 *
 * These five are different in kind: each is a (state, message, result) triple
 * lifted from a trace of Apple's real bridge hash, together spanning all three
 * per-hash offsets, both mutation variants, and three blocks whose message
 * genuinely varies with the payload.
 *
 * Deliberately not written with assert(): assert() compiles away under
 * -DNDEBUG, which is the default in most release builds, and a KAT that
 * silently vanishes is worse than no KAT at all.
 */
struct bridge_hw_kat {
    const char *name;
    uint32_t offset;
    bridge_mutation_t variant;
    uint32_t state[4];
    uint32_t msg[16];
    uint32_t want[4];
};

static const struct bridge_hw_kat BRIDGE_HW_KATS[] = {
    { "B1", BRIDGE_HASH1_OFFSET, BRIDGE_MUTATION_KDF,
      { 0xb9f3dcdcu, 0xfbdc740bu, 0x60f77f86u, 0x51907216u },
      { 0x4739a369u, 0x98051ca8u, 0xcc907eb5u, 0x2b2f24b1u,
        0x6a9cf800u, 0x307a5e9eu, 0xe083f082u, 0x05f89a33u,
        0xb5827de2u, 0xac11f834u, 0x4bb8d831u, 0x907269eau,
        0x47a571efu, 0xbaa9597fu, 0x10651a4bu, 0x9759f089u },
      { 0xf20bb0afu, 0x2d1ce261u, 0xe8e91068u, 0xec7e94dbu } },
    { "B3", BRIDGE_HASH1_OFFSET, BRIDGE_MUTATION_KDF,
      { 0xae98150bu, 0xcab5b264u, 0x5800b818u, 0xcd8094afu },
      { 0xec44bb2fu, 0x6d4b9c49u, 0x75e66e88u, 0xd4012450u,
        0x0758a421u, 0x019ee7e0u, 0xd437cbeau, 0x7d8def76u,
        0xc91e3235u, 0xe57a6ce0u, 0x43b44a7eu, 0x6e1ce5edu,
        0x42ed3697u, 0x84f0cfd9u, 0x34c43487u, 0xe05a1a5au },
      { 0xa5cdff64u, 0xef81680au, 0x9ea37b66u, 0x3f794376u } },
    { "B5", BRIDGE_HASH1_FINAL_OFFSET, BRIDGE_MUTATION_KDF,
      { 0xcce8dabcu, 0xdf507ee8u, 0x5cea1ef2u, 0xe7174fa7u },
      { 0xc629579bu, 0xd9b6360au, 0xc8701f59u, 0xfbe19fe3u,
        0x4fec4e27u, 0x5efdf2e8u, 0x3097ae70u, 0xfbe0003fu,
        0x1c398000u, 0x00000000u, 0x00000000u, 0x00000000u,
        0x00000000u, 0x00000000u, 0x10090000u, 0x00000000u },
      { 0x367c7f22u, 0x37dde99eu, 0xc0c00053u, 0x1247390au } },
    { "C1", BRIDGE_HASH2_OFFSET, BRIDGE_MUTATION_CYCLE,
      { 0xd39b6229u, 0x9ae94dd0u, 0x8c31d460u, 0xeb9bd436u },
      { 0xc9bc378du, 0x335c58bfu, 0x983d6c0cu, 0x5f154286u,
        0xa3779d24u, 0x0d5503c2u, 0xbd5e95a6u, 0xe2d33f57u,
        0x925d2306u, 0x88ec9d58u, 0x28937d55u, 0x6d4d0f0eu,
        0x24801713u, 0x9783fea3u, 0xed3fbf6fu, 0x743495adu },
      { 0xc6bf6e93u, 0x542728dcu, 0xe90f673cu, 0x5ae9bfa5u } },
    { "C2", BRIDGE_HASH2_OFFSET, BRIDGE_MUTATION_CYCLE,
      { 0xd1dd1548u, 0xefd049cau, 0x68e33ee6u, 0x3d31dc46u },
      { 0x8f831b50u, 0x5b78ef45u, 0x14c24b8du, 0x03f28b33u,
        0xb972d234u, 0xf91c2a4bu, 0x870a4976u, 0x68e04f99u,
        0x4f338181u, 0x642e5904u, 0xc006efcdu, 0x4b5e1860u,
        0x1b08c6a8u, 0x4a5cda50u, 0x3d457dddu, 0x20aca5dbu },
      { 0xd30fe3adu, 0x8670fb82u, 0xc1ebdda2u, 0x3fb07aa8u } },
};

static int run_hardware_kats(void)
{
    const size_t n = sizeof BRIDGE_HW_KATS / sizeof BRIDGE_HW_KATS[0];
    int failures = 0;
    size_t k;

    for (k = 0; k < n; k++) {
        const struct bridge_hw_kat *t = &BRIDGE_HW_KATS[k];
        uint32_t state[4], msg[16];
        int i;

        memcpy(state, t->state, sizeof state);
        memcpy(msg, t->msg, sizeof msg);
        bridge_md5_compress(state, msg, t->offset, t->variant);
        for (i = 0; i < 4; i++) {
            if (state[i] != t->want[i]) {
                fprintf(stderr, "FAIL: hardware KAT %s word %d: got %08x want %08x\n",
                        t->name, i, state[i], t->want[i]);
                failures++;
            }
        }

        /* Control: the offset and the round-31 permutation must both matter.
         * A port that hardcodes one offset, or skips the permutation, would
         * otherwise pass the vectors above by accident on some blocks. */
        memcpy(state, t->state, sizeof state);
        memcpy(msg, t->msg, sizeof msg);
        bridge_md5_compress(state, msg, t->offset + 1u, t->variant);
        if (memcmp(state, t->want, sizeof state) == 0) {
            fprintf(stderr, "FAIL: %s: offset is not load-bearing\n", t->name);
            failures++;
        }

        memcpy(state, t->state, sizeof state);
        memcpy(msg, t->msg, sizeof msg);
        bridge_md5_compress(state, msg, t->offset,
                            t->variant == BRIDGE_MUTATION_KDF
                                ? BRIDGE_MUTATION_CYCLE
                                : BRIDGE_MUTATION_KDF);
        if (memcmp(state, t->want, sizeof state) == 0) {
            fprintf(stderr, "FAIL: %s: mutation variant is not load-bearing\n",
                    t->name);
            failures++;
        }
    }

    if (failures != 0) {
        fprintf(stderr, "FAIL: bridge hardware KATs (%d checks failed)\n", failures);
        return 1;
    }
    printf("PASS: bridge hardware KATs (5 blocks, 3 offsets, 2 variants)\n");
    return 0;
}

int main(void) {
    /* Vector generated from the reference implementation; the Go, Rust, Python
     * and C# ports assert the same numbers, so all of them agree bit-for-bit. */
    uint32_t message[16] = {
        2546976663u, 960577546u, 1698508769u, 1855391692u,
        3391201467u, 2557583070u, 3274602661u, 1912197568u,
        191961631u, 1855758578u, 4196764585u, 2306695412u,
        2755794883u, 994892358u, 790883565u, 349006184u,
    };
    const uint32_t expected[4] = {
        0x3295ab96u, 0xea9e90ebu, 0x908160bdu, 0x2261d759u,
    };
    uint32_t state[4];
    int failures = 0;

    bridge_md5_init(state);
    bridge_md5_compress(state, message, BRIDGE_HASH1_OFFSET, BRIDGE_MUTATION_KDF);

    for (int i = 0; i < 4; ++i) {
        if (state[i] != expected[i]) {
            fprintf(stderr, "FAIL: state[%d] = 0x%08x, want 0x%08x\n", i,
                    state[i], expected[i]);
            ++failures;
        }
    }

    if (failures != 0) {
        fprintf(stderr, "FAIL: bridge_md5_compress KAT (%d/4 words wrong)\n",
                failures);
        return 1;
    }

    printf("PASS: bridge_md5_compress KAT\n");

    if (run_hardware_kats() != 0) {
        return 1;
    }

    return 0;
}

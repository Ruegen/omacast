/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Derived from github.com/omarroth/doubletake at 8ccea5f, via
 * fpsapcore. See ../../NOTICE.md.
 *
 * fairplay_sapcore.h -- the FairPlay SAP Phase-1 bridge.
 *
 * fairplay_bridge.h in this directory has the bridge *primitive*. This has the
 * functions that feed it, so the two together are a complete responder.
 *
 * Freestanding: only <stdint.h> and <string.h>. No allocation, no globals
 * mutated at runtime, so every entry point is reentrant.
 *
 * --- THREE THINGS THAT WILL BITE A PORT -----------------------------------
 * Each is silent, and each fails 30+ of the 40 vectors in ../../conformance/.
 *
 *  1. The ring index derivation underflows a uint32_t on purpose. C is the
 *     one language here where this needs no special care: unsigned wraparound
 *     is defined behaviour, so `i - 155u` is already correct and even
 *     -fsanitize=undefined stays quiet. Do not "fix" it.
 *  2. fp_rotate_or_zero() returns 0 for a zero count, not the input. It is
 *     not a rotate.
 *  3. fp_wide_seed()'s index is computed in uint32_t, wider than a byte.
 *     Masking it to 8 bits changes the answer.
 *
 * Beware C's integer promotions in the other direction too: every operand
 * below is promoted to int before arithmetic, so results must be truncated
 * back with a (uint8_t) cast. Where the Go original deliberately computes in
 * a wider type before dividing, the cast is placed after the division and a
 * comment says so.
 */

#ifndef FAIRPLAY_SAPCORE_H
#define FAIRPLAY_SAPCORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* FairPlay's proprietary SAP hash of one 64-byte block. Not a standard hash. */
void fp_sap_hash(const uint8_t block[64], uint8_t out[16]);

/* The 20-byte descriptor over prefix || m3_sap || m2_sap || suffix. */
void fp_sap_descriptor_for_sap(const uint8_t m3_sap[128],
                               const uint8_t m2_sap[128],
                               uint8_t out[20]);

/* The 20 payload-dependent bytes Phase 2 consumes, for a per-session SAP.
 * `gp` is Phase 1's 128-byte output buffer. */
void fp_bridge_x9_head_for_sap(const uint8_t local_sap[128],
                               const uint8_t gp[128],
                               uint8_t out[20]);

/* Exposed for conformance testing against ../../conformance/ring_indices.csv. */
void fp_build_ring_indices(uint8_t x[840], uint8_t y[840],
                           uint8_t z[840], uint8_t w[840]);

/* Exposed because they are the two easiest things to port wrongly. */
uint8_t fp_rotate_or_zero(uint8_t value, uint8_t count);
uint8_t fp_wide_seed(uint8_t value, uint8_t count);

#ifdef __cplusplus
}
#endif

#endif /* FAIRPLAY_SAPCORE_H */

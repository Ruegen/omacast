/* SPDX-License-Identifier: BlueOak-1.0.0 */
#ifndef FAIRPLAY_BRIDGE_H
#define FAIRPLAY_BRIDGE_H

/*
 * Standalone C99 interface for the recovered FairPlay SAP bridge hash.
 *
 * This is authentication-handshake logic, not FairPlay Streaming DRM. The
 * compression function is useful as a portable adapter, but a complete
 * payload-to-m3 implementation also needs the recovered White-Box AES data
 * and the fixed bridge tables described in impact.md.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Per-hash-instance additive offsets, added to the standard MD5 K table for
 * every round of every block in that group. */
#define BRIDGE_HASH1_OFFSET 0xb36309e4u       /* Hash1's non-final blocks (first 4 of 5) */
#define BRIDGE_HASH1_FINAL_OFFSET 0x00000000u /* Hash1's final (5th) block: no offset */
#define BRIDGE_HASH2_OFFSET 0xd68864c0u       /* all 4 of Hash2's blocks */

/* Which round-31-boundary message permutation a block uses. */
typedef enum {
    BRIDGE_MUTATION_KDF = 0,   /* Hash1's blocks */
    BRIDGE_MUTATION_CYCLE = 1, /* Hash2's blocks */
} bridge_mutation_t;

/* Initialize state with the recovered round8InitialState IV. */
void bridge_md5_init(uint32_t state[4]);

/* Compress one 16-word little-endian block into state in place. message is
 * mutated in place by the round-31 permutation. */
void bridge_md5_compress(uint32_t state[4], uint32_t message[16],
                          uint32_t offset, bridge_mutation_t variant);

#ifdef __cplusplus
}
#endif

#endif

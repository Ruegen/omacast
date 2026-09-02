// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import "math/bits"

// This file captures the Phase-1 "bridge" hash — the previously-opaque
// white-box computation that produces the 20 payload-dependent bytes
// (`x9Data[0:20]`, from which `Vreg0 = neonBlock(x9[0:16])`) that Phase 2
// consumes. See docs/fairplay/FAIRPLAY_SAP_UNWINDING.md.
//
// Reverse-engineered 2026-07-26, CORRECTED 2026-07-28: the primitive is a
// STANDARD MD5 compression — standard message schedule, standard rotation
// amounts, standard F/G/H/I round functions, standard per-round additive
// constants (the RFC 1321 MD5 K table) plus one FIXED per-hash offset added
// to every K[i] — with ONE extra step: right after round 31, the 16-word
// message array is permuted in place (a nibble-indexed swap/cycle of the
// current MD5 working state a,b,c,d), and rounds 32-63 continue reading the
// SAME schedule indices against the now-permuted array. It runs as TWO
// independent hashes over the GP data (Hash1 = 5 blocks, Hash2 = 4 blocks),
// both starting from IV = round8InitialState.
//
// The original 2026-07-26 recovery published a single 64-entry "BridgeMD5K"
// table with no round-31 permutation step. That table was extracted from
// ONLY Hash1's block 1 (B1), whose message content happens to be constant
// (payload-independent) — so a same-payload/no-permutation "cross-validation"
// against a second payload trivially passed without ever exercising the
// permutation or the other two K-offset variants. It reproduced B1 but NOT
// blocks B2-C4, and 18 of its 64 entries were a single-payload permutation
// artifact baked in as if constant (see internal/m3trace/scratch_*_test.go,
// 2026-07-28 session). Root-caused and fixed by: (1) scanning every
// instruction of a payload-varying block for message-buffer writes to find
// the exact round-31-boundary mutation, matching doubletake's independently
// implemented "kdf"/"cycle" swap patterns byte-for-byte
// (github.com/omarroth/doubletake, internal/airplay/fairplay_md5.go); (2)
// back-solving each block's true per-round K and finding it is `StdMD5K[i] +
// offset` for a CONSTANT offset that differs only per hash-instance, not per
// block or payload.
//
// Recovery method: each sub-round's ROR (EXTR Wd,Wn,Wn,#s) instruction
// exposes the pre-rotate accumulator tmp_i = a_i + F + M[sched[i]] + K[i];
// the output stream follows P[i] = P[i-1] + ror(tmp_i, s_i) from the IV,
// giving every K[i] = tmp_i - P[i-4] - F(P[i-1],P[i-2],P[i-3]) - M[sched[i]].
//
// VERIFIED (2026-07-28): 63/63 — all 9 blocks (B1-B5, C1-C4) reproduced
// exactly across 7 independently generated payloads (arithmetic sequences,
// all-zero, all-0xff), each using its own (offset, message source, mutation
// variant) triple below. See internal/m3trace/scratch_finalverify_test.go.

// BridgeMD5IV is the IV of the Phase-1 bridge hash (== round8InitialState).
var BridgeMD5IV = [4]uint32{0xb9f3dcdc, 0xfbdc740b, 0x60f77f86, 0x51907216}

// StdMD5K is the standard RFC 1321 MD5 per-round additive constant table.
// The bridge hash's real per-round constant is StdMD5K[i] + a fixed offset
// that depends only on which hash-instance a block belongs to (see the
// Bridge*Offset constants below) — NOT a bespoke 64-entry table.
var StdMD5K = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

// Per-hash-instance additive offsets, added to StdMD5K[i] for every round of
// every block in that group. Discovered by back-solving K from raw ROR
// accumulator traces and finding the offset is IDENTICAL across all rounds
// and all blocks within a group, and across every payload tested.
const (
	// BridgeHash1Offset applies to Hash1's non-final blocks (B1-B4, i.e. the
	// first 4 of Hash1's 5 blocks).
	BridgeHash1Offset uint32 = 0xb36309e4
	// BridgeHash1FinalOffset applies to Hash1's final block (B5) — plain
	// StdMD5K with NO offset.
	BridgeHash1FinalOffset uint32 = 0x00000000
	// BridgeHash2Offset applies to all 4 of Hash2's blocks (C1-C4).
	BridgeHash2Offset uint32 = 0xd68864c0
)

// BridgeMutation selects which round-31-boundary message permutation a block
// uses. Both variants match doubletake's independently-implemented FairPlay
// MD5 mutation family (internal/airplay/fairplay_md5.go in
// github.com/omarroth/doubletake) byte-for-byte.
type BridgeMutation uint8

const (
	// BridgeMutationKDF: swap(msg[a&15],msg[b&15]); swap(msg[c&15],msg[d&15]);
	// for shift in {4,8,12}: swap(msg[(a>>shift)&15], msg[(b>>shift)&15]).
	// Used by Hash1's blocks (B1-B5).
	BridgeMutationKDF BridgeMutation = iota
	// BridgeMutationCycle: save first=msg[idx[0]], then msg[idx[i]]=msg[idx[i+1]]
	// for i=0..6, then msg[idx[7]]=first, where idx=[a&15,b&15,c&15,d&15,
	// (a>>4)&15,(b>>4)&15,(c>>4)&15,(d>>4)&15]. Used by Hash2's blocks (C1-C4).
	BridgeMutationCycle
)

// bridgeMD5Rot are the (standard MD5) left-rotation amounts.
var bridgeMD5Rot = [64]int{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

// bridgeMD5Schedule is the standard MD5 message-word schedule.
var bridgeMD5Schedule = [64]int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
	5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
	0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
}

func bridgeMD5F(round int, b, c, d uint32) uint32 {
	switch round >> 4 {
	case 0:
		return (b & c) | (^b & d)
	case 1:
		return (d & b) | (^d & c)
	case 2:
		return b ^ c ^ d
	default:
		return c ^ (b | ^d)
	}
}

func applyBridgeMutation(msg *[16]uint32, variant BridgeMutation, a, b, c, d uint32) {
	switch variant {
	case BridgeMutationKDF:
		swap := func(i, j int) { msg[i], msg[j] = msg[j], msg[i] }
		swap(int(a&15), int(b&15))
		swap(int(c&15), int(d&15))
		for shift := 4; shift <= 12; shift += 4 {
			swap(int((a>>uint(shift))&15), int((b>>uint(shift))&15))
		}
	case BridgeMutationCycle:
		idx := [8]int{
			int(a & 15), int(b & 15), int(c & 15), int(d & 15),
			int((a >> 4) & 15), int((b >> 4) & 15), int((c >> 4) & 15), int((d >> 4) & 15),
		}
		first := msg[idx[0]]
		for i := 0; i < len(idx)-1; i++ {
			msg[idx[i]] = msg[idx[i+1]]
		}
		msg[idx[len(idx)-1]] = first
	}
}

// BridgeMD5Compress runs one 64-round block of the bridge hash: standard MD5
// structure with StdMD5K[i]+offset, and a message permutation applied right
// after round 31 (before round 32 consumes the message array). state is
// updated in place (Merkle-Damgard add-back). msg is mutated in place if
// variant triggers a permutation — pass a copy if the caller needs the
// original.
func BridgeMD5Compress(state *[4]uint32, msg *[16]uint32, offset uint32, variant BridgeMutation) {
	a, b, c, d := state[0], state[1], state[2], state[3]
	for i := 0; i < 64; i++ {
		f := bridgeMD5F(i, b, c, d)
		tmp := a + f + msg[bridgeMD5Schedule[i]] + StdMD5K[i] + offset
		newB := b + bits.RotateLeft32(tmp, bridgeMD5Rot[i])
		a, b, c, d = d, newB, b, c
		if i == 31 {
			applyBridgeMutation(msg, variant, a, b, c, d)
		}
	}
	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
}

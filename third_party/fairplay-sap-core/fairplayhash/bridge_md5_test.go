// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import "testing"

// bridgeKAT is a known-answer test vector for one of the bridge hash's 9 MD5
// blocks, captured directly from the interpreter trace for payload
// byte(i*7+3), i in [0,128).
type bridgeKAT struct {
	name    string
	offset  uint32
	variant BridgeMutation
	state   [4]uint32
	msg     [16]uint32
	want    [4]uint32
}

// This file previously argued (in TestBridgeMD5KMatchesHardware /
// TestBridgeMD5KRoundsAreAllExercised) that the single-table BridgeMD5K with
// no round-31 permutation was correct, because it reproduced one captured
// "hardware" vector and every constant was shown to be load-bearing for that
// vector. That conclusion was wrong, and the flaw is visible in retrospect:
// the captured vector was always Hash1's block 1 (B1) — see the "B1" entry
// below — whose 64-byte message is IDENTICAL for every payload (it depends
// only on GP-buffer setup, not the challenge). Testing exclusively against a
// payload-independent block cannot distinguish "the table is correct" from
// "the table happens to reproduce the one block that never exercises message
// permutation or the other two offset variants." It reproduced B1 and NO
// other block.
//
// The real structure (verified against all 9 blocks across 7 payloads, see
// pkg/fairplayhash/m3hash.go and internal/m3trace/bridgemd5_test.go in the
// research repo): every block uses stdMD5K[i] + a per-hash-instance offset
// (three values total: BridgeHash1Offset for B1-B4, BridgeHash1FinalOffset
// for B5, BridgeHash2Offset for C1-C4), plus a message permutation applied
// once, immediately after round 31, using one of two variants
// (BridgeMutationKDF for Hash1's blocks, BridgeMutationCycle for Hash2's).
//
// The vectors below span all three offsets and both mutation variants, and
// three of them (B3, C1, C2) have genuinely payload-dependent messages, so
// this file can no longer pass by only exercising the one block that never
// needed the fix.
var bridgeKATs = []bridgeKAT{
	{
		name: "B1", offset: BridgeHash1Offset, variant: BridgeMutationKDF,
		state: [4]uint32{0xb9f3dcdc, 0xfbdc740b, 0x60f77f86, 0x51907216},
		msg: [16]uint32{
			0x4739a369, 0x98051ca8, 0xcc907eb5, 0x2b2f24b1,
			0x6a9cf800, 0x307a5e9e, 0xe083f082, 0x05f89a33,
			0xb5827de2, 0xac11f834, 0x4bb8d831, 0x907269ea,
			0x47a571ef, 0xbaa9597f, 0x10651a4b, 0x9759f089,
		},
		want: [4]uint32{0xf20bb0af, 0x2d1ce261, 0xe8e91068, 0xec7e94db},
	},
	{
		name: "B3", offset: BridgeHash1Offset, variant: BridgeMutationKDF,
		state: [4]uint32{0xae98150b, 0xcab5b264, 0x5800b818, 0xcd8094af},
		msg: [16]uint32{
			0xec44bb2f, 0x6d4b9c49, 0x75e66e88, 0xd4012450,
			0x0758a421, 0x019ee7e0, 0xd437cbea, 0x7d8def76,
			0xc91e3235, 0xe57a6ce0, 0x43b44a7e, 0x6e1ce5ed,
			0x42ed3697, 0x84f0cfd9, 0x34c43487, 0xe05a1a5a,
		},
		want: [4]uint32{0xa5cdff64, 0xef81680a, 0x9ea37b66, 0x3f794376},
	},
	{
		name: "B5", offset: BridgeHash1FinalOffset, variant: BridgeMutationKDF,
		state: [4]uint32{0xcce8dabc, 0xdf507ee8, 0x5cea1ef2, 0xe7174fa7},
		msg: [16]uint32{
			0xc629579b, 0xd9b6360a, 0xc8701f59, 0xfbe19fe3,
			0x4fec4e27, 0x5efdf2e8, 0x3097ae70, 0xfbe0003f,
			0x1c398000, 0x00000000, 0x00000000, 0x00000000,
			0x00000000, 0x00000000, 0x10090000, 0x00000000,
		},
		want: [4]uint32{0x367c7f22, 0x37dde99e, 0xc0c00053, 0x1247390a},
	},
	{
		name: "C1", offset: BridgeHash2Offset, variant: BridgeMutationCycle,
		state: [4]uint32{0xd39b6229, 0x9ae94dd0, 0x8c31d460, 0xeb9bd436},
		msg: [16]uint32{
			0xc9bc378d, 0x335c58bf, 0x983d6c0c, 0x5f154286,
			0xa3779d24, 0x0d5503c2, 0xbd5e95a6, 0xe2d33f57,
			0x925d2306, 0x88ec9d58, 0x28937d55, 0x6d4d0f0e,
			0x24801713, 0x9783fea3, 0xed3fbf6f, 0x743495ad,
		},
		want: [4]uint32{0xc6bf6e93, 0x542728dc, 0xe90f673c, 0x5ae9bfa5},
	},
	{
		name: "C2", offset: BridgeHash2Offset, variant: BridgeMutationCycle,
		state: [4]uint32{0xd1dd1548, 0xefd049ca, 0x68e33ee6, 0x3d31dc46},
		msg: [16]uint32{
			0x8f831b50, 0x5b78ef45, 0x14c24b8d, 0x03f28b33,
			0xb972d234, 0xf91c2a4b, 0x870a4976, 0x68e04f99,
			0x4f338181, 0x642e5904, 0xc006efcd, 0x4b5e1860,
			0x1b08c6a8, 0x4a5cda50, 0x3d457ddd, 0x20aca5db,
		},
		want: [4]uint32{0xd30fe3ad, 0x8670fb82, 0xc1ebdda2, 0x3fb07aa8},
	},
}

func TestBridgeMD5CompressKATs(t *testing.T) {
	for _, k := range bridgeKATs {
		state := k.state
		msg := k.msg
		BridgeMD5Compress(&state, &msg, k.offset, k.variant)
		if state != k.want {
			t.Errorf("%s: got=%08x want=%08x", k.name, state, k.want)
		}
	}
}

// TestBridgeMD5CompressExercisesEveryRound is the control: it confirms every
// one of the 64 additive constants is load-bearing for at least one KAT, so a
// passing TestBridgeMD5CompressKATs cannot be an artifact of an unchecked
// round. Runs against B3 and C1 specifically, since both have genuinely
// payload-dependent messages (unlike B1, whose message is constant).
func TestBridgeMD5CompressExercisesEveryRound(t *testing.T) {
	targets := map[string]bridgeKAT{}
	for _, k := range bridgeKATs {
		targets[k.name] = k
	}
	saved := StdMD5K
	defer func() { StdMD5K = saved }()
	for _, name := range []string{"B3", "C1"} {
		k := targets[name]
		for r := 0; r < 64; r++ {
			StdMD5K = saved
			StdMD5K[r]++
			state := k.state
			msg := k.msg
			BridgeMD5Compress(&state, &msg, k.offset, k.variant)
			if state == k.want {
				t.Errorf("%s: round %d is not exercised by its KAT", name, r)
			}
		}
	}
}

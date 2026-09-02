// SPDX-License-Identifier: LGPL-3.0-or-later

package fpsapcore

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The four ring index tables, pinned by digest.
//
// These constants were NOT produced by this package. They come from an
// independent Python computation that forces the 32-bit wrap explicitly with
// ((i - k) % 2**32) % 210 over arbitrary-precision integers -- a different
// route to the same numbers, checked in the same pass against
// ../conformance/ring_indices.csv.
//
// That distinction is the whole point. This repository's recurring failure is a
// validator that shares an implementation with the thing it validates, which
// proves only that the code agrees with itself. Regenerating these from
// buildRingIndices would restore exactly that, so don't.
const (
	ringXDigest = "408941a6f3d6aef71c0c85e73d2ff3293ad04a5791466a1188d1b1d1e50d3b7a"
	ringYDigest = "4ed70521d7e11ac671d3033ecb148d6fdb828b30e89fa2d634e90c31e17de877"
	ringZDigest = "df5d95d147ce57d0784c369765781ae97c644550afe6665be288a24cdc34b4ae"
	ringWDigest = "9bab2dd29089584c30562cb3dcd1d48676e86a239524742da13bfb83d2ecc752"
)

// TestRingIndicesMatchConformanceDigests guards the unsigned-underflow trap: for
// i < 155 the subtraction in buildRingIndices wraps through 2^32 before the
// modulo, so (i-155)%210 is (i+101)%210 and not the (i+55)%210 that ordinary
// signed reasoning gives. 2^32 mod 210 is 46, and 55+46 is 101.
//
// A port that gets this wrong is wrong on every input while still looking
// deterministic and payload-sensitive, so nothing else in this suite would
// catch it.
func TestRingIndicesMatchConformanceDigests(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table [840]uint8
		want  string
	}{
		{"ringX", ringX, ringXDigest},
		{"ringY", ringY, ringYDigest},
		{"ringZ", ringZ, ringZDigest},
		{"ringW", ringW, ringWDigest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum := sha256.Sum256(tc.table[:])
			if got := hex.EncodeToString(sum[:]); got != tc.want {
				t.Errorf("%s digest\n got %s\nwant %s", tc.name, got, tc.want)
			}
		})
	}
}

// TestRingIndicesUnderflowBoundary states the trap as values rather than a
// digest, so a failure says what went wrong instead of only that something did.
//
// The naive column is what you get by reasoning about (i-155)%210 as though i
// were signed. It agrees with the correct answer from i=155 on, which is why a
// port can look fine in a spot check that starts anywhere past the boundary.
func TestRingIndicesUnderflowBoundary(t *testing.T) {
	for _, tc := range []struct {
		i             int
		want, naive   uint8
		shouldBeEqual bool
	}{
		{0, 101, 55, false},
		{1, 102, 56, false},
		{154, 45, 209, false},
		{155, 0, 0, true},
		{156, 1, 1, true},
	} {
		if got := ringX[tc.i]; got != tc.want {
			t.Errorf("ringX[%d] = %d, want %d", tc.i, got, tc.want)
		}
		naive := uint8((tc.i + 55) % 210)
		if naive != tc.naive {
			t.Fatalf("test is self-inconsistent: naive form at %d gave %d, expected %d", tc.i, naive, tc.naive)
		}
		if equal := tc.want == tc.naive; equal != tc.shouldBeEqual {
			t.Errorf("at i=%d the two forms agree=%v, want agree=%v", tc.i, equal, tc.shouldBeEqual)
		}
	}

	// The damage is bounded and different per table: exactly the entries below
	// each subtrahend underflow, and ringW never does.
	for _, tc := range []struct {
		name   string
		table  [840]uint8
		sub    int
		expect int
	}{
		{"ringX", ringX, 155, 155},
		{"ringY", ringY, 57, 57},
		{"ringZ", ringZ, 13, 13},
		{"ringW", ringW, 0, 0},
	} {
		differing := 0
		for i := 0; i < 840; i++ {
			naive := uint8(((i - tc.sub) % 210 % 210))
			if (i - tc.sub) < 0 {
				naive = uint8(((i - tc.sub) + 210) % 210)
			}
			if tc.table[i] != naive {
				differing++
			}
		}
		if differing != tc.expect {
			t.Errorf("%s: %d entries differ from the non-wrapping form, want %d", tc.name, differing, tc.expect)
		}
	}
}

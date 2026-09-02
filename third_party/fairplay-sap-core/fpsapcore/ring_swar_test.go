// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import (
	"encoding/binary"
	"math/bits"
	"math/rand"
	"testing"
)

func lanes(v uint64) [8]byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b
}

func packLanes(b [8]byte) uint64 { return binary.LittleEndian.Uint64(b[:]) }

// Each SWAR primitive against the byte-at-a-time version it stands in for.
func TestSWARPrimitives(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 200000; i++ {
		a, b := rng.Uint64(), rng.Uint64()
		la, lb := lanes(a), lanes(b)

		for _, n := range []uint{3, 5, 7} {
			var want [8]byte
			for k, v := range la {
				want[k] = bits.RotateLeft8(v, int(n))
			}
			if got := rotl8x8(a, n); got != packLanes(want) {
				t.Fatalf("rotl8x8(%#016x, %d) = %#016x, want %#016x", a, n, got, packLanes(want))
			}
		}

		var wantAdd, wantSub [8]byte
		for k := range la {
			wantAdd[k] = la[k] + lb[k]
			wantSub[k] = la[k] - lb[k]
		}
		if got := add8x8(a, b); got != packLanes(wantAdd) {
			t.Fatalf("add8x8(%#016x, %#016x) = %#016x, want %#016x", a, b, got, packLanes(wantAdd))
		}
		if got := sub8x8(a, b); got != packLanes(wantSub) {
			t.Fatalf("sub8x8(%#016x, %#016x) = %#016x, want %#016x", a, b, got, packLanes(wantSub))
		}
	}
}

// ringSegmentReference is the loop ringSegment replaces, kept as its oracle.
func ringSegmentReference(work *[210]byte, xi, yi, zi, wi, n int) {
	for k := 0; k < n; k++ {
		x, y, z := work[xi+k], work[yi+k], work[zi+k]
		w := work[wi+k]
		work[wi+k] = bits.RotateLeft8(y, 5) + (bits.RotateLeft8(z, 3) ^ w) - bits.RotateLeft8(x, 7)
	}
}

// Every segment length the real loop can produce, including the short tails that
// fall through to the scalar path.
func TestRingSegmentMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for trial := 0; trial < 4000; trial++ {
		var a, b [210]byte
		rng.Read(a[:])
		b = a

		// indices as the real loop holds them: four counters, no wrap in n steps
		xi, yi, zi, wi := 0, 98, 142, 155
		n := 1 + rng.Intn(55)
		for _, idx := range [4]int{xi, yi, zi, wi} {
			if r := 210 - idx; r < n {
				n = r
			}
		}
		ringSegment(&a, xi, yi, zi, wi, n)
		ringSegmentReference(&b, xi, yi, zi, wi, n)
		if a != b {
			t.Fatalf("trial %d, n=%d: segments differ", trial, n)
		}
	}
}

// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import (
	"encoding/binary"
	"math/bits"
)

// The scramble's shortest lag is 13 -- every step reads work[i-13], work[i-57]
// and work[i-155] -- so any eight consecutive steps read only values written
// before the first of them, and are therefore independent of each other. Eight
// bytes is exactly a uint64, so eight steps run at once with no vector
// instructions and no assembly: the arithmetic is done SWAR, byte lanes packed
// into one word.
//
// Two things have to be done by hand because a uint64 add carries between lanes
// and the byte arithmetic must not:
//
//   - rotate is (v<<n)|(v>>(8-n)) masked so neither half bleeds into the
//     neighbouring byte;
//   - add and subtract clear the top bit of every lane, operate, then reinsert
//     the lane-local carry with an XOR.
//
// ring_swar_test.go checks each primitive against the plain byte version over
// the whole input space it can reach, and the loop against the scalar reference.
const (
	swarH = 0x8080808080808080
	swarL = 0x7f7f7f7f7f7f7f7f
)

// rotl8x8 rotates each of the eight byte lanes left by n.
func rotl8x8(v uint64, n uint) uint64 {
	hi := uint64(byte(0xff<<n)) * 0x0101010101010101
	lo := uint64((1<<n)-1) * 0x0101010101010101
	return ((v << n) & hi) | ((v >> (8 - n)) & lo)
}

// add8x8 and sub8x8 are per-lane, with no carry or borrow crossing a lane.
func add8x8(a, b uint64) uint64 { return ((a & swarL) + (b & swarL)) ^ ((a ^ b) & swarH) }
func sub8x8(a, b uint64) uint64 { return ((a | swarH) - (b & swarL)) ^ ((a ^ ^b) & swarH) }

// ringSegment runs n steps of the scramble over contiguous spans, eight at a
// time. The caller guarantees no index wraps within the segment.
func ringSegment(work *[210]byte, xi, yi, zi, wi, n int) {
	// Sliced once up front. Inside the loop the compiler then has len(xs) == n
	// against the guard k+8 <= n, which discharges the bounds checks -- there
	// were eight per iteration, on the hottest loop in the module.
	xs := work[xi : xi+n : xi+n]
	ys := work[yi : yi+n : yi+n]
	zs := work[zi : zi+n : zi+n]
	ws := work[wi : wi+n : wi+n]

	k := 0
	for ; k+8 <= n; k += 8 {
		x := binary.LittleEndian.Uint64(xs[k : k+8])
		y := binary.LittleEndian.Uint64(ys[k : k+8])
		z := binary.LittleEndian.Uint64(zs[k : k+8])
		w := binary.LittleEndian.Uint64(ws[k : k+8])
		r := sub8x8(add8x8(rotl8x8(y, 5), rotl8x8(z, 3)^w), rotl8x8(x, 7))
		binary.LittleEndian.PutUint64(ws[k:k+8], r)
	}
	for ; k < n; k++ {
		x, y, z := xs[k], ys[k], zs[k]
		w := ws[k]
		ws[k] = bits.RotateLeft8(y, 5) + (bits.RotateLeft8(z, 3) ^ w) - bits.RotateLeft8(x, 7)
	}
}

// ringRun is one maximal stretch of the first 155 steps over which all four
// indices advance by one, so it can go through ringSegment like the tail does.
type ringRun struct{ xi, yi, zi, wi, n int }

// ringRuns is derived from the index tables rather than hard-coded, so a change
// to them cannot silently leave this describing the old shape. The first 155
// steps split into five runs; the shortest backward lag across all of them is
// 11, which is what makes eight-wide SWAR safe there as well.
var ringRuns = buildRingRuns()

func buildRingRuns() []ringRun {
	var runs []ringRun
	start := 0
	for i := 1; i <= 155; i++ {
		contiguous := i < 155 &&
			ringX[i] == ringX[i-1]+1 && ringY[i] == ringY[i-1]+1 &&
			ringZ[i] == ringZ[i-1]+1 && ringW[i] == ringW[i-1]+1
		if contiguous {
			continue
		}
		runs = append(runs, ringRun{
			xi: int(ringX[start]), yi: int(ringY[start]),
			zi: int(ringZ[start]), wi: int(ringW[start]), n: i - start,
		})
		start = i
	}
	// Eight steps run at once, so no read may be fewer than eight steps behind
	// the write it depends on. Checked here rather than assumed.
	for _, r := range runs {
		for k := 0; k < r.n; k++ {
			for _, idx := range [3]int{r.xi + k, r.yi + k, r.zi + k} {
				if d := (r.wi + k) - idx; d > 0 && d < 8 {
					panic("fpsapcore: ring run lag too short for 8-wide SWAR")
				}
			}
		}
	}
	return runs
}

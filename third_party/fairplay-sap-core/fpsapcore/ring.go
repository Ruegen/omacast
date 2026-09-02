// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

// The scramble's four index sequences are the same on every call, and three of
// them are irregular only because i is unsigned: for i < 155 the subtraction
// wraps through 2^32 before the modulo, so (i-155)%210 is not (i+55)%210. Rather
// than re-derive that with four divisions per iteration -- 3,360 per hash --
// they are tabulated once, using the identical uint32 arithmetic.
// Built as variable initialisers, not in an init(): descStateAt128 in fast.go
// is computed by an init() that calls fairplaySAPHash, and Go runs every
// variable initialiser before any init(), which is the ordering this needs.
var ringX, ringY, ringZ, ringW = buildRingIndices()

func buildRingIndices() (x, y, z, w [840]uint8) {
	for i := uint32(0); i < 840; i++ {
		x[i] = uint8((i - 155) % 210)
		y[i] = uint8((i - 57) % 210)
		z[i] = uint8((i - 13) % 210)
		w[i] = uint8(i % 210)
	}
	return
}

// sapWorkPerm is block[(i&63)^3] for one 64-byte block: a fixed permutation, so
// the 210-byte work buffer is three copies of it plus 18 bytes.
func fillWork(work *[210]byte, block []byte) {
	var p [64]byte
	for i := 0; i < 64; i++ {
		p[i] = block[i^3]
	}
	copy(work[0:], p[:])
	copy(work[64:], p[:])
	copy(work[128:], p[:])
	copy(work[192:], p[:18])
}

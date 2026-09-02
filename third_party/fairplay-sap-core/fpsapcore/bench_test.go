// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import "testing"

func benchGP() (gp [128]byte) {
	for i := range gp {
		gp[i] = byte(i*7 + 3)
	}
	return
}

func BenchmarkBridgeX9Head(b *testing.B) {
	gp := benchGP()
	for i := 0; i < b.N; i++ {
		_ = BridgeX9Head(gp)
	}
}

func BenchmarkSAPHash(b *testing.B) {
	var blk [64]byte
	for i := range blk {
		blk[i] = byte(i * 11)
	}
	for i := 0; i < b.N; i++ {
		_ = fairplaySAPHash(blk[:])
	}
}

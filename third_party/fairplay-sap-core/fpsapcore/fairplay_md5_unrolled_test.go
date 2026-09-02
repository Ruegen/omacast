// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import (
	"math/rand"
	"testing"
)

// TestMD5CompressUnrolledMatchesReference checks the unrolled round loop against
// the one it replaces, across all three message mutations.
func TestMD5CompressUnrolledMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(0xd15ea5e))
	muts := [3]fairplayMD5Mutation{fpsapSwapMutation, fpsapCycleMutation, fairplayKDFMutation}
	for iter := 0; iter < 20000; iter++ {
		var st [4]uint32
		for i := range st {
			st[i] = r.Uint32()
		}
		block := make([]byte, 64)
		for i := range block {
			block[i] = byte(r.Intn(256))
		}
		mut := muts[iter%3]

		want := fairplayMD5CompressReference(st, block, mut)
		got := fairplayMD5Compress(st, block, mut)
		if want != got {
			t.Fatalf("iter %d mutation %d: got %v want %v", iter, mut, got, want)
		}
	}
}

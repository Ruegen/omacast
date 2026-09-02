// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import (
	"math/rand"
	"testing"
)

// TestShuffleHiddenG2MatchesReference checks the unrolled swaps against the loop
// they replace.
func TestShuffleHiddenG2MatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(0x5b0ff1e))
	for iter := 0; iter < 50000; iter++ {
		var g0 [16]uint32
		for i := range g0 {
			g0[i] = r.Uint32()
		}
		a, b, c, d := r.Uint32(), r.Uint32(), r.Uint32(), r.Uint32()
		if want, got := ShuffleHiddenG2Reference(&g0, a, b, c, d), ShuffleHiddenG2(&g0, a, b, c, d); want != got {
			t.Fatalf("iter %d: got %v want %v", iter, got, want)
		}
	}
}

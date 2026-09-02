// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import (
	"math/rand"
	"testing"
)

// TestRoundCUnrolledMatchesReference checks the unrolled sub-round loop against
// the one it replaces, on both paths: hiddenG2 supplied, and hiddenG2 nil, which
// is the one that runs ShuffleHiddenG2 at sub-round 32.
func TestRoundCUnrolledMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(0x5ea1ed))
	for iter := 0; iter < 20000; iter++ {
		var st [4]uint32
		var g0, g2 [16]uint32
		for i := range st {
			st[i] = r.Uint32()
		}
		for i := range g0 {
			g0[i] = r.Uint32()
			g2[i] = r.Uint32()
		}

		var g2p *[16]uint32
		if iter%2 == 0 {
			g2p = &g2
		}

		want, got := st, st
		RoundC_MD5PlainReference(&want, &g0, g2p)
		RoundC_MD5Plain(&got, &g0, g2p)
		if want != got {
			t.Fatalf("iter %d (hiddenG2 nil=%v): got %v want %v", iter, g2p == nil, got, want)
		}
	}
}

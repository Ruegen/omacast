// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import (
	"math/rand"
	"testing"
)

// TestTailSPNMatchesReference checks the current TailSPN against the form it
// replaces, over random inputs and mixing tables.
func TestTailSPNMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(0xfeed5))
	for iter := 0; iter < 20000; iter++ {
		var in [16]byte
		var mix [144]byte
		for i := range in {
			in[i] = byte(r.Intn(256))
		}
		for i := range mix {
			mix[i] = byte(r.Intn(256))
		}
		if want, got := TailSPNReference(in, mix), TailSPN(in, mix); want != got {
			t.Fatalf("iter %d: got %x want %x", iter, got, want)
		}
	}
}

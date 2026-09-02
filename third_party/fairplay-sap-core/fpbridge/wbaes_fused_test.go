// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import (
	"math/rand"
	"testing"
)

// The fused table folds three passes into one. It is only worth having if it is
// the same function, so it is checked against the core it replaces over inputs
// the golden vectors never produce.
func TestFusedTypeIMatchesReference(t *testing.T) {
	wbaesInitMixingConsts()
	rng := rand.New(rand.NewSource(31))
	for i := 0; i < 20000; i++ {
		var in [16]byte
		rng.Read(in[:])
		if got, want := wbaesBlockCore(in), wbaesBlockCoreReference(in); got != want {
			t.Fatalf("input %x\n fused     %x\n reference %x", in, got, want)
		}
	}
}

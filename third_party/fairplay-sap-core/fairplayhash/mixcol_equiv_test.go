// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import (
	"math/rand"
	"testing"
)

func TestMixColumnsFastEquivalent(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 20000; i++ {
		var in [16]byte
		rng.Read(in[:])
		if got, want := ApplyMixColumns(in), applyMixColumnsReference(in); got != want {
			t.Fatalf("mismatch on %x\n slow %x\n fast %x", in, want, got)
		}
	}
}

func BenchmarkMixColSlow(b *testing.B) {
	var in [16]byte
	for i := range in {
		in[i] = byte(i * 17)
	}
	for i := 0; i < b.N; i++ {
		_ = applyMixColumnsReference(in)
	}
}

func BenchmarkMixColFast(b *testing.B) {
	var in [16]byte
	for i := range in {
		in[i] = byte(i * 17)
	}
	for i := 0; i < b.N; i++ {
		_ = ApplyMixColumns(in)
	}
}

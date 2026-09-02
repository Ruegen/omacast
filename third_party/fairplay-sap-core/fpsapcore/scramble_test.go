// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import (
	"math/rand"
	"testing"
)

func TestScrambleMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(21))
	for i := 0; i < 50000; i++ {
		var a, b [16]byte
		rng.Read(a[:])
		b = a
		applyScramble(&a)
		applyScrambleReference(&b)
		if a != b {
			t.Fatalf("iteration %d: table %x reference %x", i, a, b)
		}
	}
}

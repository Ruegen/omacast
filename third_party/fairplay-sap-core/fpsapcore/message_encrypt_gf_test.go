// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import "testing"

// TestGFMultiplyTables checks the two MixColumns tables against the loop they
// replace, over the whole input space rather than trusting the exchange vectors
// to reach every entry.
func TestGFMultiplyTables(t *testing.T) {
	for v := 0; v < 256; v++ {
		if got, want := gfMul2[v], gfMul(byte(v), 2); got != want {
			t.Fatalf("gfMul2[%d] = %d, want %d", v, got, want)
		}
		if got, want := gfMul3[v], gfMul(byte(v), 3); got != want {
			t.Fatalf("gfMul3[%d] = %d, want %d", v, got, want)
		}
	}
}

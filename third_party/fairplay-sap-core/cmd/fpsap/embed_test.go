// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"os"
	"testing"
)

// TestEmbeddedVectorsMatchTestdata pins the embedded copy of the golden vectors
// to the canonical testdata file. The CLI embeds its own copy so the release
// binary is self-proving without a working tree; this test is the guard that
// keeps that copy from drifting from testdata/golden_vectors.csv.
func TestEmbeddedVectorsMatchTestdata(t *testing.T) {
	canonical, err := os.ReadFile("../../testdata/golden_vectors.csv")
	if err != nil {
		t.Fatalf("read canonical vectors: %v", err)
	}
	if string(goldenVectors) != string(canonical) {
		t.Fatal("embedded golden_vectors.csv differs from testdata/golden_vectors.csv; " +
			"re-copy testdata/golden_vectors.csv into cmd/fpsap/")
	}
}

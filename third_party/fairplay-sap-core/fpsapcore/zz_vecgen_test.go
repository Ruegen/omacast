package fpsapcore

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"testing"
)

// TestGenerateCrossLanguageVectors is a generator, not a check. Run with
// -run TestGenerateCrossLanguageVectors to refresh conformance.
func TestGenerateCrossLanguageVectors(t *testing.T) {
	if os.Getenv("GEN_VECTORS") == "" {
		t.Skip("set GEN_VECTORS=1 to regenerate")
	}
	rng := rand.New(rand.NewSource(20260803))

	var sap string
	// 1. block -> fairplaySAPHash
	sap += "# block(64 bytes hex),sapHash(16 bytes hex)\n"
	for i := 0; i < 40; i++ {
		block := make([]byte, 64)
		switch i {
		case 0: // all zero
		case 1:
			for j := range block {
				block[j] = 0xff
			}
		default:
			rng.Read(block)
		}
		h := fairplaySAPHash(block)
		sap += fmt.Sprintf("%s,%s\n", hex.EncodeToString(block), hex.EncodeToString(h[:]))
	}
	os.WriteFile(os.Args[len(os.Args)-2]+"/sap_hash.csv", []byte(sap), 0o644)

	// 2. (localSAP, gp) -> x9 head
	var br string
	br += "# localSAP(128 hex),gp(128 hex),x9head(20 hex)\n"
	for i := 0; i < 30; i++ {
		var ls, gp [128]byte
		if i == 0 {
			ls = localSAP
		} else {
			rng.Read(ls[:])
		}
		rng.Read(gp[:])
		out := BridgeX9HeadForSAP(ls, gp)
		br += fmt.Sprintf("%s,%s,%s\n", hex.EncodeToString(ls[:]), hex.EncodeToString(gp[:]), hex.EncodeToString(out[:]))
	}
	os.WriteFile(os.Args[len(os.Args)-2]+"/bridge_x9head.csv", []byte(br), 0o644)
	t.Logf("wrote to %s", os.Args[len(os.Args)-2])
}

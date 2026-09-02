// SPDX-License-Identifier: LGPL-3.0-or-later
// Written here, but modelled on github.com/omarroth/doubletake. See ../NOTICE.md.

package fpbridge

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestSessionM3MatchesDoubletake cross-checks the session-aware path against an
// independent implementation, over the whole 164-byte frame.
//
// Both are given the same local SAP and the same m2, so agreement covers every
// part of the frame at once: the FPLY framing, the mode byte and label, the
// AES-encrypted body, and the twenty-byte response that folds the local SAP into
// the descriptor.
//
// The constants were produced on 2026-08-01 by omarroth/doubletake at main @
// 8ccea5f. It reaches the same bytes by a different construction -- an
// inverse-AES loop with per-mode round keys where ours is white-box AES over
// baked T-boxes, and a descriptor computed from scratch where ours had to give
// up its precomputed first two blocks. Nothing here agrees by construction.
func TestSessionM3MatchesDoubletake(t *testing.T) {
	localSAPHex := "00010b31577da3c9ef153b6187add3f91f456b91b7dd03294f759bc1e70d33597fa5cbf1173d6389afd5fb21476d93b9df052b51779dc3e90f355b81a7cdf3193f658bb1d7fd23496f95bbe1072d53799fc5eb11375d83a9cff51b41678db3d9ff254b7197bde3092f557ba1c7ed13395f85abd1f71d43698fb5db01274d7399"
	wantM3Hex := "46504c590301030000000098038f1a9c259de84df8480139a7ed23872b3133ebe500855a3de7ab89cd478388031af72df6904aaf7c563711cbfe9ff9d6b78b6a8176f73b860e3bf5b8727b8eff3bdcdeaf615470e858e2371e271f0355afe843361d938a26fa9422c388979e57f58bdd34e529eedb5c47408822823020fce8bb0f698ea592fccf23c73e2d9b36e9c3e67f53fbf91e2d8093384f764d79db8df969fff654"

	lb, err := hex.DecodeString(localSAPHex)
	if err != nil || len(lb) != 128 {
		t.Fatalf("bad local SAP literal: %v", err)
	}
	var localSAP [128]byte
	copy(localSAP[:], lb)

	var challenge [128]byte
	for i := range challenge {
		challenge[i] = byte(i*7 + 3)
	}

	s := &FPSAPSession{localSAP: localSAP}
	got, err := s.ExchangeM3(NewFPSAPM2(SupportedFPSAPMode, challenge))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(wantM3Hex)

	if !bytes.Equal(got, want) {
		// Say which part diverged; the three regions fail for different reasons.
		for _, r := range []struct {
			name   string
			lo, hi int
		}{
			{"FPLY framing and mode", 0, 16},
			{"encrypted local SAP body", 16, 144},
			{"exchange response", 144, 164},
		} {
			if !bytes.Equal(got[r.lo:r.hi], want[r.lo:r.hi]) {
				t.Errorf("%s differs:\n got  %x\n want %x", r.name, got[r.lo:r.hi], want[r.lo:r.hi])
			}
		}
		t.FailNow()
	}
	t.Logf("✅ 164/164 bytes match doubletake for the same local SAP")
}

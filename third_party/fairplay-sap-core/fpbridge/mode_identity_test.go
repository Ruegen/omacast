// SPDX-License-Identifier: LGPL-3.0-or-later
// Written here, but modelled on github.com/omarroth/doubletake. See ../NOTICE.md.

package fpbridge

import (
	"encoding/hex"
	"testing"
)

// TestModeIdentityAgainstDoubletake pins which FairPlay message mode this
// package implements, against an implementation that supports all four.
//
// The four constants below were produced on 2026-08-01 by omarroth/doubletake at
// main @ 8ccea5f, evaluating
//
//	fpsapExchangeForSAP(fpsapReferenceLocalSAP(), decryptFPSAPBody(mode, payload))
//
// for mode 0..3 on the payload built here. doubletake reaches this by a
// different route -- an inverse-AES loop with per-mode round keys, where ours is
// white-box AES over baked T-boxes -- so agreement is evidence, not tautology.
//
// The point is the disagreement as much as the agreement: modes 0, 1 and 2 give
// completely different answers, and there is no parameter in this package that
// could produce them. That is why FPSAPExchangeM3 refuses them rather than
// replying with mode 3's answer.
func TestModeIdentityAgainstDoubletake(t *testing.T) {
	doubletakeByMode := [4]string{
		0: "24ec098ab42a241038f378a1b41134644b566611",
		1: "ec2ad9490a7bfe3f3ab76ab21849f60fd7ccc939",
		2: "ba529abe0e4cd3c087798108e94b156170be5af6",
		3: "8f8a14a2ba7ad459c687cbd6dc4a3d4ec0d594af",
	}

	var payload [128]byte
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	got := hex.EncodeToString(func() []byte { r := FPExchangeNative(payload); return r[:] }())

	if want := doubletakeByMode[SupportedFPSAPMode]; got != want {
		t.Fatalf("we no longer reproduce doubletake's mode %d:\n got  %s\n want %s",
			SupportedFPSAPMode, got, want)
	}
	for mode, want := range doubletakeByMode {
		if mode == SupportedFPSAPMode {
			continue
		}
		if got == want {
			t.Fatalf("we now match doubletake's mode %d as well as mode %d; "+
				"SupportedFPSAPMode is no longer a single value", mode, SupportedFPSAPMode)
		}
	}
	t.Logf("✅ reproduces doubletake mode %d byte for byte, and none of the other three",
		SupportedFPSAPMode)
}

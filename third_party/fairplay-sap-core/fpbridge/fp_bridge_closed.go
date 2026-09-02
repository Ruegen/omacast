// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import "github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpsapcore"

// bridgeX9DataClosed is bridgeX9Data computed in closed form rather than by
// replaying the generated layers. Only x9Data[0:20] is payload-dependent; the
// rest is the constant tail the old path also appended.
//
// pkg/fpsapcore documents where the closed form came from and how it was
// checked; TestClosedFormMatchesLayers pins the two against each other.
func bridgeX9DataClosed(gp [128]byte) [64]byte {
	head := fpsapcore.BridgeX9Head(gp)
	var x9 [64]byte
	copy(x9[:], head[:])
	copy(x9[20:], bridgeX9Tail[:])
	return x9
}

func bridgeX9DataClosedForSAP(localSAP, gp [128]byte) [64]byte {
	head := fpsapcore.BridgeX9HeadForSAP(localSAP, gp)
	var x9 [64]byte
	copy(x9[:], head[:])
	// The tail is constant across both payload and local SAP: Phase 2 is seeded
	// by the 20-byte descriptor alone, which is why doubletake's exchange takes
	// only that digest. TestPhase2NeedsOnlyTheBridgeDigest pins it.
	copy(x9[20:], bridgeX9Tail[:])
	return x9
}

// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import "encoding/hex"

// localSAP is the receiver-side SAP body for the frozen post-m1 session that
// pkg/fpbridge's m3Prefix encodes. It is constant for every exchange this
// package serves, which is what makes the first two blocks of the descriptor
// precomputable.
var localSAP = func() (sap [128]byte) {
	b, err := hex.DecodeString("0001e4e3dd688293e6fa66b95ba41768e587c65f750218ff1be21543d573cefb087bd36e0c6363c3c8242f4abcfa6d660b801032015405eb4ab04dda7aeff38ffb36f4cfa48f0b5d92ae363f68b45925bbe6413ab6bdc4968f548d21e67d20f1912b6820e53f1013cde29df7350a9b9fa7c51320aea62d2949786c87642e34ba")
	if err != nil {
		panic(err)
	}
	copy(sap[:], b)
	return
}()

// gpOutputMask is the white-box output encoding wbaesFullPhase1 leaves on the
// GP buffer: a single XOR constant across all 128 bytes, measured against the
// same buffer computed without it.
const gpOutputMask = 0x0f

// BridgeX9Head returns x9Data[0:20] -- the only payload-dependent bytes Phase 2
// consumes -- from the Phase-1 GP buffer.
func BridgeX9Head(gp [128]byte) [20]byte {
	var body [128]byte
	for i, v := range gp {
		body[i] = v ^ gpOutputMask
	}
	d := descriptorFast(&body)
	// The descriptor emits big-endian words; x9Data is little-endian.
	var out [20]byte
	for w := 0; w < 5; w++ {
		out[w*4+0], out[w*4+1], out[w*4+2], out[w*4+3] =
			d[w*4+3], d[w*4+2], d[w*4+1], d[w*4+0]
	}
	return out
}

// BridgeX9HeadForSAP is BridgeX9Head for a caller-supplied local SAP, as a real
// sender generates per session.
//
// It cannot use the precomputed descriptor state: that shortcut exists precisely
// because the first two blocks are prefix and a *fixed* localSAP, so a fresh one
// invalidates it. The cost is two extra fairplaySAPHash calls and two extra
// compressions per exchange -- which is the whole of the saving, paid back.
// BridgeX9Head stays for the frozen session the golden vectors pin.
func BridgeX9HeadForSAP(localSAP, gp [128]byte) [20]byte {
	var body [128]byte
	for i, v := range gp {
		body[i] = v ^ gpOutputMask
	}
	d := fpsapDescriptorForSAP(localSAP, body)
	var out [20]byte
	for w := 0; w < 5; w++ {
		out[w*4+0], out[w*4+1], out[w*4+2], out[w*4+3] =
			d[w*4+3], d[w*4+2], d[w*4+1], d[w*4+0]
	}
	return out
}

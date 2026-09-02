// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import (
	"encoding/binary"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fairplayhash"
)

// bridgeNeonState builds Phase 2's vector inputs. Only Vreg0 is
// payload-dependent: it is x9Data[0:16] put through the NEON prologue
// transform, with the three constant vector registers as its masks.
func bridgeNeonState(x9 []byte) fairplayhash.NeonState {
	w0, w1, w2, w3 := fairplayhash.NeonBlockExport(
		binary.LittleEndian.Uint64(x9[0:8]),
		binary.LittleEndian.Uint64(x9[8:16]),
		bridgeVreg1, bridgeVreg3, bridgeVreg2)
	return fairplayhash.NeonState{
		Vreg0: [2]uint64{
			uint64(w0) | uint64(w1)<<32,
			uint64(w2) | uint64(w3)<<32,
		},
		Vreg1: bridgeVreg1,
		Vreg2: bridgeVreg2,
		Vreg3: bridgeVreg3,
	}
}

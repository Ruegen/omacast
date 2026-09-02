// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

// FPBridgeZeroBlob computes the FairPlay Phase-1 "bridge" outputs -- Vreg0 and
// the 64-byte x9Data -- from a payload, using only computation.
//
// Earlier releases produced these by replaying a ~17 MB instruction-by-
// instruction transliteration of Apple's ARM64 bridge against ~94 KB of baked
// constant pages. That is gone: the bridge is now computed from the GP buffer
// (see fp_bridge_native.go), so no template program, baked memory image, or
// address translation remains in this package.
//
// The signature and outputs are unchanged, and the two implementations were
// cross-checked against each other before the old one was removed.
func FPBridgeZeroBlob(payload [128]byte) (vreg0 [2]uint64, x9Data [64]byte) {
	x9Data = bridgeX9DataClosed(wbaesFullPhase1(payload))
	return bridgeNeonState(x9Data[:]).Vreg0, x9Data
}

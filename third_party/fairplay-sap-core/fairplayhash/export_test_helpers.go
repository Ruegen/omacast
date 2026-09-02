// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

// RoundA_Bswap_Export is an exported wrapper around roundA_bswap for testing.
func RoundA_Bswap_Export(state *HashState, offset, count int) {
	roundA_bswap(state, offset, count)
}

// RoundB_ConstExpand_Export is an exported wrapper around roundB_constExpand for testing.
func RoundB_ConstExpand_Export(state *HashState, round int) {
	roundB_constExpand(state, round)
}

// ReadState_Export is an exported wrapper around readState for testing.
func ReadState_Export(state *HashState, md5 *[4]uint32, round int) {
	readState(state, md5, round)
}

// WriteState_Export is an exported wrapper around writeState for testing.
func WriteState_Export(state *HashState, md5 *[4]uint32, round int) {
	writeState(state, md5, round)
}

// Round8InitialState_Export exposes the round 8 initial state for testing.
var Round8InitialState_Export = round8InitialState

// Exported constants for testing.
const (
	RoundAShortOffset_Export = RoundAShortOffset
	RoundAShortCount_Export  = RoundAShortCount
	RoundALongOffset_Export  = RoundALongOffset
	RoundALongCount_Export   = RoundALongCount
)

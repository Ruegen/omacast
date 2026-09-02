// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import "encoding/binary"

// The descriptor hashes prefix(17) ‖ localSAP(128) ‖ body(128) ‖ suffix(17),
// padded to 320 bytes. The body starts at flat 145, so the first two 64-byte
// blocks are entirely prefix and localSAP: payload-independent, and therefore
// precomputable once. That removes two of the five fairplaySAPHash calls and two
// of the six compressions from every exchange.
var (
	descTemplate   [320]byte
	descStateAt128 [4]uint32
)

const descBodyOffset = 17 + 128

func init() {
	offset := copy(descTemplate[:], fpsapDescriptorPrefix[:])
	offset += copy(descTemplate[offset:], localSAP[:])
	offset += 128 // the body, filled per call
	offset += copy(descTemplate[offset:], fpsapDescriptorSuffix[:])
	descTemplate[offset] = 0x80
	binary.LittleEndian.PutUint64(descTemplate[len(descTemplate)-8:], uint64(offset)*8)

	descStateAt128 = fairplayWordsFromLittleEndian(fairplayInitialSessionKey)
	for blockOffset := 0; blockOffset < 128; blockOffset += 64 {
		block := descTemplate[blockOffset : blockOffset+64]
		add := fairplaySAPHash(block)
		for i := range descStateAt128 {
			descStateAt128[i] += binary.LittleEndian.Uint32(add[i*4:])
		}
		descStateAt128 = fairplayMD5Compress(descStateAt128, block, fpsapCycleMutation)
	}
}

// descriptorFast is fpsapDescriptorForSAP with the constant prefix folded away.
func descriptorFast(body *[128]byte) (out [20]byte) {
	padded := descTemplate
	copy(padded[descBodyOffset:], body[:])

	state := descStateAt128
	var firstFinal [4]uint32
	for blockOffset := 128; blockOffset < len(padded); blockOffset += 64 {
		block := padded[blockOffset : blockOffset+64]
		add := fairplaySAPHash(block)
		for i := range state {
			state[i] += binary.LittleEndian.Uint32(add[i*4:])
		}
		state = fairplayMD5Compress(state, block, fpsapCycleMutation)
		if blockOffset == len(padded)-64 {
			firstFinal = state
			state = fairplayMD5Compress(state, block, fpsapCycleMutation)
		}
	}

	binary.BigEndian.PutUint32(out[:4], firstFinal[0])
	tail := fairplayWordsBigEndian(state)
	copy(out[4:], tail[:])
	return out
}

// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

// Package fpsapcore is the closed-form FairPlay Phase-1 bridge.
//
// It computes the same 20 payload-dependent bytes as internal/layera +
// internal/layerb + internal/layerc did, from the same GP buffer, in about 350
// lines instead of 7.2 MB of generated straight-line code.
//
// The decomposition follows omarroth/doubletake @ 8ccea5f (LGPL-3.0), whose
// fpsapDescriptorForSAP was verified byte-for-byte against our generated layers
// before any of this was written. The mapping is:
//
//	our x9Data[0:20], big-endian per word = descriptor(localSAP, gp ^ 0x0f)
//
// The XOR is the white-box output encoding our wbaesFullPhase1 leaves applied;
// it is a single constant across all 128 bytes, measured, not assumed.
package fpsapcore

import "encoding/binary"

var fairplayInitialSessionKey = [16]byte{
	0xdc, 0xdc, 0xf3, 0xb9, 0x0b, 0x74, 0xdc, 0xfb,
	0x86, 0x7f, 0xf7, 0x60, 0x16, 0x72, 0x90, 0x51,
}
var fpsapDescriptorPrefix = [...]byte{
	0xa0, 0x44, 0x9c, 0x4d, 0x09, 0xe4, 0xbd, 0x7f, 0x6e,
	0xc5, 0xd0, 0xcc, 0x35, 0x9d, 0xa7, 0x46, 0x7a,
}

var fpsapDescriptorSuffix = [...]byte{
	0x97, 0xb5, 0x0f, 0x84, 0xe2, 0x15, 0x5a, 0x9c, 0x24,
	0x99, 0x1c, 0xf4, 0x3a, 0x09, 0x63, 0x55, 0x47,
}

func fpsapDescriptorForSAP(m3SAP, m2SAP [128]byte) (out [20]byte) {
	var padded [320]byte
	offset := copy(padded[:], fpsapDescriptorPrefix[:])
	offset += copy(padded[offset:], m3SAP[:])
	offset += copy(padded[offset:], m2SAP[:])
	offset += copy(padded[offset:], fpsapDescriptorSuffix[:])
	padded[offset] = 0x80
	binary.LittleEndian.PutUint64(padded[len(padded)-8:], uint64(offset)*8)

	state := fairplayWordsFromLittleEndian(fairplayInitialSessionKey)
	var firstFinal [4]uint32
	for blockOffset := 0; blockOffset < len(padded); blockOffset += 64 {
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

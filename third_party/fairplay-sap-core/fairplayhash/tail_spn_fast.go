// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import "encoding/binary"

// tailSPNFinalI folds the final output encoding and the constant XOR mask into
// one table, so the last two loops of TailSPN become one. Built by
// wbaes_tables.go's init, which is where wbaesTypeI is filled.
var tailSPNFinalI [16][256]byte

func buildTailSPNFinal() {
	for p := 0; p < 16; p++ {
		for v := 0; v < 256; v++ {
			tailSPNFinalI[p][v] = wbaesTypeI[144+p][v] ^ tailSPNXORMask[p]
		}
	}
}

// TailSPN computes the 9-round WB-AES SPN analytically.
//
// Parameters:
//   - input: 16-byte span7 state at the T-box input for round 0
//   - mixTable: 144-byte mixing table from Block A output
//
// Returns: 16-byte span7 state after SPN + output encoding + XOR mask
func TailSPN(input [16]byte, mixTable [144]byte) [16]byte {
	state := input

	for round := 0; round < 9; round++ {
		// Inter-round encoding (identity for round 0)
		if round > 0 {
			typeI := &tailSPNTypeI[round]
			mix := mixTable[(8-round)*16:]
			var newState [16]byte
			for pos := 0; pos < 16; pos++ {
				srcPos := tailSPNInvShiftRows[pos]
				newState[pos] = wbaesTypeI[typeI[15-pos]][state[srcPos]] ^ mix[pos]
			}
			state = newState
		}

		// TypeII T-box (SubBytes + MixColumns + AddRoundKey), then scatter. The
		// four bytes of a column go to consecutive positions in little-endian
		// order, so the scatter is just the word write.
		for col := 0; col < 4; col++ {
			binary.LittleEndian.PutUint32(state[col*4:], wbaesTypeII[0][state[col*4+0]]^
				wbaesTypeII[1][state[col*4+1]]^
				wbaesTypeII[2][state[col*4+2]]^
				wbaesTypeII[3][state[col*4+3]])
		}
	}

	var encoded [16]byte
	for p := 0; p < 16; p++ {
		encoded[p] = tailSPNFinalI[p][state[tailSPNInvShiftRows[p]]]
	}
	return encoded
}

// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

// tail_spn.go implements the analytically reverse-engineered 9-round WB-AES
// Substitution-Permutation Network (SPN) from FairPlay's Phase 2.
// This covers Blocks B + C1 + C2 (bytecode ops ~63700-66280).
//
// Architecture:
//   For each round r ∈ [0,8]:
//     1. Inter-round encoding (skip for round 0):
//        For each position p ∈ [0,15]:
//          state[p] = TypeI[idx(r,p)][state[InvShiftRows[p]]] ⊕ mixTable[(8-r)*16+p]
//     2. TypeII T-box (SubBytes + MixColumns + AddRoundKey):
//        For each column c ∈ [0,3]:
//          cols[c] = TypeII[0][state[c*4+0]] ⊕ TypeII[1][state[c*4+1]] ⊕
//                    TypeII[2][state[c*4+2]] ⊕ TypeII[3][state[c*4+3]]
//     3. Scatter (LE byte order):
//          state[c*4+k] = byte(cols[c] >> (8*k))
//   Output encoding (all 16 positions):
//     encoded[P] = TypeI[144+P][state[InvShiftRows[P]]]
//   Post-encoding XOR mask (constant, payload-independent):
//     result[P] = encoded[P] ⊕ tailSPNXORMask[P]

// tailSPNTypeI holds the TypeI table indices for each of the 9 rounds.
// Position P uses index tailSPNTypeI[round][15-P].
var tailSPNTypeI = [9][16]int{
	{47, 94, 141, 44, 91, 138, 41, 88, 135, 38, 85, 132, 35, 82, 129, 32},
	{79, 126, 29, 76, 123, 26, 73, 120, 23, 70, 117, 20, 67, 114, 17, 64},
	{111, 14, 61, 108, 11, 58, 105, 8, 55, 102, 5, 52, 99, 2, 49, 96},
	{143, 46, 93, 140, 43, 90, 137, 40, 87, 134, 37, 84, 131, 34, 81, 128},
	{31, 78, 125, 28, 75, 122, 25, 72, 119, 22, 69, 116, 19, 66, 113, 16},
	{63, 110, 13, 60, 107, 10, 57, 104, 7, 54, 101, 4, 51, 98, 1, 48},
	{95, 142, 45, 92, 139, 42, 89, 136, 39, 86, 133, 36, 83, 130, 33, 80},
	{127, 30, 77, 124, 27, 74, 121, 24, 71, 118, 21, 68, 115, 18, 65, 112},
	{15, 62, 109, 12, 59, 106, 9, 56, 103, 6, 53, 100, 3, 50, 97, 0},
}

// tailSPNInvShiftRows is the AES InvShiftRows permutation for a column-major
// 4×4 byte matrix.
var tailSPNInvShiftRows = [16]int{0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3}

// tailSPNXORMask is the constant 16-byte XOR mask applied after TypeI output
// encoding. Extracted empirically: identical for all tested payloads.
var tailSPNXORMask = [16]byte{
	0x67, 0xbc, 0x54, 0xc0, 0x8e, 0x32, 0x85, 0x1b,
	0x50, 0xd2, 0x12, 0x5f, 0x68, 0xb7, 0x40, 0xa5,
}

// TailSPN computes the 9-round WB-AES SPN analytically.
//
// Parameters:
//   - input: 16-byte span7 state at the T-box input for round 0
//   - mixTable: 144-byte mixing table from Block A output
//
// Returns: 16-byte span7 state after SPN + output encoding + XOR mask
// TailSPNReference is the loop as first written, kept as the oracle
// TestTailSPNMatchesReference checks the current form against.
func TailSPNReference(input [16]byte, mixTable [144]byte) [16]byte {
	state := input

	for round := 0; round < 9; round++ {
		// Inter-round encoding (identity for round 0)
		if round > 0 {
			var newState [16]byte
			for pos := 0; pos < 16; pos++ {
				srcPos := tailSPNInvShiftRows[pos]
				typeIIdx := tailSPNTypeI[round][15-pos]
				newState[pos] = wbaesTypeI[typeIIdx][state[srcPos]] ^ mixTable[(8-round)*16+pos]
			}
			state = newState
		}

		// TypeII T-box (SubBytes + MixColumns + AddRoundKey)
		var cols [4]uint32
		for col := 0; col < 4; col++ {
			cols[col] = wbaesTypeII[0][state[col*4+0]] ^
				wbaesTypeII[1][state[col*4+1]] ^
				wbaesTypeII[2][state[col*4+2]] ^
				wbaesTypeII[3][state[col*4+3]]
		}

		// Scatter output (LE byte order within each column)
		for col := 0; col < 4; col++ {
			state[col*4+0] = byte(cols[col])
			state[col*4+1] = byte(cols[col] >> 8)
			state[col*4+2] = byte(cols[col] >> 16)
			state[col*4+3] = byte(cols[col] >> 24)
		}
	}

	// Final output encoding
	var encoded [16]byte
	for p := 0; p < 16; p++ {
		encoded[p] = wbaesTypeI[144+p][state[tailSPNInvShiftRows[p]]]
	}

	// Post-encoding XOR mask
	for p := 0; p < 16; p++ {
		encoded[p] ^= tailSPNXORMask[p]
	}

	return encoded
}

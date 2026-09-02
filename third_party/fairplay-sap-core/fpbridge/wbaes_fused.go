// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

// Per round the core does three passes over the state: a Type-I lookup through
// the per-position order table, the mixing permutation σ, and an XOR with the
// round's mixing constant. Written out that is 16 order loads, 16 table reads,
// 16 permuted reads and 16 XORs before MixColumns even starts.
//
// All three collapse into one table, because the combined formula is already
// known (see wbaes_consts.go):
//
//	sub[i] = TypeI[order[σ(i)]][state[i]] ^ mixConst[i]
//
// so wbaesFusedI[rnd][i] is a 256-byte table indexed directly by state[i]. It is
// built from wbaesTypeI and wbaesMixingConsts inside the same sync.Once that
// produces them, which is what guarantees it sees them populated -- building it
// in a separate init() would be a silent zero-table bug.
//
// 36 KB of runtime memory, no new constants in source.
var wbaesFusedI [9][16][256]byte

func buildFusedTypeI() {
	for rnd := 0; rnd < 9; rnd++ {
		order := &wbaesTypeIOrder[rnd]
		mixC := &wbaesMixingConsts[rnd]
		for i := 0; i < 16; i++ {
			src := &wbaesTypeI[order[wbaesMixingSigma[i]]]
			c := mixC[i]
			for v := 0; v < 256; v++ {
				wbaesFusedI[rnd][i][v] = src[v] ^ c
			}
		}
	}
}

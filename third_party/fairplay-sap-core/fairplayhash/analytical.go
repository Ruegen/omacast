// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import "encoding/binary"

// ComputeRoundOutputsAnalytical computes all 20 WB-MD5 round outputs with NO
// hardcoded (all-zero-only) hidden words for rounds 8 and 19. It follows the
// true FairPlay Phase-2 pipeline:
//
//	rounds 0..7,10..18  (independent WB-MD5, from the NEON prologue)  ->
//	  mixTable = BE(roundOutputs[10..18])                             ->
//	  SPN1(roundOutputs) -> R8 hidden words -> roundOutputs[8]        ->
//	  TailInput(roundOutputs) -> TailSPN -> R19 hidden words -> [19]
//
// Rounds 8 and 19 are the two SPN-consuming rounds; they depend on the later
// rounds' outputs (via the mixTable), which is why the straight 0..19 loop is
// structurally wrong and this two-phase order is required. Round 9 is a
// no-op restoration round (its output is never consumed).
//
// Every step is verified against the interpreter: SPN1 (TestSPN1EndToEnd),
// R8 (TestR8FromSPN1), TailInput+TailSPN+R19 (TestR19FullyStandalone), and the
// normal-round execution->storage schedule (TestHiddenSchedule), validated
// end-to-end by TestFPExchangeAnalytical.
func ComputeRoundOutputsAnalytical(state *HashState, ns *NeonState, x9Data []byte) [20][4]uint32 {
	var ro [20][4]uint32
	_ = state // no longer needed for the IV (see normalRoundIV below)

	// The normal WB-MD5 rounds use a PAYLOAD-INDEPENDENT constant IV (verified
	// identical across zero/all42/allFF/bit-flip captures; it equals round 9's
	// output, which is the no-op restoration round).
	normalRoundIV := [4]uint32{0x1d4a4587, 0x92f39fcc, 0x1d87d836, 0xcdc86697}

	// ALL normal WB-MD5 rounds share ONE hidden-word set -- the Phase-1 Vreg0
	// prologue output (ComputeHiddenWords round 0) -- and differ ONLY by the
	// per-round counter injected into the MSB of hidden[5] (recovered via
	// TestVreg0Schedule: every stored normal round is "Vreg0 + c<n>"). The x9
	// value is used unpatched; the [52:56] patch only affects intermediate
	// staging, never a stored round.
	base := ComputeHiddenWords(ns, x9Data, 0) // counter 0 already in hidden[5]
	runCtr := func(c int) [4]uint32 {
		h := base
		h[5] += uint32(c) << 24
		st := normalRoundIV
		RoundC_MD5Plain(&st, &h, nil)
		return st
	}

	// Execution order != storage order: pass 1 stores counters 0..8 into r10..r18.
	ro[10] = runCtr(0)
	for k := 1; k <= 8; k++ {
		ro[10+k] = runCtr(k)
	}
	// Round 9 is the no-op restoration round; its output is the constant IV.
	ro[9] = normalRoundIV
	// Pass 2's normal rounds reproduce r0..r7 identically to r11..r18 (counters
	// 1..8), verified across all captures (StateAfter[k] == StateAfter[11+k]).
	for k := 0; k < 8; k++ {
		ro[k] = ro[11+k]
	}

	// mixTable = BE(roundOutputs[10..18]), the 144-byte AddRoundKey source that
	// feeds both SPN#1 and TailSPN.
	var mixTable [144]byte
	for b := 0; b < 9; b++ {
		be := beRoundOutput(ro[10+b])
		copy(mixTable[b*16:], be[:])
	}

	// Round 8: SPN#1 output -> hidden words -> RoundC.
	spn1Out := SPN1(&ro)
	{
		g0 := R8HiddenWords(spn1Out)
		st := round8InitialState
		RoundC_MD5Plain(&st, &g0, nil)
		ro[8] = st
	}

	// Round 19: TailInput -> TailSPN -> staging(ro8, tailOut) -> hidden -> RoundC.
	tailIn := TailInput(&ro)
	tailOut := TailSPN(tailIn, mixTable)
	{
		g0 := hiddenFromStaging(R19Staging(ro[8], tailOut))
		st := round8InitialState
		RoundC_MD5Plain(&st, &g0, nil)
		ro[19] = st
	}

	return ro
}

// ComputeHashAnalytical runs the reordered pipeline and writes span7 (the 20-byte
// hash) into state.Mem[Span7Offset:Span7Offset+20]. It has no dependence on the
// hardcoded per-payload R8/R19 hidden-word tables or the (all-zero-only) fold in
// FinalizeSpan7, so it is correct for arbitrary payloads.
//
// The whole hash comes from the tail SPN pass:
//
//	span7[0:4]  = TailSPN(TailInput(ro), mixTable)[0:4]
//	span7[4:20] = BigEndian(roundOutputs[19])
func ComputeHashAnalytical(state *HashState, ns *NeonState, x9Data []byte) {
	ro := ComputeRoundOutputsAnalytical(state, ns, x9Data)

	var mixTable [144]byte
	for b := 0; b < 9; b++ {
		be := beRoundOutput(ro[10+b])
		copy(mixTable[b*16:], be[:])
	}
	tailOut := TailSPN(TailInput(&ro), mixTable)

	if Span7Offset+20 <= len(state.Mem) {
		copy(state.Mem[Span7Offset:Span7Offset+4], tailOut[0:4])
		for w := 0; w < 4; w++ {
			binary.BigEndian.PutUint32(state.Mem[Span7Offset+4+w*4:], ro[19][w])
		}
	}
}

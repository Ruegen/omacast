// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import (
	"crypto/rand"
	"testing"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fairplayhash"
	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpsapcore"
)

func benchPayload() (p [128]byte) {
	for i := range p {
		p[i] = byte(i*7 + 3)
	}
	return
}

func BenchmarkStage1WBAES(b *testing.B) {
	p := benchPayload()
	for i := 0; i < b.N; i++ {
		_ = wbaesFullPhase1(p)
	}
}

func BenchmarkStage2Bridge(b *testing.B) {
	gp := wbaesFullPhase1(benchPayload())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fpsapcore.BridgeX9Head(gp)
	}
}

func BenchmarkStage3Phase2(b *testing.B) {
	gp := wbaesFullPhase1(benchPayload())
	x9 := bridgeX9DataClosed(gp)
	ns := bridgeNeonState(x9[:])
	mem := make([]byte, 16384)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st := fairplayhash.HashState{Mem: mem}
		fairplayhash.ComputeM3Setup(&st, [4]uint32{})
		fairplayhash.ComputeHashAnalytical(&st, &ns, x9[:])
	}
}

func BenchmarkStageAllExchange(b *testing.B) {
	p := benchPayload()
	for i := 0; i < b.N; i++ {
		_ = FPExchangeNative(p)
	}
}

func BenchmarkSessionExchangeM3(b *testing.B) {
	var challenge [128]byte
	for i := range challenge {
		challenge[i] = byte(i*7 + 3)
	}
	m2 := NewFPSAPM2(SupportedFPSAPMode, challenge)
	s, err := NewFPSAPSession(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.ExchangeM3(m2); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFrozenExchangeM3(b *testing.B) {
	var challenge [128]byte
	for i := range challenge {
		challenge[i] = byte(i*7 + 3)
	}
	m2 := NewFPSAPM2(SupportedFPSAPMode, challenge)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := FPSAPExchangeM3(m2); err != nil {
			b.Fatal(err)
		}
	}
}

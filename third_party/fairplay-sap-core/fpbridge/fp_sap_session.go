// SPDX-License-Identifier: LGPL-3.0-or-later
// Written here, but modelled on github.com/omarroth/doubletake. See ../NOTICE.md.

package fpbridge

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpsapcore"
)

// fpsapM3Label is the three-byte label a sender writes after the mode byte.
var fpsapM3Label = [3]byte{0x8f, 0x1a, 0x9c}

// FPSAPSession is one FairPlay SAP exchange with its own local SAP, which is
// what makes its m3 acceptable to receivers that check the body.
//
// FPSAPExchangeM3 replays a local SAP captured once from an emulator snapshot,
// so every m3 it emits is identical; strict receivers reject that with
// RTSP/1.0 466 Key Management Error (omarroth/doubletake#17). A session
// generates its own, encrypts it into the m3 body, and folds it into the
// response — so no two sessions produce the same frame.
//
// Only mode 3 is supported; see SupportedFPSAPMode for why.
type FPSAPSession struct {
	localSAP [128]byte
}

// NewFPSAPSession creates a session with a local SAP drawn from entropy, which
// should be crypto/rand.Reader outside tests.
//
// The native sender fills the local SAP from an arc4random-seeded internal
// generator and then overwrites the first two bytes with 00 01. Taking the
// remaining 126 opaque bytes from the caller's entropy source preserves those
// protocol semantics without reproducing Apple's PRNG — the same choice
// doubletake made, and the frozen capture confirms the 00 01 head.
func NewFPSAPSession(entropy io.Reader) (*FPSAPSession, error) {
	s := &FPSAPSession{}
	s.localSAP[1] = 1
	if _, err := io.ReadFull(entropy, s.localSAP[2:]); err != nil {
		return nil, fmt.Errorf("initialize local SAP: %w", err)
	}
	return s, nil
}

// LocalSAP returns this session's local SAP.
func (s *FPSAPSession) LocalSAP() [128]byte { return s.localSAP }

// ExchangeM3 computes the 164-byte m3 for a receiver's m2, using this session's
// own local SAP rather than a replayed one.
func (s *FPSAPSession) ExchangeM3(m2 []byte) ([]byte, error) {
	payload, err := parseFPSAPM2(m2)
	if err != nil {
		return nil, err
	}

	body := fpsapcore.EncryptMessageBodyMode3(s.localSAP)

	m3 := make([]byte, 164)
	copy(m3[:4], "FPLY")
	copy(m3[4:8], []byte{3, 1, 3, 0})
	binary.BigEndian.PutUint32(m3[8:12], 152)
	m3[12] = SupportedFPSAPMode
	copy(m3[13:16], fpsapM3Label[:])
	copy(m3[16:144], body[:])

	gp := wbaesFullPhase1(payload)
	x9 := bridgeX9DataClosedForSAP(s.localSAP, gp)
	hash := exchangeFromX9(x9[:])
	copy(m3[144:], hash[:])
	return m3, nil
}

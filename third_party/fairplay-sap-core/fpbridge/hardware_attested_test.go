// SPDX-License-Identifier: LGPL-3.0-or-later

package fpbridge

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"os"
	"testing"
)

// attestedCSV holds exchanges that a real AirPlay 2 receiver accepted.
//
// Every other corpus in this repository answers "this is what Apple's compiled
// code computed", because that is what an emulator capture can tell you. These
// rows answer something strictly stronger: **a HomePod was given this response
// and accepted it**, having refused a single flipped bit in the same session.
// That oracle only became available once the pairing layer worked; see
// docs/12-pairing.md.
//
// Captured 2026-08-04 from AudioAccessory5,1 on firmware 23L471, with
// `ap2probe attest`. Replaying them needs no device and no network.
const attestedCSV = "../testdata/hardware_attested.csv"

func loadAttested(t *testing.T) [][]string {
	t.Helper()
	f, err := os.Open(attestedCSV)
	if err != nil {
		// Fail rather than skip, for the same reason the golden vectors do: a
		// missing corpus must not be indistinguishable from a passing one.
		t.Fatalf("hardware-attested vectors missing (%v)", err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read attested vectors: %v", err)
	}
	if len(rows) < 2 {
		t.Fatal("hardware-attested corpus is empty")
	}
	return rows[1:]
}

// replayAttested recomputes the response for one recorded row.
//
// The 20-byte response is a function of both the challenge and the sender's
// per-session local SAP, so the SAP is replayed too. NewFPSAPSession fixes
// localSAP[0:2] to 00 01 and fills the remaining 126 bytes from the reader,
// which is exactly what feeding back the stored tail reproduces.
func replayAttested(t *testing.T, challengeHex, sapHex string) []byte {
	t.Helper()
	ch, err := hex.DecodeString(challengeHex)
	if err != nil || len(ch) != 128 {
		t.Fatalf("bad challenge hex (%d bytes): %v", len(ch), err)
	}
	sap, err := hex.DecodeString(sapHex)
	if err != nil || len(sap) != 128 {
		t.Fatalf("bad local SAP hex (%d bytes): %v", len(sap), err)
	}

	sess, err := NewFPSAPSession(bytes.NewReader(sap[2:]))
	if err != nil {
		t.Fatalf("rebuild session: %v", err)
	}
	if got := sess.LocalSAP(); !bytes.Equal(got[:], sap) {
		t.Fatalf("replayed local SAP differs from the recorded one:\n got %x\nwant %x", got, sap)
	}

	var challenge [128]byte
	copy(challenge[:], ch)
	m3, err := sess.ExchangeM3(NewFPSAPM2(SupportedFPSAPMode, challenge))
	if err != nil {
		t.Fatalf("ExchangeM3: %v", err)
	}
	return m3[144:164]
}

// TestHardwareAttestedVectors replays every exchange a real receiver accepted
// and requires this code to produce the same 20 bytes.
//
// If this fails, the implementation has drifted away from what actual hardware
// accepts — which is a sharper signal than any archived vector can give.
func TestHardwareAttestedVectors(t *testing.T) {
	rows := loadAttested(t)
	pass := 0
	for i, rec := range rows {
		if len(rec) < 4 {
			t.Fatalf("row %d is malformed", i+1)
		}
		if rec[3] != "accepted" {
			t.Fatalf("row %d has verdict %q; only device-accepted rows belong in this corpus",
				i+1, rec[3])
		}
		got := replayAttested(t, rec[0], rec[1])
		want, err := hex.DecodeString(rec[2])
		if err != nil || len(want) != 20 {
			t.Fatalf("row %d: bad response hex", i+1)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("row %d: replay produced %x, but the receiver accepted %x", i+1, got, want)
		}
		pass++
	}
	if pass == 0 {
		t.Fatal("no attested vectors executed")
	}
	t.Logf("✅ %d/%d hardware-attested exchanges reproduced", pass, pass)
}

// TestAttestedCorpusRejectsWrongAnswers checks the corpus can actually fail.
//
// A corpus that cannot distinguish a right answer from a wrong one is not
// evidence — the same point docs/07-conformance.md makes about the all-zero
// SAP-hash row, and the same point the receiver itself demonstrated by refusing
// a single flipped bit. Perturbing one byte of the challenge must change the
// response; if it does not, this file is decoration.
func TestAttestedCorpusRejectsWrongAnswers(t *testing.T) {
	rows := loadAttested(t)
	rec := rows[0]

	ch, _ := hex.DecodeString(rec[0])
	want, _ := hex.DecodeString(rec[2])

	for _, bit := range []int{0, 63, 127} {
		mutated := append([]byte(nil), ch...)
		mutated[bit] ^= 0x01
		got := replayAttested(t, hex.EncodeToString(mutated), rec[1])
		if bytes.Equal(got, want) {
			t.Fatalf("flipping challenge byte %d left the response unchanged — "+
				"this corpus cannot detect a wrong implementation", bit)
		}
	}

	// The local SAP must matter too, or the recorded SAP column is meaningless.
	sap, _ := hex.DecodeString(rec[1])
	sap[64] ^= 0x01
	if got := replayAttested(t, rec[0], hex.EncodeToString(sap)); bytes.Equal(got, want) {
		t.Fatal("changing the local SAP left the response unchanged")
	}
}

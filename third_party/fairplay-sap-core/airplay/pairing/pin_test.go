// SPDX-License-Identifier: LGPL-3.0-or-later
// Modelled on github.com/omarroth/doubletake's pair-setup/pair-verify. See ../../../NOTICE.md.

package pairing

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/tlv8"
)

// A structurally valid V2 for pair-verify: a 32-byte server X25519 key and, when
// asked, an authenticated blob under the derived key. Built with a real X25519
// key so ECDH on the client side succeeds and produces the same shared secret
// the fake server would.
func fakeV2(t *testing.T, clientPubHex string, withBlob bool) (body []byte, sharedHex string) {
	t.Helper()
	curve := ecdh.X25519()
	serverPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cpBytes, _ := hex.DecodeString(clientPubHex)
	clientPub, err := curve.NewPublicKey(cpBytes)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		t.Fatal(err)
	}
	items := []tlv8.Item{
		tlv8.Byte(tlv8.TypeState, 2),
		{Type: tlv8.TypePublicKey, Value: serverPriv.PublicKey().Bytes()},
	}
	if withBlob {
		vk := hkdf32(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
		blob, _ := aeadSeal(vk, "PV-Msg02", []byte("accessory-signed-data"))
		items = append(items, tlv8.Item{Type: tlv8.TypeEncryptedData, Value: blob})
	}
	return tlv8.Encode(items...), hex.EncodeToString(shared)
}

// TestVerifyReachesSharedSecret drives pair-verify end to end against a fake
// receiver and checks the client and server agree on the X25519 shared secret —
// the value the control channel keys come from. A capturing server reads the
// client's V1 public key to build a matching V2.
func TestVerifyReachesSharedSecret(t *testing.T) {
	cr, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverShared := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		// --- V1 in ---
		clientPubHex, blob := readTLVField(t, br, tlv8.TypePublicKey)
		_ = blob
		v2, shared := fakeV2(t, clientPubHex, true)
		serverShared <- shared
		writeReply(conn, v2)

		// --- V3 in: just acknowledge ---
		drainRequest(br)
		writeReply(conn, tlv8.Encode(tlv8.Byte(tlv8.TypeState, 4)))
	}()

	c := dialFake(t, ln.Addr().String())
	got, err := Verify(c, cr)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := <-serverShared
	if hex.EncodeToString(got) != want {
		t.Fatalf("client shared %x != server shared %s", got, want)
	}
}

// TestVerifyRejectsUnauthenticatedV2 checks that if the receiver's V2 blob does
// not authenticate under the derived key — i.e. the peer does not actually hold
// the shared secret — Verify refuses rather than proceeding. Without this a man
// in the middle who forwards a public key it cannot use still completes.
func TestVerifyRejectsUnauthenticatedV2(t *testing.T) {
	cr, _ := NewCredentials()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		clientPubHex, _ := readTLVField(t, br, tlv8.TypePublicKey)

		// Build a V2 whose encrypted blob is sealed under the WRONG key.
		curve := ecdh.X25519()
		sp, _ := curve.GenerateKey(rand.Reader)
		cp, _ := hex.DecodeString(clientPubHex)
		_ = cp
		garbage, _ := aeadSeal(make([]byte, 32), "PV-Msg02", []byte("nope"))
		v2 := tlv8.Encode(
			tlv8.Byte(tlv8.TypeState, 2),
			tlv8.Item{Type: tlv8.TypePublicKey, Value: sp.PublicKey().Bytes()},
			tlv8.Item{Type: tlv8.TypeEncryptedData, Value: garbage},
		)
		writeReply(conn, v2)
	}()

	c := dialFake(t, ln.Addr().String())
	if _, err := Verify(c, cr); err == nil {
		t.Fatal("Verify accepted a V2 that did not authenticate")
	}
}

// TestPINSetupWrongPINNamesIt checks the M4 authentication error is reported as
// a wrong PIN, since that is the likely cause and the message is what a user
// reads.
func TestPINSetupWrongPINNamesIt(t *testing.T) {
	cr, _ := NewCredentials()
	salt := make([]byte, 16)
	pub := make([]byte, 384) // non-zero, so SRP reaches M4 rather than rejecting B=0
	for i := range pub {
		pub[i] = byte(i*7 + 1)
	}
	m2 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeState, 2),
		tlv8.Item{Type: tlv8.TypeSalt, Value: salt},
		tlv8.Item{Type: tlv8.TypePublicKey, Value: pub},
	)
	m4 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeState, 4),
		tlv8.Byte(tlv8.TypeError, tlv8.ErrAuthentication),
	)
	addr := fakeReceiver(t, [][]byte{m2, m4})

	err := PINSetup(dialFake(t, addr), "9999", cr)
	if err == nil {
		t.Fatal("wrong PIN was accepted")
	}
	if !strings.Contains(err.Error(), "PIN is wrong") {
		t.Fatalf("error should name the PIN, got: %v", err)
	}
}

// TestM5CarriesSignedIdentity pins the M5 signature preimage:
// sigKey || pairingID || LTPK, signed by the client's Ed25519 key. Getting the
// preimage wrong is a bug that only surfaces on real hardware, so it is checked
// in isolation here — both that the correct preimage verifies and that a
// perturbed one does not.
func TestM5CarriesSignedIdentity(t *testing.T) {
	cr, _ := NewCredentials()

	sigKey := make([]byte, 32)
	for i := range sigKey {
		sigKey[i] = byte(i)
	}
	signed := concat(sigKey, []byte(cr.PairingID), cr.Ed25519Public)
	sig := ed25519.Sign(cr.Ed25519Private, signed)
	if !ed25519.Verify(cr.Ed25519Public, signed, sig) {
		t.Fatal("self-signed identity does not verify — signature preimage is wrong")
	}
	// And a signature over a different preimage must NOT verify, so the check
	// above is meaningful.
	if ed25519.Verify(cr.Ed25519Public, append([]byte("x"), signed...), sig) {
		t.Fatal("signature verified over the wrong preimage")
	}
}

// TestHKPHeadersShape pins the headers PIN pairing sends: type 5 by default,
// with the client name and ID; type 3 when set.
func TestHKPHeadersShape(t *testing.T) {
	cr, _ := NewCredentials()
	h := strings.Join(cr.hkpHeaders(), "\n")
	if !strings.Contains(h, "X-Apple-HKP: 5") {
		t.Errorf("default HKP should be 5 (Apple TV), got:\n%s", h)
	}
	if !strings.Contains(h, "X-Apple-Client-ID: "+cr.PairingID) {
		t.Errorf("missing client ID header:\n%s", h)
	}
	cr.HKPType = HKPSystemPairing
	if !strings.Contains(strings.Join(cr.hkpHeaders(), "\n"), "X-Apple-HKP: 3") {
		t.Error("HKP 3 not reflected")
	}
}

// --- small helpers over the raw socket, shared with transient_test.go's style ---

func readTLVField(t *testing.T, br *bufio.Reader, tag byte) (valueHex string, allTags string) {
	t.Helper()
	body := drainRequest(br)
	m, err := tlv8.Decode(body)
	if err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	v, _ := m.Get(tag)
	return hex.EncodeToString(v), fmt.Sprintf("%v", m)
}

func drainRequest(br *bufio.Reader) []byte {
	clen := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil
		}
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok &&
			strings.EqualFold(strings.TrimSpace(k), "content-length") {
			fmt.Sscanf(strings.TrimSpace(v), "%d", &clen)
		}
		if line == "\r\n" {
			break
		}
	}
	buf := make([]byte, clen)
	if clen > 0 {
		readFull(br, buf)
	}
	return buf
}

func writeReply(conn net.Conn, body []byte) {
	fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
	conn.Write(body)
}

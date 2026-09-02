// SPDX-License-Identifier: BlueOak-1.0.0

package pairing

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/rtsp"
	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/tlv8"
)

// fakeReceiver replies to each request in turn with the next body in replies.
// Transient makes three requests — /pair-pin-start, M1, M3 — so a test supplies
// three bodies and controls exactly what the "device" says at each step.
func fakeReceiver(t *testing.T, replies [][]byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for _, body := range replies {
			// Consume the request head, then its body if it declared one.
			clen := 0
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok &&
					strings.EqualFold(strings.TrimSpace(k), "content-length") {
					fmt.Sscanf(strings.TrimSpace(v), "%d", &clen)
				}
				if line == "\r\n" {
					break
				}
			}
			if clen > 0 {
				io := make([]byte, clen)
				if _, err := readFull(br, io); err != nil {
					return
				}
			}
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
			conn.Write(body)
		}
	}()
	return ln.Addr().String()
}

func readFull(br *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := br.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func dialFake(t *testing.T, addr string) *rtsp.Client {
	t.Helper()
	c, err := rtsp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Timeout = 3 * time.Second
	return c
}

// wellFormedM2 is a structurally valid M2: state 2, a 16-byte salt, and a
// 384-byte server public key. The key is not from a real SRP server, which does
// not matter for the tests below — the client will derive *some* session key
// from it and then check the receiver's proof, which is the behaviour under test.
func wellFormedM2() []byte {
	salt := make([]byte, 16)
	pub := make([]byte, 384)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	for i := range pub {
		pub[i] = byte(i*7 + 3)
	}
	return tlv8.Encode(
		tlv8.Byte(tlv8.TypeState, 2),
		tlv8.Item{Type: tlv8.TypeSalt, Value: salt},
		tlv8.Item{Type: tlv8.TypePublicKey, Value: pub},
	)
}

// TestServerProofIsEnforced is the test that matters.
//
// SRP's whole value is mutual authentication: the receiver proves it knows the
// password too. If that check were skipped, mis-wired, or its error swallowed,
// this client would accept a session key from anything that answered — and no
// unit test of VerifyServerProof in isolation would notice, because the bug
// would be in the caller.
//
// Here the receiver returns a syntactically valid M4 carrying a garbage proof.
// It must be refused.
func TestServerProofIsEnforced(t *testing.T) {
	badProof := make([]byte, 64) // right length, wrong value
	m4 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeState, 4),
		tlv8.Item{Type: tlv8.TypeProof, Value: badProof},
	)
	addr := fakeReceiver(t, [][]byte{nil, wellFormedM2(), m4})

	_, err := Transient(dialFake(t, addr), nil)
	if err == nil {
		t.Fatal("a receiver returning a bogus proof was accepted — MITM defence is not wired up")
	}
	if !strings.Contains(err.Error(), "proof") {
		t.Fatalf("want a proof-mismatch error, got: %v", err)
	}
}

// TestMissingServerProofIsRefused checks an M4 with no proof at all fails.
// A `if proof, ok := ...; ok { verify }` with no else would silently succeed
// here, which is the same class of bug as skipping the check outright.
func TestMissingServerProofIsRefused(t *testing.T) {
	m4 := tlv8.Encode(tlv8.Byte(tlv8.TypeState, 4))
	addr := fakeReceiver(t, [][]byte{nil, wellFormedM2(), m4})

	if _, err := Transient(dialFake(t, addr), nil); err == nil {
		t.Fatal("an M4 with no proof was accepted")
	}
}

// TestReceiverErrorsAreNamed checks a TLV error code surfaces by name rather
// than as a generic parse failure. kTLVError_Backoff in particular is a
// rate-limit that a caller should recognise and wait out, not retry blindly.
func TestReceiverErrorsAreNamed(t *testing.T) {
	for _, tc := range []struct {
		code byte
		want string
	}{
		{tlv8.ErrBackoff, "kTLVError_Backoff"},
		{tlv8.ErrAuthentication, "kTLVError_Authentication"},
		{tlv8.ErrMaxTries, "kTLVError_MaxTries"},
	} {
		m2 := tlv8.Encode(tlv8.Byte(tlv8.TypeState, 2), tlv8.Byte(tlv8.TypeError, tc.code))
		addr := fakeReceiver(t, [][]byte{nil, m2})

		_, err := Transient(dialFake(t, addr), nil)
		if err == nil {
			t.Fatalf("%s: error reply was accepted", tc.want)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("want %q named in the error, got: %v", tc.want, err)
		}
	}
}

// TestAuthenticationErrorAtM4MentionsThePassword checks the failure a wrong SRP
// password produces points at the password. This exact error cost several
// debugging rounds while the flow was being worked out, because it looks like a
// crypto bug rather than a credential one.
func TestAuthenticationErrorAtM4MentionsThePassword(t *testing.T) {
	m4 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeState, 4),
		tlv8.Byte(tlv8.TypeError, tlv8.ErrAuthentication),
	)
	addr := fakeReceiver(t, [][]byte{nil, wellFormedM2(), m4})

	_, err := Transient(dialFake(t, addr), nil)
	if err == nil {
		t.Fatal("an authentication error was accepted")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Fatalf("the error should point at the password, got: %v", err)
	}
}

// TestMalformedM2IsRefused covers replies that parse but lack what M3 needs.
func TestMalformedM2IsRefused(t *testing.T) {
	salt := make([]byte, 16)
	pub := make([]byte, 384)
	for _, tc := range []struct {
		name string
		m2   []byte
	}{
		{"no salt", tlv8.Encode(
			tlv8.Byte(tlv8.TypeState, 2),
			tlv8.Item{Type: tlv8.TypePublicKey, Value: pub})},
		{"no public key", tlv8.Encode(
			tlv8.Byte(tlv8.TypeState, 2),
			tlv8.Item{Type: tlv8.TypeSalt, Value: salt})},
		{"empty body", nil},
		{"not TLV8 at all", []byte{0xff}},
	} {
		addr := fakeReceiver(t, [][]byte{nil, tc.m2})
		if _, err := Transient(dialFake(t, addr), nil); err == nil {
			t.Errorf("%s: was accepted", tc.name)
		}
	}
}

// TestM1CarriesTheRequiredShape pins the wire shape of M1.
//
// The X-Apple-HKP value and the Flags encoding are both load-bearing and both
// fail late — with the wrong value the receiver still returns a well-formed M2
// and only refuses at M4. The /pair-pin-start call is asserted because the code
// makes it, NOT because it is required: isolating it against a HomePod showed
// pairing succeeds without it (see the HKPTransient doc comment).
func TestM1CarriesTheRequiredShape(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type req struct {
		path, head string
		body       []byte
	}
	got := make(chan req, 2)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for n := 0; n < 2; n++ {
			var head strings.Builder
			path, clen := "", 0
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				head.WriteString(line)
				if f := strings.Fields(line); len(f) >= 2 && (f[0] == "POST" || f[0] == "GET") {
					path = f[1]
				}
				if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok &&
					strings.EqualFold(strings.TrimSpace(k), "content-length") {
					fmt.Sscanf(strings.TrimSpace(v), "%d", &clen)
				}
				if line == "\r\n" {
					break
				}
			}
			body := make([]byte, clen)
			if clen > 0 {
				readFull(br, body)
			}
			got <- req{path, head.String(), body}
			conn.Write([]byte("RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}
	}()

	// Fails at M2 (empty reply); we only care about what went out first.
	_, _ = Transient(dialFake(t, ln.Addr().String()), nil)

	first := <-got
	if first.path != "/pair-pin-start" {
		t.Errorf("first request is %s, want /pair-pin-start (kept deliberately, though not required)", first.path)
	}

	second := <-got
	if second.path != "/pair-setup" {
		t.Fatalf("second request is %s, want /pair-setup", second.path)
	}
	if !strings.Contains(second.head, "X-Apple-HKP: 4") {
		t.Errorf("M1 is missing X-Apple-HKP: 4 (value 3 gets an M2 then dead-ends at M4)")
	}

	m1, err := tlv8.Decode(second.body)
	if err != nil {
		t.Fatalf("M1 is not valid TLV8: %v", err)
	}
	if v, ok := m1.Get(tlv8.TypeFlags); !ok || len(v) != 1 || v[0] != byte(tlv8.FlagTransient) {
		t.Errorf("Flags = %x, want the single byte %02x — the 4-byte "+
			"little-endian form is accepted at M1 and fails at M4",
			v, byte(tlv8.FlagTransient))
	}
	if v, ok := m1.GetByte(tlv8.TypeState); !ok || v != 1 {
		t.Errorf("State = %d, want 1", v)
	}
	if v, ok := m1.GetByte(tlv8.TypeMethod); !ok || v != 0 {
		t.Errorf("Method = %d, want 0", v)
	}
}

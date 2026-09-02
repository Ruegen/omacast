// SPDX-License-Identifier: BlueOak-1.0.0

package srp

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func bigHex(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(strings.Join(strings.Fields(s), ""), 16)
	if !ok {
		t.Fatalf("bad big hex")
	}
	return n
}

// TestRFC5054Multiplier pins k = H(N | PAD(g)) against the value RFC 5054
// Appendix B publishes for the 1024-bit group with SHA-1.
//
// This is the one constant in SRP-6a that is both published and sensitive to
// getting the hashing convention wrong: forget to left-pad g to the modulus
// width and k comes out different, which then poisons S and M1 with no clue as
// to why. Checking it against an external number rather than against our own
// code is the point.
func TestRFC5054Multiplier(t *testing.T) {
	c, err := NewClient(Group1024, sha1.New, []byte("alice"), []byte("password123"))
	if err != nil {
		t.Fatal(err)
	}
	want := bigHex(t, "7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F")
	if c.K().Cmp(want) != 0 {
		t.Fatalf("k = %x, want %x (RFC 5054 Appendix B)", c.K(), want)
	}
}

// TestRFC5054PrivateKey pins x = H(salt | H(I | ":" | P)) against Appendix B.
func TestRFC5054PrivateKey(t *testing.T) {
	c, err := NewClient(Group1024, sha1.New, []byte("alice"), []byte("password123"))
	if err != nil {
		t.Fatal(err)
	}
	salt := unhex(t, "BEB25379 D1A8581E B5A72767 3A2441EE")
	want := bigHex(t, "94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124")
	if got := c.X(salt); got.Cmp(want) != 0 {
		t.Fatalf("x = %x, want %x (RFC 5054 Appendix B)", got, want)
	}
}

// TestRFC5054Verifier pins v = g^x mod N against Appendix B's published value.
func TestRFC5054Verifier(t *testing.T) {
	c, err := NewClient(Group1024, sha1.New, []byte("alice"), []byte("password123"))
	if err != nil {
		t.Fatal(err)
	}
	salt := unhex(t, "BEB25379 D1A8581E B5A72767 3A2441EE")
	want := bigHex(t, `
		7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
		9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
		C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
		EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
		E955A5E2 9E7AB245 DB2BE315 E2099AFB`)
	if got := c.Verifier(salt); got.Cmp(want) != 0 {
		t.Fatalf("v mismatch\n got %x\nwant %x", got, want)
	}
}

// TestRFC5054PublicKey pins A = g^a mod N for the published private a.
func TestRFC5054PublicKey(t *testing.T) {
	c, err := NewClient(Group1024, sha1.New, []byte("alice"), []byte("password123"))
	if err != nil {
		t.Fatal(err)
	}
	c.SetEphemeral(bigHex(t, `
		60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD
		DA2D4393`))
	want := bigHex(t, `
		61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
		4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
		8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
		BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
		B349EF5D 76988A36 72FAC47B 0769447B`)
	if got := new(big.Int).SetBytes(c.PublicKey()); got.Cmp(want) != 0 {
		t.Fatalf("A mismatch\n got %x\nwant %x", got, want)
	}
}

// TestClientAndServerAgreeOnSecret cross-checks the two halves of SRP-6a.
//
// The client reaches S as (B - k*g^x)^(a + u*x) and the server reaches it as
// (A * v^u)^b. Those are algebraically different expressions, so agreement is
// evidence the implementation is right rather than merely self-consistent —
// the distinction this repository's conformance docs keep insisting on. Run
// with the real 3072-bit/SHA-512 parameters, which have no published vectors.
func TestClientAndServerAgreeOnSecret(t *testing.T) {
	salt := unhex(t, "0102030405060708090a0b0c0d0e0f10")
	c, err := NewClient(Group3072, sha512.New, []byte("Pair-Setup"), []byte("3939"))
	if err != nil {
		t.Fatal(err)
	}
	b := bigHex(t, "E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20")

	v := c.Verifier(salt)
	B := c.ServerPublic(v, b)
	serverS := c.ServerSecret(v, b)

	if _, err := c.Proof(salt, c.group.pad(B)); err != nil {
		t.Fatalf("client proof: %v", err)
	}
	// The client stores K = H(S); recompute the server's K the same way.
	wantKey := c.hashBytes(serverS.Bytes())
	if hex.EncodeToString(c.SessionKey()) != hex.EncodeToString(wantKey) {
		t.Fatalf("client and server derived different session keys\n client %x\n server %x",
			c.SessionKey(), wantKey)
	}
}

// TestServerProofRoundTrip checks VerifyServerProof accepts a correct M2 and
// rejects a corrupted one. A verifier that never rejects is not a verifier.
func TestServerProofRoundTrip(t *testing.T) {
	salt := unhex(t, "0102030405060708090a0b0c0d0e0f10")
	c, err := NewClient(Group3072, sha512.New, []byte("Pair-Setup"), []byte("3939"))
	if err != nil {
		t.Fatal(err)
	}
	b := bigHex(t, "00E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20")
	v := c.Verifier(salt)
	B := c.ServerPublic(v, b)
	m1, err := c.Proof(salt, c.group.pad(B))
	if err != nil {
		t.Fatal(err)
	}

	good := c.hashBytes(c.A.Bytes(), m1, c.SessionKey())
	if err := c.VerifyServerProof(good); err != nil {
		t.Fatalf("correct server proof rejected: %v", err)
	}
	bad := append([]byte(nil), good...)
	bad[0] ^= 0xff
	if err := c.VerifyServerProof(bad); err == nil {
		t.Fatal("corrupted server proof was accepted")
	}
}

// TestRejectsDegenerateServerKey checks B ≡ 0 (mod N) is refused rather than
// silently producing a shared secret an attacker chose.
func TestRejectsDegenerateServerKey(t *testing.T) {
	c, err := NewClient(Group3072, sha512.New, []byte("Pair-Setup"), []byte("3939"))
	if err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, 384)
	if _, err := c.Proof(make([]byte, 16), zero); err == nil {
		t.Fatal("B = 0 was accepted")
	}
}

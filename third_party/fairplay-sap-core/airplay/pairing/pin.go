// SPDX-License-Identifier: LGPL-3.0-or-later
// Modelled on github.com/omarroth/doubletake's pair-setup/pair-verify. See ../../../NOTICE.md.

package pairing

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/rtsp"
	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/srp"
	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/tlv8"
)

// This file implements PIN-based (persistent) HomeKit pair-setup and the
// pair-verify that follows it. Transient pairing (transient.go) is one SRP
// exchange with a fixed password and yields a session key directly; that is
// what HomePods accept. Apple TVs advertise OneTimePairingRequired and refuse
// it, wanting the full flow here: SRP against a user-entered PIN (M1–M6), an
// Ed25519 long-term key exchanged in M5, then a separate X25519 pair-verify
// that produces the encrypted channel.
//
// Modelled on omarroth/doubletake's working implementation. See ../NOTICE.md.

// HKP pairing types, the value of the X-Apple-HKP header.
//
// The choice is load-bearing and device-specific: issue omarroth/doubletake#30
// found current receivers accept type 5 (screen-capture pairing, with the ACL
// below) only on Apple TVs, while other receiver families want type 3. An Apple
// TV is the reason this PIN path exists, so 5 is the default.
const (
	HKPScreenCapture = 5
	HKPSystemPairing = 3
)

// screenCaptureACL is the OPACK encoding of {"com.apple.ScreenCapture": true}.
// Apple includes this access request in M5 for HKP type 5, and receivers reject
// a type-5 identity that omits it.
const screenCaptureACL = "\xe1\x57com.apple.ScreenCapture\x01"

// Credentials are the long-term identity a PIN pairing establishes. The Ed25519
// key proves who we are during pair-verify; the pairing ID names us. Persist
// these to skip pair-setup on reconnect — pair-verify alone re-establishes a
// channel.
type Credentials struct {
	PairingID      string
	Ed25519Public  ed25519.PublicKey
	Ed25519Private ed25519.PrivateKey
	HKPType        int
}

// NewCredentials mints a fresh identity: a random Ed25519 key and a v4 UUID.
func NewCredentials() (*Credentials, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519: %w", err)
	}
	return &Credentials{
		PairingID:      uuidV4(),
		Ed25519Public:  pub,
		Ed25519Private: priv,
		HKPType:        HKPScreenCapture,
	}, nil
}

func uuidV4() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (cr *Credentials) hkpHeaders() []string {
	return []string{
		fmt.Sprintf("X-Apple-HKP: %d", cr.HKPType),
		"X-Apple-Client-Name: doubletake device",
		"X-Apple-Client-ID: " + cr.PairingID,
	}
}

func hkdf32(secret []byte, salt, info string) []byte {
	r := hkdf.New(sha512.New, secret, []byte(salt), []byte(info))
	key := make([]byte, 32)
	io.ReadFull(r, key)
	return key
}

// aeadSeal / aeadOpen apply ChaCha20-Poly1305 with a HAP nonce: the 8-byte
// label sits in the low bytes of a 12-byte, otherwise-zero nonce.
func aeadSeal(key []byte, label string, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, hapNonce(label), plaintext, nil), nil
}

func aeadOpen(key []byte, label string, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, hapNonce(label), ciphertext, nil)
}

func hapNonce(label string) []byte {
	n := make([]byte, 12)
	copy(n[4:], label)
	return n
}

// PINSetup runs pair-setup M1–M6 with a user-entered PIN, exchanging the
// long-term Ed25519 key. It does not itself yield a usable channel; call Verify
// with the same credentials afterward.
func PINSetup(c *rtsp.Client, pin string, cr *Credentials) error {
	c.UserAgent = transientUserAgent
	hdrs := cr.hkpHeaders()

	// M1 -> M2: open a PIN pair-setup and receive salt + server public key.
	m1 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeMethod, 0),
		tlv8.Byte(tlv8.TypeState, 1),
	)
	resp, err := c.Do("POST", "/pair-setup", "application/octet-stream", m1, hdrs...)
	if err != nil {
		return fmt.Errorf("M1: %w", err)
	}
	if !resp.OK() {
		return fmt.Errorf("M1: receiver said %q", resp.Status)
	}
	m2, err := tlv8.Decode(resp.Body)
	if err != nil {
		return fmt.Errorf("M2: %w", err)
	}
	if code, ok := m2.Err(); ok {
		return fmt.Errorf("M2: receiver returned %s", tlv8.ErrorName(code))
	}
	salt, ok := m2.Get(tlv8.TypeSalt)
	if !ok {
		return fmt.Errorf("M2: no salt")
	}
	serverPub, ok := m2.Get(tlv8.TypePublicKey)
	if !ok {
		return fmt.Errorf("M2: no public key")
	}

	// M3 -> M4: SRP against the PIN.
	client, err := srp.NewClient(srp.Group3072, sha512.New, srpIdentity, []byte(pin))
	if err != nil {
		return err
	}
	proof, err := client.Proof(salt, serverPub)
	if err != nil {
		return fmt.Errorf("M3: %w", err)
	}
	m3 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeState, 3),
		tlv8.Item{Type: tlv8.TypePublicKey, Value: client.PublicKey()},
		tlv8.Item{Type: tlv8.TypeProof, Value: proof},
	)
	resp, err = c.Do("POST", "/pair-setup", "application/octet-stream", m3, hdrs...)
	if err != nil {
		return fmt.Errorf("M3: %w", err)
	}
	if !resp.OK() {
		return fmt.Errorf("M3: receiver said %q", resp.Status)
	}
	m4, err := tlv8.Decode(resp.Body)
	if err != nil {
		return fmt.Errorf("M4: %w", err)
	}
	if code, ok := m4.Err(); ok {
		if code == tlv8.ErrAuthentication {
			return fmt.Errorf("M4: %s — the PIN is wrong", tlv8.ErrorName(code))
		}
		return fmt.Errorf("M4: receiver returned %s", tlv8.ErrorName(code))
	}
	if sp, ok := m4.Get(tlv8.TypeProof); ok {
		if err := client.VerifyServerProof(sp); err != nil {
			return fmt.Errorf("M4: %w", err)
		}
	}

	// M5 -> M6: sign our identity and hand the receiver our long-term key,
	// encrypted under a key derived from the SRP secret.
	K := client.SessionKey()
	encKey := hkdf32(K, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
	sigKey := hkdf32(K, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")

	signed := concat(sigKey, []byte(cr.PairingID), cr.Ed25519Public)
	signature := ed25519.Sign(cr.Ed25519Private, signed)

	sub := []tlv8.Item{
		{Type: tlv8.TypeIdentifier, Value: []byte(cr.PairingID)},
		{Type: tlv8.TypePublicKey, Value: cr.Ed25519Public},
		{Type: tlv8.TypeSignature, Value: signature},
	}
	if cr.HKPType == HKPScreenCapture {
		sub = append(sub, tlv8.Item{Type: tlv8.TypeACL, Value: []byte(screenCaptureACL)})
	}
	encrypted, err := aeadSeal(encKey, "PS-Msg05", tlv8.Encode(sub...))
	if err != nil {
		return fmt.Errorf("M5 seal: %w", err)
	}
	m5 := tlv8.Encode(
		tlv8.Item{Type: tlv8.TypeEncryptedData, Value: encrypted},
		tlv8.Byte(tlv8.TypeState, 5),
	)
	resp, err = c.Do("POST", "/pair-setup", "application/octet-stream", m5, hdrs...)
	if err != nil {
		return fmt.Errorf("M5: %w", err)
	}
	if !resp.OK() {
		return fmt.Errorf("M5: receiver said %q", resp.Status)
	}
	m6, err := tlv8.Decode(resp.Body)
	if err != nil {
		return fmt.Errorf("M6: %w", err)
	}
	if code, ok := m6.Err(); ok {
		return fmt.Errorf("M6: receiver returned %s", tlv8.ErrorName(code))
	}
	return nil
}

// Verify runs pair-verify V1–V4 and returns the shared secret the control
// channel's read/write keys are derived from. Use it with credentials from a
// completed PINSetup, on a fresh connection.
func Verify(c *rtsp.Client, cr *Credentials) ([]byte, error) {
	c.UserAgent = transientUserAgent
	hdrs := append(cr.hkpHeaders(), "X-Apple-PD: 1")

	// V1: our ephemeral X25519 public key.
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	clientPub := priv.PublicKey().Bytes()

	v1 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeState, 1),
		tlv8.Item{Type: tlv8.TypePublicKey, Value: clientPub},
	)
	resp, err := c.Do("POST", "/pair-verify", "application/octet-stream", v1, hdrs...)
	if err != nil {
		return nil, fmt.Errorf("V1: %w", err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("V1: receiver said %q", resp.Status)
	}
	v2, err := tlv8.Decode(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("V2: %w", err)
	}
	if code, ok := v2.Err(); ok {
		return nil, fmt.Errorf("V2: receiver returned %s", tlv8.ErrorName(code))
	}
	serverKey, ok := v2.Get(tlv8.TypePublicKey)
	if !ok || len(serverKey) < 32 {
		return nil, fmt.Errorf("V2: server public key missing or short")
	}
	serverPub, err := curve.NewPublicKey(serverKey[:32])
	if err != nil {
		return nil, fmt.Errorf("V2: bad server public key: %w", err)
	}
	shared, err := priv.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("V2: ECDH: %w", err)
	}

	verifyKey := hkdf32(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")

	// The receiver's encrypted V2 blob authenticates under verifyKey; a failed
	// open means the shared secret is wrong, so check it even though we do not
	// need its contents.
	if enc, ok := v2.Get(tlv8.TypeEncryptedData); ok && len(enc) > 0 {
		if _, err := aeadOpen(verifyKey, "PV-Msg02", enc); err != nil {
			return nil, fmt.Errorf("V2: could not authenticate receiver: %w", err)
		}
	}

	// V3: prove our identity by signing clientPub || pairingID || serverPub.
	signed := concat(clientPub, []byte(cr.PairingID), serverKey[:32])
	signature := ed25519.Sign(cr.Ed25519Private, signed)
	sub := tlv8.Encode(
		tlv8.Item{Type: tlv8.TypeIdentifier, Value: []byte(cr.PairingID)},
		tlv8.Item{Type: tlv8.TypeSignature, Value: signature},
	)
	encrypted, err := aeadSeal(verifyKey, "PV-Msg03", sub)
	if err != nil {
		return nil, fmt.Errorf("V3 seal: %w", err)
	}
	v3 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeState, 3),
		tlv8.Item{Type: tlv8.TypeEncryptedData, Value: encrypted},
	)
	resp, err = c.Do("POST", "/pair-verify", "application/octet-stream", v3, hdrs...)
	if err != nil {
		return nil, fmt.Errorf("V3: %w", err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("V3: receiver said %q", resp.Status)
	}
	if len(resp.Body) > 0 {
		v4, err := tlv8.Decode(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("V4: %w", err)
		}
		if code, ok := v4.Err(); ok {
			return nil, fmt.Errorf("V4: receiver returned %s", tlv8.ErrorName(code))
		}
	}
	return shared, nil
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

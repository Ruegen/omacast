// SPDX-License-Identifier: BlueOak-1.0.0

package pairing

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// HKDF salt/info strings for the control channel. These are protocol
// constants; getting one wrong produces keys that decrypt nothing, with no
// error until the first frame fails to authenticate.
const (
	controlSalt     = "Control-Salt"
	controlWriteKey = "Control-Write-Encryption-Key"
	controlReadKey  = "Control-Read-Encryption-Key"
)

// deriveKey runs HKDF-SHA512 over a shared secret to a 32-byte AEAD key.
func deriveKey(secret []byte, salt, info string) ([]byte, error) {
	r := hkdf.New(sha512.New, secret, []byte(salt), []byte(info))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("pairing: derive %s: %w", info, err)
	}
	return key, nil
}

// Session is the encrypted control channel established by pairing.
//
// Framing, which is the part that has to be exactly right: each frame is a
// 2-byte little-endian plaintext length, then the ChaCha20-Poly1305 ciphertext
// and its 16-byte tag. The length prefix is the AEAD's associated data. Nonces
// are a 64-bit little-endian counter in the last 8 bytes of a 12-byte nonce,
// counted independently in each direction, both starting at zero.
type Session struct {
	rw       io.ReadWriter
	writeKey []byte
	readKey  []byte
	writeCtr uint64
	readCtr  uint64

	pending []byte // decrypted bytes not yet consumed by Read
}

// maxFrame is the largest plaintext a single frame carries.
const maxFrame = 1024

// NewSession derives the read/write keys from a pairing secret and wraps rw.
//
// For transient pairing the secret is SRP's session key K; for a pair-verify
// exchange it would be the X25519 shared secret instead.
func NewSession(rw io.ReadWriter, secret []byte) (*Session, error) {
	wk, err := deriveKey(secret, controlSalt, controlWriteKey)
	if err != nil {
		return nil, err
	}
	rk, err := deriveKey(secret, controlSalt, controlReadKey)
	if err != nil {
		return nil, err
	}
	return &Session{rw: rw, writeKey: wk, readKey: rk}, nil
}

func nonceFor(ctr uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize) // 12; first 4 stay zero
	binary.LittleEndian.PutUint64(n[4:], ctr)
	return n
}

// Write splits p into frames, encrypting each under the next write nonce.
func (s *Session) Write(p []byte) (int, error) {
	aead, err := chacha20poly1305.New(s.writeKey)
	if err != nil {
		return 0, err
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxFrame {
			n = maxFrame
		}
		var lenPrefix [2]byte
		binary.LittleEndian.PutUint16(lenPrefix[:], uint16(n))
		ct := aead.Seal(nil, nonceFor(s.writeCtr), p[:n], lenPrefix[:])
		s.writeCtr++
		if _, err := s.rw.Write(append(lenPrefix[:], ct...)); err != nil {
			return written, fmt.Errorf("pairing: write frame: %w", err)
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Read returns decrypted bytes, pulling and authenticating whole frames as
// needed. A frame that fails authentication is a hard error — returning partial
// data would hand the caller attacker-controlled bytes.
func (s *Session) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		var lenPrefix [2]byte
		if _, err := io.ReadFull(s.rw, lenPrefix[:]); err != nil {
			return 0, err
		}
		n := int(binary.LittleEndian.Uint16(lenPrefix[:]))
		buf := make([]byte, n+chacha20poly1305.Overhead)
		if _, err := io.ReadFull(s.rw, buf); err != nil {
			return 0, fmt.Errorf("pairing: read %d-byte frame: %w", n, err)
		}
		aead, err := chacha20poly1305.New(s.readKey)
		if err != nil {
			return 0, err
		}
		pt, err := aead.Open(nil, nonceFor(s.readCtr), buf, lenPrefix[:])
		if err != nil {
			return 0, fmt.Errorf("pairing: frame %d failed authentication: %w", s.readCtr, err)
		}
		s.readCtr++
		s.pending = pt
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

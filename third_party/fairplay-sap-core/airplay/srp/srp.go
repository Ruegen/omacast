// SPDX-License-Identifier: BlueOak-1.0.0

// Package srp implements the SRP-6a client half of pair-setup.
//
// The group and hash are parameters rather than constants. That is not
// generality for its own sake: it is what lets the algebra be tested against
// RFC 5054's published 1024-bit/SHA-1 vectors while the pairing code runs the
// 3072-bit/SHA-512 parameters HomeKit actually uses. A hand-rolled SRP that has
// only ever been run against the live device cannot be distinguished from a
// protocol misunderstanding when it fails.
package srp

import (
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"
)

// Group is an SRP group: a safe prime and a generator.
type Group struct {
	N *big.Int
	G *big.Int
}

// padLen is the byte width every value is left-padded to, per SRP-6a's PAD().
func (g Group) padLen() int { return (g.N.BitLen() + 7) / 8 }

// pad renders x left-padded with zeros to the group's modulus width.
func (g Group) pad(x *big.Int) []byte {
	b := x.Bytes()
	n := g.padLen()
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// Client holds one SRP-6a client exchange.
type Client struct {
	group    Group
	newHash  func() hash.Hash
	identity []byte
	password []byte

	a *big.Int // private ephemeral
	A *big.Int // public ephemeral

	k   *big.Int
	key []byte // K, the session key
	m1  []byte // our proof
}

// NewClient starts an exchange. The ephemeral secret comes from crypto/rand;
// SetEphemeral overrides it for tests with published vectors.
func NewClient(g Group, h func() hash.Hash, identity, password []byte) (*Client, error) {
	c := &Client{group: g, newHash: h, identity: identity, password: password}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("srp: read entropy: %w", err)
	}
	c.setA(new(big.Int).SetBytes(buf))
	c.k = c.hashInts(c.group.N, c.group.G) // k = H(N | PAD(g))
	return c, nil
}

// SetEphemeral pins the client's private ephemeral. Tests only.
func (c *Client) SetEphemeral(a *big.Int) { c.setA(a) }

func (c *Client) setA(a *big.Int) {
	c.a = a
	c.A = new(big.Int).Exp(c.group.G, a, c.group.N)
}

func (c *Client) hashBytes(parts ...[]byte) []byte {
	h := c.newHash()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// hashInts hashes padded big integers, as PAD() requires.
func (c *Client) hashInts(xs ...*big.Int) *big.Int {
	h := c.newHash()
	for _, x := range xs {
		h.Write(c.group.pad(x))
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// PublicKey returns A, padded to the group width for the wire.
func (c *Client) PublicKey() []byte { return c.group.pad(c.A) }

// X computes the private key x = H(salt | H(identity | ":" | password)).
func (c *Client) X(salt []byte) *big.Int {
	inner := c.hashBytes(c.identity, []byte(":"), c.password)
	return new(big.Int).SetBytes(c.hashBytes(salt, inner))
}

// Proof consumes the server's salt and public key B, derives the session key,
// and returns the client proof M1 to send in pair-setup M3.
func (c *Client) Proof(salt, serverPub []byte) ([]byte, error) {
	B := new(big.Int).SetBytes(serverPub)
	if new(big.Int).Mod(B, c.group.N).Sign() == 0 {
		return nil, fmt.Errorf("srp: server public key is zero mod N — aborting")
	}

	u := c.hashInts(c.A, B)
	if u.Sign() == 0 {
		return nil, fmt.Errorf("srp: u is zero — aborting")
	}
	x := c.X(salt)

	// S = (B - k*g^x) ^ (a + u*x)  mod N
	gx := new(big.Int).Exp(c.group.G, x, c.group.N)
	kgx := new(big.Int).Mul(c.k, gx)
	base := new(big.Int).Sub(B, kgx)
	base.Mod(base, c.group.N) // Mod yields a non-negative result in Go
	exp := new(big.Int).Add(c.a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, c.group.N)

	// Padding is not uniform across SRP-6a, and getting it wrong here fails in
	// the least helpful way possible: every value looks right, the exchange runs
	// to completion, and the receiver simply answers kTLVError_Authentication.
	//
	// PAD() applies only where the spec calls for it — k = H(N | PAD(g)) and
	// u = H(PAD(A) | PAD(B)), both above. The session key and the proof use each
	// value's natural big-endian byte string, so H(g) here hashes the single
	// byte 0x05 rather than 384 bytes of mostly zeros. The wire encoding is a
	// separate question: A is still padded to the group width when sent.
	c.key = c.hashBytes(S.Bytes())

	// M1 = H( H(N) XOR H(g) | H(I) | salt | A | B | K )
	hn := c.hashBytes(c.group.N.Bytes())
	hg := c.hashBytes(c.group.G.Bytes())
	xorNG := make([]byte, len(hn))
	for i := range hn {
		xorNG[i] = hn[i] ^ hg[i]
	}
	c.m1 = c.hashBytes(xorNG, c.hashBytes(c.identity), salt,
		c.A.Bytes(), B.Bytes(), c.key)
	return c.m1, nil
}

// SessionKey returns K. Valid only after Proof.
func (c *Client) SessionKey() []byte { return c.key }

// VerifyServerProof checks the receiver's M2 = H(A | M1 | K). Skipping this
// check is what lets a man in the middle complete the exchange, so callers
// should treat a failure as fatal.
func (c *Client) VerifyServerProof(serverProof []byte) error {
	if c.key == nil {
		return fmt.Errorf("srp: no session key yet")
	}
	want := c.hashBytes(c.A.Bytes(), c.m1, c.key)
	if len(want) != len(serverProof) {
		return fmt.Errorf("srp: server proof is %d bytes, want %d", len(serverProof), len(want))
	}
	var diff byte
	for i := range want {
		diff |= want[i] ^ serverProof[i]
	}
	if diff != 0 {
		return fmt.Errorf("srp: server proof mismatch — wrong password, or not the device we think it is")
	}
	return nil
}

// Verifier computes v = g^x mod N. Only the server needs this; it is here so
// tests can run an independent server side and cross-check the shared secret.
func (c *Client) Verifier(salt []byte) *big.Int {
	return new(big.Int).Exp(c.group.G, c.X(salt), c.group.N)
}

// ServerSecret derives S the *server's* way: S = (A * v^u) ^ b mod N. The
// client and server reach the same S by algebraically different routes, so
// agreement between them is a real check rather than a restatement.
func (c *Client) ServerSecret(v, b *big.Int) *big.Int {
	B := new(big.Int).Mod(new(big.Int).Add(
		new(big.Int).Mul(c.k, v),
		new(big.Int).Exp(c.group.G, b, c.group.N)), c.group.N)
	u := c.hashInts(c.A, B)
	base := new(big.Int).Mod(new(big.Int).Mul(c.A,
		new(big.Int).Exp(v, u, c.group.N)), c.group.N)
	return new(big.Int).Exp(base, b, c.group.N)
}

// ServerPublic computes B = (k*v + g^b) mod N, for the test server side.
func (c *Client) ServerPublic(v, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(
		new(big.Int).Mul(c.k, v),
		new(big.Int).Exp(c.group.G, b, c.group.N)), c.group.N)
}

// K exposes the multiplier k = H(N | PAD(g)), which RFC 5054 publishes for the
// 1024-bit group and which therefore pins the hashing convention.
func (c *Client) K() *big.Int { return c.k }

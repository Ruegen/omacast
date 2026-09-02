// SPDX-License-Identifier: BlueOak-1.0.0

// Package pairing implements the HomeKit-style pair-setup an AirPlay 2 receiver
// requires before it will route /fp-setup.
//
// Only the transient variant is implemented: one SRP-6a exchange, no PIN typed
// by the user, and no long-term key stored anywhere. That is the mode a sender
// uses to stream to a receiver it does not intend to stay paired with, and it
// is what feature bit 48 (SupportsTransientPairing) advertises.
package pairing

import (
	"crypto/sha512"
	"fmt"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/rtsp"
	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/srp"
	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/tlv8"
)

// HKPTransient is the X-Apple-HKP header value that selects transient pairing.
//
// This is the one value that matters, established by isolating it against a
// HomePod (AudioAccessory5,1, fw 23L471) on 2026-08-06:
//
//	HKP: 4, /pair-pin-start called    -> pair-setup succeeds
//	HKP: 4, /pair-pin-start skipped   -> pair-setup succeeds
//	HKP: 3, /pair-pin-start called    -> M4 kTLVError_Authentication
//	HKP: 3, /pair-pin-start skipped   -> M4 kTLVError_Authentication
//
// So 4 is necessary and sufficient. With 3 the receiver still returns a
// well-formed M2 and only refuses at M4, which is what makes the wrong value
// look plausible for a while.
const HKPTransient = "X-Apple-HKP: 4"

// transientUserAgent matches what a real sender advertises. Receivers are not
// known to gate on it, but there is no reason to look unusual.
const transientUserAgent = "AirPlay/320.20"

// ETHeader selects FairPlay SAP v3 on /fp-setup, and is required.
//
// Without it a receiver answers with a v2.5 record (version byte 0x02) and then
// refuses every m3 — correct or deliberately corrupted alike — with 403. With
// it the same receiver offers version byte 0x03, which is what this project
// implements, and accepts a correct response. The header is what selects the
// encryption type, so the version difference is a consequence of asking rather
// than a property of the device.
const ETHeader = "X-Apple-ET: 32"

// SRP parameters for pair-setup. The identity is fixed by the protocol; the
// password is the well-known transient PIN, which exists so the SRP exchange
// has a password at all rather than to authenticate a human.
var (
	srpIdentity = []byte("Pair-Setup")
	srpPassword = []byte("3939")
)

// Result carries what a completed pair-setup yields.
type Result struct {
	// SessionKey is SRP's K. For transient pairing this is the secret the
	// control-channel keys are derived from.
	SessionKey []byte
}

// Transient runs pair-setup M1..M4 over an existing connection and returns the
// SRP session key.
//
// The password is a parameter because the transient PIN is the least certain
// constant here: sources disagree on whether transient pairing uses a fixed
// "3939" or an empty password, so a caller that hits an authentication error
// can retry with the alternative rather than being stuck.
func Transient(c *rtsp.Client, password []byte) (*Result, error) {
	if password == nil {
		password = srpPassword
	}

	c.UserAgent = transientUserAgent

	// Kept because a real sender does it, NOT because it is required: pairing
	// succeeds without it on every HomePod tested (see HKPTransient above).
	// An earlier revision claimed this call was essential. That was a
	// confounded-variable error — it was added in the same change that fixed
	// the X-Apple-HKP value, and both were credited. Only the header mattered.
	// Retained on the chance a PIN-requiring receiver needs the window opened;
	// that is untested, and one extra round trip is a cheap hedge.
	if _, err := c.Do("POST", "/pair-pin-start", "application/octet-stream", nil, HKPTransient); err != nil {
		return nil, fmt.Errorf("pair-pin-start: %w", err)
	}

	// --- M1: announce a transient pair-setup ---
	//
	// Field order and the Flags encoding both follow what a working sender
	// emits: Method, then State, then Flags as a *single big-endian byte*.
	// A four-byte little-endian Flags is accepted at M1 and still fails at M4.
	m1 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeMethod, 0),
		tlv8.Byte(tlv8.TypeState, 1),
		tlv8.Byte(tlv8.TypeFlags, byte(tlv8.FlagTransient)),
	)
	resp, err := c.Do("POST", "/pair-setup", "application/octet-stream", m1, HKPTransient)
	if err != nil {
		return nil, fmt.Errorf("pair-setup M1: %w", err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("pair-setup M1: receiver said %q "+
			"(470 usually means /pair-pin-start was not called first)", resp.Status)
	}
	m2, err := tlv8.Decode(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("pair-setup M2: %w", err)
	}
	if code, ok := m2.Err(); ok {
		return nil, fmt.Errorf("pair-setup M2: receiver returned %s", tlv8.ErrorName(code))
	}
	salt, ok := m2.Get(tlv8.TypeSalt)
	if !ok {
		return nil, fmt.Errorf("pair-setup M2: no salt")
	}
	serverPub, ok := m2.Get(tlv8.TypePublicKey)
	if !ok {
		return nil, fmt.Errorf("pair-setup M2: no public key")
	}

	// --- M3: our public key and proof ---
	client, err := srp.NewClient(srp.Group3072, sha512.New, srpIdentity, password)
	if err != nil {
		return nil, err
	}
	proof, err := client.Proof(salt, serverPub)
	if err != nil {
		return nil, fmt.Errorf("pair-setup M3: %w", err)
	}
	m3 := tlv8.Encode(
		tlv8.Byte(tlv8.TypeState, 3),
		tlv8.Item{Type: tlv8.TypePublicKey, Value: client.PublicKey()},
		tlv8.Item{Type: tlv8.TypeProof, Value: proof},
	)
	resp, err = c.Do("POST", "/pair-setup", "application/octet-stream", m3, HKPTransient)
	if err != nil {
		return nil, fmt.Errorf("pair-setup M3: %w", err)
	}
	if !resp.OK() {
		return nil, fmt.Errorf("pair-setup M3: receiver said %q", resp.Status)
	}
	m4, err := tlv8.Decode(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("pair-setup M4: %w", err)
	}
	if code, ok := m4.Err(); ok {
		if code == tlv8.ErrAuthentication {
			return nil, fmt.Errorf("pair-setup M4: %s — the SRP password is wrong "+
				"(tried %q; the other candidate is an empty password)",
				tlv8.ErrorName(code), password)
		}
		return nil, fmt.Errorf("pair-setup M4: receiver returned %s", tlv8.ErrorName(code))
	}

	// Verify the receiver's proof. Skipping this would mean accepting a session
	// key from anything that answered, which is the whole attack SRP prevents.
	serverProof, ok := m4.Get(tlv8.TypeProof)
	if !ok {
		return nil, fmt.Errorf("pair-setup M4: no proof from receiver")
	}
	if err := client.VerifyServerProof(serverProof); err != nil {
		return nil, fmt.Errorf("pair-setup M4: %w", err)
	}

	return &Result{SessionKey: client.SessionKey()}, nil
}

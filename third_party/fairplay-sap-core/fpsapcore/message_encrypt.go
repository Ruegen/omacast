// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import "encoding/hex"

// Forward AES for the m3 message body.
//
// An m3 carries the sender's local SAP encrypted in bytes 16..144, in CBC over
// eight 16-byte blocks. The cipher is AES-128 in shape but not in key schedule:
// the round keys are Apple's, baked per FairPlay message mode, and there is no
// key to derive them from. Only mode 3's schedule is here, because Phase 1's
// white-box tables implement mode 3 alone -- see fpbridge.SupportedFPSAPMode.
//
// Provenance: these round keys are Apple-derived data, transcribed from
// omarroth/doubletake's internal/airplay/fairplay_message.go (LGPL-3.0) at
// main @ 8ccea5f, the same source NOTICE.md already records this package as
// deriving from. They are extracted constants, not an independent derivation.
//
// EncryptMessageBodyMode3 is checked against the one ciphertext we already
// hold: encrypting the frozen session's localSAP must reproduce fpbridge's
// m3Prefix[16:144] byte for byte. See TestEncryptReproducesFrozenPrefix.
var (
	msgIVMode3         = mustHex("27078b2123361e7adc9d0b115354690d")
	msgRoundKey0       = mustHex("d30dfdb563def72b012ead72884dca25")
	msgRoundKey10      = mustHex("cd5ecf47e9af289b51188f68d085eb69")
	msgMiddleKeysMode3 = mustHex("f6a223b4f01d8a7927a7c965de554de00cd1515d43246c87fc2f494364a4cfbcd66e3bdd6c7f1b811f90291984b5eaee530d7ae85b3040569f13130f18fbb1e50784c47a9fe10f3d5ea5432ecdd9f585b9b0368eb7d134d90ebd1b94b255a4fbb2a4352534066fdec1ce38db3d8c3b850b317a942520622d89578e9fe5a13fc3bdf569e6befc1d2fc08baf733f1d176a") // 9 rounds x 16 bytes
	forwardAESSBox     = mustHex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("fpsapcore: bad table literal: " + err.Error())
	}
	return b
}

// EncryptMessageBodyMode3 encrypts a 128-byte SAP body for an m3 under mode 3.
// CBC, eight blocks, chaining from the mode's fixed IV.
func EncryptMessageBodyMode3(plaintext [128]byte) (out [128]byte) {
	chain := msgIVMode3
	for block := 0; block < 8; block++ {
		start := block * 16
		var state [16]byte
		for i := range state {
			state[i] = plaintext[start+i] ^ chain[i]
		}
		encryptMessageBlockMode3(&state)
		copy(out[start:start+16], state[:])
		chain = out[start : start+16]
	}
	return out
}

func encryptMessageBlockMode3(state *[16]byte) {
	xorRoundKey(state, msgRoundKey0)
	subBytes(state)
	shiftRows(state)
	for round := 0; round < 9; round++ {
		mixColumns(state)
		xorRoundKey(state, msgMiddleKeysMode3[round*16:round*16+16])
		subBytes(state)
		shiftRows(state)
	}
	xorRoundKey(state, msgRoundKey10)
}

func xorRoundKey(state *[16]byte, key []byte) {
	for i := range state {
		state[i] ^= key[i]
	}
}

func subBytes(state *[16]byte) {
	for i := range state {
		state[i] = forwardAESSBox[state[i]]
	}
}

func shiftRows(state *[16]byte) {
	previous := *state
	for row := 0; row < 4; row++ {
		for column := 0; column < 4; column++ {
			state[4*column+row] = previous[4*((column+row)&3)+row]
		}
	}
}

// Forward MixColumns needs only the multipliers 2 and 3, so both become 256-byte
// tables -- built by gfMul itself, so the definition of the field arithmetic
// does not move and no new constants enter the source. gfMul walks the
// multiplier bit by bit and is called sixteen times per column otherwise, which
// dominated the m3 body encryption. This is the same change offered upstream as
// upstream-doubletake/patches/0001.
var gfMul2, gfMul3 = func() (t2, t3 [256]byte) {
	for v := 0; v < 256; v++ {
		t2[v] = gfMul(byte(v), 2)
		t3[v] = gfMul(byte(v), 3)
	}
	return
}()

func mixColumns(state *[16]byte) {
	for column := 0; column < 4; column++ {
		o := column * 4
		a, b, c, d := state[o], state[o+1], state[o+2], state[o+3]
		state[o] = gfMul2[a] ^ gfMul3[b] ^ c ^ d
		state[o+1] = a ^ gfMul2[b] ^ gfMul3[c] ^ d
		state[o+2] = a ^ b ^ gfMul2[c] ^ gfMul3[d]
		state[o+3] = gfMul3[a] ^ b ^ c ^ gfMul2[d]
	}
}

func gfMul(a, b byte) byte {
	var product byte
	for b != 0 {
		if b&1 != 0 {
			product ^= a
		}
		high := a & 0x80
		a <<= 1
		if high != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return product
}

// FrozenLocalSAP returns the plaintext local SAP of the captured session that
// fpbridge's m3Prefix encodes. Exported so the framing layer can check its
// constant prefix against this package's encryption.
func FrozenLocalSAP() [128]byte { return localSAP }

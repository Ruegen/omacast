// SPDX-License-Identifier: BlueOak-1.0.0

// Package fpbridge is a self-contained, fully algorithmic implementation of the
// FairPlay SAP handshake: it computes the 20-byte m3 response from the 128-byte
// m2 challenge with no Apple blob, no build tags, and no transliterated code.
//
// The pipeline is:
//
//	Phase 1  wbaesFullPhase1   White-Box AES T-boxes -> the 128-byte GP buffer
//	Bridge   bridgeX9DataClosed  closed-form descriptor -> x9Data
//	Phase 2  fairplayhash      analytical White-Box MD5 -> the 20-byte response
//
// The bridge step used to be an 18.8 MB re-rolled transliteration of Apple's ARM64
// code replayed against a baked memory image. It is now computed: every
// payload-dependent value in it is a function of one contiguous slice of the GP
// buffer, and the slices are gp[0:47], gp[47:111] and gp[111:128]. See
// fp_bridge_native.go for the structure, and the docs/ directory for
// how it was recovered.
//
// Provenance: reverse-engineered from Apple's FairPlay SAP; defensive
// interoperability research (an authentication handshake, not DRM / content
// keys). It does not extract content keys and is not FairPlay Streaming DRM.
package fpbridge

// FairPlay SAP M1/M3 C ABI for omacast.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
// The handshake algorithm is vendored from
// github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake
// (LGPL-3.0-or-later). See ../fairplay-sap-core/LICENSE and NOTICE.md.
package main

import "C"

import (
	"crypto/rand"
	"unsafe"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpbridge"
)

//export fpsap_m1
func fpsap_m1(out *C.uchar, cap C.int) C.int {
	m1 := fpbridge.NewFPSAPM1(fpbridge.FPSAPFullCapabilities)
	if int(cap) < len(m1) {
		return -1
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(cap))
	copy(dst, m1)
	return C.int(len(m1))
}

//export fpsap_exchange_m3
func fpsap_exchange_m3(m2 *C.uchar, m2len C.int, out *C.uchar, cap C.int) C.int {
	if m2len <= 0 || m2 == nil {
		return -1
	}
	in := C.GoBytes(unsafe.Pointer(m2), m2len)
	sess, err := fpbridge.NewFPSAPSession(rand.Reader)
	if err != nil {
		return -2
	}
	m3, err := sess.ExchangeM3(in)
	if err != nil {
		return -3
	}
	if int(cap) < len(m3) {
		return -1
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(cap))
	copy(dst, m3)
	return C.int(len(m3))
}

func main() {}

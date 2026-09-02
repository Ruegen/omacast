// SPDX-License-Identifier: LGPL-3.0-or-later
package fpbridge

import "encoding/binary"

// FPSAPFullCapabilities is the m1 capability byte Apple's sender advertises when
// nothing is unavailable.
//
// It is a **bit mask, not a mode**. The distinction matters because both are
// small integers that reach 3, and confusing them is easy: the sender puts its
// capabilities in m1, and the *receiver* then selects a message mode 0..3 in
// byte 13 of m2. Advertising 3 does not request mode 3.
const FPSAPFullCapabilities = byte(3)

// NewFPSAPM1 builds the 16-byte m1 record that opens a FairPlay SAP exchange.
//
// # Why this matters for mode selection, and what it cannot do
//
// This package answers mode 3 only (see SupportedFPSAPMode), and the mode is
// chosen by the receiver, not by us — so an exchange can fail at m2 through no
// fault of the caller's. The capability mask is the only lever a sender has on
// that choice, which is why this constructor takes it rather than hardcoding it.
//
// Be clear about the limit of that lever: **whether clearing capability bits
// reliably steers a receiver to mode 3 is not established here.** We have no
// hardware, the mapping from capability bits to selected mode is not documented
// anywhere we have found, and every exchange this project has ever observed used
// mode 3. Passing FPSAPFullCapabilities reproduces what Apple's sender does with
// a full feature set, which is the behaviour most likely to be accepted; if a
// receiver then selects another mode, ExchangeM3 returns an error naming it
// rather than answering with the wrong key schedule.
//
// If you find a receiver that selects anything other than mode 3, that is worth
// reporting — it would be the first evidence that supporting the other three is
// worth the Apple-derived key schedules it would cost.
func NewFPSAPM1(capabilities byte) []byte {
	m1 := make([]byte, 16)
	copy(m1[:4], "FPLY")
	copy(m1[4:8], []byte{3, 1, 1, 0})
	binary.BigEndian.PutUint32(m1[8:12], 4)
	copy(m1[12:], []byte{0x02, 0x00, capabilities, 0xbb})
	return m1
}

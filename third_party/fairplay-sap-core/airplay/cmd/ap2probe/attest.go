// SPDX-License-Identifier: BlueOak-1.0.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/pairing"
	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpbridge"
)

// cmdAttest records vectors that a real receiver has confirmed.
//
// Every existing golden vector in this project came from archived emulator
// captures — they say "this is what Apple's code computed". A validating
// receiver says something strictly stronger: "this is the answer I accept".
// That is an oracle no emulator provides, and it is only available now that
// pairing works.
//
// Each row is replayable offline. The 20-byte response depends on both the
// challenge and the session's local SAP, so all three are recorded; feeding the
// stored SAP back through NewFPSAPSession reproduces the exchange exactly, with
// no device and no network.
func cmdAttest(args []string) error {
	count := 8
	out := ""
	target := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--count":
			if i+1 >= len(args) {
				return fmt.Errorf("--count needs a value")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 || n > 200 {
				return fmt.Errorf("--count must be 1..200, got %q", args[i+1])
			}
			count = n
			i++
		case "--out":
			if i+1 >= len(args) {
				return fmt.Errorf("--out needs a path")
			}
			out = args[i+1]
			i++
		default:
			if target != "" {
				return fmt.Errorf("unexpected argument %q", args[i])
			}
			target = args[i]
		}
	}
	if target == "" {
		return fmt.Errorf("need a <host:port>")
	}
	t, err := needTarget([]string{target})
	if err != nil {
		return err
	}

	var rows [][4]string
	accepted, rejected := 0, 0
	for i := 0; i < count; i++ {
		c, _, err := pairTo(t)
		if err != nil {
			return fmt.Errorf("exchange %d: pair: %w", i+1, err)
		}

		m1 := fpbridge.NewFPSAPM1(fpbridge.FPSAPFullCapabilities)
		resp, err := c.Do("POST", "/fp-setup", "application/octet-stream", m1,
			pairing.ETHeader)
		if err != nil || !resp.OK() || len(resp.Body) != 142 {
			c.Close()
			return fmt.Errorf("exchange %d: m1: %v (status %v)", i+1, err, resp)
		}
		m2 := resp.Body

		// Draw the local SAP from crypto/rand exactly as a real sender would,
		// then keep the bytes so the exchange can be replayed without a device.
		sapEntropy := make([]byte, 126)
		if _, err := rand.Read(sapEntropy); err != nil {
			c.Close()
			return err
		}
		sess, err := fpbridge.NewFPSAPSession(bytes.NewReader(sapEntropy))
		if err != nil {
			c.Close()
			return err
		}
		m3, err := sess.ExchangeM3(m2)
		if err != nil {
			c.Close()
			return fmt.Errorf("exchange %d: compute m3: %w", i+1, err)
		}

		resp2, err := c.Do("POST", "/fp-setup", "application/octet-stream", m3,
			pairing.ETHeader)
		c.Close()
		if err != nil {
			return fmt.Errorf("exchange %d: m3: %w", i+1, err)
		}

		verdict := "rejected"
		if resp2.OK() {
			verdict = "accepted"
			accepted++
		} else {
			rejected++
		}
		localSAP := sess.LocalSAP()
		rows = append(rows, [4]string{
			hex.EncodeToString(m2[14:142]),  // the receiver's 128-byte challenge
			hex.EncodeToString(localSAP[:]), // our per-session local SAP
			hex.EncodeToString(m3[144:164]), // the 20-byte response it judged
			verdict,
		})
		fmt.Printf("  %2d/%d  challenge %s…  -> %s\n",
			i+1, count, hex.EncodeToString(m2[14:22]), verdict)
	}

	fmt.Printf("\n%d accepted, %d rejected\n", accepted, rejected)
	if rejected > 0 {
		return fmt.Errorf("%d exchange(s) were rejected — do not publish these as attested", rejected)
	}

	var buf bytes.Buffer
	buf.WriteString("challenge_hex,local_sap_hex,response_hex,verdict\n")
	for _, r := range rows {
		fmt.Fprintf(&buf, "%s,%s,%s,%s\n", r[0], r[1], r[2], r[3])
	}
	if out == "" {
		os.Stdout.Write(buf.Bytes())
		return nil
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d attested vectors to %s\n", len(rows), out)
	return nil
}

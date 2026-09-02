// SPDX-License-Identifier: BlueOak-1.0.0

// Command ap2probe drives a real AirPlay 2 receiver: transient pair-setup,
// then the FairPlay SAP handshake through the resulting channel.
//
// It exists to answer one question the core module cannot answer about itself —
// whether a real receiver accepts the 20-byte response this project computes.
// The `control` subcommand is the part that makes that answer worth anything:
// it sends deliberately wrong responses and checks they are refused. A receiver
// that accepts a wrong answer cannot confirm a right one.
package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/pairing"
	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay/rtsp"
	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpbridge"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	args = extractPIN(args)

	var err error
	switch cmd {
	case "info":
		err = cmdInfo(args)
	case "pair":
		err = cmdPair(args)
	case "fp-setup":
		err = cmdFPSetup(args, false)
	case "control":
		err = cmdControl(args)
	case "attest":
		err = cmdAttest(args)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "ap2probe: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ap2probe %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `ap2probe — drive a real AirPlay 2 receiver's pairing and FairPlay handshake

Usage:
  ap2probe info     <host:port>   fetch /info and report the FairPlay-relevant bits
  ap2probe pair     <host:port>   transient pair-setup only; report the derived key
  ap2probe fp-setup <host:port>   pair, then run one FairPlay SAP exchange
  ap2probe control  <host:port>   pair, then send a correct AND two corrupted
                                  responses — the test that proves the receiver
                                  actually validates
  ap2probe attest   <host:port>   record vectors a real receiver confirmed
                                  [--count N] [--out file.csv]

Flags:
  --pin <code>   use PIN-based pairing (Apple TVs). Read the code off the screen.
                 Without it, transient pairing is used (HomePods).

This talks to devices on your network. The core fpsap module does not; all
network code lives in this separate module.
`)
}

// extractPIN pulls a "--pin <code>" pair out of args and sets pinCode, leaving
// the rest for the per-command parser. A global flag is simpler than threading
// it through every subcommand, and pairing is the only thing that reads it.
func extractPIN(args []string) []string {
	out := args[:0:0]
	for i := 0; i < len(args); i++ {
		if args[i] == "--pin" && i+1 < len(args) {
			pinCode = args[i+1]
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func needTarget(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("need exactly one <host:port>")
	}
	t := args[0]
	if !strings.Contains(t, ":") {
		t += ":7000"
	}
	return t, nil
}

func cmdInfo(args []string) error {
	target, err := needTarget(args)
	if err != nil {
		return err
	}
	c, err := rtsp.Dial(target)
	if err != nil {
		return err
	}
	defer c.Close()

	resp, err := c.Do("GET", "/info", "", nil)
	if err != nil {
		return err
	}
	fmt.Printf("%s  (%d bytes)\n", resp.Status, len(resp.Body))
	if len(resp.Body) > 0 {
		fmt.Printf("body[0:64] = %x\n", resp.Body[:min(64, len(resp.Body))])
	}
	return nil
}

// pairPassword is the SRP password used for transient pair-setup. Which value
// a receiver expects is the least-documented part of this protocol, so it is
// overridable with AP2_PASSWORD rather than compiled in.
func pairPassword() []byte {
	if v, ok := os.LookupEnv("AP2_PASSWORD"); ok {
		return []byte(v)
	}
	return nil // package default
}

// pinCode is set by --pin. When present, pairing uses the PIN-based path
// (pair-setup M1–M6 + pair-verify) instead of transient. HomePods take
// transient; Apple TVs require a PIN read off the screen.
var pinCode string

// pairTo opens a connection, pairs, and switches the connection over to the
// encrypted control channel.
//
// The switch is not optional. Once pairing completes the receiver expects every
// subsequent byte to be a ChaCha20-Poly1305 frame; sending a plaintext request
// instead gets the connection reset rather than an error response.
func pairTo(target string) (*rtsp.Client, *pairing.Result, error) {
	c, err := rtsp.Dial(target)
	if err != nil {
		return nil, nil, err
	}

	var secret []byte
	if pinCode != "" {
		cr, err := pairing.NewCredentials()
		if err != nil {
			c.Close()
			return nil, nil, err
		}
		if err := pairing.PINSetup(c, pinCode, cr); err != nil {
			c.Close()
			return nil, nil, fmt.Errorf("pair-setup: %w", err)
		}
		// pair-verify runs on the same still-plaintext connection and yields the
		// X25519 secret the channel keys come from.
		secret, err = pairing.Verify(c, cr)
		if err != nil {
			c.Close()
			return nil, nil, fmt.Errorf("pair-verify: %w", err)
		}
	} else {
		res, err := pairing.Transient(c, pairPassword())
		if err != nil {
			c.Close()
			return nil, nil, err
		}
		secret = res.SessionKey
	}

	sess, err := pairing.NewSession(c.Conn(), secret)
	if err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("derive control keys: %w", err)
	}
	c.UseStream(sess)
	return c, &pairing.Result{SessionKey: secret}, nil
}

func cmdPair(args []string) error {
	target, err := needTarget(args)
	if err != nil {
		return err
	}
	c, res, err := pairTo(target)
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Printf("pair-setup OK — SRP session key %d bytes: %x...\n",
		len(res.SessionKey), res.SessionKey[:min(16, len(res.SessionKey))])
	return nil
}

// exchange runs one FairPlay SAP handshake over an established session and
// reports whether the receiver accepted the m3. corrupt, if non-nil, mutates
// the m3 before it is sent.
func exchange(c *rtsp.Client, corrupt func([]byte), label string) (bool, error) {
	m1 := fpbridge.NewFPSAPM1(fpbridge.FPSAPFullCapabilities)
	resp, err := c.Do("POST", "/fp-setup", "application/octet-stream", m1, pairing.ETHeader)
	if err != nil {
		return false, fmt.Errorf("fp-setup m1: %w", err)
	}
	if !resp.OK() {
		return false, fmt.Errorf("fp-setup m1: receiver said %q", resp.Status)
	}
	m2 := resp.Body
	fmt.Printf("  <-- m2 %d bytes", len(m2))
	if len(m2) >= 14 {
		fmt.Printf("  magic=%q mode=%d", string(m2[:4]), m2[13])
	}
	fmt.Println()

	// With ETHeader set the receiver frames its records as v3, so the m2 goes
	// straight into the core parser with no translation.
	if _, err := fpbridge.ParseFPSAPM2(m2); err != nil {
		return false, fmt.Errorf("m2 rejected by ParseFPSAPM2: %w", err)
	}
	sess, err := fpbridge.NewFPSAPSession(rand.Reader)
	if err != nil {
		return false, err
	}
	m3, err := sess.ExchangeM3(m2)
	if err != nil {
		return false, fmt.Errorf("compute m3: %w", err)
	}
	if corrupt != nil {
		corrupt(m3)
	}
	resp, err = c.Do("POST", "/fp-setup", "application/octet-stream", m3, pairing.ETHeader)
	if err != nil {
		return false, fmt.Errorf("fp-setup m3: %w", err)
	}
	fmt.Printf("  [%s] --> m3 %d bytes   <-- %s (%d-byte body)\n",
		label, len(m3), resp.Status, len(resp.Body))
	return resp.OK(), nil
}

func cmdFPSetup(args []string, quiet bool) error {
	target, err := needTarget(args)
	if err != nil {
		return err
	}
	c, _, err := pairTo(target)
	if err != nil {
		return err
	}
	defer c.Close()
	ok, err := exchange(c, nil, "correct")
	if err != nil {
		return err
	}
	fmt.Printf("RESULT: receiver %s the m3\n", accepted(ok))
	return nil
}

// cmdControl is the point of this tool. It runs three exchanges — one correct,
// two deliberately wrong — and interprets the pattern. The verdict is decided
// by whether the receiver *discriminates*, not by whether it said yes.
func cmdControl(args []string) error {
	target, err := needTarget(args)
	if err != nil {
		return err
	}

	type trial struct {
		label   string
		corrupt func([]byte)
	}
	trials := []trial{
		{"correct", nil},
		{"flipped-last-byte", func(m3 []byte) { m3[len(m3)-1] ^= 0xff }},
		{"zeroed-response", func(m3 []byte) {
			for i := 144; i < len(m3); i++ {
				m3[i] = 0
			}
		}},
	}

	results := map[string]outcome{}
	for _, tr := range trials {
		// A fresh connection per trial: pairing state and any FairPlay state
		// live on the connection, so reusing one would let trial N's outcome
		// depend on trial N-1.
		c, _, err := pairTo(target)
		if err != nil {
			fmt.Printf("  [%s] pair failed: %v\n", tr.label, err)
			results[tr.label] = outcomeErrored
			continue
		}
		ok, err := exchange(c, tr.corrupt, tr.label)
		c.Close()
		switch {
		case err != nil:
			// Explicitly NOT a rejection. We do not know what the receiver
			// would have said, so the run is incomplete rather than negative.
			fmt.Printf("  [%s] error: %v\n", tr.label, err)
			results[tr.label] = outcomeErrored
		case ok:
			results[tr.label] = outcomeAccepted
		default:
			results[tr.label] = outcomeRejected
		}
	}

	fmt.Println("\n--- verdict ---")
	for _, tr := range trials {
		fmt.Printf("  %-20s %s\n", tr.label, results[tr.label])
	}
	text, proven := verdict(
		results["correct"], results["flipped-last-byte"], results["zeroed-response"])
	fmt.Printf("\n%s\n", text)
	if !proven {
		return errNotProven
	}
	return nil
}

func accepted(ok bool) string {
	if ok {
		return "ACCEPTED"
	}
	return "rejected"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

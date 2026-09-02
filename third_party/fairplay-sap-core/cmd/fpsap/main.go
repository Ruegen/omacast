// SPDX-License-Identifier: LGPL-3.0-or-later

// Command fpsap is a small, network-free tool for driving the FairPlay SAP
// authentication handshake an AirPlay 2 sender performs. It is hex-in/hex-out:
// it computes bytes, it does not speak RTSP and it never talks to a device.
//
// The one command that makes a release binary self-proving is `fpsap verify`,
// which runs the 142 golden vectors bundled into the binary and prints 142/142.
//
// Only FairPlay message mode 3 is answerable here; see the fpbridge package for
// why. Any m2 selecting another mode is refused, naming the mode.
package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpbridge"
)

// Build metadata, overridable at link time:
//
//	go build -ldflags "-X main.version=v1.0.0 -X main.commit=$(git rev-parse --short HEAD)"
var (
	version = "dev"
	commit  = "none"
)

//go:embed golden_vectors.csv
var goldenVectors []byte

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "exchange":
		err = cmdExchange(args)
	case "m1":
		err = cmdM1(args)
	case "m3":
		err = cmdM3(args)
	case "verify":
		err = cmdVerify(args)
	case "version", "--version", "-v":
		cmdVersion()
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "fpsap: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "fpsap %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `fpsap — FairPlay SAP authentication handshake, hex-in/hex-out (no network)

Usage:
  fpsap exchange              128-byte payload hex on stdin -> 20-byte response hex
  fpsap m1 [--capabilities N] emit a 16-byte m1 record hex (default capabilities 3)
  fpsap m3 [--frozen]         142-byte m2 hex on stdin -> 164-byte m3 hex
                              (session-aware by default; --frozen replays a captured SAP)
  fpsap verify                run the 142 bundled golden vectors, print 142/142
  fpsap version               version, commit, and the mode-3-only statement

This tool computes bytes only. It does not speak RTSP and does not talk to
devices. Only FairPlay message mode 3 is answerable; any other mode is refused.
`)
}

// readHexStdin reads all of stdin, strips whitespace, and hex-decodes it. A
// caller who pastes a payload with newlines still gets a clean decode.
func readHexStdin() ([]byte, error) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, string(raw))
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("input is not valid hex: %w", err)
	}
	return b, nil
}

func cmdExchange(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("takes no arguments; payload hex comes on stdin")
	}
	b, err := readHexStdin()
	if err != nil {
		return err
	}
	if len(b) != 128 {
		return fmt.Errorf("payload is %d bytes, want 128", len(b))
	}
	var payload [128]byte
	copy(payload[:], b)
	resp := fpbridge.FPExchangeBlobless(payload)
	fmt.Println(hex.EncodeToString(resp[:]))
	return nil
}

func cmdM1(args []string) error {
	capabilities := fpbridge.FPSAPFullCapabilities
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--capabilities":
			if i+1 >= len(args) {
				return fmt.Errorf("--capabilities needs a value 0..255")
			}
			var n int
			if _, err := fmt.Sscanf(args[i+1], "%d", &n); err != nil || n < 0 || n > 255 {
				return fmt.Errorf("--capabilities must be an integer 0..255, got %q", args[i+1])
			}
			capabilities = byte(n)
			i++
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	m1 := fpbridge.NewFPSAPM1(capabilities)
	fmt.Println(hex.EncodeToString(m1))
	return nil
}

func cmdM3(args []string) error {
	frozen := false
	for _, a := range args {
		switch a {
		case "--frozen":
			frozen = true
		default:
			return fmt.Errorf("unknown flag %q", a)
		}
	}
	m2, err := readHexStdin()
	if err != nil {
		return err
	}

	var m3 []byte
	if frozen {
		// The replay path: a captured local SAP, identical every time. Works
		// only against permissive mode-3 receivers.
		m3, err = fpbridge.FPSAPExchangeM3(m2)
	} else {
		// Session-aware default: a fresh local SAP drawn from crypto entropy,
		// so no two invocations emit the same frame.
		var session *fpbridge.FPSAPSession
		session, err = fpbridge.NewFPSAPSession(rand.Reader)
		if err != nil {
			return err
		}
		m3, err = session.ExchangeM3(m2)
	}
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(m3))
	return nil
}

func cmdVerify(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("takes no arguments")
	}
	rows, err := csv.NewReader(strings.NewReader(string(goldenVectors))).ReadAll()
	if err != nil {
		return fmt.Errorf("read bundled vectors: %w", err)
	}
	if len(rows) < 2 {
		return fmt.Errorf("bundled vectors are empty")
	}

	pass, fail := 0, 0
	for _, rec := range rows[1:] {
		if len(rec) < 4 {
			continue
		}
		category, payloadHex, wantHex := rec[0], rec[2], rec[3]
		pb, err := hex.DecodeString(payloadHex)
		if err != nil || len(pb) != 128 {
			return fmt.Errorf("%s: malformed payload in bundled vectors", category)
		}
		want, err := hex.DecodeString(wantHex)
		if err != nil || len(want) != 20 {
			return fmt.Errorf("%s: malformed hash in bundled vectors", category)
		}
		var payload [128]byte
		copy(payload[:], pb)

		got := fpbridge.FPExchangeBlobless(payload)
		if string(got[:]) == string(want) {
			pass++
			continue
		}
		fail++
		if fail <= 3 {
			fmt.Fprintf(os.Stderr, "MISMATCH %s: got %x, want %x\n", category, got, want)
		}
	}

	total := pass + fail
	if fail != 0 {
		fmt.Printf("%d/%d\n", pass, total)
		return fmt.Errorf("%d vector(s) FAILED", fail)
	}
	if pass == 0 {
		return fmt.Errorf("no vectors executed")
	}
	fmt.Printf("%d/%d\n", pass, total)
	return nil
}

func cmdVersion() {
	fmt.Printf("fpsap %s (commit %s)\n", version, commit)
	fmt.Printf("FairPlay SAP authentication handshake for AirPlay 2 senders.\n")
	fmt.Printf("Answers FairPlay message mode %d only; no content is decrypted and no keys are extracted.\n",
		fpbridge.SupportedFPSAPMode)
}

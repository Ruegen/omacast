// SPDX-License-Identifier: BlueOak-1.0.0

package rtsp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// serve runs a one-shot fake receiver that replies with raw, giving tests a
// device that can misbehave in ways a real one might.
func serve(t *testing.T, raw string) (addr string, gotRequest chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gotRequest = make(chan string, 1)
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var req strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			req.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		gotRequest <- req.String()
		conn.Write([]byte(raw))
	}()
	return ln.Addr().String(), gotRequest
}

func dialTest(t *testing.T, addr string) *Client {
	t.Helper()
	c, err := Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Timeout = 3 * time.Second
	return c
}

// TestHostileContentLengthIsRefused is the reason this file exists.
//
// The body was allocated as make([]byte, clen) straight from the header, so a
// receiver claiming a multi-gigabyte body — whether hostile or merely broken —
// got this process to allocate it before reading a single byte. The reply below
// is 12 bytes and declares 8 GB.
//
// This is the same bug class as omarroth/doubletake#24, which this project
// reported upstream and then shipped itself. Worth stating plainly: writing the
// fix for someone else's parser did not stop it appearing in ours, because ours
// had no tests here at all.
func TestHostileContentLengthIsRefused(t *testing.T) {
	addr, _ := serve(t, "RTSP/1.0 200 OK\r\nContent-Length: 8589934592\r\n\r\nshort body")
	c := dialTest(t, addr)

	_, err := c.Do("POST", "/fp-setup", "application/octet-stream", []byte("x"))
	if err == nil {
		t.Fatal("a body declaring 8 GB was accepted")
	}
	if !strings.Contains(err.Error(), "implausible") {
		t.Fatalf("want an explicit size refusal, got: %v", err)
	}
}

// TestContentLengthMustParse checks a non-numeric length is an error rather
// than silently becoming zero, which would hand the caller an empty body and
// let a truncated exchange look successful.
func TestContentLengthMustParse(t *testing.T) {
	addr, _ := serve(t, "RTSP/1.0 200 OK\r\nContent-Length: banana\r\n\r\n")
	c := dialTest(t, addr)

	if _, err := c.Do("POST", "/x", "", nil); err == nil {
		t.Fatal("a malformed Content-Length was accepted")
	}
}

func TestNegativeContentLengthIsRefused(t *testing.T) {
	addr, _ := serve(t, "RTSP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n")
	c := dialTest(t, addr)

	if _, err := c.Do("POST", "/x", "", nil); err == nil {
		t.Fatal("a negative Content-Length was accepted")
	}
}

// TestRoundTrip covers the ordinary path: a 142-byte body like a real m2.
func TestRoundTrip(t *testing.T) {
	body := strings.Repeat("A", 142)
	addr, reqCh := serve(t,
		"RTSP/1.0 200 OK\r\nContent-Length: 142\r\nServer: AirTunes/950.7.1\r\n\r\n"+body)
	c := dialTest(t, addr)

	resp, err := c.Do("POST", "/fp-setup", "application/octet-stream",
		[]byte("m1"), "X-Apple-ET: 32")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK() || resp.Code != 200 {
		t.Fatalf("code = %d, OK = %v", resp.Code, resp.OK())
	}
	if len(resp.Body) != 142 {
		t.Fatalf("body is %d bytes, want 142", len(resp.Body))
	}
	if got := resp.Header["server"]; got != "AirTunes/950.7.1" {
		t.Fatalf("header lookup should be lowercased; got %q", got)
	}

	// The request must carry the extra header and a correct Content-Length,
	// since both are load-bearing for /fp-setup.
	req := <-reqCh
	for _, want := range []string{"POST /fp-setup RTSP/1.0", "X-Apple-ET: 32", "Content-Length: 2", "CSeq: 1"} {
		if !strings.Contains(req, want) {
			t.Errorf("request missing %q:\n%s", want, req)
		}
	}
}

// TestCSeqIncrements checks the sequence number advances across requests on
// one connection. A receiver that tracks CSeq will drop a connection that
// repeats one, and pairing needs several requests on the same socket.
func TestCSeqIncrements(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	seen := make(chan string, 2)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for n := 0; n < 2; n++ {
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.HasPrefix(line, "CSeq:") {
					seen <- strings.TrimSpace(line)
				}
				if line == "\r\n" {
					break
				}
			}
			conn.Write([]byte("RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}
	}()

	c := dialTest(t, ln.Addr().String())
	for i := 0; i < 2; i++ {
		if _, err := c.Do("POST", "/x", "", nil); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	for _, want := range []string{"CSeq: 1", "CSeq: 2"} {
		if got := <-seen; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestMalformedStatusLineIsRefused(t *testing.T) {
	for _, raw := range []string{
		"garbage\r\n\r\n",
		"RTSP/1.0\r\n\r\n",
		"RTSP/1.0 notanumber OK\r\n\r\n",
	} {
		addr, _ := serve(t, raw)
		c := dialTest(t, addr)
		if _, err := c.Do("POST", "/x", "", nil); err == nil {
			t.Errorf("malformed status %q was accepted", strings.TrimSpace(raw))
		}
	}
}

// TestNon2xxIsReturnedNotErrored checks a 403 comes back as a Response the
// caller can inspect. The whole device matrix depends on telling 403 from 404,
// so these must not collapse into a transport error.
func TestNon2xxIsReturnedNotErrored(t *testing.T) {
	for _, code := range []int{403, 404, 470} {
		addr, _ := serve(t, fmt.Sprintf("RTSP/1.0 %d Nope\r\nContent-Length: 0\r\n\r\n", code))
		c := dialTest(t, addr)
		resp, err := c.Do("POST", "/fp-setup", "", nil)
		if err != nil {
			t.Fatalf("%d should not be a transport error: %v", code, err)
		}
		if resp.Code != code || resp.OK() {
			t.Fatalf("code = %d OK = %v, want %d and not-OK", resp.Code, resp.OK(), code)
		}
	}
}

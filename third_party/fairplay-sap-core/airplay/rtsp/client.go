// SPDX-License-Identifier: BlueOak-1.0.0

// Package rtsp is a minimal client for the HTTP-shaped RTSP that AirPlay 2
// receivers speak on port 7000.
//
// Two properties matter and neither is optional. Pairing state lives on the TCP
// connection, so every request in an exchange has to go down the same one. And
// once pairing completes the byte stream becomes ChaCha20-Poly1305 framed, so
// the transport has to be swappable underneath the request/response logic
// without the caller restructuring anything.
package rtsp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// maxBodyBytes caps a reply body. Every message this client exchanges is small
// and fixed-size — /info is a plist of a few hundred bytes, an m2 is 142, an m4
// is 32 — so a megabyte is orders of magnitude of headroom while still refusing
// a receiver that declares a length it has no intention of sending.
const maxBodyBytes = 1 << 20

// Response is one parsed reply.
type Response struct {
	Proto  string
	Code   int
	Status string
	Header map[string]string
	Body   []byte
}

// Client is one connection to a receiver.
type Client struct {
	conn net.Conn
	rw   io.ReadWriter // swapped for the encrypted stream after pairing
	br   *bufio.Reader
	host string
	cseq int

	// Proto selects the request line's protocol token. Receivers differ:
	// an Apple TV answers pair-setup over RTSP/1.0 and rejects some requests
	// framed as HTTP/1.1.
	Proto string

	// UserAgent and ClientID appear on every request.
	UserAgent string
	ClientID  string

	// Timeout bounds each request/response.
	Timeout time.Duration
}

// Dial opens a connection. target is "host:port".
func Dial(target string) (*Client, error) {
	c, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("rtsp: dial %s: %w", target, err)
	}
	cl := &Client{
		conn:      c,
		rw:        c,
		host:      target,
		Proto:     "RTSP/1.0",
		UserAgent: "AirPlay/366.0",
		ClientID:  "5FA1E4E01234ABCD",
		Timeout:   12 * time.Second,
	}
	cl.br = bufio.NewReader(c)
	return cl, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Conn exposes the raw connection, for handing to the encrypted-session wrapper.
func (c *Client) Conn() net.Conn { return c.conn }

// UseStream switches all subsequent traffic onto rw, which is how the
// ChaCha20-Poly1305 session is installed once pairing completes. Any buffered
// plaintext is dropped deliberately: carrying it across the switch would mean
// interpreting pre-encryption bytes as encrypted frames.
func (c *Client) UseStream(rw io.ReadWriter) {
	c.rw = rw
	c.br = bufio.NewReader(rw)
}

// Do sends one request and reads one response. extra holds raw header lines
// such as "X-Apple-HKP: 3".
func (c *Client) Do(method, path, contentType string, body []byte, extra ...string) (*Response, error) {
	c.cseq++
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s %s\r\n", method, path, c.Proto)
	fmt.Fprintf(&b, "CSeq: %d\r\n", c.cseq)
	fmt.Fprintf(&b, "Host: %s\r\n", c.host)
	fmt.Fprintf(&b, "User-Agent: %s\r\n", c.UserAgent)
	fmt.Fprintf(&b, "Connection: keep-alive\r\n")
	fmt.Fprintf(&b, "Client-Instance: %s\r\n", c.ClientID)
	fmt.Fprintf(&b, "DACP-ID: %s\r\n", c.ClientID)
	for _, h := range extra {
		fmt.Fprintf(&b, "%s\r\n", h)
	}
	if len(body) > 0 || contentType != "" {
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.Write(body)

	c.conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err := c.rw.Write(b.Bytes()); err != nil {
		return nil, fmt.Errorf("rtsp: write %s %s: %w", method, path, err)
	}
	return c.readResponse(method, path)
}

func (c *Client) readResponse(method, path string) (*Response, error) {
	line, err := c.br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("rtsp: read status for %s %s: %w", method, path, err)
	}
	r := &Response{Header: map[string]string{}, Status: strings.TrimSpace(line)}
	f := strings.Fields(r.Status)
	if len(f) < 2 {
		return nil, fmt.Errorf("rtsp: malformed status line %q", r.Status)
	}
	r.Proto = f[0]
	if r.Code, err = strconv.Atoi(f[1]); err != nil {
		return nil, fmt.Errorf("rtsp: malformed status code in %q", r.Status)
	}

	clen := 0
	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("rtsp: read headers: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		r.Header[strings.ToLower(k)] = v
		if strings.EqualFold(k, "content-length") {
			clen, err = strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("rtsp: Content-Length %q is not a number", v)
			}
			if clen < 0 {
				return nil, fmt.Errorf("rtsp: Content-Length is negative (%d)", clen)
			}
			if clen > maxBodyBytes {
				// Refuse before allocating. Without this the declared length is
				// trusted enough to make([]byte, clen) against it, so a receiver
				// claiming gigabytes gets them allocated before the first byte
				// of body is read.
				return nil, fmt.Errorf("rtsp: implausible Content-Length %d (limit %d)",
					clen, maxBodyBytes)
			}
		}
	}
	if clen > 0 {
		r.Body = make([]byte, clen)
		if _, err := io.ReadFull(c.br, r.Body); err != nil {
			return nil, fmt.Errorf("rtsp: read %d-byte body: %w", clen, err)
		}
	}
	return r, nil
}

// OK reports whether the response is a 2xx.
func (r *Response) OK() bool { return r.Code >= 200 && r.Code < 300 }

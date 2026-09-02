// SPDX-License-Identifier: BlueOak-1.0.0

package pairing

import (
	"bytes"
	"io"
	"testing"
)

// pipePair wires two Sessions together with the read/write keys crossed, the
// way a client and a receiver see the same channel from opposite ends.
type pipePair struct {
	toB, toA *bytes.Buffer
}

func (p *pipePair) sideA() io.ReadWriter { return &rw{r: p.toA, w: p.toB} }
func (p *pipePair) sideB() io.ReadWriter { return &rw{r: p.toB, w: p.toA} }

type rw struct {
	r io.Reader
	w io.Writer
}

func (x *rw) Read(b []byte) (int, error)  { return x.r.Read(b) }
func (x *rw) Write(b []byte) (int, error) { return x.w.Write(b) }

// newCrossed builds a session whose read key is the peer's write key.
func newCrossed(t *testing.T, s io.ReadWriter, secret []byte, flip bool) *Session {
	t.Helper()
	sess, err := NewSession(s, secret)
	if err != nil {
		t.Fatal(err)
	}
	if flip {
		sess.writeKey, sess.readKey = sess.readKey, sess.writeKey
	}
	return sess
}

// TestSessionRoundTrip checks a payload survives the ChaCha20-Poly1305 framing,
// including one larger than a single frame. The 1024-byte frame limit means an
// RTSP body of any real size is multi-frame, so a codec that only ever handles
// one frame works in a unit test and stalls against a device.
func TestSessionRoundTrip(t *testing.T) {
	for _, size := range []int{1, 64, 1023, 1024, 1025, 4096} {
		p := &pipePair{toB: &bytes.Buffer{}, toA: &bytes.Buffer{}}
		secret := []byte("a shared secret from pair-setup")
		client := newCrossed(t, p.sideA(), secret, false)
		server := newCrossed(t, p.sideB(), secret, true)

		msg := make([]byte, size)
		for i := range msg {
			msg[i] = byte(i * 31)
		}
		if _, err := client.Write(msg); err != nil {
			t.Fatalf("size %d: write: %v", size, err)
		}
		got := make([]byte, 0, size)
		buf := make([]byte, 4096)
		for len(got) < size {
			n, err := server.Read(buf)
			if err != nil {
				t.Fatalf("size %d: read after %d bytes: %v", size, len(got), err)
			}
			got = append(got, buf[:n]...)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("size %d: payload changed across the channel", size)
		}
	}
}

// TestSessionRejectsTamperedFrame checks the AEAD tag is actually enforced.
// Silently returning corrupted plaintext would hand the caller attacker
// controlled bytes, which is the failure mode an AEAD exists to prevent.
func TestSessionRejectsTamperedFrame(t *testing.T) {
	wire := &bytes.Buffer{}
	secret := []byte("a shared secret from pair-setup")
	client := newCrossed(t, &rw{r: &bytes.Buffer{}, w: wire}, secret, false)
	if _, err := client.Write([]byte("hello receiver")); err != nil {
		t.Fatal(err)
	}

	framed := wire.Bytes()
	framed[len(framed)-1] ^= 0xff // corrupt the Poly1305 tag

	server := newCrossed(t, &rw{r: bytes.NewReader(framed), w: &bytes.Buffer{}}, secret, true)
	if _, err := server.Read(make([]byte, 256)); err == nil {
		t.Fatal("a frame with a corrupted tag was accepted")
	}
}

// TestNoncesAdvance checks two writes do not reuse a nonce. Reusing a
// ChaCha20-Poly1305 nonce under one key is catastrophic, and it is the easiest
// thing to get wrong in framing code.
func TestNoncesAdvance(t *testing.T) {
	wire := &bytes.Buffer{}
	secret := []byte("a shared secret from pair-setup")
	c := newCrossed(t, &rw{r: &bytes.Buffer{}, w: wire}, secret, false)

	msg := []byte("identical payload")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	first := append([]byte(nil), wire.Bytes()...)
	wire.Reset()
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, wire.Bytes()) {
		t.Fatal("the same plaintext encrypted identically twice — the nonce did not advance")
	}
	if c.writeCtr != 2 {
		t.Fatalf("write counter = %d after two frames, want 2", c.writeCtr)
	}
}

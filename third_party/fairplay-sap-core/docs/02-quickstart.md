# Quickstart

The `fpsap` command is a small, network-free tool: hex in, hex out. It computes
the handshake bytes; it does not speak RTSP and it never talks to a device.

## Install

With a Go toolchain (1.21+):

```sh
go install github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/cmd/fpsap@latest
```

Or grab a prebuilt binary from the [release](https://github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/releases)
for your platform and put it on your `PATH`. Or build from a clone:

```sh
git clone https://github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake
cd fairplay-sap-core-airplay2-sender-authentication-handshake
go build ./cmd/fpsap
```

## 1. Prove the binary is correct

Run this first. It runs the 142 golden vectors bundled inside the binary and
prints the score:

```sh
$ fpsap verify
142/142
```

`verify` exits non-zero if any vector fails, so it doubles as a self-check for a
binary you downloaded rather than built. If it does not print `142/142`, do not
trust anything else the binary tells you.

## 2. Run the core primitive: `exchange`

`exchange` is the heart of the handshake: a 128-byte challenge payload in (hex on
stdin), the 20-byte response out. Here it is on the all-zero payload, whose answer
is a fixed golden vector:

```sh
$ printf '%0256d' 0 | tr '0-9' '0' | fpsap exchange
6f627565f3e77f5b5ede91beee7baf92e4241e0b
```

Any 128-byte payload works; whitespace and newlines in the input are ignored.

## 3. Frame the records: `m1` and `m3`

The full wire exchange (see [The handshake](03-the-handshake.md)) needs framed
records, not just the bare response.

`m1` opens the exchange — a 16-byte record the sender sends first:

```sh
$ fpsap m1
46504c590301010000000004020003bb
```

`m3` takes the receiver's 142-byte m2 record on stdin and produces the 164-byte
m3 response frame. By **default it is session-aware**: it draws a fresh local SAP
from `crypto/rand`, so no two invocations produce the same frame — this is what
receivers that validate the m3 body require.

```sh
# m2hex is a 142-byte FairPlay record captured from a receiver
$ echo "$m2hex" | fpsap m3
46504c59030103000000009803...   # 164 bytes
```

Pass `--frozen` to use the replay path instead — a captured local SAP that is
identical every time, which only permissive mode-3 receivers accept:

```sh
$ echo "$m2hex" | fpsap m3 --frozen
```

An m2 that selects any mode other than 3 is refused with a non-zero exit and a
message naming the mode — the tool will not answer with the wrong key schedule.

## Talking to a real device

`fpsap` deliberately has no network code. Driving an actual receiver needs the
pairing layer in the separate [`airplay/`](../airplay) module:

```sh
cd airplay && go build -o ap2probe ./cmd/ap2probe
./ap2probe control ferrier.local   # pair, exchange, check the receiver discriminates
```

That is what confirmed this implementation against three HomePods — see
[Pairing](12-pairing.md) for the full device matrix, including the Apple TVs and
Macs that refuse before the check.

## What next

- Understand what these bytes mean on the wire → [The handshake](03-the-handshake.md)
- Understand how the bytes are computed → [Architecture](04-architecture.md)
- Every command and its flags, plus the library API → [API reference](08-api-reference.md)

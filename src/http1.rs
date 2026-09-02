//! Persistent HTTP/1.1 (and RTSP/1.0) client on one TCP connection (AirPlay control).
//!
//! Optional HAP control-channel encryption after pair-verify / transient pairing:
//! 1024-byte frames, `len_le_u16 || ChaCha20-Poly1305(frame, nonce=pad12(counter_le_u64), aad=len)`.

use std::net::IpAddr;
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HAP_FRAME: usize = 1024;
const HAP_TAG: usize = 16;
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER: usize = 64 * 1024;
const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub body: Vec<u8>,
}

/// Incoming HTTP/1 request (reverse / event channel).
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn content_type(&self) -> &str {
        self.header("content-type").unwrap_or("")
    }
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub struct HapCrypto {
    out_key: [u8; 32],
    in_key: [u8; 32],
    out_counter: u64,
    in_counter: u64,
    decrypt_buf: Vec<u8>,
}

impl HapCrypto {
    pub fn new(output_key: [u8; 32], input_key: [u8; 32]) -> Self {
        Self {
            out_key: output_key,
            in_key: input_key,
            out_counter: 0,
            in_counter: 0,
            decrypt_buf: Vec::new(),
        }
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();
        let mut rest = data;
        while !rest.is_empty() {
            let n = rest.len().min(HAP_FRAME);
            let frame = &rest[..n];
            rest = &rest[n..];
            let len = (n as u16).to_le_bytes();
            let ct = chacha_aad(&self.out_key, self.out_counter, frame, &len, true)?;
            self.out_counter = self.out_counter.wrapping_add(1);
            output.extend_from_slice(&len);
            output.extend_from_slice(&ct);
        }
        Ok(output)
    }

    /// Decrypt as many complete HAP frames as are available; incomplete bytes stay buffered.
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.decrypt_buf.extend_from_slice(data);
        let mut output = Vec::new();
        loop {
            if self.decrypt_buf.len() < 2 {
                break;
            }
            let length = u16::from_le_bytes([self.decrypt_buf[0], self.decrypt_buf[1]]) as usize;
            let block_len = length.saturating_add(HAP_TAG);
            if self.decrypt_buf.len() < 2 + block_len {
                break;
            }
            let len_bytes = [self.decrypt_buf[0], self.decrypt_buf[1]];
            let block = self.decrypt_buf[2..2 + block_len].to_vec();
            self.decrypt_buf.drain(..2 + block_len);
            let plain = chacha_aad(&self.in_key, self.in_counter, &block, &len_bytes, false)?;
            self.in_counter = self.in_counter.wrapping_add(1);
            output.extend_from_slice(&plain);
        }
        Ok(output)
    }
}

fn nonce_from_counter(counter: u64) -> [u8; 12] {
    // 4 zero bytes + 8-byte little-endian counter (pyatv Chacha20Cipher nonce_length=8).
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

fn chacha_aad(
    key: &[u8; 32],
    counter: u64,
    data: &[u8],
    aad: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("chacha key: {e}"))?;
    let nonce = Nonce::from(nonce_from_counter(counter));
    let payload = Payload { msg: data, aad };
    if encrypt {
        cipher
            .encrypt(&nonce, payload)
            .map_err(|e| format!("chacha encrypt: {e}"))
    } else {
        cipher
            .decrypt(&nonce, payload)
            .map_err(|e| format!("chacha decrypt: {e}"))
    }
}

pub struct Http1Client {
    stream: TcpStream,
    host_header: String,
    crypto: Option<HapCrypto>,
    plaintext_buf: Vec<u8>,
}

impl Http1Client {
    pub async fn connect(host: &str, port: u16) -> Result<Self, String> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
            .await
            .map_err(|_| format!("connect {host}:{port} timed out"))?
            .map_err(|e| format!("connect {host}:{port}: {e}"))?;
        let _ = stream.set_nodelay(true);
        let host_header = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        Ok(Self {
            stream,
            host_header,
            crypto: None,
            plaintext_buf: Vec::new(),
        })
    }

    pub fn enable_encryption(&mut self, output_key: [u8; 32], input_key: [u8; 32]) {
        self.crypto = Some(HapCrypto::new(output_key, input_key));
        self.plaintext_buf.clear();
    }

    pub fn is_encrypted(&self) -> bool {
        self.crypto.is_some()
    }

    /// Source IP of this TCP connection (for `rtsp://<local>/session`).
    pub fn local_ip(&self) -> Option<String> {
        let addr = self.stream.local_addr().ok()?;
        match addr.ip() {
            IpAddr::V4(v) => Some(v.to_string()),
            IpAddr::V6(v) => Some(format!("[{v}]")),
        }
    }

    pub async fn request(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        self.request_proto(method, path, extra_headers, body, WireProtocol::Http11)
            .await
    }

    pub async fn request_timeout(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        self.request_proto_timeout(
            method,
            path,
            extra_headers,
            body,
            WireProtocol::Http11,
            timeout,
        )
        .await
    }

    pub async fn request_rtsp(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        self.request_proto(method, path, extra_headers, body, WireProtocol::Rtsp10)
            .await
    }

    pub async fn request_proto(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
        protocol: WireProtocol,
    ) -> Result<HttpResponse, String> {
        self.request_proto_timeout(method, path, extra_headers, body, protocol, REQUEST_TIMEOUT)
            .await
    }

    /// One request with a caller-chosen timeout. Pair-setup stays on the default
    /// 20s; screen SETUP uses 3s. A timeout poisons this socket — reconnect.
    pub async fn request_rtsp_timeout(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        self.request_proto_timeout(
            method,
            path,
            extra_headers,
            body,
            WireProtocol::Rtsp10,
            timeout,
        )
        .await
    }

    pub async fn request_proto_timeout(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
        protocol: WireProtocol,
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let req = build_request(
            method,
            path,
            &self.host_header,
            extra_headers,
            body,
            protocol,
        );
        let wire = if let Some(crypto) = &mut self.crypto {
            crypto.encrypt(&req)?
        } else {
            req
        };
        tokio::time::timeout(timeout, async {
            self.stream
                .write_all(&wire)
                .await
                .map_err(|e| format!("write {method} {path}: {e}"))?;
            self.stream
                .flush()
                .await
                .map_err(|e| format!("flush {method} {path}: {e}"))?;
            self.read_response().await
        })
        .await
        .map_err(|_| format!("{method} {path} timed out"))?
    }

    /// Split into the TCP stream, optional HAP crypto, and leftover plaintext.
    pub fn into_parts(self) -> (TcpStream, Option<HapCrypto>, Vec<u8>) {
        (self.stream, self.crypto, self.plaintext_buf)
    }

    async fn read_response(&mut self) -> Result<HttpResponse, String> {
        loop {
            match try_parse_http(&mut self.plaintext_buf)? {
                Some(resp) => return Ok(resp),
                None => {}
            }
            let mut tmp = [0u8; 4096];
            let n = self
                .stream
                .read(&mut tmp)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed while reading response".into());
            }
            if let Some(crypto) = &mut self.crypto {
                let plain = crypto.decrypt(&tmp[..n])?;
                self.plaintext_buf.extend_from_slice(&plain);
            } else {
                self.plaintext_buf.extend_from_slice(&tmp[..n]);
            }
            if self.plaintext_buf.len() > MAX_HEADER + MAX_BODY {
                return Err("HTTP response too large".into());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireProtocol {
    Http11,
    Rtsp10,
}

impl WireProtocol {
    fn token(self) -> &'static str {
        match self {
            Self::Http11 => "HTTP/1.1",
            Self::Rtsp10 => "RTSP/1.0",
        }
    }
}

fn build_request(
    method: &str,
    path: &str,
    host: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    protocol: WireProtocol,
) -> Vec<u8> {
    let proto = protocol.token();
    let mut msg = format!(
        "{method} {path} {proto}\r\nHost: {host}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        msg.push_str(k);
        msg.push_str(": ");
        msg.push_str(v);
        msg.push_str("\r\n");
    }
    msg.push_str("\r\n");
    let mut out = msg.into_bytes();
    out.extend_from_slice(body);
    out
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse one HTTP/1 request from `buf` when headers + Content-Length body are complete.
pub fn try_parse_http_request(buf: &mut Vec<u8>) -> Result<Option<HttpRequest>, String> {
    let header_end = match find_header_end(buf) {
        Some(i) => i,
        None => {
            if buf.len() > MAX_HEADER {
                return Err("HTTP headers too large".into());
            }
            return Ok(None);
        }
    };
    let header_bytes = &buf[..header_end];
    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| "HTTP headers are not valid UTF-8".to_string())?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "empty HTTP request line".to_string())?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| format!("bad request line: {request_line}"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| format!("bad request line: {request_line}"))?
        .to_string();
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let val = v.trim().to_string();
            if k.eq_ignore_ascii_case("content-length") {
                let n: usize = val
                    .parse()
                    .map_err(|_| format!("bad Content-Length: {val}"))?;
                if n > MAX_BODY {
                    return Err("HTTP body too large".into());
                }
                content_length = Some(n);
            }
            headers.push((k.trim().to_string(), val));
        }
    }
    let body_len = content_length.unwrap_or(0);
    let body_start = header_end + 4;
    if buf.len() < body_start + body_len {
        return Ok(None);
    }
    let body = buf[body_start..body_start + body_len].to_vec();
    buf.drain(..body_start + body_len);
    Ok(Some(HttpRequest {
        method,
        path,
        headers,
        body,
    }))
}

/// Parse one HTTP response from `buf` when headers + Content-Length body are complete.
pub fn try_parse_http(buf: &mut Vec<u8>) -> Result<Option<HttpResponse>, String> {
    let header_end = match find_header_end(buf) {
        Some(i) => i,
        None => {
            if buf.len() > MAX_HEADER {
                return Err("HTTP headers too large".into());
            }
            return Ok(None);
        }
    };
    let header_bytes = &buf[..header_end];
    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| "HTTP headers are not valid UTF-8".to_string())?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "empty HTTP status line".to_string())?;
    let mut status_parts = status_line.splitn(3, ' ');
    let _proto = status_parts.next().unwrap_or("");
    let status: u16 = status_parts
        .next()
        .ok_or_else(|| format!("bad status line: {status_line}"))?
        .parse()
        .map_err(|_| format!("bad status code: {status_line}"))?;
    let reason = status_parts.next().unwrap_or("").to_string();

    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                let n: usize = v
                    .trim()
                    .parse()
                    .map_err(|_| format!("bad Content-Length: {v}"))?;
                if n > MAX_BODY {
                    return Err("HTTP body too large".into());
                }
                content_length = Some(n);
            }
        }
    }
    let body_len = content_length.unwrap_or(0);
    let body_start = header_end + 4;
    if buf.len() < body_start + body_len {
        return Ok(None);
    }
    let body = buf[body_start..body_start + body_len].to_vec();
    buf.drain(..body_start + body_len);
    Ok(Some(HttpResponse {
        status,
        reason,
        body,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_complete_response_leaves_extra() {
        let mut buf = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA".to_vec();
        let resp = try_parse_http(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.body, b"hello");
        assert_eq!(&buf, b"EXTRA");
    }

    #[test]
    fn parse_incomplete_body() {
        let mut buf = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel".to_vec();
        assert!(try_parse_http(&mut buf).unwrap().is_none());
    }

    #[test]
    fn parse_no_content_length_is_empty_body() {
        let mut buf = b"HTTP/1.1 204 No Content\r\n\r\n".to_vec();
        let resp = try_parse_http(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn parse_forbidden() {
        let mut buf = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        let resp = try_parse_http(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 403);
        assert!(!resp.is_success());
    }

    #[test]
    fn nonce_is_4_zeros_plus_le_u64() {
        let n0 = nonce_from_counter(0);
        assert_eq!(n0, [0u8; 12]);
        let n1 = nonce_from_counter(1);
        assert_eq!(&n1[..4], &[0, 0, 0, 0]);
        assert_eq!(&n1[4..], &[1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn hap_frame_roundtrip_small_and_split() {
        let write = [7u8; 32];
        let read = [9u8; 32];
        let mut client = HapCrypto::new(write, read);
        let mut server = HapCrypto::new(read, write);

        let small = b"POST /play HTTP/1.1\r\n\r\n";
        let ct = client.encrypt(small).unwrap();
        assert_eq!(&ct[..2], &(small.len() as u16).to_le_bytes());
        assert_eq!(ct.len(), 2 + small.len() + HAP_TAG);
        let pt = server.decrypt(&ct).unwrap();
        assert_eq!(pt, small);

        let big = vec![0x5Au8; HAP_FRAME + 50];
        let ct = client.encrypt(&big).unwrap();
        // two frames
        let len0 = u16::from_le_bytes([ct[0], ct[1]]) as usize;
        assert_eq!(len0, HAP_FRAME);
        let pt = server.decrypt(&ct).unwrap();
        assert_eq!(pt, big);
    }

    #[test]
    fn hap_decrypt_buffers_partial_frame() {
        let key = [3u8; 32];
        let mut a = HapCrypto::new(key, key);
        let mut b = HapCrypto::new(key, key);
        let ct = a.encrypt(b"abc").unwrap();
        let first = b.decrypt(&ct[..3]).unwrap();
        assert!(first.is_empty());
        let rest = b.decrypt(&ct[3..]).unwrap();
        assert_eq!(rest, b"abc");
    }

    #[test]
    fn build_request_has_content_length_and_keep_alive() {
        let bytes = build_request(
            "POST",
            "/play",
            "192.0.2.1:7000",
            &[
                ("User-Agent", "AirPlay/320.20"),
                ("Connection", "keep-alive"),
            ],
            b"hi",
            WireProtocol::Http11,
        );
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("POST /play HTTP/1.1\r\n"));
        assert!(s.contains("Host: 192.0.2.1:7000\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.contains("Connection: keep-alive\r\n"));
        assert!(s.ends_with("\r\n\r\nhi"));
    }

    #[test]
    fn build_rtsp_setup_first_line() {
        let bytes = build_request(
            "SETUP",
            "rtsp://192.0.2.10/42",
            "192.0.2.1:7000",
            &[
                ("User-Agent", "AirPlay/550.10"),
                ("CSeq", "1"),
                ("Content-Type", "application/x-apple-binary-plist"),
                ("X-Apple-ProtocolVersion", "1"),
                ("DACP-ID", "AABBCCDDEEFF0011"),
                ("Active-Remote", "123"),
            ],
            b"plist",
            WireProtocol::Rtsp10,
        );
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("SETUP rtsp://192.0.2.10/42 RTSP/1.0\r\n"));
        assert!(!s.starts_with("SETUP rtsp://192.0.2.10/42 HTTP/1.1"));
        assert!(s.contains("User-Agent: AirPlay/550.10\r\n"));
        assert!(s.contains("CSeq: 1\r\n"));
        assert!(s.contains("X-Apple-ProtocolVersion: 1\r\n"));
        assert!(s.contains("DACP-ID: AABBCCDDEEFF0011\r\n"));
        assert!(s.contains("Active-Remote: 123\r\n"));
        assert!(s.ends_with("\r\n\r\nplist"));
    }

    #[test]
    fn parse_rtsp_status_line() {
        let mut buf = b"RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
        let resp = try_parse_http(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
    }

    #[test]
    fn parse_http_request_post_event() {
        let mut buf =
            b"POST /event HTTP/1.1\r\nContent-Type: text/x-apple-plist+xml\r\nContent-Length: 4\r\n\r\nbodyEXTRA"
                .to_vec();
        let req = try_parse_http_request(&mut buf).unwrap().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/event");
        assert_eq!(req.content_type(), "text/x-apple-plist+xml");
        assert_eq!(req.body, b"body");
        assert_eq!(&buf, b"EXTRA");
    }

    #[test]
    fn parse_http_request_get_no_length() {
        let mut buf = b"GET /master.m3u8 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let req = try_parse_http_request(&mut buf).unwrap().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/master.m3u8");
        assert!(req.body.is_empty());
        assert!(buf.is_empty());
    }
}

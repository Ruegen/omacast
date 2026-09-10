//! Minimal Cast v2 sender: TLS :8009, default media receiver, LOAD an HTTP URL.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const NS_CONN: &str = "urn:x-cast:com.google.cast.tp.connection";
const NS_HEART: &str = "urn:x-cast:com.google.cast.tp.heartbeat";
const NS_RECV: &str = "urn:x-cast:com.google.cast.receiver";
const NS_MEDIA: &str = "urn:x-cast:com.google.cast.media";
const DEFAULT_APP: &str = "CC1AD845";
const SENDER: &str = "sender-0";
const RECEIVER: &str = "receiver-0";
/// Screen mirror only (same as AirPlay screen). Never 1.0.
pub(crate) const CAST_SCREEN_VOLUME: f64 = 0.15;
/// Movie LOAD. 0.15 on top of a normal TV volume is nearly silent.
pub(crate) const CAST_FILE_VOLUME: f64 = 0.85;

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct CastConn {
    stream: TlsStream<TcpStream>,
    request_id: u64,
    transport_id: Option<String>,
    media_session_id: Option<i64>,
    default_receiver: bool,
}

struct Incoming {
    namespace: String,
    payload: Value,
}

impl CastConn {
    pub async fn connect(host: &str, port: u16) -> Result<Self, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let name: ServerName<'static> = host
            .to_string()
            .try_into()
            .map_err(|err| format!("cast server name: {err}"))?;
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|err| format!("cast connect {host}:{port}: {err}"))?;
        let stream = TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .map_err(|err| format!("cast TLS: {err}"))?;
        let mut conn = Self {
            stream,
            request_id: 1,
            transport_id: None,
            media_session_id: None,
            default_receiver: false,
        };
        conn.send(RECEIVER, NS_CONN, &json!({"type":"CONNECT"}))
            .await?;
        Ok(conn)
    }

    fn next_id(&mut self) -> u64 {
        let id = self.request_id;
        self.request_id += 1;
        id
    }

    pub async fn launch_and_load(
        &mut self,
        content_id: &str,
        content_type: &str,
        stream_type: &str,
        start: f64,
        force_relaunch: bool,
        volume: f64,
    ) -> Result<(), String> {
        let id = self.next_id();
        self.send(
            RECEIVER,
            NS_RECV,
            &json!({"type":"GET_STATUS","requestId": id}),
        )
        .await?;
        self.collect_status(Duration::from_millis(500)).await;

        let reuse = !force_relaunch && self.default_receiver && self.transport_id.is_some();
        if !reuse {
            if self.transport_id.is_some() {
                let id = self.next_id();
                let _ = self
                    .send(RECEIVER, NS_RECV, &json!({"type":"STOP","requestId": id}))
                    .await;
                self.transport_id = None;
                self.media_session_id = None;
                self.default_receiver = false;
                self.collect_status(Duration::from_millis(250)).await;
                self.transport_id = None;
                self.media_session_id = None;
                self.default_receiver = false;
            }
            let id = self.next_id();
            self.send(
                RECEIVER,
                NS_RECV,
                &json!({"type":"LAUNCH","appId": DEFAULT_APP,"requestId": id}),
            )
            .await?;
            self.wait_transport(Duration::from_secs(12)).await?;
        } else {
            crate::airplay::debug_log("chromecast reuse default receiver");
        }

        let transport = self
            .transport_id
            .clone()
            .ok_or_else(|| "Chromecast launched but sent no transportId".to_string())?;
        self.send(&transport, NS_CONN, &json!({"type":"CONNECT"}))
            .await?;
        self.set_volume(volume).await?;
        let id = self.next_id();
        let load = json!({
            "type": "LOAD",
            "requestId": id,
            "autoplay": true,
            "currentTime": start.max(0.0),
            "media": {
                "contentId": content_id,
                "streamType": stream_type,
                "contentType": content_type,
            }
        });
        self.send(&transport, NS_MEDIA, &load).await?;
        // LOAD is enough to start the GET. Do not block 15s for MEDIA_STATUS.
        let started = self.wait_media_started(Duration::from_secs(2)).await;
        let _ = self.set_volume(volume).await;
        started
    }

    async fn collect_status(&mut self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, self.recv()).await {
                Ok(Ok(msg)) => {
                    self.handle_incoming(msg);
                    if self.transport_id.is_some() {
                        return;
                    }
                }
                _ => return,
            }
        }
    }

    async fn drain_for(&mut self, dur: Duration) {
        let deadline = tokio::time::Instant::now() + dur;
        while tokio::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, self.recv()).await {
                Ok(Ok(msg)) => {
                    let _ = self.handle_incoming(msg);
                }
                _ => return,
            }
        }
    }

    async fn set_volume(&mut self, level: f64) -> Result<(), String> {
        debug_assert!(level < 1.0, "never send Chromecast volume 1.0");
        let id = self.next_id();
        self.send(
            RECEIVER,
            NS_RECV,
            &json!({
                "type": "SET_VOLUME",
                "requestId": id,
                "volume": { "level": level, "muted": false }
            }),
        )
        .await
    }

    pub async fn stop_media(&mut self) {
        if let (Some(transport), Some(sid)) = (self.transport_id.clone(), self.media_session_id) {
            let id = self.next_id();
            let _ = self
                .send(
                    &transport,
                    NS_MEDIA,
                    &json!({
                        "type": "STOP",
                        "requestId": id,
                        "mediaSessionId": sid
                    }),
                )
                .await;
        }
        let _ = self
            .send(RECEIVER, NS_CONN, &json!({"type":"CLOSE"}))
            .await;
    }

    pub async fn pump_until_idle(&mut self, mut stop: tokio::sync::oneshot::Receiver<()>) {
        let mut ping = tokio::time::interval(Duration::from_secs(5));
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = &mut stop => {
                    self.stop_media().await;
                    return;
                }
                _ = ping.tick() => {
                    let _ = self.send(RECEIVER, NS_HEART, &json!({"type":"PING"})).await;
                }
                msg = self.recv() => {
                    let Ok(msg) = msg else { return; };
                    if !self.handle_incoming(msg) {
                        return;
                    }
                }
            }
        }
    }

    async fn wait_transport(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let msg = tokio::time::timeout(left, self.recv())
                .await
                .map_err(|_| "Chromecast launch timed out".to_string())?
                .map_err(|err| format!("cast: {err}"))?;
            self.handle_incoming(msg);
            if self.transport_id.is_some() {
                return Ok(());
            }
        }
        Err("Chromecast launch timed out".into())
    }

    async fn wait_media_started(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut saw_ok = false;
        while tokio::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let msg = match tokio::time::timeout(left, self.recv()).await {
                Ok(Ok(msg)) => msg,
                Ok(Err(err)) => return Err(err),
                Err(_) => break,
            };
            let typ = msg.payload.get("type").and_then(Value::as_str).unwrap_or("");
            if typ == "LOAD_FAILED" || typ == "ERROR" || typ == "LOAD_CANCELLED" {
                return Err(format!(
                    "Chromecast refused the file: {}",
                    msg.payload
                ));
            }
            if !self.handle_incoming(msg) {
                return Err("Chromecast closed after LOAD".into());
            }
            if self.media_session_id.is_some() {
                saw_ok = true;
                break;
            }
        }
        if saw_ok {
            Ok(())
        } else {
            // Default receiver often starts fetching before MEDIA_STATUS. Treat as started.
            Ok(())
        }
    }

    /// Returns false when the receiver went idle after play (or the link died).
    fn handle_incoming(&mut self, msg: Incoming) -> bool {
        if msg.namespace == NS_HEART
            && msg.payload.get("type").and_then(Value::as_str) == Some("PING")
        {
            // answered in pump; during wait we reply inline via spawn-less send later
        }
        if msg.namespace == NS_RECV {
            if let Some(apps) = msg
                .payload
                .pointer("/status/applications")
                .and_then(Value::as_array)
            {
                for app in apps {
                    let id = app.get("appId").and_then(Value::as_str).unwrap_or("");
                    if id == DEFAULT_APP {
                        if let Some(tid) = app.get("transportId").and_then(Value::as_str) {
                            self.transport_id = Some(tid.to_string());
                            self.default_receiver = true;
                        }
                    } else if !self.default_receiver
                        && (id.is_empty() || apps.len() == 1)
                    {
                        if let Some(tid) = app.get("transportId").and_then(Value::as_str) {
                            self.transport_id = Some(tid.to_string());
                        }
                    }
                }
            }
        }
        if msg.namespace == NS_MEDIA {
            if let Some(sid) = msg
                .payload
                .pointer("/status/0/mediaSessionId")
                .and_then(Value::as_i64)
            {
                self.media_session_id = Some(sid);
            }
            let state = msg
                .payload
                .pointer("/status/0/playerState")
                .and_then(Value::as_str)
                .unwrap_or("");
            if state == "IDLE" {
                let reason = msg
                    .payload
                    .pointer("/status/0/idleReason")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if reason == "ERROR" {
                    return false;
                }
                if reason == "FINISHED" || reason == "CANCELLED" {
                    return false;
                }
            }
        }
        true
    }

    async fn send(&mut self, dest: &str, namespace: &str, payload: &Value) -> Result<(), String> {
        if namespace == NS_HEART && payload.get("type").and_then(Value::as_str) == Some("PING") {
            // keep going
        }
        let utf8 = serde_json::to_string(payload).map_err(|err| err.to_string())?;
        let body = encode_cast_message(SENDER, dest, namespace, &utf8);
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        self.stream
            .write_all(&frame)
            .await
            .map_err(|err| format!("cast write: {err}"))?;
        self.stream
            .flush()
            .await
            .map_err(|err| format!("cast flush: {err}"))
    }

    async fn recv(&mut self) -> Result<Incoming, String> {
        loop {
            let mut lenb = [0u8; 4];
            self.stream
                .read_exact(&mut lenb)
                .await
                .map_err(|err| format!("cast read: {err}"))?;
            let len = u32::from_be_bytes(lenb) as usize;
            if len == 0 || len > 1 << 20 {
                return Err(format!("cast bad frame len {len}"));
            }
            let mut buf = vec![0u8; len];
            self.stream
                .read_exact(&mut buf)
                .await
                .map_err(|err| format!("cast read body: {err}"))?;
            let (namespace, dest, utf8) = decode_cast_message(&buf)?;
            if namespace == NS_HEART {
                let v: Value = serde_json::from_str(&utf8).unwrap_or(Value::Null);
                if v.get("type").and_then(Value::as_str) == Some("PING") {
                    let _ = self.send(&dest_or_receiver(&dest), NS_HEART, &json!({"type":"PONG"})).await;
                }
                continue;
            }
            let payload = serde_json::from_str(&utf8).unwrap_or(Value::Null);
            return Ok(Incoming { namespace, payload });
        }
    }
}

fn dest_or_receiver(dest: &str) -> &str {
    if dest.is_empty() || dest == SENDER {
        RECEIVER
    } else {
        dest
    }
}

fn encode_cast_message(source: &str, dest: &str, namespace: &str, utf8: &str) -> Vec<u8> {
    let mut out = Vec::new();
    // protocol_version = CASTV2_1_0 (0), field 1 varint
    put_key(&mut out, 1, 0);
    put_varint(&mut out, 0);
    put_string(&mut out, 2, source);
    put_string(&mut out, 3, dest);
    put_string(&mut out, 4, namespace);
    // payload_type = STRING (0), field 5
    put_key(&mut out, 5, 0);
    put_varint(&mut out, 0);
    put_string(&mut out, 6, utf8);
    out
}

fn decode_cast_message(buf: &[u8]) -> Result<(String, String, String), String> {
    let mut i = 0;
    let mut namespace = String::new();
    let mut dest = String::new();
    let mut utf8 = String::new();
    while i < buf.len() {
        let (key, n) = read_varint(buf, i)?;
        i = n;
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u32;
        match (field, wire) {
            (3, 2) => {
                let (s, n) = read_bytes(buf, i)?;
                dest = String::from_utf8_lossy(s).into_owned();
                i = n;
            }
            (4, 2) => {
                let (s, n) = read_bytes(buf, i)?;
                namespace = String::from_utf8_lossy(s).into_owned();
                i = n;
            }
            (6, 2) => {
                let (s, n) = read_bytes(buf, i)?;
                utf8 = String::from_utf8_lossy(s).into_owned();
                i = n;
            }
            (_, 0) => {
                let (_, n) = read_varint(buf, i)?;
                i = n;
            }
            (_, 1) => i = i.saturating_add(8),
            (_, 2) => {
                let (_, n) = read_bytes(buf, i)?;
                i = n;
            }
            (_, 5) => i = i.saturating_add(4),
            _ => return Err("cast protobuf wire".into()),
        }
    }
    if namespace.is_empty() {
        return Err("cast message missing namespace".into());
    }
    Ok((namespace, dest, utf8))
}

fn put_key(out: &mut Vec<u8>, field: u32, wire: u32) {
    put_varint(out, ((field << 3) | wire) as u64);
}

fn put_string(out: &mut Vec<u8>, field: u32, s: &str) {
    put_key(out, field, 2);
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn read_varint(buf: &[u8], mut i: usize) -> Result<(u64, usize), String> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *buf.get(i).ok_or("cast varint")?;
        i += 1;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((v, i));
        }
        shift += 7;
        if shift > 63 {
            return Err("cast varint overflow".into());
        }
    }
}

fn read_bytes(buf: &[u8], i: usize) -> Result<(&[u8], usize), String> {
    let (len, i) = read_varint(buf, i)?;
    let len = len as usize;
    let end = i.checked_add(len).ok_or("cast bytes")?;
    let s = buf.get(i..end).ok_or("cast bytes")?;
    Ok((s, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cast_message_roundtrip_namespace_and_json() {
        let body = encode_cast_message(SENDER, RECEIVER, NS_MEDIA, r#"{"type":"LOAD"}"#);
        let (ns, dest, utf8) = decode_cast_message(&body).expect("decode");
        assert_eq!(ns, NS_MEDIA);
        assert_eq!(dest, RECEIVER);
        assert!(utf8.contains("LOAD"));
    }

    #[test]
    fn cast_screen_volume_is_fifteen_percent_not_max() {
        assert!((CAST_SCREEN_VOLUME - 0.15).abs() < 1e-9);
        assert_ne!(CAST_SCREEN_VOLUME, 1.0);
    }

    #[test]
    fn cast_file_volume_is_audible_and_not_max() {
        assert!((CAST_FILE_VOLUME - 0.85).abs() < 1e-9);
        assert!(CAST_FILE_VOLUME > CAST_SCREEN_VOLUME);
        assert!(CAST_FILE_VOLUME < 1.0);
        assert_ne!(CAST_FILE_VOLUME, 1.0);
    }
}

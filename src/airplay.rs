//! AirPlay HTTP/RTSP control client on one persistent TCP connection.
//!
//! pair-*, SETUP, RECORD, /play, /rate, /scrub, /stop, /playback-info share a
//! keep-alive socket. After HAP pair-verify (or transient SRP), that same
//! socket is encrypted. AirPlay 2 play matches pyatv `AirPlayV2.play_url`.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::discovery::AirPlayDevice;
use crate::event::{self, EventHub, FcupNeed, HlsOrigin};
use crate::hap::{HapCredentials, PairSetupSession, PairVerifySession};
use crate::http1::{Http1Client, HttpResponse};
use crate::screen::{self, PayloadCrypto, ScreenStream};

#[derive(Debug, Clone)]
pub struct PlaybackInfo {
    pub duration: Option<f64>,
    pub position: Option<f64>,
    pub rate: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayClassify {
    Ok,
    NeedPairing,
    Failed,
}

impl PlayClassify {
    #[cfg(test)]
    pub fn is_playing(self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn needs_pairing(self) -> bool {
        matches!(self, Self::NeedPairing)
    }
}

/// 2xx = play ok. 403 / 453 = pairing/session is wrong. 404 is a hard play
/// failure (not "need a new PIN"). Anything else is a hard error.
pub fn classify_play_http(status: u16) -> PlayClassify {
    if (200..300).contains(&status) {
        PlayClassify::Ok
    } else if matches!(status, 403 | 453) {
        PlayClassify::NeedPairing
    } else {
        PlayClassify::Failed
    }
}

#[derive(Debug)]
pub enum PlayError {
    Forbidden(String),
    Other(String),
}

impl PlayError {
    pub fn message(&self) -> String {
        match self {
            PlayError::Forbidden(s) | PlayError::Other(s) => s.clone(),
        }
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(self, PlayError::Forbidden(_))
    }

    pub fn needs_pairing(&self) -> bool {
        self.is_forbidden()
    }
}

fn play_error_from_response(label: &str, resp: &HttpResponse) -> PlayError {
    let msg = status_message(label, resp);
    if classify_play_http(resp.status).needs_pairing() {
        PlayError::Forbidden(msg)
    } else {
        PlayError::Other(msg)
    }
}

const FEAT_VIDEO: u32 = 0;
const FEAT_HLS: u32 = 4;
const FEAT_SCREEN: u32 = 7;
const FEAT_AUDIO: u32 = 9;

/// Parse mDNS `features` (`0xLOW,0xHIGH` or a single hex) as `(high << 32) | low`.
fn parse_features(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut parts = s.split(',');
    let low = parse_hex_u64(parts.next()?)?;
    match parts.next() {
        None => Some(low),
        Some(high_s) => {
            let high = parse_hex_u64(high_s)?;
            Some((high << 32) | (low & 0xFFFF_FFFF))
        }
    }
}

fn parse_hex_u64(raw: &str) -> Option<u64> {
    let s = raw.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn yn(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "?",
    }
}

fn feature_bit(bits: Option<u64>, bit: u32) -> Option<bool> {
    bits.map(|b| (b & (1u64 << bit)) != 0)
}

pub fn is_screen_mirroring_tv(device: &AirPlayDevice) -> bool {
    let bits = device.features.as_deref().and_then(parse_features);
    matches!(feature_bit(bits, FEAT_SCREEN), Some(true))
        && matches!(feature_bit(bits, FEAT_VIDEO), Some(false))
}

/// Video=no and HLS=yes: local files are served as HLS (type 120 playlist URL).
pub fn device_wants_hls(device: &AirPlayDevice) -> bool {
    let bits = device.features.as_deref().and_then(parse_features);
    matches!(feature_bit(bits, FEAT_HLS), Some(true))
        && matches!(feature_bit(bits, FEAT_VIDEO), Some(false))
}

struct ScreenSetupTimeout;

enum ScreenStreamSetup {
    Port(u16),
    OkNoPort,
    Rejected,
}

/// VCL payload cipher after type-110 SETUP. HAP uses ChaCha from pair-verify IKM.
enum VclCryptoKind {
    None,
    HapChaCha,
}

enum FpSetupProbe {
    M2 { bytes: usize, mode: u8 },
    NotFound,
    Other,
    MixedEncrypt,
}

fn or_q(s: Option<&str>) -> &str {
    match s.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => "?",
    }
}

fn tv_features_line(device: &AirPlayDevice) -> String {
    let model = or_q(device.model.as_deref());
    let srcvers = or_q(device.srcvers.as_deref());
    let features_raw = or_q(device.features.as_deref());
    let bits = device.features.as_deref().and_then(parse_features);
    format!(
        "TV model={model} srcvers={srcvers} features={features_raw} Video={} HLS={} Screen={} Audio={}",
        yn(feature_bit(bits, FEAT_VIDEO)),
        yn(feature_bit(bits, FEAT_HLS)),
        yn(feature_bit(bits, FEAT_SCREEN)),
        yn(feature_bit(bits, FEAT_AUDIO)),
    )
}

const INFO_SKIP: &[&str] = &[
    "pk",
    "pi",
    "psi",
    "serialnumber",
    "serial",
    "macaddress",
    "deviceid",
];

/// FairPlay SAP m1 (FPLY v3, seq 1, capability mask 0x03). We cannot answer m3
/// without the white-box AES tables.
pub const FP_SETUP_M1: [u8; 16] = [
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
    0x00, 0x03, 0xbb,
];

/// Mode byte from a FairPlay m2 record, if the body is a framed FPLY reply.
pub fn fp_m2_mode(body: &[u8]) -> Option<u8> {
    if body.len() >= 14 && body.starts_with(b"FPLY") {
        Some(body[13])
    } else {
        None
    }
}

fn info_scalar(v: &crate::bplist::PlistValue) -> Option<String> {
    use crate::bplist::PlistValue;
    let s = match v {
        PlistValue::String(s) => s.clone(),
        PlistValue::Integer(n) => n.to_string(),
        PlistValue::Real(r) => r.to_string(),
        PlistValue::Boolean(true) => "true".into(),
        PlistValue::Boolean(false) => "false".into(),
        _ => return None,
    };
    if s.len() > 64 {
        None
    } else {
        Some(s)
    }
}

fn skip_info_key(k: &str) -> bool {
    INFO_SKIP.iter().any(|s| *s == k.to_ascii_lowercase())
}

fn info_tree(val: &crate::bplist::PlistValue, prefix: &str, parts: &mut Vec<String>) {
    use crate::bplist::PlistValue;
    match val {
        PlistValue::Dict(pairs) => {
            for (k, v) in pairs {
                if skip_info_key(k) {
                    continue;
                }
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                match v {
                    PlistValue::Dict(_) | PlistValue::Array(_) => info_tree(v, &path, parts),
                    PlistValue::Data(_) => {}
                    other => {
                        if let Some(vs) = info_scalar(other) {
                            parts.push(format!("{path}={vs}"));
                        }
                    }
                }
            }
        }
        PlistValue::Array(items) => {
            parts.push(format!("{prefix}.len={}", items.len()));
            for (i, item) in items.iter().enumerate() {
                let path = format!("{prefix}[{i}]");
                match item {
                    PlistValue::Dict(_) | PlistValue::Array(_) => info_tree(item, &path, parts),
                    PlistValue::Data(_) => {}
                    other => {
                        if let Some(vs) = info_scalar(other) {
                            parts.push(format!("{path}={vs}"));
                        }
                    }
                }
            }
        }
        PlistValue::Data(_) => {}
        other => {
            if let Some(vs) = info_scalar(other) {
                if prefix.is_empty() {
                    parts.push(vs);
                } else {
                    parts.push(format!("{prefix}={vs}"));
                }
            }
        }
    }
}

fn info_summary(val: &crate::bplist::PlistValue) -> String {
    let mut parts = Vec::new();
    let keys: Vec<String> = event::plist_key_names(val)
        .into_iter()
        .filter(|k| !skip_info_key(k))
        .collect();
    if !keys.is_empty() {
        parts.push(format!("keys={}", keys.join(",")));
    }
    info_tree(val, "", &mut parts);
    parts.join(" ")
}

fn info_log_line(resp: &HttpResponse) -> String {
    if !resp.is_success() {
        return format!("GET /info {}", resp.status);
    }
    let n = resp.body.len();
    if resp.body.starts_with(b"bplist") {
        match crate::bplist::from_binary(&resp.body) {
            Ok(val) => {
                let summary = info_summary(&val);
                if summary.is_empty() {
                    format!("GET /info {} bytes={n} bplist", resp.status)
                } else {
                    format!("GET /info {} bytes={n} {summary}", resp.status)
                }
            }
            Err(_) => format!("GET /info {} bytes={n} bplist", resp.status),
        }
    } else {
        format!("GET /info {} bytes={n}", resp.status)
    }
}

fn log_info_response(resp: &HttpResponse) {
    debug_log(&info_log_line(resp));
}

const NET_LOG_MAX: usize = 6;
static NET_LOG: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Newest last. Compact AirPlay request/status lines for the TUI.
pub fn net_log_lines() -> Vec<String> {
    NET_LOG
        .lock()
        .map(|g| g.iter().cloned().collect())
        .unwrap_or_default()
}

pub fn clear_net_log() {
    if let Ok(mut g) = NET_LOG.lock() {
        g.clear();
    }
}

fn push_net_log(line: &str) {
    if let Ok(mut g) = NET_LOG.lock() {
        if g.len() >= NET_LOG_MAX {
            g.pop_front();
        }
        g.push_back(line.to_string());
    }
}

pub struct AirPlayClient {
    http: Http1Client,
    host: String,
    port: u16,
    device_id: String,
    session_id: String,
    rtsp_session: u32,
    dacp_id: String,
    active_remote: String,
    cseq: u32,
    /// True only after POST /play returned 2xx on this connection.
    play_ok: bool,
    timing: Option<Arc<UdpSocket>>,
    control_udp: Option<Arc<UdpSocket>>,
    timing_task: Option<tokio::task::JoinHandle<()>>,
    event_task: Option<tokio::task::JoinHandle<()>>,
    reverse_task: Option<tokio::task::JoinHandle<()>>,
    event_tx: mpsc::UnboundedSender<FcupNeed>,
    event_rx: Option<mpsc::UnboundedReceiver<FcupNeed>>,
    fcup_ok: Arc<AtomicU64>,
    event_http: Arc<AtomicU64>,
    hls: Option<HlsOrigin>,
    creds: Option<HapCredentials>,
    is_screen_mirroring: bool,
    wants_hls: bool,
    media_gets: Option<Arc<AtomicU64>>,
    screen: Option<ScreenStream>,
    /// Events-Write, Events-Read HKDF pair (controller uses them swapped).
    event_keys: Option<([u8; 32], [u8; 32])>,
    incoming: Arc<AtomicU64>,
    listen_task: Option<tokio::task::JoinHandle<()>>,
    /// Pair-verify X25519 shared secret (IKM). Never log these bytes.
    hap_ikm: Option<[u8; 32]>,
    /// Last type-110 SETUP `streamConnectionID` (decimal salt for ChaCha HKDF).
    last_stream_connection_id: Option<u64>,
}

impl Drop for AirPlayClient {
    fn drop(&mut self) {
        self.stop_screen_stream();
        if let Some(task) = self.timing_task.take() {
            task.abort();
        }
        if let Some(task) = self.event_task.take() {
            task.abort();
        }
        if let Some(task) = self.reverse_task.take() {
            task.abort();
        }
        if let Some(task) = self.listen_task.take() {
            task.abort();
        }
    }
}

impl AirPlayClient {
    pub async fn connect(device: AirPlayDevice, device_id: String) -> Result<Self, String> {
        let host = device.preferred_host();
        let port = device.port;
        let http = Http1Client::connect(&host, port).await?;
        debug_log(&format!("TCP {host}:{port}"));
        debug_log(&tv_features_line(&device));
        let mut rng = rand::rngs::OsRng;
        let mut dacp = [0u8; 8];
        rng.fill_bytes(&mut dacp);
        let mut remote = [0u8; 4];
        rng.fill_bytes(&mut remote);
        let is_screen_mirroring = is_screen_mirroring_tv(&device);
        let hub = EventHub::new();
        Ok(Self {
            http,
            host,
            port,
            device_id,
            session_id: Uuid::new_v4().to_string(),
            rtsp_session: rng.next_u32().max(1),
            dacp_id: hex::encode_upper(dacp),
            active_remote: u32::from_le_bytes(remote).to_string(),
            cseq: 1,
            play_ok: false,
            timing: None,
            control_udp: None,
            timing_task: None,
            event_task: None,
            reverse_task: None,
            event_tx: hub.tx,
            event_rx: Some(hub.rx),
            fcup_ok: hub.fcup_ok,
            event_http: hub.event_http,
            hls: None,
            creds: None,
            is_screen_mirroring,
            wants_hls: device_wants_hls(&device),
            media_gets: None,
            screen: None,
            event_keys: None,
            incoming: Arc::new(AtomicU64::new(0)),
            listen_task: None,
            hap_ikm: None,
            last_stream_connection_id: None,
        })
    }

    pub fn is_encrypted(&self) -> bool {
        self.http.is_encrypted()
    }

    pub fn set_creds(&mut self, creds: HapCredentials) {
        self.creds = Some(creds);
    }

    pub fn set_media_gets(&mut self, gets: Arc<AtomicU64>) {
        self.media_gets = Some(gets);
    }

    pub fn set_hls(&mut self, dir: std::path::PathBuf, origin: String) {
        self.hls = Some(HlsOrigin { dir, origin });
    }

    fn fcup_count(&self) -> u64 {
        self.fcup_ok.load(Ordering::Relaxed)
    }

    fn event_http_count(&self) -> u64 {
        self.event_http.load(Ordering::Relaxed)
    }

    fn media_get_count(&self) -> u64 {
        self.media_gets
            .as_ref()
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn next_cseq(&mut self) -> String {
        let n = self.cseq;
        self.cseq = self.cseq.saturating_add(1);
        n.to_string()
    }

    fn rtsp_uri(&self) -> String {
        let ip = self
            .http
            .local_ip()
            .unwrap_or_else(|| "0.0.0.0".to_string());
        format!("rtsp://{ip}/{}", self.rtsp_session)
    }

    fn common_headers(&self) -> Vec<(String, String)> {
        vec![
            ("User-Agent".into(), "AirPlay/550.10".into()),
            ("X-Apple-Device-ID".into(), self.device_id.clone()),
            ("X-Apple-Session-ID".into(), self.session_id.clone()),
            ("X-Apple-Client-Name".into(), "omacast".into()),
            ("Connection".into(), "keep-alive".into()),
        ]
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        let mut headers = self.common_headers();
        for (k, v) in extra {
            headers.push(((*k).to_string(), (*v).to_string()));
        }
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.http.request(method, path, &refs, body).await
    }

    #[allow(dead_code)]
    async fn request_timeout(
        &mut self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let mut headers = self.common_headers();
        for (k, v) in extra {
            headers.push(((*k).to_string(), (*v).to_string()));
        }
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.http
            .request_timeout(method, path, &refs, body, timeout)
            .await
    }

    async fn request_rtsp(
        &mut self,
        method: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        let uri = self.rtsp_uri();
        self.request_rtsp_uri(method, &uri, extra, body).await
    }

    async fn post_bytes(
        &mut self,
        label: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: &[u8],
        log_label: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        let resp = self.request("POST", path, extra, body).await?;
        if let Some(ll) = log_label {
            debug_status(ll, resp.status);
        }
        if resp.is_success() {
            Ok(resp.body)
        } else {
            Err(status_message(label, &resp))
        }
    }

    async fn ensure_timing_port(&mut self) -> Result<u16, String> {
        if let Some(sock) = &self.timing {
            return sock
                .local_addr()
                .map(|a| a.port())
                .map_err(|e| format!("timing port: {e}"));
        }
        let sock = UdpSocket::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| format!("timing bind: {e}"))?;
        let port = sock
            .local_addr()
            .map_err(|e| format!("timing port: {e}"))?
            .port();
        let sock = Arc::new(sock);
        let task_sock = sock.clone();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            loop {
                match task_sock.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        if let Some(reply) = timing_reply(&buf[..n]) {
                            let _ = task_sock.send_to(&reply, peer).await;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        self.timing = Some(sock);
        self.timing_task = Some(handle);
        Ok(port)
    }

    async fn bind_udp_in_range(used: &[u16]) -> Result<(UdpSocket, u16), String> {
        let mut last = "no UDP in 60000-60010".to_string();
        for p in Self::UDP_PORT_MIN..=Self::UDP_PORT_MAX {
            if used.contains(&p) {
                continue;
            }
            match UdpSocket::bind(("0.0.0.0", p)).await {
                Ok(sock) => {
                    let port = sock
                        .local_addr()
                        .map_err(|e| format!("udp port: {e}"))?
                        .port();
                    return Ok((sock, port));
                }
                Err(e) => last = format!("udp bind {p}: {e}"),
            }
        }
        Err(last)
    }

    async fn bind_tcp_in_range(used: &[u16]) -> Result<(TcpListener, u16), String> {
        let mut last = "no TCP in 60000-60010".to_string();
        for p in Self::UDP_PORT_MIN..=Self::UDP_PORT_MAX {
            if used.contains(&p) {
                continue;
            }
            match TcpListener::bind(("0.0.0.0", p)).await {
                Ok(sock) => {
                    let port = sock
                        .local_addr()
                        .map_err(|e| format!("tcp port: {e}"))?
                        .port();
                    return Ok((sock, port));
                }
                Err(e) => last = format!("tcp bind {p}: {e}"),
            }
        }
        Err(last)
    }

    /// Bind UDP timing/ctrl/data and event TCP in 60000-60010 (UFW allow from TV).
    async fn bind_screen_ports(&mut self) -> Result<(u16, u16, u16, u16), String> {
        if let Some(task) = self.timing_task.take() {
            task.abort();
        }
        self.timing = None;
        self.control_udp = None;
        let mut used = Vec::new();
        let (timing, tport) = Self::bind_udp_in_range(&used).await?;
        used.push(tport);
        let (control, cport) = Self::bind_udp_in_range(&used).await?;
        used.push(cport);
        let (data, dport) = Self::bind_udp_in_range(&used).await?;
        used.push(dport);
        let (event, eport) = Self::bind_tcp_in_range(&used).await?;
        let timing = Arc::new(timing);
        let control = Arc::new(control);
        let data = Arc::new(data);
        let t2 = timing.clone();
        let c2 = control.clone();
        let d2 = data.clone();
        let handle = tokio::spawn(async move {
            let mut tbuf = [0u8; 128];
            let mut cbuf = [0u8; 128];
            let mut dbuf = [0u8; 128];
            loop {
                tokio::select! {
                    r = t2.recv_from(&mut tbuf) => {
                        match r {
                            Ok((n, peer)) => {
                                if let Some(reply) = timing_reply(&tbuf[..n]) {
                                    let _ = t2.send_to(&reply, peer).await;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    r = c2.recv_from(&mut cbuf) => {
                        match r {
                            Ok((n, peer)) => {
                                if let Some(reply) = timing_reply(&cbuf[..n]) {
                                    let _ = c2.send_to(&reply, peer).await;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    r = d2.recv_from(&mut dbuf) => {
                        match r {
                            Ok((n, peer)) => {
                                if let Some(reply) = timing_reply(&dbuf[..n]) {
                                    let _ = d2.send_to(&reply, peer).await;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });
        self.timing = Some(timing);
        self.control_udp = Some(control);
        self.timing_task = Some(handle);
        if let Some(task) = self.listen_task.take() {
            task.abort();
        }
        let incoming = self.incoming.clone();
        self.listen_task = Some(tokio::spawn(async move {
            loop {
                match event.accept().await {
                    Ok((_stream, peer)) => {
                        incoming.fetch_add(1, Ordering::Relaxed);
                        debug_log(&format!("event TCP inbound peer={peer}"));
                    }
                    Err(_) => break,
                }
            }
        }));
        Ok((tport, cport, dport, eport))
    }

    async fn setup_rtsp(
        &mut self,
        timing_port: u16,
        is_screen_mirroring: bool,
    ) -> Result<HttpResponse, String> {
        let session_uuid = Uuid::new_v4().to_string().to_uppercase();
        let body = crate::bplist::encode_setup(
            &self.device_id,
            &session_uuid,
            timing_port,
            is_screen_mirroring,
        );
        if is_screen_mirroring {
            debug_log("SETUP session isScreenMirroringSession=true");
        } else {
            debug_log("SETUP session media (no isScreenMirroringSession)");
        }
        self.setup_rtsp_bplist(&body).await
    }

    async fn setup_rtsp_bplist(&mut self, body: &[u8]) -> Result<HttpResponse, String> {
        let extra = [
            ("Content-Type", "application/x-apple-binary-plist"),
            ("X-Apple-ProtocolVersion", "1"),
        ];
        self.request_rtsp("SETUP", &extra, body).await
    }

    async fn setup_rtsp_bplist_timeout(
        &mut self,
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let extra = [
            ("Content-Type", "application/x-apple-binary-plist"),
            ("X-Apple-ProtocolVersion", "1"),
        ];
        self.request_rtsp_uri_timeout("SETUP", extra.as_slice(), body, timeout)
            .await
    }

    const SCREEN_SETUP_TIMEOUT: Duration = Duration::from_secs(20);
    const UDP_PORT_MIN: u16 = 60000;
    const UDP_PORT_MAX: u16 = 60010;
    const STREAM_120_TIMEOUT: Duration = Duration::from_secs(5);

    fn random_stream_connection_id() -> u64 {
        let n = rand::rngs::OsRng.next_u64() & (i64::MAX as u64);
        n.max(1)
    }

    fn log_screen_setup_result(label: &str, resp: &HttpResponse) {
        debug_status(label, resp.status);
        if !resp.body.is_empty() {
            debug_log(&format!(
                "{label} {}",
                crate::bplist::setup_response_keys(&resp.body)
            ));
        }
        if resp.is_success() {
            match crate::bplist::data_port_from_setup(&resp.body) {
                Some(port) => debug_log(&format!("dataPort {port}")),
                None => debug_log("dataPort missing"),
            }
        }
    }

    fn incoming_count(&self) -> u64 {
        self.incoming.load(Ordering::Relaxed)
    }

    fn classify_stream_setup(resp: &HttpResponse) -> ScreenStreamSetup {
        if resp.is_success() {
            match crate::bplist::data_port_from_setup(&resp.body) {
                Some(port) => ScreenStreamSetup::Port(port),
                None => ScreenStreamSetup::OkNoPort,
            }
        } else {
            ScreenStreamSetup::Rejected
        }
    }

    async fn setup_stream_timeout(
        &mut self,
        body: &[u8],
        timeout: Duration,
        label: &str,
    ) -> Result<ScreenStreamSetup, ScreenSetupTimeout> {
        match self.setup_rtsp_bplist_timeout(body, timeout).await {
            Ok(resp) => {
                Self::log_screen_setup_result(label, &resp);
                Ok(Self::classify_stream_setup(&resp))
            }
            Err(err) if screen::is_timeout_err(&err) => {
                debug_log(&format!("{label} timed out"));
                Err(ScreenSetupTimeout)
            }
            Err(err) => {
                debug_status_msg(label, &err);
                Ok(ScreenStreamSetup::Rejected)
            }
        }
    }

    fn log_fp_setup(label: &str, resp: &HttpResponse) {
        let fply = resp.body.starts_with(b"FPLY");
        debug_log(&format!(
            "{label} {} bytes={} fply={}",
            resp.status,
            resp.body.len(),
            if fply { "yes" } else { "no" }
        ));
        if resp.is_success() {
            if let Some(mode) = fp_m2_mode(&resp.body) {
                debug_log(&format!(
                    "fp-setup M2 bytes={} mode_byte={mode}",
                    resp.body.len()
                ));
            }
        }
    }

    /// POST /fp-setup m1 only. Real FairPlay m3 needs white-box AES tables we do not ship.
    #[allow(dead_code)]
    async fn fp_setup_m1(&mut self) {
        let extra = [
            ("Content-Type", "application/octet-stream"),
            ("X-Apple-ET", "32"),
        ];
        match self.request("POST", "/fp-setup", &extra, &FP_SETUP_M1).await {
            Ok(resp) if resp.is_success() => {
                Self::log_fp_setup("fp-setup HTTP", &resp);
                return;
            }
            Ok(resp) => Self::log_fp_setup("fp-setup HTTP", &resp),
            Err(err) => debug_status_msg("fp-setup HTTP", &err),
        }
        match self
            .request_rtsp_uri("POST", "/fp-setup", &extra, &FP_SETUP_M1)
            .await
        {
            Ok(resp) => Self::log_fp_setup("fp-setup RTSP", &resp),
            Err(err) => debug_status_msg("fp-setup RTSP", &err),
        }
    }

    async fn teardown_rtsp(&mut self) {
        match tokio::time::timeout(
            Duration::from_millis(500),
            self.request_rtsp("TEARDOWN", &[], b""),
        )
        .await
        {
            Ok(Ok(resp)) => debug_status("TEARDOWN", resp.status),
            Ok(Err(err)) => debug_status_msg("TEARDOWN", &err),
            Err(_) => debug_log("TEARDOWN timed out"),
        }
    }

    async fn bind_sender_ports(&mut self) -> Result<(u16, u16), String> {
        if let Some(task) = self.listen_task.take() {
            task.abort();
        }
        let data = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| format!("dataPort bind: {e}"))?;
        let control = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| format!("controlPort bind: {e}"))?;
        let data_port = data
            .local_addr()
            .map_err(|e| format!("dataPort: {e}"))?
            .port();
        let control_port = control
            .local_addr()
            .map_err(|e| format!("controlPort: {e}"))?
            .port();
        let incoming = self.incoming.clone();
        self.listen_task = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    a = data.accept() => {
                        match a {
                            Ok((_stream, peer)) => {
                                incoming.fetch_add(1, Ordering::Relaxed);
                                debug_log(&format!("dataPort inbound peer={peer}"));
                            }
                            Err(_) => break,
                        }
                    }
                    a = control.accept() => {
                        match a {
                            Ok((_stream, peer)) => {
                                incoming.fetch_add(1, Ordering::Relaxed);
                                debug_log(&format!("controlPort inbound peer={peer}"));
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }));
        Ok((data_port, control_port))
    }

    #[allow(dead_code)]
    async fn setup_type_110_once(&mut self) -> Result<ScreenStreamSetup, ScreenSetupTimeout> {
        self.setup_type_110_once_ekey(None).await
    }

    async fn setup_type_110_once_ekey(
        &mut self,
        ekey: Option<&[u8]>,
    ) -> Result<ScreenStreamSetup, ScreenSetupTimeout> {
        let id = Self::random_stream_connection_id();
        self.last_stream_connection_id = Some(id);
        let uuid = Uuid::new_v4().to_string();
        let ekey_len = ekey.map(|k| k.len()).unwrap_or(0);
        let body = crate::bplist::encode_setup_screen_ios_ekey(id, &uuid, ekey);
        debug_log(&format!(
            "SETUP stream 110 ekey_len={ekey_len} (20s timeout, once)"
        ));
        self.setup_stream_timeout(&body, Self::SCREEN_SETUP_TIMEOUT, "SETUP stream 110")
            .await
    }

    async fn setup_type_110_once_fp(
        &mut self,
        ekey: Option<&[u8]>,
        eiv: Option<&[u8]>,
        timing_port: Option<u16>,
        control_port: Option<u16>,
    ) -> Result<ScreenStreamSetup, ScreenSetupTimeout> {
        let (Some(tp), Some(cp)) = (timing_port, control_port) else {
            return self.setup_type_110_once_ekey(ekey).await;
        };
        let id = Self::random_stream_connection_id();
        self.last_stream_connection_id = Some(id);
        let uuid = Uuid::new_v4().to_string();
        let ekey_len = ekey.map(|k| k.len()).unwrap_or(0);
        let body = crate::bplist::encode_setup_screen_ios_fp(id, &uuid, ekey, eiv, tp, cp);
        debug_log(&format!(
            "SETUP stream 110 ekey_len={ekey_len} timingPort={tp} controlPort={cp} (20s timeout, no audio)"
        ));
        self.setup_stream_timeout(&body, Self::SCREEN_SETUP_TIMEOUT, "SETUP stream 110")
            .await
    }

    /// Encrypted GET /stream.xml and POST /stream probes. Not play success.
    #[allow(dead_code)]
    async fn probe_stream_endpoints(&mut self) {
        match self.request("GET", "/stream.xml", &[], b"").await {
            Ok(resp) => debug_log(&format!(
                "GET /stream.xml {} bytes={}",
                resp.status,
                resp.body.len()
            )),
            Err(err) => debug_status_msg("GET /stream.xml", &err),
        }
        match self.request("POST", "/stream", &[], b"").await {
            Ok(resp) => debug_log(&format!(
                "POST /stream {} bytes={}",
                resp.status,
                resp.body.len()
            )),
            Err(err) => debug_status_msg("POST /stream", &err),
        }
    }

    async fn record_rtsp(&mut self) -> Result<HttpResponse, String> {
        // pyatv record() has no Range; Range: npt=0- is RAOP audio and 500s on video.
        self.request_rtsp("RECORD", &[], b"").await
    }

    async fn request_rtsp_uri(
        &mut self,
        method: &str,
        uri: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        let cseq = self.next_cseq();
        let mut headers = vec![
            ("User-Agent".to_string(), "AirPlay/550.10".to_string()),
            ("CSeq".to_string(), cseq),
            ("DACP-ID".to_string(), self.dacp_id.clone()),
            ("Active-Remote".to_string(), self.active_remote.clone()),
            ("Client-Instance".to_string(), self.dacp_id.clone()),
            ("X-Apple-ProtocolVersion".to_string(), "1".to_string()),
            ("X-Apple-Session-ID".to_string(), self.session_id.clone()),
        ];
        for (k, v) in extra {
            headers.push(((*k).to_string(), (*v).to_string()));
        }
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.http.request_rtsp(method, uri, &refs, body).await
    }

    async fn request_rtsp_uri_timeout(
        &mut self,
        method: &str,
        extra: &[(&str, &str)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let uri = self.rtsp_uri();
        let cseq = self.next_cseq();
        let mut headers = vec![
            ("User-Agent".to_string(), "AirPlay/550.10".to_string()),
            ("CSeq".to_string(), cseq),
            ("DACP-ID".to_string(), self.dacp_id.clone()),
            ("Active-Remote".to_string(), self.active_remote.clone()),
            ("Client-Instance".to_string(), self.dacp_id.clone()),
            ("X-Apple-ProtocolVersion".to_string(), "1".to_string()),
            ("X-Apple-Session-ID".to_string(), self.session_id.clone()),
        ];
        for (k, v) in extra {
            headers.push(((*k).to_string(), (*v).to_string()));
        }
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.http
            .request_rtsp_timeout(method, &uri, &refs, body, timeout)
            .await
    }

    fn play_plist_body(content_location: &str, start_position: f64) -> Vec<u8> {
        let play_uuid = Uuid::new_v4().to_string();
        crate::bplist::encode_play(content_location, start_position, &play_uuid)
    }

    async fn post_play_plist(
        &mut self,
        content_location: &str,
        start_position: f64,
    ) -> Result<HttpResponse, String> {
        let body = Self::play_plist_body(content_location, start_position);
        self.post_play_plist_http(&body).await
    }

    async fn post_play_plist_http(&mut self, body: &[u8]) -> Result<HttpResponse, String> {
        self.post_bplist("/play", body).await
    }

    #[allow(dead_code)]
    async fn post_play_plist_http_timeout(
        &mut self,
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, String> {
        let extra = [
            ("Content-Type", "application/x-apple-binary-plist"),
            ("X-Apple-ProtocolVersion", "1"),
            ("X-Apple-Stream-ID", "1"),
        ];
        self.request_timeout("POST", "/play", &extra, body, timeout)
            .await
    }

    async fn post_bplist(&mut self, path: &str, body: &[u8]) -> Result<HttpResponse, String> {
        let extra = [
            ("Content-Type", "application/x-apple-binary-plist"),
            ("X-Apple-ProtocolVersion", "1"),
            ("X-Apple-Stream-ID", "1"),
        ];
        self.request("POST", path, &extra, body).await
    }

    /// Same plist as HTTP POST /play, sent as `POST /play RTSP/1.0`.
    async fn post_play_plist_rtsp(&mut self, body: &[u8]) -> Result<HttpResponse, String> {
        let extra = [
            ("Content-Type", "application/x-apple-binary-plist"),
            ("X-Apple-ProtocolVersion", "1"),
            ("X-Apple-Stream-ID", "1"),
        ];
        self.request_rtsp_uri("POST", "/play", &extra, body).await
    }

    async fn post_play_text(
        &mut self,
        content_location: &str,
        start_position: f64,
    ) -> Result<HttpResponse, String> {
        let text = format!(
            "Content-Location: {content_location}\r\nStart-Position: {start_position:.4}\r\n"
        );
        let extra = [("Content-Type", "text/parameters")];
        self.request("POST", "/play", &extra, text.as_bytes()).await
    }

    /// POST /rate?value=… — only after a successful /play (see [`Self::play_succeeded`]).
    async fn post_rate(&mut self, rate: f64) -> Result<HttpResponse, String> {
        let path = format!("/rate?value={rate:.6}");
        self.request("POST", &path, &[], b"").await
    }

    async fn probe_info(&mut self) {
        match self.request("GET", "/info", &[], b"").await {
            Ok(resp) => {
                log_info_response(&resp);
                if resp.is_success() {
                    return;
                }
            }
            Err(err) => debug_status_msg("GET /info", &err),
        }
        match self.request("GET", "/server-info", &[], b"").await {
            Ok(resp) => debug_status("GET /server-info", resp.status),
            Err(err) => debug_status_msg("GET /server-info", &err),
        }
    }

    async fn maybe_connect_event_port(&mut self, setup_body: &[u8]) {
        let Some(port) = crate::bplist::event_port_from_setup(setup_body) else {
            return;
        };
        debug_log(&format!("eventPort {port}"));
        let host = self.host.clone();
        let connect = TcpStream::connect((host.as_str(), port));
        match tokio::time::timeout(Duration::from_secs(2), connect).await {
            Ok(Ok(stream)) => {
                debug_log(&format!("eventPort {port} connected"));
                let crypto = self.event_keys.map(|(write, read)| {
                    debug_log("event HAP listen (Events-Salt swapped, no POST)");
                    crate::http1::HapCrypto::new(read, write)
                });
                if crypto.is_none() {
                    debug_log("event plaintext listen (no event keys)");
                }
                if let Some(task) = self.event_task.take() {
                    task.abort();
                }
                self.event_task = Some(event::spawn_event_reader(
                    stream,
                    crypto,
                    Vec::new(),
                    "event",
                    self.hls.clone(),
                    self.event_tx.clone(),
                    self.event_http.clone(),
                ));
            }
            Ok(Err(err)) => debug_log(&format!("eventPort {port} connect fail: {err}")),
            Err(_) => debug_log(&format!("eventPort {port} connect timeout")),
        }
    }

    async fn start_ptth_reverse(&mut self) {
        let host = self.host.clone();
        let port = self.port;
        let session_id = self.session_id.clone();
        let device_id = self.device_id.clone();
        let extra_owned = event::build_reverse_upgrade(&session_id, &device_id);
        let extra: Vec<(&str, &str)> = extra_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        match Http1Client::connect(&host, port).await {
            Ok(mut http) => {
                match http
                    .request_timeout(
                        "POST",
                        "/reverse",
                        &extra,
                        b"",
                        Duration::from_secs(5),
                    )
                    .await
                {
                    Ok(resp) => {
                        debug_log(&format!(
                            "POST /reverse {} bytes={}",
                            resp.status,
                            resp.body.len()
                        ));
                        if resp.status == 101 || resp.is_success() {
                            let (stream, crypto, leftover) = http.into_parts();
                            if let Some(task) = self.reverse_task.take() {
                                task.abort();
                            }
                            self.reverse_task = Some(event::spawn_event_reader(
                                stream,
                                crypto,
                                leftover,
                                "ptth",
                                self.hls.clone(),
                                self.event_tx.clone(),
                                self.event_http.clone(),
                            ));
                        }
                    }
                    Err(err) => debug_status_msg("POST /reverse", &err),
                }
            }
            Err(err) => debug_log(&format!("POST /reverse connect {err}")),
        }
    }

    async fn pair_verify_second(&mut self) -> Result<Http1Client, String> {
        let creds = self
            .creds
            .clone()
            .ok_or_else(|| "no pairing keys for reverse".to_string())?;
        let mut http = Http1Client::connect(&self.host, self.port).await?;
        let mut session = PairVerifySession::new(creds);
        let m1 = session.m1();
        let hkp = [("X-Apple-HKP", "3"), ("Content-Type", "application/octet-stream")];
        let resp = http
            .request_timeout("POST", "/pair-verify", &hkp, &m1, Duration::from_secs(5))
            .await?;
        debug_status("ptth pair-verify M1", resp.status);
        if !resp.is_success() {
            return Err(status_message("ptth pair-verify M1", &resp));
        }
        let m3 = session.m3_from_m2(&resp.body)?;
        let resp = http
            .request_timeout("POST", "/pair-verify", &hkp, &m3, Duration::from_secs(5))
            .await?;
        debug_status("ptth pair-verify M3", resp.status);
        if !resp.is_success() {
            return Err(status_message("ptth pair-verify M3", &resp));
        }
        if let Some((write, read)) = session.control_keys() {
            http.enable_encryption(write, read);
        }
        Ok(http)
    }

    async fn start_ptth_reverse_hap(&mut self) {
        match self.pair_verify_second().await {
            Ok(mut http) => {
                let extra_owned = event::build_reverse_upgrade(&self.session_id, &self.device_id);
                let extra: Vec<(&str, &str)> = extra_owned
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                match http
                    .request_timeout("POST", "/reverse", &extra, b"", Duration::from_secs(5))
                    .await
                {
                    Ok(resp) => {
                        debug_log(&format!(
                            "POST /reverse hap {} bytes={}",
                            resp.status,
                            resp.body.len()
                        ));
                        if resp.status == 101 || resp.is_success() {
                            let (stream, crypto, leftover) = http.into_parts();
                            if let Some(task) = self.reverse_task.take() {
                                task.abort();
                            }
                            self.reverse_task = Some(event::spawn_event_reader(
                                stream,
                                crypto,
                                leftover,
                                "ptth",
                                self.hls.clone(),
                                self.event_tx.clone(),
                                self.event_http.clone(),
                            ));
                        }
                    }
                    Err(err) => debug_status_msg("POST /reverse hap", &err),
                }
            }
            Err(err) => debug_log(&format!("ptth pair-verify {err}")),
        }
    }

    async fn post_command_shape(&mut self, label: &str, body: &[u8]) -> Result<HttpResponse, String> {
        let resp = self.post_bplist("/command", body).await?;
        debug_response(label, &resp);
        Ok(resp)
    }

    async fn post_action_shape(&mut self, label: &str, body: &[u8]) -> Result<HttpResponse, String> {
        let resp = self.post_bplist("/action", body).await?;
        debug_response(label, &resp);
        Ok(resp)
    }

    #[allow(dead_code)]
    async fn probe_v2_play(&mut self, mlhls: &str, http_url: &str) {
        let uuid = Uuid::new_v4().to_string();
        // iPhone HLS (Crunchyroll/UxPlay): playlistInsert is POST /action, not /command.
        debug_log(
            "POST /action playlistInsert keys=type,params,item,uuid,Content-Location,url,mediaType,streamType,clientProcName url=mlhls",
        );
        let body = crate::bplist::encode_action_playlist_insert(mlhls, &uuid);
        let _ = self
            .post_action_shape("POST /action playlistInsert mlhls", &body)
            .await;
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        let body = crate::bplist::encode_action_playlist_insert(http_url, &uuid);
        let _ = self
            .post_action_shape("POST /action playlistInsert http", &body)
            .await;
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        let body = crate::bplist::encode_command_play_items(mlhls, &uuid);
        let _ = self
            .post_action_shape("POST /action play-items mlhls", &body)
            .await;
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        debug_log("POST /action unhandledURLResponse unsolicited master.m3u8 status=0");
        let need = FcupNeed {
            url: mlhls.to_string(),
            request_id: 1,
        };
        self.send_fcup_response(&need).await;
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        let xml = crate::bplist::encode_playlist_insert_xml(mlhls, &uuid);
        let extra_xml = [("Content-Type", "text/x-apple-plist+xml")];
        match self
            .request("POST", "/action", &extra_xml, xml.as_bytes())
            .await
        {
            Ok(resp) => debug_response("POST /action playlistInsert xml", &resp),
            Err(err) => debug_status_msg("POST /action xml", &err),
        }
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        let json = crate::bplist::encode_playlist_insert_json(mlhls, &uuid);
        let extra_json = [("Content-Type", "application/json")];
        match self
            .request("POST", "/action", &extra_json, json.as_bytes())
            .await
        {
            Ok(resp) => debug_response("POST /action playlistInsert json", &resp),
            Err(err) => debug_status_msg("POST /action json", &err),
        }
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        let extra_xml_cmd = [("Content-Type", "text/x-apple-plist+xml")];
        match self
            .request("POST", "/command", &extra_xml_cmd, xml.as_bytes())
            .await
        {
            Ok(resp) => debug_response("POST /command playlistInsert xml", &resp),
            Err(err) => debug_status_msg("POST /command xml", &err),
        }
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        let extra_json_cmd = [("Content-Type", "application/json")];
        match self
            .request("POST", "/command", &extra_json_cmd, json.as_bytes())
            .await
        {
            Ok(resp) => debug_response("POST /command playlistInsert json", &resp),
            Err(err) => debug_status_msg("POST /command json", &err),
        }
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        debug_log(
            "POST /command playlistInsert keys=type,params,item,uuid,Content-Location,mediaType,streamType url=mlhls",
        );
        let body = crate::bplist::encode_command_playlist_insert(mlhls, &uuid);
        let _ = self
            .post_command_shape("POST /command playlistInsert mlhls", &body)
            .await;
        match self
            .request_rtsp_uri(
                "POST",
                "/command",
                &[("Content-Type", "application/x-apple-binary-plist")],
                &body,
            )
            .await
        {
            Ok(resp) => debug_response("POST /command RTSP playlistInsert", &resp),
            Err(err) => debug_status_msg("POST /command RTSP", &err),
        }
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        debug_log("POST /command play items keys=type,params,uuid,items,Content-Location,url,mediaType,streamType");
        let body = crate::bplist::encode_command_play_items(mlhls, &uuid);
        let _ = self
            .post_command_shape("POST /command play-items mlhls", &body)
            .await;
        if self.media_get_count() > 0 || self.fcup_count() > 0 {
            return;
        }
        let body = crate::bplist::encode_command_play_items(http_url, &uuid);
        let _ = self
            .post_command_shape("POST /command play-items http", &body)
            .await;
        match self.request("POST", "/rate?value=1.000000", &[], b"").await {
            Ok(resp) => debug_response("POST /rate", &resp),
            Err(err) => debug_status_msg("POST /rate", &err),
        }
        match self
            .request("PUT", "/setProperty?actionAtItemEnd", &[], b"")
            .await
        {
            Ok(resp) => debug_response("PUT /setProperty", &resp),
            Err(err) => debug_status_msg("PUT /setProperty", &err),
        }
        match self.request("POST", "/ctrl-int/1/play", &[], b"").await {
            Ok(resp) => debug_response("POST /ctrl-int/1/play", &resp),
            Err(err) => debug_status_msg("POST /ctrl-int/1/play", &err),
        }
        match self.request("POST", "/feedback", &[], b"").await {
            Ok(fb) => debug_response("POST /feedback", &fb),
            Err(err) => debug_status_msg("POST /feedback", &err),
        }
    }

    async fn send_fcup_response(&mut self, need: &FcupNeed) {
        let Some(hls) = self.hls.clone() else {
            debug_log("fcup no hls origin");
            return;
        };
        let Some((bytes, mime)) = event::load_hls_asset(&hls, &need.url) else {
            debug_log(&format!("fcup missing asset {}", need.url));
            return;
        };
        debug_log(&format!(
            "POST /action unhandledURLResponse url={} bytes={} mime={mime} request_id={}",
            need.url,
            bytes.len(),
            need.request_id
        ));
        let body = crate::bplist::encode_fcup_response(&need.url, need.request_id, &bytes, 0);
        match self.post_bplist("/action", &body).await {
            Ok(resp) => {
                debug_response("POST /action", &resp);
                if resp.is_success() {
                    self.fcup_ok.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(err) => debug_status_msg("POST /action", &err),
        }
    }

    async fn wait_hls_or_fcup(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.media_get_count() > 0 {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let wait = left.min(Duration::from_millis(250));
            enum Wait {
                Need(FcupNeed),
                Closed,
                Tick,
            }
            let outcome = if let Some(rx) = self.event_rx.as_mut() {
                tokio::select! {
                    msg = rx.recv() => match msg {
                        Some(need) => Wait::Need(need),
                        None => Wait::Closed,
                    },
                    _ = tokio::time::sleep(wait) => Wait::Tick,
                }
            } else {
                tokio::time::sleep(wait).await;
                Wait::Tick
            };
            match outcome {
                Wait::Need(need) => self.send_fcup_response(&need).await,
                Wait::Closed => self.event_rx = None,
                Wait::Tick => {}
            }
        }
        self.media_get_count() > 0 || self.fcup_count() > 0
    }

    async fn replay_play_on_fresh_connection(
        &mut self,
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        let creds = self
            .creds
            .clone()
            .ok_or_else(|| "no pairing keys for reconnect".to_string())?;
        debug_log("reconnect POST /play (no SETUP)");
        let http = Http1Client::connect(&self.host, self.port).await?;
        self.http = http;
        self.cseq = 1;
        self.play_ok = false;
        self.hap_pair_verify(creds).await?;
        let resp = self.post_play_plist_http(body).await?;
        debug_response("POST /play", &resp);
        Ok(resp)
    }

    async fn reconnect_pair_verify(&mut self) -> Result<(), String> {
        let creds = self
            .creds
            .clone()
            .ok_or_else(|| "no pairing keys for reconnect".to_string())?;
        debug_log("reconnect (fresh TCP + pair-verify)");
        if let Some(task) = self.event_task.take() {
            task.abort();
        }
        if let Some(task) = self.reverse_task.take() {
            task.abort();
        }
        if let Some(task) = self.listen_task.take() {
            task.abort();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let http = Http1Client::connect(&self.host, self.port).await?;
        self.http = http;
        self.cseq = 1;
        self.play_ok = false;
        match self.hap_pair_verify(creds).await {
            Ok(()) => Ok(()),
            Err(err) => {
                debug_log(&format!("reconnect pair-verify {err}"));
                Err(err)
            }
        }
    }

    fn stop_screen_stream(&mut self) {
        if let Some(mut s) = self.screen.take() {
            s.stop();
        }
    }

    pub fn screen_stream_active(&self) -> bool {
        self.screen.as_ref().is_some_and(|s| s.is_active())
    }

    pub fn is_screen_mirroring(&self) -> bool {
        self.is_screen_mirroring
    }

    pub fn screen_stream_frames(&self) -> u64 {
        self.screen.as_ref().map(|s| s.frame_count()).unwrap_or(0)
    }

    pub fn screen_stream_bytes(&self) -> u64 {
        self.screen.as_ref().map(|s| s.bytes_sent()).unwrap_or(0)
    }

    fn log_screen_stats(&self) {
        let n = self.screen_stream_frames();
        let b = self.screen_stream_bytes();
        if n > 0 || b > 0 {
            debug_log(&format!("screen stream frames={n} bytes={b}"));
        }
    }

    pub async fn wait_screen_stream(&mut self, timeout: Duration) {
        if let Some(s) = self.screen.as_mut() {
            s.wait_or_timeout(timeout).await;
        }
        self.log_screen_stats();
    }

    /// Wait until first frames/bytes (or ffmpeg already ended). Leaves the stream running.
    pub async fn wait_screen_stream_rolling(&mut self, timeout: Duration) {
        if let Some(s) = self.screen.as_mut() {
            s.wait_until(screen::ScreenWaitGoal::Rolling, Some(timeout))
                .await;
        }
        self.log_screen_stats();
    }

    /// Wait until the stream task finishes (ffmpeg EOF). No timeout cap.
    pub async fn wait_screen_stream_eof(&mut self) {
        if let Some(s) = self.screen.as_mut() {
            s.wait_until(screen::ScreenWaitGoal::UntilEof, None).await;
        }
        self.log_screen_stats();
    }

    async fn start_h264_if_port(
        &mut self,
        data_port: u16,
        local_file: Option<&Path>,
        crypto: Option<PayloadCrypto>,
    ) {
        let Some(file) = local_file else {
            return;
        };
        self.stop_screen_stream();
        let host = self.host.clone();
        let started = screen::start_screen_stream(&host, data_port, file, crypto, |line| {
            debug_log(line);
        })
        .await;
        if let Some(stream) = started {
            self.screen = Some(stream);
        }
    }

    async fn setup_record_session(
        &mut self,
        is_screen: bool,
    ) -> Result<HttpResponse, PlayError> {
        let timing_port = self.ensure_timing_port().await.map_err(PlayError::Other)?;
        let setup = self
            .setup_rtsp(timing_port, is_screen)
            .await
            .map_err(PlayError::Other)?;
        debug_status("SETUP", setup.status);
        if setup.is_success() {
            self.maybe_connect_event_port(&setup.body).await;
            let record = self.record_rtsp().await.map_err(PlayError::Other)?;
            debug_status("RECORD", record.status);
            if !record.is_success() {
                debug_log("RECORD failed, continuing");
            }
            self.start_ptth_reverse().await;
            if self.reverse_task.is_none() {
                self.start_ptth_reverse_hap().await;
            }
        }
        Ok(setup)
    }

    async fn wait_hls_or_incoming(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.media_get_count() > 0 || self.fcup_count() > 0 || self.incoming_count() > 0 {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let _ = self.wait_hls_or_fcup(left.min(Duration::from_millis(250))).await;
        }
        self.media_get_count() > 0 || self.fcup_count() > 0 || self.incoming_count() > 0
    }

    fn log_hls_counts(&self, note: &str) {
        debug_log(&format!(
            "{note} hls GET count={} fcup={} event_http={} inbound={}",
            self.media_get_count(),
            self.fcup_count(),
            self.event_http_count(),
            self.incoming_count()
        ));
    }

    /// Media session: no isScreenMirroringSession, SETUP 120 (YouTube-style then URL then sender ports).
    async fn play_media_hls(&mut self, content_location: &str) -> Result<bool, PlayError> {
        debug_log("media path: session without isScreenMirroringSession");
        let setup = self.setup_record_session(false).await?;
        if !setup.is_success() {
            if matches!(setup.status, 404 | 501) {
                return Ok(false);
            }
            return Err(play_error_from_response("SETUP", &setup));
        }

        debug_log("SETUP stream 120 minimal keys=type");
        let body = crate::bplist::encode_setup_type_120_minimal();
        if self
            .setup_stream_timeout(&body, Self::STREAM_120_TIMEOUT, "SETUP stream 120 minimal")
            .await
            .is_err()
        {
            self.reconnect_pair_verify()
                .await
                .map_err(PlayError::Other)?;
            return Ok(false);
        }
        if self.wait_hls_or_fcup(Duration::from_secs(3)).await {
            self.log_hls_counts("media 120 minimal");
            return Ok(true);
        }

        let uuid = Uuid::new_v4().to_string();
        debug_log("SETUP stream 120 url=http playlist");
        let body = crate::bplist::encode_setup_type_120(content_location, &uuid);
        if self
            .setup_stream_timeout(&body, Self::STREAM_120_TIMEOUT, "SETUP stream 120 url")
            .await
            .is_err()
        {
            self.reconnect_pair_verify()
                .await
                .map_err(PlayError::Other)?;
            return Ok(false);
        }
        if self.wait_hls_or_fcup(Duration::from_secs(3)).await {
            self.log_hls_counts("media 120 url");
            return Ok(true);
        }

        if let Ok((data_port, control_port)) = self.bind_sender_ports().await {
            let timing = self.ensure_timing_port().await.unwrap_or(0);
            debug_log(&format!(
                "SETUP stream 120 sender ports dataPort={data_port} controlPort={control_port} timingPort={timing}"
            ));
            let body = crate::bplist::encode_setup_type_120_sender_ports(
                content_location,
                &uuid,
                data_port,
                control_port,
                timing,
            );
            if self
                .setup_stream_timeout(
                    &body,
                    Self::STREAM_120_TIMEOUT,
                    "SETUP stream 120 sender-ports",
                )
                .await
                .is_err()
            {
                self.reconnect_pair_verify()
                    .await
                    .map_err(PlayError::Other)?;
                return Ok(false);
            }
        }
        if self.wait_hls_or_incoming(Duration::from_secs(4)).await {
            self.log_hls_counts("media 120 sender-ports");
            return Ok(self.media_get_count() > 0 || self.fcup_count() > 0);
        }

        debug_log("POST /command playlistInsert url=http");
        let body = crate::bplist::encode_command_playlist_insert(content_location, &uuid);
        let _ = self
            .post_command_shape("POST /command playlistInsert http", &body)
            .await;
        if self.wait_hls_or_fcup(Duration::from_secs(4)).await {
            self.log_hls_counts("media /command");
            return Ok(true);
        }
        self.log_hls_counts("media path done");
        debug_log("media path: TV did not fetch HLS");
        Ok(false)
    }

    #[allow(dead_code)]
    async fn setup_session_only(&mut self, is_screen: bool) -> Result<HttpResponse, PlayError> {
        let timing_port = self.ensure_timing_port().await.map_err(PlayError::Other)?;
        let setup = self
            .setup_rtsp(timing_port, is_screen)
            .await
            .map_err(PlayError::Other)?;
        debug_status("SETUP", setup.status);
        if setup.is_success() {
            self.maybe_connect_event_port(&setup.body).await;
        }
        Ok(setup)
    }

    async fn reconnect_plaintext(&mut self) -> Result<(), String> {
        debug_log("plaintext TCP reconnect (no pair-verify/HAP)");
        let http = Http1Client::connect(&self.host, self.port).await?;
        if http.is_encrypted() {
            return Err("plaintext reconnect was encrypted".into());
        }
        self.http = http;
        self.cseq = 1;
        Ok(())
    }

    async fn options_star(&mut self) {
        match tokio::time::timeout(
            Duration::from_secs(5),
            self.request_rtsp_uri("OPTIONS", "*", &[], b""),
        )
        .await
        {
            Ok(Ok(resp)) => debug_status("OPTIONS *", resp.status),
            Ok(Err(err)) => debug_status_msg("OPTIONS *", &err),
            Err(_) => {
                debug_log("OPTIONS * timed out");
                let _ = self.reconnect_plaintext().await;
            }
        }
    }

    fn fp_extra(et: bool) -> Vec<(&'static str, &'static str)> {
        if et {
            vec![
                ("Content-Type", "application/octet-stream"),
                ("X-Apple-ET", "32"),
            ]
        } else {
            vec![("Content-Type", "application/octet-stream")]
        }
    }

    /// POST /fp-setup (and /fp-setup2) on this plaintext socket. Stops at first M2.
    async fn fp_setup_plaintext_probe(&mut self) -> FpSetupProbe {
        debug_log("fp-setup plaintext probe (no HAP encrypt)");
        let probes: [(&str, bool, &str, bool); 6] = [
            ("fp-setup RTSP ET", true, "/fp-setup", true),
            ("fp-setup HTTP ET", false, "/fp-setup", true),
            ("fp-setup RTSP", true, "/fp-setup", false),
            ("fp-setup HTTP", false, "/fp-setup", false),
            ("fp-setup2 RTSP ET", true, "/fp-setup2", true),
            ("fp-setup2 HTTP ET", false, "/fp-setup2", true),
        ];
        let mut saw_404 = false;
        let mut saw_other = false;
        for (label, rtsp, path, et) in probes {
            if self.http.is_encrypted() {
                debug_log("fp-setup aborted: socket is HAP-encrypted");
                return FpSetupProbe::MixedEncrypt;
            }
            let extra = Self::fp_extra(et);
            let result = if rtsp {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    self.request_rtsp_uri("POST", path, extra.as_slice(), &FP_SETUP_M1),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => Err(format!("POST {path} timed out")),
                }
            } else {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    self.request("POST", path, extra.as_slice(), &FP_SETUP_M1),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => Err(format!("POST {path} timed out")),
                }
            };
            match result {
                Ok(resp) => {
                    Self::log_fp_setup(label, &resp);
                    if resp.is_success() {
                        if let Some(mode) = fp_m2_mode(&resp.body) {
                            return FpSetupProbe::M2 {
                                bytes: resp.body.len(),
                                mode,
                            };
                        }
                    }
                    if resp.status == 404 {
                        saw_404 = true;
                    } else {
                        saw_other = true;
                    }
                }
                Err(err) => {
                    debug_status_msg(label, &err);
                    if err.contains("closed")
                        || err.contains("reset")
                        || screen::is_timeout_err(&err)
                    {
                        if self.reconnect_plaintext().await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
        if saw_other {
            FpSetupProbe::Other
        } else if saw_404 {
            FpSetupProbe::NotFound
        } else {
            FpSetupProbe::Other
        }
    }

    async fn setup_session_screen_plaintext(
        &mut self,
    ) -> Result<Option<HttpResponse>, PlayError> {
        let timing_port = self.ensure_timing_port().await.map_err(PlayError::Other)?;
        let session_uuid = Uuid::new_v4().to_string().to_uppercase();
        let body = crate::bplist::encode_setup_fairplay(
            &self.device_id,
            &session_uuid,
            timing_port,
            None,
            None,
        );
        debug_log("SETUP session isScreenMirroringSession=true ekey_len=0 (plaintext)");
        match self
            .setup_rtsp_bplist_timeout(&body, Self::SCREEN_SETUP_TIMEOUT)
            .await
        {
            Ok(resp) => {
                debug_status("SETUP session", resp.status);
                if !resp.body.is_empty() {
                    debug_log(&format!(
                        "SETUP session {}",
                        crate::bplist::setup_response_keys(&resp.body)
                    ));
                }
                if resp.is_success() {
                    self.maybe_connect_event_port(&resp.body).await;
                }
                Ok(Some(resp))
            }
            Err(err) if screen::is_timeout_err(&err) => {
                debug_log("SETUP session timed out");
                Ok(None)
            }
            Err(err) => Err(PlayError::Other(err)),
        }
    }

    async fn finish_type_110(
        &mut self,
        local_file: Option<&Path>,
        ekey: Option<&[u8]>,
    ) -> Result<bool, PlayError> {
        self.finish_type_110_crypto(local_file, ekey, None, VclCryptoKind::None, None, None)
            .await
    }

    async fn finish_type_110_crypto(
        &mut self,
        local_file: Option<&Path>,
        ekey: Option<&[u8]>,
        eiv: Option<&[u8]>,
        vcl_crypto: VclCryptoKind,
        timing_port: Option<u16>,
        control_port: Option<u16>,
    ) -> Result<bool, PlayError> {
        match self
            .setup_type_110_once_fp(
                ekey,
                eiv,
                timing_port,
                control_port,
            )
            .await
        {
            Ok(ScreenStreamSetup::Port(port)) => {
                // RECORD before ffmpeg so the TV is ready before the first frame.
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    self.request_rtsp("RECORD", &[], b""),
                )
                .await
                {
                    Ok(Ok(record)) => debug_status("RECORD", record.status),
                    Ok(Err(err)) => debug_status_msg("RECORD", &err),
                    Err(_) => debug_log("RECORD timed out"),
                }
                let crypto = match vcl_crypto {
                    VclCryptoKind::None => None,
                    VclCryptoKind::HapChaCha => match (self.hap_ikm, self.last_stream_connection_id)
                    {
                        (Some(ikm), Some(id)) => {
                            let key = crate::hap::data_stream_output_key(&ikm, id);
                            Some(PayloadCrypto::chacha(&key))
                        }
                        (None, _) => {
                            debug_log("no pair-verify IKM, cannot ChaCha");
                            return Ok(false);
                        }
                        (_, None) => {
                            debug_log("no streamConnectionID, cannot ChaCha");
                            return Ok(false);
                        }
                    },
                };
                self.start_h264_if_port(port, local_file, crypto).await;
                self.feedback_and_get_parameter().await;
                // First frames only — leave ScreenStream running. Do not wait for EOF here.
                self.wait_screen_stream_rolling(Duration::from_secs(8)).await;
                let n = self.screen_stream_frames();
                let b = self.screen_stream_bytes();
                let rolling = n > 0 || b > 0 || self.screen_stream_active();
                debug_log(&format!("screen dataPort={port} frames={n} bytes={b} rolling={rolling}"));
                Ok(rolling)
            }
            Ok(ScreenStreamSetup::OkNoPort) => {
                debug_log("SETUP 110 200 dataPort missing");
                Ok(false)
            }
            Ok(ScreenStreamSetup::Rejected) => {
                debug_log("SETUP 110 rejected");
                Ok(false)
            }
            Err(ScreenSetupTimeout) => {
                debug_log("SETUP 110 hang — TEARDOWN");
                self.teardown_rtsp().await;
                Ok(false)
            }
        }
    }

    /// iPhone-style screen path: fresh TCP, no pair-verify/HAP encrypt.
    async fn play_legacy_iphone_screen(
        &mut self,
        local_file: Option<&Path>,
    ) -> Result<bool, PlayError> {
        debug_log("legacy iPhone screen: new plaintext TCP (no pair-verify/HAP)");
        let plaintext = Http1Client::connect(&self.host, self.port)
            .await
            .map_err(PlayError::Other)?;
        if plaintext.is_encrypted() {
            return Err(PlayError::Other("plaintext TCP came up encrypted".into()));
        }
        let hap = std::mem::replace(&mut self.http, plaintext);
        let hap_session = self.session_id.clone();
        let hap_cseq = self.cseq;
        let hap_event_keys = self.event_keys.take();
        self.session_id = Uuid::new_v4().to_string();
        self.cseq = 1;

        let outcome = self.play_legacy_iphone_screen_inner(local_file).await;

        match &outcome {
            Ok(true) => {
                drop(hap);
            }
            _ => {
                debug_log("legacy iPhone screen done; restore HAP socket for media fallback");
                self.http = hap;
                self.session_id = hap_session;
                self.cseq = hap_cseq;
                self.event_keys = hap_event_keys;
            }
        }
        outcome
    }

    async fn play_legacy_iphone_screen_inner(
        &mut self,
        local_file: Option<&Path>,
    ) -> Result<bool, PlayError> {
        debug_log(&format!(
            "legacy socket encrypted={}",
            self.http.is_encrypted()
        ));
        self.options_star().await;
        self.probe_info().await;
        match self.fp_setup_plaintext_probe().await {
            FpSetupProbe::M2 { bytes, mode } => {
                debug_log(&format!(
                    "fp-setup handshake M2 bytes={bytes} mode_byte={mode}; M3 needs FairPlay SAP crate, skip"
                ));
            }
            FpSetupProbe::NotFound => {
                debug_log("fp-setup plaintext 404; try unencrypted SETUP 110 once");
            }
            FpSetupProbe::Other => {
                debug_log("fp-setup plaintext no M2; try unencrypted SETUP 110 once");
            }
            FpSetupProbe::MixedEncrypt => {
                debug_log("fp-setup mixed HAP encrypt; abort legacy path");
                return Ok(false);
            }
        }

        if self.http.is_encrypted() {
            debug_log("legacy path mixed HAP encrypt; abort");
            return Ok(false);
        }

        match self.setup_session_screen_plaintext().await? {
            Some(resp) if resp.is_success() => {}
            Some(resp) => {
                debug_log(&format!(
                    "SETUP session {} — still trying SETUP 110",
                    resp.status
                ));
            }
            None => {
                debug_log("SETUP session timeout — TEARDOWN");
                self.teardown_rtsp().await;
                return Ok(false);
            }
        }

        self.finish_type_110(local_file, None).await
    }


    async fn setup_session_screen_hap(
        &mut self,
        timing_port: u16,
        event_port: Option<u16>,
    ) -> Result<Option<HttpResponse>, PlayError> {
        let session_uuid = Uuid::new_v4().to_string().to_uppercase();
        let body = crate::bplist::encode_setup_screen_session(
            &self.device_id,
            &session_uuid,
            timing_port,
            event_port,
        );
        debug_log(&format!(
            "SETUP session isScreenMirroringSession=true ekey_len=0 timingPort={timing_port} (HAP, no audio)"
        ));
        match self
            .setup_rtsp_bplist_timeout(&body, Self::SCREEN_SETUP_TIMEOUT)
            .await
        {
            Ok(resp) => {
                debug_status("SETUP session", resp.status);
                if !resp.body.is_empty() {
                    debug_log(&format!(
                        "SETUP session {}",
                        crate::bplist::setup_response_keys(&resp.body)
                    ));
                }
                if resp.is_success() {
                    self.maybe_connect_event_port(&resp.body).await;
                }
                Ok(Some(resp))
            }
            Err(err) if screen::is_timeout_err(&err) => {
                debug_log("SETUP session timed out");
                Ok(None)
            }
            Err(err) => Err(PlayError::Other(err)),
        }
    }

    async fn feedback_and_get_parameter(&mut self) {
        let fb_ok = match self.request("POST", "/feedback", &[], b"").await {
            Ok(fb) => {
                debug_response("POST /feedback", &fb);
                fb.is_success()
            }
            Err(err) => {
                debug_status_msg("POST /feedback", &err);
                false
            }
        };
        match self.request_rtsp("GET_PARAMETER", &[], b"").await {
            Ok(resp) => {
                debug_status("GET_PARAMETER", resp.status);
                if resp.status == 400 && fb_ok {
                    debug_log("GET_PARAMETER 400 ignored (/feedback 200)");
                }
            }
            Err(err) => debug_status_msg("GET_PARAMETER", &err),
        }
    }

    /// HAP-encrypted screen: skip FairPlay SAP (not advertised), skip audio,
    /// SETUP type 110, RECORD, then H264 dataPort with ChaCha from pair-verify IKM.
    async fn play_hap_fairplay_screen(
        &mut self,
        local_file: Option<&Path>,
    ) -> Result<bool, PlayError> {
        debug_log("HAP screen path (encrypted RTSP, FairPlay SAP skipped, no audio SETUP)");
        if !self.http.is_encrypted() {
            debug_log("screen path skipped: control channel not HAP-encrypted");
            return Ok(false);
        }
        self.probe_info().await;
        debug_log(
            "firewall: bind TCP/UDP 60000-60010; allow from 192.168.178.25 proto tcp/udp to 60000:60010",
        );
        debug_log("FairPlay SAP skipped (not advertised); type 110 VCL ChaCha from pair-verify IKM");
        let (timing_port, control_port, data_port, event_port) =
            match self.bind_screen_ports().await {
                Ok(p) => p,
                Err(err) => {
                    debug_log(&format!("bind 60000-60010 {err}"));
                    return Ok(false);
                }
            };
        debug_log(&format!(
            "UDP timingPort={timing_port} controlPort={control_port} dataPort={data_port} event TCP={event_port} range=60000-60010"
        ));
        match self
            .setup_session_screen_hap(timing_port, Some(event_port))
            .await?
        {
            Some(resp) if resp.is_success() => {}
            Some(resp) => {
                debug_log(&format!(
                    "SETUP session {} — still trying SETUP 110",
                    resp.status
                ));
            }
            None => {
                debug_log("SETUP session timeout — TEARDOWN");
                self.teardown_rtsp().await;
                return Ok(false);
            }
        }
        debug_log("audio SETUP skipped");
        let plain = std::env::var("OMACAST_PLAIN").ok().as_deref() == Some("1");
        if plain {
            debug_log("OMACAST_PLAIN: SETUP 110 ekey_len=0, VCL unencrypted");
            return self
                .finish_type_110_crypto(
                    local_file,
                    None,
                    None,
                    VclCryptoKind::None,
                    Some(timing_port),
                    Some(control_port),
                )
                .await;
        }
        if self.hap_ikm.is_none() {
            debug_log("no pair-verify IKM, cannot ChaCha");
            return Ok(false);
        }
        self.finish_type_110_crypto(
            local_file,
            None,
            None,
            VclCryptoKind::HapChaCha,
            Some(timing_port),
            Some(control_port),
        )
        .await
    }

    /// Play a URL. Screen TVs try HAP encrypted type 110 first (no audio).
    /// HLS type 120 stays as fallback. `/play` 404 is not success.
    pub async fn play(
        &mut self,
        content_location: &str,
        start_position: f64,
        local_file: Option<&Path>,
    ) -> Result<(), PlayError> {
        self.play_ok = false;
        debug_log(&format!("Content-Location {content_location}"));

        if self.is_screen_mirroring {
            if !self.http.is_encrypted() {
                if let Some(creds) = self.creds.clone() {
                    debug_log("HAP pair-verify before FairPlay screen");
                    self.hap_pair_verify(creds)
                        .await
                        .map_err(PlayError::Other)?;
                }
            }
            match self.play_hap_fairplay_screen(local_file).await {
                Ok(true) => {
                    self.play_ok = true;
                    return Ok(());
                }
                Ok(false) if self.screen_stream_active() => {
                    // Stream was started; do not POST /play 404 over a live type-110 send.
                    self.play_ok = true;
                    return Ok(());
                }
                Ok(false) => {
                    debug_log("FairPlay screen: no dataPort/bytes; HAP media fallback");
                }
                Err(err) => {
                    debug_log(&format!("FairPlay screen {}", err.message()));
                    if err.is_forbidden() {
                        return Err(err);
                    }
                    if self.screen_stream_active() {
                        self.play_ok = true;
                        return Ok(());
                    }
                }
            }
        }

        if !self.http.is_encrypted() {
            if let Some(creds) = self.creds.clone() {
                debug_log("HAP pair-verify after screen path");
                self.hap_pair_verify(creds)
                    .await
                    .map_err(PlayError::Other)?;
            }
        }

        if self.http.is_encrypted() {
            self.probe_info().await;
            if self.wants_hls {
                if self.play_media_hls(content_location).await? {
                    self.play_ok = true;
                    return Ok(());
                }
            } else {
                let setup = self.setup_record_session(false).await?;
                if setup.is_success() {
                    let body = Self::play_plist_body(content_location, start_position);
                    let mut resp = self
                        .post_play_plist_http(&body)
                        .await
                        .map_err(PlayError::Other)?;
                    debug_response("POST /play", &resp);
                    if resp.status == 404 && self.screen_stream_frames() == 0 {
                        resp = self
                            .try_play_alts_on_setup_session(content_location, start_position, &body)
                            .await
                            .map_err(PlayError::Other)?;
                    }
                    return self.finish_play(resp).await;
                }
                if !matches!(setup.status, 404 | 501) {
                    return Err(play_error_from_response("SETUP", &setup));
                }
            }

            if self.wants_hls {
                return Err(PlayError::Other(
                    "no hls GET, no FCUP, no screen dataPort".into(),
                ));
            }
        }

        self.play_airplay1(content_location, start_position).await
    }

    /// After HTTP POST /play 404 on a live SETUP session: RTSP /play, then
    /// text/parameters /play, /queue, /command (same plist), /command wrapper,
    /// /feedback probe, then reconnect POST /play. Stop at the first 2xx of 1–4.
    async fn try_play_alts_on_setup_session(
        &mut self,
        content_location: &str,
        start_position: f64,
        play_body: &[u8],
    ) -> Result<HttpResponse, String> {
        let mut resp = self.post_play_plist_rtsp(play_body).await?;
        debug_response("POST /play RTSP", &resp);
        if resp.is_success() {
            return Ok(resp);
        }

        resp = self
            .post_play_text(content_location, start_position)
            .await?;
        debug_response("POST /play", &resp);
        if resp.is_success() {
            return Ok(resp);
        }

        resp = self.post_bplist("/queue", play_body).await?;
        debug_response("POST /queue", &resp);
        if resp.is_success() {
            return Ok(resp);
        }

        resp = self.post_bplist("/command", play_body).await?;
        debug_response("POST /command", &resp);
        if resp.is_success() {
            return Ok(resp);
        }

        let wrapped = crate::bplist::encode_command_play(content_location, start_position);
        resp = self.post_bplist("/command", &wrapped).await?;
        debug_response("POST /command", &resp);
        if resp.is_success() {
            return Ok(resp);
        }

        match self.request("POST", "/feedback", &[], b"").await {
            Ok(fb) => debug_response("POST /feedback", &fb),
            Err(err) => debug_status_msg("POST /feedback", &err),
        }

        match self.replay_play_on_fresh_connection(play_body).await {
            Ok(r) => resp = r,
            Err(err) => debug_status_msg("reconnect", &err),
        }
        Ok(resp)
    }

    async fn play_airplay1(
        &mut self,
        content_location: &str,
        start_position: f64,
    ) -> Result<(), PlayError> {
        let encrypted = self.http.is_encrypted();
        let attempts_plist_first = encrypted;
        let mut last = None;
        for i in 0..2 {
            let plist_now = if attempts_plist_first { i == 0 } else { i == 1 };
            let resp = if plist_now {
                self.post_play_plist(content_location, start_position).await
            } else {
                self.post_play_text(content_location, start_position).await
            }
            .map_err(PlayError::Other)?;
            let label = if i == 0 {
                "POST /play"
            } else {
                "POST /play fallback"
            };
            debug_response(label, &resp);
            if resp.is_success() {
                return self.finish_play(resp).await;
            }
            let can_fallback = i == 0 && matches!(resp.status, 400 | 404 | 415);
            last = Some(resp);
            if !can_fallback {
                break;
            }
        }
        let resp = last.expect("POST /play issued at least one request");
        Err(play_error_from_response("POST /play", &resp))
    }

    async fn finish_play(&mut self, resp: HttpResponse) -> Result<(), PlayError> {
        let hls_n = self.media_get_count();
        if self.wants_hls {
            debug_log(&format!(
                "hls GET count={hls_n} fcup={} event_http={}",
                self.fcup_count(),
                self.event_http_count()
            ));
        }
        if resp.is_success() {
            self.play_ok = true;
            match self.post_rate(1.0).await {
                Ok(rate_resp) => debug_status("POST /rate", rate_resp.status),
                Err(err) => debug_status_msg("POST /rate", &err),
            }
            return Ok(());
        }
        let n = self.screen_stream_frames();
        if n > 0 {
            self.play_ok = true;
            debug_log(&format!("screen stream frames={n}"));
            return Ok(());
        }
        if self.wants_hls && (hls_n > 0 || self.fcup_count() > 0) {
            self.play_ok = true;
            return Ok(());
        }
        Err(play_error_from_response("POST /play", &resp))
    }

    /// POST /rate?value=0|1
    pub async fn set_rate(&mut self, rate: f64) -> Result<(), String> {
        if !self.play_ok {
            return Err("no active play session".into());
        }
        let resp = self.post_rate(rate).await?;
        if resp.is_success() {
            Ok(())
        } else {
            Err(status_message("POST /rate", &resp))
        }
    }

    /// POST /scrub?position=<seconds>
    pub async fn scrub(&mut self, position: f64) -> Result<(), String> {
        if !self.play_ok {
            return Err("no active play session".into());
        }
        let path = format!("/scrub?position={position:.6}");
        let resp = self.request("POST", &path, &[], b"").await?;
        if resp.is_success() {
            Ok(())
        } else {
            Err(status_message("POST /scrub", &resp))
        }
    }

    /// Kill ffmpeg, TEARDOWN the screen session, then POST /stop for HTTP play.
    pub async fn stop(&mut self) -> Result<(), String> {
        let had_screen = self.screen.is_some();
        self.stop_screen_stream();
        if had_screen {
            self.teardown_rtsp().await;
            self.play_ok = false;
            return Ok(());
        }
        if !self.play_ok {
            return Ok(());
        }
        let resp = self.request("POST", "/stop", &[], b"").await?;
        self.play_ok = false;
        if resp.is_success() {
            Ok(())
        } else {
            Err(status_message("POST /stop", &resp))
        }
    }

    /// GET /playback-info — best-effort parse of plist-ish duration/position/rate.
    pub async fn playback_info(&mut self) -> Result<PlaybackInfo, String> {
        if !self.play_ok {
            return Err("no active play session".into());
        }
        let resp = self.request("GET", "/playback-info", &[], b"").await?;
        if !resp.is_success() {
            return Err(status_message("GET /playback-info", &resp));
        }
        Ok(parse_playback_info(&resp.body))
    }

    pub async fn pair_pin_start(&mut self, hkp: u8) -> Result<(), String> {
        let hkp_s = hkp.to_string();
        let extra = [
            ("X-Apple-HKP", hkp_s.as_str()),
            ("Content-Type", "application/octet-stream"),
        ];
        let _ = self
            .post_bytes("POST /pair-pin-start", "/pair-pin-start", &extra, b"", None)
            .await?;
        Ok(())
    }

    pub async fn pair_setup(
        &mut self,
        body: Vec<u8>,
        hkp: u8,
        step: &str,
    ) -> Result<Vec<u8>, String> {
        let hkp_s = hkp.to_string();
        let extra = [
            ("X-Apple-HKP", hkp_s.as_str()),
            ("Content-Type", "application/octet-stream"),
        ];
        self.post_bytes(
            &format!("POST /pair-setup {step}"),
            "/pair-setup",
            &extra,
            &body,
            Some(&format!("pair-setup {step}")),
        )
        .await
    }

    pub async fn pair_verify(&mut self, body: Vec<u8>, step: &str) -> Result<Vec<u8>, String> {
        let extra = [
            ("X-Apple-HKP", "3"),
            ("Content-Type", "application/octet-stream"),
        ];
        self.post_bytes(
            &format!("POST /pair-verify {step}"),
            "/pair-verify",
            &extra,
            &body,
            Some(&format!("pair-verify {step}")),
        )
        .await
    }

    pub async fn hap_pair_verify(&mut self, creds: HapCredentials) -> Result<(), String> {
        self.creds = Some(creds.clone());
        let mut session = PairVerifySession::new(creds);
        let m1 = session.m1();
        let m2 = self.pair_verify(m1, "M1").await?;
        let m3 = session.m3_from_m2(&m2)?;
        let _m4 = self.pair_verify(m3, "M3").await?;
        if let Some((write, read)) = session.control_keys() {
            self.http.enable_encryption(write, read);
        }
        self.event_keys = session.event_keys();
        self.hap_ikm = session.shared_secret();
        Ok(())
    }

    /// Regular PIN pairing M1. On success the session holds salt + B from M2.
    pub async fn start_regular_setup(&mut self) -> Result<PairSetupSession, String> {
        let _ = self.pair_pin_start(3).await;
        let mut setup = PairSetupSession::new(false);
        let m2 = self.pair_setup(setup.m1(), 3, "M1").await?;
        setup.process_m2(&m2)?;
        Ok(setup)
    }

    /// Transient pairing (PIN 3939, no UI). Completes M1–M4, then encrypts this socket.
    pub async fn try_transient_pairing(&mut self) -> Result<(), String> {
        let _ = self.pair_pin_start(4).await;
        let mut setup = PairSetupSession::new(true);
        let m2 = self.pair_setup(setup.m1(), 4, "M1").await?;
        setup.process_m2(&m2)?;
        let m3 = setup.m3("3939")?;
        let m4 = self.pair_setup(m3, 4, "M3").await?;
        setup.process_m4(&m4)?;
        if let Some((write, read)) = setup.control_keys() {
            self.http.enable_encryption(write, read);
        }
        self.event_keys = setup.event_keys();
        Ok(())
    }

    pub async fn finish_regular_setup(
        &mut self,
        setup: &mut PairSetupSession,
        pin: &str,
    ) -> Result<HapCredentials, String> {
        let m3 = setup.m3(pin)?;
        let m4 = self.pair_setup(m3, 3, "M3").await?;
        setup.process_m4(&m4)?;
        let m5 = setup.m5()?;
        let m6 = self.pair_setup(m5, 3, "M5").await?;
        setup.process_m6(&m6)
    }
}

fn status_message(label: &str, resp: &HttpResponse) -> String {
    format!("{label} {}", response_status_detail(resp))
}

fn response_status_detail(resp: &HttpResponse) -> String {
    if resp.body.is_empty() {
        return format!("HTTP {} bytes=0", resp.status);
    }
    if resp.body.starts_with(b"bplist") {
        return format!("HTTP {} bytes={} bplist", resp.status, resp.body.len());
    }
    let snippet: String = String::from_utf8_lossy(&resp.body)
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .take(180)
        .collect();
    let snippet = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    if snippet.is_empty() {
        format!("HTTP {} bytes={}", resp.status, resp.body.len())
    } else {
        format!("HTTP {}: {snippet}", resp.status)
    }
}

fn debug_response(label: &str, resp: &HttpResponse) {
    debug_log(&status_message(label, resp));
}

/// Non-secret debug: pair-setup, pair-verify, SETUP, RECORD status codes.
fn debug_status(label: &str, status: u16) {
    debug_log(&format!("{label} {status}"));
}

fn debug_status_msg(label: &str, msg: &str) {
    debug_log(&format!("{label} {msg}"));
}

pub(crate) fn debug_log(line: &str) {
    push_net_log(line);
    if cfg!(test) {
        return;
    }
    let _ = crate::creds::ensure_config_dir();
    let path = crate::creds::config_dir().join("omacast.log");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "{ts} {line}");
    }
}

/// Best-effort AirPlay timing / NTP reply. Packet is ignored if it is not a known size.
fn timing_reply(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() == 32 {
        let mut reply = [0u8; 32];
        reply[..8].copy_from_slice(&data[..8]);
        reply[1] = 0xd3;
        let now = ntp_now();
        reply[8..16].copy_from_slice(&data[24..32]);
        reply[16..24].copy_from_slice(&now);
        reply[24..32].copy_from_slice(&now);
        return Some(reply.to_vec());
    }
    if data.len() == 48 {
        let mut reply = [0u8; 48];
        reply[0] = 0x24; // LI=0 VN=4 Mode=4 (server)
        reply[1] = data[1];
        reply[2] = data[2];
        reply[3] = data[3];
        reply[24..32].copy_from_slice(&data[40..48]);
        let now = ntp_now();
        reply[32..40].copy_from_slice(&now);
        reply[40..48].copy_from_slice(&now);
        return Some(reply.to_vec());
    }
    None
}

fn ntp_now() -> [u8; 8] {
    const NTP_UNIX: u64 = 2_208_988_800;
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs().saturating_add(NTP_UNIX) as u32;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&secs.to_be_bytes());
    out[4..].copy_from_slice(&(frac as u32).to_be_bytes());
    out
}

/// Parse duration / position / rate from XML plist or ignore binary/unknown bodies.
pub fn parse_playback_info(body: &[u8]) -> PlaybackInfo {
    if body.starts_with(b"bplist") {
        return PlaybackInfo {
            duration: None,
            position: None,
            rate: None,
        };
    }
    let text = String::from_utf8_lossy(body);
    PlaybackInfo {
        duration: plist_number(&text, "duration"),
        position: plist_number(&text, "position")
            .or_else(|| plist_number(&text, "currentPosition")),
        rate: plist_number(&text, "rate"),
    }
}

fn plist_number(body: &str, key: &str) -> Option<f64> {
    let key_tag = format!("<key>{key}</key>");
    let idx = body.find(&key_tag)?;
    let rest = body[idx + key_tag.len()..].trim_start();
    if let Some(inner) = rest.strip_prefix("<real>") {
        let end = inner.find("</real>")?;
        return inner[..end].trim().parse().ok();
    }
    if let Some(inner) = rest.strip_prefix("<integer>") {
        let end = inner.find("</integer>")?;
        return inner[..end].trim().parse::<i64>().ok().map(|n| n as f64);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        classify_play_http, clear_net_log, debug_log, debug_status, device_wants_hls, feature_bit,
        fp_m2_mode, info_log_line, info_summary, is_screen_mirroring_tv, net_log_lines,
        parse_features, parse_playback_info, status_message, timing_reply, tv_features_line,
        PlayClassify, FEAT_AUDIO, FEAT_HLS, FEAT_SCREEN, FEAT_VIDEO, FP_SETUP_M1,
    };
    use crate::bplist::PlistValue;
    use crate::discovery::AirPlayDevice;
    use crate::http1::HttpResponse;

    fn sample_tv() -> AirPlayDevice {
        AirPlayDevice {
            fullname: "Lounge Room._airplay._tcp.local.".into(),
            name: "Lounge Room".into(),
            host: "192.168.178.25".into(),
            port: 7000,
            addresses: vec![],
            deviceid: None,
            features: Some("0x7F8AD0,0x38BCF46".into()),
            flags: None,
            model: Some("65A5HE".into()),
            pw: None,
            srcvers: Some("377.40.00".into()),
        }
    }

    fn http_resp(status: u16, body: &[u8]) -> HttpResponse {
        HttpResponse {
            status,
            reason: String::new(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn play_http_200_is_ok_and_playing() {
        let c = classify_play_http(200);
        assert_eq!(c, PlayClassify::Ok);
        assert!(c.is_playing());
        assert!(!c.needs_pairing());
        assert_eq!(classify_play_http(204), PlayClassify::Ok);
    }

    #[test]
    fn play_http_403_453_need_pairing_not_playing() {
        for status in [403_u16, 453] {
            let c = classify_play_http(status);
            assert_eq!(c, PlayClassify::NeedPairing, "status {status}");
            assert!(
                !c.is_playing(),
                "status {status} must not look like playing"
            );
            assert!(c.needs_pairing(), "status {status}");
        }
    }

    #[test]
    fn play_http_404_is_failed_not_need_pairing() {
        let c = classify_play_http(404);
        assert_eq!(c, PlayClassify::Failed);
        assert!(!c.is_playing());
        assert!(
            !c.needs_pairing(),
            "404 must not bounce to PIN after a paired play"
        );
    }

    #[test]
    fn play_http_other_errors_are_failed_not_playing() {
        for status in [400_u16, 404, 415, 500, 503] {
            let c = classify_play_http(status);
            assert_eq!(c, PlayClassify::Failed, "status {status}");
            assert!(!c.is_playing());
            assert!(!c.needs_pairing());
        }
    }

    #[test]
    fn net_log_keeps_last_six_newest_last() {
        clear_net_log();
        debug_status("SETUP", 200);
        debug_status("RECORD", 500);
        debug_status("POST /play", 404);
        debug_log("Content-Location http://192.0.2.10:9/media.mp4");
        let lines = net_log_lines();
        assert!(lines.iter().any(|l| l == "SETUP 200"));
        assert!(lines.iter().any(|l| l == "RECORD 500"));
        assert!(lines.iter().any(|l| l == "POST /play 404"));
        assert!(lines.last().unwrap().contains("192.0.2.10:9"));
        assert!(!lines.iter().any(|l| l.to_ascii_lowercase().contains("pin")));
        clear_net_log();
        for i in 0..8 {
            debug_status("GET /info", 200 + i);
        }
        let lines = net_log_lines();
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[0], "GET /info 202");
        assert_eq!(lines[5], "GET /info 207");
        clear_net_log();
    }

    #[test]
    fn xml_plist_duration_position() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict>
<key>duration</key><real>123.5</real>
<key>position</key><real>12</real>
<key>rate</key><integer>1</integer>
</dict></plist>"#;
        let info = parse_playback_info(xml.as_bytes());
        assert_eq!(info.duration, Some(123.5));
        assert_eq!(info.position, Some(12.0));
        assert_eq!(info.rate, Some(1.0));
    }

    #[test]
    fn binary_plist_is_ignored() {
        let info = parse_playback_info(b"bplist00....");
        assert!(info.duration.is_none());
        assert!(info.position.is_none());
    }

    #[test]
    fn timing_reply_32_and_48() {
        let mut req32 = [0u8; 32];
        req32[0] = 0x80;
        req32[1] = 0xd2;
        req32[24..32].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let r = timing_reply(&req32).unwrap();
        assert_eq!(r.len(), 32);
        assert_eq!(r[1], 0xd3);
        assert_eq!(&r[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);

        let mut req48 = [0u8; 48];
        req48[40..48].copy_from_slice(&[9, 8, 7, 6, 5, 4, 3, 2]);
        let r = timing_reply(&req48).unwrap();
        assert_eq!(r.len(), 48);
        assert_eq!(r[0], 0x24);
        assert_eq!(&r[24..32], &[9, 8, 7, 6, 5, 4, 3, 2]);
        assert!(timing_reply(&[0u8; 8]).is_none());
    }

    #[test]
    fn parse_hisense_features_video_hls_screen_audio() {
        let bits = parse_features("0x7F8AD0,0x38BCF46").unwrap();
        assert_eq!(feature_bit(Some(bits), FEAT_VIDEO), Some(false));
        assert_eq!(feature_bit(Some(bits), FEAT_HLS), Some(true));
        assert_eq!(feature_bit(Some(bits), FEAT_SCREEN), Some(true));
        assert_eq!(feature_bit(Some(bits), FEAT_AUDIO), Some(true));
        let packed = (0x38BCF46u64 << 32) | 0x7F8AD0;
        assert_eq!(bits, packed);
    }

    #[test]
    fn tv_features_line_hisense_and_missing_fields() {
        let line = tv_features_line(&sample_tv());
        assert_eq!(
            line,
            "TV model=65A5HE srcvers=377.40.00 features=0x7F8AD0,0x38BCF46 Video=no HLS=yes Screen=yes Audio=yes"
        );
        let mut blank = sample_tv();
        blank.model = None;
        blank.srcvers = None;
        blank.features = None;
        assert_eq!(
            tv_features_line(&blank),
            "TV model=? srcvers=? features=? Video=? HLS=? Screen=? Audio=?"
        );
        blank.features = Some("not-hex".into());
        let bad = tv_features_line(&blank);
        assert!(bad.contains("features=not-hex"));
        assert!(bad.contains("Video=?"));
        assert!(parse_features("").is_none());
        assert!(parse_features("nope").is_none());
    }

    #[test]
    fn status_message_play_empty_and_snippet() {
        assert_eq!(
            status_message("POST /play", &http_resp(404, b"")),
            "POST /play HTTP 404 bytes=0"
        );
        assert_eq!(
            status_message("POST /play RTSP", &http_resp(404, b"no resource\nfound")),
            "POST /play RTSP HTTP 404: no resource found"
        );
        assert_eq!(
            status_message("POST /play", &http_resp(200, b"bplist00xxxx")),
            "POST /play HTTP 200 bytes=12 bplist"
        );
    }

    #[test]
    fn info_summary_skips_pk_and_unparseable_bplist_logs_bytes() {
        let val = PlistValue::Dict(vec![
            ("model".into(), PlistValue::String("65A5HE".into())),
            ("pk".into(), PlistValue::String("SECRETKEY".into())),
            (
                "serialNumber".into(),
                PlistValue::String("SERIAL123".into()),
            ),
            (
                "sourceVersion".into(),
                PlistValue::String("377.40.00".into()),
            ),
        ]);
        let summary = info_summary(&val);
        assert!(summary.contains("model=65A5HE"));
        assert!(summary.contains("sourceVersion=377.40.00"));
        assert!(!summary.to_ascii_lowercase().contains("pk"));
        assert!(!summary.contains("SECRETKEY"));
        assert!(!summary.contains("SERIAL"));

        let line = info_log_line(&http_resp(200, b"bplist00not-a-real-plist"));
        assert_eq!(line, "GET /info 200 bytes=24 bplist");
        assert!(!line.to_ascii_lowercase().contains("pk"));
    }

    #[test]
    fn debug_log_does_not_write_omacast_log_under_test() {
        let path = crate::creds::config_dir().join("omacast.log");
        let marker = "cfg-test-must-not-write-omacast-log";
        let before = std::fs::read(&path).unwrap_or_default();
        debug_log(marker);
        let after = std::fs::read(&path).unwrap_or_default();
        assert_eq!(
            before, after,
            "debug_log must not touch omacast.log under cfg(test)"
        );
        let as_text = String::from_utf8_lossy(&after);
        assert!(!as_text.contains(marker));
    }

    #[test]
    fn hisense_is_screen_mirroring_tv() {
        assert!(is_screen_mirroring_tv(&sample_tv()));
        let mut video = sample_tv();
        video.features = Some("0x7F8AD1,0x38BCF46".into());
        assert!(!is_screen_mirroring_tv(&video));
        video.features = None;
        assert!(!is_screen_mirroring_tv(&video));
    }

    #[test]
    fn fp_setup_m1_is_fply_v3_16_bytes() {
        assert_eq!(FP_SETUP_M1.len(), 16);
        assert_eq!(&FP_SETUP_M1[..4], b"FPLY");
        assert_eq!(FP_SETUP_M1[4], 3);
        assert_eq!(FP_SETUP_M1[6], 1);
        assert_eq!(&FP_SETUP_M1[8..12], &[0, 0, 0, 4]);
        assert_eq!(FP_SETUP_M1[12], 0x02);
        assert_eq!(FP_SETUP_M1[14], 0x03);
        assert_eq!(FP_SETUP_M1[15], 0xbb);
    }

    #[test]
    fn fp_m2_mode_reads_mode_not_challenge() {
        let mut m2 = vec![0u8; 142];
        m2[..4].copy_from_slice(b"FPLY");
        m2[13] = 3;
        m2[14] = 0xAB;
        assert_eq!(fp_m2_mode(&m2), Some(3));
        assert!(fp_m2_mode(b"not-fply").is_none());
        assert!(fp_m2_mode(&m2[..10]).is_none());
        clear_net_log();
        debug_log("fp-setup RTSP ET 404 bytes=0 fply=no");
        debug_log("SETUP stream 110 ekey_len=0 (20s timeout, once)");
        let lines = net_log_lines();
        assert!(lines.iter().any(|l| l.contains("fp-setup RTSP ET 404")));
        assert!(lines.iter().any(|l| l.contains("ekey_len=0")));
        assert!(!lines.iter().any(|l| l.to_ascii_lowercase().contains("ab")));
        assert!(!lines.iter().any(|l| l.to_ascii_lowercase().contains("pin")));
        clear_net_log();
    }

    #[test]
    fn info_summary_nested_array_dicts_skips_pk() {
        let val = PlistValue::Dict(vec![
            (
                "displays".into(),
                PlistValue::Array(vec![PlistValue::Dict(vec![
                    ("widthPixels".into(), PlistValue::Integer(1920)),
                    ("uuid".into(), PlistValue::String("disp-1".into())),
                ])]),
            ),
            ("pk".into(), PlistValue::String("SECRETKEY".into())),
        ]);
        let summary = info_summary(&val);
        assert!(summary.contains("displays.len=1"));
        assert!(summary.contains("displays[0].widthPixels=1920"));
        assert!(summary.contains("displays[0].uuid=disp-1"));
        assert!(!summary.contains("SECRETKEY"));
        assert!(!summary.to_ascii_lowercase().contains("pk="));
    }

    #[test]
    fn hisense_wants_hls_wrap() {
        assert!(device_wants_hls(&sample_tv()));
        let mut video = sample_tv();
        video.features = Some("0x7F8AD1,0x38BCF46".into());
        assert!(!device_wants_hls(&video));
        video.features = None;
        assert!(!device_wants_hls(&video));
    }
}

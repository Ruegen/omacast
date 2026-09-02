//! Reverse HTTP / event-channel handling for AirPlay 2 HLS (FCUP).
//!
//! The TV may POST `/event` `unhandledURLRequest` on the event TCP (or a
//! PTTH-upgraded reverse connection). The sender replies with POST `/action`
//! `unhandledURLResponse` wrapping playlist bytes.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::bplist::{self, PlistValue};
use crate::hls;
use crate::http1::{self, HapCrypto, HttpRequest};

#[derive(Debug, Clone)]
pub struct FcupNeed {
    pub url: String,
    pub request_id: i64,
}

#[derive(Clone)]
pub struct HlsOrigin {
    pub dir: PathBuf,
    pub origin: String,
}

pub struct EventHub {
    pub tx: mpsc::UnboundedSender<FcupNeed>,
    pub rx: mpsc::UnboundedReceiver<FcupNeed>,
    pub fcup_ok: Arc<AtomicU64>,
    pub event_http: Arc<AtomicU64>,
}

impl EventHub {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            tx,
            rx,
            fcup_ok: Arc::new(AtomicU64::new(0)),
            event_http: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Spawn a reader that logs reverse HTTP and forwards FCUP playlist requests.
pub fn spawn_event_reader(
    mut stream: TcpStream,
    mut crypto: Option<HapCrypto>,
    leftover: Vec<u8>,
    label: &'static str,
    hls: Option<HlsOrigin>,
    tx: mpsc::UnboundedSender<FcupNeed>,
    event_http: Arc<AtomicU64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = stream.set_nodelay(true);
        let mut plain = leftover;
        let mut tmp = [0u8; 4096];
        let mut logged_first = false;
        loop {
            match try_next_event(&mut plain) {
                Ok(Some(EventMsg::Http(req))) => {
                    event_http.fetch_add(1, Ordering::Relaxed);
                    handle_reverse_http(
                        &mut stream,
                        crypto.as_mut(),
                        &req,
                        label,
                        hls.as_ref(),
                        &tx,
                    )
                    .await;
                    continue;
                }
                Ok(Some(EventMsg::Plist)) => continue,
                Ok(None) => {}
                Err(err) => {
                    crate::airplay::debug_log(&format!("{label} parse {err}"));
                    break;
                }
            }
            match stream.read(&mut tmp).await {
                Ok(0) => {
                    crate::airplay::debug_log(&format!("{label} closed"));
                    break;
                }
                Err(err) => {
                    crate::airplay::debug_log(&format!("{label} read {err}"));
                    break;
                }
                Ok(n) => {
                    let chunk = &tmp[..n];
                    if !logged_first {
                        logged_first = true;
                        log_first_bytes(label, chunk);
                    }
                    match &mut crypto {
                        Some(c) => match c.decrypt(chunk) {
                            Ok(pt) => plain.extend_from_slice(&pt),
                            Err(err) => {
                                crate::airplay::debug_log(&format!("{label} decrypt {err}"));
                                break;
                            }
                        },
                        None => plain.extend_from_slice(chunk),
                    }
                    if plain.len() > 64 * 1024 + 1024 * 1024 {
                        crate::airplay::debug_log(&format!("{label} buffer overflow"));
                        break;
                    }
                }
            }
        }
    })
}

enum EventMsg {
    Http(HttpRequest),
    Plist,
}

fn try_next_event(buf: &mut Vec<u8>) -> Result<Option<EventMsg>, String> {
    if buf.is_empty() {
        return Ok(None);
    }
    if looks_like_http(buf) {
        return http1::try_parse_http_request(buf).map(|o| o.map(EventMsg::Http));
    }
    if buf.starts_with(b"bplist") && buf.len() >= 40 {
        match bplist::from_binary(buf) {
            Ok(val) => {
                let keys = plist_key_names(&val);
                crate::airplay::debug_log(&format!(
                    "event bplist keys={}",
                    keys.join(",")
                ));
                buf.clear();
                return Ok(Some(EventMsg::Plist));
            }
            Err(_) => return Ok(None),
        }
    }
    if buf.len() >= 8 && !looks_like_http(buf) && !buf.starts_with(b"bplist") {
        crate::airplay::debug_log(&format!(
            "event bytes={} head={}",
            buf.len(),
            printable_head(buf, 48)
        ));
        buf.clear();
        return Ok(Some(EventMsg::Plist));
    }
    Ok(None)
}

fn looks_like_http(buf: &[u8]) -> bool {
    buf.starts_with(b"GET ")
        || buf.starts_with(b"POST ")
        || buf.starts_with(b"PUT ")
        || buf.starts_with(b"HEAD ")
        || buf.starts_with(b"OPTIONS ")
        || buf.starts_with(b"HTTP/")
        || buf.starts_with(b"RTSP/")
}

fn log_first_bytes(label: &str, chunk: &[u8]) {
    crate::airplay::debug_log(&format!(
        "{label} first bytes={} head={}",
        chunk.len(),
        printable_head(chunk, 48)
    ));
}

fn printable_head(buf: &[u8], n: usize) -> String {
    buf.iter()
        .take(n)
        .map(|b| {
            let c = *b as char;
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '.'
            }
        })
        .collect()
}

async fn handle_reverse_http(
    stream: &mut TcpStream,
    crypto: Option<&mut HapCrypto>,
    req: &HttpRequest,
    label: &str,
    hls: Option<&HlsOrigin>,
    tx: &mpsc::UnboundedSender<FcupNeed>,
) {
    let ct = req.content_type();
    let keys = event_body_keys(&req.body, ct);
    crate::airplay::debug_log(&format!(
        "{label} {} {} ct={} keys={}",
        req.method,
        req.path,
        if ct.is_empty() { "-" } else { ct },
        if keys.is_empty() {
            "-".into()
        } else {
            keys.join(",")
        }
    ));

    let method = req.method.to_ascii_uppercase();
    // A response to our event-socket POST, not a reverse request.
    if method.starts_with("HTTP/") || method.starts_with("RTSP/") {
        return;
    }
    if method == "GET" || method == "HEAD" {
        if let Some(hls) = hls {
            if let Some((bytes, mime)) = load_hls_asset(hls, &req.path) {
                let body = if method == "HEAD" { Vec::new() } else { bytes };
                let _ = write_http(
                    stream,
                    crypto,
                    200,
                    mime,
                    &body,
                )
                .await;
                return;
            }
        }
        let _ = write_http(stream, crypto, 404, "text/plain", b"").await;
        return;
    }

    if method == "POST" {
        if let Some(need) = parse_fcup_event(&req.body, ct) {
            crate::airplay::debug_log(&format!(
                "{label} fcup url={} request_id={}",
                need.url, need.request_id
            ));
            let _ = tx.send(need);
        }
        let _ = write_http(stream, crypto, 200, "text/plain", b"").await;
        return;
    }

    let _ = write_http(stream, crypto, 200, "text/plain", b"").await;
}

/// Send an HTTP/RTSP request on the event TCP (optionally HAP-framed).
#[allow(dead_code)]
pub async fn write_request(
    stream: &mut TcpStream,
    crypto: Option<&mut HapCrypto>,
    method: &str,
    path: &str,
    protocol: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Result<(), String> {
    let mut msg = format!(
        "{method} {path} {protocol}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra {
        msg.push_str(k);
        msg.push_str(": ");
        msg.push_str(v);
        msg.push_str("\r\n");
    }
    msg.push_str("\r\n");
    let mut out = msg.into_bytes();
    out.extend_from_slice(body);
    let wire = if let Some(c) = crypto {
        c.encrypt(&out)?
    } else {
        out
    };
    stream
        .write_all(&wire)
        .await
        .map_err(|e| format!("event write: {e}"))?;
    stream.flush().await.map_err(|e| format!("event flush: {e}"))
}

async fn write_http(
    stream: &mut TcpStream,
    crypto: Option<&mut HapCrypto>,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "OK",
    };
    let msg = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        body.len()
    );
    let mut out = msg.into_bytes();
    out.extend_from_slice(body);
    let wire = if let Some(c) = crypto {
        c.encrypt(&out)?
    } else {
        out
    };
    stream
        .write_all(&wire)
        .await
        .map_err(|e| format!("event write: {e}"))?;
    stream.flush().await.map_err(|e| format!("event flush: {e}"))
}

pub fn parse_fcup_event(body: &[u8], content_type: &str) -> Option<FcupNeed> {
    if body.starts_with(b"bplist") || content_type.contains("binary-plist") {
        let val = bplist::from_binary(body).ok()?;
        return fcup_from_plist(&val);
    }
    let text = std::str::from_utf8(body).ok()?;
    if text.contains("<plist") || content_type.contains("plist") || text.contains("FCUP") {
        return fcup_from_xml(text);
    }
    fcup_from_xml(text)
}

fn fcup_from_plist(val: &PlistValue) -> Option<FcupNeed> {
    let PlistValue::Dict(root) = val else {
        return None;
    };
    let type_name = dict_string(root, "type").unwrap_or_default();
    let mut url = dict_string(root, "FCUP_Response_URL");
    let mut request_id = dict_int(root, "FCUP_Response_RequestID").unwrap_or(0);
    if let Some(PlistValue::Dict(req)) = dict_get(root, "request") {
        if url.is_none() {
            url = dict_string(req, "FCUP_Response_URL");
        }
        if request_id == 0 {
            request_id = dict_int(req, "FCUP_Response_RequestID").unwrap_or(0);
        }
        if let Some(PlistValue::Dict(params)) = dict_get(req, "params") {
            if url.is_none() {
                url = dict_string(params, "FCUP_Response_URL");
            }
        }
    }
    if let Some(PlistValue::Dict(params)) = dict_get(root, "params") {
        if url.is_none() {
            url = dict_string(params, "FCUP_Response_URL");
        }
        if request_id == 0 {
            request_id = dict_int(params, "FCUP_Response_RequestID").unwrap_or(0);
        }
    }
    let url = url?;
    let is_fcup = type_name.contains("unhandledURLRequest")
        || type_name.to_ascii_lowercase().contains("fcup")
        || url.contains("m3u8")
        || url.contains("mlhls");
    if !is_fcup {
        return None;
    }
    Some(FcupNeed { url, request_id })
}

fn fcup_from_xml(xml: &str) -> Option<FcupNeed> {
    let type_name = xml_string(xml, "type").unwrap_or_default();
    let url = xml_string(xml, "FCUP_Response_URL")?;
    let request_id = xml_int(xml, "FCUP_Response_RequestID").unwrap_or(0);
    let is_fcup = type_name.contains("unhandledURLRequest")
        || type_name.to_ascii_lowercase().contains("fcup")
        || url.contains("m3u8")
        || url.contains("mlhls");
    if !is_fcup {
        return None;
    }
    Some(FcupNeed { url, request_id })
}

fn xml_string(xml: &str, key: &str) -> Option<String> {
    let tag = format!("<key>{key}</key>");
    let idx = xml.find(&tag)?;
    let rest = xml[idx + tag.len()..].trim_start();
    let inner = rest.strip_prefix("<string>")?;
    let end = inner.find("</string>")?;
    Some(inner[..end].to_string())
}

fn xml_int(xml: &str, key: &str) -> Option<i64> {
    let tag = format!("<key>{key}</key>");
    let idx = xml.find(&tag)?;
    let rest = xml[idx + tag.len()..].trim_start();
    let inner = rest.strip_prefix("<integer>")?;
    let end = inner.find("</integer>")?;
    inner[..end].trim().parse().ok()
}

fn event_body_keys(body: &[u8], content_type: &str) -> Vec<String> {
    if body.starts_with(b"bplist") || content_type.contains("binary-plist") {
        return bplist::from_binary(body)
            .map(|v| plist_key_names(&v))
            .unwrap_or_default();
    }
    if let Ok(text) = std::str::from_utf8(body) {
        return xml_key_names(text);
    }
    Vec::new()
}

fn xml_key_names(xml: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<key>") {
        rest = &rest[i + 5..];
        if let Some(end) = rest.find("</key>") {
            let k = rest[..end].trim();
            if !k.is_empty() && !keys.iter().any(|e: &String| e == k) {
                keys.push(k.to_string());
            }
            rest = &rest[end + 6..];
        } else {
            break;
        }
    }
    keys
}

pub fn plist_key_names(val: &PlistValue) -> Vec<String> {
    let mut keys = Vec::new();
    walk_keys(val, &mut keys);
    keys
}

fn walk_keys(val: &PlistValue, out: &mut Vec<String>) {
    match val {
        PlistValue::Dict(pairs) => {
            for (k, v) in pairs {
                if !out.iter().any(|e| e == k) {
                    out.push(k.clone());
                }
                walk_keys(v, out);
            }
        }
        PlistValue::Array(items) => {
            for item in items {
                walk_keys(item, out);
            }
        }
        _ => {}
    }
}

fn dict_get<'a>(pairs: &'a [(String, PlistValue)], key: &str) -> Option<&'a PlistValue> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn dict_string(pairs: &[(String, PlistValue)], key: &str) -> Option<String> {
    match dict_get(pairs, key) {
        Some(PlistValue::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn dict_int(pairs: &[(String, PlistValue)], key: &str) -> Option<i64> {
    match dict_get(pairs, key) {
        Some(PlistValue::Integer(n)) => Some(*n),
        Some(PlistValue::Real(r)) if r.is_finite() => Some(*r as i64),
        _ => None,
    }
}

/// Map a FCUP / reverse URL to a local HLS asset name.
pub fn asset_name_from_url(url: &str) -> Option<String> {
    let path = url.split('?').next().unwrap_or(url);
    if path.contains("..") {
        return None;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    hls::hls_safe_name(name).map(|s| s.to_string())
}

pub fn load_hls_asset(hls: &HlsOrigin, url_or_path: &str) -> Option<(Vec<u8>, &'static str)> {
    let name = asset_name_from_url(url_or_path)?;
    let mime = hls::hls_content_type(&name)?;
    let path = hls.dir.join(&name);
    let bytes = std::fs::read(&path).ok()?;
    if name.ends_with(".m3u8") {
        let text = String::from_utf8_lossy(&bytes);
        let rewritten = rewrite_playlist_uris(&text, &hls.origin);
        return Some((rewritten.into_bytes(), mime));
    }
    Some((bytes, mime))
}

pub fn rewrite_playlist_uris(playlist: &str, origin: &str) -> String {
    let origin = origin.trim_end_matches('/');
    let mut out = String::with_capacity(playlist.len() + 64);
    for (i, line) in playlist.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(line);
            continue;
        }
        if trimmed.contains("://") {
            out.push_str(line);
            continue;
        }
        out.push_str(origin);
        out.push('/');
        out.push_str(trimmed.trim_start_matches('/'));
    }
    if playlist.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// HTTP 200 empty body for a reverse-channel POST.
pub fn build_reverse_upgrade(session_id: &str, device_id: &str) -> Vec<(String, String)> {
    vec![
        ("Upgrade".into(), "PTTH/1.0".into()),
        ("Connection".into(), "Upgrade".into()),
        ("X-Apple-Purpose".into(), "event".into()),
        ("X-Apple-Session-ID".into(), session_id.into()),
        ("X-Apple-Device-ID".into(), device_id.into()),
        ("User-Agent".into(), "AirPlay/550.10".into()),
        ("X-Apple-Client-Name".into(), "omacast".into()),
    ]
}

pub fn is_hls_location(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.contains(".m3u8") || lower.starts_with("mlhls://")
}

#[allow(dead_code)]
pub fn hls_dir_exists(dir: &Path) -> bool {
    dir.is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bplist::{encode_fcup_request, encode_fcup_response, from_binary};

    #[test]
    fn looks_like_rtsp_status_and_post() {
        assert!(looks_like_http(b"RTSP/1.0 200 OK\r\n"));
        assert!(looks_like_http(b"POST /event HTTP/1.1\r\n"));
        assert!(looks_like_http(b"HTTP/1.1 101 Switching\r\n"));
        assert!(!looks_like_http(b"bplist00"));
    }

    #[test]
    fn rewrite_relative_and_leave_absolute() {
        let pl = "#EXTM3U\n#EXTINF:2,\nout0.ts\nhttp://ex/a.ts\n";
        let got = rewrite_playlist_uris(pl, "http://192.0.2.10:9");
        assert!(got.contains("http://192.0.2.10:9/out0.ts"));
        assert!(got.contains("http://ex/a.ts"));
        assert!(got.contains("#EXTM3U"));
    }

    #[test]
    fn asset_name_from_mlhls_and_http() {
        assert_eq!(
            asset_name_from_url("mlhls://localhost/master.m3u8"),
            Some("master.m3u8".into())
        );
        assert_eq!(
            asset_name_from_url("http://192.0.2.1:8/out.m3u8?x=1"),
            Some("out.m3u8".into())
        );
        assert_eq!(asset_name_from_url("../x"), None);
    }

    #[test]
    fn parse_fcup_from_xml() {
        let xml = r#"<?xml version="1.0"?>
<plist><dict>
<key>sessionID</key><integer>1</integer>
<key>type</key><string>unhandledURLRequest</string>
<key>request</key><dict>
<key>FCUP_Response_RequestID</key><integer>3</integer>
<key>FCUP_Response_URL</key><string>mlhls://localhost/master.m3u8</string>
</dict>
</dict></plist>"#;
        let need = parse_fcup_event(xml.as_bytes(), "text/x-apple-plist+xml").unwrap();
        assert_eq!(need.url, "mlhls://localhost/master.m3u8");
        assert_eq!(need.request_id, 3);
    }

    #[test]
    fn parse_fcup_from_binary() {
        let bytes = encode_fcup_request("mlhls://localhost/out.m3u8", 7, "sess");
        let need = parse_fcup_event(&bytes, "application/x-apple-binary-plist").unwrap();
        assert_eq!(need.url, "mlhls://localhost/out.m3u8");
        assert_eq!(need.request_id, 7);
        let keys = event_body_keys(&bytes, "application/x-apple-binary-plist");
        assert!(keys.iter().any(|k| k == "type"));
        assert!(keys.iter().any(|k| k == "FCUP_Response_URL"));
    }

    #[test]
    fn fcup_response_roundtrip_has_data() {
        let bytes = encode_fcup_response("mlhls://localhost/master.m3u8", 1, b"#EXTM3U\n", 200);
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not dict");
        };
        assert_eq!(
            dict_get(&pairs, "type"),
            Some(&PlistValue::String("unhandledURLResponse".into()))
        );
        let Some(PlistValue::Dict(params)) = dict_get(&pairs, "params") else {
            panic!("params");
        };
        assert_eq!(
            dict_get(params, "FCUP_Response_URL"),
            Some(&PlistValue::String("mlhls://localhost/master.m3u8".into()))
        );
        assert_eq!(
            dict_get(params, "FCUP_Response_Data"),
            Some(&PlistValue::Data(b"#EXTM3U\n".to_vec()))
        );
        assert_eq!(
            dict_get(params, "FCUP_Response_StatusCode"),
            Some(&PlistValue::Integer(200))
        );
        assert_eq!(
            dict_get(params, "FCUP_Response_RequestID"),
            Some(&PlistValue::Integer(1))
        );
    }

    #[test]
    fn is_hls_location_mlhls_and_m3u8() {
        assert!(is_hls_location("mlhls://localhost/master.m3u8"));
        assert!(is_hls_location("http://192.0.2.1/master.m3u8"));
        assert!(!is_hls_location("http://192.0.2.1/media.mkv"));
    }
}

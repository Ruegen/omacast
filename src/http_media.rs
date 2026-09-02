//! Local HTTP file server with Range / 206 Partial Content.
//! Also serves an HLS directory (m3u8 + MPEG-TS) for Video=no HLS=yes TVs.

use crate::app::Error;
use crate::files;
use crate::hls::{self, HlsSession};
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;

/// Inclusive byte range `(start, end)` within a file of `file_size` bytes.
///
/// Accepts a single `bytes=` range: `start-end`, `start-`, or `-suffix`.
/// Returns `None` when the header is missing, malformed, or unsatisfiable.
pub fn parse_byte_range(header: &str, file_size: u64) -> Option<(u64, u64)> {
    if file_size == 0 {
        return None;
    }
    let spec = header.trim();
    let spec = spec.strip_prefix("bytes=")?.trim();
    let spec = spec.split(',').next()?.trim();
    if spec.is_empty() {
        return None;
    }

    if let Some(suffix) = spec.strip_prefix('-') {
        let n: u64 = suffix.parse().ok()?;
        if n == 0 {
            return None;
        }
        let start = file_size.saturating_sub(n);
        return Some((start, file_size - 1));
    }

    let (start_s, end_s) = spec.split_once('-')?;
    let start: u64 = start_s.parse().ok()?;
    if start >= file_size {
        return None;
    }
    let end = if end_s.is_empty() {
        file_size - 1
    } else {
        end_s.parse::<u64>().ok()?.min(file_size - 1)
    };
    if end < start {
        return None;
    }
    Some((start, end))
}

fn lan_ipv4() -> Result<Ipv4Addr, Error> {
    let mut candidates: Vec<Ipv4Addr> = Vec::new();
    if let Ok(ifaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in ifaces {
            let lname = name.to_ascii_lowercase();
            if lname == "lo"
                || lname.starts_with("lo")
                || lname.starts_with("docker")
                || lname.starts_with("br-")
                || lname.starts_with("veth")
                || lname.starts_with("virbr")
            {
                continue;
            }
            if let std::net::IpAddr::V4(v4) = ip {
                if v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    || v4.is_link_local()
                {
                    continue;
                }
                candidates.push(v4);
            }
        }
    }

    if let Some(ip) = candidates.iter().copied().find(Ipv4Addr::is_private) {
        return Ok(ip);
    }
    if let Some(ip) = candidates.first().copied() {
        return Ok(ip);
    }

    match local_ip_address::local_ip() {
        Ok(std::net::IpAddr::V4(v4)) if !v4.is_loopback() && !v4.is_link_local() => Ok(v4),
        _ => Err(Error::NoLanIp),
    }
}

#[derive(Clone)]
struct MediaState {
    path: Arc<PathBuf>,
    hls: bool,
    lan_ip: Ipv4Addr,
    gets: Arc<AtomicU64>,
}

/// Running media server. Dropping it (or calling [`shutdown`](Self::shutdown))
/// stops accepting new requests.
pub struct MediaServer {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    pub port: u16,
    pub lan_ip: Ipv4Addr,
    ext: &'static str,
    hls: Option<HlsSession>,
    gets: Arc<AtomicU64>,
}

impl MediaServer {
    pub async fn start(path: PathBuf, bind_port: u16) -> Result<Self, Error> {
        Self::bind(path, bind_port, None).await
    }

    pub async fn start_hls(path: PathBuf, bind_port: u16) -> Result<Self, Error> {
        let session = HlsSession::start(&path).await.map_err(Error::Hls)?;
        let dir = session.dir.clone();
        Self::bind(dir, bind_port, Some(session)).await
    }

    pub async fn start_for(path: PathBuf, bind_port: u16, hls: bool) -> Result<Self, Error> {
        if hls {
            Self::start_hls(path, bind_port).await
        } else {
            Self::start(path, bind_port).await
        }
    }

    async fn bind(path: PathBuf, bind_port: u16, hls: Option<HlsSession>) -> Result<Self, Error> {
        let lan_ip = lan_ipv4()?;
        let ext = files::media_ext(&path);
        let listener = TcpListener::bind(("0.0.0.0", bind_port)).await?;
        let port = listener.local_addr()?.port();
        let gets = Arc::new(AtomicU64::new(0));
        let is_hls = hls.is_some();

        let state = MediaState {
            path: Arc::new(path),
            hls: is_hls,
            lan_ip,
            gets: gets.clone(),
        };
        let app = if is_hls {
            Router::new()
                .fallback(serve_media)
                .with_state(state)
        } else {
            Router::new()
                .route("/media", get(serve_media).head(serve_media))
                .route("/media.mp4", get(serve_media).head(serve_media))
                .route("/media.mkv", get(serve_media).head(serve_media))
                .route("/media.mov", get(serve_media).head(serve_media))
                .with_state(state)
        };

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
        });

        Ok(Self {
            shutdown: Some(tx),
            port,
            lan_ip,
            ext,
            hls,
            gets,
        })
    }

    /// URL the AirPlay receiver must fetch. Always a LAN IPv4, never loopback.
    pub fn content_location(&self) -> String {
        if let Some(hls) = &self.hls {
            format!("http://{}:{}/{}", self.lan_ip, self.port, hls.playlist)
        } else {
            format!("http://{}:{}/media.{}", self.lan_ip, self.port, self.ext)
        }
    }

    pub fn request_count(&self) -> Arc<AtomicU64> {
        self.gets.clone()
    }

    pub fn origin(&self) -> String {
        format!("http://{}:{}", self.lan_ip, self.port)
    }

    pub fn hls_dir(&self) -> Option<std::path::PathBuf> {
        self.hls.as_ref().map(|h| h.dir.clone())
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.hls = None;
    }
}

impl Drop for MediaServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn is_remote_hls_peer(ip: std::net::IpAddr, lan_ip: Ipv4Addr) -> bool {
    if ip.is_loopback() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) if v4 == lan_ip => false,
        _ => true,
    }
}

fn apply_cors(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, HEAD, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
    resp
}

fn log_media_request(
    method: &Method,
    path: &str,
    range: Option<&str>,
    peer: &str,
    status: StatusCode,
) {
    let mut line = format!("media {method} {path}");
    if let Some(range) = range.filter(|s| !s.is_empty()) {
        line.push_str(" Range=");
        line.push_str(range);
    }
    if !peer.is_empty() {
        line.push_str(" peer=");
        line.push_str(peer);
    }
    line.push(' ');
    line.push_str(&status.as_u16().to_string());
    crate::airplay::debug_log(&line);
}

async fn serve_media(
    method: Method,
    uri: Uri,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<MediaState>,
) -> Response {
    if method == Method::OPTIONS {
        return apply_cors(StatusCode::NO_CONTENT.into_response());
    }

    let path = uri.path().to_string();
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .map(str::to_string);
    let peer = addr.ip().to_string();
    let response = serve_media_body(method.clone(), uri, headers, state.clone()).await;
    let status = response.status();
    log_media_request(&method, &path, range.as_deref(), &peer, status);
    if (method == Method::GET || method == Method::HEAD)
        && status.is_success()
        && state.hls
        && hls::is_hls_asset(&path)
        && is_remote_hls_peer(addr.ip(), state.lan_ip)
    {
        state.gets.fetch_add(1, Ordering::Relaxed);
    }
    apply_cors(response)
}

async fn serve_media_body(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    state: MediaState,
) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let (file_path, content_type) = if state.hls {
        let Some(name) = hls::hls_safe_name(uri.path()) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let Some(content_type) = hls::hls_content_type(name) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        (state.path.join(name), content_type)
    } else {
        (state.path.as_ref().clone(), files::content_type_for(state.path.as_ref()))
    };

    serve_file(method, headers, &file_path, content_type).await
}

async fn serve_file(
    method: Method,
    headers: HeaderMap,
    path: &Path,
    content_type: &'static str,
) -> Response {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let meta = match file.metadata().await {
        Ok(meta) => meta,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let file_size = meta.len();

    let range_header = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::trim);

    let selected = match range_header {
        Some(raw) if raw.starts_with("bytes=") => match parse_byte_range(raw, file_size) {
            Some(range) => Some(range),
            None => {
                return (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [
                        (header::CONTENT_RANGE, format!("bytes */{file_size}")),
                        (header::ACCEPT_RANGES, "bytes".to_string()),
                        (header::CONTENT_LENGTH, "0".to_string()),
                    ],
                )
                    .into_response();
            }
        },
        _ => None,
    };

    let (status, start, end) = match selected {
        Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end),
        None => {
            if file_size == 0 {
                return empty_ok(content_type);
            }
            (StatusCode::OK, 0, file_size.saturating_sub(1))
        }
    };

    let length = end.saturating_sub(start).saturating_add(1);
    let mut builder = Response::builder()
        .status(status)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, length.to_string())
        .header(header::CONNECTION, "keep-alive")
        .header(header::CACHE_CONTROL, "no-cache");

    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{file_size}"),
        );
    }

    if method == Method::HEAD {
        return builder
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let mut file = file;
    if let Err(_) = file.seek(std::io::SeekFrom::Start(start)).await {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let stream = ReaderStream::new(file.take(length));
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn empty_ok(content_type: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::ACCEPT_RANGES, "bytes"),
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_LENGTH, "0"),
            (header::CONNECTION, "keep-alive"),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{is_remote_hls_peer, parse_byte_range};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn remote_hls_peer_skips_self_and_loopback() {
        let lan = Ipv4Addr::new(192, 168, 178, 31);
        assert!(!is_remote_hls_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), lan));
        assert!(!is_remote_hls_peer(IpAddr::V4(lan), lan));
        assert!(is_remote_hls_peer(
            IpAddr::V4(Ipv4Addr::new(192, 168, 178, 25)),
            lan
        ));
    }

    #[test]
    fn range_open_end() {
        assert_eq!(parse_byte_range("bytes=0-", 100), Some((0, 99)));
        assert_eq!(parse_byte_range("bytes=50-", 100), Some((50, 99)));
    }

    #[test]
    fn range_closed() {
        assert_eq!(parse_byte_range("bytes=10-19", 100), Some((10, 19)));
        assert_eq!(parse_byte_range(" bytes=0-0 ", 100), Some((0, 0)));
    }

    #[test]
    fn range_suffix() {
        assert_eq!(parse_byte_range("bytes=-10", 100), Some((90, 99)));
        assert_eq!(parse_byte_range("bytes=-1", 100), Some((99, 99)));
    }

    #[test]
    fn range_clips_end() {
        assert_eq!(parse_byte_range("bytes=90-999", 100), Some((90, 99)));
    }

    #[test]
    fn range_unsatisfiable_or_invalid() {
        assert_eq!(parse_byte_range("bytes=100-200", 100), None);
        assert_eq!(parse_byte_range("bytes=20-10", 100), None);
        assert_eq!(parse_byte_range("bytes=-0", 100), None);
        assert_eq!(parse_byte_range("bytes=", 100), None);
        assert_eq!(parse_byte_range("items=0-1", 100), None);
        assert_eq!(parse_byte_range("bytes=0-1", 0), None);
    }
}

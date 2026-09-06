//! Chromecast play: HTTP file + Cast v2 LOAD (picture + sound).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::process::Command;
use tokio::sync::oneshot;

use crate::cast::CastConn;
use crate::http_media::MediaServer;

pub struct CastSession {
    stop: Option<oneshot::Sender<()>>,
    finished: Arc<AtomicBool>,
    server: Option<MediaServer>,
    tmp: Option<PathBuf>,
}

impl CastSession {
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Relaxed)
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(mut server) = self.server.take() {
            server.shutdown();
        }
        if let Some(tmp) = self.tmp.take() {
            let _ = tokio::fs::remove_file(tmp).await;
        }
    }
}

impl Drop for CastSession {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(mut server) = self.server.take() {
            server.shutdown();
        }
        if let Some(tmp) = self.tmp.take() {
            let _ = std::fs::remove_file(tmp);
        }
    }
}

pub async fn probe_duration(path: &Path) -> f64 {
    let out = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "csv=p=0",
        ])
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .ok();
    let Some(out) = out else {
        return 0.0;
    };
    if !out.status.success() {
        return 0.0;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|d| d.is_finite() && *d > 0.0)
        .unwrap_or(0.0)
}

pub async fn start_cast(
    ip: &str,
    port: u16,
    file: &Path,
    media_port: u16,
    start: f64,
) -> Result<(CastSession, f64), String> {
    let duration = probe_duration(file).await;
    let source = decide_cast_source(file).await;
    let slug = uuid::Uuid::new_v4().simple().to_string();
    let server = match bind_on_open_port(file.to_path_buf(), media_port, ip, &slug, source, start)
        .await
    {
        Ok(s) => s,
        Err(err) => return Err(err),
    };
    let url = server.content_location();
    let stream_type = if server.is_live() { "LIVE" } else { "BUFFERED" };
    crate::airplay::debug_log(&format!(
        "chromecast LOAD {url} {stream_type} -> {ip}:{port}"
    ));

    let mut conn = CastConn::connect(ip, port).await?;
    if let Err(err) = conn
        .launch_and_load(&url, "video/mp4", stream_type, start)
        .await
    {
        drop(server);
        return Err(err);
    }

    let finished = Arc::new(AtomicBool::new(false));
    let (stop_tx, stop_rx) = oneshot::channel();
    let flag = finished.clone();
    tokio::spawn(async move {
        conn.pump_until_idle(stop_rx).await;
        flag.store(true, Ordering::Relaxed);
    });

    if !wait_for_remote_get(&server, Duration::from_secs(10)).await {
        let _ = stop_tx.send(());
        drop(server);
        return Err(
            "Chromecast could not fetch the file from this PC (inbound TCP still blocked)."
                .to_string(),
        );
    }

    Ok((
        CastSession {
            stop: Some(stop_tx),
            finished,
            server: Some(server),
            tmp: None,
        },
        duration,
    ))
}

pub async fn start_cast_desktop(
    ip: &str,
    port: u16,
    media_port: u16,
) -> Result<(CastSession, f64), String> {
    let slug = uuid::Uuid::new_v4().simple().to_string();
    let dummy = crate::capture::desktop_path();
    let server = bind_on_open_port(
        dummy,
        media_port,
        ip,
        &slug,
        CastSource::Desktop,
        0.0,
    )
    .await?;
    let url = server.content_location();
    crate::airplay::debug_log(&format!(
        "chromecast LOAD desktop {url} LIVE -> {ip}:{port}"
    ));

    let mut conn = CastConn::connect(ip, port).await?;
    if let Err(err) = conn
        .launch_and_load(&url, "video/mp4", "LIVE", 0.0)
        .await
    {
        drop(server);
        return Err(err);
    }

    let finished = Arc::new(AtomicBool::new(false));
    let (stop_tx, stop_rx) = oneshot::channel();
    let flag = finished.clone();
    tokio::spawn(async move {
        conn.pump_until_idle(stop_rx).await;
        flag.store(true, Ordering::Relaxed);
    });

    if !wait_for_remote_get(&server, Duration::from_secs(15)).await {
        let _ = stop_tx.send(());
        drop(server);
        return Err("Chromecast did not fetch the desktop stream.".to_string());
    }

    Ok((
        CastSession {
            stop: Some(stop_tx),
            finished,
            server: Some(server),
            tmp: None,
        },
        0.0,
    ))
}

async fn bind_on_open_port(
    path: PathBuf,
    requested: u16,
    from_ip: &str,
    slug: &str,
    source: CastSource,
    start: f64,
) -> Result<MediaServer, String> {
    let mut ports = Vec::new();
    if requested != 0 {
        ports.push(requested);
    }
    ports.extend(already_open_tcp_ports(from_ip));
    if ports.is_empty() {
        ports.push(53317);
    }
    let mut last = "no inbound TCP port already open for the dongle".to_string();
    let mut tried = std::collections::HashSet::new();
    for port in ports {
        if !tried.insert(port) {
            continue;
        }
        let started = match source {
            CastSource::File => MediaServer::start_unique(path.clone(), port, slug.to_string()).await,
            CastSource::LiveCopyVideo => {
                MediaServer::start_live_unique(path.clone(), port, slug.to_string(), true, start)
                    .await
            }
            CastSource::LiveTranscode => {
                MediaServer::start_live_unique(path.clone(), port, slug.to_string(), false, start)
                    .await
            }
            CastSource::Desktop => MediaServer::start_desktop_unique(port, slug.to_string()).await,
        };
        match started {
            Ok(server) => {
                crate::airplay::debug_log(&format!(
                    "chromecast HTTP :{} (already allowed for {from_ip})",
                    server.port
                ));
                return Ok(server);
            }
            Err(err) => last = format!(":{port} {err}"),
        }
    }
    Err(format!("media server: {last}"))
}

/// Ports UFW already accepts from this Chromecast. Prefer LocalSend (53317);
/// skip SSH/RDP unless nothing else is listed.
fn already_open_tcp_ports(from_ip: &str) -> Vec<u16> {
    let mut ports = allowed_tcp_ports(from_ip);
    ports.sort();
    ports.dedup();
    let mut first = Vec::new();
    let mut later = Vec::new();
    for p in ports {
        if p == 22 || p == 3389 {
            later.push(p);
        } else {
            first.push(p);
        }
    }
    if first.iter().any(|p| *p == 53317) {
        first.retain(|p| *p != 53317);
        first.insert(0, 53317);
    }
    first.extend(later);
    first
}

fn allowed_tcp_ports(from_ip: &str) -> Vec<u16> {
    let Ok(text) = std::fs::read_to_string("/etc/ufw/user.rules") else {
        return vec![53317];
    };
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains("ufw-user-input") || !line.contains("-p tcp") || !line.contains("-j ACCEPT")
        {
            continue;
        }
        if let Some(src) = line_source(line) {
            if !source_matches(&src, from_ip) {
                continue;
            }
        }
        out.extend(line_ports(line));
    }
    if out.is_empty() {
        out.push(53317);
    }
    out
}

fn line_ports(line: &str) -> Vec<u16> {
    if let Some(rest) = line.split("--dport ").nth(1) {
        return port_spec_list(rest.split_whitespace().next().unwrap_or(""));
    }
    if let Some(rest) = line.split("--dports ").nth(1) {
        return port_spec_list(rest.split_whitespace().next().unwrap_or(""));
    }
    Vec::new()
}

fn port_spec_list(spec: &str) -> Vec<u16> {
    if let Some((a, b)) = spec.split_once(':') {
        let Ok(lo) = a.parse::<u16>() else {
            return Vec::new();
        };
        let Ok(hi) = b.parse::<u16>() else {
            return Vec::new();
        };
        if hi < lo || hi - lo > 32 {
            return Vec::new();
        }
        return (lo..=hi).collect();
    }
    spec.parse::<u16>().ok().into_iter().collect()
}

fn line_source(line: &str) -> Option<String> {
    let rest = line.split(" -s ").nth(1)?;
    Some(rest.split_whitespace().next()?.to_string())
}

fn source_matches(src: &str, ip: &str) -> bool {
    if src == "0.0.0.0/0" || src == ip {
        return true;
    }
    if let Some((base, bits)) = src.split_once('/') {
        let Ok(bits) = bits.parse::<u32>() else {
            return false;
        };
        if bits == 0 {
            return true;
        }
        let Ok(net) = base.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        let shift = 32u32.saturating_sub(bits);
        let mask = if bits == 0 { 0 } else { u32::MAX << shift };
        return (u32::from(net) & mask) == (u32::from(addr) & mask);
    }
    false
}

async fn wait_for_remote_get(server: &MediaServer, timeout: Duration) -> bool {
    let gets = server.request_count();
    let start = tokio::time::Instant::now();
    while start.elapsed() < timeout {
        if gets.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            crate::airplay::debug_log("chromecast fetched media");
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    crate::airplay::debug_log("chromecast GET timeout (no fetch)");
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CastSource {
    File,
    LiveCopyVideo,
    LiveTranscode,
    Desktop,
}

async fn decide_cast_source(path: &Path) -> CastSource {
    let info = probe_streams(path).await;
    let ok_video = info.video == "h264";
    let ok_audio = audio_ok_for_cast(&info.audio, info.channels);
    let ok_size = info.width > 0 && info.width <= 1920 && info.height <= 1080;
    let is_mp4 = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("mp4"));
    let faststart = moov_before_mdat(path).await;
    if is_mp4 && ok_video && ok_audio && ok_size && faststart {
        return CastSource::File;
    }
    if ok_video && ok_size {
        crate::airplay::debug_log(&format!(
            "chromecast live copy-video, audio {} ch={}",
            info.audio, info.channels
        ));
        return CastSource::LiveCopyVideo;
    }
    crate::airplay::debug_log("chromecast live transcode");
    CastSource::LiveTranscode
}

fn audio_ok_for_cast(codec: &str, channels: u32) -> bool {
    codec.is_empty() || (codec == "aac" && channels > 0 && channels <= 2)
}

struct Probe {
    video: String,
    audio: String,
    width: u32,
    height: u32,
    channels: u32,
}

async fn probe_streams(path: &Path) -> Probe {
    let mut probe = Probe {
        video: String::new(),
        audio: String::new(),
        width: 0,
        height: 0,
        channels: 0,
    };
    let out = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "stream=codec_type,codec_name,width,height,channels",
            "-of",
            "csv=p=0",
        ])
        .arg(path)
        .output()
        .await
        .ok();
    let Some(out) = out else {
        return probe;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 2 {
            continue;
        }
        // csv order can vary; look for known tokens
        if line.contains("video") || parts.iter().any(|p| *p == "h264" || *p == "hevc") {
            if let Some(name) = parts.iter().find(|p| {
                matches!(
                    **p,
                    "h264" | "hevc" | "av1" | "vp9" | "mpeg4" | "mpeg2video"
                )
            }) {
                probe.video = (*name).to_string();
            }
            for p in &parts {
                if let Ok(n) = p.parse::<u32>() {
                    if n >= 16 {
                        if probe.width == 0 {
                            probe.width = n;
                        } else if probe.height == 0 {
                            probe.height = n;
                        }
                    }
                }
            }
        }
        if line.contains("audio")
            || parts
                .iter()
                .any(|p| matches!(*p, "aac" | "ac3" | "eac3" | "mp3" | "opus"))
        {
            if let Some(name) = parts
                .iter()
                .find(|p| matches!(**p, "aac" | "ac3" | "eac3" | "mp3" | "opus"))
            {
                probe.audio = (*name).to_string();
            }
            if let Some(ch) = parts.iter().find_map(|p| {
                p.parse::<u32>()
                    .ok()
                    .filter(|n| (1..=16).contains(n))
            }) {
                probe.channels = ch;
            }
        }
    }
    probe
}

async fn moov_before_mdat(path: &Path) -> bool {
    let Ok(mut file) = tokio::fs::File::open(path).await else {
        return false;
    };
    let mut head = vec![0u8; 2 * 1024 * 1024];
    let n = match tokio::io::AsyncReadExt::read(&mut file, &mut head).await {
        Ok(n) => n,
        Err(_) => return false,
    };
    head.truncate(n);
    let moov = find_box(&head, *b"moov");
    let mdat = find_box(&head, *b"mdat");
    match (moov, mdat) {
        (Some(a), Some(b)) => a < b,
        (Some(_), None) => true,
        _ => false,
    }
}

fn find_box(data: &[u8], kind: [u8; 4]) -> Option<usize> {
    let mut i = 0;
    while i + 8 <= data.len() {
        let size = u32::from_be_bytes(data[i..i + 4].try_into().ok()?) as usize;
        if size < 8 {
            return None;
        }
        if data[i + 4..i + 8] == kind {
            return Some(i);
        }
        i = i.saturating_add(size);
        if size == 0 {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{audio_ok_for_cast, CastSource};

    #[test]
    fn five_one_aac_uses_live_copy_not_file() {
        assert_eq!(
            if audio_ok_for_cast("aac", 6) {
                CastSource::File
            } else {
                CastSource::LiveCopyVideo
            },
            CastSource::LiveCopyVideo
        );
    }

    #[test]
    fn stereo_aac_is_ok_51_is_not() {
        assert!(audio_ok_for_cast("aac", 2));
        assert!(audio_ok_for_cast("aac", 1));
        assert!(!audio_ok_for_cast("aac", 6));
        assert!(!audio_ok_for_cast("ac3", 2));
        assert!(audio_ok_for_cast("", 0));
    }
}

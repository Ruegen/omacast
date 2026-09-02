//! ffmpeg HLS remux/transcode of a local file into a temp directory.
//!
//! Prefers bitstream copy into MPEG-TS HLS. If that fails, transcodes with
//! libx264 + AAC. No GUI window.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

const FFMPEG: &str = "/usr/bin/ffmpeg";

pub struct HlsSession {
    pub dir: PathBuf,
    child: Option<Child>,
    pub playlist: String,
}

impl Drop for HlsSession {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        if self.dir.exists() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

impl HlsSession {
    pub async fn start(input: &Path) -> Result<Self, String> {
        if !Path::new(FFMPEG).is_file() {
            return Err(format!("ffmpeg not found at {FFMPEG}"));
        }
        let dir = hls_temp_dir();
        if dir.exists() {
            let _ = tokio::fs::remove_dir_all(&dir).await;
        }
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| format!("hls dir: {e}"))?;

        match spawn_and_wait_playlist(input, &dir, false).await {
            Ok(child) => {
                crate::airplay::debug_log("hls remux copy");
                let playlist = playlist_name(&dir);
                return Ok(Self {
                    dir,
                    child: Some(child),
                    playlist,
                });
            }
            Err(err) => {
                crate::airplay::debug_log(&format!("hls copy failed, transcoding ({err})"));
                clear_dir(&dir);
            }
        }

        let child = spawn_and_wait_playlist(input, &dir, true).await?;
        crate::airplay::debug_log("hls transcode");
        let playlist = playlist_name(&dir);
        Ok(Self {
            dir,
            child: Some(child),
            playlist,
        })
    }
}

fn hls_temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!("omacast-hls-{}", std::process::id()))
}

fn clear_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let _ = std::fs::remove_dir_all(&path);
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

fn playlist_ready(dir: &Path) -> bool {
    for name in ["master.m3u8", "out.m3u8"] {
        if file_nonempty(&dir.join(name)) {
            return true;
        }
    }
    false
}

fn playlist_name(dir: &Path) -> String {
    if file_nonempty(&dir.join("master.m3u8")) {
        "master.m3u8".into()
    } else {
        "out.m3u8".into()
    }
}

fn file_nonempty(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.len() > 0)
        .unwrap_or(false)
}

/// Simple HLS asset name: no slash, no `..`.
pub fn hls_safe_name(path: &str) -> Option<&str> {
    let name = path.trim_start_matches('/');
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return None;
    }
    Some(name)
}

pub fn hls_content_type(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".m3u8") {
        Some("application/vnd.apple.mpegurl")
    } else if lower.ends_with(".ts") {
        Some("video/mp2t")
    } else {
        None
    }
}

pub fn is_hls_asset(path: &str) -> bool {
    hls_safe_name(path).and_then(hls_content_type).is_some()
}

async fn spawn_and_wait_playlist(
    input: &Path,
    dir: &Path,
    transcode: bool,
) -> Result<Child, String> {
    let mut cmd = Command::new(FFMPEG);
    cmd.kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .current_dir(dir)
        .args(["-nostdin", "-y", "-hide_banner", "-loglevel", "error", "-i"])
        .arg(input);
    if transcode {
        cmd.args([
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-c:a",
            "aac",
            "-ac",
            "2",
        ]);
    } else {
        cmd.args(["-c:v", "copy", "-c:a", "copy"]);
    }
    cmd.args([
        "-f",
        "hls",
        "-hls_time",
        "2",
        "-hls_list_size",
        "0",
        "-hls_flags",
        "independent_segments+program_date_time",
        "-master_pl_name",
        "master.m3u8",
        "out.m3u8",
    ]);

    let mut child = cmd.spawn().map_err(|e| format!("ffmpeg: {e}"))?;
    let mut stderr = child.stderr.take();
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut r) = stderr.take() {
            let _ = r.read_to_end(&mut buf).await;
        }
        String::from_utf8_lossy(&buf)
            .chars()
            .filter(|c| *c != '\0')
            .take(200)
            .collect::<String>()
            .trim()
            .to_string()
    });

    let deadline = Instant::now() + Duration::from_secs(45);
    let mut ready_at: Option<Instant> = None;
    loop {
        if playlist_ready(dir) {
            ready_at.get_or_insert_with(Instant::now);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if playlist_ready(dir) {
                    drop(stderr_task);
                    return Ok(child);
                }
                let err = stderr_task.await.unwrap_or_default();
                let extra = if err.is_empty() {
                    String::new()
                } else {
                    format!(" {err}")
                };
                return Err(format!("ffmpeg {status}{extra}"));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("ffmpeg wait: {e}")),
        }
        if let Some(t) = ready_at {
            if t.elapsed() >= Duration::from_millis(800) {
                drop(stderr_task);
                return Ok(child);
            }
        }
        if Instant::now() > deadline {
            let _ = child.start_kill();
            return Err("ffmpeg hls timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{hls_content_type, hls_safe_name, is_hls_asset};

    #[test]
    fn safe_name_rejects_traversal() {
        assert_eq!(hls_safe_name("/master.m3u8"), Some("master.m3u8"));
        assert_eq!(hls_safe_name("out0.ts"), Some("out0.ts"));
        assert_eq!(hls_safe_name("../etc/passwd"), None);
        assert_eq!(hls_safe_name("a/b.ts"), None);
        assert_eq!(hls_safe_name(""), None);
        assert_eq!(hls_safe_name("/"), None);
    }

    #[test]
    fn content_types_m3u8_and_ts() {
        assert_eq!(
            hls_content_type("master.m3u8"),
            Some("application/vnd.apple.mpegurl")
        );
        assert_eq!(
            hls_content_type("OUT.M3U8"),
            Some("application/vnd.apple.mpegurl")
        );
        assert_eq!(hls_content_type("out0.ts"), Some("video/mp2t"));
        assert_eq!(hls_content_type("clip.mkv"), None);
        assert!(is_hls_asset("/master.m3u8"));
        assert!(is_hls_asset("/out1.ts"));
        assert!(!is_hls_asset("/media.mkv"));
    }
}

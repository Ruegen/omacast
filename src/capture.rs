//! Desktop capture for screen mirroring (Hyprland / gpu-screen-recorder).
//!
//! `-w focused` is window capture and fails on Wayland. `-o -` writes nothing.
//! Use the monitor name and `-o /dev/stdout`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStdout, Command};

const GSR: &str = "/usr/bin/gpu-screen-recorder";
const FFMPEG: &str = "/usr/bin/ffmpeg";
const DESKTOP_SENTINEL: &str = "/__omacast_desktop__";

pub fn desktop_path() -> PathBuf {
    PathBuf::from(DESKTOP_SENTINEL)
}

pub fn is_desktop(path: &Path) -> bool {
    path == Path::new(DESKTOP_SENTINEL)
}

pub fn tools_available() -> bool {
    Path::new(GSR).is_file() && Path::new(FFMPEG).is_file()
}

pub struct DesktopPipe {
    pub ffmpeg: Child,
    pub recorder: Child,
    pub stdout: ChildStdout,
}

enum OutKind {
    AnnexB,
    FragMp4,
}

/// Annex-B H.264 for AirPlay type 110 (video only).
pub fn spawn_h264() -> Result<DesktopPipe, String> {
    spawn_pipeline(false, OutKind::AnnexB)
}

/// Fragmented MP4 for Chromecast LIVE. Silent AAC is required — the default
/// Cast receiver often ignores video-only streams and never even GETs the URL.
pub fn spawn_frag_mp4() -> Result<DesktopPipe, String> {
    spawn_pipeline(false, OutKind::FragMp4)
}

/// gpu-screen-recorder writing MKV to stdout (`-o /dev/stdout`).
pub fn spawn_recorder(audio: bool) -> Result<Child, String> {
    spawn_recorder_keyint(audio, 30)
}

fn spawn_recorder_keyint(audio: bool, keyint: u32) -> Result<Child, String> {
    if !Path::new(GSR).is_file() {
        return Err("gpu-screen-recorder is not installed".into());
    }
    let monitor = monitor_name();
    let mut recorder = Command::new(GSR);
    recorder
        .args(gsr_args(&monitor, audio, keyint))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        recorder.process_group(0);
    }
    let mut recorder = recorder
        .spawn()
        .map_err(|e| format!("gpu-screen-recorder: {e}"))?;
    log_child_stderr("gsr", recorder.stderr.take());
    crate::airplay::debug_log(&format!("desktop capture {monitor} → /dev/stdout"));
    Ok(recorder)
}

/// Attach ffmpeg to an already-running recorder (KMS warm, no encoded backlog).
pub fn spawn_frag_mp4_from(recorder: Child) -> Result<DesktopPipe, String> {
    attach_ffmpeg(recorder, OutKind::FragMp4)
}

fn spawn_pipeline(audio: bool, kind: OutKind) -> Result<DesktopPipe, String> {
    let recorder = spawn_recorder_keyint(audio, 30)?;
    attach_ffmpeg(recorder, kind)
}

fn attach_ffmpeg(mut recorder: Child, kind: OutKind) -> Result<DesktopPipe, String> {
    if !Path::new(FFMPEG).is_file() {
        let _ = recorder.start_kill();
        return Err("ffmpeg is not installed".into());
    }

    let rec_out = recorder
        .stdout
        .take()
        .ok_or_else(|| "gpu-screen-recorder: no stdout".to_string())?;
    let rec_fd = rec_out
        .into_owned_fd()
        .map_err(|e| format!("gpu-screen-recorder stdout: {e}"))?;

    let vaapi = match kind {
        OutKind::FragMp4 => vaapi_h264_device(),
        OutKind::AnnexB => None,
    };

    let mut ffmpeg = Command::new(FFMPEG);
    // Default probe — GSR needs ~1s to attach KMS before it writes. A short
    // analyzeduration made Chromecast GET a broken/empty fMP4 (blank TV).
    ffmpeg.args(["-nostdin", "-hide_banner", "-loglevel", "error"]);
    if let Some(dev) = vaapi {
        ffmpeg.args(["-vaapi_device", dev]);
    }
    ffmpeg.args(["-fflags", "+genpts", "-i", "pipe:0"]);
    match kind {
        OutKind::AnnexB => {
            ffmpeg.args([
                "-an",
                "-c:v",
                "copy",
                "-bsf:v",
                "h264_mp4toannexb",
                "-f",
                "h264",
                "pipe:1",
            ]);
        }
        OutKind::FragMp4 => {
            ffmpeg.args([
                "-f",
                "lavfi",
                "-i",
                "anullsrc=channel_layout=stereo:sample_rate=44100",
                "-map",
                "0:v:0",
                "-map",
                "1:a:0",
            ]);
            if let Some(dev) = vaapi {
                crate::airplay::debug_log(&format!("chromecast desktop encode h264_vaapi {dev}"));
                ffmpeg.args([
                    "-vf",
                    "format=nv12,hwupload",
                    "-c:v",
                    "h264_vaapi",
                    "-profile:v",
                    "high",
                    "-level",
                    "41",
                    "-bf",
                    "0",
                    "-g",
                    "15",
                    "-quality",
                    "4",
                ]);
            } else {
                crate::airplay::debug_log("chromecast desktop encode libx264");
                ffmpeg.args([
                    "-c:v",
                    "libx264",
                    "-preset",
                    "ultrafast",
                    "-tune",
                    "zerolatency",
                    "-profile:v",
                    "high",
                    "-level",
                    "4.1",
                    "-pix_fmt",
                    "yuv420p",
                    "-g",
                    "15",
                    "-bf",
                    "0",
                    "-x264-params",
                    "keyint=15:min-keyint=15:scenecut=0:bframes=0:rc-lookahead=0:sync-lookahead=0:sliced-threads=1:mbtree=0",
                ]);
            }
            ffmpeg.args([
                "-c:a",
                "aac",
                "-b:a",
                "64k",
                "-ac",
                "2",
                "-ar",
                "44100",
                "-muxdelay",
                "0",
                "-muxpreload",
                "0",
                "-f",
                "mp4",
                "-movflags",
                "frag_keyframe+empty_moov+default_base_moof",
                "-flush_packets",
                "1",
                "pipe:1",
            ]);
        }
    }
    ffmpeg
        .stdin(Stdio::from(rec_fd))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        ffmpeg.process_group(0);
    }

    let mut ffmpeg = match ffmpeg.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = recorder.start_kill();
            return Err(format!("ffmpeg: {e}"));
        }
    };
    log_child_stderr("ffmpeg-desktop", ffmpeg.stderr.take());
    let stdout = match ffmpeg.stdout.take() {
        Some(s) => s,
        None => {
            let _ = ffmpeg.start_kill();
            let _ = recorder.start_kill();
            return Err("ffmpeg: no stdout".into());
        }
    };
    Ok(DesktopPipe {
        ffmpeg,
        recorder,
        stdout,
    })
}

fn log_child_stderr(tag: &'static str, stderr: Option<tokio::process::ChildStderr>) {
    let Some(mut stderr) = stderr else {
        return;
    };
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut acc = String::new();
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => acc.push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
        for line in acc.lines().take(12) {
            let line = line.trim();
            if !line.is_empty() {
                crate::airplay::debug_log(&format!("{tag}: {line}"));
            }
        }
    });
}

fn monitor_name() -> String {
    let listed = std::process::Command::new(GSR)
        .arg("--list-monitors")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let names: Vec<String> = listed
        .lines()
        .filter_map(|l| l.split('|').next())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
        .collect();
    if let Some(focused) = hypr_focused_monitor() {
        if names.iter().any(|n| n == &focused) {
            return focused;
        }
    }
    names
        .into_iter()
        .next()
        .or_else(hypr_focused_monitor)
        .unwrap_or_else(|| "screen".into())
}

fn hypr_focused_monitor() -> Option<String> {
    let out = std::process::Command::new("hyprctl")
        .args(["monitors", "-j"])
        .output()
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v.as_array()?
        .iter()
        .find(|m| m.get("focused") == Some(&serde_json::Value::Bool(true)))?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

/// `/dev/dri/renderD*` + ffmpeg `h264_vaapi`. Cached. AirPlay still copies GSR.
fn vaapi_h264_device() -> Option<&'static str> {
    static DEV: OnceLock<Option<String>> = OnceLock::new();
    DEV.get_or_init(|| {
        const NODES: &[&str] = &["/dev/dri/renderD128", "/dev/dri/renderD129"];
        let node = NODES.iter().copied().find(|p| Path::new(p).exists())?;
        if !ffmpeg_has_h264_vaapi() {
            return None;
        }
        Some(node.to_string())
    })
    .as_deref()
}

fn ffmpeg_has_h264_vaapi() -> bool {
    std::process::Command::new(FFMPEG)
        .args(["-hide_banner", "-encoders"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("h264_vaapi"))
        .unwrap_or(false)
}

fn gsr_args(monitor: &str, audio: bool, keyint: u32) -> Vec<String> {
    let mut a = vec![
        "-w".into(),
        monitor.into(),
        "-s".into(),
        "1920x1080".into(),
        "-f".into(),
        "30".into(),
        "-k".into(),
        "h264".into(),
        "-c".into(),
        "mkv".into(),
        "-cursor".into(),
        "yes".into(),
        "-keyint".into(),
        keyint.to_string(),
        "-fm".into(),
        "cfr".into(),
        "-fallback-cpu-encoding".into(),
        "yes".into(),
        "-o".into(),
        "/dev/stdout".into(),
    ];
    if audio {
        a.extend([
            "-a".into(),
            "default_output".into(),
            "-ac".into(),
            "aac".into(),
        ]);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::{desktop_path, gsr_args, is_desktop, vaapi_h264_device};

    #[test]
    fn sentinel_path_is_stable() {
        let p = desktop_path();
        assert!(is_desktop(&p));
        assert!(!is_desktop(std::path::Path::new("/home/ruegen/Videos")));
    }

    #[test]
    fn recorder_uses_monitor_and_dev_stdout() {
        let joined = gsr_args("HDMI-A-1", false, 30).join(" ");
        assert!(joined.contains("-w HDMI-A-1"), "{joined}");
        assert!(joined.contains("-s 1920x1080"), "{joined}");
        assert!(joined.contains("-o /dev/stdout"), "{joined}");
        assert!(joined.contains("-keyint 30"), "{joined}");
        assert!(!joined.contains("-w focused"), "{joined}");
        assert!(!joined.contains("-o -"), "{joined}");
        let with_a = gsr_args("HDMI-A-1", true, 15).join(" ");
        assert!(with_a.contains("default_output"), "{with_a}");
        assert!(with_a.contains("-keyint 15"), "{with_a}");
    }

    #[test]
    fn vaapi_detect_does_not_panic() {
        let _ = vaapi_h264_device();
    }
}

//! Desktop capture for screen mirroring (Hyprland / gpu-screen-recorder).
//!
//! `-w focused` is window capture and fails on Wayland. `-o -` writes nothing.
//! Use the monitor name and `-o /dev/stdout`.

use std::path::{Path, PathBuf};
use std::process::Stdio;

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
    if !Path::new(GSR).is_file() {
        return Err("gpu-screen-recorder is not installed".into());
    }
    let monitor = monitor_name();
    let mut recorder = Command::new(GSR);
    recorder
        .args(gsr_args(&monitor, audio))
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

fn spawn_pipeline(audio: bool, kind: OutKind) -> Result<DesktopPipe, String> {
    if !Path::new(FFMPEG).is_file() {
        return Err("ffmpeg is not installed".into());
    }

    let mut recorder = spawn_recorder(audio)?;
    let rec_out = recorder
        .stdout
        .take()
        .ok_or_else(|| "gpu-screen-recorder: no stdout".to_string())?;
    let rec_fd = rec_out
        .into_owned_fd()
        .map_err(|e| format!("gpu-screen-recorder stdout: {e}"))?;

    let mut ffmpeg = Command::new(FFMPEG);
    ffmpeg.args([
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-fflags",
        "+genpts",
        "-i",
        "pipe:0",
    ]);
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
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "-tune",
                "zerolatency",
                "-profile:v",
                "high",
                "-level",
                "4.1",
                "-pix_fmt",
                "yuv420p",
                "-g",
                "30",
                "-bf",
                "0",
                "-c:a",
                "aac",
                "-b:a",
                "64k",
                "-ac",
                "2",
                "-ar",
                "44100",
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

fn gsr_args(monitor: &str, audio: bool) -> Vec<String> {
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
        "30".into(),
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
    use super::{desktop_path, gsr_args, is_desktop};

    #[test]
    fn sentinel_path_is_stable() {
        let p = desktop_path();
        assert!(is_desktop(&p));
        assert!(!is_desktop(std::path::Path::new("/home/ruegen/Videos")));
    }

    #[test]
    fn recorder_uses_monitor_and_dev_stdout() {
        let joined = gsr_args("HDMI-A-1", false).join(" ");
        assert!(joined.contains("-w HDMI-A-1"), "{joined}");
        assert!(joined.contains("-s 1920x1080"), "{joined}");
        assert!(joined.contains("-o /dev/stdout"), "{joined}");
        assert!(!joined.contains("-w focused"), "{joined}");
        assert!(!joined.contains("-o -"), "{joined}");
        let with_a = gsr_args("HDMI-A-1", true).join(" ");
        assert!(with_a.contains("default_output"), "{with_a}");
    }
}

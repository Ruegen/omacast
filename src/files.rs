//! Recursive media scan and name filter across multiple folders.

use std::path::{Path, PathBuf};
use std::process::Command;

const VIDEO_EXTS: &[&str] = &["mp4", "mkv", "mov"];

#[derive(Debug, Clone)]
pub struct MediaFile {
    pub path: PathBuf,
    pub root: PathBuf,
    /// Dim suffix on the file row (`mkv`, `hevc · 5.1`). Cheap first, then ffprobe.
    pub tag: String,
}

impl MediaFile {
    pub fn new(path: PathBuf, root: PathBuf) -> Self {
        let tag = cheap_tag(&path);
        Self { path, root, tag }
    }
}

/// True when the path has a supported video extension (case-insensitive).
pub fn is_video_file(path: &Path) -> bool {
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => ext,
        None => return false,
    };
    let ext = ext.to_ascii_lowercase();
    VIDEO_EXTS.iter().any(|ok| *ok == ext)
}

/// Recursively collect supported video files under every `root`.
/// Directory symlinks are not followed. Hidden names (starting with `.`) are skipped.
pub fn scan_media_dirs(roots: &[PathBuf]) -> Vec<MediaFile> {
    let mut out = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        let mut files = Vec::new();
        walk(root, &mut files);
        for path in files {
            out.push(MediaFile::new(path, root.clone()));
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            if file_type.is_symlink() {
                continue;
            }
            walk(&path, out);
        } else if is_video_file(&path) {
            out.push(path);
        }
    }
}

/// Indices into `files` whose path matches `query` (case-insensitive substring).
pub fn filter_indices(files: &[MediaFile], query: &str) -> Vec<usize> {
    if query.is_empty() {
        return (0..files.len()).collect();
    }
    let needle = query.to_lowercase();
    files
        .iter()
        .enumerate()
        .filter(|(_, f)| f.path.to_string_lossy().to_lowercase().contains(&needle))
        .map(|(i, _)| i)
        .collect()
}

/// Label for the file list: path relative to its configured root.
pub fn display_name(file: &MediaFile, show_root: bool) -> String {
    let rel = file
        .path
        .strip_prefix(&file.root)
        .map(|r| r.display().to_string())
        .unwrap_or_else(|_| file.path.display().to_string());
    if show_root {
        let root_label = file
            .root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.root.display().to_string());
        format!("{root_label}/{rel}")
    } else {
        rel
    }
}

/// Content-Type for a video path.
pub fn content_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("mkv") => "video/x-matroska",
        Some("mov") => "video/quicktime",
        _ => "video/mp4",
    }
}

/// Container-only tag so the list is useful before ffprobe finishes.
pub fn cheap_tag(path: &Path) -> String {
    match media_ext(path) {
        "mkv" => "mkv".into(),
        "mov" => "mov".into(),
        _ => String::new(),
    }
}

/// `mkv · hevc · 5.1` — empty when the file is a typical direct-play MP4.
pub fn format_cast_tag(ext: &str, video: &str, audio: &str, channels: u32) -> String {
    let mut parts: Vec<String> = Vec::new();
    if ext == "mkv" || ext == "mov" {
        parts.push(ext.to_string());
    }
    if matches!(video, "hevc" | "av1" | "vp9") {
        parts.push(video.to_string());
    }
    if channels >= 6 || matches!(audio, "ac3" | "eac3") {
        parts.push("5.1".into());
    }
    parts.join(" · ")
}

/// Blocking ffprobe. Call from `spawn_blocking`.
pub fn probe_cast_tag(path: &Path) -> String {
    let (video, audio, channels) = probe_streams(path);
    format_cast_tag(media_ext(path), &video, &audio, channels)
}

fn probe_streams(path: &Path) -> (String, String, u32) {
    let mut video = String::new();
    let mut audio = String::new();
    let mut channels = 0u32;
    let Ok(out) = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "stream=codec_type,codec_name,channels",
            "-of",
            "csv=p=0",
        ])
        .arg(path)
        .output()
    else {
        return (video, audio, channels);
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 2 {
            continue;
        }
        if line.contains("video")
            || parts
                .iter()
                .any(|p| matches!(*p, "h264" | "hevc" | "av1" | "vp9" | "mpeg4"))
        {
            if let Some(name) = parts
                .iter()
                .find(|p| matches!(**p, "h264" | "hevc" | "av1" | "vp9" | "mpeg4" | "mpeg2video"))
            {
                video = (*name).to_string();
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
                audio = (*name).to_string();
            }
            if let Some(ch) = parts.iter().find_map(|p| {
                p.parse::<u32>().ok().filter(|n| (1..=16).contains(n))
            }) {
                channels = ch;
            }
        }
    }
    (video, audio, channels)
}

/// Lowercase extension without the dot, or "mp4" as a fallback for the URL.
pub fn media_ext(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("mkv") => "mkv",
        Some("mov") => "mov",
        _ => "mp4",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_filter_is_case_insensitive() {
        assert!(is_video_file(Path::new("clip.mp4")));
        assert!(is_video_file(Path::new("clip.MP4")));
        assert!(is_video_file(Path::new("clip.MkV")));
        assert!(is_video_file(Path::new("clip.mov")));
        assert!(!is_video_file(Path::new("clip.avi")));
        assert!(!is_video_file(Path::new("clip.txt")));
        assert!(!is_video_file(Path::new("clip")));
    }

    #[test]
    fn playlist_search_filter() {
        let files = vec![
            MediaFile::new(PathBuf::from("/media/clip.mp4"), PathBuf::from("/media")),
            MediaFile::new(PathBuf::from("/media/beach.mkv"), PathBuf::from("/media")),
            MediaFile::new(PathBuf::from("/media/notes.MOV"), PathBuf::from("/media")),
        ];
        assert_eq!(filter_indices(&files, "").len(), 3);
        assert_eq!(filter_indices(&files, "CLIP"), vec![0]);
        assert_eq!(filter_indices(&files, "beach"), vec![1]);
        assert_eq!(filter_indices(&files, "no"), vec![2]);
        assert!(filter_indices(&files, "missing").is_empty());
        assert_eq!(files[0].tag, "");
        assert_eq!(files[1].tag, "mkv");
        assert_eq!(files[2].tag, "mov");
    }

    #[test]
    fn cast_tags_flag_remux_before_play() {
        assert_eq!(format_cast_tag("mp4", "h264", "aac", 2), "");
        assert_eq!(format_cast_tag("mkv", "h264", "aac", 2), "mkv");
        assert_eq!(format_cast_tag("mkv", "hevc", "aac", 6), "mkv · hevc · 5.1");
        assert_eq!(format_cast_tag("mp4", "hevc", "eac3", 2), "hevc · 5.1");
        assert_eq!(cheap_tag(Path::new("clip.mp4")), "");
        assert_eq!(cheap_tag(Path::new("clip.mkv")), "mkv");
    }
}

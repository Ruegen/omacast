//! Recursive media scan and name filter across multiple folders.

use std::path::{Path, PathBuf};

const VIDEO_EXTS: &[&str] = &["mp4", "mkv", "mov"];

#[derive(Debug, Clone)]
pub struct MediaFile {
    pub path: PathBuf,
    pub root: PathBuf,
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
            out.push(MediaFile {
                path,
                root: root.clone(),
            });
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
            MediaFile {
                path: PathBuf::from("/media/clip.mp4"),
                root: PathBuf::from("/media"),
            },
            MediaFile {
                path: PathBuf::from("/media/beach.mkv"),
                root: PathBuf::from("/media"),
            },
            MediaFile {
                path: PathBuf::from("/media/notes.MOV"),
                root: PathBuf::from("/media"),
            },
        ];
        assert_eq!(filter_indices(&files, "").len(), 3);
        assert_eq!(filter_indices(&files, "CLIP"), vec![0]);
        assert_eq!(filter_indices(&files, "beach"), vec![1]);
        assert_eq!(filter_indices(&files, "no"), vec![2]);
        assert!(filter_indices(&files, "missing").is_empty());
    }
}

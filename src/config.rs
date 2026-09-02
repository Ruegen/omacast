//! App config: multiple media folders in ~/.config/omacast/config.json.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::creds;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub folders: Vec<PathBuf>,
}

pub fn config_path() -> PathBuf {
    creds::config_dir().join("config.json")
}

pub fn load() -> AppConfig {
    let path = config_path();
    let Ok(bytes) = fs::read(&path) else {
        return AppConfig::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(cfg: &AppConfig) -> io::Result<()> {
    creds::ensure_config_dir()?;
    let json = serde_json::to_vec_pretty(cfg).map_err(io::Error::other)?;
    fs::write(config_path(), json)?;
    Ok(())
}

/// `$HOME/Videos` when that directory exists. Never a hardcoded username path.
pub fn default_videos_folder() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let videos = PathBuf::from(home).join("Videos");
    if videos.is_dir() {
        Some(videos)
    } else {
        None
    }
}

/// Expand `~` / `~/…` using $HOME. Relative paths stay relative.
pub fn expand_path(raw: &str) -> PathBuf {
    let raw = raw.trim();
    if raw.is_empty() {
        return PathBuf::new();
    }
    if raw == "~" {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(raw));
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

pub fn paths_equal(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

pub fn contains_folder(folders: &[PathBuf], candidate: &Path) -> bool {
    folders.iter().any(|f| paths_equal(f, candidate))
}

/// Folders to scan: saved list, plus ~/Videos if the list is empty and it exists,
/// plus an optional `--media-dir` for this run (appended, never replacing the list
/// unless it is the only source).
pub fn resolve_folders(cli_media_dir: Option<PathBuf>) -> Vec<PathBuf> {
    let saved = load();
    let mut folders: Vec<PathBuf> = Vec::new();
    for f in saved.folders {
        if !contains_folder(&folders, &f) {
            folders.push(f);
        }
    }
    if folders.is_empty() {
        if let Some(videos) = default_videos_folder() {
            folders.push(videos);
        }
    }
    if let Some(extra) = cli_media_dir {
        if !extra.as_os_str().is_empty() && !contains_folder(&folders, &extra) {
            folders.push(extra);
        }
    }
    folders
}

pub fn persist_folders(folders: &[PathBuf]) -> io::Result<()> {
    save(&AppConfig {
        folders: folders.to_vec(),
    })
}

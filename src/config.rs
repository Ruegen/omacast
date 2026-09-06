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

/// Directory matches for Tab-complete. Paths keep a `~/` prefix when the user typed `~`.
pub fn list_folder_matches(input: &str) -> Vec<String> {
    if input == "~" {
        return vec!["~/".to_string()];
    }
    let Some((disp_parent, name_prefix, fs_parent)) = completion_parts(input) else {
        return Vec::new();
    };
    let Ok(rd) = fs::read_dir(&fs_parent) else {
        return Vec::new();
    };
    let hide_dot = !name_prefix.starts_with('.');
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if hide_dot && name.starts_with('.') {
            continue;
        }
        if !name.starts_with(&name_prefix) {
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false) || entry.path().is_dir();
        if !is_dir {
            continue;
        }
        out.push(join_displayed(&disp_parent, name));
    }
    out.sort();
    out
}

/// Longest shared prefix of match strings (bytes/chars as `str` prefixes).
pub fn common_folder_prefix(matches: &[String]) -> String {
    let Some(first) = matches.first() else {
        return String::new();
    };
    let mut prefix = first.as_str();
    for m in matches.iter().skip(1) {
        let n = prefix
            .chars()
            .zip(m.chars())
            .take_while(|(a, b)| a == b)
            .count();
        prefix = &prefix[..prefix.char_indices().nth(n).map(|(i, _)| i).unwrap_or(prefix.len())];
        if prefix.is_empty() {
            break;
        }
    }
    prefix.to_string()
}

fn completion_parts(input: &str) -> Option<(String, String, PathBuf)> {
    if input.is_empty() {
        let home = expand_path("~");
        if home.as_os_str().is_empty() {
            return None;
        }
        return Some(("~".into(), String::new(), home));
    }
    if input.ends_with('/') {
        let fs = expand_path(input);
        let disp = if input.starts_with('/') && input.chars().all(|c| c == '/') {
            "/".to_string()
        } else {
            input.trim_end_matches('/').to_string()
        };
        return Some((disp, String::new(), fs));
    }
    if let Some((parent, name)) = input.rsplit_once('/') {
        let fs_parent = if parent.is_empty() {
            PathBuf::from("/")
        } else {
            expand_path(parent)
        };
        let disp_parent = parent.to_string();
        return Some((disp_parent, name.to_string(), fs_parent));
    }
    let cwd = std::env::current_dir().ok()?;
    Some((String::new(), input.to_string(), cwd))
}

fn join_displayed(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        format!("{name}/")
    } else if parent == "/" {
        format!("/{name}/")
    } else {
        format!("{parent}/{name}/")
    }
}

#[cfg(test)]
mod tests {
    use super::{common_folder_prefix, join_displayed};

    #[test]
    fn common_prefix_extends_shared_stem() {
        let m = vec![
            "~/Videos/".to_string(),
            "~/VirtualBox/".to_string(),
        ];
        assert_eq!(common_folder_prefix(&m), "~/Vi");
        assert_eq!(common_folder_prefix(&["~/Videos/".into()]), "~/Videos/");
        assert_eq!(common_folder_prefix(&[]), "");
    }

    #[test]
    fn join_keeps_tilde_and_root() {
        assert_eq!(join_displayed("~", "Videos"), "~/Videos/");
        assert_eq!(join_displayed("", "Videos"), "Videos/");
        assert_eq!(join_displayed("/", "home"), "/home/");
    }
}

//! Last playback position per file. Used to offer resume after a quit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::creds;

const MIN_RESUME_SECS: f64 = 15.0;
const END_MARGIN_SECS: f64 = 20.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeEntry {
    pub position: f64,
    #[serde(default)]
    pub duration: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ResumeFile {
    #[serde(default)]
    entries: HashMap<String, ResumeEntry>,
}

fn store_path() -> PathBuf {
    creds::config_dir().join("resume.json")
}

fn key_for(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn load_store() -> ResumeFile {
    let Ok(bytes) = std::fs::read(store_path()) else {
        return ResumeFile::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_store(store: &ResumeFile) {
    let _ = creds::ensure_config_dir();
    if let Ok(json) = serde_json::to_vec_pretty(store) {
        let _ = std::fs::write(store_path(), json);
    }
}

pub fn should_offer(position: f64, duration: f64) -> bool {
    if !position.is_finite() || position < MIN_RESUME_SECS {
        return false;
    }
    if duration.is_finite() && duration > 0.0 && position + END_MARGIN_SECS >= duration {
        return false;
    }
    true
}

pub fn lookup(path: &Path) -> Option<ResumeEntry> {
    let store = load_store();
    store.entries.get(&key_for(path)).cloned().filter(|e| {
        should_offer(e.position, e.duration)
    })
}

pub fn save(path: &Path, position: f64, duration: f64) {
    if !should_offer(position, duration) {
        clear(path);
        return;
    }
    let mut store = load_store();
    store.entries.insert(
        key_for(path),
        ResumeEntry {
            position,
            duration,
        },
    );
    save_store(&store);
}

pub fn clear(path: &Path) {
    let mut store = load_store();
    if store.entries.remove(&key_for(path)).is_some() {
        save_store(&store);
    }
}

#[cfg(test)]
mod tests {
    use super::should_offer;

    #[test]
    fn offer_mid_film_not_start_or_end() {
        assert!(!should_offer(5.0, 9000.0));
        assert!(should_offer(120.0, 9000.0));
        assert!(!should_offer(8990.0, 9000.0));
        assert!(!should_offer(f64::NAN, 100.0));
    }
}

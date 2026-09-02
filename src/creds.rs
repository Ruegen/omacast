//! Persistent HAP pairing keys in ~/.config/omacast/credentials.json.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::hap::HapCredentials;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialStore {
    #[serde(flatten)]
    pub devices: BTreeMap<String, StoredCreds>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCreds {
    pub ltpk: String,
    pub ltsk: String,
    pub atv_id: String,
    pub client_id: String,
}

impl StoredCreds {
    pub fn from_hap(c: &HapCredentials) -> Self {
        Self {
            ltpk: hex::encode(&c.ltpk),
            ltsk: hex::encode(&c.ltsk),
            atv_id: hex::encode(&c.atv_id),
            client_id: hex::encode(&c.client_id),
        }
    }

    pub fn to_hap(&self) -> Result<HapCredentials, String> {
        Ok(HapCredentials {
            ltpk: hex::decode(&self.ltpk).map_err(|e| format!("ltpk: {e}"))?,
            ltsk: hex::decode(&self.ltsk).map_err(|e| format!("ltsk: {e}"))?,
            atv_id: hex::decode(&self.atv_id).map_err(|e| format!("atv_id: {e}"))?,
            client_id: hex::decode(&self.client_id).map_err(|e| format!("client_id: {e}"))?,
        })
    }
}

pub fn config_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = home.join(".config").join("omacast");
    let legacy = home.join(".config").join("aircast");
    if !dir.exists() && legacy.exists() {
        let _ = std::fs::rename(&legacy, &dir);
    }
    dir
}

pub fn credentials_path() -> PathBuf {
    config_dir().join("credentials.json")
}

pub fn ensure_config_dir() -> io::Result<PathBuf> {
    let dir = config_dir();
    if !dir.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&dir)?;
    }
    Ok(dir)
}

pub fn load() -> CredentialStore {
    let path = credentials_path();
    let Ok(bytes) = fs::read(&path) else {
        return CredentialStore::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(store: &CredentialStore) -> io::Result<()> {
    ensure_config_dir()?;
    let path = credentials_path();
    let json = serde_json::to_vec_pretty(store).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        use std::io::Write;
        let mut f = opts.open(&tmp)?;
        f.write_all(&json)?;
        f.write_all(b"\n")?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn lookup(store: &CredentialStore, keys: &[String]) -> Option<HapCredentials> {
    for k in keys {
        if let Some(c) = store.devices.get(k) {
            if let Ok(hap) = c.to_hap() {
                return Some(hap);
            }
        }
    }
    None
}

pub fn insert(store: &mut CredentialStore, key: String, creds: &HapCredentials) {
    store.devices.insert(key, StoredCreds::from_hap(creds));
}

/// Drop saved HAP keys for this device (all lookup keys).
pub fn remove(store: &mut CredentialStore, keys: &[String]) -> bool {
    let mut any = false;
    for k in keys {
        if store.devices.remove(k).is_some() {
            any = true;
        }
    }
    any
}

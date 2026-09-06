//! mDNS browse for AirPlay and Chromecast receivers.

use std::net::IpAddr;

use mdns_sd::{ServiceDaemon, ServiceEvent};
use tokio::sync::mpsc;

use crate::app::Error;

const AIRPLAY_TYPE: &str = "_airplay._tcp.local.";
const CHROMECAST_TYPE: &str = "_googlecast._tcp.local.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    AirPlay,
    Chromecast,
}

impl DeviceKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::AirPlay => "AirPlay",
            Self::Chromecast => "Chromecast",
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AirPlayDevice {
    pub kind: DeviceKind,
    pub fullname: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
    pub deviceid: Option<String>,
    pub features: Option<String>,
    pub flags: Option<String>,
    pub model: Option<String>,
    pub pw: Option<String>,
    pub srcvers: Option<String>,
}

impl AirPlayDevice {
    /// Prefer IPv4; fall back to any address or the hostname.
    pub fn preferred_host(&self) -> String {
        if let Some(v4) = self.addresses.iter().find_map(|ip| match ip {
            IpAddr::V4(v) if !v.is_loopback() && !v.is_unspecified() => Some(*v),
            _ => None,
        }) {
            return v4.to_string();
        }
        if let Some(ip) = self.addresses.iter().find(|ip| match ip {
            IpAddr::V4(v) => !v.is_loopback(),
            IpAddr::V6(v) => !v.is_loopback(),
        }) {
            return ip.to_string();
        }
        self.host.trim_end_matches('.').to_string()
    }

    pub fn addr_label(&self) -> String {
        format!("{}:{}", self.preferred_host(), self.port)
    }

    /// Credential map key: mDNS `deviceid`, else `host:port`.
    pub fn cred_key(&self) -> String {
        self.deviceid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}:{}", self.preferred_host(), self.port))
    }

    pub fn cred_lookup_keys(&self) -> Vec<String> {
        let mut keys = vec![self.cred_key()];
        let hostport = format!("{}:{}", self.preferred_host(), self.port);
        if keys[0] != hostport {
            keys.push(hostport);
        }
        keys
    }

    pub fn is_chromecast(&self) -> bool {
        self.kind == DeviceKind::Chromecast
    }
}

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    Found(AirPlayDevice),
    Removed(String),
    Cleared,
}

pub struct Discovery {
    _daemon: ServiceDaemon,
    refresh_tx: mpsc::UnboundedSender<()>,
    events_rx: mpsc::UnboundedReceiver<DiscoveryEvent>,
}

impl Discovery {
    pub fn start() -> Result<Self, Error> {
        let daemon = ServiceDaemon::new().map_err(|err| Error::Mdns(err.to_string()))?;
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (refresh_tx, mut refresh_rx) = mpsc::unbounded_channel::<()>();
        let daemon_for_task = daemon.clone();

        tokio::spawn(async move {
            loop {
                let airplay = match daemon_for_task.browse(AIRPLAY_TYPE) {
                    Ok(receiver) => receiver,
                    Err(_) => break,
                };
                let chromecast = daemon_for_task.browse(CHROMECAST_TYPE).ok();
                loop {
                    tokio::select! {
                        biased;
                        _ = refresh_rx.recv() => {
                            let _ = daemon_for_task.stop_browse(AIRPLAY_TYPE);
                            let _ = daemon_for_task.stop_browse(CHROMECAST_TYPE);
                            let _ = events_tx.send(DiscoveryEvent::Cleared);
                            break;
                        }
                        event = airplay.recv_async() => {
                            if !forward_event(&events_tx, event) {
                                return;
                            }
                        }
                        event = async {
                            match &chromecast {
                                Some(rx) => rx.recv_async().await,
                                None => std::future::pending().await,
                            }
                        } => {
                            if !forward_event(&events_tx, event) {
                                return;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            _daemon: daemon,
            refresh_tx,
            events_rx,
        })
    }

    pub fn refresh(&self) {
        let _ = self.refresh_tx.send(());
    }

    pub async fn recv(&mut self) -> Option<DiscoveryEvent> {
        self.events_rx.recv().await
    }
}

fn txt(resolved: &mdns_sd::ResolvedService, key: &str) -> Option<String> {
    resolved
        .get_property_val_str(key)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn forward_event(
    events_tx: &mpsc::UnboundedSender<DiscoveryEvent>,
    event: Result<ServiceEvent, mdns_sd::RecvError>,
) -> bool {
    match event {
        Ok(ServiceEvent::ServiceResolved(resolved)) => {
            let device = device_from_resolved(&resolved);
            let _ = events_tx.send(DiscoveryEvent::Found(device));
            true
        }
        Ok(ServiceEvent::ServiceRemoved(_, name)) => {
            let _ = events_tx.send(DiscoveryEvent::Removed(name));
            true
        }
        Err(_) => false,
        _ => true,
    }
}

fn device_from_resolved(resolved: &mdns_sd::ResolvedService) -> AirPlayDevice {
    let kind = if resolved.fullname.contains("._googlecast._tcp") {
        DeviceKind::Chromecast
    } else {
        DeviceKind::AirPlay
    };
    let name = match kind {
        DeviceKind::Chromecast => txt(resolved, "fn")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| display_name(&resolved.fullname)),
        DeviceKind::AirPlay => display_name(&resolved.fullname),
    };
    let mut addresses: Vec<IpAddr> = Vec::new();
    for scoped in &resolved.addresses {
        match scoped {
            mdns_sd::ScopedIp::V4(v4) => {
                let ip = *v4.addr();
                if !ip.is_unspecified() {
                    addresses.push(IpAddr::V4(ip));
                }
            }
            mdns_sd::ScopedIp::V6(v6) => {
                let ip = *v6.addr();
                if !ip.is_unspecified() {
                    addresses.push(IpAddr::V6(ip));
                }
            }
            _ => {}
        }
    }
    addresses.sort_by_key(|ip| match ip {
        IpAddr::V4(_) => 0u8,
        IpAddr::V6(_) => 1u8,
    });
    addresses.dedup();

    AirPlayDevice {
        kind,
        fullname: resolved.fullname.clone(),
        name,
        host: resolved.host.trim_end_matches('.').to_string(),
        port: resolved.port,
        addresses,
        deviceid: match kind {
            DeviceKind::Chromecast => txt(resolved, "id").or_else(|| txt(resolved, "deviceid")),
            DeviceKind::AirPlay => txt(resolved, "deviceid"),
        },
        features: txt(resolved, "features").or_else(|| txt(resolved, "ft")),
        flags: txt(resolved, "flags").or_else(|| txt(resolved, "sf")),
        model: match kind {
            DeviceKind::Chromecast => txt(resolved, "md").or_else(|| txt(resolved, "model")),
            DeviceKind::AirPlay => txt(resolved, "model"),
        },
        pw: txt(resolved, "pw"),
        srcvers: txt(resolved, "srcvers"),
    }
}

fn display_name(fullname: &str) -> String {
    let stem = fullname
        .strip_suffix("._airplay._tcp.local.")
        .or_else(|| fullname.strip_suffix("._airplay._tcp.local"))
        .or_else(|| fullname.strip_suffix("._googlecast._tcp.local."))
        .or_else(|| fullname.strip_suffix("._googlecast._tcp.local"))
        .unwrap_or(fullname);
    unescape_mdns(stem)
}

fn unescape_mdns(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &bytes[i + 1..i + 4];
            if oct.iter().all(|b| b.is_ascii_digit()) {
                if let Ok(n) = std::str::from_utf8(oct).unwrap_or("").parse::<u8>() {
                    out.push(n as char);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

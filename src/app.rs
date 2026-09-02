//! TUI state machine: discovery (pair) → files → pin → control.

use std::future::Future;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::airplay::AirPlayClient;
use crate::config;
use crate::creds;
use crate::discovery::{AirPlayDevice, Discovery, DiscoveryEvent};
use crate::files::{self, MediaFile};
use crate::hap::{self, HapCredentials, PairSetupSession};
use crate::http_media::MediaServer;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("mDNS: {0}")]
    Mdns(String),
    #[error("could not determine this machine's LAN IPv4 address")]
    NoLanIp,
    #[error("hls: {0}")]
    Hls(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Discovery,
    Files,
    AddFolder,
    Pin,
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyKind {
    Connecting,
    Pairing,
    StartingPlayback,
    SendingToTv,
}

impl BusyKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connecting => "Connecting",
            Self::Pairing => "Pairing",
            Self::StartingPlayback => "Starting playback",
            Self::SendingToTv => "Sending to TV",
        }
    }
}

pub fn busy_dots(tick: u8) -> &'static str {
    match tick % 3 {
        0 => ".",
        1 => "..",
        _ => "...",
    }
}

enum NetResult {
    ConnectFailed {
        err: String,
    },
    Paired {
        client: AirPlayClient,
    },
    NeedPin {
        client: AirPlayClient,
        setup: PairSetupSession,
        prior_err: Option<String>,
        from_discovery: bool,
    },
    PairingFailed {
        err: String,
        from_discovery: bool,
    },
    PinOk {
        client: AirPlayClient,
        creds: HapCredentials,
        verify_err: Option<String>,
    },
    PinRetry {
        client: AirPlayClient,
        err: String,
        setup: Option<PairSetupSession>,
    },
    PlayOk {
        client: AirPlayClient,
        server: Option<MediaServer>,
        location: String,
    },
    PlayNeedPin {
        client: AirPlayClient,
        server: Option<MediaServer>,
        location: String,
        err: String,
    },
    PlayFail {
        client: Option<AirPlayClient>,
        err: String,
    },
}

pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub status: String,

    pub devices: Vec<AirPlayDevice>,
    pub selected_device: usize,
    discovery: Discovery,

    pub folders: Vec<PathBuf>,
    media_port: u16,
    pub files: Vec<MediaFile>,
    pub filter: String,
    pub filtered: Vec<usize>,
    pub selected_file: usize,
    pub scanning: bool,
    scan_rx: Option<oneshot::Receiver<Vec<MediaFile>>>,
    pub folder_input: String,

    pub device: Option<AirPlayDevice>,
    pub current_file: Option<PathBuf>,
    pub playing: bool,
    pub position: f64,
    pub duration: f64,
    pub playback_info_ok: bool,
    pub last_error: Option<String>,
    pub screen_cast: bool,

    pub pin_buf: String,
    pair_setup: Option<PairSetupSession>,
    pending_location: Option<String>,
    pin_from_discovery: bool,
    play_ok: bool,
    session_paired: bool,

    busy: Option<BusyKind>,
    busy_tick: u8,
    job_rx: Option<oneshot::Receiver<NetResult>>,
    job_handle: Option<tokio::task::JoinHandle<()>>,

    last_tick: Instant,
    last_info_at: Instant,
    device_id: String,
    airplay: Option<AirPlayClient>,
    media_server: Option<MediaServer>,
}

impl App {
    pub fn new(cli_media_dir: Option<PathBuf>, media_port: u16) -> Result<Self, Error> {
        let discovery = Discovery::start()?;
        let device_id = {
            let bytes = Uuid::new_v4().into_bytes();
            format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
            )
        };
        let folders = config::resolve_folders(cli_media_dir);
        let mut app = Self {
            screen: Screen::Discovery,
            should_quit: false,
            status: "Browsing for AirPlay receivers…".to_string(),
            devices: Vec::new(),
            selected_device: 0,
            discovery,
            folders,
            media_port,
            files: Vec::new(),
            filter: String::new(),
            filtered: Vec::new(),
            selected_file: 0,
            scanning: false,
            scan_rx: None,
            folder_input: String::new(),
            device: None,
            current_file: None,
            playing: false,
            position: 0.0,
            duration: 0.0,
            playback_info_ok: false,
            last_error: None,
            screen_cast: false,
            pin_buf: String::new(),
            pair_setup: None,
            pending_location: None,
            pin_from_discovery: false,
            play_ok: false,
            session_paired: false,
            busy: None,
            busy_tick: 0,
            job_rx: None,
            job_handle: None,
            last_tick: Instant::now(),
            last_info_at: Instant::now() - Duration::from_secs(2),
            device_id,
            airplay: None,
            media_server: None,
        };
        app.start_scan();
        Ok(app)
    }

    pub async fn discovery_event(&mut self) -> Option<DiscoveryEvent> {
        self.discovery.recv().await
    }

    pub fn apply_discovery(&mut self, event: DiscoveryEvent) {
        match event {
            DiscoveryEvent::Found(device) => {
                if let Some(existing) = self
                    .devices
                    .iter_mut()
                    .find(|d| d.fullname == device.fullname)
                {
                    *existing = device;
                } else {
                    self.devices.push(device);
                    self.devices.sort_by(|a, b| a.name.cmp(&b.name));
                }
                if self.screen == Screen::Discovery {
                    let n = self.devices.len();
                    if n > 0 {
                        self.status = format!("{n} AirPlay receiver(s)");
                    }
                }
            }
            DiscoveryEvent::Removed(name) => {
                self.devices
                    .retain(|d| d.fullname != name && d.name != name);
                if self.selected_device >= self.devices.len() && !self.devices.is_empty() {
                    self.selected_device = self.devices.len() - 1;
                }
                if self.screen == Screen::Discovery && self.devices.is_empty() {
                    self.status = "No AirPlay devices found. Press r to refresh.".to_string();
                }
            }
            DiscoveryEvent::Cleared => {
                self.devices.clear();
                self.selected_device = 0;
                if self.screen == Screen::Discovery {
                    self.status = "Refreshing…".to_string();
                }
            }
        }
        if self.selected_device >= self.devices.len() && !self.devices.is_empty() {
            self.selected_device = self.devices.len() - 1;
        }
    }

    fn start_scan(&mut self) {
        let folders = self.folders.clone();
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _ = tx.send(files::scan_media_dirs(&folders));
        });
        self.scan_rx = Some(rx);
        self.scanning = true;
        if matches!(self.screen, Screen::Files | Screen::AddFolder) {
            self.status = format!("Scanning {} folder(s)…", self.folders.len());
        }
    }

    fn poll_scan(&mut self) {
        let Some(rx) = self.scan_rx.as_mut() else {
            return;
        };
        match rx.try_recv() {
            Ok(files) => {
                self.scan_rx = None;
                self.scanning = false;
                self.files = files;
                self.recompute_filter();
                if self.screen == Screen::Files {
                    self.status_files();
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(oneshot::error::TryRecvError::Closed) => {
                self.scan_rx = None;
                self.scanning = false;
            }
        }
    }

    fn status_files(&mut self) {
        let n = self.files.len();
        let f = self.folders.len();
        if self.scanning {
            self.status = format!("Scanning… {n} file(s) so far, {f} folder(s)");
        } else if n == 0 {
            self.status = format!("No .mp4/.mkv/.mov in {f} folder(s). Press a to add a folder.");
        } else {
            self.status = format!("{n} video(s) in {f} folder(s)");
        }
    }

    pub async fn handle_key(&mut self, key: KeyEvent) {
        if self.is_busy() {
            match key.code {
                KeyCode::Char('q') => self.should_quit = true,
                KeyCode::Esc => self.cancel_busy(),
                _ => {}
            }
            return;
        }
        match self.screen {
            Screen::Discovery => self.handle_discovery_key(key),
            Screen::Files => self.handle_files_key(key),
            Screen::AddFolder => self.handle_add_folder_key(key),
            Screen::Pin => self.handle_pin_key(key),
            Screen::Control => self.handle_control_key(key).await,
        }
    }

    fn handle_discovery_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('r') => {
                self.status = "Refreshing…".to_string();
                self.discovery.refresh();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_device > 0 {
                    self.selected_device -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.devices.is_empty() && self.selected_device + 1 < self.devices.len() {
                    self.selected_device += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(device) = self.devices.get(self.selected_device).cloned() {
                    self.queue_select_tv(device);
                }
            }
            _ => {}
        }
    }

    /// Pair when picking the TV, then go to Files. No media server yet.
    fn queue_select_tv(&mut self, device: AirPlayDevice) {
        crate::airplay::clear_net_log();
        self.device = Some(device.clone());
        self.airplay = None;
        self.play_ok = false;
        self.session_paired = false;
        self.pending_location = None;
        self.last_error = None;
        let device_id = self.device_id.clone();
        let creds = self.saved_creds();
        self.spawn_net(BusyKind::Connecting, async move {
            job_select_tv(device, device_id, creds).await
        });
    }

    fn show_files(&mut self) {
        self.filter.clear();
        self.selected_file = 0;
        self.screen = Screen::Files;
        if self.files.is_empty() && !self.scanning {
            self.start_scan();
        }
        self.status_files();
        if let Some(device) = &self.device {
            self.status = format!("{} — {}", device.name, self.status);
        }
    }

    fn recompute_filter(&mut self) {
        self.filtered = files::filter_indices(&self.files, &self.filter);
        if self.selected_file >= self.filtered.len() {
            self.selected_file = self.filtered.len().saturating_sub(1);
        }
    }

    fn handle_files_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.airplay = None;
                self.play_ok = false;
                self.session_paired = false;
                self.teardown_server();
                self.pending_location = None;
                self.device = None;
                self.screen = Screen::Discovery;
                self.status = if self.devices.is_empty() {
                    "No AirPlay devices found. Press r to refresh.".to_string()
                } else {
                    format!("{} AirPlay receiver(s)", self.devices.len())
                };
            }
            KeyCode::Up => {
                if self.selected_file > 0 {
                    self.selected_file -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected_file + 1 < self.filtered.len() {
                    self.selected_file += 1;
                }
            }
            KeyCode::Enter => self.queue_start_playback(),
            KeyCode::Char('a') => {
                self.folder_input.clear();
                self.screen = Screen::AddFolder;
                self.status = "Type a folder path, then Enter. ~ is expanded.".to_string();
            }
            KeyCode::Char('d') => self.remove_selected_folder(),
            KeyCode::Backspace => {
                self.filter.pop();
                self.recompute_filter();
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.filter.push(c);
                self.recompute_filter();
            }
            _ => {}
        }
    }

    fn handle_add_folder_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::Files;
                self.status_files();
            }
            KeyCode::Enter => {
                let path = config::expand_path(&self.folder_input);
                if path.as_os_str().is_empty() {
                    self.status = "Empty path.".to_string();
                    return;
                }
                if !path.is_dir() {
                    self.status = format!("Not a directory: {}", path.display());
                    return;
                }
                if config::contains_folder(&self.folders, &path) {
                    self.status = "Folder already in the list.".to_string();
                    self.screen = Screen::Files;
                    return;
                }
                self.folders.push(path);
                let _ = config::persist_folders(&self.folders);
                self.screen = Screen::Files;
                self.start_scan();
            }
            KeyCode::Backspace => {
                self.folder_input.pop();
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.folder_input.push(c);
            }
            _ => {}
        }
    }

    fn remove_selected_folder(&mut self) {
        let root = if let Some(&idx) = self.filtered.get(self.selected_file) {
            self.files.get(idx).map(|f| f.root.clone())
        } else {
            None
        };
        let removed = if let Some(root) = root {
            let before = self.folders.len();
            self.folders.retain(|f| !config::paths_equal(f, &root));
            if self.folders.len() < before {
                Some(root)
            } else {
                None
            }
        } else {
            self.folders.pop()
        };
        match removed {
            Some(p) => {
                let _ = config::persist_folders(&self.folders);
                self.status = format!("Removed {}", p.display());
                self.start_scan();
            }
            None => {
                self.status = "No folder to remove.".to_string();
            }
        }
    }

    fn handle_pin_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                let from_discovery = self.pin_from_discovery;
                self.cancel_pairing();
                if from_discovery {
                    self.device = None;
                    self.screen = Screen::Discovery;
                    self.status = if self.devices.is_empty() {
                        "No AirPlay devices found. Press r to refresh.".to_string()
                    } else {
                        format!("{} AirPlay receiver(s)", self.devices.len())
                    };
                } else {
                    self.screen = Screen::Files;
                    self.status_files();
                }
            }
            KeyCode::Enter => {
                if self.pin_buf.len() == 4 {
                    self.queue_submit_pin();
                }
            }
            KeyCode::Backspace => {
                self.pin_buf.pop();
            }
            KeyCode::Char(c) if c.is_ascii_digit() && self.pin_buf.len() < 4 => {
                self.pin_buf.push(c);
            }
            _ => {}
        }
    }

    fn cancel_pairing(&mut self) {
        self.pair_setup = None;
        self.pin_buf.clear();
        self.pending_location = None;
        self.airplay = None;
        self.play_ok = false;
        self.pin_from_discovery = false;
        self.teardown_server();
    }

    fn queue_start_playback(&mut self) {
        let Some(&idx) = self.filtered.get(self.selected_file) else {
            return;
        };
        let Some(file) = self.files.get(idx).cloned() else {
            return;
        };
        let Some(device) = self.device.clone() else {
            return;
        };
        if let Some(mut server) = self.media_server.take() {
            server.shutdown();
        }
        let play_ok = self.play_ok;
        self.play_ok = false;
        let client = self.airplay.take();
        let creds = self.saved_creds();
        let session_paired = self.session_paired;
        let device_id = self.device_id.clone();
        let media_port = self.media_port;
        self.current_file = Some(file.path.clone());
        self.last_error = None;
        self.pending_location = None;
        let kind = if self
            .device
            .as_ref()
            .is_some_and(crate::airplay::is_screen_mirroring_tv)
        {
            BusyKind::SendingToTv
        } else {
            BusyKind::StartingPlayback
        };
        self.spawn_net(kind, async move {
            job_play(
                client,
                device,
                device_id,
                file,
                media_port,
                creds,
                session_paired,
                play_ok,
            )
            .await
        });
    }

    fn queue_begin_pairing(&mut self, from_discovery: bool) {
        let Some(client) = self.airplay.take() else {
            self.pairing_gave_up();
            return;
        };
        self.pin_from_discovery = from_discovery;
        self.spawn_net(BusyKind::Pairing, async move {
            job_begin_pairing(client, None, from_discovery).await
        });
    }

    fn queue_submit_pin(&mut self) {
        let pin = hap::zfill_pin(&self.pin_buf);
        let Some(client) = self.airplay.take() else {
            self.status = "no AirPlay client".to_string();
            return;
        };
        let setup = self.pair_setup.take();
        self.spawn_net(BusyKind::Pairing, async move {
            job_submit_pin(client, setup, pin).await
        });
    }

    fn queue_retry_play(&mut self) {
        let Some(location) = self.pending_location.clone() else {
            self.stay_on_files_not_playing();
            return;
        };
        let Some(client) = self.airplay.take() else {
            self.stay_on_files_not_playing();
            return;
        };
        let server = self.media_server.take();
        let local_file = self.current_file.clone();
        let kind = if server.is_none() {
            BusyKind::SendingToTv
        } else {
            BusyKind::StartingPlayback
        };
        self.spawn_net(kind, async move {
            job_retry_play(client, location, server, local_file).await
        });
    }

    fn spawn_net<F>(&mut self, kind: BusyKind, fut: F)
    where
        F: Future<Output = NetResult> + Send + 'static,
    {
        if let Some(handle) = self.job_handle.take() {
            handle.abort();
        }
        let (tx, rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = tx.send(fut.await);
        });
        self.job_handle = Some(handle);
        self.job_rx = Some(rx);
        self.busy = Some(kind);
        self.busy_tick = 0;
        self.status = format!("{}{}", kind.label(), busy_dots(0));
    }

    pub fn has_pending_network(&self) -> bool {
        self.job_rx.is_some()
    }

    pub fn is_busy(&self) -> bool {
        self.busy.is_some()
    }

    pub fn busy_text(&self) -> Option<String> {
        let kind = self.busy?;
        Some(format!("{}{}", kind.label(), busy_dots(self.busy_tick)))
    }

    pub fn show_net_panel(&self) -> bool {
        match self.screen {
            Screen::Files | Screen::Pin | Screen::Control => true,
            Screen::Discovery => self.busy.is_some() || self.device.is_some(),
            Screen::AddFolder => false,
        }
    }

    pub fn net_log(&self) -> Vec<String> {
        crate::airplay::net_log_lines()
    }

    fn cancel_busy(&mut self) {
        if let Some(handle) = self.job_handle.take() {
            handle.abort();
        }
        self.job_rx = None;
        self.busy = None;
        self.airplay = None;
        self.status = "Cancelled".to_string();
        match self.screen {
            Screen::Pin => {
                self.pair_setup = None;
                self.pin_buf.clear();
                if self.pin_from_discovery {
                    self.device = None;
                    self.pin_from_discovery = false;
                    self.screen = Screen::Discovery;
                    self.status = if self.devices.is_empty() {
                        "No AirPlay devices found. Press r to refresh.".to_string()
                    } else {
                        format!("{} AirPlay receiver(s)", self.devices.len())
                    };
                } else {
                    self.teardown_server();
                    self.pending_location = None;
                    self.screen = Screen::Files;
                    self.status_files();
                }
            }
            Screen::Discovery => {
                self.device = None;
                self.session_paired = false;
            }
            Screen::Files => {
                self.teardown_server();
                self.pending_location = None;
                self.play_ok = false;
            }
            _ => {}
        }
    }

    fn poll_job(&mut self) {
        let Some(rx) = self.job_rx.as_mut() else {
            return;
        };
        match rx.try_recv() {
            Ok(result) => {
                self.job_rx = None;
                self.job_handle = None;
                self.apply_net_result(result);
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(oneshot::error::TryRecvError::Closed) => {
                self.job_rx = None;
                self.job_handle = None;
                if self.is_busy() {
                    self.busy = None;
                    self.status = "Cancelled".to_string();
                }
            }
        }
    }

    fn apply_net_result(&mut self, result: NetResult) {
        self.busy = None;
        match result {
            NetResult::ConnectFailed { err } => {
                self.last_error = Some(err.clone());
                self.status = err;
            }
            NetResult::Paired { client } => {
                self.airplay = Some(client);
                self.session_paired = true;
                self.pin_from_discovery = false;
                self.show_files();
                let name = self
                    .device
                    .as_ref()
                    .map(|d| d.name.as_str())
                    .unwrap_or("TV");
                self.status = format!("{name} — paired, pick a file");
            }
            NetResult::NeedPin {
                client,
                setup,
                prior_err,
                from_discovery,
            } => {
                self.airplay = Some(client);
                self.pair_setup = Some(setup);
                self.pin_buf.clear();
                self.pin_from_discovery = from_discovery;
                self.screen = Screen::Pin;
                self.status = if let Some(err) = prior_err {
                    format!("pair-verify failed: {err}")
                } else {
                    "Enter the code shown on the TV".to_string()
                };
            }
            NetResult::PairingFailed {
                err,
                from_discovery,
            } => {
                self.last_error = Some(err.clone());
                self.status = err;
                self.pin_from_discovery = from_discovery;
                self.pairing_gave_up();
            }
            NetResult::PinOk {
                client,
                creds,
                verify_err,
            } => {
                if let Some(device) = &self.device {
                    let mut store = creds::load();
                    creds::insert(&mut store, device.cred_key(), &creds);
                    if let Err(err) = creds::save(&store) {
                        self.last_error =
                            Some(format!("saved pairing but could not write keys: {err}"));
                    }
                }
                self.airplay = Some(client);
                self.session_paired = verify_err.is_none();
                self.pin_buf.clear();
                if let Some(err) = verify_err {
                    self.last_error = Some(err.clone());
                    self.status = format!("paired, pair-verify: {err}");
                    self.session_paired = false;
                }
                if self.pending_location.is_some() {
                    self.queue_retry_play();
                } else {
                    self.pin_from_discovery = false;
                    self.show_files();
                    let name = self
                        .device
                        .as_ref()
                        .map(|d| d.name.as_str())
                        .unwrap_or("TV");
                    self.status = format!("{name} — paired, pick a file");
                }
            }
            NetResult::PinRetry { client, err, setup } => {
                self.airplay = Some(client);
                self.pin_buf.clear();
                self.screen = Screen::Pin;
                self.last_error = Some(err.clone());
                match setup {
                    Some(setup) => {
                        self.pair_setup = Some(setup);
                        self.status = format!("{err} — enter the new code on the TV");
                    }
                    None => {
                        self.pair_setup = None;
                        self.status = err;
                    }
                }
            }
            NetResult::PlayOk {
                client,
                server,
                location,
            } => {
                self.airplay = Some(client);
                self.media_server = server;
                self.pending_location = Some(location);
                self.play_ok = true;
                self.session_paired = true;
                self.last_error = None;
                self.screen_cast = self.airplay.as_ref().is_some_and(|c| {
                    c.screen_stream_active()
                        || c.screen_stream_frames() > 0
                        || c.screen_stream_bytes() > 0
                });
                let name = self
                    .device
                    .as_ref()
                    .map(|d| d.name.as_str())
                    .unwrap_or("TV");
                self.status = if self.screen_cast {
                    format!("On {name}")
                } else {
                    format!("Playing on {name}")
                };
                self.goto_control_current(true);
            }
            NetResult::PlayNeedPin {
                client,
                server,
                location,
                err,
            } => {
                self.airplay = Some(client);
                self.media_server = server;
                self.pending_location = Some(location);
                self.last_error = Some(err.clone());
                self.status = format!("{err} — starting pairing");
                self.forget_device_creds();
                self.session_paired = false;
                self.pin_from_discovery = false;
                self.queue_begin_pairing(false);
            }
            NetResult::PlayFail { client, err } => {
                self.airplay = client;
                self.last_error = Some(err.clone());
                self.status = err;
                self.stay_on_files_not_playing();
            }
        }
    }

    fn forget_device_creds(&mut self) {
        let Some(device) = self.device.as_ref() else {
            return;
        };
        let mut store = creds::load();
        if creds::remove(&mut store, &device.cred_lookup_keys()) {
            let _ = creds::save(&store);
        }
    }

    fn stay_on_files_not_playing(&mut self) {
        self.playing = false;
        self.play_ok = false;
        self.screen_cast = false;
        self.teardown_server();
        self.pending_location = None;
        self.screen = Screen::Files;
    }

    fn pairing_gave_up(&mut self) {
        self.playing = false;
        self.play_ok = false;
        self.screen_cast = false;
        self.session_paired = false;
        self.teardown_server();
        self.pending_location = None;
        self.pair_setup = None;
        self.pin_buf.clear();
        if self.pin_from_discovery {
            self.airplay = None;
            self.device = None;
            self.pin_from_discovery = false;
            self.screen = Screen::Discovery;
        } else {
            self.screen = Screen::Files;
        }
    }

    fn saved_creds(&self) -> Option<HapCredentials> {
        let device = self.device.as_ref()?;
        let store = creds::load();
        creds::lookup(&store, &device.cred_lookup_keys())
    }

    fn goto_control(&mut self, path: PathBuf, playing: bool) {
        if !self.play_ok {
            self.stay_on_files_not_playing();
            return;
        }
        self.current_file = Some(path);
        self.playing = playing;
        self.position = 0.0;
        self.duration = 0.0;
        self.playback_info_ok = false;
        self.last_tick = Instant::now();
        self.last_info_at = Instant::now() - Duration::from_secs(2);
        self.screen = Screen::Control;
    }

    fn goto_control_current(&mut self, playing: bool) {
        let path = self.current_file.clone().unwrap_or_default();
        self.goto_control(path, playing);
    }

    async fn handle_control_key(&mut self, key: KeyEvent) {
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        match key.code {
            KeyCode::Char('q') => {
                self.stop_and_exit().await;
            }
            KeyCode::Esc => {
                self.stop_and_files().await;
            }
            _ if self.screen_cast => {}
            KeyCode::Char(' ') => self.toggle_pause().await,
            KeyCode::Left if shift => self.seek(-60.0).await,
            KeyCode::Right if shift => self.seek(60.0).await,
            KeyCode::Left => self.seek(-10.0).await,
            KeyCode::Right => self.seek(10.0).await,
            KeyCode::Char('[') => self.seek(-60.0).await,
            KeyCode::Char(']') => self.seek(60.0).await,
            KeyCode::Home => self.seek_to(0.0).await,
            KeyCode::End => {
                if self.duration > 0.0 {
                    self.seek_to(self.duration).await;
                }
            }
            KeyCode::Char(c) if c.is_ascii_digit() => {
                let n = c.to_digit(10).unwrap_or(0) as f64;
                if self.duration > 0.0 {
                    self.seek_to(self.duration * n / 10.0).await;
                } else if n == 0.0 {
                    self.seek_to(0.0).await;
                } else {
                    self.status = "Duration unknown — cannot jump by percent yet".to_string();
                }
            }
            _ => {}
        }
    }

    async fn toggle_pause(&mut self) {
        if !self.play_ok {
            return;
        }
        let next = if self.playing { 0.0 } else { 1.0 };
        if let Some(client) = self.airplay.as_mut() {
            match tokio::time::timeout(Duration::from_secs(3), client.set_rate(next)).await {
                Ok(Ok(())) => {
                    self.playing = next > 0.5;
                    self.status = if self.playing {
                        "Playing".into()
                    } else {
                        "Paused".into()
                    };
                    self.last_error = None;
                }
                Ok(Err(err)) => {
                    self.last_error = Some(err.clone());
                    self.status = err;
                    self.playing = next > 0.5;
                }
                Err(_) => {
                    self.last_error = Some("POST /rate timed out".into());
                    self.playing = next > 0.5;
                }
            }
        } else {
            self.playing = next > 0.5;
        }
        self.last_tick = Instant::now();
    }

    async fn seek(&mut self, delta: f64) {
        let mut pos = (self.position + delta).max(0.0);
        if self.duration > 0.0 {
            pos = pos.min(self.duration);
        }
        self.seek_to(pos).await;
    }

    async fn seek_to(&mut self, pos: f64) {
        if !self.play_ok {
            return;
        }
        let mut pos = pos.max(0.0);
        if self.duration > 0.0 {
            pos = pos.min(self.duration);
        }
        self.position = pos;
        if let Some(client) = self.airplay.as_mut() {
            match tokio::time::timeout(Duration::from_secs(3), client.scrub(pos)).await {
                Ok(Ok(())) => {
                    self.last_error = None;
                    self.status = format!("Seek {}", format_time(pos));
                }
                Ok(Err(err)) => {
                    self.last_error = Some(err.clone());
                    self.status = err;
                }
                Err(_) => {
                    self.last_error = Some("POST /scrub timed out".into());
                }
            }
        }
        self.last_tick = Instant::now();
    }

    async fn stop_and_files(&mut self) {
        self.send_stop().await;
        self.teardown_server();
        self.airplay = None;
        self.playing = false;
        self.play_ok = false;
        self.screen_cast = false;
        self.pair_setup = None;
        self.pending_location = None;
        self.screen = Screen::Files;
        self.status = "Stopped".to_string();
    }

    async fn screen_cast_finished(&mut self) {
        self.send_stop().await;
        self.teardown_server();
        self.airplay = None;
        self.playing = false;
        self.play_ok = false;
        self.screen_cast = false;
        self.pair_setup = None;
        self.pending_location = None;
        self.screen = Screen::Files;
        self.status = "Done".to_string();
    }

    async fn stop_and_exit(&mut self) {
        self.send_stop().await;
        self.teardown_server();
        self.should_quit = true;
    }

    async fn send_stop(&mut self) {
        if !self.play_ok {
            return;
        }
        if let Some(client) = self.airplay.as_mut() {
            let _ = tokio::time::timeout(Duration::from_secs(2), client.stop()).await;
        }
        self.play_ok = false;
    }

    fn teardown_server(&mut self) {
        if let Some(mut server) = self.media_server.take() {
            server.shutdown();
        }
    }

    pub async fn shutdown(&mut self) {
        self.send_stop().await;
        self.teardown_server();
    }

    pub async fn on_tick(&mut self) {
        self.poll_scan();
        self.poll_job();
        if let Some(kind) = self.busy {
            self.busy_tick = self.busy_tick.wrapping_add(1);
            self.status = format!("{}{}", kind.label(), busy_dots(self.busy_tick));
        }

        if self.screen != Screen::Control || !self.play_ok {
            self.last_tick = Instant::now();
            return;
        }

        let now = Instant::now();
        if self.screen_cast {
            if self.playing {
                let dt = now.duration_since(self.last_tick).as_secs_f64();
                self.position += dt;
                if self.duration > 0.0 {
                    self.position = self.position.min(self.duration);
                }
            }
            self.last_tick = now;
            let active = self
                .airplay
                .as_ref()
                .is_some_and(|c| c.screen_stream_active());
            if !active {
                self.screen_cast_finished().await;
            }
            return;
        }

        if self.playing && !self.playback_info_ok {
            let dt = now.duration_since(self.last_tick).as_secs_f64();
            self.position += dt;
            if self.duration > 0.0 {
                self.position = self.position.min(self.duration);
            }
        }
        self.last_tick = now;

        if now.duration_since(self.last_info_at) >= Duration::from_secs(1) {
            self.last_info_at = now;
            self.refresh_playback_info().await;
        }
    }

    async fn refresh_playback_info(&mut self) {
        if !self.play_ok {
            return;
        }
        let Some(client) = self.airplay.as_mut() else {
            return;
        };
        match tokio::time::timeout(Duration::from_millis(900), client.playback_info()).await {
            Ok(Ok(info)) => {
                self.playback_info_ok = info.duration.is_some() || info.position.is_some();
                if let Some(d) = info.duration {
                    if d.is_finite() && d >= 0.0 {
                        self.duration = d;
                    }
                }
                if let Some(p) = info.position {
                    if p.is_finite() && p >= 0.0 {
                        self.position = p;
                    }
                }
                if let Some(rate) = info.rate {
                    self.playing = rate > 0.01;
                }
            }
            _ => {
                self.playback_info_ok = false;
            }
        }
    }

    pub fn progress_ratio(&self) -> f64 {
        if self.duration > 0.0 {
            (self.position / self.duration).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }

    pub fn progress_percent(&self) -> Option<u32> {
        if self.duration > 0.0 {
            Some((self.progress_ratio() * 100.0).round() as u32)
        } else {
            None
        }
    }
}

async fn job_select_tv(
    device: AirPlayDevice,
    device_id: String,
    creds: Option<HapCredentials>,
) -> NetResult {
    let mut client = match AirPlayClient::connect(device, device_id).await {
        Ok(c) => c,
        Err(err) => {
            return NetResult::ConnectFailed {
                err: format!("connect: {err}"),
            }
        }
    };
    if let Some(creds) = creds {
        match client.hap_pair_verify(creds).await {
            Ok(()) => return NetResult::Paired { client },
            Err(err) => return job_begin_pairing(client, Some(err), true).await,
        }
    }
    job_begin_pairing(client, None, true).await
}

async fn job_begin_pairing(
    mut client: AirPlayClient,
    prior: Option<String>,
    from_discovery: bool,
) -> NetResult {
    match client.start_regular_setup().await {
        Ok(setup) => NetResult::NeedPin {
            client,
            setup,
            prior_err: prior,
            from_discovery,
        },
        Err(_) => match client.try_transient_pairing().await {
            Ok(()) => NetResult::Paired { client },
            Err(err) => NetResult::PairingFailed {
                err: format!("Pairing failed: {err}"),
                from_discovery,
            },
        },
    }
}

async fn job_submit_pin(
    mut client: AirPlayClient,
    mut setup: Option<PairSetupSession>,
    pin: String,
) -> NetResult {
    if setup.is_none() {
        match client.start_regular_setup().await {
            Ok(s) => setup = Some(s),
            Err(err) => {
                return NetResult::PinRetry {
                    client,
                    err: format!("Could not start pairing: {err}"),
                    setup: None,
                };
            }
        }
    }
    let Some(mut setup) = setup else {
        return NetResult::PinRetry {
            client,
            err: "no pairing session".into(),
            setup: None,
        };
    };
    match client.finish_regular_setup(&mut setup, &pin).await {
        Ok(creds) => {
            let verify_err = client.hap_pair_verify(creds.clone()).await.err();
            NetResult::PinOk {
                client,
                creds,
                verify_err,
            }
        }
        Err(err) => {
            let restarted = client.start_regular_setup().await.ok();
            NetResult::PinRetry {
                client,
                err: format!("PIN pairing failed: {err}"),
                setup: restarted,
            }
        }
    }
}

async fn job_play(
    mut client: Option<AirPlayClient>,
    device: AirPlayDevice,
    device_id: String,
    file: MediaFile,
    media_port: u16,
    creds: Option<HapCredentials>,
    _session_paired: bool,
    play_ok: bool,
) -> NetResult {
    if play_ok {
        if let Some(c) = client.as_mut() {
            let _ = tokio::time::timeout(Duration::from_secs(2), c.stop()).await;
        }
    }
    let screen = crate::airplay::is_screen_mirroring_tv(&device);
    let mut server = None;
    let location = if screen {
        format!("file://{}", file.path.to_string_lossy())
    } else {
        let hls = crate::airplay::device_wants_hls(&device);
        match MediaServer::start_for(file.path.clone(), media_port, hls).await {
            Ok(s) => {
                let loc = s.content_location();
                server = Some(s);
                loc
            }
            Err(err) => {
                return NetResult::PlayFail {
                    client,
                    err: format!("media server: {err}"),
                };
            }
        }
    };
    let mut client = match client {
        Some(c) => c,
        None => match AirPlayClient::connect(device, device_id).await {
            Ok(c) => c,
            Err(err) => {
                return NetResult::PlayFail {
                    client: None,
                    err: format!("connect: {err}"),
                };
            }
        },
    };
    if !client.is_encrypted() {
        if let Some(creds) = creds {
            if let Err(err) = client.hap_pair_verify(creds).await {
                return NetResult::PlayNeedPin {
                    client,
                    server,
                    location,
                    err,
                };
            }
        }
    }
    if let Some(ref s) = server {
        client.set_media_gets(s.request_count());
        if let Some(dir) = s.hls_dir() {
            client.set_hls(dir, s.origin());
        }
    }
    // Handshake only. play() returns once a type-110 stream is rolling.
    match tokio::time::timeout(Duration::from_secs(75), client.play(&location, 0.0, Some(file.path.as_path()))).await {
        Ok(Ok(())) => NetResult::PlayOk {
            client,
            server,
            location,
        },
        Ok(Err(err)) if err.needs_pairing() => NetResult::PlayNeedPin {
            client,
            server,
            location,
            err: err.message(),
        },
        Ok(Err(err)) => NetResult::PlayFail {
            client: Some(client),
            err: err.message(),
        },
        Err(_) => NetResult::PlayFail {
            client: Some(client),
            err: "play timed out".into(),
        },
    }
}

async fn job_retry_play(
    mut client: AirPlayClient,
    location: String,
    server: Option<MediaServer>,
    local_file: Option<PathBuf>,
) -> NetResult {
    if let Some(ref s) = server {
        client.set_media_gets(s.request_count());
        if let Some(dir) = s.hls_dir() {
            client.set_hls(dir, s.origin());
        }
    }
    match tokio::time::timeout(
        Duration::from_secs(75),
        client.play(&location, 0.0, local_file.as_deref()),
    )
    .await
    {
        Ok(Ok(())) => NetResult::PlayOk {
            client,
            server,
            location,
        },
        Ok(Err(err)) => NetResult::PlayFail {
            client: Some(client),
            err: err.message(),
        },
        Err(_) => NetResult::PlayFail {
            client: Some(client),
            err: "play timed out".into(),
        },
    }
}

pub fn format_time(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--:--".to_string();
    }
    let total = secs.round() as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

pub fn help_text(screen: Screen) -> &'static str {
    help_text_cast(screen, false)
}

pub fn help_text_cast(screen: Screen, screen_cast: bool) -> &'static str {
    match screen {
        Screen::Discovery => "↑↓ select  Enter TV (pair)  r refresh  q quit",
        Screen::Files => {
            "↑↓ select  type to search  Enter play  a add folder  d remove folder  Esc back"
        }
        Screen::AddFolder => "type path  Enter save  Esc cancel  ~ expands",
        Screen::Pin => "0–9 enter code  Enter confirm  Esc cancel",
        Screen::Control if screen_cast => "Esc stop  q quit",
        Screen::Control => {
            "Space play/pause  ←→ 10s  Shift+←→ 1m  0–9 jump 10%  Home/End  Esc stop  q quit"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{busy_dots, help_text, help_text_cast, BusyKind, Screen};

    #[test]
    fn busy_dots_cycle_connecting_pairing_playback() {
        assert_eq!(BusyKind::Connecting.label(), "Connecting");
        assert_eq!(BusyKind::Pairing.label(), "Pairing");
        assert_eq!(BusyKind::StartingPlayback.label(), "Starting playback");
        assert_eq!(BusyKind::SendingToTv.label(), "Sending to TV");
        assert_eq!(busy_dots(0), ".");
        assert_eq!(busy_dots(1), "..");
        assert_eq!(busy_dots(2), "...");
        assert_eq!(busy_dots(3), ".");
    }

    #[test]
    fn screen_cast_help_drops_seek_pause() {
        let h = help_text_cast(Screen::Control, true).to_ascii_lowercase();
        assert!(h.contains("esc"), "{h}");
        assert!(h.contains("quit"), "{h}");
        assert!(!h.contains("space"), "{h}");
        assert!(!h.contains("seek"), "{h}");
        assert!(!h.contains("pause"), "{h}");
        let http = help_text(Screen::Control).to_ascii_lowercase();
        assert!(http.contains("space"), "{http}");
    }

    #[test]
    fn discovery_help_mentions_pair_files_does_not_mention_pin() {
        let d = help_text(Screen::Discovery).to_ascii_lowercase();
        assert!(
            d.contains("pair"),
            "discovery help should mention pairing: {d}"
        );
        let f = help_text(Screen::Files).to_ascii_lowercase();
        assert!(!f.contains("pin"), "files help must not mention PIN: {f}");
        assert!(
            !f.contains("pair"),
            "files help must not mention pairing: {f}"
        );
    }
}

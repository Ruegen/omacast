//! omacast — AirPlay video TUI.
mod airplay;
mod app;
mod bplist;
mod config;
mod creds;
mod discovery;
mod event;
mod fairplay;
mod files;
mod hap;
mod hls;
mod http1;
mod http_media;
mod screen;
mod tlv8;
mod ui;

use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers};
use futures::StreamExt;
use ratatui::DefaultTerminal;
use uuid::Uuid;

use crate::airplay::AirPlayClient;
use crate::app::{App, Error};
use crate::discovery::AirPlayDevice;
use crate::http_media::MediaServer;

/// Minimalist AirPlay video TUI for keyboard-driven Linux.
#[derive(Debug, Parser)]
#[command(name = "omacast", version, about, long_about = None)]
struct Cli {
    /// Extra media folder for this run (appended to the saved folder list)
    #[arg(long, env = "OMACAST_MEDIA_DIR", value_name = "PATH")]
    media_dir: Option<PathBuf>,

    /// Bind port for the local media HTTP server (0 = ephemeral)
    #[arg(long, default_value_t = 0)]
    port: u16,

    /// Play a file headlessly against a known receiver (no TUI)
    #[arg(long, value_name = "PATH")]
    play: Option<PathBuf>,

    /// AirPlay receiver host (headless --play)
    #[arg(long, default_value = "192.168.178.25")]
    host: String,
}

fn main() {
    let cli = Cli::parse();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    if let Some(path) = cli.play {
        runtime.block_on(run_play(path, cli.host, cli.port));
        return;
    }

    let result = runtime.block_on(async move {
        let mut app = App::new(cli.media_dir, cli.port)?;
        let mut terminal = ratatui::init();
        install_panic_hook();
        let run_result = run(&mut terminal, &mut app).await;
        ratatui::restore();
        run_result
    });

    if let Err(err) = result {
        eprintln!("omacast: {err}");
        std::process::exit(1);
    }
}

async fn run_play(path: PathBuf, host: String, media_port: u16) {
    let name = "Lounge Room";
    let addresses = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => Vec::new(),
    };
    let device = AirPlayDevice {
        fullname: format!("{name}._airplay._tcp.local."),
        name: name.to_string(),
        host: host.clone(),
        port: 7000,
        addresses,
        deviceid: Some("56:CF:EF:D3:A2:AA".into()),
        features: Some("0x7F8AD0,0x38BCF46".into()),
        flags: None,
        model: Some("65A5HE".into()),
        pw: None,
        srcvers: Some("377.40.00".into()),
    };

    let store = creds::load();
    let Some(hap_creds) = creds::lookup(&store, &device.cred_lookup_keys()) else {
        eprintln!("omacast: no saved credentials for {name}");
        std::process::exit(1);
    };

    let local_path = path.clone();
    let screen = crate::airplay::is_screen_mirroring_tv(&device);
    let mut server = None;
    let location = if screen {
        format!("file://{}", local_path.to_string_lossy())
    } else {
        let hls = crate::airplay::device_wants_hls(&device);
        match MediaServer::start_for(path, media_port, hls).await {
            Ok(s) => {
                let loc = s.content_location();
                server = Some(s);
                loc
            }
            Err(err) => {
                eprintln!("omacast: media server: {err}");
                std::process::exit(2);
            }
        }
    };

    let sender_id = {
        let bytes = Uuid::new_v4().into_bytes();
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    };

    let mut client = match AirPlayClient::connect(device, sender_id).await {
        Ok(client) => client,
        Err(err) => {
            eprintln!("omacast: connect: {err}");
            std::process::exit(2);
        }
    };

    client.set_creds(hap_creds);

    if let Some(ref server) = server {
        client.set_media_gets(server.request_count());
        if let Some(dir) = server.hls_dir() {
            client.set_hls(dir, server.origin());
        }
    }
    // Handshake only (~75s). play() returns once the type-110 stream is rolling.
    let play_result = tokio::time::timeout(
        Duration::from_secs(75),
        client.play(&location, 0.0, Some(local_path.as_path())),
    )
    .await;

    match play_result {
        Ok(Ok(())) => println!("play: ok"),
        Ok(Err(err)) => println!("play: {}", err.message()),
        Err(_) => println!("play: timed out"),
    }

    if client.screen_stream_active() {
        // Full file: ffmpeg EOF (POST /feedback ~15s while waiting), then TEARDOWN. No 12s cap.
        client.wait_screen_stream_eof().await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = client.stop().await;
    } else {
        tokio::time::sleep(Duration::from_secs(8)).await;
    }
    drop(client);
    drop(server);
    std::process::exit(0);
}

fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        original(info);
    }));
}

async fn run(terminal: &mut DefaultTerminal, app: &mut App) -> Result<(), Error> {
    let mut events = EventStream::new();
    let mut ticks = tokio::time::interval(Duration::from_millis(200));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;

        let _ = app.has_pending_network();

        if app.should_quit {
            app.shutdown().await;
            break;
        }

        tokio::select! {
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if is_press_or_repeat(key) => {
                        if key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL)
                        {
                            app.should_quit = true;
                        } else {
                            app.handle_key(key).await;
                        }
                    }
                    Some(Ok(Event::Resize(_, _))) => {}
                    Some(Err(err)) => {
                        return Err(Error::Io(io::Error::other(err)));
                    }
                    None => break,
                    _ => {}
                }
            }
            event = app.discovery_event() => {
                if let Some(event) = event {
                    app.apply_discovery(event);
                }
            }
            _ = ticks.tick() => {
                app.on_tick().await;
            }
        }
    }

    Ok(())
}

fn is_press_or_repeat(key: KeyEvent) -> bool {
    matches!(
        key.kind,
        crossterm::event::KeyEventKind::Press | crossterm::event::KeyEventKind::Repeat
    )
}

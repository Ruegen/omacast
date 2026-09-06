//! AirPlay screen audio (type 96): ffmpeg PCM → ALAC verbatim → RTP + ChaCha.
//!
//! Matches iOS/Mac mirror SETUP: ALAC 44.1 kHz stereo, 352 samples/frame.
//! SETUP carries a 32-byte `shk`. Packets are
//! `[RTP 12][ciphertext+tag 16][nonce 8]` with AAD = timestamp ∥ SSRC.

use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};

const FFMPEG: &str = "/usr/bin/ffmpeg";
const SAMPLE_RATE: u32 = 44100;
const SPF: u32 = 352;
const PCM_FRAME: usize = SPF as usize * 2 * 2;
const PT_AUDIO: u8 = 96;
const PT_SYNC: u8 = 84;
const TAG_LEN: usize = 16;
const NONCE_WIRE: usize = 8;

const FFMPEG_PCM: &[&str] = &[
    "-nostdin",
    "-hide_banner",
    "-loglevel",
    "error",
    "-re",
    "-i",
];

const FFMPEG_PCM_AFTER: &[&str] = &[
    "-vn",
    "-c:a",
    "pcm_s16le",
    "-ar",
    "44100",
    "-ac",
    "2",
    "-f",
    "s16le",
    "pipe:1",
];

pub struct AudioStream {
    child: Option<Child>,
    task: Option<tokio::task::JoinHandle<()>>,
    packets: Arc<AtomicU64>,
}

impl Drop for AudioStream {
    fn drop(&mut self) {
        self.stop();
    }
}

impl AudioStream {
    pub fn packet_count(&self) -> u64 {
        self.packets.load(Ordering::Relaxed)
    }

    pub fn is_active(&self) -> bool {
        match &self.task {
            Some(t) => !t.is_finished(),
            None => false,
        }
    }

    pub fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
    }
}

/// PCM 44.1 kHz stereo → ALAC verbatim → encrypted RTP on `data_port`.
/// `shk` is never logged.
pub async fn start_audio_stream(
    host: &str,
    data_port: u16,
    control_port: Option<u16>,
    file: &Path,
    shk: &[u8; 32],
    log: impl Fn(&str) + Send + Sync + 'static,
) -> Option<AudioStream> {
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(log);
    if !Path::new(FFMPEG).is_file() {
        log(&format!("audio ffmpeg: not found at {FFMPEG}"));
        return None;
    }
    let file_s = file.to_string_lossy().into_owned();
    let mut cmd = Command::new(FFMPEG);
    cmd.kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.args(FFMPEG_PCM);
    cmd.arg(&file_s);
    cmd.args(FFMPEG_PCM_AFTER);
    log("ffmpeg audio: pcm_s16le 44100 stereo → ALAC 352 (no video)");
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            log(&format!("audio ffmpeg: {err}"));
            return None;
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.start_kill();
            log("audio ffmpeg: no stdout pipe");
            return None;
        }
    };
    if let Some(mut stderr) = child.stderr.take() {
        let log_err = log.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let mut acc = String::new();
            loop {
                match stderr.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => acc.push_str(&String::from_utf8_lossy(&buf[..n])),
                    Err(_) => break,
                }
            }
            for line in acc.lines().take(4) {
                let line = line.trim();
                if !line.is_empty() {
                    log_err(&format!("audio ffmpeg: {line}"));
                }
            }
        });
    }

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(err) => {
            let _ = child.start_kill();
            log(&format!("audio UDP bind: {err}"));
            return None;
        }
    };
    let dest = format!("{host}:{data_port}");
    if let Err(err) = sock.connect(&dest).await {
        let _ = child.start_kill();
        log(&format!("audio dataPort {data_port} connect: {err}"));
        return None;
    }
    log(&format!("audio dataPort {data_port} UDP ready"));

    let ctrl = if let Some(p) = control_port {
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => {
                let addr = format!("{host}:{p}");
                if s.connect(&addr).await.is_ok() {
                    log(&format!("audio controlPort {p} sync PT=84"));
                    Some(s)
                } else {
                    log(&format!("audio controlPort {p} connect fail; sync off"));
                    None
                }
            }
            Err(_) => {
                log("audio control UDP bind failed; sync packets off");
                None
            }
        }
    } else {
        None
    };

    let cipher = match ChaCha20Poly1305::new_from_slice(shk) {
        Ok(c) => c,
        Err(_) => {
            let _ = child.start_kill();
            log("audio: bad shk length");
            return None;
        }
    };

    let packets = Arc::new(AtomicU64::new(0));
    let packets_task = packets.clone();
    let log_task = log.clone();
    let task = tokio::spawn(async move {
        pump_alac(stdout, sock, ctrl, cipher, packets_task, log_task).await;
    });

    Some(AudioStream {
        child: Some(child),
        task: Some(task),
        packets,
    })
}

async fn pump_alac(
    mut stdout: tokio::process::ChildStdout,
    sock: UdpSocket,
    ctrl: Option<UdpSocket>,
    cipher: ChaCha20Poly1305,
    packets: Arc<AtomicU64>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let mut seq = 0u16;
    let mut ts = 0u32;
    let ssrc = 0x0A0C_0A57_u32;
    let mut first = true;
    let mut first_sync = true;
    let t0 = Instant::now();
    let mut next_sync = t0;
    let mut logged = 0u32;

    loop {
        match stdout.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
        while raw.len() >= PCM_FRAME {
            let frame: Vec<u8> = raw.drain(..PCM_FRAME).collect();
            let pcm = pcm_s16le(&frame);
            let au = encode_alac_verbatim_stereo(&pcm);
            let pkt = match encrypt_rtp(&cipher, seq, ts, ssrc, first, &au) {
                Some(p) => p,
                None => {
                    log("audio ChaCha encrypt fail");
                    return;
                }
            };
            if sock.send(&pkt).await.is_err() {
                return;
            }
            packets.fetch_add(1, Ordering::Relaxed);
            if logged < 2 {
                log(&format!(
                    "audio RTP seq={seq} ts={ts} alac={} wire={}",
                    au.len(),
                    pkt.len()
                ));
                logged += 1;
            }
            first = false;
            seq = seq.wrapping_add(1);
            ts = ts.wrapping_add(SPF);

            if let Some(ref c) = ctrl {
                let now = Instant::now();
                if now >= next_sync {
                    let sync = sync_packet(ts, first_sync);
                    let _ = c.send(&sync).await;
                    first_sync = false;
                    next_sync = now + Duration::from_secs(1);
                }
            }
        }
    }
}

fn pcm_s16le(bytes: &[u8]) -> Vec<i16> {
    bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// FFmpeg-compatible verbatim ALAC stereo frame (CPE + sample count + END).
pub fn encode_alac_verbatim_stereo(pcm: &[i16]) -> Vec<u8> {
    let n = pcm.len() / 2;
    let mut b = BitW::new();
    b.put(3, 1);
    b.put(4, 0);
    b.put(12, 0);
    b.put(1, 1);
    b.put(2, 0);
    b.put(1, 1);
    b.put(32, n as u32);
    for i in 0..n {
        b.put(16, pcm[i * 2] as u16 as u32);
        b.put(16, pcm[i * 2 + 1] as u16 as u32);
    }
    b.put(3, 7);
    b.finish()
}

struct BitW {
    buf: Vec<u8>,
    acc: u64,
    bits: u8,
}

impl BitW {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            acc: 0,
            bits: 0,
        }
    }

    fn put(&mut self, n: u8, val: u32) {
        let mask = if n >= 32 { u64::from(u32::MAX) } else { (1u64 << n) - 1 };
        self.acc = (self.acc << n) | (u64::from(val) & mask);
        self.bits += n;
        while self.bits >= 8 {
            self.bits -= 8;
            self.buf.push((self.acc >> self.bits) as u8);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.buf.push((self.acc << (8 - self.bits)) as u8);
        }
        self.buf
    }
}

pub fn encrypt_rtp(
    cipher: &ChaCha20Poly1305,
    seq: u16,
    ts: u32,
    ssrc: u32,
    marker: bool,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 12];
    hdr[0] = 0x80;
    hdr[1] = if marker {
        0x80 | PT_AUDIO
    } else {
        PT_AUDIO
    };
    hdr[2..4].copy_from_slice(&seq.to_be_bytes());
    hdr[4..8].copy_from_slice(&ts.to_be_bytes());
    hdr[8..12].copy_from_slice(&ssrc.to_be_bytes());

    let mut nonce = [0u8; 12];
    nonce[4..6].copy_from_slice(&seq.to_le_bytes());
    let aad = &hdr[4..12];
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad,
            },
        )
        .ok()?;
    if ct.len() < TAG_LEN {
        return None;
    }
    let mut pkt = Vec::with_capacity(12 + ct.len() + NONCE_WIRE);
    pkt.extend_from_slice(&hdr);
    pkt.extend_from_slice(&ct);
    pkt.extend_from_slice(&nonce[4..12]);
    Some(pkt)
}

fn sync_packet(next_ts: u32, first: bool) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = if first { 0x90 } else { 0x80 };
    pkt[1] = 0x80 | PT_SYNC;
    pkt[4..8].copy_from_slice(&next_ts.to_be_bytes());
    pkt[8..16].copy_from_slice(&ntp_now());
    pkt[16..20].copy_from_slice(&next_ts.to_be_bytes());
    pkt
}

fn ntp_now() -> [u8; 8] {
    const NTP_UNIX: u64 = 2_208_988_800;
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs().saturating_add(NTP_UNIX) as u32;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&secs.to_be_bytes());
    out[4..].copy_from_slice(&(frac as u32).to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alac_verbatim_has_cpe_and_end() {
        let pcm = [0i16; 352 * 2];
        let f = encode_alac_verbatim_stereo(&pcm);
        assert!(f.len() > 4, "{}", f.len());
        assert_eq!(f[0] & 0xE0, 0x20);
    }

    #[test]
    fn rtp_has_tag_then_nonce_trailer() {
        let key = [0x11u8; 32];
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let payload = b"aac-frame";
        let pkt = encrypt_rtp(&cipher, 42, 44100, 0x1234_5678, true, payload).unwrap();
        assert_eq!(pkt[0], 0x80);
        assert_eq!(pkt[1], 0x80 | PT_AUDIO);
        assert_eq!(&pkt[2..4], &42u16.to_be_bytes());
        assert_eq!(&pkt[4..8], &44100u32.to_be_bytes());
        let trailer = pkt.len() - 24;
        assert_eq!(&pkt[pkt.len() - 8..], &[42, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(pkt.len(), 12 + payload.len() + TAG_LEN + NONCE_WIRE);
        let cipher2 = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let mut nonce = [0u8; 12];
        nonce[4..6].copy_from_slice(&42u16.to_le_bytes());
        let pt = cipher2
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &pkt[12..pkt.len() - NONCE_WIRE],
                    aad: &pkt[4..12],
                },
            )
            .unwrap();
        assert_eq!(pt, payload);
        let _ = trailer;
    }

    #[test]
    fn ffmpeg_audio_is_pcm_no_video() {
        let joined = [FFMPEG_PCM, FFMPEG_PCM_AFTER].concat().join(" ");
        assert!(joined.contains("-re"), "{joined}");
        assert!(joined.contains("-vn"), "{joined}");
        assert!(joined.contains("pcm_s16le"), "{joined}");
        assert!(joined.contains("44100"), "{joined}");
        assert!(!joined.contains("-c:v"), "{joined}");
    }

    #[test]
    fn sample_rate_and_spf_match_alac() {
        assert_eq!(SAMPLE_RATE, 44100);
        assert_eq!(SPF, 352);
        assert_eq!(PCM_FRAME, 1408);
    }
}

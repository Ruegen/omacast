//! AirPlay screen-stream H264 sender (type 110 dataPort).
//!
//! ffmpeg re-encodes a local file to annex-B H264 on stdout (no window). Packets
//! follow the OpenAirPlay 128-byte little-endian header (DoubleTake 0.4.0):
//!   - bytes 0-3: payload size u32 LE
//!   - codec (type 1): [4]=0x01 [5]=0x00 [6]=0x16 [7]=0x01; encoded/display floats
//!   - video (type 0): [4]=0x00 [5]=0x10 if IDR else 0x00; [6]=0x00 [7]=0x00;
//!     [16:128] zeroed (no image-size data for VCL)
//!   - heartbeat (type 2): [4]=0x02 [6]=0x1e
//!   - bytes 8-15: boot-relative NTP 32.32 (100ms bias, no 1900 epoch)
//! Codec avcC is ISO 14496-15 plus a 4-byte trailer (0x02, rest zeros) observed
//! in iPhone/DoubleTake. VCL is AVCC (4-byte BE NAL lengths). HAP pair-verify
//! encrypts VCL with ChaCha20-Poly1305 (AAD = 128-byte header, +16 tag);
//! AES-CTR remains for legacy. Codec and heartbeat stay plaintext.
//! Codec headers advertise 1920x1080.

use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes::Aes128;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

type AesCtr = Ctr128BE<Aes128>;

const FFMPEG: &str = "/usr/bin/ffmpeg";
const HEADER_LEN: usize = 128;
const OPCODE_VIDEO: u8 = 0x00;
const OPCODE_CONFIG: u8 = 0x01;
const OPCODE_HEARTBEAT: u8 = 0x02;
const CODEC_OPTION: u8 = 0x16;
const CODEC_OPTION_HI: u8 = 0x01;
const HEARTBEAT_OPTION: u8 = 0x1e;
const DEFAULT_W: f32 = 1920.0;
const DEFAULT_H: f32 = 1080.0;
const TIMESTAMP_BIAS: Duration = Duration::from_millis(100);

const FFMPEG_ENCODE: &[&str] = &[
    "-nostdin",
    "-hide_banner",
    "-loglevel",
    "error",
    "-re",
    "-i",
];

pub struct ScreenStream {
    child: Option<Child>,
    task: Option<tokio::task::JoinHandle<()>>,
    frames: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
}

impl Drop for ScreenStream {
    fn drop(&mut self) {
        self.stop();
    }
}

impl ScreenStream {
    pub fn frame_count(&self) -> u64 {
        self.frames.load(Ordering::Relaxed)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
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

    pub async fn wait_until(&mut self, goal: ScreenWaitGoal, timeout: Option<Duration>) {
        let Some(task) = self.task.as_ref() else {
            return;
        };
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            let finished = task.is_finished();
            if screen_wait_done(goal, self.frame_count(), self.bytes_sent(), finished) {
                return;
            }
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

}

/// `play()` waits until first frames (Rolling). CLI `--play` waits for ffmpeg EOF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenWaitGoal {
    Rolling,
    UntilEof,
}

/// Whether a type-110 waiter should return.
/// Rolling: first frames/bytes, or the task already ended.
/// UntilEof: only when the stream task has finished (ffmpeg EOF).
pub fn screen_wait_done(goal: ScreenWaitGoal, frames: u64, bytes: u64, finished: bool) -> bool {
    match goal {
        ScreenWaitGoal::Rolling => frames > 0 || bytes > 0 || finished,
        ScreenWaitGoal::UntilEof => finished,
    }
}

const POLY1305_TAG_LEN: usize = 16;

enum PayloadCryptoInner {
    AesCtr(AesCtr),
    ChaCha {
        cipher: ChaCha20Poly1305,
        counter: u64,
    },
}

pub struct PayloadCrypto {
    inner: PayloadCryptoInner,
}

impl PayloadCrypto {
    pub fn aes_ctr(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            inner: PayloadCryptoInner::AesCtr(AesCtr::new(key.into(), iv.into())),
        }
    }

    pub fn chacha(key: &[u8; 32]) -> Self {
        Self {
            inner: PayloadCryptoInner::ChaCha {
                cipher: ChaCha20Poly1305::new_from_slice(key).expect("chacha key 32"),
                counter: 0,
            },
        }
    }

    pub fn is_chacha(&self) -> bool {
        matches!(&self.inner, PayloadCryptoInner::ChaCha { .. })
    }

    /// Wire payloadSize for a VCL frame: ChaCha includes the 16-byte Poly1305 tag.
    fn vcl_wire_len(&self, plaintext_len: usize) -> usize {
        match &self.inner {
            PayloadCryptoInner::AesCtr(_) => plaintext_len,
            PayloadCryptoInner::ChaCha { .. } => plaintext_len + POLY1305_TAG_LEN,
        }
    }

    /// Encrypt one VCL frame. `header` is the 128-byte packet header already
    /// filled (including payloadSize). ChaCha uses it as AAD. AES-CTR ignores it.
    fn encrypt_vcl(
        &mut self,
        header: &[u8; HEADER_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ()> {
        match &mut self.inner {
            PayloadCryptoInner::AesCtr(ctr) => {
                let mut data = plaintext.to_vec();
                ctr.apply_keystream(&mut data);
                Ok(data)
            }
            PayloadCryptoInner::ChaCha { cipher, counter } => {
                let mut nonce = [0u8; 12];
                nonce[4..12].copy_from_slice(&counter.to_le_bytes());
                let ct = cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: plaintext,
                            aad: header.as_slice(),
                        },
                    )
                    .map_err(|_| ())?;
                *counter = counter.wrapping_add(1);
                Ok(ct)
            }
        }
    }
}

/// Spawn ffmpeg → annex-B → 128-byte framed TCP. Returns None if ffmpeg cannot start.
pub async fn start_screen_stream(
    host: &str,
    data_port: u16,
    file: &Path,
    crypto: Option<PayloadCrypto>,
    log: impl Fn(&str) + Send + Sync + 'static,
) -> Option<ScreenStream> {
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(log);
    if !Path::new(FFMPEG).is_file() {
        log(&format!("ffmpeg: not found at {FFMPEG}"));
        return None;
    }
    // Advertise the encoded size, not the source file's ffprobe dimensions.
    let (width, height) = (DEFAULT_W, DEFAULT_H);
    let file_s = file.to_string_lossy().into_owned();
    let mut cmd = Command::new(FFMPEG);
    cmd.kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Match DoubleTake videotestsrc x264enc: zerolatency, no B-frames, IDR+SPS.
    // Re-encode (do not bitstream-copy High-profile MKV annex-B).
    cmd.args(FFMPEG_ENCODE);
    cmd.arg(&file_s);
    cmd.args([
        "-an",
        "-c:v",
        "libx264",
        "-tune",
        "zerolatency",
        "-profile:v",
        "baseline",
        "-pix_fmt",
        "yuv420p",
        "-g",
        "30",
        "-bf",
        "0",
        "-s",
        "1920x1080",
        "-x264-params",
        "repeat-headers=1:bframes=0:aud=1",
        "-f",
        "h264",
        "pipe:1",
    ]);
    log("ffmpeg: libx264 -tune zerolatency -profile:v baseline -pix_fmt yuv420p -g 30 -bf 0 -re 1920x1080");
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            log(&format!("ffmpeg: {err}"));
            return None;
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.start_kill();
            log("ffmpeg: no stdout pipe");
            return None;
        }
    };
    if let Some(mut stderr) = child.stderr.take() {
        let log_err = log.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut acc = String::new();
            loop {
                match stderr.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => acc.push_str(&String::from_utf8_lossy(&buf[..n])),
                    Err(_) => break,
                }
            }
            for line in acc.lines().take(8) {
                let line = line.trim();
                if !line.is_empty() {
                    log_err(&format!("ffmpeg: {line}"));
                }
            }
        });
    }

    let connect = TcpStream::connect((host, data_port));
    let stream = match tokio::time::timeout(Duration::from_secs(2), connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            let _ = child.start_kill();
            log(&format!("dataPort {data_port} connect fail: {err}"));
            return None;
        }
        Err(_) => {
            let _ = child.start_kill();
            log(&format!("dataPort {data_port} connect timeout"));
            return None;
        }
    };
    let _ = stream.set_nodelay(true);
    log(&format!("dataPort {data_port} connected"));
    match crypto.as_ref() {
        Some(c) if c.is_chacha() => {
            log("dataPort ChaCha20-Poly1305 VCL AAD=header tag=16");
        }
        Some(_) => {
            log("dataPort AES-CTR VCL only (codec plaintext avcC, type 0 encrypted)");
        }
        None => {
            log("dataPort unencrypted (codec avcC 01 00 16 01, video 00 10/00 00 00)");
        }
    }

    let frames = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let frames_task = frames.clone();
    let bytes_task = bytes.clone();
    let log_task = log.clone();
    let task = tokio::spawn(async move {
        pump_h264(
            stdout,
            stream,
            width,
            height,
            frames_task,
            bytes_task,
            crypto,
            log_task,
        )
        .await;
    });

    Some(ScreenStream {
        child: Some(child),
        task: Some(task),
        frames,
        bytes,
    })
}

async fn pump_h264(
    mut stdout: tokio::process::ChildStdout,
    stream: TcpStream,
    width: f32,
    height: f32,
    frames: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    crypto: Option<PayloadCrypto>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) {
    let mut parser = AnnexB::new();
    let mut buf = [0u8; 32 * 1024];
    let mut sender = FrameSender {
        stream,
        width,
        height,
        frames,
        bytes,
        crypto,
        sps: None,
        pps: None,
        vcl: Vec::new(),
        pending_keyframe: false,
        primed: false,
        logged_codec: false,
        logged_vcl: 0,
        log,
        t0: Instant::now(),
    };
    let mut hb = tokio::time::interval(Duration::from_secs(1));
    hb.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            res = stdout.read(&mut buf) => {
                match res {
                    Ok(0) => break,
                    Ok(n) => parser.push(&buf[..n]),
                    Err(_) => break,
                }
                while let Some(nal) = parser.next_nal() {
                    if !sender.push_nal(&nal).await {
                        return;
                    }
                }
            }
            _ = hb.tick() => {
                // DoubleTake waits until the first video/codec frame.
                // tokio::interval fires immediately; skip until primed.
                if sender.primed && !sender.send_heartbeat().await {
                    return;
                }
            }
        }
    }
    if let Some(nal) = parser.flush() {
        let _ = sender.push_nal(&nal).await;
    }
    let _ = sender.flush_vcl().await;
}

struct FrameSender {
    stream: TcpStream,
    width: f32,
    height: f32,
    frames: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    crypto: Option<PayloadCrypto>,
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
    vcl: Vec<u8>,
    pending_keyframe: bool,
    primed: bool,
    logged_codec: bool,
    logged_vcl: u32,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    t0: Instant,
}

impl FrameSender {
    async fn push_nal(&mut self, nal: &[u8]) -> bool {
        let Some(nt) = nal_type(nal) else {
            return true;
        };
        let raw = strip_start_code(nal);
        if raw.is_empty() {
            return true;
        }
        match nt {
            9 => self.flush_vcl().await,
            7 => {
                if !self.flush_vcl().await {
                    return false;
                }
                self.sps = Some(raw.to_vec());
                true
            }
            8 => {
                self.pps = Some(raw.to_vec());
                true
            }
            6 => true,
            5 => {
                if !self.vcl.is_empty() && !self.pending_keyframe {
                    if !self.flush_vcl().await {
                        return false;
                    }
                }
                if !self.vcl.is_empty() && self.pending_keyframe && is_first_slice(raw) {
                    if !self.flush_vcl().await {
                        return false;
                    }
                }
                self.pending_keyframe = true;
                avcc_append(&mut self.vcl, raw);
                true
            }
            1 | 2 | 3 | 4 => {
                if self.pending_keyframe && !self.vcl.is_empty() {
                    if !self.flush_vcl().await {
                        return false;
                    }
                }
                if !self.vcl.is_empty() && is_first_slice(raw) {
                    if !self.flush_vcl().await {
                        return false;
                    }
                }
                avcc_append(&mut self.vcl, raw);
                true
            }
            _ => true,
        }
    }

    async fn flush_vcl(&mut self) -> bool {
        if self.vcl.is_empty() {
            return true;
        }
        if !self.primed {
            if !self.pending_keyframe || self.sps.is_none() || self.pps.is_none() {
                self.vcl.clear();
                self.pending_keyframe = false;
                return true;
            }
        }

        let ts = ntp_from_elapsed(self.t0.elapsed());
        if self.pending_keyframe {
            if let (Some(sps), Some(pps)) = (self.sps.as_deref(), self.pps.as_deref()) {
                let avcc = build_avcc_config(sps, pps);
                if !self.logged_codec {
                    (self.log)(&format!(
                        "codec avcC len={} header[4]=0x01 header[6]=0x16 header[7]=0x01 unencrypted",
                        avcc.len()
                    ));
                    self.logged_codec = true;
                }
                if !self.write_all(&config_header(avcc.len(), ts, self.width, self.height), &avcc).await
                {
                    return false;
                }
                self.primed = true;
            } else if !self.primed {
                self.vcl.clear();
                self.pending_keyframe = false;
                return true;
            }
        }

        let plaintext = std::mem::take(&mut self.vcl);
        let avcc_len = plaintext.len();
        let keyframe = self.pending_keyframe;
        let wire_len = self
            .crypto
            .as_ref()
            .map(|c| c.vcl_wire_len(avcc_len))
            .unwrap_or(avcc_len);
        // Header first so ChaCha AAD includes payloadSize = plaintext + 16.
        let header = video_header(wire_len, ts, keyframe);
        let encrypted = self.crypto.is_some();
        let payload = if let Some(c) = self.crypto.as_mut() {
            match c.encrypt_vcl(&header, &plaintext) {
                Ok(p) => p,
                Err(()) => {
                    (self.log)("VCL encrypt fail");
                    return false;
                }
            }
        } else {
            plaintext
        };
        if self.logged_vcl < 3 {
            (self.log)(&format!(
                "VCL {} avcc_len={} header[4]=0x00 header[5]=0x{:02x} header[6]=0x00 encrypted={}",
                if keyframe { "IDR" } else { "P" },
                avcc_len,
                if keyframe { 0x10 } else { 0x00 },
                encrypted
            ));
            self.logged_vcl += 1;
        }
        if !self.write_all(&header, &payload).await {
            return false;
        }
        self.frames.fetch_add(1, Ordering::Relaxed);
        self.pending_keyframe = false;
        true
    }

    async fn send_heartbeat(&mut self) -> bool {
        self.write_all(&heartbeat_header(), &[]).await
    }

    async fn write_all(&mut self, header: &[u8], payload: &[u8]) -> bool {
        if self.stream.write_all(header).await.is_err() {
            return false;
        }
        if self.stream.write_all(payload).await.is_err() {
            return false;
        }
        self.bytes
            .fetch_add((header.len() + payload.len()) as u64, Ordering::Relaxed);
        true
    }
}

/// Boot-relative NTP 32.32 like DoubleTake `ntpTimeWithBias`.
/// `elapsed` is time since the stream Instant start; a 100ms bias is added.
/// No 1900 epoch offset (+2208988800).
pub fn ntp_from_elapsed(elapsed: Duration) -> u64 {
    let d = elapsed + TIMESTAMP_BIAS;
    let sec = d.as_secs();
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (sec << 32) | frac
}

fn put_dimensions(header: &mut [u8; HEADER_LEN], width: f32, height: f32) {
    for (offset, value) in [
        (16, width),
        (20, height),
        (40, width),
        (44, height),
        (56, DEFAULT_W),
        (60, DEFAULT_H),
    ] {
        header[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

pub fn config_header(payload_len: usize, timestamp: u64, width: f32, height: f32) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&(payload_len as u32).to_le_bytes());
    header[4] = OPCODE_CONFIG;
    header[5] = 0;
    header[6] = CODEC_OPTION;
    header[7] = CODEC_OPTION_HI;
    header[8..16].copy_from_slice(&timestamp.to_le_bytes());
    put_dimensions(&mut header, width, height);
    header
}

/// VCL packet header. [16:128] is zeroed — no image-size data for VCL
/// (DoubleTake sendFrame).
pub fn video_header(payload_len: usize, timestamp: u64, keyframe: bool) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(&(payload_len as u32).to_le_bytes());
    header[4] = OPCODE_VIDEO;
    header[5] = if keyframe { 0x10 } else { 0x00 };
    header[6] = 0x00;
    header[7] = 0x00;
    header[8..16].copy_from_slice(&timestamp.to_le_bytes());
    header
}

pub fn heartbeat_header() -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[4] = OPCODE_HEARTBEAT;
    header[6] = HEARTBEAT_OPTION;
    header
}

pub fn build_avcc_config(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let avcc_len = 6 + 2 + sps.len() + 1 + 2 + pps.len();
    // +4 trailer observed in iPhone/DoubleTake captures.
    let mut payload = vec![0u8; avcc_len + 4];
    payload[0] = 0x01;
    payload[1] = sps.get(1).copied().unwrap_or(0x42);
    payload[2] = sps.get(2).copied().unwrap_or(0);
    payload[3] = sps.get(3).copied().unwrap_or(0x1E);
    payload[4] = 0xff;
    payload[5] = 0xe1;
    payload[6..8].copy_from_slice(&(sps.len() as u16).to_be_bytes());
    payload[8..8 + sps.len()].copy_from_slice(sps);
    let off = 8 + sps.len();
    payload[off] = 0x01;
    payload[off + 1..off + 3].copy_from_slice(&(pps.len() as u16).to_be_bytes());
    payload[off + 3..off + 3 + pps.len()].copy_from_slice(pps);
    payload[avcc_len] = 0x02;
    payload
}

fn avcc_append(buf: &mut Vec<u8>, raw: &[u8]) {
    buf.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    buf.extend_from_slice(raw);
}

fn is_first_slice(raw: &[u8]) -> bool {
    raw.get(1).map(|b| b & 0x80 != 0).unwrap_or(false)
}

fn strip_start_code(nal: &[u8]) -> &[u8] {
    let skip = start_code_len(nal).unwrap_or(0);
    nal.get(skip..).unwrap_or(&[])
}

/// NAL unit type (low 5 bits of the first byte after the annex-B start code).
pub fn nal_type(nal: &[u8]) -> Option<u8> {
    let skip = start_code_len(nal)?;
    let b = *nal.get(skip)?;
    Some(b & 0x1F)
}

fn start_code_len(nal: &[u8]) -> Option<usize> {
    if nal.len() >= 4 && nal.starts_with(&[0, 0, 0, 1]) {
        Some(4)
    } else if nal.len() >= 3 && nal.starts_with(&[0, 0, 1]) {
        Some(3)
    } else if !nal.is_empty() {
        Some(0)
    } else {
        None
    }
}

pub fn find_start_code(buf: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i + 3 <= buf.len() {
        if i + 4 <= buf.len() && buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 1
        {
            return Some((i, 4));
        }
        if buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1 {
            return Some((i, 3));
        }
        i += 1;
    }
    None
}

struct AnnexB {
    buf: Vec<u8>,
}

impl AnnexB {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn next_nal(&mut self) -> Option<Vec<u8>> {
        let (start, _) = find_start_code(&self.buf, 0)?;
        if start > 0 {
            self.buf.drain(..start);
        }
        let (_, sc) = find_start_code(&self.buf, 0)?;
        let (next, _) = find_start_code(&self.buf, sc)?;
        let nal: Vec<u8> = self.buf.drain(..next).collect();
        Some(nal)
    }

    fn flush(&mut self) -> Option<Vec<u8>> {
        let (start, _) = find_start_code(&self.buf, 0)?;
        if start > 0 {
            self.buf.drain(..start);
        }
        if self.buf.len() <= 4 {
            return None;
        }
        Some(std::mem::take(&mut self.buf))
    }
}

pub fn is_timeout_err(err: &str) -> bool {
    err.contains("timed out")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_dim_floats(h: &[u8; HEADER_LEN], width: f32, height: f32) {
        assert_eq!(&h[16..20], &width.to_le_bytes());
        assert_eq!(&h[20..24], &height.to_le_bytes());
        assert_eq!(&h[40..44], &width.to_le_bytes());
        assert_eq!(&h[44..48], &height.to_le_bytes());
        assert_eq!(&h[56..60], &DEFAULT_W.to_le_bytes());
        assert_eq!(&h[60..64], &DEFAULT_H.to_le_bytes());
    }

    #[test]
    fn annex_b_splits_sps_pps_idr() {
        let mut p = AnnexB::new();
        let mut data = Vec::new();
        data.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0x00]);
        data.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xCE]);
        data.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88, 0x01]);
        p.push(&data);
        let sps = p.next_nal().unwrap();
        assert_eq!(nal_type(&sps), Some(7));
        let pps = p.next_nal().unwrap();
        assert_eq!(nal_type(&pps), Some(8));
        assert!(p.next_nal().is_none(), "IDR incomplete until next start or flush");
        let idr = p.flush().unwrap();
        assert_eq!(nal_type(&idr), Some(5));
        assert!(sps.starts_with(&[0, 0, 0, 1]));
        assert_eq!(strip_start_code(&sps), &[0x67, 0x42, 0x00]);
    }

    #[test]
    fn three_byte_start_code_and_p_slice() {
        let mut p = AnnexB::new();
        p.push(&[0, 0, 1, 0x41, 0xAA, 0, 0, 1, 0x41, 0xBB]);
        let a = p.next_nal().unwrap();
        assert_eq!(nal_type(&a), Some(1));
        assert!(a.starts_with(&[0, 0, 1]));
    }

    #[test]
    fn config_header_layout() {
        let h = config_header(42, 0x0102_0304_0506_0708, 1920.0, 1080.0);
        assert_eq!(h.len(), 128);
        assert_eq!(&h[..4], &42u32.to_le_bytes());
        assert_eq!([h[4], h[5], h[6], h[7]], [0x01, 0x00, 0x16, 0x01]);
        assert_eq!(&h[8..16], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_dim_floats(&h, 1920.0, 1080.0);
    }

    #[test]
    fn video_header_layout() {
        let k = video_header(9, 7, true);
        assert_eq!([k[4], k[5], k[6], k[7]], [0x00, 0x10, 0x00, 0x00]);
        assert_eq!(&k[8..16], &7u64.to_le_bytes());
        assert!(k[16..64].iter().all(|&b| b == 0), "VCL packets have no image-size floats");
        assert!(k[16..].iter().all(|&b| b == 0));
        let p = video_header(9, 7, false);
        assert_eq!([p[4], p[5], p[6], p[7]], [0x00, 0x00, 0x00, 0x00]);
        assert!(p[16..64].iter().all(|&b| b == 0));
    }

    #[test]
    fn codec_and_video_payload_type() {
        let c = config_header(8, 1, 1920.0, 1080.0);
        assert_eq!([c[4], c[5], c[6], c[7]], [0x01, 0x00, 0x16, 0x01]);
        let idr = video_header(8, 1, true);
        assert_eq!([idr[4], idr[5], idr[6], idr[7]], [0x00, 0x10, 0x00, 0x00]);
        let v = video_header(8, 1, false);
        assert_eq!([v[4], v[5], v[6], v[7]], [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn heartbeat_header_layout() {
        let h = heartbeat_header();
        assert_eq!(h.len(), 128);
        assert_eq!(&h[..4], &0u32.to_le_bytes());
        assert_eq!([h[4], h[5], h[6], h[7]], [2, 0, 0x1e, 0]);
    }

    #[test]
    fn avcc_config_has_iphone_trailer() {
        let sps = [0x67, 0x42, 0xC0, 0x1E, 0x00];
        let pps = [0x68, 0xCE, 0x06, 0xE2];
        let p = build_avcc_config(&sps, &pps);
        let avcc_len = 6 + 2 + sps.len() + 1 + 2 + pps.len();
        assert_eq!(p.len(), avcc_len + 4);
        assert_eq!(p[0], 0x01);
        assert_eq!(p[1], 0x42);
        assert_eq!(p[4], 0xff);
        assert_eq!(p[5], 0xe1);
        assert_eq!(u16::from_be_bytes(p[6..8].try_into().unwrap()), 5);
        assert_eq!(&p[8..13], &sps);
        assert_eq!(p[13], 0x01);
        assert_eq!(u16::from_be_bytes(p[14..16].try_into().unwrap()), 4);
        assert_eq!(&p[16..20], &pps);
        assert_eq!(p[avcc_len], 0x02);
        assert_eq!(&p[avcc_len + 1..], &[0, 0, 0]);
    }

    #[test]
    fn ntp_from_elapsed_is_boot_relative() {
        let t0 = ntp_from_elapsed(Duration::ZERO);
        let secs0 = t0 >> 32;
        assert_eq!(secs0, 0, "100ms bias is under 1s; high 32 bits stay small, not unix NTP");
        assert!(secs0 < 100, "must not be unix-epoch NTP (~0xE9xxxxxx)");
        let frac0 = t0 & 0xffff_ffff;
        let expected_frac = (100_000_000u64 << 32) / 1_000_000_000;
        assert_eq!(frac0, expected_frac);
        let t2 = ntp_from_elapsed(Duration::from_secs(2));
        assert_eq!(t2 >> 32, 2);
        assert!((t2 >> 32) < 0xE000_0000, "not unix-epoch NTP");
    }

    #[test]
    fn avcc_append_length_prefix() {
        let mut buf = Vec::new();
        avcc_append(&mut buf, &[0x65, 0x88]);
        assert_eq!(buf, vec![0, 0, 0, 2, 0x65, 0x88]);
    }

    #[test]
    fn timeout_err_detects_timed_out() {
        assert!(is_timeout_err("SETUP rtsp://192.0.2.1/1 timed out"));
        assert!(!is_timeout_err("SETUP 400"));
    }

    #[test]
    fn screen_wait_rolling_vs_eof() {
        use ScreenWaitGoal::{Rolling, UntilEof};
        assert!(!screen_wait_done(Rolling, 0, 0, false));
        assert!(screen_wait_done(Rolling, 1, 0, false));
        assert!(screen_wait_done(Rolling, 0, 80, false));
        assert!(screen_wait_done(Rolling, 0, 0, true));
        assert!(!screen_wait_done(UntilEof, 12, 4096, false), "frames must not end an UntilEof wait");
        assert!(screen_wait_done(UntilEof, 12, 4096, true));
        assert!(screen_wait_done(UntilEof, 0, 0, true));
    }

    #[test]
    fn chacha_vcl_header_size_includes_tag_and_roundtrips() {
        let key = [0x22u8; 32];
        let mut crypto = PayloadCrypto::chacha(&key);
        assert!(crypto.is_chacha());
        let plain = vec![1u8, 2, 3, 4, 5];
        let wire = crypto.vcl_wire_len(plain.len());
        assert_eq!(wire, plain.len() + 16);
        let header = video_header(wire, 0, true);
        assert_eq!(&header[..4], &(wire as u32).to_le_bytes());
        let ct = crypto.encrypt_vcl(&header, &plain).unwrap();
        assert_eq!(ct.len(), plain.len() + 16);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ct,
                    aad: header.as_slice(),
                },
            )
            .unwrap();
        assert_eq!(pt, plain);
        // Second frame uses counter=1 (nonce[4..12] = 1u64 LE).
        let header2 = video_header(wire, 0, false);
        let ct2 = crypto.encrypt_vcl(&header2, &plain).unwrap();
        assert_ne!(ct, ct2);
        let mut nonce1 = [0u8; 12];
        nonce1[4..12].copy_from_slice(&1u64.to_le_bytes());
        let pt2 = cipher
            .decrypt(
                Nonce::from_slice(&nonce1),
                Payload {
                    msg: &ct2,
                    aad: header2.as_slice(),
                },
            )
            .unwrap();
        assert_eq!(pt2, plain);
        // Wrong AAD must fail (header is bound).
        assert!(cipher
            .decrypt(
                Nonce::from_slice(&[0u8; 12]),
                Payload {
                    msg: &ct,
                    aad: &header2,
                },
            )
            .is_err());
    }

    #[test]
    fn aes_ctr_wire_len_has_no_tag() {
        let mut crypto = PayloadCrypto::aes_ctr(&[0x33; 16], &[0x44; 16]);
        assert!(!crypto.is_chacha());
        let plain = vec![9u8, 8, 7];
        assert_eq!(crypto.vcl_wire_len(plain.len()), plain.len());
        let header = video_header(plain.len(), 0, false);
        let out = crypto.encrypt_vcl(&header, &plain).unwrap();
        assert_eq!(out.len(), plain.len());
        assert_ne!(out, plain);
    }
}

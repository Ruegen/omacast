//! Minimal binary plist (bplist00) for AirPlay SETUP / POST /play bodies.
//!
//! Writer/reader covers dictionaries and arrays of ASCII strings, 64-bit
//! reals, integers, and booleans.

#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    String(String),
    Real(f64),
    Integer(i64),
    Boolean(bool),
    Data(Vec<u8>),
    Array(Vec<PlistValue>),
    Dict(Vec<(String, PlistValue)>),
}

enum Obj {
    String(String),
    Real(f64),
    Integer(i64),
    Boolean(bool),
    Data(Vec<u8>),
    Array(Vec<usize>),
    Dict { keys: Vec<usize>, vals: Vec<usize> },
}

/// Binary plist for AirPlay 2 `/play`: Content-Location + Start-Position-Seconds.
pub fn encode_play(content_location: &str, start_position: f64, uuid: &str) -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![
        (
            "Content-Location".into(),
            PlistValue::String(content_location.into()),
        ),
        (
            "Start-Position-Seconds".into(),
            PlistValue::Real(start_position),
        ),
        ("uuid".into(), PlistValue::String(uuid.into())),
        ("streamType".into(), PlistValue::Integer(1)),
        ("mediaType".into(), PlistValue::String("file".into())),
        ("rate".into(), PlistValue::Real(1.0)),
    ]))
}

/// Unified-control `POST /command` play wrapper used by hls.js AirPlaySDK TVs.
pub fn encode_command_play(content_location: &str, start_position: f64) -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![
        ("type".into(), PlistValue::String("play".into())),
        (
            "params".into(),
            PlistValue::Dict(vec![
                ("url".into(), PlistValue::String(content_location.into())),
                (
                    "Content-Location".into(),
                    PlistValue::String(content_location.into()),
                ),
                (
                    "Start-Position-Seconds".into(),
                    PlistValue::Real(start_position),
                ),
            ]),
        ),
    ]))
}

/// MRP `playlistInsert` (UxPlay / Crunchyroll AirPlay HLS).
pub fn encode_command_playlist_insert(content_location: &str, uuid: &str) -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![
        ("type".into(), PlistValue::String("playlistInsert".into())),
        (
            "params".into(),
            PlistValue::Dict(vec![(
                "item".into(),
                PlistValue::Dict(vec![
                    ("uuid".into(), PlistValue::String(uuid.into())),
                    (
                        "Content-Location".into(),
                        PlistValue::String(content_location.into()),
                    ),
                    ("mediaType".into(), PlistValue::String("streaming".into())),
                    ("streamType".into(), PlistValue::Integer(1)),
                    ("Start-Position-Seconds".into(), PlistValue::Real(0.0)),
                ]),
            )]),
        ),
    ]))
}

/// iPhone Crunchyroll / UxPlay: `POST /action` `playlistInsert` (HLS start).
pub fn encode_action_playlist_insert(content_location: &str, uuid: &str) -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![
        ("type".into(), PlistValue::String("playlistInsert".into())),
        (
            "params".into(),
            PlistValue::Dict(vec![(
                "item".into(),
                PlistValue::Dict(vec![
                    ("uuid".into(), PlistValue::String(uuid.into())),
                    (
                        "Content-Location".into(),
                        PlistValue::String(content_location.into()),
                    ),
                    ("url".into(), PlistValue::String(content_location.into())),
                    ("mediaType".into(), PlistValue::String("streaming".into())),
                    ("streamType".into(), PlistValue::Integer(1)),
                    ("Start-Position-Seconds".into(), PlistValue::Real(0.0)),
                    (
                        "clientProcName".into(),
                        PlistValue::String("omacast".into()),
                    ),
                    (
                        "clientBundleID".into(),
                        PlistValue::String("dev.omacast".into()),
                    ),
                ]),
            )]),
        ),
    ]))
}

/// XML plist of `playlistInsert` for `text/x-apple-plist+xml`.
pub fn encode_playlist_insert_xml(content_location: &str, uuid: &str) -> String {
    let uuid = xml_escape(uuid);
    let url = xml_escape(content_location);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>type</key><string>playlistInsert</string>\n\
  <key>params</key>\n\
  <dict>\n\
    <key>item</key>\n\
    <dict>\n\
      <key>uuid</key><string>{uuid}</string>\n\
      <key>Content-Location</key><string>{url}</string>\n\
      <key>mediaType</key><string>streaming</string>\n\
      <key>streamType</key><integer>1</integer>\n\
    </dict>\n\
  </dict>\n\
</dict>\n\
</plist>\n"
    )
}

/// JSON `playlistInsert` probe.
pub fn encode_playlist_insert_json(content_location: &str, uuid: &str) -> String {
    format!(
        "{{\"type\":\"playlistInsert\",\"params\":{{\"item\":{{\"uuid\":\"{}\",\"Content-Location\":\"{}\",\"mediaType\":\"streaming\",\"streamType\":1}}}}}}",
        json_escape(uuid),
        json_escape(content_location)
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// MRP `play` with `params.items` (Video V2 / unified media).
pub fn encode_command_play_items(content_location: &str, uuid: &str) -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![
        ("type".into(), PlistValue::String("play".into())),
        (
            "params".into(),
            PlistValue::Dict(vec![
                ("uuid".into(), PlistValue::String(uuid.into())),
                (
                    "items".into(),
                    PlistValue::Array(vec![PlistValue::Dict(vec![
                        ("uuid".into(), PlistValue::String(uuid.into())),
                        (
                            "Content-Location".into(),
                            PlistValue::String(content_location.into()),
                        ),
                        ("url".into(), PlistValue::String(content_location.into())),
                        ("mediaType".into(), PlistValue::String("streaming".into())),
                        ("streamType".into(), PlistValue::Integer(1)),
                    ])]),
                ),
            ]),
        ),
    ]))
}

/// Sender POST `/action` after a reverse-HTTP FCUP playlist request.
pub fn encode_fcup_response(url: &str, request_id: i64, data: &[u8], status: i64) -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![
        (
            "type".into(),
            PlistValue::String("unhandledURLResponse".into()),
        ),
        (
            "params".into(),
            PlistValue::Dict(vec![
                (
                    "FCUP_Response_URL".into(),
                    PlistValue::String(url.into()),
                ),
                (
                    "FCUP_Response_Data".into(),
                    PlistValue::Data(data.to_vec()),
                ),
                (
                    "FCUP_Response_StatusCode".into(),
                    PlistValue::Integer(status),
                ),
                (
                    "FCUP_Response_RequestID".into(),
                    PlistValue::Integer(request_id),
                ),
            ]),
        ),
    ]))
}

/// Receiver POST `/event` `unhandledURLRequest` (tests + logging).
pub fn encode_fcup_request(url: &str, request_id: i64, session_id: &str) -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![
        ("sessionID".into(), PlistValue::Integer(1)),
        (
            "type".into(),
            PlistValue::String("unhandledURLRequest".into()),
        ),
        (
            "request".into(),
            PlistValue::Dict(vec![
                ("FCUP_Response_ClientInfo".into(), PlistValue::Integer(1)),
                (
                    "FCUP_Response_ClientRef".into(),
                    PlistValue::Integer(40030004),
                ),
                (
                    "FCUP_Response_RequestID".into(),
                    PlistValue::Integer(request_id),
                ),
                (
                    "FCUP_Response_URL".into(),
                    PlistValue::String(url.into()),
                ),
                ("sessionID".into(), PlistValue::Integer(1)),
                (
                    "FCUP_Response_Headers".into(),
                    PlistValue::Dict(vec![
                        (
                            "X-Playback-Session-Id".into(),
                            PlistValue::String(session_id.into()),
                        ),
                        (
                            "User-Agent".into(),
                            PlistValue::String(
                                "AppleCoreMedia/1.0.0.11B554a (Apple TV; U; CPU OS 7_0_4 like Mac OS X; en_us"
                                    .into(),
                            ),
                        ),
                    ]),
                ),
            ]),
        ),
    ]))
}

/// Binary plist for AirPlay 2 RTSP SETUP (pyatv `_setup_base`).
///
/// `is_screen_mirroring` is true when the receiver advertises Screen and not
/// Video (bit 0 off) — Hisense-style screen-only TVs.
pub fn encode_setup(
    device_id: &str,
    session_uuid: &str,
    timing_port: u16,
    is_screen_mirroring: bool,
) -> Vec<u8> {
    encode_setup_body(
        device_id,
        session_uuid,
        timing_port,
        is_screen_mirroring,
        None,
        None,
        None,
    )
}

/// Screen-mirroring session SETUP. `ekey`/`eiv` are FairPlay-wrapped AES material
/// when the handshake produced them; omit both for an unencrypted probe.
pub fn encode_setup_fairplay(
    device_id: &str,
    session_uuid: &str,
    timing_port: u16,
    ekey: Option<&[u8]>,
    eiv: Option<&[u8]>,
) -> Vec<u8> {
    encode_setup_body(device_id, session_uuid, timing_port, true, ekey, eiv, None)
}

/// Screen session SETUP with optional sender eventPort (TCP in 60000-60010).
pub fn encode_setup_screen_session(
    device_id: &str,
    session_uuid: &str,
    timing_port: u16,
    event_port: Option<u16>,
) -> Vec<u8> {
    encode_setup_body(
        device_id,
        session_uuid,
        timing_port,
        true,
        None,
        None,
        event_port,
    )
}

fn encode_setup_body(
    device_id: &str,
    session_uuid: &str,
    timing_port: u16,
    is_screen_mirroring: bool,
    ekey: Option<&[u8]>,
    eiv: Option<&[u8]>,
    event_port: Option<u16>,
) -> Vec<u8> {
    let mut pairs = vec![
        ("deviceID".into(), PlistValue::String(device_id.into())),
        (
            "sessionUUID".into(),
            PlistValue::String(session_uuid.into()),
        ),
        (
            "timingPort".into(),
            PlistValue::Integer(i64::from(timing_port)),
        ),
        ("timingProtocol".into(), PlistValue::String("NTP".into())),
        ("isMultiSelectAirPlay".into(), PlistValue::Boolean(true)),
        (
            "groupContainsGroupLeader".into(),
            PlistValue::Boolean(false),
        ),
        ("macAddress".into(), PlistValue::String(device_id.into())),
        ("model".into(), PlistValue::String("iPhone14,3".into())),
        ("name".into(), PlistValue::String("omacast".into())),
        ("osBuildVersion".into(), PlistValue::String("20F66".into())),
        ("osName".into(), PlistValue::String("iPhone OS".into())),
        ("osVersion".into(), PlistValue::String("16.5".into())),
        ("senderSupportsRelay".into(), PlistValue::Boolean(false)),
        ("sourceVersion".into(), PlistValue::String("690.7.1".into())),
        ("statsCollectionEnabled".into(), PlistValue::Boolean(false)),
    ];
    if is_screen_mirroring {
        pairs.push((
            "isScreenMirroringSession".into(),
            PlistValue::Boolean(true),
        ));
    }
    if let Some(key) = ekey {
        pairs.push(("ekey".into(), PlistValue::Data(key.to_vec())));
        pairs.push(("et".into(), PlistValue::Integer(32)));
    }
    if let Some(iv) = eiv {
        pairs.push(("eiv".into(), PlistValue::Data(iv.to_vec())));
    }
    if let Some(port) = event_port {
        pairs.push(("eventPort".into(), PlistValue::Integer(i64::from(port))));
    }
    to_binary(&PlistValue::Dict(pairs))
}

/// `eventPort` from an RTSP SETUP response plist, if present.
pub fn event_port_from_setup(bytes: &[u8]) -> Option<u16> {
    let root = from_binary(bytes).ok()?;
    let PlistValue::Dict(pairs) = root else {
        return None;
    };
    for (k, v) in &pairs {
        if k == "eventPort" {
            return port_from_value(v);
        }
    }
    None
}

fn stream_connection_id_i64(stream_connection_id: u64) -> i64 {
    (stream_connection_id & (i64::MAX as u64)).max(1) as i64
}

const TIMESTAMP_INFO_NAMES: [&str; 5] = ["SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc"];

/// RTSP SETUP body for AirPlay screen stream type 110 (airplay-rs create_setup_request).
///
/// `streams` is an array of one dict: type 110, a nonzero `streamConnectionID`,
/// `timestampInfo` names, `latencyMs` 90, `fps` 30, `usingScreen`,
/// `supportsHighAccuracyTimestamps`. No FairPlay/Data blobs.
pub fn encode_setup_screen(stream_connection_id: u64) -> Vec<u8> {
    encode_setup_screen_body(stream_connection_id, true, None, None)
}

/// Slimmer type-110 SETUP: only `type` and `streamConnectionID` in the stream dict.
pub fn encode_setup_screen_slim(stream_connection_id: u64) -> Vec<u8> {
    encode_setup_screen_body(stream_connection_id, false, None, None)
}

/// Type-120 playback SETUP: `{streams:[{type:120, Content-Location, url, ...}]}`.
pub fn encode_setup_type_120(content_location: &str, uuid: &str) -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![(
        "streams".into(),
        PlistValue::Array(vec![PlistValue::Dict(vec![
            ("type".into(), PlistValue::Integer(120)),
            (
                "Content-Location".into(),
                PlistValue::String(content_location.into()),
            ),
            ("url".into(), PlistValue::String(content_location.into())),
            ("uuid".into(), PlistValue::String(uuid.into())),
            (
                "mediaType".into(),
                PlistValue::String(if content_location.contains(".m3u8")
                    || content_location.starts_with("mlhls://")
                {
                    "streaming".into()
                } else {
                    "file".into()
                }),
            ),
            ("streamType".into(), PlistValue::Integer(1)),
            (
                "Start-Position-Seconds".into(),
                PlistValue::Real(0.0),
            ),
        ])]),
    )]))
}

/// YouTube / Apple Music video relay: `{streams:[{type:120}]}` only.
pub fn encode_setup_type_120_minimal() -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![(
        "streams".into(),
        PlistValue::Array(vec![PlistValue::Dict(vec![(
            "type".into(),
            PlistValue::Integer(120),
        )])]),
    )]))
}

/// Type-120 SETUP with sender-advertised listening ports (hunch: TV connects to us).
pub fn encode_setup_type_120_sender_ports(
    content_location: &str,
    uuid: &str,
    data_port: u16,
    control_port: u16,
    timing_port: u16,
) -> Vec<u8> {
    to_binary(&PlistValue::Dict(vec![(
        "streams".into(),
        PlistValue::Array(vec![PlistValue::Dict(vec![
            ("type".into(), PlistValue::Integer(120)),
            (
                "Content-Location".into(),
                PlistValue::String(content_location.into()),
            ),
            ("url".into(), PlistValue::String(content_location.into())),
            ("uuid".into(), PlistValue::String(uuid.into())),
            ("dataPort".into(), PlistValue::Integer(i64::from(data_port))),
            (
                "controlPort".into(),
                PlistValue::Integer(i64::from(control_port)),
            ),
            (
                "timingPort".into(),
                PlistValue::Integer(i64::from(timing_port)),
            ),
        ])]),
    )]))
}

/// iOS-like type-110 SETUP plus `uuid`.
pub fn encode_setup_screen_ios(stream_connection_id: u64, uuid: &str) -> Vec<u8> {
    encode_setup_screen_body(stream_connection_id, true, Some(uuid), None)
}

/// iOS-like type-110 SETUP with optional FairPlay `ekey` (length logged, not bytes).
pub fn encode_setup_screen_ios_ekey(
    stream_connection_id: u64,
    uuid: &str,
    ekey: Option<&[u8]>,
) -> Vec<u8> {
    encode_setup_screen_body(stream_connection_id, true, Some(uuid), ekey)
}

/// Type-110 SETUP with ekey/eiv plus sender UDP timing/control ports.
pub fn encode_setup_screen_ios_fp(
    stream_connection_id: u64,
    uuid: &str,
    ekey: Option<&[u8]>,
    eiv: Option<&[u8]>,
    timing_port: u16,
    control_port: u16,
) -> Vec<u8> {
    encode_setup_screen_body_full(
        stream_connection_id,
        true,
        Some(uuid),
        ekey,
        eiv,
        Some(timing_port),
        Some(control_port),
    )
}

/// SETUP-response key list (no data blobs / secrets).
pub fn setup_response_keys(bytes: &[u8]) -> String {
    match from_binary(bytes) {
        Ok(val) => {
            let keys = crate::event::plist_key_names(&val);
            if keys.is_empty() {
                "keys=-".into()
            } else {
                format!("keys={}", keys.join(","))
            }
        }
        Err(_) => "keys=?".into(),
    }
}

fn timestamp_info_array() -> PlistValue {
    PlistValue::Array(
        TIMESTAMP_INFO_NAMES
            .iter()
            .map(|name| {
                PlistValue::Dict(vec![("name".into(), PlistValue::String((*name).into()))])
            })
            .collect(),
    )
}

fn encode_setup_screen_body(
    stream_connection_id: u64,
    extra: bool,
    uuid: Option<&str>,
    ekey: Option<&[u8]>,
) -> Vec<u8> {
    encode_setup_screen_body_full(stream_connection_id, extra, uuid, ekey, None, None, None)
}

fn encode_setup_screen_body_full(
    stream_connection_id: u64,
    extra: bool,
    uuid: Option<&str>,
    ekey: Option<&[u8]>,
    eiv: Option<&[u8]>,
    timing_port: Option<u16>,
    control_port: Option<u16>,
) -> Vec<u8> {
    let id = stream_connection_id_i64(stream_connection_id);
    let mut stream = vec![
        ("type".into(), PlistValue::Integer(110)),
        ("streamConnectionID".into(), PlistValue::Integer(id)),
    ];
    if extra {
        stream.push(("timestampInfo".into(), timestamp_info_array()));
        stream.push(("latencyMs".into(), PlistValue::Integer(90)));
        stream.push(("fps".into(), PlistValue::Integer(30)));
        stream.push(("usingScreen".into(), PlistValue::Boolean(true)));
        stream.push((
            "supportsHighAccuracyTimestamps".into(),
            PlistValue::Boolean(true),
        ));
        if let Some(u) = uuid {
            stream.push(("uuid".into(), PlistValue::String(u.into())));
        }
        if let Some(key) = ekey {
            stream.push(("ekey".into(), PlistValue::Data(key.to_vec())));
            stream.push(("et".into(), PlistValue::Integer(32)));
        }
        if let Some(iv) = eiv {
            stream.push(("eiv".into(), PlistValue::Data(iv.to_vec())));
        }
        if let Some(port) = timing_port {
            stream.push(("timingPort".into(), PlistValue::Integer(i64::from(port))));
        }
        if let Some(port) = control_port {
            stream.push(("controlPort".into(), PlistValue::Integer(i64::from(port))));
        }
    }
    to_binary(&PlistValue::Dict(vec![(
        "streams".into(),
        PlistValue::Array(vec![PlistValue::Dict(stream)]),
    )]))
}

/// `dataPort` from a screen-stream SETUP response (`streams[0].dataPort`).
/// Extra keys on the root or stream dict are ignored.
pub fn data_port_from_setup(bytes: &[u8]) -> Option<u16> {
    let root = from_binary(bytes).ok()?;
    let PlistValue::Dict(pairs) = root else {
        return None;
    };
    for (k, v) in &pairs {
        if k != "streams" {
            continue;
        }
        let PlistValue::Array(items) = v else {
            continue;
        };
        for item in items {
            let PlistValue::Dict(stream) = item else {
                continue;
            };
            for (sk, sv) in stream {
                if sk == "dataPort" {
                    return port_from_value(sv);
                }
            }
            // First dict had no usable dataPort.
            return None;
        }
        return None;
    }
    None
}

fn port_from_value(v: &PlistValue) -> Option<u16> {
    match v {
        PlistValue::Integer(n) if (1..=i64::from(u16::MAX)).contains(n) => Some(*n as u16),
        PlistValue::Real(r) if r.is_finite() && *r >= 1.0 && *r <= f64::from(u16::MAX) => {
            Some(*r as u16)
        }
        _ => None,
    }
}

/// Decode a play plist produced by [`encode_play`].
#[cfg(test)]
pub fn decode_play(bytes: &[u8]) -> Result<(String, f64), String> {
    let root = from_binary(bytes)?;
    let PlistValue::Dict(pairs) = root else {
        return Err("play plist root is not a dict".into());
    };
    let mut location = None;
    let mut start = None;
    for (k, v) in pairs {
        match (k.as_str(), v) {
            ("Content-Location", PlistValue::String(s)) => location = Some(s),
            ("Start-Position-Seconds", PlistValue::Real(r)) => start = Some(r),
            _ => {}
        }
    }
    match (location, start) {
        (Some(l), Some(s)) => Ok((l, s)),
        _ => Err("play plist missing Content-Location or Start-Position-Seconds".into()),
    }
}

pub fn to_binary(root: &PlistValue) -> Vec<u8> {
    let mut objs: Vec<Obj> = Vec::new();
    let top = intern(&mut objs, root);
    let n = objs.len();
    let ref_size = int_size(n.saturating_sub(1) as u64);

    let encoded: Vec<Vec<u8>> = objs.iter().map(|o| encode_obj(o, ref_size)).collect();

    let mut body = Vec::from(*b"bplist00");
    let mut offsets = Vec::with_capacity(n);
    for chunk in &encoded {
        offsets.push(body.len() as u64);
        body.extend_from_slice(chunk);
    }
    let offset_table_off = body.len() as u64;
    let max_off = offsets.last().copied().unwrap_or(0);
    let off_size = int_size(max_off);
    for off in offsets {
        write_be(&mut body, off, off_size);
    }

    // 32-byte trailer
    body.extend_from_slice(&[0u8; 6]);
    body.push(off_size);
    body.push(ref_size);
    body.extend_from_slice(&(n as u64).to_be_bytes());
    body.extend_from_slice(&(top as u64).to_be_bytes());
    body.extend_from_slice(&offset_table_off.to_be_bytes());
    body
}

pub fn from_binary(bytes: &[u8]) -> Result<PlistValue, String> {
    if bytes.len() < 8 + 32 || !bytes.starts_with(b"bplist00") {
        return Err("not a bplist00 buffer".into());
    }
    let t = &bytes[bytes.len() - 32..];
    let off_size = t[6] as usize;
    let ref_size = t[7] as usize;
    if off_size == 0 || off_size > 8 || ref_size == 0 || ref_size > 8 {
        return Err("bad bplist trailer sizes".into());
    }
    let num = u64::from_be_bytes(t[8..16].try_into().unwrap()) as usize;
    let top = u64::from_be_bytes(t[16..24].try_into().unwrap()) as usize;
    let table_off = u64::from_be_bytes(t[24..32].try_into().unwrap()) as usize;
    if num == 0 || top >= num {
        return Err("bad bplist object count".into());
    }
    let table_end = table_off.saturating_add(num.saturating_mul(off_size));
    if table_end > bytes.len() - 32 {
        return Err("bplist offset table truncated".into());
    }
    let mut offsets = Vec::with_capacity(num);
    for i in 0..num {
        let s = table_off + i * off_size;
        offsets.push(read_be(&bytes[s..s + off_size]) as usize);
    }
    parse_obj(bytes, &offsets, top, ref_size)
}

fn intern(objs: &mut Vec<Obj>, v: &PlistValue) -> usize {
    match v {
        PlistValue::String(s) => {
            objs.push(Obj::String(s.clone()));
            objs.len() - 1
        }
        PlistValue::Real(r) => {
            objs.push(Obj::Real(*r));
            objs.len() - 1
        }
        PlistValue::Integer(n) => {
            objs.push(Obj::Integer(*n));
            objs.len() - 1
        }
        PlistValue::Boolean(b) => {
            objs.push(Obj::Boolean(*b));
            objs.len() - 1
        }
        PlistValue::Data(d) => {
            objs.push(Obj::Data(d.clone()));
            objs.len() - 1
        }
        PlistValue::Array(items) => {
            let mut refs = Vec::with_capacity(items.len());
            for item in items {
                refs.push(intern(objs, item));
            }
            objs.push(Obj::Array(refs));
            objs.len() - 1
        }
        PlistValue::Dict(pairs) => {
            let mut keys = Vec::new();
            let mut vals = Vec::new();
            for (k, val) in pairs {
                keys.push(intern(objs, &PlistValue::String(k.clone())));
                vals.push(intern(objs, val));
            }
            objs.push(Obj::Dict { keys, vals });
            objs.len() - 1
        }
    }
}

fn encode_obj(o: &Obj, ref_size: u8) -> Vec<u8> {
    match o {
        Obj::String(s) => {
            let b = s.as_bytes();
            let mut out = Vec::new();
            push_marker(&mut out, 0x50, b.len());
            out.extend_from_slice(b);
            out
        }
        Obj::Real(r) => {
            let mut out = vec![0x23];
            out.extend_from_slice(&r.to_bits().to_be_bytes());
            out
        }
        Obj::Integer(n) => encode_int(*n),
        Obj::Boolean(false) => vec![0x08],
        Obj::Boolean(true) => vec![0x09],
        Obj::Data(d) => {
            let mut out = Vec::new();
            push_marker(&mut out, 0x40, d.len());
            out.extend_from_slice(d);
            out
        }
        Obj::Array(refs) => {
            let mut out = Vec::new();
            push_marker(&mut out, 0xA0, refs.len());
            for idx in refs {
                write_be(&mut out, *idx as u64, ref_size);
            }
            out
        }
        Obj::Dict { keys, vals } => {
            let mut out = Vec::new();
            push_marker(&mut out, 0xD0, keys.len());
            for idx in keys.iter().chain(vals.iter()) {
                write_be(&mut out, *idx as u64, ref_size);
            }
            out
        }
    }
}

fn encode_int(n: i64) -> Vec<u8> {
    // Signed two's-complement so values like 61145 are 4-byte, not a negative i16.
    if (-0x80..=0x7F).contains(&n) {
        vec![0x10, n as u8]
    } else if (-0x8000..=0x7FFF).contains(&n) {
        let mut out = vec![0x11];
        out.extend_from_slice(&(n as i16).to_be_bytes());
        out
    } else if (i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&n) {
        let mut out = vec![0x12];
        out.extend_from_slice(&(n as i32).to_be_bytes());
        out
    } else {
        let mut out = vec![0x13];
        out.extend_from_slice(&n.to_be_bytes());
        out
    }
}

fn parse_obj(
    buf: &[u8],
    offsets: &[usize],
    idx: usize,
    ref_size: usize,
) -> Result<PlistValue, String> {
    let off = *offsets.get(idx).ok_or("object ref out of range")?;
    let marker = *buf.get(off).ok_or("object truncated")?;
    let ty = marker & 0xF0;
    let nibble = marker & 0x0F;
    match ty {
        0x00 => match nibble {
            0x08 => Ok(PlistValue::Boolean(false)),
            0x09 => Ok(PlistValue::Boolean(true)),
            _ => Err(format!(
                "unsupported bplist null/bool nibble 0x{nibble:02X}"
            )),
        },
        0x10 => {
            let size = 1usize << nibble;
            let start = off + 1;
            let end = start.saturating_add(size);
            if end > buf.len() {
                return Err("int truncated".into());
            }
            let mut b = [0u8; 8];
            b[8 - size..].copy_from_slice(&buf[start..end]);
            if size < 8 && buf[start] & 0x80 != 0 {
                for slot in b.iter_mut().take(8 - size) {
                    *slot = 0xFF;
                }
            }
            Ok(PlistValue::Integer(i64::from_be_bytes(b)))
        }
        0x40 => {
            let (len, start) = object_len(buf, off, nibble)?;
            let end = start.saturating_add(len);
            if end > buf.len() {
                return Err("data truncated".into());
            }
            Ok(PlistValue::Data(buf[start..end].to_vec()))
        }
        0x50 => {
            let (len, start) = object_len(buf, off, nibble)?;
            let end = start.saturating_add(len);
            if end > buf.len() {
                return Err("string truncated".into());
            }
            let s = String::from_utf8(buf[start..end].to_vec()).map_err(|e| e.to_string())?;
            Ok(PlistValue::String(s))
        }
        0x20 => {
            let size = 1usize << nibble;
            let start = off + 1;
            let end = start.saturating_add(size);
            if end > buf.len() {
                return Err("real truncated".into());
            }
            if size == 8 {
                let bits = u64::from_be_bytes(buf[start..end].try_into().unwrap());
                Ok(PlistValue::Real(f64::from_bits(bits)))
            } else if size == 4 {
                let bits = u32::from_be_bytes(buf[start..end].try_into().unwrap());
                Ok(PlistValue::Real(f32::from_bits(bits) as f64))
            } else {
                Err(format!("unsupported real size {size}"))
            }
        }
        0xD0 => {
            let (count, mut pos) = object_len(buf, off, nibble)?;
            let mut keys = Vec::with_capacity(count);
            let mut vals = Vec::with_capacity(count);
            for _ in 0..count {
                if pos + ref_size > buf.len() {
                    return Err("dict key ref truncated".into());
                }
                let r = read_be(&buf[pos..pos + ref_size]) as usize;
                pos += ref_size;
                keys.push(r);
            }
            for _ in 0..count {
                if pos + ref_size > buf.len() {
                    return Err("dict val ref truncated".into());
                }
                let r = read_be(&buf[pos..pos + ref_size]) as usize;
                pos += ref_size;
                vals.push(r);
            }
            let mut pairs = Vec::with_capacity(count);
            for (k, v) in keys.into_iter().zip(vals) {
                let key = match parse_obj(buf, offsets, k, ref_size)? {
                    PlistValue::String(s) => s,
                    _ => return Err("dict key is not a string".into()),
                };
                let val = parse_obj(buf, offsets, v, ref_size)?;
                pairs.push((key, val));
            }
            Ok(PlistValue::Dict(pairs))
        }
        0xA0 => {
            let (count, mut pos) = object_len(buf, off, nibble)?;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                if pos + ref_size > buf.len() {
                    return Err("array ref truncated".into());
                }
                let r = read_be(&buf[pos..pos + ref_size]) as usize;
                pos += ref_size;
                items.push(parse_obj(buf, offsets, r, ref_size)?);
            }
            Ok(PlistValue::Array(items))
        }
        _ => Err(format!("unsupported bplist type 0x{ty:02X}")),
    }
}

fn object_len(buf: &[u8], off: usize, nibble: u8) -> Result<(usize, usize), String> {
    if nibble != 0x0F {
        return Ok((nibble as usize, off + 1));
    }
    let int_off = off + 1;
    let marker = *buf.get(int_off).ok_or("inline length truncated")?;
    if marker & 0xF0 != 0x10 {
        return Err("inline length is not an int".into());
    }
    let size = 1usize << (marker & 0x0F);
    let start = int_off + 1;
    let end = start.saturating_add(size);
    if end > buf.len() {
        return Err("inline length truncated".into());
    }
    Ok((read_be(&buf[start..end]) as usize, end))
}

fn push_marker(out: &mut Vec<u8>, base: u8, len: usize) {
    if len < 15 {
        out.push(base | (len as u8));
    } else {
        out.push(base | 0x0F);
        push_int(out, len as u64);
    }
}

fn push_int(out: &mut Vec<u8>, n: u64) {
    if n <= 0xFF {
        out.push(0x10);
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0x11);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(0x12);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(0x13);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn int_size(n: u64) -> u8 {
    if n <= 0xFF {
        1
    } else if n <= 0xFFFF {
        2
    } else if n <= 0xFFFF_FFFF {
        4
    } else {
        8
    }
}

fn write_be(out: &mut Vec<u8>, n: u64, size: u8) {
    let b = n.to_be_bytes();
    out.extend_from_slice(&b[8 - size as usize..]);
}

fn read_be(slice: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b[8 - slice.len()..].copy_from_slice(slice);
    u64::from_be_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn play_plist_roundtrip_content_location_and_start_position_seconds() {
        let url = "http://192.0.2.1:8080/media";
        let start = 12.5_f64;
        let bytes = encode_play(url, start, "play-uuid");
        assert!(bytes.starts_with(b"bplist00"), "magic");
        assert!(bytes.len() > 40, "header + objects + trailer");
        let as_text = String::from_utf8_lossy(&bytes);
        assert!(
            as_text.contains("Start-Position-Seconds"),
            "AP2 key must be present"
        );
        assert!(
            as_text.contains("Content-Location"),
            "url key must be present"
        );
        assert!(
            !as_text.contains("Start-Position\0") && !as_text.contains("Start-Position\x08"),
            "must not use the AirPlay 1 Start-Position key"
        );
        assert!(!as_text.contains("Start-Position:") && as_text.contains("Start-Position-Seconds"));
        let (got_url, got_start) = decode_play(&bytes).expect("decode play plist");
        assert_eq!(got_url, url);
        assert_eq!(got_start, start);
    }

    #[test]
    fn play_plist_zero_start() {
        let url = "http://10.0.0.2:9/media";
        let bytes = encode_play(url, 0.0, "u");
        let (got_url, got_start) = decode_play(&bytes).unwrap();
        assert_eq!(got_url, url);
        assert_eq!(got_start, 0.0);
    }

    #[test]
    fn long_url_uses_extended_string_marker() {
        let url = "http://192.168.100.200:54321/media";
        assert!(url.len() >= 15);
        let bytes = encode_play(url, 0.0, "uuid-long");
        let (got, _) = decode_play(&bytes).unwrap();
        assert_eq!(got, url);
    }

    #[test]
    fn command_play_plist_has_type_play_and_params_url() {
        let url = "http://192.0.2.1:8080/media";
        let bytes = encode_command_play(url, 1.5);
        assert!(bytes.starts_with(b"bplist00"), "magic");
        let root = from_binary(&bytes).expect("decode command play plist");
        let PlistValue::Dict(pairs) = root else {
            panic!("not a dict");
        };
        let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v);
        assert_eq!(get("type"), Some(&PlistValue::String("play".into())));
        let Some(PlistValue::Dict(params)) = get("params").cloned() else {
            panic!("params is not a dict");
        };
        let pget = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v);
        assert_eq!(pget("url"), Some(&PlistValue::String(url.into())));
        assert_eq!(
            pget("Content-Location"),
            Some(&PlistValue::String(url.into()))
        );
        assert_eq!(pget("Start-Position-Seconds"), Some(&PlistValue::Real(1.5)));
        let blob = String::from_utf8_lossy(&bytes);
        assert!(blob.contains("play"));
        assert!(blob.contains("url"));
    }

    #[test]
    fn setup_plist_has_timing_and_device_id() {
        let bytes = encode_setup("AA:BB:CC:DD:EE:FF", "SESSION-UUID", 61145, false);
        let root = from_binary(&bytes).expect("decode setup");
        let PlistValue::Dict(pairs) = root else {
            panic!("not a dict");
        };
        let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v);
        assert_eq!(
            get("deviceID"),
            Some(&PlistValue::String("AA:BB:CC:DD:EE:FF".into()))
        );
        assert_eq!(get("timingPort"), Some(&PlistValue::Integer(61145)));
        assert_eq!(
            get("timingProtocol"),
            Some(&PlistValue::String("NTP".into()))
        );
        assert_eq!(get("name"), Some(&PlistValue::String("omacast".into())));
        assert_eq!(
            get("isMultiSelectAirPlay"),
            Some(&PlistValue::Boolean(true))
        );
        assert_eq!(
            get("statsCollectionEnabled"),
            Some(&PlistValue::Boolean(false))
        );
        assert_eq!(
            get("macAddress"),
            Some(&PlistValue::String("AA:BB:CC:DD:EE:FF".into()))
        );
        assert!(get("isScreenMirroringSession").is_none());
        let screen = encode_setup("AA:BB:CC:DD:EE:FF", "SESSION-UUID", 61145, true);
        let screen_root = from_binary(&screen).expect("decode screen setup");
        let PlistValue::Dict(spairs) = screen_root else {
            panic!("not a dict");
        };
        let sget = |k: &str| spairs.iter().find(|(n, _)| n == k).map(|(_, v)| v);
        assert_eq!(
            sget("isScreenMirroringSession"),
            Some(&PlistValue::Boolean(true))
        );
        let blob = String::from_utf8_lossy(&bytes);
        assert!(blob.contains("AA:BB:CC:DD:EE:FF"));
        assert!(!blob.contains("0xAA"));
    }

    #[test]
    fn event_port_from_setup_plist() {
        let bytes = to_binary(&PlistValue::Dict(vec![
            ("eventPort".into(), PlistValue::Integer(7001)),
            ("timingPort".into(), PlistValue::Integer(1234)),
        ]));
        assert_eq!(event_port_from_setup(&bytes), Some(7001));
        assert!(event_port_from_setup(&encode_setup("AA:BB:CC:DD:EE:FF", "U", 9, false)).is_none());
    }

    fn dict_get<'a>(pairs: &'a [(String, PlistValue)], key: &str) -> Option<&'a PlistValue> {
        pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    #[test]
    fn array_of_dicts_ints_bools_strings_roundtrips() {
        let original = PlistValue::Array(vec![
            PlistValue::Dict(vec![
                ("name".into(), PlistValue::String("s".into())),
                ("n".into(), PlistValue::Integer(7)),
                ("ok".into(), PlistValue::Boolean(true)),
            ]),
            PlistValue::Integer(110),
            PlistValue::Boolean(false),
            PlistValue::String("hi".into()),
        ]);
        let bytes = to_binary(&original);
        let got = from_binary(&bytes).expect("decode array");
        assert_eq!(got, original);
        assert!(bytes.iter().any(|b| *b & 0xF0 == 0xA0), "array marker 0xA0");
    }

    #[test]
    fn screen_setup_plist_roundtrips_type_110_and_stream_connection_id() {
        let id = 0x1122_3344_5566_u64;
        assert_ne!(id, 0);
        let bytes = encode_setup_screen(id);
        assert!(bytes.starts_with(b"bplist00"));
        let root = from_binary(&bytes).expect("decode screen setup");
        let PlistValue::Dict(pairs) = root else {
            panic!("not a dict");
        };
        let Some(PlistValue::Array(items)) = dict_get(&pairs, "streams") else {
            panic!("streams is not an array");
        };
        assert_eq!(items.len(), 1);
        let PlistValue::Dict(stream) = &items[0] else {
            panic!("stream is not a dict");
        };
        assert_eq!(dict_get(stream, "type"), Some(&PlistValue::Integer(110)));
        let conn = dict_get(stream, "streamConnectionID").cloned();
        assert_eq!(conn, Some(PlistValue::Integer(id as i64)));
        match conn {
            Some(PlistValue::Integer(n)) => assert_ne!(n, 0),
            other => panic!("streamConnectionID not an integer: {other:?}"),
        }
        assert_eq!(
            dict_get(stream, "usingScreen"),
            Some(&PlistValue::Boolean(true))
        );
        assert_eq!(dict_get(stream, "fps"), Some(&PlistValue::Integer(30)));
        assert_eq!(
            dict_get(stream, "latencyMs"),
            Some(&PlistValue::Integer(90))
        );
        assert_eq!(
            dict_get(stream, "supportsHighAccuracyTimestamps"),
            Some(&PlistValue::Boolean(true))
        );
        let Some(PlistValue::Array(ts)) = dict_get(stream, "timestampInfo") else {
            panic!("timestampInfo missing");
        };
        let names: Vec<&str> = ts
            .iter()
            .map(|v| {
                let PlistValue::Dict(d) = v else {
                    panic!("timestampInfo entry not a dict");
                };
                match dict_get(d, "name") {
                    Some(PlistValue::String(n)) => n.as_str(),
                    other => panic!("timestampInfo name: {other:?}"),
                }
            })
            .collect();
        assert_eq!(names, ["SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc"]);
        let blob = String::from_utf8_lossy(&bytes);
        assert!(blob.contains("streamConnectionID"));
        assert!(blob.contains("usingScreen"));

        let slim = encode_setup_screen_slim(id);
        let slim_root = from_binary(&slim).expect("decode slim");
        let PlistValue::Dict(spairs) = slim_root else {
            panic!("slim not a dict");
        };
        let Some(PlistValue::Array(sitems)) = dict_get(&spairs, "streams") else {
            panic!("slim streams is not an array");
        };
        let PlistValue::Dict(sstream) = &sitems[0] else {
            panic!("slim stream is not a dict");
        };
        assert_eq!(dict_get(sstream, "type"), Some(&PlistValue::Integer(110)));
        assert_eq!(
            dict_get(sstream, "streamConnectionID"),
            Some(&PlistValue::Integer(id as i64))
        );
        assert!(dict_get(sstream, "usingScreen").is_none());
        assert!(dict_get(sstream, "fps").is_none());
        assert!(dict_get(sstream, "latencyMs").is_none());
        assert!(dict_get(sstream, "timestampInfo").is_none());
        assert!(dict_get(sstream, "supportsHighAccuracyTimestamps").is_none());

        let url = "http://192.0.2.10:9/media.mkv";
        let t120 = encode_setup_type_120(url, "stream-120-uuid");
        let r120 = from_binary(&t120).expect("decode 120");
        let PlistValue::Dict(p120) = r120 else {
            panic!("120 not a dict");
        };
        let Some(PlistValue::Array(i120)) = dict_get(&p120, "streams") else {
            panic!("120 streams");
        };
        let PlistValue::Dict(s120) = &i120[0] else {
            panic!("120 stream not dict");
        };
        assert_eq!(dict_get(s120, "type"), Some(&PlistValue::Integer(120)));
        assert_eq!(
            dict_get(s120, "Content-Location"),
            Some(&PlistValue::String(url.into()))
        );
        assert_eq!(
            dict_get(s120, "url"),
            Some(&PlistValue::String(url.into()))
        );
        assert_eq!(
            dict_get(s120, "uuid"),
            Some(&PlistValue::String("stream-120-uuid".into()))
        );
        assert_eq!(
            dict_get(s120, "mediaType"),
            Some(&PlistValue::String("file".into()))
        );
        let hls_url = "mlhls://localhost/master.m3u8";
        let t120h = encode_setup_type_120(hls_url, "hls-uuid");
        let r120h = from_binary(&t120h).expect("decode 120 hls");
        let PlistValue::Dict(p120h) = r120h else {
            panic!("120 hls not a dict");
        };
        let Some(PlistValue::Array(i120h)) = dict_get(&p120h, "streams") else {
            panic!("120 hls streams");
        };
        let PlistValue::Dict(s120h) = &i120h[0] else {
            panic!("120 hls stream not dict");
        };
        assert_eq!(
            dict_get(s120h, "mediaType"),
            Some(&PlistValue::String("streaming".into()))
        );
        assert_eq!(
            dict_get(s120h, "Content-Location"),
            Some(&PlistValue::String(hls_url.into()))
        );
        assert_eq!(dict_get(s120, "streamType"), Some(&PlistValue::Integer(1)));
        assert_eq!(
            dict_get(s120, "Start-Position-Seconds"),
            Some(&PlistValue::Real(0.0))
        );
        assert!(dict_get(s120, "streamConnectionID").is_none());
    }

    #[test]
    fn data_port_from_setup_finds_port_despite_extra_keys() {
        let bytes = to_binary(&PlistValue::Dict(vec![
            ("eventPort".into(), PlistValue::Integer(7001)),
            (
                "streams".into(),
                PlistValue::Array(vec![PlistValue::Dict(vec![
                    ("type".into(), PlistValue::Integer(110)),
                    ("unknownKey".into(), PlistValue::String("x".into())),
                    ("dataPort".into(), PlistValue::Integer(7010)),
                    ("usingScreen".into(), PlistValue::Boolean(true)),
                ])]),
            ),
            ("extra".into(), PlistValue::Boolean(true)),
        ]));
        assert_eq!(data_port_from_setup(&bytes), Some(7010));
        assert!(data_port_from_setup(&encode_setup_screen(99)).is_none());
        assert!(data_port_from_setup(&encode_setup("AA:BB:CC:DD:EE:FF", "U", 9, false)).is_none());
        assert_eq!(data_port_from_setup(b"not-a-plist"), None);
        let zero = to_binary(&PlistValue::Dict(vec![(
            "streams".into(),
            PlistValue::Array(vec![PlistValue::Dict(vec![(
                "dataPort".into(),
                PlistValue::Integer(0),
            )])]),
        )]));
        assert!(data_port_from_setup(&zero).is_none());
        let over = to_binary(&PlistValue::Dict(vec![(
            "streams".into(),
            PlistValue::Array(vec![PlistValue::Dict(vec![(
                "dataPort".into(),
                PlistValue::Integer(70000),
            )])]),
        )]));
        assert!(data_port_from_setup(&over).is_none());
    }

    #[test]
    fn data_bytes_roundtrip() {
        let original = PlistValue::Dict(vec![(
            "FCUP_Response_Data".into(),
            PlistValue::Data(b"#EXTM3U\n".to_vec()),
        )]);
        let bytes = to_binary(&original);
        let got = from_binary(&bytes).expect("decode data");
        assert_eq!(got, original);
    }

    #[test]
    fn playlist_insert_has_streaming_item() {
        let url = "mlhls://localhost/master.m3u8";
        let bytes = encode_command_playlist_insert(url, "u-1");
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not dict");
        };
        assert_eq!(
            dict_get(&pairs, "type"),
            Some(&PlistValue::String("playlistInsert".into()))
        );
        let Some(PlistValue::Dict(params)) = dict_get(&pairs, "params") else {
            panic!("params");
        };
        let Some(PlistValue::Dict(item)) = dict_get(params, "item") else {
            panic!("item");
        };
        assert_eq!(
            dict_get(item, "Content-Location"),
            Some(&PlistValue::String(url.into()))
        );
        assert_eq!(
            dict_get(item, "mediaType"),
            Some(&PlistValue::String("streaming".into()))
        );
    }

    #[test]
    fn action_playlist_insert_has_client_proc() {
        let url = "mlhls://localhost/master.m3u8";
        let bytes = encode_action_playlist_insert(url, "u-act");
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not dict");
        };
        assert_eq!(
            dict_get(&pairs, "type"),
            Some(&PlistValue::String("playlistInsert".into()))
        );
        let xml = encode_playlist_insert_xml(url, "u-act");
        assert!(xml.contains("<string>playlistInsert</string>"));
        assert!(xml.contains(url));
        let json = encode_playlist_insert_json(url, "u-act");
        assert!(json.contains("playlistInsert"));
        assert!(json.contains(url));
    }

    #[test]
    fn play_items_has_items_array() {
        let url = "http://192.0.2.1:8/master.m3u8";
        let bytes = encode_command_play_items(url, "u-2");
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not dict");
        };
        let Some(PlistValue::Dict(params)) = dict_get(&pairs, "params") else {
            panic!("params");
        };
        let Some(PlistValue::Array(items)) = dict_get(params, "items") else {
            panic!("items");
        };
        let PlistValue::Dict(item) = &items[0] else {
            panic!("item0");
        };
        assert_eq!(
            dict_get(item, "url"),
            Some(&PlistValue::String(url.into()))
        );
    }

    #[test]
    fn type_120_minimal_is_only_type() {
        let bytes = encode_setup_type_120_minimal();
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not dict");
        };
        let Some(PlistValue::Array(items)) = dict_get(&pairs, "streams") else {
            panic!("streams");
        };
        let PlistValue::Dict(stream) = &items[0] else {
            panic!("stream");
        };
        assert_eq!(dict_get(stream, "type"), Some(&PlistValue::Integer(120)));
        assert!(dict_get(stream, "Content-Location").is_none());
        assert!(dict_get(stream, "dataPort").is_none());
        assert_eq!(stream.len(), 1);
    }

    #[test]
    fn type_120_sender_ports_roundtrip() {
        let url = "http://192.0.2.10:9/master.m3u8";
        let bytes = encode_setup_type_120_sender_ports(url, "u120", 7010, 7011, 7012);
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not dict");
        };
        let Some(PlistValue::Array(items)) = dict_get(&pairs, "streams") else {
            panic!("streams");
        };
        let PlistValue::Dict(stream) = &items[0] else {
            panic!("stream");
        };
        assert_eq!(dict_get(stream, "type"), Some(&PlistValue::Integer(120)));
        assert_eq!(dict_get(stream, "dataPort"), Some(&PlistValue::Integer(7010)));
        assert_eq!(
            dict_get(stream, "controlPort"),
            Some(&PlistValue::Integer(7011))
        );
        assert_eq!(
            dict_get(stream, "timingPort"),
            Some(&PlistValue::Integer(7012))
        );
        assert_eq!(
            dict_get(stream, "Content-Location"),
            Some(&PlistValue::String(url.into()))
        );
        let keys = setup_response_keys(&bytes);
        assert!(keys.contains("type"));
        assert!(keys.contains("dataPort"));
        assert!(!keys.to_ascii_lowercase().contains("pk"));
    }

    #[test]
    fn screen_ios_setup_has_uuid() {
        let bytes = encode_setup_screen_ios(99, "screen-uuid");
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not dict");
        };
        let Some(PlistValue::Array(items)) = dict_get(&pairs, "streams") else {
            panic!("streams");
        };
        let PlistValue::Dict(stream) = &items[0] else {
            panic!("stream");
        };
        assert_eq!(dict_get(stream, "type"), Some(&PlistValue::Integer(110)));
        assert_eq!(
            dict_get(stream, "uuid"),
            Some(&PlistValue::String("screen-uuid".into()))
        );
        assert_eq!(
            dict_get(stream, "latencyMs"),
            Some(&PlistValue::Integer(90))
        );
        assert!(dict_get(stream, "streamConnectionID").is_some());
        assert!(dict_get(stream, "ekey").is_none());
    }

    #[test]
    fn screen_ios_fp_has_ports_and_ekey_not_bytes_in_keys() {
        let ekey = [0xABu8; 16];
        let eiv = [0xCDu8; 16];
        let bytes = encode_setup_screen_ios_fp(99, "screen-uuid", Some(&ekey), Some(&eiv), 60000, 60001);
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not dict");
        };
        let Some(PlistValue::Array(items)) = dict_get(&pairs, "streams") else {
            panic!("streams");
        };
        let PlistValue::Dict(stream) = &items[0] else {
            panic!("stream");
        };
        assert_eq!(dict_get(stream, "timingPort"), Some(&PlistValue::Integer(60000)));
        assert_eq!(dict_get(stream, "controlPort"), Some(&PlistValue::Integer(60001)));
        assert_eq!(dict_get(stream, "et"), Some(&PlistValue::Integer(32)));
        match dict_get(stream, "ekey") {
            Some(PlistValue::Data(d)) => assert_eq!(d.len(), 16),
            other => panic!("ekey missing: {other:?}"),
        }
        let keys = setup_response_keys(&bytes);
        assert!(keys.contains("ekey"));
        assert!(keys.contains("timingPort"));
        assert!(!keys.to_ascii_lowercase().contains("ab"));
    }

    #[test]
    fn screen_ios_setup_ekey_len_only() {
        let ekey = [0xABu8; 72];
        let bytes = encode_setup_screen_ios_ekey(99, "screen-uuid", Some(&ekey));
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not dict");
        };
        let Some(PlistValue::Array(items)) = dict_get(&pairs, "streams") else {
            panic!("streams");
        };
        let PlistValue::Dict(stream) = &items[0] else {
            panic!("stream");
        };
        match dict_get(stream, "ekey") {
            Some(PlistValue::Data(d)) => assert_eq!(d.len(), 72),
            other => panic!("ekey missing: {other:?}"),
        }
        let session = encode_setup_fairplay("AA:BB:CC:DD:EE:FF", "U", 9, Some(&ekey), Some(&[0u8; 16]));
        let sroot = from_binary(&session).unwrap();
        let PlistValue::Dict(spairs) = sroot else {
            panic!("not dict");
        };
        match spairs.iter().find(|(k, _)| k == "ekey").map(|(_, v)| v) {
            Some(PlistValue::Data(d)) => assert_eq!(d.len(), 72),
            other => panic!("session ekey: {other:?}"),
        }
        assert_eq!(
            spairs.iter().find(|(k, _)| k == "et").map(|(_, v)| v),
            Some(&PlistValue::Integer(32))
        );
        let keys = setup_response_keys(&session);
        assert!(keys.contains("ekey"));
        assert!(!keys.contains("AB"));
    }

    #[test]
    fn encode_setup_screen_zero_id_becomes_nonzero() {
        let bytes = encode_setup_screen(0);
        let root = from_binary(&bytes).unwrap();
        let PlistValue::Dict(pairs) = root else {
            panic!("not a dict");
        };
        let Some(PlistValue::Array(items)) = dict_get(&pairs, "streams") else {
            panic!("streams is not an array");
        };
        let PlistValue::Dict(stream) = &items[0] else {
            panic!("stream is not a dict");
        };
        match dict_get(stream, "streamConnectionID") {
            Some(PlistValue::Integer(n)) => assert_ne!(*n, 0),
            other => panic!("expected nonzero integer, got {other:?}"),
        }
    }
}

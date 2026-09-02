//! FairPlay SAP M1/M2/M3 (session-aware) plus screen stream AES-CTR keys.
//!
//! Handshake bytes come from the vendored LGPL `third_party/fairplay-sap-core`
//! algorithm (not DoubleTake). Logs must never print ekey/key bytes.

use std::os::raw::{c_int, c_uchar};

use rand::RngCore;

extern "C" {
    fn fpsap_m1(out: *mut c_uchar, cap: c_int) -> c_int;
    fn fpsap_exchange_m3(
        m2: *const c_uchar,
        m2len: c_int,
        out: *mut c_uchar,
        cap: c_int,
    ) -> c_int;
}

pub const M1_LEN: usize = 16;
pub const M2_LEN: usize = 142;
pub const M3_LEN: usize = 164;

/// 16-byte FPLY v3 m1 (capability mask 0x03). Same bytes as `FP_SETUP_M1`.
pub fn m1() -> [u8; M1_LEN] {
    let mut out = [0u8; M1_LEN];
    let n = unsafe { fpsap_m1(out.as_mut_ptr(), out.len() as c_int) };
    if n != M1_LEN as c_int {
        out = [
            0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00,
            0x03, 0xbb,
        ];
    }
    out
}

/// Mode byte from a framed FPLY m2, if the body looks like one.
pub fn m2_mode(body: &[u8]) -> Option<u8> {
    if body.len() >= 14 && body.starts_with(b"FPLY") {
        Some(body[13])
    } else {
        None
    }
}

pub fn parse_m2(body: &[u8]) -> Result<u8, String> {
    if body.len() != M2_LEN {
        return Err(format!("m2 is {} bytes, want {M2_LEN}", body.len()));
    }
    if &body[..4] != b"FPLY" {
        return Err("m2 missing FPLY".into());
    }
    if body[4] != 3 || body[5] != 1 || body[6] != 2 {
        return Err("m2 version/type".into());
    }
    let mode = body[13];
    if mode != 3 {
        return Err(format!(
            "m2 selected FairPlay mode {mode}; this sender answers mode 3 only"
        ));
    }
    Ok(mode)
}

/// Session-aware 164-byte m3 for a 142-byte m2.
pub fn exchange_m3(m2: &[u8]) -> Result<Vec<u8>, String> {
    let _ = parse_m2(m2)?;
    let mut out = vec![0u8; M3_LEN];
    let n = unsafe {
        fpsap_exchange_m3(
            m2.as_ptr(),
            m2.len() as c_int,
            out.as_mut_ptr(),
            out.len() as c_int,
        )
    };
    if n < 0 {
        return Err(format!("fpsap m3 failed ({n})"));
    }
    out.truncate(n as usize);
    if out.len() != M3_LEN || !out.starts_with(b"FPLY") {
        return Err(format!("m3 framing bytes={}", out.len()));
    }
    Ok(out)
}

pub fn m4_is_ack(body: &[u8]) -> bool {
    body.len() >= 12 && body.starts_with(b"FPLY") && body.get(6) == Some(&0x04)
}

/// AES-128 key + IV for the type-110 payload. `ekey` is the SETUP blob
/// (HAP descriptor-only: raw 16-byte key). Never log these bytes.
pub struct StreamKeys {
    pub aes_key: [u8; 16],
    pub eiv: [u8; 16],
    pub ekey: Vec<u8>,
}

pub fn new_stream_keys() -> StreamKeys {
    let mut aes_key = [0u8; 16];
    let mut eiv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut aes_key);
    rand::rngs::OsRng.fill_bytes(&mut eiv);
    StreamKeys {
        ekey: aes_key.to_vec(),
        aes_key,
        eiv,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m1_is_fply_v3_16() {
        let m = m1();
        assert_eq!(m.len(), 16);
        assert_eq!(&m[..4], b"FPLY");
        assert_eq!(m[4], 3);
        assert_eq!(m[6], 1);
        assert_eq!(m[14], 0x03);
        assert_eq!(m[15], 0xbb);
    }

    #[test]
    fn parse_m2_rejects_wrong_mode_and_len() {
        let mut m2 = vec![0u8; 142];
        m2[..4].copy_from_slice(b"FPLY");
        m2[4] = 3;
        m2[5] = 1;
        m2[6] = 2;
        m2[13] = 0;
        assert!(parse_m2(&m2).is_err());
        m2[13] = 3;
        assert_eq!(parse_m2(&m2).unwrap(), 3);
        assert_eq!(m2_mode(&m2), Some(3));
        assert!(parse_m2(&m2[..10]).is_err());
    }

    #[test]
    fn stream_keys_ekey_len_is_16() {
        let k = new_stream_keys();
        assert_eq!(k.ekey.len(), 16);
        assert_eq!(k.aes_key.len(), 16);
        assert_eq!(k.eiv.len(), 16);
    }
}

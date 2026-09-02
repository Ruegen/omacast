//! HAP TLV8 encoding (tag u8, len u8, value; values >255 bytes are chunked).

use std::collections::BTreeMap;

pub const METHOD: u8 = 0x00;
pub const IDENTIFIER: u8 = 0x01;
pub const SALT: u8 = 0x02;
pub const PUBLIC_KEY: u8 = 0x03;
pub const PROOF: u8 = 0x04;
pub const ENCRYPTED_DATA: u8 = 0x05;
pub const SEQNO: u8 = 0x06;
pub const ERROR: u8 = 0x07;
pub const SIGNATURE: u8 = 0x0A;
#[allow(dead_code)]
pub const NAME: u8 = 0x11;
pub const FLAGS: u8 = 0x13;

pub const METHOD_PAIR_SETUP: u8 = 0x00;
pub const FLAG_TRANSIENT: u8 = 0x10;

pub type TlvMap = BTreeMap<u8, Vec<u8>>;

/// Encode a sequence of (tag, value) pairs as TLV8.
pub fn encode(pairs: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, value) in pairs {
        let mut pos = 0usize;
        if value.is_empty() {
            out.push(*tag);
            out.push(0);
            continue;
        }
        while pos < value.len() {
            let n = (value.len() - pos).min(255);
            out.push(*tag);
            out.push(n as u8);
            out.extend_from_slice(&value[pos..pos + n]);
            pos += n;
        }
    }
    out
}

/// Decode TLV8 bytes. Repeated tags are concatenated (chunked values).
pub fn decode(data: &[u8]) -> TlvMap {
    let mut map = TlvMap::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let tag = data[i];
        let len = data[i + 1] as usize;
        i += 2;
        if i + len > data.len() {
            break;
        }
        map.entry(tag)
            .or_default()
            .extend_from_slice(&data[i..i + len]);
        i += len;
    }
    map
}

pub fn get_u8(map: &TlvMap, tag: u8) -> Option<u8> {
    map.get(&tag).and_then(|v| v.first()).copied()
}

pub fn error_message(map: &TlvMap) -> Option<String> {
    let code = get_u8(map, ERROR)?;
    let name = match code {
        0x01 => "unknown",
        0x02 => "authentication",
        0x03 => "backoff",
        0x04 => "max peers",
        0x05 => "max tries",
        0x06 => "unavailable",
        0x07 => "busy",
        _ => "pairing error",
    };
    Some(format!("HAP {name} (0x{code:02x})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv8_roundtrip_small() {
        let body = encode(&[
            (METHOD, &[0x00]),
            (SEQNO, &[0x01]),
            (IDENTIFIER, b"Pair-Setup"),
        ]);
        let map = decode(&body);
        assert_eq!(map.get(&METHOD).unwrap(), &[0x00]);
        assert_eq!(map.get(&SEQNO).unwrap(), &[0x01]);
        assert_eq!(map.get(&IDENTIFIER).unwrap(), b"Pair-Setup");
    }

    #[test]
    fn tlv8_roundtrip_chunked() {
        let big = vec![0xABu8; 300];
        let body = encode(&[(PUBLIC_KEY, &big), (SEQNO, &[0x03])]);
        // 255 + 45 for the public key
        assert!(body.len() > 300);
        let map = decode(&body);
        assert_eq!(map.get(&PUBLIC_KEY).unwrap().len(), 300);
        assert_eq!(map.get(&PUBLIC_KEY).unwrap(), &big);
        assert_eq!(map.get(&SEQNO).unwrap(), &[0x03]);
    }

    #[test]
    fn tlv8_empty_value() {
        let body = encode(&[(FLAGS, &[])]);
        let map = decode(&body);
        assert_eq!(map.get(&FLAGS).unwrap(), &Vec::<u8>::new());
    }
}

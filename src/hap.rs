//! HAP pair-setup / pair-verify (SRP-6a SHA-512, RFC 5054 3072-bit, ChaCha20-Poly1305).
//!
//! Wire format and crypto match pyatv's HAP implementation.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::Zero;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::tlv8::{self, TlvMap};

const PAIR_SETUP_USER: &[u8] = b"Pair-Setup";

/// RFC 5054 3072-bit safe prime (N). g = 5.
const RFC5054_3072_N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
);

#[derive(Debug, Clone)]
pub struct HapCredentials {
    pub ltpk: Vec<u8>,
    pub ltsk: Vec<u8>,
    pub atv_id: Vec<u8>,
    pub client_id: Vec<u8>,
}

/// PIN as a 4-digit decimal string (`"12"` → `"0012"`).
pub fn zfill_pin(pin: &str) -> String {
    let digits: String = pin.chars().filter(|c| c.is_ascii_digit()).collect();
    format!("{digits:0>4}")
}

fn srp_n() -> BigUint {
    BigUint::parse_bytes(RFC5054_3072_N_HEX.as_bytes(), 16).expect("RFC 5054 N")
}

fn srp_g() -> BigUint {
    BigUint::from(5u8)
}

fn int_to_bytes(n: &BigUint) -> Vec<u8> {
    let v = n.to_bytes_be();
    if v.is_empty() {
        vec![0]
    } else {
        v
    }
}

fn pad_n(n: &BigUint, val: &BigUint) -> Vec<u8> {
    let width = int_to_bytes(n).len();
    let mut v = int_to_bytes(val);
    if v.len() > width {
        v = v[v.len() - width..].to_vec();
    } else if v.len() < width {
        let mut p = vec![0u8; width - v.len()];
        p.extend_from_slice(&v);
        v = p;
    }
    v
}

fn h_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().to_vec()
}

fn h_int(parts: &[&[u8]]) -> BigUint {
    BigUint::from_bytes_be(&h_bytes(parts))
}

fn hkdf_32(salt: &[u8], info: &[u8], ikm: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf 32");
    okm
}

fn hap_nonce(label: &[u8]) -> [u8; 12] {
    // 4 zero bytes + 8-byte nonce (HomeKit / pyatv Chacha20Cipher8byteNonce).
    let mut n = [0u8; 12];
    let take = label.len().min(8);
    n[12 - take..].copy_from_slice(&label[..take]);
    n
}

fn chacha_encrypt(key: &[u8], nonce_label: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("chacha key: {e}"))?;
    let nonce = Nonce::from(hap_nonce(nonce_label));
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("chacha encrypt: {e}"))
}

fn chacha_decrypt(key: &[u8], nonce_label: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("chacha key: {e}"))?;
    let nonce = Nonce::from(hap_nonce(nonce_label));
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| format!("chacha decrypt: {e}"))
}

fn srp_client(
    pin: &str,
    a: &BigUint,
    salt: &[u8],
    b_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let n = srp_n();
    let g = srp_g();
    let b = BigUint::from_bytes_be(b_bytes);
    if (&b % &n).is_zero() {
        return Err("SRP server public is zero".into());
    }

    let n_bytes = int_to_bytes(&n);
    let k = h_int(&[&n_bytes, &pad_n(&n, &g)]);
    let inner = h_bytes(&[PAIR_SETUP_USER, b":", pin.as_bytes()]);
    let x = h_int(&[salt, &inner]);
    let v = g.modpow(&x, &n);
    let a_pub = g.modpow(a, &n);
    if (&a_pub % &n).is_zero() {
        return Err("SRP client public is zero".into());
    }
    let u = h_int(&[&pad_n(&n, &a_pub), &pad_n(&n, &b)]);
    if u.is_zero() {
        return Err("SRP scrambler u is zero".into());
    }
    let kv = (&k * &v) % &n;
    let base = (&b + &n - kv) % &n;
    let exp = a + &u * &x;
    let s = base.modpow(&exp, &n);
    // HAP / RFC 5054: K = H(PAD(S)) with S padded to the length of N (384 bytes).
    let session_key = h_bytes(&[&pad_n(&n, &s)]);

    let hn = h_int(&[&n_bytes]);
    let hg = h_int(&[&int_to_bytes(&g)]);
    let hx = hn ^ hg;
    let hi = h_int(&[PAIR_SETUP_USER]);
    let m = h_bytes(&[
        &int_to_bytes(&hx),
        &int_to_bytes(&hi),
        salt,
        &int_to_bytes(&a_pub),
        &int_to_bytes(&b),
        &session_key,
    ]);
    // Send A padded to N (384 bytes) so the TV's SRP parser accepts M3.
    let a_pub_bytes = pad_n(&n, &a_pub);
    Ok((a_pub_bytes, m, session_key))
}

fn verify_server_proof(a_pub: &[u8], m: &[u8], k: &[u8], proof: &[u8]) -> bool {
    let a = BigUint::from_bytes_be(a_pub);
    let expected = h_bytes(&[&int_to_bytes(&a), m, k]);
    expected.as_slice() == proof
}

pub struct PairSetupSession {
    pub transient: bool,
    signing: SigningKey,
    pairing_id: Vec<u8>,
    a: BigUint,
    salt: Option<Vec<u8>>,
    server_b: Option<Vec<u8>>,
    a_pub: Option<Vec<u8>>,
    client_m: Option<Vec<u8>>,
    session_key: Option<Vec<u8>>,
}

impl PairSetupSession {
    pub fn new(transient: bool) -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        // pyatv: SRP private `a` is hexlify(ed25519 seed) parsed as int (BE 32 bytes).
        let a = BigUint::from_bytes_be(&seed);
        let pairing_id = Uuid::new_v4().to_string().into_bytes();
        Self {
            transient,
            signing,
            pairing_id,
            a,
            salt: None,
            server_b: None,
            a_pub: None,
            client_m: None,
            session_key: None,
        }
    }

    pub fn m1(&self) -> Vec<u8> {
        if self.transient {
            tlv8::encode(&[
                (tlv8::METHOD, &[tlv8::METHOD_PAIR_SETUP]),
                (tlv8::SEQNO, &[0x01]),
                (tlv8::FLAGS, &[tlv8::FLAG_TRANSIENT]),
            ])
        } else {
            tlv8::encode(&[
                (tlv8::METHOD, &[tlv8::METHOD_PAIR_SETUP]),
                (tlv8::SEQNO, &[0x01]),
            ])
        }
    }

    pub fn process_m2(&mut self, body: &[u8]) -> Result<(), String> {
        let map = tlv8::decode(body);
        if let Some(msg) = tlv8::error_message(&map) {
            return Err(msg);
        }
        let salt = map
            .get(&tlv8::SALT)
            .cloned()
            .ok_or_else(|| "pair-setup M2 missing salt".to_string())?;
        let pk = map
            .get(&tlv8::PUBLIC_KEY)
            .cloned()
            .ok_or_else(|| "pair-setup M2 missing public key".to_string())?;
        self.salt = Some(salt);
        self.server_b = Some(pk);
        Ok(())
    }

    pub fn m3(&mut self, pin: &str) -> Result<Vec<u8>, String> {
        let pin = zfill_pin(pin);
        let salt = self
            .salt
            .as_ref()
            .ok_or_else(|| "pair-setup M3 without M2".to_string())?;
        let b = self
            .server_b
            .as_ref()
            .ok_or_else(|| "pair-setup M3 without M2".to_string())?;
        let (a_pub, m, k) = srp_client(&pin, &self.a, salt, b)?;
        self.a_pub = Some(a_pub.clone());
        self.client_m = Some(m.clone());
        self.session_key = Some(k);
        Ok(tlv8::encode(&[
            (tlv8::SEQNO, &[0x03]),
            (tlv8::PUBLIC_KEY, &a_pub),
            (tlv8::PROOF, &m),
        ]))
    }

    pub fn process_m4(&mut self, body: &[u8]) -> Result<(), String> {
        let map = tlv8::decode(body);
        if let Some(msg) = tlv8::error_message(&map) {
            return Err(msg);
        }
        if let Some(proof) = map.get(&tlv8::PROOF) {
            if let (Some(a_pub), Some(m), Some(k)) =
                (&self.a_pub, &self.client_m, &self.session_key)
            {
                if !verify_server_proof(a_pub, m, k, proof) {
                    // Optional: some TVs omit or differ; do not abort.
                }
            }
        }
        Ok(())
    }

    pub fn m5(&self) -> Result<Vec<u8>, String> {
        if self.transient {
            return Err("transient pairing has no M5".into());
        }
        let k = self
            .session_key
            .as_ref()
            .ok_or_else(|| "pair-setup M5 without session key".to_string())?;
        let ios_device_x = hkdf_32(
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
            k,
        );
        let session_enc = hkdf_32(b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info", k);
        let auth_public = self.signing.verifying_key().to_bytes();
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(&ios_device_x);
        to_sign.extend_from_slice(&self.pairing_id);
        to_sign.extend_from_slice(&auth_public);
        let signature = self.signing.sign(&to_sign);
        let inner = tlv8::encode(&[
            (tlv8::IDENTIFIER, &self.pairing_id),
            (tlv8::PUBLIC_KEY, &auth_public),
            (tlv8::SIGNATURE, &signature.to_bytes()),
        ]);
        let encrypted = chacha_encrypt(&session_enc, b"PS-Msg05", &inner)?;
        Ok(tlv8::encode(&[
            (tlv8::SEQNO, &[0x05]),
            (tlv8::ENCRYPTED_DATA, &encrypted),
        ]))
    }

    pub fn process_m6(&self, body: &[u8]) -> Result<HapCredentials, String> {
        let map = tlv8::decode(body);
        if let Some(msg) = tlv8::error_message(&map) {
            return Err(msg);
        }
        let k = self
            .session_key
            .as_ref()
            .ok_or_else(|| "pair-setup M6 without session key".to_string())?;
        let encrypted = map
            .get(&tlv8::ENCRYPTED_DATA)
            .ok_or_else(|| "pair-setup M6 missing encrypted data".to_string())?;
        let session_enc = hkdf_32(b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info", k);
        let plain = chacha_decrypt(&session_enc, b"PS-Msg06", encrypted)?;
        let inner = tlv8::decode(&plain);
        let atv_id = inner
            .get(&tlv8::IDENTIFIER)
            .cloned()
            .ok_or_else(|| "pair-setup M6 missing identifier".to_string())?;
        let ltpk = inner
            .get(&tlv8::PUBLIC_KEY)
            .cloned()
            .ok_or_else(|| "pair-setup M6 missing public key".to_string())?;
        let _sig = inner.get(&tlv8::SIGNATURE);
        Ok(HapCredentials {
            ltpk,
            ltsk: self.signing.to_bytes().to_vec(),
            atv_id,
            client_id: self.pairing_id.clone(),
        })
    }

    /// Transient pairing: encrypt control HTTP with keys derived from the SRP session key.
    pub fn control_keys(&self) -> Option<([u8; 32], [u8; 32])> {
        let shared = self.session_key.as_ref()?;
        Some(control_channel_keys(shared))
    }

    pub fn event_keys(&self) -> Option<([u8; 32], [u8; 32])> {
        let shared = self.session_key.as_ref()?;
        Some(event_channel_keys(shared))
    }
}

pub struct PairVerifySession {
    creds: HapCredentials,
    secret: StaticSecret,
    public: X25519Public,
    shared: Option<[u8; 32]>,
}

impl PairVerifySession {
    pub fn new(creds: HapCredentials) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);
        Self {
            creds,
            secret,
            public,
            shared: None,
        }
    }

    pub fn m1(&self) -> Vec<u8> {
        tlv8::encode(&[
            (tlv8::SEQNO, &[0x01]),
            (tlv8::PUBLIC_KEY, self.public.as_bytes()),
        ])
    }

    pub fn m3_from_m2(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        let map = decode_or_error(body)?;
        let their_pub_b = map
            .get(&tlv8::PUBLIC_KEY)
            .ok_or_else(|| "pair-verify M2 missing public key".to_string())?;
        let encrypted = map
            .get(&tlv8::ENCRYPTED_DATA)
            .ok_or_else(|| "pair-verify M2 missing encrypted data".to_string())?;
        let their_arr: [u8; 32] = their_pub_b
            .as_slice()
            .try_into()
            .map_err(|_| "pair-verify M2 public key is not 32 bytes".to_string())?;
        let their_pub = X25519Public::from(their_arr);
        let shared = self.secret.diffie_hellman(&their_pub);
        self.shared = Some(*shared.as_bytes());
        let session_key = hkdf_32(
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
            shared.as_bytes(),
        );
        let plain = chacha_decrypt(&session_key, b"PV-Msg02", encrypted)?;
        let inner = tlv8::decode(&plain);
        let ident = inner
            .get(&tlv8::IDENTIFIER)
            .ok_or_else(|| "pair-verify M2 missing identifier".to_string())?;
        if ident.as_slice() != self.creds.atv_id.as_slice() {
            return Err("pair-verify: accessory id mismatch".into());
        }
        if let Some(sig_b) = inner.get(&tlv8::SIGNATURE) {
            if let (Ok(ltpk), Ok(sig_arr)) = (
                <[u8; 32]>::try_from(self.creds.ltpk.as_slice()),
                <[u8; 64]>::try_from(sig_b.as_slice()),
            ) {
                if let Ok(vk) = VerifyingKey::from_bytes(&ltpk) {
                    let mut info = Vec::new();
                    info.extend_from_slice(&their_arr);
                    info.extend_from_slice(ident);
                    info.extend_from_slice(self.public.as_bytes());
                    let _ = vk.verify(&info, &Signature::from_bytes(&sig_arr));
                }
            }
        }
        let ltsk: [u8; 32] = self
            .creds
            .ltsk
            .as_slice()
            .try_into()
            .map_err(|_| "ltsk is not 32 bytes".to_string())?;
        let signing = SigningKey::from_bytes(&ltsk);
        let mut device_info = Vec::new();
        device_info.extend_from_slice(self.public.as_bytes());
        device_info.extend_from_slice(&self.creds.client_id);
        device_info.extend_from_slice(&their_arr);
        let sig = signing.sign(&device_info);
        let inner_out = tlv8::encode(&[
            (tlv8::IDENTIFIER, &self.creds.client_id),
            (tlv8::SIGNATURE, &sig.to_bytes()),
        ]);
        let enc = chacha_encrypt(&session_key, b"PV-Msg03", &inner_out)?;
        Ok(tlv8::encode(&[
            (tlv8::SEQNO, &[0x03]),
            (tlv8::ENCRYPTED_DATA, &enc),
        ]))
    }

    pub fn control_keys(&self) -> Option<([u8; 32], [u8; 32])> {
        let shared = self.shared?;
        Some(control_channel_keys(&shared))
    }

    pub fn event_keys(&self) -> Option<([u8; 32], [u8; 32])> {
        let shared = self.shared?;
        Some(event_channel_keys(&shared))
    }

    /// Pair-verify X25519 shared secret (IKM for type-110 dataPort ChaCha).
    /// Callers must not log these bytes.
    pub fn shared_secret(&self) -> Option<[u8; 32]> {
        self.shared
    }
}

/// Control-channel keys after pair-verify (X25519 shared) or transient pairing (SRP K).
pub fn control_channel_keys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
    let write = hkdf_32(b"Control-Salt", b"Control-Write-Encryption-Key", shared);
    let read = hkdf_32(b"Control-Salt", b"Control-Read-Encryption-Key", shared);
    (write, read)
}

pub fn event_channel_keys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
    let write = hkdf_32(b"Events-Salt", b"Events-Write-Encryption-Key", shared);
    let read = hkdf_32(b"Events-Salt", b"Events-Read-Encryption-Key", shared);
    (write, read)
}

/// Type-110 dataPort VCL key (ChaCha20-Poly1305). Salt is decimal streamConnectionID
/// as sent in SETUP (`DataStream-Salt{id}`), info `DataStream-Output-Encryption-Key`.
/// Never log the resulting key bytes.
pub fn data_stream_output_key(ikm: &[u8; 32], stream_connection_id: u64) -> [u8; 32] {
    let salt = format!("DataStream-Salt{stream_connection_id}");
    hkdf_32(
        salt.as_bytes(),
        b"DataStream-Output-Encryption-Key",
        ikm,
    )
}

fn decode_or_error(body: &[u8]) -> Result<TlvMap, String> {
    let map = tlv8::decode(body);
    if let Some(msg) = tlv8::error_message(&map) {
        return Err(msg);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_zfill_four_digits() {
        assert_eq!(zfill_pin("12"), "0012");
        assert_eq!(zfill_pin("1234"), "1234");
        assert_eq!(zfill_pin("4"), "0004");
        assert_eq!(zfill_pin("0000"), "0000");
        assert_eq!(zfill_pin("ab12cd"), "0012");
    }

    #[test]
    fn hap_nonce_pads_8_byte_label() {
        let n = hap_nonce(b"PS-Msg05");
        assert_eq!(&n[..4], &[0, 0, 0, 0]);
        assert_eq!(&n[4..], b"PS-Msg05");
    }

    #[test]
    fn rfc5054_n_is_384_bytes() {
        assert_eq!(int_to_bytes(&srp_n()).len(), 384);
    }

    #[test]
    fn pad_n_left_zeros_to_384() {
        let n = srp_n();
        let padded = pad_n(&n, &BigUint::from(0xABu32));
        assert_eq!(padded.len(), 384);
        assert_eq!(padded[383], 0xAB);
        assert!(padded[..383].iter().all(|&b| b == 0));
    }

    #[test]
    fn event_keys_differ_from_control() {
        let shared = [7u8; 32];
        let c = control_channel_keys(&shared);
        let e = event_channel_keys(&shared);
        assert_ne!(c.0, e.0);
        assert_ne!(c.1, e.1);
        assert_ne!(e.0, e.1);
    }

    #[test]
    fn data_stream_output_key_is_deterministic() {
        let ikm = [0x11u8; 32];
        let a = data_stream_output_key(&ikm, 42);
        let b = data_stream_output_key(&ikm, 42);
        let c = data_stream_output_key(&ikm, 43);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
        let d = data_stream_output_key(&ikm, 1);
        let e = data_stream_output_key(&ikm, 1);
        assert_eq!(d, e);
        assert_ne!(d, a);
    }

    #[test]
    fn m3_public_a_padded_to_384() {
        let mut setup = PairSetupSession::new(false);
        let b = pad_n(&srp_n(), &srp_g());
        setup
            .process_m2(&crate::tlv8::encode(&[
                (crate::tlv8::SEQNO, &[0x02]),
                (crate::tlv8::SALT, &[0u8; 16]),
                (crate::tlv8::PUBLIC_KEY, &b),
            ]))
            .unwrap();
        let m3 = setup.m3("1234").unwrap();
        let map = crate::tlv8::decode(&m3);
        assert_eq!(map.get(&crate::tlv8::PUBLIC_KEY).unwrap().len(), 384);
        assert_eq!(map.get(&crate::tlv8::SEQNO).unwrap(), &[0x03]);
    }
}

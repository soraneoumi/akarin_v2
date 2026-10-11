//! auth_akarin_v2 TCP wire format and key schedule shared by both peers.
use crate::crypto::{Aes128BlockCipher, hkdf_sha256_array, hmac_sha256};
use anyhow::{Result, anyhow, bail};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{RngExt, rng};
use sha2::{Digest, Sha256, Sha512};

pub const V2_PROTOCOL_VERSION: u8 = 1;
pub const CLIENT_HELLO_FLAG_RESUME: u8 = 0x01;
pub const SERVER_HELLO_FLAG_RESUME: u8 = 0x01;
pub const SERVER_FRAME_FLAG_TICKET_UPDATE: u8 = 0x01;
pub const SERVER_FRAME_FLAG_KEY_UPDATE: u8 = 0x02;
pub const AEAD_KEY_LEN: usize = 16;
pub const KEY_UPDATE_SALT_LEN: usize = 16;
pub const TICKET_ROTATION_TICKET_LEN: usize = 16;
pub const TICKET_ROTATION_SECRET_LEN: usize = 32;
pub const TICKET_ROTATION_METADATA_LEN: usize =
    TICKET_ROTATION_TICKET_LEN + TICKET_ROTATION_SECRET_LEN;
pub const CLIENT_HELLO_LEN: usize = 96;
pub const SERVER_HELLO_LEN: usize = 100;
pub const SERVER_HELLO_TAG_LEN: usize = 16;
pub const CLIENT_HELLO_PREFIX_LEN: usize = 4;
pub const CLIENT_HELLO_SEED_LEN: usize = 8;
pub const SERVER_HELLO_PREFIX_LEN: usize = 4;
pub const SERVER_HELLO_SEED_LEN: usize = 12;
pub const FRAME_HEADER_LEN: usize = 8;
pub const FRAME_OUTER_LEN: usize = 2;
pub const FRAME_TAG_LEN: usize = 16;
pub const MAX_FRAME_PLAIN_LEN: usize = 60 * 1024;
pub const DEFAULT_TCP_MSS: u16 = 1460;
pub const MIN_TCP_MSS: u16 = 500;
pub const MAX_TCP_MSS: u16 = 1500;
pub const COUNTER_WINDOW: u32 = 1;
pub const MAX_METHOD_LABEL_LEN: usize = 32;

/// The MSS a peer advertises and shapes against: `0` selects the default and
/// anything else is held to the range both peers accept.
pub fn normalize_tcp_mss(tcp_mss: u16) -> u16 {
    if tcp_mss == 0 {
        DEFAULT_TCP_MSS
    } else {
        tcp_mss.clamp(MIN_TCP_MSS, MAX_TCP_MSS)
    }
}

#[derive(Clone, Debug)]
pub struct ClientHello {
    pub prefix: [u8; CLIENT_HELLO_PREFIX_LEN],
    pub flags: u8,
    pub user_id: u32,
    pub client_id: u32,
    pub connection_id: u32,
    pub client_overhead: u16,
    pub tcp_mss: u16,
    pub client_nonce: [u8; 16],
    pub ticket: [u8; 16],
    pub client_share: [u8; 32],
    pub hello_seed: [u8; CLIENT_HELLO_SEED_LEN],
}

impl ClientHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CLIENT_HELLO_LEN);
        out.extend_from_slice(&self.prefix);
        out.push(V2_PROTOCOL_VERSION);
        out.push(self.flags);
        out.extend_from_slice(&[0_u8; 2]);
        out.extend_from_slice(&self.user_id.to_le_bytes());
        out.extend_from_slice(&self.client_id.to_le_bytes());
        out.extend_from_slice(&self.connection_id.to_le_bytes());
        out.extend_from_slice(&self.client_overhead.to_le_bytes());
        out.extend_from_slice(&self.tcp_mss.to_le_bytes());
        out.extend_from_slice(&self.client_nonce);
        out.extend_from_slice(&self.ticket);
        out.extend_from_slice(&self.client_share);
        out.extend_from_slice(&self.hello_seed);
        out
    }

    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < CLIENT_HELLO_LEN {
            bail!("auth_akarin_v2 client hello is incomplete");
        }
        if input[4] != V2_PROTOCOL_VERSION {
            bail!("auth_akarin_v2 client hello version mismatch");
        }
        if input[6] != 0 || input[7] != 0 {
            bail!("auth_akarin_v2 client hello reserved bytes must be zero");
        }
        let flags = input[5];
        if (flags & !CLIENT_HELLO_FLAG_RESUME) != 0 {
            bail!("auth_akarin_v2 client hello has unknown flags");
        }
        let ticket: [u8; 16] = input[40..56]
            .try_into()
            .map_err(|_| anyhow!("invalid auth_akarin_v2 ticket field"))?;
        let zero_ticket = [0_u8; 16];
        if (flags & CLIENT_HELLO_FLAG_RESUME) == 0 && ticket != zero_ticket {
            bail!("auth_akarin_v2 full handshake ticket must be zero");
        }
        if (flags & CLIENT_HELLO_FLAG_RESUME) != 0 && ticket == zero_ticket {
            bail!("auth_akarin_v2 resume handshake ticket must be non-zero");
        }
        Ok(Self {
            prefix: input[0..4]
                .try_into()
                .map_err(|_| anyhow!("invalid auth_akarin_v2 client hello prefix"))?,
            flags,
            user_id: u32::from_le_bytes(input[8..12].try_into().unwrap()),
            client_id: u32::from_le_bytes(input[12..16].try_into().unwrap()),
            connection_id: u32::from_le_bytes(input[16..20].try_into().unwrap()),
            client_overhead: u16::from_le_bytes(input[20..22].try_into().unwrap()),
            tcp_mss: u16::from_le_bytes(input[22..24].try_into().unwrap()),
            client_nonce: input[24..40]
                .try_into()
                .map_err(|_| anyhow!("invalid auth_akarin_v2 client nonce"))?,
            ticket,
            client_share: input[56..88]
                .try_into()
                .map_err(|_| anyhow!("invalid auth_akarin_v2 client share"))?,
            hello_seed: input[88..96]
                .try_into()
                .map_err(|_| anyhow!("invalid auth_akarin_v2 hello seed"))?,
        })
    }

    pub fn is_resume(&self) -> bool {
        (self.flags & CLIENT_HELLO_FLAG_RESUME) != 0
    }
}

#[derive(Clone, Debug)]
pub struct ServerHello {
    pub prefix: [u8; SERVER_HELLO_PREFIX_LEN],
    pub flags: u8,
    pub seed: [u8; SERVER_HELLO_SEED_LEN],
    pub ticket: [u8; 16],
    pub server_nonce: [u8; 16],
    pub server_share: [u8; 32],
    pub tcp_mss: u16,
    pub tag: [u8; SERVER_HELLO_TAG_LEN],
}

impl ServerHello {
    pub fn encode(&self) -> [u8; SERVER_HELLO_LEN] {
        let mut out = [0_u8; SERVER_HELLO_LEN];
        let mut pos = 0_usize;
        out[pos..pos + SERVER_HELLO_PREFIX_LEN].copy_from_slice(&self.prefix);
        pos += SERVER_HELLO_PREFIX_LEN;
        out[pos] = V2_PROTOCOL_VERSION;
        pos += 1;
        out[pos] = self.flags;
        pos += 1;
        out[pos..pos + 2].copy_from_slice(&self.tcp_mss.to_le_bytes());
        pos += 2;
        out[pos..pos + SERVER_HELLO_SEED_LEN].copy_from_slice(&self.seed);
        pos += SERVER_HELLO_SEED_LEN;
        out[pos..pos + 16].copy_from_slice(&self.ticket);
        pos += 16;
        out[pos..pos + 16].copy_from_slice(&self.server_nonce);
        pos += 16;
        out[pos..pos + 32].copy_from_slice(&self.server_share);
        pos += 32;
        out[pos..pos + SERVER_HELLO_TAG_LEN].copy_from_slice(&self.tag);
        out
    }

    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < SERVER_HELLO_LEN {
            bail!("auth_akarin_v2 server hello is incomplete");
        }
        if input[4] != V2_PROTOCOL_VERSION {
            bail!("auth_akarin_v2 server hello version mismatch");
        }
        let tcp_mss =
            u16::from_le_bytes(input[6..8].try_into().unwrap()).clamp(MIN_TCP_MSS, MAX_TCP_MSS);
        if (input[5] & !SERVER_HELLO_FLAG_RESUME) != 0 {
            bail!("auth_akarin_v2 server hello has unknown flags");
        }
        Ok(Self {
            prefix: input[0..4].try_into().unwrap(),
            flags: input[5],
            seed: input[8..20].try_into().unwrap(),
            ticket: input[20..36].try_into().unwrap(),
            server_nonce: input[36..52].try_into().unwrap(),
            server_share: input[52..84].try_into().unwrap(),
            tcp_mss,
            tag: input[84..100].try_into().unwrap(),
        })
    }
}

// Owns the frame-length key bytes together with their expanded schedule so the two cannot drift.
pub struct LenKey {
    pub key: [u8; AEAD_KEY_LEN],
    pub cipher: Aes128BlockCipher,
}

impl LenKey {
    pub fn new(key: [u8; AEAD_KEY_LEN]) -> Self {
        let cipher = Aes128BlockCipher::new(&key);
        Self { key, cipher }
    }
}

pub struct TransportKeys {
    pub c2s_key: [u8; AEAD_KEY_LEN],
    pub s2c_key: [u8; AEAD_KEY_LEN],
    pub c2s_len_key: [u8; AEAD_KEY_LEN],
    pub s2c_len_key: [u8; AEAD_KEY_LEN],
    pub c2s_nonce: [u8; 8],
    pub s2c_nonce: [u8; 8],
}

#[derive(Clone, Default)]
pub struct XorShift128Plus {
    pub v0: u64,
    pub v1: u64,
}

impl XorShift128Plus {
    const MOV_MASK: u64 = (1_u64 << (64 - 23)) - 1;

    pub fn next(&mut self) -> u64 {
        let mut x = self.v0;
        let y = self.v1;
        self.v0 = y;
        x ^= (x & Self::MOV_MASK) << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.v1 = x;
        x.wrapping_add(y)
    }

    pub fn init_from_bin(&mut self, input: &[u8]) {
        let mut data = [0_u8; 16];
        let n = input.len().min(16);
        data[..n].copy_from_slice(&input[..n]);
        self.v0 = u64::from_le_bytes(data[0..8].try_into().unwrap());
        self.v1 = u64::from_le_bytes(data[8..16].try_into().unwrap());
    }
}

pub fn spake_point(label: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"ssrr-auth-akarin-v2-spake2:");
    hasher.update(label);
    let digest = hasher.finalize();
    let mut wide = [0_u8; 64];
    wide.copy_from_slice(&digest[..64]);
    RistrettoPoint::from_uniform_bytes(&wide)
}

pub fn password_scalar(user_key: &[u8], method: &str, user_id: Option<u32>) -> Result<Scalar> {
    let mut salt = [0_u8; MAX_METHOD_LABEL_LEN + 6];
    let method_len = method.len();
    salt[..method_len].copy_from_slice(method.as_bytes());
    let mut salt_len = method_len;
    salt[salt_len] = 0;
    salt_len += 1;
    if let Some(uid) = user_id {
        salt[salt_len] = 1;
        salt_len += 1;
        salt[salt_len..salt_len + 4].copy_from_slice(&uid.to_le_bytes());
        salt_len += 4;
    } else {
        salt[salt_len] = 0;
        salt_len += 1;
    }
    let wide_bytes = hkdf_sha256_array::<64>(
        user_key,
        &salt[..salt_len],
        b"ssrr-auth-akarin-v2-password-scalar",
    )?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide_bytes))
}

pub fn random_scalar() -> Scalar {
    let mut wide = [0_u8; 64];
    rng().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn transcript_hash(
    method: &str,
    user_id: Option<u32>,
    hello: &ClientHello,
    server_hello: &ServerHello,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update([0_u8]);
    match user_id {
        Some(uid) => {
            hasher.update([1_u8]);
            hasher.update(uid.to_le_bytes());
        }
        None => hasher.update([0_u8]),
    }
    hasher.update(hello.prefix);
    hasher.update([hello.flags]);
    hasher.update(hello.user_id.to_le_bytes());
    hasher.update(hello.client_id.to_le_bytes());
    hasher.update(hello.connection_id.to_le_bytes());
    hasher.update(hello.client_overhead.to_le_bytes());
    hasher.update(hello.tcp_mss.to_le_bytes());
    hasher.update(hello.client_nonce);
    hasher.update(hello.ticket);
    hasher.update(hello.client_share);
    hasher.update(hello.hello_seed);
    hasher.update(server_hello.prefix);
    hasher.update([server_hello.flags]);
    hasher.update(server_hello.tcp_mss.to_le_bytes());
    hasher.update(server_hello.seed);
    hasher.update(server_hello.ticket);
    hasher.update(server_hello.server_nonce);
    hasher.update(server_hello.server_share);
    let digest = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn derive_master_secret(
    shared_point: &RistrettoPoint,
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let shared = shared_point.compress().to_bytes();
    hkdf_sha256_array::<32>(&shared, transcript_hash, b"ssrr-auth-akarin-v2-master")
}

pub fn derive_resume_master_secret(
    shared_point: &RistrettoPoint,
    resumption_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut ikm = [0_u8; 64];
    ikm[..32].copy_from_slice(&shared_point.compress().to_bytes());
    ikm[32..].copy_from_slice(resumption_secret);
    hkdf_sha256_array::<32>(&ikm, transcript_hash, b"ssrr-auth-akarin-v2-resume-master")
}

pub fn derive_resumption_secret(
    master_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    hkdf_sha256_array::<32>(
        master_secret,
        transcript_hash,
        b"ssrr-auth-akarin-v2-resumption",
    )
}

pub fn derive_server_confirm_tag(
    master_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<[u8; SERVER_HELLO_TAG_LEN]> {
    let confirm_key = hkdf_sha256_array::<32>(
        master_secret,
        transcript_hash,
        b"ssrr-auth-akarin-v2-server-confirm",
    )?;
    let full = hmac_sha256(&confirm_key, transcript_hash);
    let mut out = [0_u8; SERVER_HELLO_TAG_LEN];
    out.copy_from_slice(&full[..SERVER_HELLO_TAG_LEN]);
    Ok(out)
}

pub fn derive_server_key_update(
    method: &str,
    master_secret: &[u8; 32],
    salt: &[u8; KEY_UPDATE_SALT_LEN],
) -> Result<([u8; AEAD_KEY_LEN], [u8; AEAD_KEY_LEN], [u8; 8])> {
    let mut hkdf_salt = [0_u8; MAX_METHOD_LABEL_LEN + 1 + KEY_UPDATE_SALT_LEN];
    let method_len = method.len();
    hkdf_salt[..method_len].copy_from_slice(method.as_bytes());
    hkdf_salt[method_len] = 0;
    hkdf_salt[method_len + 1..method_len + 1 + KEY_UPDATE_SALT_LEN].copy_from_slice(salt);
    let hkdf_salt = &hkdf_salt[..method_len + 1 + KEY_UPDATE_SALT_LEN];
    let key = hkdf_sha256_array::<AEAD_KEY_LEN>(
        master_secret,
        hkdf_salt,
        b"ssrr-auth-akarin-v2-server->client-key-update-key",
    )?;
    let len_key = hkdf_sha256_array::<AEAD_KEY_LEN>(
        master_secret,
        hkdf_salt,
        b"ssrr-auth-akarin-v2-server->client-key-update-len-key",
    )?;
    let nonce = hkdf_sha256_array::<8>(
        master_secret,
        hkdf_salt,
        b"ssrr-auth-akarin-v2-server->client-key-update-nonce",
    )?;
    Ok((key, len_key, nonce))
}

pub fn derive_transport_keys(
    master_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<TransportKeys> {
    let c2s_key = hkdf_sha256_array::<AEAD_KEY_LEN>(
        master_secret,
        transcript_hash,
        b"ssrr-auth-akarin-v2-client->server-key",
    )?;
    let s2c_key = hkdf_sha256_array::<AEAD_KEY_LEN>(
        master_secret,
        transcript_hash,
        b"ssrr-auth-akarin-v2-server->client-key",
    )?;
    let c2s_len_key = hkdf_sha256_array::<AEAD_KEY_LEN>(
        master_secret,
        transcript_hash,
        b"ssrr-auth-akarin-v2-client->server-len-key",
    )?;
    let s2c_len_key = hkdf_sha256_array::<AEAD_KEY_LEN>(
        master_secret,
        transcript_hash,
        b"ssrr-auth-akarin-v2-server->client-len-key",
    )?;
    let c2s_nonce = hkdf_sha256_array::<8>(
        master_secret,
        transcript_hash,
        b"ssrr-auth-akarin-v2-client->server-nonce",
    )?;
    let s2c_nonce = hkdf_sha256_array::<8>(
        master_secret,
        transcript_hash,
        b"ssrr-auth-akarin-v2-server->client-nonce",
    )?;
    Ok(TransportKeys {
        c2s_key,
        s2c_key,
        c2s_len_key,
        s2c_len_key,
        c2s_nonce,
        s2c_nonce,
    })
}

pub fn frame_nonce(prefix: &[u8; 8], counter: u32) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

pub fn frame_len_mask(len_cipher: &Aes128BlockCipher, prefix: &[u8; 8], counter: u32) -> u16 {
    let mut block = [0_u8; 16];
    block[..8].copy_from_slice(prefix);
    block[8..12].copy_from_slice(&counter.to_le_bytes());
    block[12..].copy_from_slice(b"len!");
    let mask = len_cipher.encrypt_block(&block);
    u16::from_le_bytes(mask[..2].try_into().unwrap())
}

pub fn encode_frame_len(
    len_cipher: &Aes128BlockCipher,
    prefix: &[u8; 8],
    counter: u32,
    body_cipher_len: usize,
) -> Result<[u8; FRAME_OUTER_LEN]> {
    let len = u16::try_from(body_cipher_len)
        .map_err(|_| anyhow!("auth_akarin_v2 frame body is too large"))?;
    Ok((len ^ frame_len_mask(len_cipher, prefix, counter)).to_le_bytes())
}

pub fn decode_frame_len(
    len_cipher: &Aes128BlockCipher,
    prefix: &[u8; 8],
    counter: u32,
    masked_len: &[u8; FRAME_OUTER_LEN],
) -> usize {
    let masked = u16::from_le_bytes(*masked_len);
    usize::from(masked ^ frame_len_mask(len_cipher, prefix, counter))
}

pub fn frame_aad(counter: u32, masked_len: &[u8; FRAME_OUTER_LEN]) -> [u8; 6] {
    let mut aad = [0_u8; 6];
    aad[..4].copy_from_slice(&counter.to_le_bytes());
    aad[4..].copy_from_slice(masked_len);
    aad
}

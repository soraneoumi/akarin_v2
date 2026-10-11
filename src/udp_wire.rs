//! auth_akarin_v2 UDP wire format and key schedule shared by both peers.
use crate::crypto::{hkdf_sha256_array, hmac_sha256};
use anyhow::Result;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

pub const UDP_V2_PROTOCOL_VERSION: u8 = 1;
pub const UDP_V2_BOOTSTRAP_TYPE: u8 = 0x01;
pub const UDP_V2_BOOTSTRAP_RESP_TYPE: u8 = 0x02;
pub const UDP_V2_DATA_TYPE: u8 = 0x03;
pub const UDP_V2_BOOTSTRAP_RESP_LEN: usize = 96;
pub const UDP_V2_DATA_HEADER_LEN: usize = 37;
pub const UDP_V2_META_LEN: usize = 4;
pub const UDP_V2_DATA_FLAG_TICKET_UPDATE: u8 = 0x01;
pub const UDP_V2_DATA_FLAG_FRAGMENT: u8 = 0x02;
pub const UDP_V2_TICKET_ID_LEN: usize = 16;
pub const UDP_V2_TICKET_SECRET_LEN: usize = 32;
pub const UDP_V2_TICKET_UPDATE_LEN: usize = UDP_V2_TICKET_ID_LEN + UDP_V2_TICKET_SECRET_LEN;
pub const UDP_V2_FRAGMENT_META_LEN: usize = 8;
pub const UDP_V2_FRAGMENT_TIMEOUT_SECS: u64 = 30;
pub const UDP_V2_MAX_PLAIN_LEN: usize = u16::MAX as usize;
pub const UDP_V2_AEAD_KEY_LEN: usize = 16;
pub const UDP_V2_METHOD_LABEL_MAX_LEN: usize = 32;
pub const UDP_V2_DEFAULT_PACKET_SIZE: usize = 1232;
pub const UDP_V2_MIN_PACKET_SIZE: u16 = 576;
pub const UDP_V2_MAX_PACKET_SIZE: u16 = 1500;

pub struct UdpV2BootstrapTranscript<'a> {
    pub client_udp_packet_size: u16,
    pub server_udp_packet_size: u16,
    pub user_id_field: u32,
    pub selected_user_id: Option<u32>,
    pub client_seed: [u8; 4],
    pub client_nonce: &'a [u8; 16],
    pub client_share: &'a [u8; 32],
    pub server_seed: [u8; 12],
    pub ticket: &'a [u8; 16],
    pub server_nonce: &'a [u8; 16],
    pub server_share: &'a [u8; 32],
}

/// The one authority on what packet sizes the v2 codec accepts, so a
/// size derived from the path is held to the same bounds as a configured
/// one. Zero means "no opinion" and yields the safe default.
pub fn normalize_v2_udp_packet_size(size: u16) -> u16 {
    if size == 0 {
        UDP_V2_DEFAULT_PACKET_SIZE as u16
    } else {
        size.clamp(UDP_V2_MIN_PACKET_SIZE, UDP_V2_MAX_PACKET_SIZE)
    }
}

pub fn udp_password_scalar(user_key: &[u8], method: &str, user_id: Option<u32>) -> Result<Scalar> {
    let mut salt = [0_u8; UDP_V2_METHOD_LABEL_MAX_LEN + 6];
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
        b"ssrr-auth-akarin-v2-udp-password-scalar",
    )?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide_bytes))
}

pub fn bootstrap_transcript_hash(
    method: &str,
    transcript: &UdpV2BootstrapTranscript<'_>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update([UDP_V2_BOOTSTRAP_TYPE, UDP_V2_PROTOCOL_VERSION]);
    hasher.update(transcript.client_udp_packet_size.to_le_bytes());
    hasher.update(transcript.server_udp_packet_size.to_le_bytes());
    hasher.update(transcript.user_id_field.to_le_bytes());
    match transcript.selected_user_id {
        Some(uid) => {
            hasher.update([1_u8]);
            hasher.update(uid.to_le_bytes());
        }
        None => hasher.update([0_u8]),
    }
    hasher.update(transcript.client_seed);
    hasher.update(transcript.client_nonce);
    hasher.update(transcript.client_share);
    hasher.update(transcript.server_seed);
    hasher.update(transcript.ticket);
    hasher.update(transcript.server_nonce);
    hasher.update(transcript.server_share);
    let digest = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn derive_v2_udp_master_secret(
    shared_point: &RistrettoPoint,
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let shared = shared_point.compress().to_bytes();
    hkdf_sha256_array::<32>(&shared, transcript_hash, b"ssrr-auth-akarin-v2-udp-master")
}

pub fn derive_v2_udp_confirm_tag(
    master_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 16]> {
    let confirm_key = hkdf_sha256_array::<32>(
        master_secret,
        transcript_hash,
        b"ssrr-auth-akarin-v2-udp-server-confirm",
    )?;
    let full = hmac_sha256(&confirm_key, transcript_hash);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&full[..16]);
    Ok(out)
}

pub fn derive_v2_udp_epoch_key(
    method: &str,
    master_secret: &[u8; 32],
    epoch: u64,
    direction: &[u8],
) -> Result<[u8; UDP_V2_AEAD_KEY_LEN]> {
    let method_len = method.len();
    let mut salt = [0_u8; UDP_V2_METHOD_LABEL_MAX_LEN + 1 + 8];
    salt[..method_len].copy_from_slice(method.as_bytes());
    let mut salt_len = method_len;
    salt[salt_len] = 0;
    salt_len += 1;
    salt[salt_len..salt_len + 8].copy_from_slice(&epoch.to_be_bytes());
    salt_len += 8;

    const INFO_PREFIX: &[u8] = b"ssrr-auth-akarin-v2-udp-epoch-key:";
    let mut info = [0_u8; 40];
    info[..INFO_PREFIX.len()].copy_from_slice(INFO_PREFIX);
    info[INFO_PREFIX.len()..INFO_PREFIX.len() + direction.len()].copy_from_slice(direction);
    let info_len = INFO_PREFIX.len() + direction.len();

    hkdf_sha256_array::<UDP_V2_AEAD_KEY_LEN>(master_secret, &salt[..salt_len], &info[..info_len])
}

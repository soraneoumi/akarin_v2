use crate::buffer::PrefixBuffer;
use crate::crypto::{Aes128GcmCipher, HmacSha256Key, hkdf_sha256_array, hmac_sha256};
use crate::error::{DecodeErrorKind, decode_error, decode_result};
use crate::now_secs_u32;
use crate::server::Server;
use crate::server::generate_opaque_session_ticket;
use crate::server::state::{
    SessionEntry, SharedReplaySet, SharedSessionTicketStore, SharedUserRegistry,
};
use crate::udp_wire::UDP_V2_DEFAULT_PACKET_SIZE;
use crate::wire::{
    AEAD_KEY_LEN, CLIENT_HELLO_LEN, COUNTER_WINDOW, ClientHello, FRAME_HEADER_LEN, FRAME_OUTER_LEN,
    FRAME_TAG_LEN, KEY_UPDATE_SALT_LEN, LenKey, MAX_FRAME_PLAIN_LEN, MAX_METHOD_LABEL_LEN,
    MAX_TCP_MSS, MIN_TCP_MSS, SERVER_FRAME_FLAG_KEY_UPDATE, SERVER_FRAME_FLAG_TICKET_UPDATE,
    SERVER_HELLO_FLAG_RESUME, SERVER_HELLO_LEN, SERVER_HELLO_PREFIX_LEN, SERVER_HELLO_SEED_LEN,
    SERVER_HELLO_TAG_LEN, ServerHello, TICKET_ROTATION_METADATA_LEN, TransportKeys,
    XorShift128Plus, decode_frame_len, derive_master_secret, derive_resume_master_secret,
    derive_resumption_secret, derive_server_confirm_tag, derive_server_key_update,
    derive_transport_keys, encode_frame_len, frame_aad, frame_nonce, normalize_tcp_mss,
    password_scalar, random_scalar, spake_point, transcript_hash,
};
use anyhow::{Result, anyhow};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use rand::{RngExt, rng};
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const KEY_UPDATE_COUNTER_TRIGGER: u32 = u32::MAX - 0x1000;
const FRAME_WIRE_OVERHEAD: usize = FRAME_OUTER_LEN + FRAME_HEADER_LEN + FRAME_TAG_LEN;
const SPEC_TIME_HYSTERESIS_SECS: u64 = 2;
const REGISTRY_ACTIVITY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const SHAPE_BIN_CAPACITY: usize = 12;
#[derive(Clone)]
struct PendingTicketRotation {
    next_ticket: [u8; 16],
    resumption_secret: [u8; 32],
    next_entry: SessionEntry,
}

#[derive(Clone, Copy)]
struct PendingKeyUpdate {
    salt: [u8; KEY_UPDATE_SALT_LEN],
    tx_key: [u8; AEAD_KEY_LEN],
    tx_len_key: [u8; AEAD_KEY_LEN],
    tx_nonce_prefix: [u8; 8],
}

#[derive(Clone, Copy)]
struct TxKeyState {
    tx_key: [u8; AEAD_KEY_LEN],
    tx_len_key: [u8; AEAD_KEY_LEN],
    tx_nonce_prefix: [u8; 8],
    tx_counter: u32,
}

struct PreparedServerHello {
    encoded: [u8; SERVER_HELLO_LEN],
    ticket: [u8; 16],
    // `Some` for a full handshake, where a new session entry must be inserted;
    // `None` for a resume, which only refreshes the presented ticket's activity.
    new_session_entry_secret: Option<[u8; 32]>,
}

struct PendingHandshakeCommit {
    ticket: [u8; 16],
    new_session_entry_secret: Option<[u8; 32]>,
}

#[derive(Clone)]
struct ShapeProfile {
    epoch: u64,
    pad_mac: HmacSha256Key,
    bins: [u16; SHAPE_BIN_CAPACITY],
    bin_len: usize,
}

impl ShapeProfile {
    fn bins(&self) -> &[u16] {
        &self.bins[..self.bin_len]
    }
}

/// Server side of one auth_akarin_v2 TCP connection.
///
/// The session is sans-IO: feed it bytes read from the socket with
/// [`decode`](Self::decode), write whatever [`encode`](Self::encode) produces,
/// and report the outcome of every such write through
/// [`on_flushed`](Self::on_flushed). Ticket issuance, ticket rotation and key
/// updates only take effect once their bytes are known to be delivered, so
/// skipping `on_flushed` leaves them staged forever.
///
/// Staged state has room for one write: report each output's fate before
/// producing the next one. Dropping the session releases its slot in the
/// per-user `max_client` budget, so drop it when the connection closes.
pub struct TcpServerSession {
    method: &'static str,
    key: Vec<u8>,
    users: Arc<HashMap<u32, Vec<u8>>>,
    recv_buf: PrefixBuffer,
    user_id: Option<u32>,
    user_key: Vec<u8>,
    client_id: u32,
    connection_id: u32,
    client_overhead: u16,
    tcp_mss: u16,
    peer_tcp_mss: u16,
    unit_len: usize,
    tx_key: Option<[u8; AEAD_KEY_LEN]>,
    rx_key: Option<[u8; AEAD_KEY_LEN]>,
    tx_len_key: Option<LenKey>,
    rx_len_key: Option<LenKey>,
    tx_cipher: Option<Aes128GcmCipher>,
    rx_cipher: Option<Aes128GcmCipher>,
    tx_nonce_prefix: [u8; 8],
    rx_nonce_prefix: [u8; 8],
    tx_counter: u32,
    rx_counter: u32,
    pending_server_hello: Option<[u8; SERVER_HELLO_LEN]>,
    pending_handshake_commit: Option<PendingHandshakeCommit>,
    current_ticket: Option<[u8; 16]>,
    registry_inserted: bool,
    registry_deferred: bool,
    next_registry_refresh_at: Option<Instant>,
    spec_time_interval: Option<u64>,
    shape_profile: Option<ShapeProfile>,
    master_secret: Option<[u8; 32]>,
    ticket_rotation_interval: Duration,
    pending_ticket_rotation: Option<PendingTicketRotation>,
    key_update_interval: Duration,
    next_key_update_at: Option<Instant>,
    pending_key_update: Option<PendingKeyUpdate>,
    key_update_rollback: Option<TxKeyState>,
    session_tickets: SharedSessionTicketStore,
    shared_registry: SharedUserRegistry,
    handshake_replays: SharedReplaySet,
}

impl TcpServerSession {
    pub(crate) fn new(server: &Server) -> Self {
        let tcp_mss = server.tcp_mss;
        let ticket_half_life = server.session_tickets.timeout() / 2;

        Self {
            method: server.method.label(),
            key: server.password.to_vec(),
            users: server.users.clone(),
            recv_buf: PrefixBuffer::new(),
            user_id: None,
            user_key: Vec::new(),
            client_id: 0,
            connection_id: 0,
            client_overhead: 0,
            tcp_mss,
            peer_tcp_mss: tcp_mss,
            unit_len: MAX_FRAME_PLAIN_LEN,
            tx_key: None,
            rx_key: None,
            tx_len_key: None,
            rx_len_key: None,
            tx_cipher: None,
            rx_cipher: None,
            tx_nonce_prefix: [0_u8; 8],
            rx_nonce_prefix: [0_u8; 8],
            tx_counter: 1,
            rx_counter: 1,
            pending_server_hello: None,
            pending_handshake_commit: None,
            current_ticket: None,
            registry_inserted: false,
            registry_deferred: false,
            next_registry_refresh_at: None,
            spec_time_interval: server.method.spec_time_interval(),
            shape_profile: None,
            master_secret: None,
            ticket_rotation_interval: ticket_half_life,
            pending_ticket_rotation: None,
            key_update_interval: ticket_half_life,
            next_key_update_at: None,
            pending_key_update: None,
            key_update_rollback: None,
            session_tickets: server.session_tickets.clone(),
            shared_registry: server.registry.clone(),
            handshake_replays: server.tcp_replays.clone(),
        }
    }

    fn select_user_key(&mut self, uid: u32) -> bool {
        if let Some(key) = self.users.get(&uid) {
            self.user_id = Some(uid);
            self.user_key = key.clone();
            return true;
        }

        if self.users.is_empty() {
            self.user_id = None;
            self.user_key = self.key.clone();
            return true;
        }

        self.user_id = Some(uid);
        self.user_key = self.dummy_user_key(uid);
        false
    }

    fn registry_user_id(&self) -> Result<u32> {
        if let Some(uid) = self.user_id {
            return Ok(uid);
        }
        if self.users.is_empty() {
            return Ok(0);
        }
        Err(anyhow!(
            "auth_akarin_v2 user id is missing after multi-user handshake"
        ))
    }

    fn registry_user_id_for_dispose(&self) -> Option<u32> {
        if let Some(uid) = self.user_id {
            return Some(uid);
        }
        if self.users.is_empty() {
            return Some(0);
        }
        None
    }

    fn dummy_user_key(&self, uid: u32) -> Vec<u8> {
        let mut salt = [0_u8; MAX_METHOD_LABEL_LEN + 1 + 4];
        let method_len = self.method.len();
        salt[..method_len].copy_from_slice(self.method.as_bytes());
        salt[method_len] = 0xff;
        salt[method_len + 1..method_len + 5].copy_from_slice(&uid.to_le_bytes());
        hmac_sha256(&self.key, &salt[..method_len + 5]).to_vec()
    }

    fn register_handshake_replay(&self, hello_bytes: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.method.as_bytes());
        hasher.update([0_u8]);
        hasher.update(hello_bytes);
        let key = hasher.finalize();
        self.handshake_replays.insert_unique(&key)
    }

    fn current_epoch_bucket(&self) -> u64 {
        let Some(interval) = self.spec_time_interval else {
            return 0;
        };

        let now = u64::from(now_secs_u32());
        let mut bucket = now / interval;

        // Hold the previous profile for the first seconds of a new interval so
        // frames sent around the boundary do not flip between two shapes.
        if let Some(current) = self.shape_profile.as_ref().map(|profile| profile.epoch)
            && bucket > current
        {
            let guard = SPEC_TIME_HYSTERESIS_SECS.min(interval - 1);
            if guard > 0 && now % interval < guard {
                bucket = current;
            }
        }

        bucket
    }

    fn ensure_shape_profile(&mut self) -> Result<()> {
        let Some(master_secret) = self.master_secret else {
            return Ok(());
        };

        let epoch = self.current_epoch_bucket();
        if self
            .shape_profile
            .as_ref()
            .is_some_and(|profile| profile.epoch == epoch)
        {
            return Ok(());
        }

        self.shape_profile = Some(Self::derive_shape_profile(
            &master_secret,
            self.method,
            epoch,
        )?);
        Ok(())
    }

    fn dedup_shape_bins(bins: &mut [u16; SHAPE_BIN_CAPACITY], len: usize) -> usize {
        let mut write = 0_usize;
        for read in 0..len {
            if read == 0 || bins[read] != bins[read - 1] {
                bins[write] = bins[read];
                write += 1;
            }
        }
        write
    }

    fn derive_shape_profile(
        master_secret: &[u8; 32],
        method: &str,
        epoch: u64,
    ) -> Result<ShapeProfile> {
        let mut salt = [0_u8; MAX_METHOD_LABEL_LEN + 8];
        let method_len = method.len();
        salt[..method_len].copy_from_slice(method.as_bytes());
        salt[method_len..method_len + 8].copy_from_slice(&epoch.to_be_bytes());
        let seed = hkdf_sha256_array::<32>(
            master_secret,
            &salt[..method_len + 8],
            b"ssrr-auth-akarin-v2-shape",
        )?;

        let base_bins = [192_u16, 224, 256, 320, 384, 512, 704, 896, 1088, 1280, 1392];
        let mut rng = XorShift128Plus::default();
        rng.init_from_bin(&seed);
        let mut bins = [0_u16; SHAPE_BIN_CAPACITY];
        let mut bin_len = 0_usize;
        for base in base_bins {
            let spread = (rng.next() % 97) as i32 - 48;
            let candidate = (base as i32 + spread).clamp(160, 1440) as u16;
            if rng.next() % 7 != 0 || candidate <= 512 {
                bins[bin_len] = candidate;
                bin_len += 1;
            }
        }
        bins[..bin_len].sort_unstable();
        bin_len = Self::dedup_shape_bins(&mut bins, bin_len);
        if bin_len == 0 || bins[bin_len - 1] < 1300 {
            bins[bin_len] = 1360;
            bin_len += 1;
            bins[..bin_len].sort_unstable();
            bin_len = Self::dedup_shape_bins(&mut bins, bin_len);
        }
        Ok(ShapeProfile {
            epoch,
            pad_mac: HmacSha256Key::new(&seed),
            bins,
            bin_len,
        })
    }

    fn init_transport_keys(
        &mut self,
        master_secret: [u8; 32],
        transcript_hash: &[u8; 32],
    ) -> Result<()> {
        let TransportKeys {
            c2s_key: rx_key,
            s2c_key: tx_key,
            c2s_len_key: rx_len_key,
            s2c_len_key: tx_len_key,
            c2s_nonce: rx_nonce,
            s2c_nonce: tx_nonce,
        } = derive_transport_keys(&master_secret, transcript_hash)?;

        self.tx_key = Some(tx_key);
        self.rx_key = Some(rx_key);
        self.tx_len_key = Some(LenKey::new(tx_len_key));
        self.rx_len_key = Some(LenKey::new(rx_len_key));
        self.tx_cipher = Some(Aes128GcmCipher::new(&tx_key));
        self.rx_cipher = Some(Aes128GcmCipher::new(&rx_key));
        self.tx_nonce_prefix = tx_nonce;
        self.rx_nonce_prefix = rx_nonce;
        self.tx_counter = 1;
        self.rx_counter = 1;
        self.master_secret = Some(master_secret);
        self.shape_profile = None;
        Ok(())
    }

    fn build_v2_session_entry(&self, resumption_secret: [u8; 32]) -> SessionEntry {
        let mut ticket_family_id = [0_u8; 16];
        rng().fill(&mut ticket_family_id);
        SessionEntry {
            master_secret: resumption_secret,
            user_id: self.user_id,
            // A TCP handshake learns nothing about the UDP path, so the ticket
            // carries the safe default datagram size.
            udp_packet_size: UDP_V2_DEFAULT_PACKET_SIZE as u16,
            ticket_family_id,
            ticket_generation: 0,
        }
    }

    fn validate_v2_session_entry(&self, entry: &SessionEntry) -> Result<()> {
        if entry.user_id != self.user_id {
            return decode_result(
                DecodeErrorKind::TicketMismatch,
                anyhow!("auth_akarin_v2 session ticket user mismatch"),
            );
        }
        Ok(())
    }

    fn generate_session_ticket(avoid: Option<&[u8; 16]>) -> [u8; 16] {
        loop {
            let ticket = generate_opaque_session_ticket();
            if avoid != Some(&ticket) {
                return ticket;
            }
        }
    }

    fn should_rotate_ticket(&self) -> bool {
        if self.pending_handshake_commit.is_some() {
            return false;
        }
        let Some(current_ticket) = self.current_ticket else {
            return false;
        };
        self.session_tickets
            .issued_age(&current_ticket)
            .is_some_and(|age| age >= self.ticket_rotation_interval)
    }

    fn should_key_update(&self) -> bool {
        self.key_update_rollback.is_none()
            && self.master_secret.is_some()
            && (self.tx_counter >= KEY_UPDATE_COUNTER_TRIGGER
                || self
                    .next_key_update_at
                    .map(|deadline| Instant::now() >= deadline)
                    .unwrap_or(false))
    }

    fn pending_control_metadata_len(&self) -> usize {
        let mut metadata_len = 0;
        if self.pending_ticket_rotation.is_some() || self.should_rotate_ticket() {
            metadata_len += TICKET_ROTATION_METADATA_LEN;
        }
        if self.pending_key_update.is_some() || self.should_key_update() {
            metadata_len += KEY_UPDATE_SALT_LEN;
        }
        metadata_len
    }

    fn prepare_ticket_rotation(&mut self) -> Result<Option<PendingTicketRotation>> {
        if !self.should_rotate_ticket() {
            return Ok(None);
        }
        if let Some(pending) = self.pending_ticket_rotation.clone() {
            return Ok(Some(pending));
        }
        let current_ticket = self
            .current_ticket
            .ok_or_else(|| anyhow!("auth_akarin_v2 current ticket is missing"))?;
        let Some(current_entry) = self.session_tickets.peek(&current_ticket) else {
            // A concurrent expiry/removal means there is no authenticated family to inherit.
            return Ok(None);
        };
        let next_ticket = Self::generate_session_ticket(Some(&current_ticket));
        let mut resumption_secret = [0_u8; 32];
        rng().fill(&mut resumption_secret);
        let pending = PendingTicketRotation {
            next_ticket,
            resumption_secret,
            next_entry: current_entry.rotated(resumption_secret),
        };
        self.pending_ticket_rotation = Some(pending.clone());
        Ok(Some(pending))
    }

    fn prepare_key_update(&mut self) -> Result<Option<PendingKeyUpdate>> {
        if !self.should_key_update() {
            return Ok(None);
        }
        if let Some(pending) = self.pending_key_update {
            return Ok(Some(pending));
        }
        let master_secret = self
            .master_secret
            .ok_or_else(|| anyhow!("auth_akarin_v2 master secret is missing"))?;
        let mut salt = [0_u8; KEY_UPDATE_SALT_LEN];
        rng().fill(&mut salt);
        let (tx_key, tx_len_key, tx_nonce_prefix) =
            derive_server_key_update(self.method, &master_secret, &salt)?;
        let pending = PendingKeyUpdate {
            salt,
            tx_key,
            tx_len_key,
            tx_nonce_prefix,
        };
        self.pending_key_update = Some(pending);
        Ok(Some(pending))
    }

    fn install_tx_key_state(&mut self, state: TxKeyState) {
        self.tx_key = Some(state.tx_key);
        self.tx_len_key = Some(LenKey::new(state.tx_len_key));
        self.tx_cipher = Some(Aes128GcmCipher::new(&state.tx_key));
        self.tx_nonce_prefix = state.tx_nonce_prefix;
        self.tx_counter = state.tx_counter;
    }

    fn activate_pending_key_update(&mut self, update: PendingKeyUpdate) -> Result<()> {
        let rollback = TxKeyState {
            tx_key: self
                .tx_key
                .ok_or_else(|| anyhow!("auth_akarin_v2 tx key is not initialized"))?,
            tx_len_key: self
                .tx_len_key
                .as_ref()
                .ok_or_else(|| anyhow!("auth_akarin_v2 tx length key is not initialized"))?
                .key,
            tx_nonce_prefix: self.tx_nonce_prefix,
            tx_counter: self.tx_counter,
        };
        self.pending_key_update = None;
        self.key_update_rollback = Some(rollback);
        self.install_tx_key_state(TxKeyState {
            tx_key: update.tx_key,
            tx_len_key: update.tx_len_key,
            tx_nonce_prefix: update.tx_nonce_prefix,
            tx_counter: 1,
        });
        Ok(())
    }

    fn prepare_server_hello(&mut self, hello: &ClientHello) -> Result<PreparedServerHello> {
        let mut server_prefix = [0_u8; SERVER_HELLO_PREFIX_LEN];
        rng().fill(&mut server_prefix);
        let mut server_seed = [0_u8; SERVER_HELLO_SEED_LEN];
        rng().fill(&mut server_seed);
        let mut server_nonce = [0_u8; 16];
        rng().fill(&mut server_nonce);

        let (server_hello, new_session_entry_secret) = if hello.is_resume() {
            let entry = self.session_tickets.peek(&hello.ticket).ok_or_else(|| {
                decode_error(
                    DecodeErrorKind::UnknownTicket,
                    anyhow!("unknown auth_akarin_v2 session ticket"),
                )
            })?;
            self.validate_v2_session_entry(&entry)?;

            let client_component = CompressedRistretto(hello.client_share)
                .decompress()
                .ok_or_else(|| {
                    decode_error(
                        DecodeErrorKind::ClientHelloMalformed,
                        anyhow!("invalid auth_akarin_v2 client share"),
                    )
                })?;
            let server_scalar = random_scalar();
            let server_share_point = RISTRETTO_BASEPOINT_POINT * server_scalar;
            let shared_point = client_component * server_scalar;
            // Resume echoes the presented ticket unchanged; the connection's
            // resumption secret stays the stored entry's secret.
            let mut server_hello = ServerHello {
                prefix: server_prefix,
                flags: SERVER_HELLO_FLAG_RESUME,
                seed: server_seed,
                ticket: hello.ticket,
                server_nonce,
                server_share: server_share_point.compress().to_bytes(),
                tcp_mss: self.tcp_mss.clamp(MIN_TCP_MSS, MAX_TCP_MSS),
                tag: [0_u8; SERVER_HELLO_TAG_LEN],
            };
            let transcript_hash = transcript_hash(self.method, self.user_id, hello, &server_hello);
            let master_secret =
                derive_resume_master_secret(&shared_point, &entry.master_secret, &transcript_hash)?;
            self.init_transport_keys(master_secret, &transcript_hash)?;
            server_hello.tag = derive_server_confirm_tag(&master_secret, &transcript_hash)?;
            (server_hello, None)
        } else {
            let password_scalar = password_scalar(&self.user_key, self.method, self.user_id)?;
            let client_share = CompressedRistretto(hello.client_share)
                .decompress()
                .ok_or_else(|| {
                    decode_error(
                        DecodeErrorKind::ClientHelloMalformed,
                        anyhow!("invalid auth_akarin_v2 client share"),
                    )
                })?;
            let client_component = client_share - spake_point(b"M") * password_scalar;
            let server_scalar = random_scalar();
            let server_share_point =
                RISTRETTO_BASEPOINT_POINT * server_scalar + spake_point(b"N") * password_scalar;
            let shared_point = client_component * server_scalar;
            let issued_ticket = Self::generate_session_ticket(None);
            let mut server_hello = ServerHello {
                prefix: server_prefix,
                flags: 0,
                seed: server_seed,
                ticket: issued_ticket,
                server_nonce,
                server_share: server_share_point.compress().to_bytes(),
                tcp_mss: self.tcp_mss.clamp(MIN_TCP_MSS, MAX_TCP_MSS),
                tag: [0_u8; SERVER_HELLO_TAG_LEN],
            };
            let transcript_hash = transcript_hash(self.method, self.user_id, hello, &server_hello);
            let master_secret = derive_master_secret(&shared_point, &transcript_hash)?;
            let resumption_secret = derive_resumption_secret(&master_secret, &transcript_hash)?;
            self.init_transport_keys(master_secret, &transcript_hash)?;
            server_hello.tag = derive_server_confirm_tag(&master_secret, &transcript_hash)?;
            (server_hello, Some(resumption_secret))
        };

        self.current_ticket = Some(server_hello.ticket);
        self.next_key_update_at = Some(Instant::now() + self.key_update_interval);
        Ok(PreparedServerHello {
            encoded: server_hello.encode(),
            ticket: server_hello.ticket,
            new_session_entry_secret,
        })
    }

    fn handle_client_hello(&mut self) -> Result<bool> {
        if self.recv_buf.len() < CLIENT_HELLO_LEN {
            return Ok(false);
        }

        let hello_bytes: [u8; CLIENT_HELLO_LEN] =
            self.recv_buf[..CLIENT_HELLO_LEN].try_into().map_err(|_| {
                decode_error(
                    DecodeErrorKind::ClientHelloMalformed,
                    anyhow!("auth_akarin_v2 client hello length mismatch"),
                )
            })?;
        let hello = ClientHello::parse(&hello_bytes)
            .map_err(|err| decode_error(DecodeErrorKind::ClientHelloMalformed, err))?;
        let known_user = self.select_user_key(hello.user_id);
        if !self.register_handshake_replay(&hello_bytes) {
            return decode_result(
                DecodeErrorKind::Replay,
                anyhow!("auth_akarin_v2 handshake replay detected"),
            );
        }

        let prepared = self.prepare_server_hello(&hello)?;

        self.registry_deferred = known_user;
        self.client_id = hello.client_id;
        self.connection_id = hello.connection_id;
        self.client_overhead = hello.client_overhead.max(1);
        self.peer_tcp_mss = hello.tcp_mss.clamp(MIN_TCP_MSS, MAX_TCP_MSS);
        self.unit_len = MAX_FRAME_PLAIN_LEN;
        self.pending_handshake_commit = known_user.then_some(PendingHandshakeCommit {
            ticket: prepared.ticket,
            new_session_entry_secret: prepared.new_session_entry_secret,
        });
        self.pending_server_hello = Some(prepared.encoded);
        self.recv_buf.consume(CLIENT_HELLO_LEN);
        Ok(true)
    }

    fn ensure_registry_inserted(&mut self) -> Result<()> {
        if self.registry_inserted || !self.registry_deferred {
            return Ok(());
        }

        let reg_user = self.registry_user_id()?;
        if !self
            .shared_registry
            .insert(reg_user, self.client_id, self.connection_id)
        {
            return decode_result(
                DecodeErrorKind::DuplicateClient,
                anyhow!("auth_akarin_v2 duplicate client connection tuple"),
            );
        }

        self.registry_inserted = true;
        self.registry_deferred = false;
        self.next_registry_refresh_at = Some(Instant::now() + REGISTRY_ACTIVITY_REFRESH_INTERVAL);
        Ok(())
    }

    fn commit_pending_handshake(&mut self) -> Result<()> {
        let Some(pending) = self.pending_handshake_commit.take() else {
            return Ok(());
        };

        // A resume has nothing to commit: validation already refreshed the
        // presented ticket immediately before registry insertion.
        if let Some(resumption_secret) = pending.new_session_entry_secret {
            self.session_tickets.insert(
                pending.ticket,
                self.build_v2_session_entry(resumption_secret),
            );
        }

        Ok(())
    }

    fn validate_pending_resume_ticket(&self) -> Result<()> {
        let Some(pending) = self.pending_handshake_commit.as_ref() else {
            return Ok(());
        };
        if pending.new_session_entry_secret.is_some() {
            return Ok(());
        }
        if !self.session_tickets.touch(&pending.ticket) {
            return decode_result(
                DecodeErrorKind::UnknownTicket,
                anyhow!("auth_akarin_v2 session ticket expired before client confirmation"),
            );
        }
        Ok(())
    }

    fn ensure_frame_counter_window(counter: u32) -> Result<()> {
        if counter > u32::MAX - COUNTER_WINDOW {
            return decode_result(
                DecodeErrorKind::StateInvalid,
                anyhow!("auth_akarin_v2 frame counter exhausted"),
            );
        }
        Ok(())
    }

    fn choose_pad_len(
        &mut self,
        payload_len: usize,
        metadata_len: usize,
        counter: u32,
    ) -> Result<(usize, u8)> {
        self.ensure_shape_profile()?;
        let Some(profile) = &self.shape_profile else {
            return Ok((0, 0));
        };

        let effective_mss = min(self.tcp_mss, self.peer_tcp_mss).clamp(MIN_TCP_MSS, MAX_TCP_MSS);
        let min_wire = payload_len + metadata_len + FRAME_WIRE_OVERHEAD;
        if min_wire >= effective_mss as usize {
            return Ok((0, 0));
        }

        let mut choice_data = [0_u8; 16];
        choice_data[0..4].copy_from_slice(&counter.to_le_bytes());
        choice_data[4..8].copy_from_slice(&(payload_len as u32).to_le_bytes());
        choice_data[8..16].copy_from_slice(&profile.epoch.to_le_bytes());
        let choice = profile.pad_mac.mac(&choice_data);

        let candidate_count = profile
            .bins()
            .iter()
            .filter(|bin| {
                let bin = **bin as usize;
                bin >= min_wire && bin <= effective_mss as usize
            })
            .count();

        if candidate_count == 0 {
            let span = effective_mss as usize - min_wire;
            let pad_len = ((choice[0] as usize) % (span.min(96) + 1)).min(span);
            return Ok((pad_len, 0));
        }

        let total_weight = candidate_count * (candidate_count + 1) / 2;
        let selector = u64::from_le_bytes(choice[0..8].try_into().unwrap()) as usize % total_weight;
        let mut cursor = 0_usize;
        let mut seen = 0_usize;
        let mut picked = None;
        for (idx, bin) in profile.bins().iter().copied().enumerate() {
            let bin_usize = bin as usize;
            if bin_usize < min_wire || bin_usize > effective_mss as usize {
                continue;
            }
            let weight = candidate_count - seen;
            cursor += weight;
            if selector < cursor {
                picked = Some((idx, bin));
                break;
            }
            seen += 1;
        }
        let (shape_class, target) = picked.expect("candidate selection must succeed");
        Ok((target as usize - min_wire, shape_class as u8))
    }

    fn encode_frame_into(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        Self::ensure_frame_counter_window(self.tx_counter)?;
        let ticket_rotation = self.prepare_ticket_rotation()?;
        let key_update = self.prepare_key_update()?;
        let metadata_len = usize::from(ticket_rotation.is_some()) * TICKET_ROTATION_METADATA_LEN
            + usize::from(key_update.is_some()) * KEY_UPDATE_SALT_LEN;
        let (pad_len, shape_class) =
            self.choose_pad_len(payload.len(), metadata_len, self.tx_counter)?;
        let cipher = self
            .tx_cipher
            .as_ref()
            .ok_or_else(|| anyhow!("auth_akarin_v2 tx cipher is not initialized"))?;
        let len_key = self
            .tx_len_key
            .as_ref()
            .ok_or_else(|| anyhow!("auth_akarin_v2 tx length key is not initialized"))?;
        let payload_len = u16::try_from(payload.len()).map_err(|_| anyhow!("payload too large"))?;
        let pad_len_u16 = u16::try_from(pad_len).map_err(|_| anyhow!("padding too large"))?;
        let metadata_len_u16 =
            u16::try_from(metadata_len).map_err(|_| anyhow!("metadata length too large"))?;

        let mut header_plain = [0_u8; FRAME_HEADER_LEN];
        header_plain[0..2].copy_from_slice(&payload_len.to_le_bytes());
        header_plain[2..4].copy_from_slice(&pad_len_u16.to_le_bytes());
        let mut flags = 0_u8;
        if ticket_rotation.is_some() {
            flags |= SERVER_FRAME_FLAG_TICKET_UPDATE;
        }
        if key_update.is_some() {
            flags |= SERVER_FRAME_FLAG_KEY_UPDATE;
        }
        header_plain[4] = flags;
        header_plain[5] = shape_class;
        header_plain[6..8].copy_from_slice(&metadata_len_u16.to_le_bytes());

        let body_plain_len = FRAME_HEADER_LEN + metadata_len + payload.len() + pad_len;
        let body_cipher_len = body_plain_len + FRAME_TAG_LEN;
        let masked_len = encode_frame_len(
            &len_key.cipher,
            &self.tx_nonce_prefix,
            self.tx_counter,
            body_cipher_len,
        )?;
        let body_nonce = frame_nonce(&self.tx_nonce_prefix, self.tx_counter);
        let body_aad = frame_aad(self.tx_counter, &masked_len);

        let out_start = out.len();
        out.reserve(FRAME_OUTER_LEN + body_plain_len + FRAME_TAG_LEN);
        out.extend_from_slice(&masked_len);
        let body_start = out.len();
        out.extend_from_slice(&header_plain);
        if let Some(rotation) = ticket_rotation {
            out.extend_from_slice(&rotation.next_ticket);
            out.extend_from_slice(&rotation.resumption_secret);
        }
        if let Some(update) = key_update {
            out.extend_from_slice(&update.salt);
        }
        out.extend_from_slice(payload);
        if pad_len > 0 {
            out.resize(out.len() + pad_len, 0);
        }

        let body_tag = match cipher.encrypt_detached(
            &body_nonce,
            &body_aad,
            &mut out[body_start..body_start + body_plain_len],
        ) {
            Ok(tag) => tag,
            Err(err) => {
                out.truncate(out_start);
                return Err(err);
            }
        };
        self.tx_counter += COUNTER_WINDOW;
        out.extend_from_slice(&body_tag);
        if let Some(update) = key_update {
            self.activate_pending_key_update(update)?;
        }
        Ok(())
    }

    fn decode_frames(&mut self, out_buf: &mut Vec<u8>) -> Result<()> {
        loop {
            if self.recv_buf.len() < FRAME_OUTER_LEN {
                break;
            }
            Self::ensure_frame_counter_window(self.rx_counter)?;
            let cipher = self.rx_cipher.as_ref().ok_or_else(|| {
                decode_error(
                    DecodeErrorKind::StateInvalid,
                    anyhow!("auth_akarin_v2 rx cipher is not initialized"),
                )
            })?;
            let len_key = self.rx_len_key.as_ref().ok_or_else(|| {
                decode_error(
                    DecodeErrorKind::StateInvalid,
                    anyhow!("auth_akarin_v2 rx length key is not initialized"),
                )
            })?;
            let masked_len: [u8; FRAME_OUTER_LEN] =
                self.recv_buf[..FRAME_OUTER_LEN].try_into().map_err(|_| {
                    decode_error(
                        DecodeErrorKind::FrameMalformed,
                        anyhow!("auth_akarin_v2 frame length field mismatch"),
                    )
                })?;
            let body_cipher_len = decode_frame_len(
                &len_key.cipher,
                &self.rx_nonce_prefix,
                self.rx_counter,
                &masked_len,
            );
            if body_cipher_len < FRAME_HEADER_LEN + FRAME_TAG_LEN {
                return decode_result(
                    DecodeErrorKind::FrameMalformed,
                    anyhow!("auth_akarin_v2 frame body is too short"),
                );
            }
            let max_body_cipher_len = FRAME_HEADER_LEN + MAX_FRAME_PLAIN_LEN + FRAME_TAG_LEN;
            if body_cipher_len > max_body_cipher_len {
                return decode_result(
                    DecodeErrorKind::PacketSize,
                    anyhow!("auth_akarin_v2 frame exceeds maximum plain length"),
                );
            }
            let frame_len = FRAME_OUTER_LEN + body_cipher_len;
            if self.recv_buf.len() < frame_len {
                break;
            }

            let body_nonce = frame_nonce(&self.rx_nonce_prefix, self.rx_counter);
            let body_cipher_end = frame_len - FRAME_TAG_LEN;
            let body_tag: [u8; FRAME_TAG_LEN] = self.recv_buf[body_cipher_end..frame_len]
                .try_into()
                .map_err(|_| {
                    decode_error(
                        DecodeErrorKind::FrameMalformed,
                        anyhow!("auth_akarin_v2 frame body tag length mismatch"),
                    )
                })?;
            let body_aad = frame_aad(self.rx_counter, &masked_len);
            {
                let recv_slice = self.recv_buf.as_mut_slice();
                let body_cipher = &mut recv_slice[FRAME_OUTER_LEN..body_cipher_end];
                cipher
                    .decrypt_detached(&body_nonce, &body_aad, body_cipher, &body_tag)
                    .map_err(|err| decode_error(DecodeErrorKind::FrameAuthFailed, err))?;
            }

            let (payload_len, payload_start) = {
                let body_plain = &self.recv_buf[FRAME_OUTER_LEN..body_cipher_end];
                let header_plain: [u8; FRAME_HEADER_LEN] =
                    body_plain[..FRAME_HEADER_LEN].try_into().map_err(|_| {
                        decode_error(
                            DecodeErrorKind::FrameMalformed,
                            anyhow!("auth_akarin_v2 frame inner header length mismatch"),
                        )
                    })?;
                if header_plain[4] != 0 {
                    return decode_result(
                        DecodeErrorKind::FrameMalformed,
                        anyhow!("auth_akarin_v2 client frame flags must be zero"),
                    );
                }

                let payload_len =
                    u16::from_le_bytes(header_plain[0..2].try_into().unwrap()) as usize;
                let pad_len = u16::from_le_bytes(header_plain[2..4].try_into().unwrap()) as usize;
                let metadata_len =
                    u16::from_le_bytes(header_plain[6..8].try_into().unwrap()) as usize;
                if metadata_len != 0 {
                    return decode_result(
                        DecodeErrorKind::FrameMalformed,
                        anyhow!("auth_akarin_v2 client frame metadata must be empty"),
                    );
                }
                let body_plain_len = metadata_len + payload_len + pad_len;
                if body_plain_len > MAX_FRAME_PLAIN_LEN {
                    return decode_result(
                        DecodeErrorKind::PacketSize,
                        anyhow!("auth_akarin_v2 frame exceeds maximum plain length"),
                    );
                }
                if body_plain.len() != FRAME_HEADER_LEN + body_plain_len {
                    return decode_result(
                        DecodeErrorKind::FrameMalformed,
                        anyhow!("auth_akarin_v2 frame body length mismatch"),
                    );
                }
                out_buf.reserve(payload_len);
                (payload_len, FRAME_HEADER_LEN + metadata_len)
            };
            self.validate_pending_resume_ticket()?;
            self.ensure_registry_inserted()?;
            self.commit_pending_handshake()?;
            let body_plain = &self.recv_buf[FRAME_OUTER_LEN..body_cipher_end];
            out_buf.extend_from_slice(&body_plain[payload_start..payload_start + payload_len]);
            self.recv_buf.consume(frame_len);
            self.rx_counter += COUNTER_WINDOW;
        }

        Ok(())
    }

    fn decode_buffered(&mut self, out: &mut Vec<u8>) -> Result<bool> {
        out.clear();
        let mut sendback = false;

        if self.pending_server_hello.is_none() && self.tx_key.is_none() {
            if self.handle_client_hello()? {
                sendback = true;
            } else {
                return Ok(false);
            }
        }

        self.decode_frames(out)?;
        if !out.is_empty() {
            self.maybe_refresh_registry_activity()?;
        }
        Ok(sendback)
    }

    fn maybe_refresh_registry_activity(&mut self) -> Result<()> {
        if !self.registry_inserted {
            return Ok(());
        }
        let Some(next_refresh_at) = self.next_registry_refresh_at else {
            return Ok(());
        };
        let now = Instant::now();
        if now < next_refresh_at {
            return Ok(());
        }
        let reg_user = self.registry_user_id()?;
        self.shared_registry.update(reg_user, self.client_id);
        self.next_registry_refresh_at = Some(now + REGISTRY_ACTIVITY_REFRESH_INTERVAL);
        Ok(())
    }
}

impl TcpServerSession {
    /// Feeds bytes read from the client and appends every authenticated
    /// payload byte to `out` (after clearing it).
    ///
    /// Returns `true` when this input completed the client hello: a server
    /// hello is now pending and the caller must call [`encode`](Self::encode)
    /// (with an empty input if it has nothing else to send) and write the
    /// result, even if `out` is empty. Errors carry a [`DecodeErrorKind`].
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        self.recv_buf.extend_from_slice(input);
        self.decode_buffered(out)
    }

    /// Like [`decode`](Self::decode), but may take over `input`'s allocation
    /// instead of copying it; `input` is left empty for the caller to reuse.
    pub fn decode_owned(&mut self, input: &mut Vec<u8>, out: &mut Vec<u8>) -> Result<bool> {
        self.recv_buf.append_owned(input);
        self.decode_buffered(out)
    }

    /// Encodes `input` for the client into `out` (after clearing it), led by
    /// the pending server hello if there is one. Report the write outcome
    /// through [`on_flushed`](Self::on_flushed).
    pub fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        if let Some(hello) = self.pending_server_hello.take() {
            out.extend_from_slice(&hello);
        }
        if input.is_empty() {
            return Ok(());
        }

        let mut start = 0;
        while start < input.len() {
            let metadata_len = self.pending_control_metadata_len();
            self.unit_len = MAX_FRAME_PLAIN_LEN.saturating_sub(metadata_len).max(1);
            let end = start + self.unit_len.min(input.len() - start);
            self.encode_frame_into(&input[start..end], out)?;
            start = end;
        }
        Ok(())
    }

    /// Replaces the configured MSS with the one the accepted socket reports,
    /// which then drives traffic shaping. `0` selects the default.
    pub fn set_tcp_mss(&mut self, tcp_mss: u16) {
        self.tcp_mss = normalize_tcp_mss(tcp_mss);
        self.unit_len = MAX_FRAME_PLAIN_LEN;
    }

    /// Reports whether the bytes from the last [`encode`](Self::encode) or
    /// [`encode_control`](Self::encode_control) were fully written.
    ///
    /// A delivered write commits what that output staged: a rotated ticket
    /// joins the shared store and becomes this connection's ticket. A failed
    /// write commits nothing. Close the connection after a failed write: the
    /// client may have received any prefix of it, so the record counters can
    /// no longer be trusted to agree.
    pub fn on_flushed(&mut self, delivered: bool) -> Result<()> {
        if !delivered {
            self.pending_handshake_commit = None;
            self.pending_ticket_rotation = None;
            self.pending_key_update = None;
            if let Some(rollback) = self.key_update_rollback.take() {
                self.install_tx_key_state(rollback);
            }
            return Ok(());
        }
        if let Some(pending) = self.pending_ticket_rotation.take() {
            self.session_tickets
                .insert(pending.next_ticket, pending.next_entry);
            self.current_ticket = Some(pending.next_ticket);
        }
        if self.key_update_rollback.take().is_some() {
            self.next_key_update_at = Some(Instant::now() + self.key_update_interval);
        }
        Ok(())
    }

    /// When the session next wants to send a control frame (ticket rotation
    /// or key update) even if the relay has no payload. At that instant call
    /// [`encode_control`](Self::encode_control).
    pub fn next_control_deadline(&self) -> Option<Instant> {
        if self.pending_handshake_commit.is_some() {
            return None;
        }
        let ticket_deadline = self.current_ticket.and_then(|ticket| {
            self.session_tickets
                .rotation_deadline(&ticket, self.ticket_rotation_interval)
        });
        if self.master_secret.is_none() {
            return ticket_deadline;
        }
        match (ticket_deadline, self.next_key_update_at) {
            (Some(ticket), Some(key)) => Some(ticket.min(key)),
            (Some(ticket), None) => Some(ticket),
            (None, key) => key,
        }
    }

    /// Writes a payload-free control frame into `out` if one is due and
    /// returns whether it did. Report the write through
    /// [`on_flushed`](Self::on_flushed) like any other output.
    pub fn encode_control(&mut self, out: &mut Vec<u8>) -> Result<bool> {
        out.clear();
        if self.pending_server_hello.is_some()
            || self.pending_handshake_commit.is_some()
            || self.pending_control_metadata_len() == 0
        {
            return Ok(false);
        }
        self.encode_frame_into(&[], out)?;
        Ok(true)
    }
}

impl Drop for TcpServerSession {
    // Releases this connection's slot in the per-user client registry, which
    // otherwise keeps counting it against `max_client`.
    fn drop(&mut self) {
        if self.registry_inserted
            && let Some(reg_user) = self.registry_user_id_for_dispose()
        {
            self.shared_registry.remove(reg_user, self.client_id);
        }
    }
}

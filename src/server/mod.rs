//! The server side: shared state plus per-connection TCP sessions and the UDP
//! datagram codec.

mod state;
mod tcp;
mod udp;

use crate::method::Method;
use crate::udp_wire::normalize_v2_udp_packet_size;
use crate::wire::normalize_tcp_mss;
use anyhow::{Result, bail};
use rand::{RngExt, rng};
use state::{SharedReplaySet, SharedSessionTicketStore, SharedUserRegistry};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

pub use tcp::TcpServerSession;
pub use udp::{UdpClientPacket, UdpSendPlan, UdpServer, UdpSession};

/// Server settings. [`ServerConfig::new`] fills in the defaults the protocol
/// was designed around; adjust fields afterwards as needed.
#[derive(Clone)]
pub struct ServerConfig {
    pub method: Method,
    /// The protocol password. With no `users` it is every client's key.
    ///
    /// With `users` it is a master credential: unknown user ids are answered
    /// under a decoy key `HMAC-SHA256(password, method || 0xff || uid)`, so
    /// a prober without the password learns nothing about which ids exist.
    /// Whoever knows the password can derive that decoy key and complete a
    /// TCP handshake under any unknown id; such a session gets no ticket and
    /// is not counted against `max_client`. Keep it at least as secret as
    /// the user keys.
    pub password: Vec<u8>,
    /// Per-user keys by user id. Empty means single-user mode.
    pub users: HashMap<u32, Vec<u8>>,
    /// How many distinct client ids each user may hold at once.
    pub max_client: usize,
    /// How long a TCP client hello is remembered for replay rejection. The
    /// hello carries no timestamp, so a recorded one is accepted again once
    /// it has been forgotten (after this window, or earlier if the filter is
    /// full and evicts it).
    pub tcp_replay_window: Duration,
    /// Fallback TCP MSS used for traffic shaping until
    /// [`TcpServerSession::set_tcp_mss`] supplies the socket's. `0` selects
    /// 1460; other values are clamped to `500..=1500`.
    pub tcp_mss: u16,
    /// Largest UDP datagram this server advertises. `0` selects 1232; other
    /// values are clamped to `576..=1500`.
    pub udp_packet_size: u16,
    /// Lifetime of a resumption ticket from issuance. Tickets rotate, and TCP
    /// send keys update, at half this lifetime.
    pub ticket_lifetime: Duration,
    /// Most tickets kept at once; the least recently used are evicted first.
    pub ticket_capacity: usize,
    /// Most entries kept by each replay filter; when full, the oldest entry
    /// is evicted.
    pub replay_capacity: usize,
}

impl fmt::Debug for ServerConfig {
    // Keys stay out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("method", &self.method)
            .field("password", &"<redacted>")
            .field("users", &self.users.keys().collect::<Vec<_>>())
            .field("max_client", &self.max_client)
            .field("tcp_replay_window", &self.tcp_replay_window)
            .field("tcp_mss", &self.tcp_mss)
            .field("udp_packet_size", &self.udp_packet_size)
            .field("ticket_lifetime", &self.ticket_lifetime)
            .field("ticket_capacity", &self.ticket_capacity)
            .field("replay_capacity", &self.replay_capacity)
            .finish()
    }
}

impl ServerConfig {
    pub const DEFAULT_MAX_CLIENT: usize = 64;
    pub const DEFAULT_TCP_REPLAY_WINDOW: Duration = Duration::from_secs(300);
    pub const DEFAULT_TICKET_LIFETIME: Duration = Duration::from_secs(1800);
    pub const DEFAULT_TICKET_CAPACITY: usize = 1 << 20;
    pub const DEFAULT_REPLAY_CAPACITY: usize = 1 << 20;

    pub fn new(method: Method, password: impl Into<Vec<u8>>) -> Self {
        Self {
            method,
            password: password.into(),
            users: HashMap::new(),
            max_client: Self::DEFAULT_MAX_CLIENT,
            tcp_replay_window: Self::DEFAULT_TCP_REPLAY_WINDOW,
            tcp_mss: 0,
            udp_packet_size: 0,
            ticket_lifetime: Self::DEFAULT_TICKET_LIFETIME,
            ticket_capacity: Self::DEFAULT_TICKET_CAPACITY,
            replay_capacity: Self::DEFAULT_REPLAY_CAPACITY,
        }
    }
}

/// State shared by every connection a server accepts. Cloning is cheap and
/// clones share that state.
///
/// TCP and UDP must come from the same `Server`: a ticket issued over one
/// transport resumes over the other only because they share the ticket store.
#[derive(Clone)]
pub struct Server {
    method: Method,
    password: Arc<[u8]>,
    users: Arc<HashMap<u32, Vec<u8>>>,
    tcp_mss: u16,
    session_tickets: SharedSessionTicketStore,
    registry: SharedUserRegistry,
    tcp_replays: SharedReplaySet,
    udp: UdpServer,
}

impl Server {
    pub fn new(config: ServerConfig) -> Result<Self> {
        if config.max_client == 0 {
            bail!("max_client must be positive");
        }
        if config.tcp_replay_window.is_zero() {
            bail!("tcp_replay_window must be positive");
        }
        // Rotation needs the predecessor and its successor alive together.
        if config.ticket_capacity < 2 {
            bail!("ticket_capacity must be at least 2");
        }
        if config.ticket_lifetime.is_zero() {
            bail!("ticket_lifetime must be positive");
        }
        if config.replay_capacity == 0 {
            bail!("replay_capacity must be positive");
        }

        let users = Arc::new(config.users);
        let session_tickets =
            SharedSessionTicketStore::with_capacity(config.ticket_lifetime, config.ticket_capacity);
        let udp = UdpServer::new(
            config.method,
            &config.password,
            users.clone(),
            normalize_v2_udp_packet_size(config.udp_packet_size),
            session_tickets.clone(),
            config.replay_capacity,
        );
        Ok(Self {
            method: config.method,
            password: config.password.into(),
            users,
            tcp_mss: normalize_tcp_mss(config.tcp_mss),
            session_tickets,
            registry: SharedUserRegistry::new(config.max_client),
            tcp_replays: SharedReplaySet::with_capacity(
                config.tcp_replay_window,
                config.replay_capacity,
            ),
            udp,
        })
    }

    /// A session for one newly accepted TCP connection.
    pub fn tcp_session(&self) -> TcpServerSession {
        TcpServerSession::new(self)
    }

    /// The codec for the server's UDP socket. It is shared state, not
    /// per-association: every datagram from every client goes through it.
    pub fn udp(&self) -> &UdpServer {
        &self.udp
    }
}

const SESSION_TOKEN_RAW_LEN: usize = 10;
const SESSION_TOKEN_LEN: usize = 16;
// Every symbol has at most two bits set, so a ticket on the wire is a run of
// low-weight bytes rather than uniformly random ones.
const SESSION_TOKEN_ALPHABET: [u8; 32] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x03, 0x05, 0x06, 0x09, 0x0a, 0x0c, 0x11, 0x12,
    0x14, 0x18, 0x21, 0x22, 0x24, 0x28, 0x30, 0x41, 0x42, 0x44, 0x48, 0x50, 0x60, 0x81, 0x82, 0x84,
];

fn encode_opaque_resume_token(raw: &[u8; SESSION_TOKEN_RAW_LEN]) -> [u8; SESSION_TOKEN_LEN] {
    let mut out = [0_u8; SESSION_TOKEN_LEN];
    let mut buffer = 0_u32;
    let mut bits = 0_usize;
    let mut out_idx = 0_usize;

    for &byte in raw {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let alphabet_idx = ((buffer >> bits) & 0x1f) as usize;
            out[out_idx] = SESSION_TOKEN_ALPHABET[alphabet_idx];
            out_idx += 1;
        }
    }

    debug_assert_eq!(bits, 0, "80 input bits should align to 16 base32 symbols");
    debug_assert_eq!(
        out_idx, SESSION_TOKEN_LEN,
        "opaque token encoding should fill the wire-sized token"
    );
    out
}

/// A fresh 16-byte resumption ticket carrying 80 random bits.
fn generate_opaque_session_ticket() -> [u8; SESSION_TOKEN_LEN] {
    let mut raw = [0_u8; SESSION_TOKEN_RAW_LEN];
    rng().fill(&mut raw);
    encode_opaque_resume_token(&raw)
}

#[cfg(test)]
mod tests {
    use super::{
        SESSION_TOKEN_ALPHABET, encode_opaque_resume_token, generate_opaque_session_ticket,
    };

    #[test]
    fn opaque_ticket_uses_only_low_weight_symbols() {
        for _ in 0..64 {
            let ticket = generate_opaque_session_ticket();
            assert!(
                ticket
                    .iter()
                    .all(|byte| SESSION_TOKEN_ALPHABET.contains(byte))
            );
        }
    }

    #[test]
    fn opaque_ticket_encoding_is_injective_on_distinct_inputs() {
        let a = encode_opaque_resume_token(&[0_u8; 10]);
        let mut raw = [0_u8; 10];
        raw[9] = 1;
        let b = encode_opaque_resume_token(&raw);
        assert_ne!(a, b);
        assert_eq!(a, [SESSION_TOKEN_ALPHABET[0]; 16]);
    }
}

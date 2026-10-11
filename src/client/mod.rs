//! The client side: shared identity and ticket cache plus per-connection TCP
//! sessions and per-association UDP sessions.

mod tcp;
mod udp;

use crate::method::Method;
use crate::udp_wire::normalize_v2_udp_packet_size;
use crate::wire::normalize_tcp_mss;
use parking_lot::Mutex;
use rand::{RngExt, rng};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub use tcp::TcpClientSession;
pub use udp::{UdpClientSession, UdpEncodeResult};

/// Client settings. [`ClientConfig::new`] fills in the defaults.
#[derive(Clone)]
pub struct ClientConfig {
    pub method: Method,
    /// The protocol password, used as the key when `user` is `None`.
    pub password: Vec<u8>,
    /// For a multi-user server: this client's user id and that user's key.
    pub user: Option<(u32, Vec<u8>)>,
    /// TCP MSS advertised to the server for its traffic shaping. `0` selects
    /// 1460; other values are clamped to `500..=1500`.
    pub tcp_mss: u16,
    /// Largest UDP datagram this client sends or accepts. `0` selects 1232;
    /// other values are clamped to `576..=1500`.
    pub udp_packet_size: u16,
    /// Carried in the TCP client hello and bound into its transcript for
    /// compatibility with existing peers; it does not affect framing.
    pub overhead: u16,
}

impl fmt::Debug for ClientConfig {
    // Keys stay out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("method", &self.method)
            .field("password", &"<redacted>")
            .field("user", &self.user.as_ref().map(|(uid, _)| uid))
            .field("tcp_mss", &self.tcp_mss)
            .field("udp_packet_size", &self.udp_packet_size)
            .field("overhead", &self.overhead)
            .finish()
    }
}

impl ClientConfig {
    pub const DEFAULT_OVERHEAD: u16 = 4;

    pub fn new(method: Method, password: impl Into<Vec<u8>>) -> Self {
        Self {
            method,
            password: password.into(),
            user: None,
            tcp_mss: 0,
            udp_packet_size: 0,
            overhead: Self::DEFAULT_OVERHEAD,
        }
    }
}

/// State shared by every connection a client makes. Cloning is cheap and
/// clones share that state.
///
/// Create TCP and UDP sessions from the same `Client`: they share one ticket
/// cache, so a ticket from any handshake resumes TCP and lets UDP skip its
/// bootstrap.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    method: Method,
    user_id: Option<u32>,
    user_key: Vec<u8>,
    tcp_mss: u16,
    udp_packet_size: u16,
    overhead: u16,
    // The server admits a bounded window of connection ids per (user,
    // client id) and rejects reuse, so one client id with an increasing
    // connection id is what lets many concurrent connections through.
    client_id: u32,
    next_connection_id: AtomicU32,
    tickets: TicketCache,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        let (user_id, user_key) = match config.user {
            Some((uid, key)) => (Some(uid), key),
            None => (None, config.password),
        };
        Self {
            inner: Arc::new(ClientInner {
                method: config.method,
                user_id,
                user_key,
                tcp_mss: normalize_tcp_mss(config.tcp_mss),
                udp_packet_size: normalize_v2_udp_packet_size(config.udp_packet_size),
                overhead: config.overhead.max(1),
                client_id: random_nonzero_u32(),
                next_connection_id: AtomicU32::new(random_nonzero_u32()),
                tickets: TicketCache::default(),
            }),
        }
    }

    /// A session for one new TCP connection.
    pub fn tcp_session(&self) -> TcpClientSession {
        TcpClientSession::new(self, self.next_connection_id())
    }

    /// A session for one UDP association (one local socket to the server).
    pub fn udp_session(&self) -> UdpClientSession {
        UdpClientSession::new(self)
    }

    fn next_connection_id(&self) -> u32 {
        loop {
            let id = self
                .inner
                .next_connection_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.wrapping_add(1).max(1))
                })
                .expect("connection id update never declines");
            if id != 0 {
                return id;
            }
        }
    }
}

fn random_nonzero_u32() -> u32 {
    rng().random::<u32>().max(1)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedTicket {
    ticket: [u8; 16],
    ticket_secret: [u8; 32],
    peer_udp_packet_size: u16,
    // Set once some transport proves this exact ticket is still recognized by the peer.
    // Belongs to the entry, not the cache: replacing the entry always starts unconfirmed.
    confirmed: bool,
}

/// The resumption ticket every session of one [`Client`] shares. Sessions
/// poll `revision` (one atomic load) and reload only when it moved.
#[derive(Default)]
struct TicketCache {
    inner: Mutex<Option<CachedTicket>>,
    revision: AtomicU64,
}

impl TicketCache {
    fn load(&self) -> Option<CachedTicket> {
        self.inner.lock().clone()
    }

    fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    fn publish_fresh(&self, ticket: [u8; 16], ticket_secret: [u8; 32], peer_udp_packet_size: u16) {
        *self.inner.lock() = Some(CachedTicket {
            ticket,
            ticket_secret,
            peer_udp_packet_size,
            confirmed: false,
        });
        self.revision.fetch_add(1, Ordering::AcqRel);
    }

    /// Moves the cache to a rotated successor, but only if it still holds
    /// `expected_ticket`: a late rotation must not roll back a newer ticket
    /// another session already published.
    fn advance(
        &self,
        expected_ticket: &[u8; 16],
        ticket: [u8; 16],
        ticket_secret: [u8; 32],
    ) -> bool {
        let mut inner = self.inner.lock();
        let Some(current) = inner.as_ref() else {
            return false;
        };
        if current.ticket != *expected_ticket {
            return false;
        }
        let peer_udp_packet_size = current.peer_udp_packet_size;
        *inner = Some(CachedTicket {
            ticket,
            ticket_secret,
            peer_udp_packet_size,
            confirmed: false,
        });
        self.revision.fetch_add(1, Ordering::AcqRel);
        true
    }

    fn discard(&self, rejected_ticket: &[u8; 16]) -> bool {
        let mut inner = self.inner.lock();
        let Some(ticket) = inner.as_ref() else {
            return false;
        };
        if ticket.ticket != *rejected_ticket {
            return false;
        }
        *inner = None;
        self.revision.fetch_add(1, Ordering::AcqRel);
        true
    }

    // Ticket liveness is a property of the ticket, not of whichever association happened to
    // prove it first: recording it here means every other association sharing this cache
    // stops probing it too. A mismatch (the cache has since moved on) is silently ignored, same
    // as a losing `advance`/`discard` race.
    fn confirm(&self, ticket: &[u8; 16]) {
        let mut inner = self.inner.lock();
        if let Some(current) = inner.as_mut()
            && current.ticket == *ticket
        {
            current.confirmed = true;
        }
    }

    fn is_confirmed(&self, ticket: &[u8; 16]) -> bool {
        self.inner
            .lock()
            .as_ref()
            .is_some_and(|current| current.ticket == *ticket && current.confirmed)
    }
}

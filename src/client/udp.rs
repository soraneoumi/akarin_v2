use crate::client::{Client, ClientInner, TicketCache};
use crate::crypto::Aes128GcmCipher;
use crate::now_secs_u32;
use crate::udp_wire::{
    UDP_V2_BOOTSTRAP_RESP_LEN, UDP_V2_BOOTSTRAP_RESP_TYPE, UDP_V2_BOOTSTRAP_TYPE,
    UDP_V2_DATA_FLAG_FRAGMENT, UDP_V2_DATA_FLAG_TICKET_UPDATE, UDP_V2_DATA_HEADER_LEN,
    UDP_V2_DATA_TYPE, UDP_V2_FRAGMENT_META_LEN, UDP_V2_FRAGMENT_TIMEOUT_SECS,
    UDP_V2_MAX_PACKET_SIZE, UDP_V2_MAX_PLAIN_LEN, UDP_V2_META_LEN, UDP_V2_PROTOCOL_VERSION,
    UDP_V2_TICKET_ID_LEN, UDP_V2_TICKET_UPDATE_LEN, UdpV2BootstrapTranscript,
    bootstrap_transcript_hash, derive_v2_udp_confirm_tag, derive_v2_udp_epoch_key,
    derive_v2_udp_master_secret, normalize_v2_udp_packet_size, udp_password_scalar,
};
use crate::wire::{derive_resumption_secret, random_scalar, spake_point};
use anyhow::{Result, anyhow, bail};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::{RngExt, rng};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

const UDP_V2_FRAGMENT_MAX_ENTRIES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpV2FragmentKey {
    ticket: [u8; 16],
    fragment_id: u32,
}

#[derive(Clone, Copy)]
struct UdpV2FragmentMeta {
    fragment_id: u32,
    offset: usize,
    total_len: usize,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpV2FragmentSlot(NonZeroU32);

impl UdpV2FragmentSlot {
    const MAX_CAPACITY: usize = u32::MAX as usize;

    fn from_index(index: usize) -> Self {
        let raw = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .expect("udp v2 fragment slot index exceeds its u32 representation");
        Self(NonZeroU32::new(raw).expect("fragment slot IDs start at one"))
    }

    fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

struct UdpV2FragmentAssembly {
    total_len: usize,
    received_len: usize,
    data: Vec<u8>,
    received: Vec<bool>,
}

impl UdpV2FragmentAssembly {
    fn new(total_len: usize) -> Self {
        Self {
            total_len,
            received_len: 0,
            data: vec![0_u8; total_len],
            received: vec![false; total_len],
        }
    }

    fn insert(&mut self, offset: usize, fragment: &[u8]) -> Result<bool> {
        let end = offset
            .checked_add(fragment.len())
            .ok_or_else(|| anyhow!("udp v2 fragment offset overflow"))?;
        if end > self.total_len {
            bail!("udp v2 fragment exceeds total length");
        }
        let received = &self.received[offset..end];
        if !received.iter().any(|received| *received) {
            self.data[offset..end].copy_from_slice(fragment);
            self.received[offset..end].fill(true);
            self.received_len += fragment.len();
            return Ok(self.received_len == self.total_len);
        }

        // An overlap must be completely checked before changing the assembly.
        // Otherwise a conflicting tail could leave a valid in-flight response
        // partly overwritten and impossible to complete on a later retry.
        for (idx, byte) in fragment.iter().copied().enumerate() {
            let pos = offset + idx;
            if self.received[pos] && self.data[pos] != byte {
                bail!("udp v2 fragment overlap mismatch");
            }
        }
        self.data[offset..end].copy_from_slice(fragment);
        for received in &mut self.received[offset..end] {
            if !*received {
                *received = true;
                self.received_len += 1;
            }
        }
        Ok(self.received_len == self.total_len)
    }
}

struct UdpV2FragmentNode {
    key: UdpV2FragmentKey,
    deadline: Instant,
    assembly: UdpV2FragmentAssembly,
    prev: Option<UdpV2FragmentSlot>,
    next: Option<UdpV2FragmentSlot>,
}

// Fragments have a fixed lifetime from their first packet and this protocol is
// driven through one mutable instance, so creation order is also deadline order.
// A linked FIFO lets expiry and pressure eviction touch only the oldest live
// assembly instead of scanning every hash entry on every received fragment.
struct UdpV2FragmentCache {
    index: HashMap<UdpV2FragmentKey, UdpV2FragmentSlot>,
    slots: Vec<Option<UdpV2FragmentNode>>,
    free_slots: Vec<UdpV2FragmentSlot>,
    head: Option<UdpV2FragmentSlot>,
    tail: Option<UdpV2FragmentSlot>,
    capacity: usize,
}

impl UdpV2FragmentCache {
    fn new(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "udp v2 fragment cache needs a positive capacity"
        );
        assert!(
            capacity <= UdpV2FragmentSlot::MAX_CAPACITY,
            "udp v2 fragment cache capacity exceeds its u32 slot representation"
        );
        Self {
            index: HashMap::with_capacity(capacity),
            slots: Vec::with_capacity(capacity),
            free_slots: Vec::with_capacity(capacity),
            head: None,
            tail: None,
            capacity,
        }
    }

    fn reassemble(
        &mut self,
        ticket: [u8; 16],
        meta: UdpV2FragmentMeta,
        fragment: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>> {
        if meta.total_len == 0 || meta.total_len > UDP_V2_MAX_PLAIN_LEN || fragment.is_empty() {
            bail!("udp v2 fragment length is invalid");
        }
        let end = meta
            .offset
            .checked_add(fragment.len())
            .ok_or_else(|| anyhow!("udp v2 fragment offset overflow"))?;
        if end > meta.total_len {
            bail!("udp v2 fragment exceeds total length");
        }
        let key = UdpV2FragmentKey {
            ticket,
            fragment_id: meta.fragment_id,
        };

        // Invalid ranges above must not mutate the cache. A valid packet may
        // clean up expired work before it looks for its own assembly.
        self.evict_expired(now);
        if let Some(&slot) = self.index.get(&key) {
            let complete = {
                let node = self.slot_mut(slot);
                if node.assembly.total_len != meta.total_len {
                    bail!("udp v2 fragment total length mismatch");
                }
                node.assembly.insert(meta.offset, fragment)?
            };
            return if complete {
                Ok(self.remove_slot(slot).assembly.data)
            } else {
                Ok(Vec::new())
            };
        }

        // A complete one-packet response needs neither a cache entry nor an
        // eviction. Existing keys were handled above so this cannot hide a
        // total-length collision with an in-flight assembly.
        if meta.offset == 0 && end == meta.total_len {
            return Ok(fragment.to_vec());
        }

        if self.index.len() == self.capacity {
            let oldest = self
                .head
                .expect("full udp v2 fragment cache must have a FIFO head");
            self.remove_slot(oldest);
        }

        let mut assembly = UdpV2FragmentAssembly::new(meta.total_len);
        let complete = assembly.insert(meta.offset, fragment)?;
        debug_assert!(!complete, "one fragment should have returned directly");
        self.insert(key, now, assembly);
        Ok(Vec::new())
    }

    fn evict_expired(&mut self, now: Instant) {
        while let Some(slot) = self.head {
            if self.slot(slot).deadline >= now {
                break;
            }
            self.remove_slot(slot);
        }
    }

    fn insert(
        &mut self,
        key: UdpV2FragmentKey,
        created_at: Instant,
        assembly: UdpV2FragmentAssembly,
    ) {
        debug_assert!(self.index.len() < self.capacity);
        let slot = match self.free_slots.pop() {
            Some(slot) => {
                debug_assert!(self.slots[slot.index()].is_none());
                slot
            }
            None => {
                let index = self.slots.len();
                debug_assert!(index < self.capacity);
                self.slots.push(None);
                UdpV2FragmentSlot::from_index(index)
            }
        };
        let previous_tail = self.tail;
        let deadline = created_at
            .checked_add(Duration::from_secs(UDP_V2_FRAGMENT_TIMEOUT_SECS))
            .expect("udp v2 fragment deadline overflow");
        self.slots[slot.index()] = Some(UdpV2FragmentNode {
            key,
            deadline,
            assembly,
            prev: previous_tail,
            next: None,
        });
        if let Some(previous_tail) = previous_tail {
            self.slot_mut(previous_tail).next = Some(slot);
        } else {
            self.head = Some(slot);
        }
        self.tail = Some(slot);
        let old = self.index.insert(key, slot);
        debug_assert!(old.is_none());
    }

    fn remove_slot(&mut self, slot: UdpV2FragmentSlot) -> UdpV2FragmentNode {
        let node = self.slots[slot.index()]
            .take()
            .expect("udp v2 fragment FIFO points at a live slot");
        let removed = self.index.remove(&node.key);
        debug_assert_eq!(removed, Some(slot));
        if let Some(prev) = node.prev {
            self.slot_mut(prev).next = node.next;
        } else {
            self.head = node.next;
        }
        if let Some(next) = node.next {
            self.slot_mut(next).prev = node.prev;
        } else {
            self.tail = node.prev;
        }
        self.free_slots.push(slot);
        node
    }

    fn slot(&self, slot: UdpV2FragmentSlot) -> &UdpV2FragmentNode {
        self.slots[slot.index()]
            .as_ref()
            .expect("udp v2 fragment index points at a live slot")
    }

    fn slot_mut(&mut self, slot: UdpV2FragmentSlot) -> &mut UdpV2FragmentNode {
        self.slots[slot.index()]
            .as_mut()
            .expect("udp v2 fragment index points at a live slot")
    }
}

/// What [`UdpClientSession::encode`] produced.
#[derive(Debug)]
pub enum UdpEncodeResult {
    /// One datagram to send: a data packet, or a bootstrap request when the
    /// session had no ticket yet (the payload then waits for the response).
    Packet(Vec<u8>),
    /// The fragments of one payload too large for a single datagram.
    Packets(Vec<Vec<u8>>),
    /// Nothing to send now: the payload is too large to carry, or a
    /// bootstrap is already in flight (the newest payload replaces the one
    /// waiting on it).
    Drop,
}

// Valid only for the exact (epoch, ticket_secret) pair it was derived from; either
// changing (epoch rollover, ticket rotation) requires rebuilding the whole bundle.
struct EpochCipher {
    epoch: u64,
    ticket_secret: [u8; 32],
    cipher: Aes128GcmCipher,
}

/// Client side of one UDP association.
///
/// Without a ticket the first [`encode`](Self::encode) returns a bootstrap
/// request and holds the payload; pass the server's answer (recognized by
/// [`is_bootstrap_response`](Self::is_bootstrap_response)) to
/// [`handle_bootstrap_response`](Self::handle_bootstrap_response), send what
/// it returns, and report that send through
/// [`on_bootstrap_data_sent`](Self::on_bootstrap_data_sent). With a ticket
/// from the shared cache, data flows at once (0-RTT).
pub struct UdpClientSession {
    client: Arc<ClientInner>,
    method: &'static str,
    user_id: Option<u32>,
    spec_time_interval: Option<u64>,
    v2_client_scalar: Option<Scalar>,
    v2_client_seed: Option<[u8; 4]>,
    v2_client_nonce: Option<[u8; 16]>,
    v2_client_share: Option<[u8; 32]>,
    v2_ticket: Option<[u8; 16]>,
    v2_ticket_secret: Option<[u8; 32]>,
    v2_previous_ticket: Option<([u8; 16], [u8; 32])>,
    // A negotiated ticket is proven live by the confirmation tag (bootstrap) or the AEAD tag
    // (rotation) that delivered it. One loaded from `V2TicketCache` carries neither proof: it
    // may be a leftover from an earlier session the peer has since forgotten. Only the cached
    // case needs the liveness probe.
    v2_ticket_from_cache: bool,
    udp_packet_size: u16,
    peer_udp_packet_size: u16,
    pending_plain: Option<Vec<u8>>,
    v2_fragments: UdpV2FragmentCache,
    v2_next_fragment_id: u32,
    v2_ticket_cache_revision: u64,
    pending_bootstrap_ticket_publish: Option<([u8; 16], [u8; 32], u16)>,
    v2_send_epoch_cipher: Option<EpochCipher>,
    v2_recv_epoch_cipher: Option<EpochCipher>,
    v2_decode_scratch: Vec<u8>,
    last_authenticated_v2_response_ticket: Option<[u8; 16]>,
}

impl UdpClientSession {
    pub(crate) fn new(client: &Client) -> Self {
        let shared = client.inner.clone();
        let mut fragment_seed = [0_u8; 4];
        rng().fill(&mut fragment_seed);

        let mut protocol = Self {
            method: shared.method.label(),
            user_id: shared.user_id,
            spec_time_interval: shared.method.spec_time_interval(),
            v2_client_scalar: None,
            v2_client_seed: None,
            v2_client_nonce: None,
            v2_client_share: None,
            v2_ticket: None,
            v2_ticket_secret: None,
            v2_previous_ticket: None,
            v2_ticket_from_cache: false,
            udp_packet_size: shared.udp_packet_size,
            peer_udp_packet_size: UDP_V2_MAX_PACKET_SIZE,
            pending_plain: None,
            v2_fragments: UdpV2FragmentCache::new(UDP_V2_FRAGMENT_MAX_ENTRIES),
            v2_next_fragment_id: u32::from_le_bytes(fragment_seed),
            v2_ticket_cache_revision: u64::MAX,
            pending_bootstrap_ticket_publish: None,
            v2_send_epoch_cipher: None,
            v2_recv_epoch_cipher: None,
            v2_decode_scratch: Vec::new(),
            last_authenticated_v2_response_ticket: None,
            client: shared,
        };
        protocol.sync_v2_ticket_cache();
        protocol
    }

    fn tickets(&self) -> &TicketCache {
        &self.client.tickets
    }

    /// Whether the session holds a ticket, so `encode` emits data packets
    /// rather than a bootstrap request.
    pub fn has_ticket(&self) -> bool {
        self.v2_ticket.is_some() && self.v2_ticket_secret.is_some()
    }

    /// A ticket loaded from the shared cache that nobody has yet proven the
    /// server still knows (a server restart forgets tickets, and UDP gets no
    /// rejection). A host that sees no authenticated reply to data sent
    /// under it should call [`discard_ticket`](Self::discard_ticket) and
    /// [`forget_ticket`](Self::forget_ticket) so the next payload bootstraps.
    pub fn probe_ticket_candidate(&self) -> Option<[u8; 16]> {
        let ticket = self
            .v2_ticket_from_cache
            .then_some(self.v2_ticket)
            .flatten()?;
        // The cache is shared across every association using this ticket; once any of them
        // has proven it live, none of the others need to spend a probe round trip on it too.
        if self.tickets().is_confirmed(&ticket) {
            return None;
        }
        Some(ticket)
    }

    /// The ticket the last successfully decoded reply was authenticated
    /// under, consumed by this call.
    pub fn take_authenticated_response_ticket(&mut self) -> Option<[u8; 16]> {
        self.last_authenticated_v2_response_ticket.take()
    }

    /// Drops `ticket` from the cache shared with every other session, if it
    /// is still the cached one. Returns whether it was dropped.
    pub fn discard_ticket(&self, ticket: &[u8; 16]) -> bool {
        self.tickets().discard(ticket)
    }

    /// Forgets this session's ticket so the next payload bootstraps afresh.
    ///
    /// Only ticket state is reset: a ticket the server no longer knows says
    /// nothing about the transport, so the host keeps its socket and any
    /// outer layer as they are.
    pub fn forget_ticket(&mut self) {
        self.v2_ticket = None;
        self.v2_ticket_secret = None;
        self.v2_ticket_from_cache = false;
        self.v2_previous_ticket = None;
        self.v2_send_epoch_cipher = None;
        self.v2_recv_epoch_cipher = None;
    }

    /// Encodes one inner datagram. `inner_packet_budget` further caps each
    /// datagram, for hosts whose outer layer adds bytes.
    pub fn encode(
        &mut self,
        plain: &[u8],
        inner_packet_budget: Option<usize>,
    ) -> Result<UdpEncodeResult> {
        // Revision is an atomic fast path; lock and derived-key resets happen only when the
        // shared TCP/UDP ticket identity changed.
        self.sync_v2_ticket_cache();
        if plain.len() > UDP_V2_MAX_PLAIN_LEN {
            return Ok(UdpEncodeResult::Drop);
        }
        if self.v2_ticket.is_none() {
            if self.pending_plain.is_some() {
                // A bootstrap is already awaiting its response. Building
                // another one per packet costs a SPAKE2 exchange each time
                // and, worse, replaces the client scalar the outstanding
                // one was built with, so the response to it can no longer
                // be validated. Keep the newest payload and wait; the
                // caller retries on a timer with a fresh bootstrap.
                self.pending_plain = Some(plain.to_vec());
                return Ok(UdpEncodeResult::Drop);
            }
            let bootstrap = self.build_v2_bootstrap()?;
            self.pending_plain = Some(plain.to_vec());
            return Ok(UdpEncodeResult::Packet(bootstrap));
        }
        self.encode_v2_data_packets(plain, inner_packet_budget)
    }

    /// Verifies the server's bootstrap response and, if a payload was waiting
    /// on it, returns that payload encoded under the new ticket.
    pub fn handle_bootstrap_response(
        &mut self,
        response: &[u8],
        inner_packet_budget: Option<usize>,
    ) -> Result<Option<UdpEncodeResult>> {
        self.parse_v2_bootstrap_response(response)?;
        let Some(plain) = self.pending_plain.take() else {
            return Ok(None);
        };
        Ok(Some(
            self.encode_v2_data_packets(&plain, inner_packet_budget)?,
        ))
    }

    /// Whether a server datagram is a bootstrap response rather than data.
    pub fn is_bootstrap_response(&self, packet: &[u8]) -> bool {
        packet.first().copied() == Some(UDP_V2_BOOTSTRAP_RESP_TYPE)
    }

    /// Decodes one datagram from the server. An empty result means nothing
    /// to deliver yet (a fragment of a larger datagram, or a bootstrap
    /// response, which belongs to
    /// [`handle_bootstrap_response`](Self::handle_bootstrap_response)).
    pub fn decode(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.last_authenticated_v2_response_ticket = None;
        if self.is_bootstrap_response(input) {
            return Ok(Vec::new());
        }
        self.decode_v2_data_packet(input)
    }

    fn current_epoch_bucket(&self) -> u64 {
        if let Some(interval) = self.spec_time_interval {
            return (now_secs_u32() as u64) / interval;
        }
        0
    }

    fn sync_v2_ticket_cache(&mut self) {
        let revision = self.tickets().revision();
        if revision == self.v2_ticket_cache_revision {
            return;
        }
        self.v2_ticket_cache_revision = revision;
        let Some(cached) = self.tickets().load() else {
            self.v2_ticket = None;
            self.v2_ticket_secret = None;
            self.v2_previous_ticket = None;
            self.peer_udp_packet_size = UDP_V2_MAX_PACKET_SIZE;
            self.v2_send_epoch_cipher = None;
            self.v2_recv_epoch_cipher = None;
            return;
        };
        let changed_ticket = self.v2_ticket != Some(cached.ticket)
            || self.v2_ticket_secret != Some(cached.ticket_secret);
        if changed_ticket {
            if let (Some(ticket), Some(secret)) = (self.v2_ticket, self.v2_ticket_secret)
                && ticket != cached.ticket
            {
                self.v2_previous_ticket = Some((ticket, secret));
            }
            self.v2_ticket = Some(cached.ticket);
            self.v2_ticket_secret = Some(cached.ticket_secret);
            self.v2_ticket_from_cache = true;
            self.v2_send_epoch_cipher = None;
            self.v2_recv_epoch_cipher = None;
        }
        self.peer_udp_packet_size = self.udp_packet_size.min(cached.peer_udp_packet_size);
    }

    fn publish_v2_ticket_cache(
        &self,
        ticket: [u8; 16],
        ticket_secret: [u8; 32],
        peer_udp_packet_size: u16,
    ) {
        self.tickets().publish_fresh(
            ticket,
            ticket_secret,
            self.udp_packet_size.min(peer_udp_packet_size),
        );
        // Same reasoning as the tcp side: this ticket arrived in a
        // bootstrap response whose confirmation tag was verified, and it is
        // only published once the first packet under it was delivered.
        self.tickets().confirm(&ticket);
    }

    fn advance_v2_ticket_cache(
        &self,
        expected_ticket: [u8; 16],
        ticket: [u8; 16],
        ticket_secret: [u8; 32],
    ) -> bool {
        self.tickets()
            .advance(&expected_ticket, ticket, ticket_secret)
    }

    fn v2_data_payload_capacity(
        &self,
        fragment: bool,
        inner_packet_budget: Option<usize>,
    ) -> Option<usize> {
        let negotiated_packet_size = self.udp_packet_size.min(self.peer_udp_packet_size) as usize;
        let packet_size = inner_packet_budget
            .map(|budget| budget.min(negotiated_packet_size))
            .unwrap_or(negotiated_packet_size);
        let metadata_len = UDP_V2_META_LEN
            + if fragment {
                UDP_V2_FRAGMENT_META_LEN
            } else {
                0
            };
        packet_size.checked_sub(UDP_V2_DATA_HEADER_LEN + metadata_len + 16)
    }

    fn next_v2_fragment_id(&mut self) -> u32 {
        let id = self.v2_next_fragment_id;
        self.v2_next_fragment_id = self.v2_next_fragment_id.wrapping_add(1);
        id
    }

    fn build_v2_bootstrap(&mut self) -> Result<Vec<u8>> {
        let user_id_field = self.user_id.unwrap_or(0);
        let password_scalar =
            udp_password_scalar(&self.client.user_key, self.method, self.user_id)?;
        let client_scalar = random_scalar();
        let client_share = (RISTRETTO_BASEPOINT_POINT * client_scalar
            + spake_point(b"M") * password_scalar)
            .compress()
            .to_bytes();
        let mut client_seed = [0_u8; 4];
        let mut client_nonce = [0_u8; 16];
        rng().fill(&mut client_seed);
        rng().fill(&mut client_nonce);
        let mut out = Vec::with_capacity(60);
        out.push(UDP_V2_BOOTSTRAP_TYPE);
        out.push(UDP_V2_PROTOCOL_VERSION);
        out.extend_from_slice(&self.udp_packet_size.to_le_bytes());
        out.extend_from_slice(&client_seed);
        out.extend_from_slice(&user_id_field.to_le_bytes());
        out.extend_from_slice(&client_nonce);
        out.extend_from_slice(&client_share);
        self.v2_client_scalar = Some(client_scalar);
        self.v2_client_seed = Some(client_seed);
        self.v2_client_nonce = Some(client_nonce);
        self.v2_client_share = Some(client_share);
        Ok(out)
    }

    fn parse_v2_bootstrap_response(&mut self, response: &[u8]) -> Result<()> {
        if response.len() != UDP_V2_BOOTSTRAP_RESP_LEN {
            bail!("udp v2 bootstrap response length mismatch");
        }
        if response[0] != UDP_V2_BOOTSTRAP_RESP_TYPE {
            bail!("udp v2 bootstrap response type/version mismatch");
        }
        if response[1] != UDP_V2_PROTOCOL_VERSION {
            bail!("udp v2 bootstrap response type/version mismatch");
        }
        let server_udp_packet_size =
            normalize_v2_udp_packet_size(u16::from_le_bytes([response[2], response[3]]));
        let server_seed: [u8; 12] = response[4..16].try_into().unwrap();
        let ticket: [u8; 16] = response[16..32].try_into().unwrap();
        let server_nonce: [u8; 16] = response[32..48].try_into().unwrap();
        let server_share: [u8; 32] = response[48..80].try_into().unwrap();
        let tag: [u8; 16] = response[80..96].try_into().unwrap();

        let server_share_point = CompressedRistretto(server_share)
            .decompress()
            .ok_or_else(|| anyhow!("invalid udp v2 server share point"))?;
        let password_scalar =
            udp_password_scalar(&self.client.user_key, self.method, self.user_id)?;
        let client_scalar = self
            .v2_client_scalar
            .ok_or_else(|| anyhow!("udp v2 bootstrap state missing client scalar"))?;
        let shared_point =
            (server_share_point - spake_point(b"N") * password_scalar) * client_scalar;
        let client_seed = self
            .v2_client_seed
            .ok_or_else(|| anyhow!("udp v2 bootstrap state missing client seed"))?;
        let client_nonce = self
            .v2_client_nonce
            .ok_or_else(|| anyhow!("udp v2 bootstrap state missing client nonce"))?;
        let client_share = self
            .v2_client_share
            .ok_or_else(|| anyhow!("udp v2 bootstrap state missing client share"))?;
        let transcript = UdpV2BootstrapTranscript {
            client_udp_packet_size: self.udp_packet_size,
            server_udp_packet_size,
            user_id_field: self.user_id.unwrap_or(0),
            selected_user_id: self.user_id,
            client_seed,
            client_nonce: &client_nonce,
            client_share: &client_share,
            server_seed,
            ticket: &ticket,
            server_nonce: &server_nonce,
            server_share: &server_share,
        };
        let transcript_hash = bootstrap_transcript_hash(self.method, &transcript);
        let master_secret = derive_v2_udp_master_secret(&shared_point, &transcript_hash)?;
        let expected_tag = derive_v2_udp_confirm_tag(&master_secret, &transcript_hash)?;
        if expected_tag != tag {
            bail!("udp v2 bootstrap confirmation tag mismatch");
        }
        let ticket_secret = derive_resumption_secret(&master_secret, &transcript_hash)?;
        self.v2_ticket = Some(ticket);
        self.v2_ticket_secret = Some(ticket_secret);
        self.v2_ticket_from_cache = false;
        self.v2_previous_ticket = None;
        self.peer_udp_packet_size = self.udp_packet_size.min(server_udp_packet_size);
        self.pending_bootstrap_ticket_publish =
            Some((ticket, ticket_secret, self.peer_udp_packet_size));
        Ok(())
    }

    /// Whether a bootstrap has been emitted and is still waiting for its
    /// response.
    pub fn bootstrap_pending(&self) -> bool {
        self.pending_plain.is_some()
    }

    /// Gives up on the outstanding bootstrap and hands back the payload that
    /// was waiting on it, so re-encoding that payload builds a fresh one. A
    /// retry has to carry a new client scalar and nonce anyway: the server
    /// rejects a byte-identical bootstrap as a replay.
    pub fn take_pending_bootstrap_plain(&mut self) -> Option<Vec<u8>> {
        self.pending_plain.take()
    }

    /// Reports whether the data packets returned by
    /// [`handle_bootstrap_response`](Self::handle_bootstrap_response) were
    /// sent. The new ticket is shared with other sessions only once they
    /// were, matching the point at which the server commits it.
    pub fn on_bootstrap_data_sent(&mut self, delivered: bool) {
        let Some((ticket, ticket_secret, peer_udp_packet_size)) =
            self.pending_bootstrap_ticket_publish.take()
        else {
            return;
        };
        if delivered {
            // Publish at the same commit boundary as the server: only after the first
            // authenticated data packet is known to have been delivered.
            self.publish_v2_ticket_cache(ticket, ticket_secret, peer_udp_packet_size);
        } else if self.v2_ticket == Some(ticket) && self.v2_ticket_secret == Some(ticket_secret) {
            // The bootstrap data was not delivered, so this codec must not keep using a ticket
            // that was never committed to the shared cache. The next packet will re-sync or
            // bootstrap afresh.
            self.v2_ticket = None;
            self.v2_ticket_secret = None;
            self.v2_previous_ticket = None;
            self.peer_udp_packet_size = UDP_V2_MAX_PACKET_SIZE;
            self.v2_send_epoch_cipher = None;
            self.v2_recv_epoch_cipher = None;
        }
    }

    fn v2_send_cipher(&mut self, ticket_secret: &[u8; 32], epoch: u64) -> Result<&Aes128GcmCipher> {
        let fresh = matches!(
            &self.v2_send_epoch_cipher,
            Some(entry) if entry.epoch == epoch && &entry.ticket_secret == ticket_secret
        );
        if !fresh {
            let key = derive_v2_udp_epoch_key(self.method, ticket_secret, epoch, b"client")?;
            self.v2_send_epoch_cipher = Some(EpochCipher {
                epoch,
                ticket_secret: *ticket_secret,
                cipher: Aes128GcmCipher::new(&key),
            });
        }
        Ok(&self.v2_send_epoch_cipher.as_ref().unwrap().cipher)
    }

    fn encode_v2_data_packets(
        &mut self,
        plain: &[u8],
        inner_packet_budget: Option<usize>,
    ) -> Result<UdpEncodeResult> {
        let capacity = self
            .v2_data_payload_capacity(false, inner_packet_budget)
            .ok_or_else(|| anyhow!("udp v2 negotiated packet size is too small"))?;
        if plain.len() <= capacity {
            return Ok(UdpEncodeResult::Packet(self.encode_v2_data_packet(
                plain,
                None,
                inner_packet_budget,
            )?));
        }
        let fragment_capacity = self
            .v2_data_payload_capacity(true, inner_packet_budget)
            .ok_or_else(|| anyhow!("udp v2 negotiated packet size is too small"))?;
        if fragment_capacity == 0 {
            return Ok(UdpEncodeResult::Drop);
        }
        let fragment_id = self.next_v2_fragment_id();
        let total_len = plain.len();
        let mut packets = Vec::with_capacity(total_len.div_ceil(fragment_capacity));
        let mut offset = 0_usize;
        while offset < total_len {
            let end = (offset + fragment_capacity).min(total_len);
            let meta = UdpV2FragmentMeta {
                fragment_id,
                offset,
                total_len,
            };
            packets.push(self.encode_v2_data_packet(
                &plain[offset..end],
                Some(meta),
                inner_packet_budget,
            )?);
            offset = end;
        }
        Ok(UdpEncodeResult::Packets(packets))
    }

    fn encode_v2_data_packet(
        &mut self,
        plain: &[u8],
        fragment: Option<UdpV2FragmentMeta>,
        inner_packet_budget: Option<usize>,
    ) -> Result<Vec<u8>> {
        let ticket = self
            .v2_ticket
            .ok_or_else(|| anyhow!("udp v2 ticket is missing"))?;
        let ticket_secret = self
            .v2_ticket_secret
            .ok_or_else(|| anyhow!("udp v2 ticket secret is missing"))?;
        let epoch = self.current_epoch_bucket();
        let mut nonce = [0_u8; 12];
        rng().fill(&mut nonce);
        let negotiated_packet_size = self.udp_packet_size.min(self.peer_udp_packet_size) as usize;
        let packet_size = inner_packet_budget
            .map(|budget| budget.min(negotiated_packet_size))
            .unwrap_or(negotiated_packet_size);
        let metadata_len = UDP_V2_META_LEN
            + if fragment.is_some() {
                UDP_V2_FRAGMENT_META_LEN
            } else {
                0
            };
        let wire_len = UDP_V2_DATA_HEADER_LEN + metadata_len + plain.len() + 16;
        if wire_len > packet_size {
            bail!("udp v2 payload exceeds negotiated packet size");
        }
        let payload_len =
            u16::try_from(plain.len()).map_err(|_| anyhow!("udp v2 payload too large"))?;
        let mut out = Vec::with_capacity(wire_len);
        out.push(UDP_V2_DATA_TYPE);
        out.extend_from_slice(&ticket);
        out.extend_from_slice(&epoch.to_le_bytes());
        out.extend_from_slice(&nonce);
        let body_start = out.len();
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.push(if fragment.is_some() {
            UDP_V2_DATA_FLAG_FRAGMENT
        } else {
            0
        });
        out.push(0);
        if let Some(meta) = fragment {
            out.extend_from_slice(&meta.fragment_id.to_le_bytes());
            out.extend_from_slice(
                &u16::try_from(meta.offset)
                    .map_err(|_| anyhow!("udp v2 fragment offset too large"))?
                    .to_le_bytes(),
            );
            out.extend_from_slice(
                &u16::try_from(meta.total_len)
                    .map_err(|_| anyhow!("udp v2 fragment total length too large"))?
                    .to_le_bytes(),
            );
        }
        out.extend_from_slice(plain);
        let (header, body) = out.split_at_mut(body_start);
        let cipher = self.v2_send_cipher(&ticket_secret, epoch)?;
        let tag = cipher.encrypt_detached(&nonce, &header[..UDP_V2_DATA_HEADER_LEN], body)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn decode_v2_data_packet(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() <= UDP_V2_DATA_HEADER_LEN + 16 {
            bail!("udp v2 data packet too short");
        }
        if input[0] != UDP_V2_DATA_TYPE {
            bail!("unsupported udp v2 packet type {}", input[0]);
        }
        if input.len() > self.udp_packet_size.min(self.peer_udp_packet_size) as usize {
            bail!("udp v2 response exceeds negotiated packet size");
        }
        let ticket: [u8; 16] = input[1..17].try_into().unwrap();
        let (ticket_secret, is_current_ticket) = if Some(ticket) == self.v2_ticket {
            (
                self.v2_ticket_secret
                    .ok_or_else(|| anyhow!("udp v2 ticket secret is missing"))?,
                true,
            )
        } else if let Some((previous_ticket, previous_secret)) = self.v2_previous_ticket {
            if ticket != previous_ticket {
                bail!("udp v2 response ticket mismatch");
            }
            (previous_secret, false)
        } else {
            bail!("udp v2 response ticket mismatch");
        };
        let epoch = u64::from_le_bytes(input[17..25].try_into().unwrap());
        let nonce: [u8; 12] = input[25..37].try_into().unwrap();
        let tag_offset = input.len() - 16;
        let tag: [u8; 16] = input[tag_offset..].try_into().unwrap();

        self.v2_decode_scratch.clear();
        self.v2_decode_scratch
            .extend_from_slice(&input[UDP_V2_DATA_HEADER_LEN..tag_offset]);
        let fresh = matches!(
            &self.v2_recv_epoch_cipher,
            Some(entry) if entry.epoch == epoch && entry.ticket_secret == ticket_secret
        );
        if !fresh {
            let key = derive_v2_udp_epoch_key(self.method, &ticket_secret, epoch, b"server")?;
            self.v2_recv_epoch_cipher = Some(EpochCipher {
                epoch,
                ticket_secret,
                cipher: Aes128GcmCipher::new(&key),
            });
        }
        let cipher = &self.v2_recv_epoch_cipher.as_ref().unwrap().cipher;
        cipher.decrypt_detached(
            &nonce,
            &input[..UDP_V2_DATA_HEADER_LEN],
            self.v2_decode_scratch.as_mut_slice(),
            &tag,
        )?;
        let (payload_len, metadata_len, fragment, next_ticket_update) = {
            let decoded = &self.v2_decode_scratch;
            if decoded.len() < UDP_V2_META_LEN {
                bail!("udp v2 response metadata is truncated");
            }
            let payload_len = u16::from_le_bytes(decoded[0..2].try_into().unwrap()) as usize;
            let flags = decoded[2];
            if (flags & !(UDP_V2_DATA_FLAG_TICKET_UPDATE | UDP_V2_DATA_FLAG_FRAGMENT)) != 0 {
                bail!("udp v2 response has unknown flags");
            }
            if (flags & UDP_V2_DATA_FLAG_TICKET_UPDATE) != 0
                && (flags & UDP_V2_DATA_FLAG_FRAGMENT) != 0
            {
                bail!("udp v2 fragmented response cannot rotate ticket");
            }
            let mut metadata_len = UDP_V2_META_LEN;
            let mut next_ticket_update: Option<([u8; 16], [u8; 32])> = None;
            if (flags & UDP_V2_DATA_FLAG_TICKET_UPDATE) != 0 {
                let end = metadata_len + UDP_V2_TICKET_UPDATE_LEN;
                if decoded.len() < end {
                    bail!("udp v2 ticket update is truncated");
                }
                let next_ticket: [u8; 16] = decoded
                    [metadata_len..metadata_len + UDP_V2_TICKET_ID_LEN]
                    .try_into()
                    .unwrap();
                let next_secret: [u8; 32] = decoded[metadata_len + UDP_V2_TICKET_ID_LEN..end]
                    .try_into()
                    .unwrap();
                next_ticket_update = Some((next_ticket, next_secret));
                metadata_len = end;
            }
            let fragment = if (flags & UDP_V2_DATA_FLAG_FRAGMENT) != 0 {
                let end = metadata_len + UDP_V2_FRAGMENT_META_LEN;
                if decoded.len() < end {
                    bail!("udp v2 fragment metadata is truncated");
                }
                let meta = UdpV2FragmentMeta {
                    fragment_id: u32::from_le_bytes(
                        decoded[metadata_len..metadata_len + 4].try_into().unwrap(),
                    ),
                    offset: u16::from_le_bytes(
                        decoded[metadata_len + 4..metadata_len + 6]
                            .try_into()
                            .unwrap(),
                    ) as usize,
                    total_len: u16::from_le_bytes(
                        decoded[metadata_len + 6..metadata_len + 8]
                            .try_into()
                            .unwrap(),
                    ) as usize,
                };
                metadata_len = end;
                Some(meta)
            } else {
                None
            };
            if payload_len > UDP_V2_MAX_PLAIN_LEN || decoded.len() < metadata_len + payload_len {
                bail!("udp v2 response payload length is invalid");
            }
            (payload_len, metadata_len, fragment, next_ticket_update)
        };
        if let Some((next_ticket, next_secret)) = next_ticket_update {
            // A delayed predecessor response from an older server may carry a
            // superseded rotation. Its authenticated payload remains valid,
            // but only the current ticket may advance outbound state.
            if is_current_ticket {
                if next_ticket == ticket {
                    bail!("udp v2 ticket update did not advance the ticket");
                }
                if self.advance_v2_ticket_cache(ticket, next_ticket, next_secret) {
                    self.v2_previous_ticket = Some((ticket, ticket_secret));
                    self.v2_ticket = Some(next_ticket);
                    self.v2_ticket_secret = Some(next_secret);
                    self.v2_ticket_from_cache = false;
                    self.v2_ticket_cache_revision = self.tickets().revision();
                } else {
                    // A late rotation must not roll the shared identity back; sync the newer
                    // TCP/UDP publication before the next outbound datagram.
                    self.v2_ticket_cache_revision = u64::MAX;
                    self.sync_v2_ticket_cache();
                }
            }
        }
        if let Some(meta) = fragment {
            let payload = &self.v2_decode_scratch[metadata_len..metadata_len + payload_len];
            let result = self
                .v2_fragments
                .reassemble(ticket, meta, payload, Instant::now());
            if result.is_ok() {
                self.last_authenticated_v2_response_ticket = Some(ticket);
                self.tickets().confirm(&ticket);
            }
            return result;
        }
        let payload = self.v2_decode_scratch[metadata_len..metadata_len + payload_len].to_vec();
        self.last_authenticated_v2_response_ticket = Some(ticket);
        self.tickets().confirm(&ticket);
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble_test_fragment(
        cache: &mut UdpV2FragmentCache,
        ticket: u8,
        fragment_id: u32,
        offset: usize,
        total_len: usize,
        fragment: &[u8],
        now: std::time::Instant,
    ) -> Result<Vec<u8>> {
        cache.reassemble(
            [ticket; 16],
            UdpV2FragmentMeta {
                fragment_id,
                offset,
                total_len,
            },
            fragment,
            now,
        )
    }

    fn fragment_key(ticket: u8, fragment_id: u32) -> UdpV2FragmentKey {
        UdpV2FragmentKey {
            ticket: [ticket; 16],
            fragment_id,
        }
    }

    fn fifo_fragment_ids(cache: &UdpV2FragmentCache) -> Vec<u32> {
        let mut ids = Vec::new();
        let mut slot = cache.head;
        while let Some(current) = slot {
            let node = cache.slot(current);
            ids.push(node.key.fragment_id);
            slot = node.next;
        }
        ids
    }

    fn assert_fragment_cache_invariants(cache: &UdpV2FragmentCache) {
        assert!(cache.index.len() <= cache.capacity);
        let mut visited = vec![false; cache.slots.len()];
        let mut previous = None;
        let mut slot = cache.head;
        let mut live = 0;
        while let Some(current) = slot {
            let index = current.index();
            assert!(!visited[index], "FIFO must not contain a cycle");
            visited[index] = true;
            let node = cache.slot(current);
            assert_eq!(node.prev, previous);
            assert_eq!(cache.index.get(&node.key), Some(&current));
            previous = Some(current);
            slot = node.next;
            live += 1;
        }
        assert_eq!(cache.tail, previous);
        assert_eq!(live, cache.index.len());
        assert_eq!(
            live,
            cache.slots.iter().filter(|slot| slot.is_some()).count()
        );
        for (key, &slot) in &cache.index {
            assert!(visited[slot.index()], "index points outside the FIFO");
            assert_eq!(&cache.slot(slot).key, key);
        }

        let mut free = vec![false; cache.slots.len()];
        for &slot in &cache.free_slots {
            let index = slot.index();
            assert!(!free[index], "free slot listed twice");
            assert!(!visited[index], "free slot overlaps a live FIFO node");
            assert!(cache.slots[index].is_none());
            free[index] = true;
        }
        assert_eq!(live + cache.free_slots.len(), cache.slots.len());
    }

    #[test]
    fn udp_v2_fragment_slots_are_compact_and_cover_the_cache_limit() {
        assert_eq!(
            std::mem::size_of::<UdpV2FragmentSlot>(),
            std::mem::size_of::<u32>()
        );
        assert_eq!(
            std::mem::size_of::<Option<UdpV2FragmentSlot>>(),
            std::mem::size_of::<u32>()
        );
        const { assert!(UDP_V2_FRAGMENT_MAX_ENTRIES <= UdpV2FragmentSlot::MAX_CAPACITY) };
        assert_eq!(UdpV2FragmentSlot::from_index(0).index(), 0);
        assert_eq!(
            UdpV2FragmentSlot::from_index(UDP_V2_FRAGMENT_MAX_ENTRIES - 1).index(),
            UDP_V2_FRAGMENT_MAX_ENTRIES - 1
        );
    }

    #[test]
    fn udp_v2_fragment_cache_expires_only_fifo_head_after_deadline() {
        let start = std::time::Instant::now();
        let mut cache = UdpV2FragmentCache::new(3);
        reassemble_test_fragment(&mut cache, 1, 10, 0, 2, b"a", start).expect("first fragment");
        reassemble_test_fragment(
            &mut cache,
            1,
            11,
            0,
            2,
            b"b",
            start + std::time::Duration::from_secs(10),
        )
        .expect("second fragment");
        reassemble_test_fragment(
            &mut cache,
            1,
            10,
            0,
            2,
            b"a",
            start + std::time::Duration::from_secs(29),
        )
        .expect("duplicate does not renew the deadline");

        cache.evict_expired(start + std::time::Duration::from_secs(30));
        assert_eq!(fifo_fragment_ids(&cache), vec![10, 11]);
        cache.evict_expired(start + std::time::Duration::from_secs(31));
        assert_eq!(fifo_fragment_ids(&cache), vec![11]);
        assert_fragment_cache_invariants(&cache);
    }

    #[test]
    fn udp_v2_fragment_cache_removes_completed_head_middle_and_tail() {
        let start = std::time::Instant::now();
        let mut cache = UdpV2FragmentCache::new(4);
        for (fragment_id, byte) in [(1, b'a'), (2, b'c'), (3, b'e')] {
            reassemble_test_fragment(
                &mut cache,
                2,
                fragment_id,
                0,
                2,
                &[byte],
                start + std::time::Duration::from_secs(fragment_id as u64),
            )
            .expect("first piece");
        }

        assert_eq!(
            reassemble_test_fragment(
                &mut cache,
                2,
                2,
                1,
                2,
                b"d",
                start + std::time::Duration::from_secs(4),
            )
            .expect("middle"),
            b"cd"
        );
        assert_eq!(fifo_fragment_ids(&cache), vec![1, 3]);
        assert_fragment_cache_invariants(&cache);

        assert_eq!(
            reassemble_test_fragment(
                &mut cache,
                2,
                1,
                1,
                2,
                b"b",
                start + std::time::Duration::from_secs(5),
            )
            .expect("head"),
            b"ab"
        );
        assert_eq!(fifo_fragment_ids(&cache), vec![3]);
        assert_fragment_cache_invariants(&cache);

        assert_eq!(
            reassemble_test_fragment(
                &mut cache,
                2,
                3,
                1,
                2,
                b"f",
                start + std::time::Duration::from_secs(6),
            )
            .expect("tail"),
            b"ef"
        );
        assert!(cache.index.is_empty());
        assert_fragment_cache_invariants(&cache);
    }

    #[test]
    fn udp_v2_fragment_cache_capacity_evicts_only_oldest_assembly() {
        let start = std::time::Instant::now();
        let mut cache = UdpV2FragmentCache::new(2);
        reassemble_test_fragment(&mut cache, 3, 1, 0, 2, b"a", start).expect("first");
        reassemble_test_fragment(
            &mut cache,
            3,
            2,
            0,
            2,
            b"b",
            start + std::time::Duration::from_secs(1),
        )
        .expect("second");
        reassemble_test_fragment(
            &mut cache,
            3,
            3,
            0,
            2,
            b"c",
            start + std::time::Duration::from_secs(2),
        )
        .expect("third");

        assert_eq!(fifo_fragment_ids(&cache), vec![2, 3]);
        assert!(!cache.index.contains_key(&fragment_key(3, 1)));
        assert_eq!(
            reassemble_test_fragment(
                &mut cache,
                3,
                2,
                1,
                2,
                b"d",
                start + std::time::Duration::from_secs(3),
            )
            .expect("retained assembly completes"),
            b"bd"
        );
        assert_fragment_cache_invariants(&cache);
    }

    #[test]
    fn udp_v2_fragment_cache_reuses_bounded_slots_under_churn() {
        let start = std::time::Instant::now();
        let mut cache = UdpV2FragmentCache::new(2);
        for fragment_id in 0..256 {
            reassemble_test_fragment(
                &mut cache,
                4,
                fragment_id,
                0,
                2,
                b"x",
                start + std::time::Duration::from_millis(fragment_id as u64),
            )
            .expect("partial fragment");
            assert!(cache.slots.len() <= 2);
            assert_fragment_cache_invariants(&cache);
        }
        assert_eq!(fifo_fragment_ids(&cache), vec![254, 255]);
        assert_eq!(cache.slots.len(), 2);
    }

    #[test]
    fn udp_v2_fragment_cache_handles_out_of_order_duplicates_and_conflicts_atomically() {
        let start = std::time::Instant::now();
        let mut cache = UdpV2FragmentCache::new(2);
        assert!(
            reassemble_test_fragment(&mut cache, 5, 1, 2, 6, b"cd", start)
                .expect("out of order")
                .is_empty()
        );
        assert!(
            reassemble_test_fragment(&mut cache, 5, 1, 2, 6, b"cd", start)
                .expect("duplicate")
                .is_empty()
        );
        let slot = *cache
            .index
            .get(&fragment_key(5, 1))
            .expect("assembly remains present");
        assert_eq!(cache.slot(slot).assembly.received_len, 2);

        assert!(reassemble_test_fragment(&mut cache, 5, 1, 2, 6, b"cX", start).is_err());
        let node = cache.slot(slot);
        assert_eq!(&node.assembly.data[2..4], b"cd");
        assert_eq!(node.assembly.received_len, 2);
        assert!(reassemble_test_fragment(&mut cache, 5, 1, 2, 7, b"cd", start).is_err());

        assert!(
            reassemble_test_fragment(&mut cache, 5, 1, 0, 6, b"ab", start)
                .expect("prefix")
                .is_empty()
        );
        assert_eq!(
            reassemble_test_fragment(&mut cache, 5, 1, 4, 6, b"ef", start).expect("complete"),
            b"abcdef"
        );
        assert_fragment_cache_invariants(&cache);
    }

    #[test]
    fn udp_v2_fragment_cache_rejects_invalid_ranges_without_evicting_live_work() {
        let start = std::time::Instant::now();
        let mut cache = UdpV2FragmentCache::new(1);
        reassemble_test_fragment(&mut cache, 6, 1, 0, 2, b"a", start).expect("live work");

        assert!(reassemble_test_fragment(&mut cache, 6, 2, 3, 4, b"xy", start).is_err());
        assert!(cache.index.contains_key(&fragment_key(6, 1)));
        assert_eq!(
            reassemble_test_fragment(&mut cache, 6, 2, 0, 2, b"ok", start)
                .expect("one-packet response"),
            b"ok"
        );
        assert!(cache.index.contains_key(&fragment_key(6, 1)));
        assert_fragment_cache_invariants(&cache);
    }
}

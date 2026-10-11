use crate::crypto::{Aes128GcmCipher, hkdf_sha256_array, hmac_sha256};
use crate::error::{DecodeErrorKind, decode_error, decode_result};
use crate::method::Method;
use crate::now_secs_u32;
use crate::server::generate_opaque_session_ticket;
use crate::server::state::{SessionEntry, SharedSessionTicketStore, TimedReplaySet};
use crate::udp_wire::{
    UDP_V2_BOOTSTRAP_RESP_LEN, UDP_V2_BOOTSTRAP_RESP_TYPE, UDP_V2_BOOTSTRAP_TYPE,
    UDP_V2_DATA_FLAG_FRAGMENT, UDP_V2_DATA_FLAG_TICKET_UPDATE, UDP_V2_DATA_HEADER_LEN,
    UDP_V2_DATA_TYPE, UDP_V2_DEFAULT_PACKET_SIZE, UDP_V2_FRAGMENT_META_LEN,
    UDP_V2_FRAGMENT_TIMEOUT_SECS, UDP_V2_MAX_PLAIN_LEN, UDP_V2_META_LEN,
    UDP_V2_METHOD_LABEL_MAX_LEN, UDP_V2_PROTOCOL_VERSION, UDP_V2_TICKET_UPDATE_LEN,
    UdpV2BootstrapTranscript, bootstrap_transcript_hash, derive_v2_udp_confirm_tag,
    derive_v2_udp_epoch_key, derive_v2_udp_master_secret, normalize_v2_udp_packet_size,
    udp_password_scalar,
};
use crate::wire::{XorShift128Plus, derive_resumption_secret, random_scalar, spake_point};
use anyhow::{Result, anyhow, bail};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use parking_lot::Mutex;
use rand::{RngExt, rng};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

const UDP_V2_BOOTSTRAP_REQ_LEN: usize = 60;
const UDP_V2_FRAGMENT_MAX_ENTRIES: usize = 8192;
const UDP_V2_FRAGMENT_MAX_TICKET_BYTES: usize = UDP_V2_MAX_PLAIN_LEN * 32;
const UDP_V2_FRAGMENT_MAX_TOTAL_BYTES: usize = UDP_V2_MAX_PLAIN_LEN * 1024;
const UDP_V2_EPOCH_CIPHER_CACHE_MAX_ENTRIES: usize = 65536;
const UDP_V2_SHAPE_CACHE_MAX_ENTRIES: usize = 65536;

#[derive(Debug)]
struct UdpV2TicketRotation {
    next_ticket: [u8; 16],
    next_secret: [u8; 32],
    next_entry: SessionEntry,
    current_ticket_expires_at: Instant,
    committed: bool,
}

type SharedUdpV2TicketRotation = Arc<Mutex<UdpV2TicketRotation>>;
type SharedUdpV2TicketRotations = Arc<Mutex<HashMap<[u8; 16], SharedUdpV2TicketRotation>>>;

#[derive(Clone, Copy)]
struct UdpShapeProfile {
    seed: [u8; 32],
    bins: [u16; 8],
    len: usize,
}

struct UdpEpochCiphers {
    client: Aes128GcmCipher,
    server: Aes128GcmCipher,
}

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

struct UdpV2FragmentAssembly {
    total_len: usize,
    received_len: usize,
    data: Vec<u8>,
    received: Vec<bool>,
}

impl UdpV2FragmentAssembly {
    fn allocation_bytes_for(total_len: usize) -> Result<usize> {
        total_len
            .checked_mul(2)
            .ok_or_else(|| anyhow!("udp v2 fragment allocation size overflow"))
    }

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
        let covered = &self.received[offset..end];
        if !covered.iter().any(|received| *received) {
            // The usual fragmented-datagram path has disjoint ranges. Keep
            // that path in the slice primitives so it does not pay per-byte
            // branch and bounds-check overhead just to assemble a packet.
            self.data[offset..end].copy_from_slice(fragment);
            self.received[offset..end].fill(true);
            self.received_len += fragment.len();
            return Ok(self.received_len == self.total_len);
        }
        // Check the complete overlap before changing the assembly. A malformed
        // later byte must not leave a valid, still-live assembly half modified.
        for (idx, byte) in fragment.iter().copied().enumerate() {
            let pos = offset + idx;
            if self.received[pos] && self.data[pos] != byte {
                bail!("udp v2 fragment overlap mismatch");
            }
        }
        for (idx, byte) in fragment.iter().copied().enumerate() {
            let pos = offset + idx;
            if self.received[pos] {
                continue;
            }
            self.data[pos] = byte;
            self.received[pos] = true;
            self.received_len += 1;
        }
        Ok(self.received_len == self.total_len)
    }

    fn allocation_bytes(&self) -> usize {
        Self::allocation_bytes_for(self.total_len).expect("stored fragment allocation is valid")
    }
}

#[derive(Clone, Copy)]
struct UdpV2FragmentLimits {
    timeout_secs: u64,
    max_entries: usize,
    max_ticket_bytes: usize,
    max_total_bytes: usize,
}

impl Default for UdpV2FragmentLimits {
    fn default() -> Self {
        Self {
            timeout_secs: UDP_V2_FRAGMENT_TIMEOUT_SECS,
            max_entries: UDP_V2_FRAGMENT_MAX_ENTRIES,
            max_ticket_bytes: UDP_V2_FRAGMENT_MAX_TICKET_BYTES,
            max_total_bytes: UDP_V2_FRAGMENT_MAX_TOTAL_BYTES,
        }
    }
}

struct UdpV2FragmentCache {
    limits: UdpV2FragmentLimits,
    keys: HashMap<UdpV2FragmentKey, UdpV2FragmentSlotId>,
    slots: Vec<Option<UdpV2FragmentNode>>,
    free_slots: Vec<UdpV2FragmentSlotId>,
    tickets: HashMap<[u8; 16], UdpV2FragmentTicketState>,
    global_head: Option<UdpV2FragmentSlotId>,
    global_tail: Option<UdpV2FragmentSlotId>,
    total_bytes: usize,
}

/// A non-zero slot index lets links represent the absence of a neighbor with
/// `Option`, while preserving a compact, reusable index into `slots`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
struct UdpV2FragmentSlotId(NonZeroU32);

impl UdpV2FragmentSlotId {
    fn from_index(index: usize) -> Self {
        let encoded = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .expect("fragment slot index exceeds u32 capacity");
        Self(NonZeroU32::new(encoded).expect("fragment slot id must be non-zero"))
    }

    fn index(self) -> usize {
        usize::try_from(self.0.get() - 1).expect("fragment slot id exceeds usize capacity")
    }
}

struct UdpV2FragmentNode {
    key: UdpV2FragmentKey,
    deadline: Instant,
    assembly: UdpV2FragmentAssembly,
    global_prev: Option<UdpV2FragmentSlotId>,
    global_next: Option<UdpV2FragmentSlotId>,
    ticket_prev: Option<UdpV2FragmentSlotId>,
    ticket_next: Option<UdpV2FragmentSlotId>,
}

#[derive(Default)]
struct UdpV2FragmentTicketState {
    bytes: usize,
    head: Option<UdpV2FragmentSlotId>,
    tail: Option<UdpV2FragmentSlotId>,
}

enum UdpV2FragmentResult {
    Pending,
    Complete(Vec<u8>),
    Dropped,
}

impl UdpV2FragmentCache {
    fn new(limits: UdpV2FragmentLimits) -> Self {
        assert!(
            u32::try_from(limits.max_entries).is_ok(),
            "udp v2 fragment cache entry limit exceeds u32 slot capacity"
        );
        Self {
            limits,
            keys: HashMap::new(),
            slots: Vec::new(),
            free_slots: Vec::new(),
            tickets: HashMap::new(),
            global_head: None,
            global_tail: None,
            total_bytes: 0,
        }
    }

    fn insert_fragment(
        &mut self,
        key: UdpV2FragmentKey,
        meta: UdpV2FragmentMeta,
        fragment: &[u8],
        now: Instant,
    ) -> Result<UdpV2FragmentResult> {
        Self::validate_fragment(meta, fragment)?;
        self.expire(now);

        if let Some(slot) = self.keys.get(&key).copied() {
            let complete = {
                let node = self.node_mut(slot);
                if node.assembly.total_len != meta.total_len {
                    bail!("udp v2 fragment total length mismatch");
                }
                node.assembly.insert(meta.offset, fragment)?
            };
            if !complete {
                return Ok(UdpV2FragmentResult::Pending);
            }
            return Ok(UdpV2FragmentResult::Complete(self.remove_slot(slot).data));
        }

        let allocation_bytes = UdpV2FragmentAssembly::allocation_bytes_for(meta.total_len)?;
        if self.limits.max_entries == 0
            || allocation_bytes > self.limits.max_ticket_bytes
            || allocation_bytes > self.limits.max_total_bytes
        {
            // An assembly that can never fit must not evict live work only to
            // fail itself. Resource pressure is an ordinary UDP drop, not a
            // malformed packet and therefore must not trigger probe redirect.
            return Ok(UdpV2FragmentResult::Dropped);
        }

        if meta.offset == 0 && fragment.len() == meta.total_len {
            // A complete, single-fragment datagram has passed the same hard
            // limits as a cached assembly, but needs no cache reservation.
            return Ok(UdpV2FragmentResult::Complete(fragment.to_vec()));
        }

        self.evict_for_new_assembly(key.ticket, allocation_bytes);
        let mut assembly = UdpV2FragmentAssembly::new(meta.total_len);
        let complete = assembly.insert(meta.offset, fragment)?;
        debug_assert!(!complete, "complete fragments return without caching");
        self.insert_node(key, assembly, now, allocation_bytes);
        Ok(UdpV2FragmentResult::Pending)
    }

    fn validate_fragment(meta: UdpV2FragmentMeta, fragment: &[u8]) -> Result<()> {
        if meta.total_len == 0 || fragment.is_empty() {
            bail!("udp v2 fragment length is invalid");
        }
        let end = meta
            .offset
            .checked_add(fragment.len())
            .ok_or_else(|| anyhow!("udp v2 fragment offset overflow"))?;
        if end > meta.total_len {
            bail!("udp v2 fragment exceeds total length");
        }
        Ok(())
    }

    fn expire(&mut self, now: Instant) {
        // Every deadline is fixed at creation. Consequently, FIFO creation
        // order is deadline order and the first live node proves all later
        // nodes are live; no packet ever scans the full reassembly table.
        while let Some(slot) = self.global_head {
            if self.node(slot).deadline >= now {
                break;
            }
            self.remove_slot(slot);
        }
    }

    fn evict_for_new_assembly(&mut self, ticket: [u8; 16], allocation_bytes: usize) {
        while self
            .ticket_bytes(ticket)
            .checked_add(allocation_bytes)
            .is_none_or(|bytes| bytes > self.limits.max_ticket_bytes)
        {
            let slot = self
                .tickets
                .get(&ticket)
                .and_then(|state| state.head)
                .expect("ticket byte accounting without a ticket FIFO head");
            self.remove_slot(slot);
        }

        while self.keys.len() >= self.limits.max_entries
            || self
                .total_bytes
                .checked_add(allocation_bytes)
                .is_none_or(|bytes| bytes > self.limits.max_total_bytes)
        {
            let slot = self
                .global_head
                .expect("fragment capacity accounting without a global FIFO head");
            self.remove_slot(slot);
        }
    }

    fn insert_node(
        &mut self,
        key: UdpV2FragmentKey,
        assembly: UdpV2FragmentAssembly,
        now: Instant,
        allocation_bytes: usize,
    ) {
        let slot = self.free_slots.pop().unwrap_or_else(|| {
            debug_assert!(self.slots.len() < self.limits.max_entries);
            let slot = UdpV2FragmentSlotId::from_index(self.slots.len());
            self.slots.push(None);
            slot
        });
        let global_prev = self.global_tail;
        let deadline = now
            .checked_add(Duration::from_secs(self.limits.timeout_secs))
            .expect("udp v2 fragment deadline overflow");
        let ticket = self.tickets.entry(key.ticket).or_default();
        let ticket_prev = ticket.tail;
        if ticket_prev.is_none() {
            ticket.head = Some(slot);
        }
        ticket.tail = Some(slot);
        ticket.bytes = ticket
            .bytes
            .checked_add(allocation_bytes)
            .expect("fragment ticket byte accounting overflow");
        self.slots[slot.index()] = Some(UdpV2FragmentNode {
            key,
            deadline,
            assembly,
            global_prev,
            global_next: None,
            ticket_prev,
            ticket_next: None,
        });
        let previous = self.keys.insert(key, slot);
        debug_assert!(previous.is_none(), "new fragment key already has a slot");

        if let Some(previous) = global_prev {
            self.node_mut(previous).global_next = Some(slot);
        } else {
            self.global_head = Some(slot);
        }
        self.global_tail = Some(slot);

        if let Some(previous) = ticket_prev {
            self.node_mut(previous).ticket_next = Some(slot);
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(allocation_bytes)
            .expect("fragment total byte accounting overflow");
    }

    fn remove_slot(&mut self, slot: UdpV2FragmentSlotId) -> UdpV2FragmentAssembly {
        let node = self.slots[slot.index()]
            .take()
            .expect("fragment FIFO points at an empty slot");
        let removed = self.keys.remove(&node.key);
        debug_assert_eq!(
            removed,
            Some(slot),
            "fragment key index disagrees with slot"
        );

        if let Some(previous) = node.global_prev {
            self.node_mut(previous).global_next = node.global_next;
        } else {
            self.global_head = node.global_next;
        }
        if let Some(next) = node.global_next {
            self.node_mut(next).global_prev = node.global_prev;
        } else {
            self.global_tail = node.global_prev;
        }

        if let Some(previous) = node.ticket_prev {
            self.node_mut(previous).ticket_next = node.ticket_next;
        }
        if let Some(next) = node.ticket_next {
            self.node_mut(next).ticket_prev = node.ticket_prev;
        }

        let allocation_bytes = node.assembly.allocation_bytes();
        self.total_bytes = self
            .total_bytes
            .checked_sub(allocation_bytes)
            .expect("fragment total byte accounting underflow");
        let remove_ticket = {
            let ticket = self
                .tickets
                .get_mut(&node.key.ticket)
                .expect("fragment node ticket state missing");
            // Queue ends and accounting belong to the same ticket state.
            // Update them together with one lookup even when the removed
            // assembly is both the head and the tail.
            if node.ticket_prev.is_none() {
                ticket.head = node.ticket_next;
            }
            if node.ticket_next.is_none() {
                ticket.tail = node.ticket_prev;
            }
            ticket.bytes = ticket
                .bytes
                .checked_sub(allocation_bytes)
                .expect("fragment ticket byte accounting underflow");
            ticket.bytes == 0
        };
        if remove_ticket {
            let ticket = self
                .tickets
                .remove(&node.key.ticket)
                .expect("fragment node ticket state missing");
            debug_assert!(ticket.head.is_none() && ticket.tail.is_none());
        }
        self.free_slots.push(slot);
        node.assembly
    }

    fn ticket_bytes(&self, ticket: [u8; 16]) -> usize {
        self.tickets.get(&ticket).map_or(0, |state| state.bytes)
    }

    fn node(&self, slot: UdpV2FragmentSlotId) -> &UdpV2FragmentNode {
        self.slots[slot.index()]
            .as_ref()
            .expect("fragment index refers to an empty slot")
    }

    fn node_mut(&mut self, slot: UdpV2FragmentSlotId) -> &mut UdpV2FragmentNode {
        self.slots[slot.index()]
            .as_mut()
            .expect("fragment index refers to an empty slot")
    }

    #[cfg(test)]
    fn assert_invariants(&self) {
        assert!(self.slots.len() <= self.limits.max_entries);
        let mut free = HashSet::with_capacity(self.free_slots.len());
        for slot in &self.free_slots {
            assert!(
                slot.index() < self.slots.len(),
                "free slot is out of bounds"
            );
            assert!(free.insert(*slot), "free slot appears more than once");
            assert!(
                self.slots[slot.index()].is_none(),
                "free slot still contains a live fragment"
            );
        }
        for slot in self.keys.values() {
            assert!(
                !free.contains(slot),
                "free slot remains reachable through the key index"
            );
        }

        let mut global_count = 0;
        let mut global_bytes = 0;
        let mut previous = None;
        let mut current = self.global_head;
        while let Some(slot) = current {
            assert!(global_count < self.slots.len(), "global FIFO looped");
            let node = self.node(slot);
            assert_eq!(node.global_prev, previous);
            assert_eq!(self.keys.get(&node.key), Some(&slot));
            global_bytes += node.assembly.allocation_bytes();
            global_count += 1;
            previous = Some(slot);
            current = node.global_next;
        }
        assert_eq!(previous, self.global_tail);
        assert_eq!(global_count, self.keys.len());
        assert_eq!(global_bytes, self.total_bytes);

        let mut ticket_count = 0;
        for (ticket_id, ticket) in &self.tickets {
            let mut ticket_bytes = 0;
            let mut previous = None;
            let mut current = ticket.head;
            while let Some(slot) = current {
                assert!(ticket_count < self.slots.len(), "ticket FIFO looped");
                let node = self.node(slot);
                assert_eq!(node.key.ticket, *ticket_id);
                assert_eq!(node.ticket_prev, previous);
                ticket_bytes += node.assembly.allocation_bytes();
                ticket_count += 1;
                previous = Some(slot);
                current = node.ticket_next;
            }
            assert_eq!(previous, ticket.tail);
            assert_eq!(ticket_bytes, ticket.bytes);
            assert!(ticket_bytes > 0);
        }
        assert_eq!(ticket_count, self.keys.len());
        assert_eq!(
            self.slots.iter().filter(|node| node.is_some()).count(),
            self.keys.len()
        );
        assert_eq!(self.free_slots.len() + self.keys.len(), self.slots.len());
    }
}

/// The server's UDP codec. Cloning is cheap and clones share all state.
///
/// Feed every datagram received on the server's UDP socket to
/// [`decode`](Self::decode), and encode replies with [`encode`](Self::encode).
/// Every [`UdpSendPlan`] must be reported back through
/// [`UdpSendPlan::complete`] once its datagrams were sent or dropped: tickets
/// are only committed once their bytes are known to have left.
#[derive(Clone)]
pub struct UdpServer {
    method: &'static str,
    key: Vec<u8>,
    users: Arc<HashMap<u32, Vec<u8>>>,
    spec_time_interval: Option<u64>,
    udp_packet_size: u16,
    replay: Arc<Mutex<TimedReplaySet>>,
    session_tickets: SharedSessionTicketStore,
    pending_bootstrap_tickets: SharedSessionTicketStore,
    ticket_rotations: SharedUdpV2TicketRotations,
    shape_cache: Arc<Mutex<HashMap<TicketEpoch, UdpShapeProfile>>>,
    epoch_cipher_cache: Arc<Mutex<HashMap<TicketEpoch, Arc<UdpEpochCiphers>>>>,
    fragment_cache: Arc<Mutex<UdpV2FragmentCache>>,
}

type TicketEpoch = ([u8; 16], u64);

/// The authenticated ticket a client datagram arrived under; pass it back to
/// [`UdpServer::encode`] to answer that client.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpSession {
    ticket: [u8; 16],
    ticket_family_id: [u8; 16],
    ticket_generation: u64,
}

impl UdpSession {
    /// Identifies the ticket family. Tickets rotate, but every ticket of a
    /// family belongs to the same client association, so key outbound UDP
    /// sockets (and anything else that must outlive a rotation) by this.
    pub fn association_id(&self) -> [u8; 16] {
        self.ticket_family_id
    }

    /// Counts rotations within the family; a larger value is a newer ticket.
    /// Answer with the newest session seen for an association so replies
    /// keep up with the client's rotated ticket.
    pub fn ticket_generation(&self) -> u64 {
        self.ticket_generation
    }
}

/// What a client datagram turned out to be.
#[derive(Debug)]
pub enum UdpClientPacket {
    /// An authenticated, fully reassembled inner datagram.
    Data { plain: Vec<u8>, session: UdpSession },
    /// A bootstrap request; send the plan back to the datagram's source.
    HandshakeResponse(UdpSendPlan),
    /// An authenticated fragment of a datagram still being reassembled.
    Pending,
    /// A valid v2 fragment could not be retained under the bounded
    /// reassembly budget. The relay must discard it silently.
    Dropped,
}

#[derive(Debug)]
enum UdpPostSendAction {
    InsertTicket {
        store: SharedSessionTicketStore,
        ticket: [u8; 16],
        entry: SessionEntry,
    },
    CommitTicketRotation {
        store: SharedSessionTicketStore,
        rotation: SharedUdpV2TicketRotation,
    },
}

impl UdpPostSendAction {
    fn commit(self) {
        match self {
            Self::InsertTicket {
                store,
                ticket,
                entry,
            } => store.insert(ticket, entry),
            Self::CommitTicketRotation { store, rotation } => {
                let mut rotation = rotation.lock();
                if !rotation.committed {
                    store.insert(rotation.next_ticket, rotation.next_entry.clone());
                    rotation.committed = true;
                }
            }
        }
    }
}

/// Datagrams to send, plus what to commit once they are sent.
#[derive(Debug)]
#[must_use = "a send plan must be completed with `complete`"]
pub struct UdpSendPlan {
    packets: Vec<Vec<u8>>,
    post_send: Option<UdpPostSendAction>,
}

impl UdpSendPlan {
    fn new(packet: Vec<u8>, post_send: Option<UdpPostSendAction>) -> Self {
        Self {
            packets: vec![packet],
            post_send,
        }
    }

    fn many(packets: Vec<Vec<u8>>, post_send: Option<UdpPostSendAction>) -> Self {
        Self { packets, post_send }
    }

    pub fn packets(&self) -> &[Vec<u8>] {
        &self.packets
    }

    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    pub fn encoded_len(&self) -> usize {
        self.packets.iter().map(Vec::len).sum()
    }

    /// Reports whether the datagrams were handed to the socket. Only a
    /// delivered plan commits the ticket it carries.
    pub fn complete(self, delivered: bool) {
        if delivered && let Some(action) = self.post_send {
            action.commit();
        }
    }

    /// Transforms the datagrams (for example, to wrap them in an outer
    /// obfuscation layer) while keeping the pending commit attached.
    pub fn try_map_packets<F>(self, f: F) -> Result<Self>
    where
        F: FnOnce(Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>>,
    {
        Ok(Self {
            packets: f(self.packets)?,
            post_send: self.post_send,
        })
    }
}

impl UdpServer {
    pub(crate) fn new(
        method: Method,
        key: &[u8],
        users: Arc<HashMap<u32, Vec<u8>>>,
        udp_packet_size: u16,
        session_tickets: SharedSessionTicketStore,
        replay_capacity: usize,
    ) -> Self {
        Self {
            method: method.label(),
            key: key.to_vec(),
            users,
            spec_time_interval: method.spec_time_interval(),
            udp_packet_size,
            // A data packet stays acceptable for as long as its ticket does,
            // so its replay key has to be remembered that long too.
            replay: Arc::new(Mutex::new(TimedReplaySet::with_capacity(
                session_tickets.timeout(),
                replay_capacity,
            ))),
            pending_bootstrap_tickets: SharedSessionTicketStore::with_capacity(
                session_tickets.timeout(),
                session_tickets.max_entries(),
            ),
            session_tickets,
            ticket_rotations: Arc::new(Mutex::new(HashMap::new())),
            shape_cache: Arc::new(Mutex::new(HashMap::new())),
            epoch_cipher_cache: Arc::new(Mutex::new(HashMap::new())),
            fragment_cache: Arc::new(Mutex::new(UdpV2FragmentCache::new(
                UdpV2FragmentLimits::default(),
            ))),
        }
    }

    /// Decodes one datagram from a client. Errors carry a
    /// [`DecodeErrorKind`](crate::DecodeErrorKind).
    pub fn decode(&self, input: &[u8]) -> Result<UdpClientPacket> {
        if input.is_empty() {
            return decode_result(
                DecodeErrorKind::PacketMalformed,
                anyhow!("udp v2 packet too short"),
            );
        }

        match input[0] {
            UDP_V2_BOOTSTRAP_TYPE => self.decode_v2_handshake_init(input),
            UDP_V2_DATA_TYPE => self.decode_v2_data_packet(input),
            other => decode_result(
                DecodeErrorKind::PacketMalformed,
                anyhow!("unsupported udp v2 packet type {}", other),
            ),
        }
    }

    /// Encodes a reply to the client behind `session`, fragmenting it when it
    /// exceeds the negotiated datagram size. `inner_packet_budget` further
    /// caps each datagram, for hosts whose outer layer adds bytes.
    pub fn encode(
        &self,
        input: &[u8],
        session: &UdpSession,
        inner_packet_budget: Option<usize>,
    ) -> Result<UdpSendPlan> {
        self.encode_to_client_v2(input, session.ticket, inner_packet_budget)
    }

    fn select_v2_user_key_for_decode(&self, uid: u32) -> (Vec<u8>, Option<u32>, bool) {
        if let Some(user_key) = self.users.get(&uid) {
            return (user_key.clone(), Some(uid), true);
        }
        if self.users.is_empty() {
            return (self.key.clone(), None, true);
        }
        (self.v2_dummy_user_key(uid), Some(uid), false)
    }

    fn v2_dummy_user_key(&self, uid: u32) -> Vec<u8> {
        let mut salt = [0_u8; UDP_V2_METHOD_LABEL_MAX_LEN + 1 + 4];
        let method_len = self.method.len();
        salt[..method_len].copy_from_slice(self.method.as_bytes());
        salt[method_len] = 0xff;
        salt[method_len + 1..method_len + 5].copy_from_slice(&uid.to_le_bytes());
        hmac_sha256(&self.key, &salt[..method_len + 5]).to_vec()
    }

    fn current_epoch_bucket(&self) -> u64 {
        if let Some(interval) = self.spec_time_interval {
            return (now_secs_u32() as u64) / interval;
        }
        0
    }

    fn accepted_epoch_buckets(&self) -> [Option<u64>; 3] {
        let current = self.current_epoch_bucket();
        if self.spec_time_interval.is_none() {
            return [Some(current), None, None];
        }
        [
            Some(current),
            current.checked_sub(1),
            current.checked_add(1),
        ]
    }

    fn cached_v2_udp_epoch_ciphers(
        &self,
        ticket: &[u8; 16],
        master_secret: &[u8; 32],
        epoch: u64,
    ) -> Result<Arc<UdpEpochCiphers>> {
        if let Some(ciphers) = self
            .epoch_cipher_cache
            .lock()
            .get(&(*ticket, epoch))
            .cloned()
        {
            return Ok(ciphers);
        }

        // Keep the prepared AEAD objects in the cache. Constructing the AES-GCM
        // object builds its key schedule, so retaining only the derived bytes
        // would leave that work on every UDP packet. The cache returns cloned
        // Arc before releasing the lock; packet encryption/decryption never
        // holds the cache lock.
        let client_key = derive_v2_udp_epoch_key(self.method, master_secret, epoch, b"client")?;
        let server_key = derive_v2_udp_epoch_key(self.method, master_secret, epoch, b"server")?;
        let ciphers = Arc::new(UdpEpochCiphers {
            client: Aes128GcmCipher::new(&client_key),
            server: Aes128GcmCipher::new(&server_key),
        });
        let mut cache = self.epoch_cipher_cache.lock();
        if let Some(ciphers) = cache.get(&(*ticket, epoch)).cloned() {
            return Ok(ciphers);
        }
        if cache.len() >= UDP_V2_EPOCH_CIPHER_CACHE_MAX_ENTRIES {
            cache.clear();
        }
        cache.insert((*ticket, epoch), ciphers.clone());
        Ok(ciphers)
    }

    fn derive_v2_udp_shape_seed(&self, master_secret: &[u8; 32], epoch: u64) -> Result<[u8; 32]> {
        let method_len = self.method.len();
        let mut salt = [0_u8; UDP_V2_METHOD_LABEL_MAX_LEN + 8];
        salt[..method_len].copy_from_slice(self.method.as_bytes());
        salt[method_len..method_len + 8].copy_from_slice(&epoch.to_be_bytes());
        hkdf_sha256_array::<32>(
            master_secret,
            &salt[..method_len + 8],
            b"ssrr-auth-akarin-v2-udp-shape",
        )
    }

    fn derive_v2_udp_shape_profile(
        &self,
        master_secret: &[u8; 32],
        epoch: u64,
    ) -> Result<UdpShapeProfile> {
        let seed = self.derive_v2_udp_shape_seed(master_secret, epoch)?;
        let base_bins = [112_u16, 160, 224, 320, 448, 640, 896, 1184];
        let mut rng = XorShift128Plus::default();
        rng.init_from_bin(&seed);
        let mut bins = [0_u16; 8];
        for (idx, base) in base_bins.into_iter().enumerate() {
            let spread = (rng.next() % 65) as i32 - 32;
            bins[idx] = (base as i32 + spread).clamp(96, UDP_V2_DEFAULT_PACKET_SIZE as i32) as u16;
        }
        bins.sort_unstable();

        let mut deduped = [0_u16; 8];
        let mut len = 0_usize;
        let mut last = None;
        for bin in bins {
            if last == Some(bin) {
                continue;
            }
            deduped[len] = bin;
            len += 1;
            last = Some(bin);
        }

        Ok(UdpShapeProfile {
            seed,
            bins: deduped,
            len,
        })
    }

    fn cached_v2_udp_shape_profile(
        &self,
        ticket: &[u8; 16],
        master_secret: &[u8; 32],
        epoch: u64,
    ) -> Result<UdpShapeProfile> {
        if let Some(profile) = self.shape_cache.lock().get(&(*ticket, epoch)).copied() {
            return Ok(profile);
        }
        let profile = self.derive_v2_udp_shape_profile(master_secret, epoch)?;
        let mut cache = self.shape_cache.lock();
        if cache.len() >= UDP_V2_SHAPE_CACHE_MAX_ENTRIES {
            cache.clear();
        }
        cache.insert((*ticket, epoch), profile);
        Ok(profile)
    }

    fn choose_v2_udp_pad_len(
        &self,
        profile: &UdpShapeProfile,
        payload_len: usize,
        metadata_len: usize,
        nonce: &[u8; 12],
        direction: &[u8],
        packet_size: usize,
    ) -> Result<(usize, u8)> {
        let min_wire = UDP_V2_DATA_HEADER_LEN + metadata_len + payload_len + 16;
        if min_wire >= packet_size {
            return Ok((0, 0));
        }

        let mut choice_data = [0_u8; 24];
        choice_data[..12].copy_from_slice(nonce);
        choice_data[12..16].copy_from_slice(&((payload_len + metadata_len) as u32).to_le_bytes());
        choice_data[16..16 + direction.len()].copy_from_slice(direction);
        let choice = hmac_sha256(&profile.seed, &choice_data);

        let mut candidate_count = 0_usize;
        let mut last_seen = None;
        for &bin in &profile.bins[..profile.len] {
            if last_seen == Some(bin) {
                continue;
            }
            last_seen = Some(bin);
            let target = bin as usize;
            if target >= min_wire && target <= packet_size {
                candidate_count += 1;
            }
        }

        if candidate_count == 0 {
            let spare = packet_size.saturating_sub(min_wire);
            return Ok((((choice[0] as usize) % (spare.min(48) + 1)).min(spare), 0));
        }

        let total_weight = candidate_count * (candidate_count + 1) / 2;
        let selector = u64::from_le_bytes(choice[0..8].try_into().unwrap()) as usize % total_weight;
        let mut cursor = 0_usize;
        let mut seen = 0_usize;
        let mut picked = None;
        let mut last_seen = None;
        for (idx, bin) in profile.bins[..profile.len].iter().copied().enumerate() {
            if last_seen == Some(bin) {
                continue;
            }
            last_seen = Some(bin);
            let target = bin as usize;
            if target < min_wire || target > packet_size {
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

    fn prepare_v2_ticket_update(
        &self,
        current_ticket: &[u8; 16],
        current_entry: &SessionEntry,
    ) -> Option<SharedUdpV2TicketRotation> {
        let timeout = self.session_tickets.timeout();
        let rotation_interval = timeout.checked_div(2).unwrap_or(Duration::from_secs(60));
        let issued_age = self.session_tickets.issued_age(current_ticket)?;
        if issued_age < rotation_interval {
            return None;
        }

        let now = Instant::now();
        let mut rotations = self.ticket_rotations.lock();
        if let Some(rotation) = rotations.get(current_ticket) {
            if rotation.lock().current_ticket_expires_at >= now {
                return Some(rotation.clone());
            }
            rotations.remove(current_ticket);
        }

        let max_entries = self.session_tickets.max_entries();
        if rotations.len() >= max_entries {
            rotations.retain(|ticket, rotation| {
                rotation.lock().current_ticket_expires_at >= now
                    && self.session_tickets.peek(ticket).is_some()
            });
            if rotations.len() >= max_entries {
                return None;
            }
        }

        let next_ticket = loop {
            let candidate = generate_opaque_session_ticket();
            if candidate != *current_ticket {
                break candidate;
            }
        };
        let mut next_secret = [0_u8; 32];
        rng().fill(&mut next_secret);
        let current_ticket_expires_at = now
            .checked_add(timeout.saturating_sub(issued_age))
            .unwrap_or(now);
        let rotation = Arc::new(Mutex::new(UdpV2TicketRotation {
            next_ticket,
            next_secret,
            next_entry: current_entry.rotated(next_secret),
            current_ticket_expires_at,
            committed: false,
        }));
        rotations.insert(*current_ticket, rotation.clone());
        Some(rotation)
    }

    fn bootstrap_replay_key_v2(&self, request: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.method.as_bytes());
        hasher.update([UDP_V2_BOOTSTRAP_TYPE]);
        hasher.update(request);
        let digest = hasher.finalize();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn replay_key_v2(
        &self,
        ticket: &[u8; 16],
        epoch: u64,
        nonce: &[u8; 12],
    ) -> ([u8; 1 + 1 + 16 + 8 + 12], usize) {
        let mut out = [0_u8; 1 + 1 + 16 + 8 + 12];
        let mut out_len = 0_usize;
        out[out_len] = u8::from(self.spec_time_interval.is_some());
        out_len += 1;
        out[out_len] = UDP_V2_DATA_TYPE;
        out_len += 1;
        out[out_len..out_len + 16].copy_from_slice(ticket);
        out_len += 16;
        out[out_len..out_len + 8].copy_from_slice(&epoch.to_le_bytes());
        out_len += 8;
        out[out_len..out_len + 12].copy_from_slice(nonce);
        out_len += 12;
        (out, out_len)
    }

    fn build_v2_session_entry(
        &self,
        ticket_secret: [u8; 32],
        user_id: Option<u32>,
        udp_packet_size: u16,
    ) -> SessionEntry {
        let mut ticket_family_id = [0_u8; 16];
        rng().fill(&mut ticket_family_id);
        SessionEntry {
            master_secret: ticket_secret,
            user_id,
            udp_packet_size,
            ticket_family_id,
            ticket_generation: 0,
        }
    }

    fn v2_data_payload_capacity(
        packet_size: usize,
        ticket_update: bool,
        fragment: bool,
    ) -> Option<usize> {
        let metadata_len = UDP_V2_META_LEN
            + if ticket_update {
                UDP_V2_TICKET_UPDATE_LEN
            } else {
                0
            }
            + if fragment {
                UDP_V2_FRAGMENT_META_LEN
            } else {
                0
            };
        packet_size.checked_sub(UDP_V2_DATA_HEADER_LEN + metadata_len + 16)
    }

    fn random_v2_fragment_id() -> u32 {
        let mut out = [0_u8; 4];
        rng().fill(&mut out);
        u32::from_le_bytes(out)
    }

    fn reassemble_v2_fragment(
        &self,
        ticket: [u8; 16],
        meta: UdpV2FragmentMeta,
        fragment: &[u8],
    ) -> Result<UdpV2FragmentResult> {
        if meta.total_len == 0 || meta.total_len > UDP_V2_MAX_PLAIN_LEN || fragment.is_empty() {
            bail!("udp v2 fragment length is invalid");
        }
        let key = UdpV2FragmentKey {
            ticket,
            fragment_id: meta.fragment_id,
        };
        let mut fragments = self.fragment_cache.lock();
        // The cache lock serializes creation order with the clock sample, so a
        // FIFO deadline is a total order even when UDP workers race to enter.
        let now = Instant::now();
        fragments.insert_fragment(key, meta, fragment, now)
    }

    fn decode_v2_handshake_init(&self, input: &[u8]) -> Result<UdpClientPacket> {
        if input.len() != UDP_V2_BOOTSTRAP_REQ_LEN {
            return decode_result(
                DecodeErrorKind::ClientHelloMalformed,
                anyhow!("udp v2 handshake packet length mismatch"),
            );
        }
        if input[1] != UDP_V2_PROTOCOL_VERSION {
            return decode_result(
                DecodeErrorKind::ClientHelloMalformed,
                anyhow!("udp v2 handshake version mismatch"),
            );
        }
        let client_udp_packet_size =
            normalize_v2_udp_packet_size(u16::from_le_bytes([input[2], input[3]]));
        let server_udp_packet_size = self.udp_packet_size;
        let effective_udp_packet_size = client_udp_packet_size.min(server_udp_packet_size);

        let client_seed: [u8; 4] = input[4..8].try_into().map_err(|_| {
            decode_error(
                DecodeErrorKind::ClientHelloMalformed,
                anyhow!("invalid udp v2 client seed"),
            )
        })?;

        let user_id_field = u32::from_le_bytes(input[8..12].try_into().map_err(|_| {
            decode_error(
                DecodeErrorKind::ClientHelloMalformed,
                anyhow!("invalid udp v2 user id"),
            )
        })?);
        let client_nonce: [u8; 16] = input[12..28].try_into().map_err(|_| {
            decode_error(
                DecodeErrorKind::ClientHelloMalformed,
                anyhow!("invalid udp v2 client nonce"),
            )
        })?;
        let client_share_bytes: [u8; 32] = input[28..60].try_into().map_err(|_| {
            decode_error(
                DecodeErrorKind::ClientHelloMalformed,
                anyhow!("invalid udp v2 client share"),
            )
        })?;
        let client_share = CompressedRistretto(client_share_bytes)
            .decompress()
            .ok_or_else(|| {
                decode_error(
                    DecodeErrorKind::ClientHelloMalformed,
                    anyhow!("invalid udp v2 client share point"),
                )
            })?;

        let (user_key, user_id, known_user) = self.select_v2_user_key_for_decode(user_id_field);
        let replay_key = self.bootstrap_replay_key_v2(input);
        if !self.replay.lock().insert_unique(&replay_key) {
            return decode_result(
                DecodeErrorKind::Replay,
                anyhow!("udp v2 bootstrap replay detected for {}", self.method),
            );
        }

        let password_scalar = udp_password_scalar(&user_key, self.method, user_id)?;
        let client_component = client_share - spake_point(b"M") * password_scalar;
        let server_scalar = random_scalar();
        let server_share_point =
            RISTRETTO_BASEPOINT_POINT * server_scalar + spake_point(b"N") * password_scalar;
        let shared_point = client_component * server_scalar;

        let ticket = generate_opaque_session_ticket();
        let mut server_nonce = [0_u8; 16];
        rng().fill(&mut server_nonce);
        let mut server_seed = [0_u8; 12];
        rng().fill(&mut server_seed);
        let server_share = server_share_point.compress().to_bytes();
        let transcript = UdpV2BootstrapTranscript {
            client_udp_packet_size,
            server_udp_packet_size,
            user_id_field,
            selected_user_id: user_id,
            client_seed,
            client_nonce: &client_nonce,
            client_share: &client_share_bytes,
            server_seed,
            ticket: &ticket,
            server_nonce: &server_nonce,
            server_share: &server_share,
        };
        let transcript_hash = bootstrap_transcript_hash(self.method, &transcript);
        let master_secret = derive_v2_udp_master_secret(&shared_point, &transcript_hash)?;
        let resumption_secret = derive_resumption_secret(&master_secret, &transcript_hash)?;
        let confirm_tag = derive_v2_udp_confirm_tag(&master_secret, &transcript_hash)?;

        let mut resp = Vec::with_capacity(UDP_V2_BOOTSTRAP_RESP_LEN);
        resp.push(UDP_V2_BOOTSTRAP_RESP_TYPE);
        resp.push(UDP_V2_PROTOCOL_VERSION);
        resp.extend_from_slice(&server_udp_packet_size.to_le_bytes());
        resp.extend_from_slice(&server_seed);
        resp.extend_from_slice(&ticket);
        resp.extend_from_slice(&server_nonce);
        resp.extend_from_slice(&server_share);
        resp.extend_from_slice(&confirm_tag);
        let post_send = known_user.then_some(UdpPostSendAction::InsertTicket {
            store: self.pending_bootstrap_tickets.clone(),
            ticket,
            entry: self.build_v2_session_entry(
                resumption_secret,
                user_id,
                effective_udp_packet_size,
            ),
        });
        Ok(UdpClientPacket::HandshakeResponse(UdpSendPlan::new(
            resp, post_send,
        )))
    }

    fn decode_v2_data_packet(&self, input: &[u8]) -> Result<UdpClientPacket> {
        if input.len() <= UDP_V2_DATA_HEADER_LEN + 16 {
            return decode_result(
                DecodeErrorKind::PacketMalformed,
                anyhow!("udp v2 data packet too short"),
            );
        }

        let ticket: [u8; 16] = input[1..17].try_into().map_err(|_| {
            decode_error(
                DecodeErrorKind::PacketMalformed,
                anyhow!("invalid udp v2 ticket"),
            )
        })?;
        let epoch = u64::from_le_bytes(input[17..25].try_into().map_err(|_| {
            decode_error(
                DecodeErrorKind::PacketMalformed,
                anyhow!("invalid udp v2 epoch"),
            )
        })?);
        if !self.accepted_epoch_buckets().contains(&Some(epoch)) {
            return decode_result(
                DecodeErrorKind::PacketMalformed,
                anyhow!("udp v2 packet epoch is outside the accepted window"),
            );
        }
        let nonce: [u8; 12] = input[25..37].try_into().map_err(|_| {
            decode_error(
                DecodeErrorKind::PacketMalformed,
                anyhow!("invalid udp v2 nonce"),
            )
        })?;
        let (entry, pending_bootstrap) = if let Some(entry) = self.session_tickets.peek(&ticket) {
            (entry, false)
        } else {
            let entry = self
                .pending_bootstrap_tickets
                .peek(&ticket)
                .ok_or_else(|| {
                    decode_error(
                        DecodeErrorKind::UnknownTicket,
                        anyhow!("unknown udp v2 session ticket"),
                    )
                })?;
            (entry, true)
        };
        if input.len() > entry.udp_packet_size as usize {
            return decode_result(
                DecodeErrorKind::PacketSize,
                anyhow!("udp v2 packet exceeds negotiated size"),
            );
        }

        let (replay_key, replay_key_len) = self.replay_key_v2(&ticket, epoch, &nonce);
        let aead_ciphers =
            self.cached_v2_udp_epoch_ciphers(&ticket, &entry.master_secret, epoch)?;
        let tag_offset = input.len() - 16;
        let mut decoded = input[UDP_V2_DATA_HEADER_LEN..tag_offset].to_vec();
        let tag: [u8; 16] = input[tag_offset..].try_into().map_err(|_| {
            decode_error(
                DecodeErrorKind::PacketMalformed,
                anyhow!("invalid udp v2 auth tag"),
            )
        })?;
        aead_ciphers
            .client
            .decrypt_detached(
                &nonce,
                &input[..UDP_V2_DATA_HEADER_LEN],
                decoded.as_mut_slice(),
                &tag,
            )
            .map_err(|err| decode_error(DecodeErrorKind::PacketAuthFailed, err))?;
        if decoded.len() < UDP_V2_META_LEN {
            return decode_result(
                DecodeErrorKind::PacketMalformed,
                anyhow!("udp v2 payload metadata is truncated"),
            );
        }
        let payload_len = u16::from_le_bytes(decoded[0..2].try_into().unwrap()) as usize;
        let flags = decoded[2];
        if (flags & !UDP_V2_DATA_FLAG_FRAGMENT) != 0 {
            return decode_result(
                DecodeErrorKind::PacketMalformed,
                anyhow!("udp v2 client packet has unknown flags"),
            );
        }
        let mut metadata_len = UDP_V2_META_LEN;
        let fragment = if (flags & UDP_V2_DATA_FLAG_FRAGMENT) != 0 {
            let end = metadata_len + UDP_V2_FRAGMENT_META_LEN;
            if decoded.len() < end {
                return decode_result(
                    DecodeErrorKind::PacketMalformed,
                    anyhow!("udp v2 fragment metadata is truncated"),
                );
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
            return decode_result(
                DecodeErrorKind::PacketMalformed,
                anyhow!("udp v2 payload length is invalid"),
            );
        }
        if !self
            .replay
            .lock()
            .insert_unique(&replay_key[..replay_key_len])
        {
            return decode_result(
                DecodeErrorKind::Replay,
                anyhow!("udp v2 replay detected for {}", self.method),
            );
        }

        let plain = if let Some(meta) = fragment {
            let payload = &decoded[metadata_len..metadata_len + payload_len];
            match self
                .reassemble_v2_fragment(ticket, meta, payload)
                .map_err(|err| decode_error(DecodeErrorKind::PacketMalformed, err))?
            {
                UdpV2FragmentResult::Complete(plain) => plain,
                UdpV2FragmentResult::Pending => {
                    if pending_bootstrap {
                        self.pending_bootstrap_tickets.touch(&ticket);
                    } else if !self.session_tickets.touch(&ticket) {
                        return decode_result(
                            DecodeErrorKind::UnknownTicket,
                            anyhow!("unknown udp v2 session ticket"),
                        );
                    }
                    return Ok(UdpClientPacket::Pending);
                }
                UdpV2FragmentResult::Dropped => return Ok(UdpClientPacket::Dropped),
            }
        } else {
            let mut plain = decoded;
            plain.copy_within(metadata_len..metadata_len + payload_len, 0);
            plain.truncate(payload_len);
            plain
        };
        let ticket_family_id = entry.ticket_family_id;
        let ticket_generation = entry.ticket_generation;
        if pending_bootstrap {
            if self.pending_bootstrap_tickets.remove(&ticket) {
                self.session_tickets.insert(ticket, entry);
            } else if !self.session_tickets.touch(&ticket) {
                return decode_result(
                    DecodeErrorKind::UnknownTicket,
                    anyhow!("unknown udp v2 session ticket"),
                );
            }
        } else if !self.session_tickets.touch(&ticket) {
            return decode_result(
                DecodeErrorKind::UnknownTicket,
                anyhow!("unknown udp v2 session ticket"),
            );
        }
        Ok(UdpClientPacket::Data {
            plain,
            session: UdpSession {
                ticket,
                ticket_family_id,
                ticket_generation,
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_v2_server_data_packet(
        &self,
        ticket: [u8; 16],
        entry: &SessionEntry,
        epoch: u64,
        input: &[u8],
        ticket_update: Option<&([u8; 16], [u8; 32])>,
        fragment: Option<UdpV2FragmentMeta>,
        packet_budget: usize,
    ) -> Result<Vec<u8>> {
        let mut nonce = [0_u8; 12];
        rng().fill(&mut nonce);
        let aead_ciphers =
            self.cached_v2_udp_epoch_ciphers(&ticket, &entry.master_secret, epoch)?;
        let metadata_len = UDP_V2_META_LEN
            + if ticket_update.is_some() {
                UDP_V2_TICKET_UPDATE_LEN
            } else {
                0
            }
            + if fragment.is_some() {
                UDP_V2_FRAGMENT_META_LEN
            } else {
                0
            };
        let min_wire = UDP_V2_DATA_HEADER_LEN + metadata_len + input.len() + 16;
        if min_wire > packet_budget {
            bail!("udp v2 response exceeds packet budget");
        }
        let shape_profile =
            self.cached_v2_udp_shape_profile(&ticket, &entry.master_secret, epoch)?;
        let (pad_len, shape_class) = self.choose_v2_udp_pad_len(
            &shape_profile,
            input.len(),
            metadata_len,
            &nonce,
            b"server",
            packet_budget,
        )?;
        let payload_len =
            u16::try_from(input.len()).map_err(|_| anyhow!("udp v2 payload too large"))?;
        let body_plain_len = metadata_len + input.len() + pad_len;
        let mut out = Vec::with_capacity(UDP_V2_DATA_HEADER_LEN + body_plain_len + 16);
        out.push(UDP_V2_DATA_TYPE);
        out.extend_from_slice(&ticket);
        out.extend_from_slice(&epoch.to_le_bytes());
        out.extend_from_slice(&nonce);
        let body_start = out.len();
        out.extend_from_slice(&payload_len.to_le_bytes());
        let mut flags = 0_u8;
        if ticket_update.is_some() {
            flags |= UDP_V2_DATA_FLAG_TICKET_UPDATE;
        }
        if fragment.is_some() {
            flags |= UDP_V2_DATA_FLAG_FRAGMENT;
        }
        out.push(flags);
        out.push(shape_class);
        if let Some((next_ticket, next_secret)) = ticket_update {
            out.extend_from_slice(next_ticket);
            out.extend_from_slice(next_secret);
        }
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
        out.extend_from_slice(input);
        if pad_len > 0 {
            out.resize(out.len() + pad_len, 0);
        }
        let (header, body) = out.split_at_mut(body_start);
        let tag = aead_ciphers.server.encrypt_detached(
            &nonce,
            &header[..UDP_V2_DATA_HEADER_LEN],
            body,
        )?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn encode_to_client_v2(
        &self,
        input: &[u8],
        ticket: [u8; 16],
        inner_packet_budget: Option<usize>,
    ) -> Result<UdpSendPlan> {
        if input.len() > UDP_V2_MAX_PLAIN_LEN {
            bail!("udp v2 payload too large");
        }
        let entry = self
            .session_tickets
            .peek(&ticket)
            .ok_or_else(|| anyhow!("unknown udp v2 session ticket"))?;

        let epoch = self.current_epoch_bucket();
        let negotiated_packet_size = entry.udp_packet_size as usize;
        let packet_size = inner_packet_budget
            .map(|budget| budget.min(negotiated_packet_size))
            .unwrap_or(negotiated_packet_size);
        let mut ticket_rotation = self.prepare_v2_ticket_update(&ticket, &entry);
        let mut ticket_update = ticket_rotation.as_ref().map(|rotation| {
            let rotation = rotation.lock();
            (rotation.next_ticket, rotation.next_secret)
        });
        let mut capacity =
            Self::v2_data_payload_capacity(packet_size, ticket_update.is_some(), false)
                .ok_or_else(|| anyhow!("udp v2 negotiated packet size is too small"))?;
        if input.len() > capacity && ticket_update.is_some() {
            ticket_rotation = None;
            ticket_update = None;
            capacity = Self::v2_data_payload_capacity(packet_size, false, false)
                .ok_or_else(|| anyhow!("udp v2 negotiated packet size is too small"))?;
        }
        if input.len() <= capacity {
            let packet = self.encode_v2_server_data_packet(
                ticket,
                &entry,
                epoch,
                input,
                ticket_update.as_ref(),
                None,
                packet_size,
            )?;
            let post_send =
                ticket_rotation.map(|rotation| UdpPostSendAction::CommitTicketRotation {
                    store: self.session_tickets.clone(),
                    rotation,
                });
            return Ok(UdpSendPlan::new(packet, post_send));
        }

        let fragment_capacity = Self::v2_data_payload_capacity(packet_size, false, true)
            .ok_or_else(|| anyhow!("udp v2 negotiated packet size is too small"))?;
        if fragment_capacity == 0 {
            bail!("udp v2 negotiated packet size is too small");
        }
        let fragment_id = Self::random_v2_fragment_id();
        let total_len = input.len();
        let mut packets = Vec::with_capacity(total_len.div_ceil(fragment_capacity));
        let mut offset = 0_usize;
        while offset < total_len {
            let end = (offset + fragment_capacity).min(total_len);
            let meta = UdpV2FragmentMeta {
                fragment_id,
                offset,
                total_len,
            };
            packets.push(self.encode_v2_server_data_packet(
                ticket,
                &entry,
                epoch,
                &input[offset..end],
                None,
                Some(meta),
                packet_size,
            )?);
            offset = end;
        }
        Ok(UdpSendPlan::many(packets, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_v2_fragment_slots_are_compact() {
        assert_eq!(std::mem::size_of::<UdpV2FragmentSlotId>(), 4);
        assert_eq!(std::mem::size_of::<Option<UdpV2FragmentSlotId>>(), 4);
        assert_eq!(UdpV2FragmentSlotId::from_index(8191).index(), 8191);
    }

    #[test]
    fn udp_v2_fragment_cache_evicts_oldest_ticket_assembly_and_reuses_slot() {
        let limits = UdpV2FragmentLimits {
            timeout_secs: 30,
            max_entries: 8,
            max_ticket_bytes: 17,
            max_total_bytes: 128,
        };
        let mut cache = UdpV2FragmentCache::new(limits);
        let start = Instant::now();
        let ticket = [0x21_u8; 16];
        let key = UdpV2FragmentKey {
            ticket,
            fragment_id: 1,
        };
        let meta = UdpV2FragmentMeta {
            fragment_id: 1,
            offset: 0,
            total_len: 8,
        };

        assert!(matches!(
            cache
                .insert_fragment(key, meta, &[0xaa], start)
                .expect("first fragment should fit"),
            UdpV2FragmentResult::Pending
        ));
        let first_slot = *cache.keys.get(&key).expect("first slot");

        let second_key = UdpV2FragmentKey {
            ticket,
            fragment_id: 2,
        };
        let second_meta = UdpV2FragmentMeta {
            fragment_id: 2,
            offset: 0,
            total_len: 8,
        };
        assert!(matches!(
            cache
                .insert_fragment(
                    second_key,
                    second_meta,
                    &[0xbb],
                    start + Duration::from_millis(1)
                )
                .expect("new fragment should evict the prior ticket assembly"),
            UdpV2FragmentResult::Pending
        ));
        assert!(!cache.keys.contains_key(&key), "oldest ticket work evicted");
        assert_eq!(
            *cache.keys.get(&second_key).expect("second slot"),
            first_slot,
            "the evicted slot is reused instead of growing metadata"
        );
        cache.assert_invariants();
    }

    #[test]
    fn udp_v2_fragment_cache_evicts_global_oldest_assembly() {
        let limits = UdpV2FragmentLimits {
            timeout_secs: 30,
            max_entries: 8,
            max_ticket_bytes: 128,
            max_total_bytes: 17,
        };
        let mut cache = UdpV2FragmentCache::new(limits);
        let start = Instant::now();
        let first_key = UdpV2FragmentKey {
            ticket: [0x31_u8; 16],
            fragment_id: 1,
        };
        let second_key = UdpV2FragmentKey {
            ticket: [0x32_u8; 16],
            fragment_id: 1,
        };
        let meta = UdpV2FragmentMeta {
            fragment_id: 1,
            offset: 0,
            total_len: 8,
        };

        assert!(matches!(
            cache
                .insert_fragment(first_key, meta, &[0xaa], start)
                .expect("first fragment should fit"),
            UdpV2FragmentResult::Pending
        ));
        assert!(matches!(
            cache
                .insert_fragment(second_key, meta, &[0xbb], start + Duration::from_millis(1))
                .expect("global pressure should evict the oldest assembly"),
            UdpV2FragmentResult::Pending
        ));
        assert!(!cache.keys.contains_key(&first_key));
        assert!(cache.keys.contains_key(&second_key));
        cache.assert_invariants();
    }

    #[test]
    fn udp_v2_fragment_cache_removes_middle_ticket_node_without_losing_neighbors() {
        let limits = UdpV2FragmentLimits {
            timeout_secs: 30,
            max_entries: 8,
            max_ticket_bytes: 128,
            max_total_bytes: 256,
        };
        let mut cache = UdpV2FragmentCache::new(limits);
        let start = Instant::now();
        let ticket = [0x41_u8; 16];
        let first = UdpV2FragmentKey {
            ticket,
            fragment_id: 1,
        };
        let middle = UdpV2FragmentKey {
            ticket,
            fragment_id: 2,
        };
        let last = UdpV2FragmentKey {
            ticket,
            fragment_id: 3,
        };
        let meta = |fragment_id| UdpV2FragmentMeta {
            fragment_id,
            offset: 0,
            total_len: 8,
        };
        for (key, at) in [(first, start), (middle, start), (last, start)] {
            assert!(matches!(
                cache.insert_fragment(key, meta(key.fragment_id), &[key.fragment_id as u8], at),
                Ok(UdpV2FragmentResult::Pending)
            ));
        }
        let middle_slot = *cache.keys.get(&middle).expect("middle slot");
        cache.remove_slot(middle_slot);
        assert!(!cache.keys.contains_key(&middle));
        assert_eq!(
            cache.tickets.get(&ticket).and_then(|state| state.head),
            cache.keys.get(&first).copied()
        );
        assert_eq!(
            cache.tickets.get(&ticket).and_then(|state| state.tail),
            cache.keys.get(&last).copied()
        );
        cache.assert_invariants();
    }

    #[test]
    fn udp_v2_fragment_cache_expires_only_after_its_strict_deadline() {
        let limits = UdpV2FragmentLimits {
            timeout_secs: 1,
            max_entries: 8,
            max_ticket_bytes: 128,
            max_total_bytes: 128,
        };
        let mut cache = UdpV2FragmentCache::new(limits);
        let start = Instant::now();
        let key = UdpV2FragmentKey {
            ticket: [0x51_u8; 16],
            fragment_id: 1,
        };
        let meta = UdpV2FragmentMeta {
            fragment_id: 1,
            offset: 0,
            total_len: 8,
        };
        assert!(matches!(
            cache.insert_fragment(key, meta, &[0xaa], start),
            Ok(UdpV2FragmentResult::Pending)
        ));
        cache.expire(start + Duration::from_secs(1));
        assert!(cache.keys.contains_key(&key), "deadline equality is live");
        cache.expire(start + Duration::from_secs(1) + Duration::from_nanos(1));
        assert!(
            cache.keys.is_empty(),
            "only a strictly past deadline expires"
        );
        cache.assert_invariants();
    }

    #[test]
    fn udp_v2_fragment_cache_accepts_out_of_order_and_duplicate_fragments() {
        let limits = UdpV2FragmentLimits {
            timeout_secs: 30,
            max_entries: 8,
            max_ticket_bytes: 128,
            max_total_bytes: 128,
        };
        let mut cache = UdpV2FragmentCache::new(limits);
        let start = Instant::now();
        let key = UdpV2FragmentKey {
            ticket: [0x61_u8; 16],
            fragment_id: 1,
        };
        let tail = UdpV2FragmentMeta {
            fragment_id: 1,
            offset: 4,
            total_len: 8,
        };
        let head = UdpV2FragmentMeta {
            fragment_id: 1,
            offset: 0,
            total_len: 8,
        };
        assert!(matches!(
            cache.insert_fragment(key, tail, b"efgh", start),
            Ok(UdpV2FragmentResult::Pending)
        ));
        assert!(matches!(
            cache.insert_fragment(key, tail, b"efgh", start + Duration::from_millis(1)),
            Ok(UdpV2FragmentResult::Pending)
        ));
        let complete = cache
            .insert_fragment(key, head, b"abcd", start + Duration::from_millis(2))
            .expect("out-of-order assembly should complete");
        assert!(
            matches!(complete, UdpV2FragmentResult::Complete(ref plain) if plain.as_slice() == b"abcdefgh")
        );
        assert!(cache.keys.is_empty());
        cache.assert_invariants();
    }

    #[test]
    fn udp_v2_fragment_cache_rejects_conflicting_overlap_without_partial_write() {
        let limits = UdpV2FragmentLimits {
            timeout_secs: 30,
            max_entries: 8,
            max_ticket_bytes: 128,
            max_total_bytes: 128,
        };
        let mut cache = UdpV2FragmentCache::new(limits);
        let start = Instant::now();
        let key = UdpV2FragmentKey {
            ticket: [0x71_u8; 16],
            fragment_id: 1,
        };
        let initial = UdpV2FragmentMeta {
            fragment_id: 1,
            offset: 0,
            total_len: 8,
        };
        assert!(matches!(
            cache.insert_fragment(key, initial, b"abcd", start),
            Ok(UdpV2FragmentResult::Pending)
        ));
        let conflicting = UdpV2FragmentMeta {
            fragment_id: 1,
            offset: 2,
            total_len: 8,
        };
        assert!(
            cache
                .insert_fragment(key, conflicting, b"cXef", start + Duration::from_millis(1))
                .is_err()
        );
        let mismatched_total = UdpV2FragmentMeta {
            fragment_id: 1,
            offset: 4,
            total_len: 7,
        };
        assert!(
            cache
                .insert_fragment(
                    key,
                    mismatched_total,
                    b"efg",
                    start + Duration::from_millis(2)
                )
                .is_err()
        );
        let node = cache.node(*cache.keys.get(&key).expect("live assembly"));
        assert_eq!(&node.assembly.data[..4], b"abcd");
        assert!(!node.assembly.received[4]);
        assert!(!node.assembly.received[5]);
        cache.assert_invariants();
    }

    #[test]
    fn udp_v2_fragment_cache_evicts_for_entry_limit_and_drops_unstorable_work() {
        let entry_limited = UdpV2FragmentLimits {
            timeout_secs: 30,
            max_entries: 1,
            max_ticket_bytes: 128,
            max_total_bytes: 128,
        };
        let mut cache = UdpV2FragmentCache::new(entry_limited);
        let start = Instant::now();
        let first = UdpV2FragmentKey {
            ticket: [0x81_u8; 16],
            fragment_id: 1,
        };
        let second = UdpV2FragmentKey {
            ticket: [0x82_u8; 16],
            fragment_id: 1,
        };
        let meta = UdpV2FragmentMeta {
            fragment_id: 1,
            offset: 0,
            total_len: 8,
        };
        assert!(matches!(
            cache.insert_fragment(first, meta, &[1], start),
            Ok(UdpV2FragmentResult::Pending)
        ));
        assert!(matches!(
            cache.insert_fragment(second, meta, &[2], start),
            Ok(UdpV2FragmentResult::Pending)
        ));
        assert!(!cache.keys.contains_key(&first));
        cache.assert_invariants();

        let disabled = UdpV2FragmentCache::new(UdpV2FragmentLimits {
            timeout_secs: 30,
            max_entries: 0,
            max_ticket_bytes: 128,
            max_total_bytes: 128,
        });
        let mut disabled = disabled;
        assert!(matches!(
            disabled.insert_fragment(first, meta, &[1], start),
            Ok(UdpV2FragmentResult::Dropped)
        ));
        disabled.assert_invariants();
    }

    #[test]
    fn udp_v2_fragment_cache_preserves_live_work_when_new_assembly_cannot_fit() {
        for (max_ticket_bytes, max_total_bytes) in [(16, 128), (128, 16)] {
            let mut cache = UdpV2FragmentCache::new(UdpV2FragmentLimits {
                timeout_secs: 30,
                max_entries: 1,
                max_ticket_bytes,
                max_total_bytes,
            });
            let now = Instant::now();
            let live = UdpV2FragmentKey {
                ticket: [0x83; 16],
                fragment_id: 1,
            };
            let meta = UdpV2FragmentMeta {
                fragment_id: 1,
                offset: 0,
                total_len: 8,
            };
            assert!(matches!(
                cache.insert_fragment(live, meta, b"abcd", now),
                Ok(UdpV2FragmentResult::Pending)
            ));
            let oversized = UdpV2FragmentKey {
                fragment_id: 2,
                ..live
            };
            assert!(matches!(
                cache.insert_fragment(
                    oversized,
                    UdpV2FragmentMeta {
                        fragment_id: 2,
                        total_len: 9,
                        ..meta
                    },
                    b"x",
                    now,
                ),
                Ok(UdpV2FragmentResult::Dropped)
            ));
            cache.assert_invariants();
            assert!(matches!(
                cache.insert_fragment(live, UdpV2FragmentMeta { offset: 4, ..meta }, b"efgh", now),
                Ok(UdpV2FragmentResult::Complete(data)) if data == b"abcdefgh"
            ));
            cache.assert_invariants();
        }
    }
}

use parking_lot::{Mutex, RwLock};
use std::cmp::Ordering;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

const INLINE_REPLAY_KEY_CAPACITY: usize = 80;
const SESSION_TICKET_ACTIVITY_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_INDEX_PREALLOC_CAPACITY: usize = 4096;

#[derive(Clone, Debug, Eq)]
struct ReplayKey {
    len: u8,
    bytes: [u8; INLINE_REPLAY_KEY_CAPACITY],
}

impl ReplayKey {
    fn new(key: &[u8]) -> Self {
        assert!(
            key.len() <= INLINE_REPLAY_KEY_CAPACITY,
            "replay key length {} exceeds inline capacity {}",
            key.len(),
            INLINE_REPLAY_KEY_CAPACITY
        );
        let mut bytes = [0_u8; INLINE_REPLAY_KEY_CAPACITY];
        bytes[..key.len()].copy_from_slice(key);
        Self {
            len: key.len() as u8,
            bytes,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl PartialEq for ReplayKey {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.as_slice() == other.as_slice()
    }
}

impl Hash for ReplayKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.as_slice().hash(state);
    }
}

#[derive(Debug)]
struct ReplaySlot {
    key: ReplayKey,
    expires_at: Instant,
    hash: u64,
    previous: Option<usize>,
    next: Option<usize>,
}

#[derive(Debug)]
pub struct TimedReplaySet {
    timeout: Duration,
    max_entries: usize,
    len: usize,
    slots: Vec<Option<ReplaySlot>>,
    free: Vec<usize>,
    // A bucket stores only its head; collision links live in reusable slots so
    // unique keys do not allocate a temporary Vec for every hash value.
    index: HashMap<u64, usize>,
    order: VecDeque<usize>,
    hash_builder: RandomState,
}

impl TimedReplaySet {
    pub fn with_capacity(timeout: Duration, max_entries: usize) -> Self {
        let index_capacity = initial_index_capacity(max_entries);
        Self {
            timeout,
            max_entries: max_entries.max(1),
            len: 0,
            slots: Vec::with_capacity(index_capacity),
            free: Vec::with_capacity(index_capacity),
            index: HashMap::with_capacity(index_capacity),
            order: VecDeque::with_capacity(index_capacity),
            hash_builder: RandomState::new(),
        }
    }

    pub fn insert_unique(&mut self, key: &[u8]) -> bool {
        let now = Instant::now();
        self.sweep_expired(now);
        let replay_key = ReplayKey::new(key);
        let hash = self.key_hash(&replay_key);
        self.insert_hashed(replay_key, hash, now)
    }

    fn insert_hashed(&mut self, replay_key: ReplayKey, hash: u64, now: Instant) -> bool {
        if self.contains_hashed(hash, &replay_key, now) {
            return false;
        }
        while self.len >= self.max_entries {
            if !self.evict_oldest() {
                break;
            }
        }
        let expires_at = now.checked_add(self.timeout).unwrap_or(now);
        let slot_idx = self.free.pop().unwrap_or_else(|| {
            self.slots.push(None);
            self.slots.len() - 1
        });
        self.slots[slot_idx] = Some(ReplaySlot {
            key: replay_key,
            expires_at,
            hash,
            previous: None,
            next: self.index.insert(hash, slot_idx),
        });
        if let Some(next_idx) = self.slots[slot_idx].as_ref().and_then(|slot| slot.next) {
            self.slots[next_idx]
                .as_mut()
                .expect("replay index points to a live slot")
                .previous = Some(slot_idx);
        }
        self.order.push_back(slot_idx);
        self.len += 1;
        true
    }

    fn sweep_expired(&mut self, now: Instant) {
        while let Some(&slot_idx) = self.order.front() {
            let Some(slot) = self.slots.get(slot_idx).and_then(|slot| slot.as_ref()) else {
                self.order.pop_front();
                continue;
            };
            if slot.expires_at >= now {
                break;
            }
            self.order.pop_front();
            self.remove_slot(slot_idx);
        }
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some(slot_idx) = self.order.pop_front() {
            if self.remove_slot(slot_idx) {
                return true;
            }
        }
        false
    }

    fn remove_slot(&mut self, slot_idx: usize) -> bool {
        let Some(slot) = self.slots.get_mut(slot_idx).and_then(Option::take) else {
            return false;
        };
        match slot.previous {
            Some(previous_idx) => {
                self.slots[previous_idx]
                    .as_mut()
                    .expect("replay chain points to a live slot")
                    .next = slot.next;
            }
            None => {
                if let Some(next_idx) = slot.next {
                    self.index.insert(slot.hash, next_idx);
                } else {
                    self.index.remove(&slot.hash);
                }
            }
        }
        if let Some(next_idx) = slot.next {
            self.slots[next_idx]
                .as_mut()
                .expect("replay chain points to a live slot")
                .previous = slot.previous;
        }
        self.free.push(slot_idx);
        self.len = self.len.saturating_sub(1);
        true
    }

    fn contains_hashed(&self, hash: u64, key: &ReplayKey, now: Instant) -> bool {
        let mut slot_idx = self.index.get(&hash).copied();
        while let Some(index) = slot_idx {
            let Some(slot) = self.slots.get(index).and_then(|slot| slot.as_ref()) else {
                debug_assert!(false, "replay index points to an empty slot");
                break;
            };
            if slot.key == *key && slot.expires_at > now {
                return true;
            }
            slot_idx = slot.next;
        }
        false
    }

    fn key_hash<T: Hash>(&self, value: &T) -> u64 {
        self.hash_builder.hash_one(value)
    }

    #[cfg(test)]
    fn contains(&mut self, key: &[u8]) -> bool {
        let now = Instant::now();
        self.sweep_expired(now);
        let replay_key = ReplayKey::new(key);
        self.contains_hashed(self.key_hash(&replay_key), &replay_key, now)
    }

    #[cfg(test)]
    pub(crate) fn len_for_test(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    fn insert_unique_with_hash_for_test(&mut self, key: &[u8], hash: u64) -> bool {
        let now = Instant::now();
        self.sweep_expired(now);
        self.insert_hashed(ReplayKey::new(key), hash, now)
    }

    #[cfg(test)]
    fn contains_with_hash_for_test(&self, key: &[u8], hash: u64) -> bool {
        self.contains_hashed(hash, &ReplayKey::new(key), Instant::now())
    }

    #[cfg(test)]
    fn slot_count_for_test(&self) -> usize {
        self.slots.len()
    }
}

#[derive(Clone, Debug)]
pub struct SharedReplaySet {
    inner: Arc<Mutex<TimedReplaySet>>,
}

impl SharedReplaySet {
    #[cfg(test)]
    pub fn new(timeout: Duration) -> Self {
        Self::with_capacity(timeout, usize::MAX)
    }

    pub fn with_capacity(timeout: Duration, max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TimedReplaySet::with_capacity(
                timeout,
                max_entries,
            ))),
        }
    }

    pub fn insert_unique(&self, key: &[u8]) -> bool {
        self.inner.lock().insert_unique(key)
    }
}

#[derive(Debug)]
pub struct ClientQueue {
    front: u32,
    back: u32,
    alloc: HashSet<u32>,
    enable: bool,
    last_update: Instant,
    ref_count: u32,
}

impl ClientQueue {
    pub fn new(begin_id: u32) -> Self {
        Self {
            front: begin_id.saturating_sub(64),
            back: begin_id.saturating_add(1),
            alloc: HashSet::new(),
            enable: true,
            last_update: Instant::now(),
            ref_count: 0,
        }
    }

    pub fn update(&mut self) {
        self.last_update = Instant::now();
    }

    pub fn add_ref(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    pub fn del_ref(&mut self) {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
    }

    pub fn is_active(&self) -> bool {
        self.ref_count > 0 && self.last_update.elapsed() < Duration::from_secs(60 * 10)
    }

    pub fn re_enable(&mut self, connection_id: u32) {
        self.enable = true;
        self.front = connection_id.saturating_sub(64);
        self.back = connection_id.saturating_add(1);
        self.alloc.clear();
        self.last_update = Instant::now();
    }

    pub fn insert(&mut self, connection_id: u32) -> bool {
        if !self.enable {
            return false;
        }
        if !self.is_active() {
            self.re_enable(connection_id);
        }
        self.update();

        if connection_id < self.front {
            return false;
        }
        if connection_id > self.front.saturating_add(0x4000) {
            return false;
        }
        if self.alloc.contains(&connection_id) {
            return false;
        }

        if self.back <= connection_id {
            self.back = connection_id.saturating_add(1);
        }
        self.alloc.insert(connection_id);

        while self.alloc.contains(&self.front) || self.front.saturating_add(0x1000) < self.back {
            self.alloc.remove(&self.front);
            self.front = self.front.saturating_add(1);
        }
        self.add_ref();
        true
    }
}

#[derive(Debug)]
pub struct UserClientRegistry {
    max_client: usize,
    users: HashMap<u32, HashMap<u32, ClientQueue>>,
}

impl UserClientRegistry {
    pub fn new(max_client: usize) -> Self {
        Self {
            max_client,
            users: HashMap::new(),
        }
    }

    pub fn insert(&mut self, user_id: u32, client_id: u32, connection_id: u32) -> bool {
        let local = self.users.entry(user_id).or_default();

        if let Some(queue) = local.get_mut(&client_id) {
            return queue.insert(connection_id);
        }

        if local.len() < self.max_client {
            let mut q = ClientQueue::new(connection_id);
            let ok = q.insert(connection_id);
            local.insert(client_id, q);
            return ok;
        }

        let stale_key = local
            .iter()
            .find_map(|(k, q)| if !q.is_active() { Some(*k) } else { None });
        if let Some(k) = stale_key {
            local.remove(&k);
            let mut q = ClientQueue::new(connection_id);
            let ok = q.insert(connection_id);
            local.insert(client_id, q);
            return ok;
        }

        false
    }

    pub fn update(&mut self, user_id: u32, client_id: u32) {
        if let Some(local) = self.users.get_mut(&user_id)
            && let Some(queue) = local.get_mut(&client_id)
        {
            queue.update();
        }
    }

    pub fn remove(&mut self, user_id: u32, client_id: u32) {
        if let Some(local) = self.users.get_mut(&user_id)
            && let Some(queue) = local.get_mut(&client_id)
        {
            queue.del_ref();
        }
    }
}

#[derive(Clone, Debug)]
pub struct SharedUserRegistry {
    inner: Arc<Mutex<UserClientRegistry>>,
}

impl SharedUserRegistry {
    pub fn new(max_client: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(UserClientRegistry::new(max_client))),
        }
    }

    pub fn insert(&self, user_id: u32, client_id: u32, connection_id: u32) -> bool {
        self.inner.lock().insert(user_id, client_id, connection_id)
    }

    pub fn update(&self, user_id: u32, client_id: u32) {
        self.inner.lock().update(user_id, client_id)
    }

    pub fn remove(&self, user_id: u32, client_id: u32) {
        self.inner.lock().remove(user_id, client_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionEntry {
    pub master_secret: [u8; 32],
    pub user_id: Option<u32>,
    pub udp_packet_size: u16,
    /// Stable server-side scope for the ticket family and its UDP association lineage.
    pub ticket_family_id: [u8; 16],
    /// Generation of the authenticated ticket within its family.
    pub ticket_generation: u64,
}

impl SessionEntry {
    /// Build the next authenticated ticket in this family without changing its association
    /// scope. Full handshakes and UDP bootstraps construct a fresh entry instead.
    pub fn rotated(&self, master_secret: [u8; 32]) -> Self {
        Self {
            master_secret,
            user_id: self.user_id,
            udp_packet_size: self.udp_packet_size,
            ticket_family_id: self.ticket_family_id,
            ticket_generation: self.ticket_generation.saturating_add(1),
        }
    }
}

/// A min-heap whose nodes can be updated and removed without leaving stale
/// snapshots behind. Each live ticket owns exactly one node in each index;
/// touching a ticket repairs its existing node in place instead of appending
/// another timestamp to an ever-growing log.
#[derive(Debug)]
struct TicketTimeIndex {
    heap: Vec<(Instant, [u8; 16])>,
    positions: HashMap<[u8; 16], usize>,
}

impl TicketTimeIndex {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            heap: Vec::with_capacity(capacity),
            positions: HashMap::with_capacity(capacity),
        }
    }

    fn insert(&mut self, ticket: [u8; 16], timestamp: Instant) {
        debug_assert!(
            !self.positions.contains_key(&ticket),
            "a ticket must have at most one node in a time index"
        );
        let position = self.heap.len();
        self.heap.push((timestamp, ticket));
        self.positions.insert(ticket, position);
        self.sift_up(position);
    }

    fn update(&mut self, ticket: [u8; 16], timestamp: Instant) -> bool {
        let Some(&position) = self.positions.get(&ticket) else {
            return false;
        };
        let previous = self.heap[position];
        self.heap[position] = (timestamp, ticket);
        match (timestamp, ticket).cmp(&previous) {
            Ordering::Less => {
                self.sift_up(position);
            }
            Ordering::Greater => {
                self.sift_down(position);
            }
            Ordering::Equal => {}
        }
        true
    }

    fn remove(&mut self, ticket: &[u8; 16]) -> bool {
        let Some(position) = self.positions.remove(ticket) else {
            return false;
        };
        let last = self.heap.pop().expect("time-index position has a node");
        if position == self.heap.len() {
            return true;
        }

        self.heap[position] = last;
        self.positions.insert(last.1, position);
        self.repair(position);
        true
    }

    fn pop_min(&mut self) -> Option<(Instant, [u8; 16])> {
        let (timestamp, ticket) = *self.heap.first()?;
        self.remove(&ticket);
        Some((timestamp, ticket))
    }

    fn peek(&self) -> Option<(Instant, [u8; 16])> {
        self.heap.first().copied()
    }

    fn repair(&mut self, position: usize) {
        if position > 0 && self.heap[position] < self.heap[(position - 1) / 2] {
            self.sift_up(position);
        } else {
            self.sift_down(position);
        }
    }

    fn sift_up(&mut self, mut position: usize) {
        while position > 0 {
            let parent = (position - 1) / 2;
            if self.heap[parent] <= self.heap[position] {
                break;
            }
            self.swap_nodes(parent, position);
            position = parent;
        }
    }

    fn sift_down(&mut self, mut position: usize) {
        loop {
            let left = position * 2 + 1;
            if left >= self.heap.len() {
                break;
            }
            let right = left + 1;
            let child = if right < self.heap.len() && self.heap[right] < self.heap[left] {
                right
            } else {
                left
            };
            if self.heap[position] <= self.heap[child] {
                break;
            }
            self.swap_nodes(position, child);
            position = child;
        }
    }

    fn swap_nodes(&mut self, first: usize, second: usize) {
        self.heap.swap(first, second);
        let first_ticket = self.heap[first].1;
        let second_ticket = self.heap[second].1;
        self.positions.insert(first_ticket, first);
        self.positions.insert(second_ticket, second);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.heap.len()
    }
}

#[derive(Debug)]
pub struct SessionTicketStore {
    timeout: Duration,
    max_entries: usize,
    entries: HashMap<[u8; 16], (SessionEntry, Instant, Instant)>,
    expirations: TicketTimeIndex,
    activity: TicketTimeIndex,
}

impl SessionTicketStore {
    #[cfg(test)]
    pub fn new(timeout: Duration) -> Self {
        Self::with_capacity(timeout, usize::MAX)
    }

    pub fn with_capacity(timeout: Duration, max_entries: usize) -> Self {
        let index_capacity = initial_index_capacity(max_entries);
        Self {
            timeout,
            max_entries: max_entries.max(2),
            entries: HashMap::with_capacity(index_capacity),
            expirations: TicketTimeIndex::with_capacity(index_capacity),
            activity: TicketTimeIndex::with_capacity(index_capacity),
        }
    }

    pub fn insert(&mut self, ticket: [u8; 16], entry: SessionEntry) {
        let now = Instant::now();
        self.prune_expired(now);
        self.remove(&ticket);
        self.enforce_capacity(&[]);
        self.entries.insert(ticket, (entry, now, now));
        self.expirations
            .insert(ticket, Self::deadline_for(self.timeout, now));
        self.activity.insert(ticket, now);
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn peek(&self, ticket: &[u8; 16]) -> Option<SessionEntry> {
        let now = Instant::now();
        let timeout = self.timeout;
        self.entries.get(ticket).and_then(|(entry, _, issued_at)| {
            (!Self::is_expired(timeout, *issued_at, now)).then(|| entry.clone())
        })
    }

    pub fn remove(&mut self, ticket: &[u8; 16]) -> bool {
        let Some(_) = self.entries.remove(ticket) else {
            return false;
        };
        self.expirations.remove(ticket);
        self.activity.remove(ticket);
        true
    }

    #[cfg(test)]
    pub fn touch(&mut self, ticket: &[u8; 16]) -> bool {
        let now = Instant::now();
        self.prune_expired(now);
        let timeout = self.timeout;
        let is_valid = self
            .entries
            .get(ticket)
            .is_some_and(|(_, _, issued_at)| !Self::is_expired(timeout, *issued_at, now));
        if !is_valid {
            self.remove(ticket);
            return false;
        }
        self.entries
            .get_mut(ticket)
            .expect("validated ticket disappeared while locked")
            .1 = now;
        assert!(
            self.activity.update(*ticket, now),
            "live ticket must have an activity index node"
        );
        true
    }

    fn touch_with_now(&mut self, ticket: &[u8; 16], now: Instant) -> bool {
        self.prune_expired(now);
        let timeout = self.timeout;
        let Some((_, last_seen, issued_at)) = self.entries.get(ticket) else {
            return false;
        };
        if Self::is_expired(timeout, *issued_at, now) {
            self.remove(ticket);
            return false;
        }
        if now.saturating_duration_since(*last_seen) >= SESSION_TICKET_ACTIVITY_REFRESH_INTERVAL {
            self.entries
                .get_mut(ticket)
                .expect("validated ticket disappeared while locked")
                .1 = now;
            assert!(
                self.activity.update(*ticket, now),
                "live ticket must have an activity index node"
            );
        }
        true
    }

    fn prune_expired(&mut self, now: Instant) {
        while let Some((expires_at, _)) = self.expirations.peek() {
            if expires_at >= now {
                break;
            }
            let (expires_at, ticket) = self
                .expirations
                .pop_min()
                .expect("peeked expiration must be present");
            let should_remove = self.entries.get(&ticket).is_some_and(|(_, _, issued_at)| {
                Self::deadline_for(self.timeout, *issued_at) == expires_at
                    && Self::is_expired(self.timeout, *issued_at, now)
            });
            if should_remove {
                self.remove(&ticket);
            } else if let Some((_, _, issued_at)) = self.entries.get(&ticket) {
                // This only matters for test-time timestamp overrides. Production updates
                // always repair the node before changing the timestamp.
                self.expirations
                    .insert(ticket, Self::deadline_for(self.timeout, *issued_at));
            }
        }
    }

    fn enforce_capacity(&mut self, protected: &[[u8; 16]]) {
        while self.entries.len() >= self.max_entries {
            let mut skipped = Vec::new();
            let mut oldest = None;
            while let Some((last_seen, ticket)) = self.activity.pop_min() {
                if protected.iter().any(|p| p == &ticket) {
                    skipped.push((last_seen, ticket));
                    continue;
                }
                oldest = Some(ticket);
                break;
            }
            for (last_seen, ticket) in skipped {
                self.activity.insert(ticket, last_seen);
            }
            let Some(ticket) = oldest else {
                break;
            };
            self.remove(&ticket);
        }
    }

    fn deadline_for(timeout: Duration, ts: Instant) -> Instant {
        ts.checked_add(timeout).unwrap_or(ts)
    }

    fn is_expired(timeout: Duration, ts: Instant, now: Instant) -> bool {
        now.saturating_duration_since(ts) > timeout
    }
}

fn initial_index_capacity(max_entries: usize) -> usize {
    max_entries.clamp(1, DEFAULT_INDEX_PREALLOC_CAPACITY)
}

#[derive(Clone, Debug)]
pub struct SharedSessionTicketStore {
    timeout: Duration,
    inner: Arc<RwLock<SessionTicketStore>>,
}

impl SharedSessionTicketStore {
    #[cfg(test)]
    pub fn new(timeout: Duration) -> Self {
        Self::with_capacity(timeout, usize::MAX)
    }

    pub fn with_capacity(timeout: Duration, max_entries: usize) -> Self {
        Self {
            timeout,
            inner: Arc::new(RwLock::new(SessionTicketStore::with_capacity(
                timeout,
                max_entries,
            ))),
        }
    }

    pub fn insert(&self, ticket: [u8; 16], entry: SessionEntry) {
        self.inner.write().insert(ticket, entry);
    }

    pub fn max_entries(&self) -> usize {
        self.inner.read().max_entries()
    }

    pub fn peek(&self, ticket: &[u8; 16]) -> Option<SessionEntry> {
        self.inner.read().peek(ticket)
    }

    pub fn remove(&self, ticket: &[u8; 16]) -> bool {
        self.inner.write().remove(ticket)
    }

    pub fn touch(&self, ticket: &[u8; 16]) -> bool {
        let now = Instant::now();
        {
            let inner = self.inner.read();
            let Some((_, last_seen, issued_at)) = inner.entries.get(ticket) else {
                return false;
            };
            if !SessionTicketStore::is_expired(self.timeout, *issued_at, now)
                && now.saturating_duration_since(*last_seen)
                    < SESSION_TICKET_ACTIVITY_REFRESH_INTERVAL
            {
                return true;
            }
        }
        self.inner.write().touch_with_now(ticket, now)
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn issued_age(&self, ticket: &[u8; 16]) -> Option<Duration> {
        let now = Instant::now();
        let inner = self.inner.read();
        inner.entries.get(ticket).and_then(|(_, _, issued_at)| {
            (!SessionTicketStore::is_expired(self.timeout, *issued_at, now))
                .then(|| now.saturating_duration_since(*issued_at))
        })
    }

    pub fn rotation_deadline(
        &self,
        ticket: &[u8; 16],
        rotation_interval: Duration,
    ) -> Option<Instant> {
        let now = Instant::now();
        let inner = self.inner.read();
        inner.entries.get(ticket).and_then(|(_, _, issued_at)| {
            (!SessionTicketStore::is_expired(self.timeout, *issued_at, now)).then(|| {
                issued_at
                    .checked_add(rotation_interval)
                    .unwrap_or(*issued_at)
            })
        })
    }

    #[cfg(test)]
    pub(crate) fn set_timestamp_for_test(&self, ticket: &[u8; 16], ts: Instant) -> bool {
        let mut inner = self.inner.write();
        if let Some((_, stored_ts, _)) = inner.entries.get_mut(ticket) {
            *stored_ts = ts;
            assert!(
                inner.activity.update(*ticket, ts),
                "live ticket must have an activity index node"
            );
            return true;
        }
        false
    }

    #[cfg(test)]
    pub(crate) fn set_issued_at_for_test(&self, ticket: &[u8; 16], ts: Instant) -> bool {
        let mut inner = self.inner.write();
        if let Some((_, _, issued_at)) = inner.entries.get_mut(ticket) {
            *issued_at = ts;
            let deadline = SessionTicketStore::deadline_for(inner.timeout, ts);
            assert!(
                inner.expirations.update(*ticket, deadline),
                "live ticket must have an expiration index node"
            );
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientQueue, SessionEntry, SessionTicketStore, SharedReplaySet, SharedSessionTicketStore,
        SharedUserRegistry, TimedReplaySet, UserClientRegistry,
    };
    use std::time::{Duration, Instant};

    fn test_entry() -> SessionEntry {
        SessionEntry {
            master_secret: [7_u8; 32],
            user_id: Some(1001),
            udp_packet_size: 1232,
            ticket_family_id: [0_u8; 16],
            ticket_generation: 0,
        }
    }

    #[test]
    fn session_ticket_peek_does_not_refresh_expiration() {
        let mut store = SessionTicketStore::new(Duration::from_secs(30));
        let ticket = [1_u8; 16];
        let entry = test_entry();
        store.insert(ticket, entry);

        let old_ts = Instant::now() - Duration::from_secs(29);
        store.entries.get_mut(&ticket).expect("ticket").1 = old_ts;

        let got = store.peek(&ticket);
        assert!(got.is_some(), "ticket should still be present");
        let refreshed_ts = store.entries.get(&ticket).expect("ticket").1;
        assert_eq!(
            refreshed_ts, old_ts,
            "peek should not refresh ticket timestamp"
        );
    }

    #[test]
    fn session_ticket_touch_refreshes_expiration() {
        let mut store = SessionTicketStore::new(Duration::from_secs(30));
        let ticket = [3_u8; 16];
        store.insert(ticket, test_entry());

        let old_ts = Instant::now() - Duration::from_secs(29);
        store.entries.get_mut(&ticket).expect("ticket").1 = old_ts;

        assert!(store.touch(&ticket), "touch should succeed");
        let refreshed_ts = store.entries.get(&ticket).expect("ticket").1;
        assert!(
            refreshed_ts > old_ts,
            "ticket timestamp should be refreshed"
        );
    }

    #[test]
    fn session_ticket_expires_when_issued_at_ages_out() {
        let mut store = SessionTicketStore::new(Duration::from_secs(30));
        let ticket = [2_u8; 16];
        store.insert(ticket, test_entry());
        store.entries.get_mut(&ticket).expect("ticket").2 =
            Instant::now() - Duration::from_secs(31);

        let got = store.peek(&ticket);
        assert!(got.is_none(), "aged ticket should expire");
    }

    #[test]
    fn session_ticket_touch_does_not_extend_issued_lifetime() {
        let mut store = SessionTicketStore::new(Duration::from_secs(30));
        let ticket = [8_u8; 16];
        store.insert(ticket, test_entry());
        store.entries.get_mut(&ticket).expect("ticket").2 =
            Instant::now() - Duration::from_secs(31);

        assert!(
            !store.touch(&ticket),
            "touch should fail once the issued lifetime has expired"
        );
        assert!(
            store.peek(&ticket).is_none(),
            "expired ticket should not become valid again after touch"
        );
        assert!(store.entries.is_empty());
        assert_eq!(store.activity.len(), 0);
        assert_eq!(store.expirations.len(), 0);
    }

    #[test]
    fn session_ticket_store_enforces_capacity_limit() {
        let mut store = SessionTicketStore::with_capacity(Duration::from_secs(30), 2);
        let first = [1_u8; 16];
        let second = [2_u8; 16];
        let third = [3_u8; 16];

        store.insert(first, test_entry());
        store.insert(second, test_entry());
        store.insert(third, test_entry());

        assert!(
            store.peek(&first).is_none(),
            "oldest ticket should be evicted when capacity is reached"
        );
        assert!(
            store.peek(&second).is_some(),
            "newer ticket should remain available"
        );
        assert!(
            store.peek(&third).is_some(),
            "latest ticket should be available"
        );
    }

    #[test]
    fn session_ticket_store_evicts_least_recently_seen_entry() {
        let mut store = SessionTicketStore::with_capacity(Duration::from_secs(30), 2);
        let first = [1_u8; 16];
        let second = [2_u8; 16];
        let third = [3_u8; 16];

        store.insert(first, test_entry());
        store.insert(second, test_entry());
        assert!(
            store.touch(&first),
            "touch should refresh first ticket activity"
        );
        store.insert(third, test_entry());

        assert!(
            store.peek(&first).is_some(),
            "recently touched ticket should remain available"
        );
        assert!(
            store.peek(&second).is_none(),
            "least recently seen ticket should be evicted first"
        );
        assert!(
            store.peek(&third).is_some(),
            "newly inserted ticket should remain available"
        );
    }

    #[test]
    fn shared_ticket_touch_updates_eviction_index() {
        let store = SharedSessionTicketStore::with_capacity(Duration::from_secs(30), 2);
        let first = [41_u8; 16];
        let second = [42_u8; 16];
        let third = [43_u8; 16];

        store.insert(first, test_entry());
        store.insert(second, test_entry());
        assert!(store.set_timestamp_for_test(&first, Instant::now() - Duration::from_secs(2)));
        // This exercises the throttled shared path used by the protocol.
        assert!(store.touch(&first));
        store.insert(third, test_entry());

        assert!(store.peek(&first).is_some());
        assert!(store.peek(&second).is_none());
        assert!(store.peek(&third).is_some());
    }

    #[test]
    fn session_ticket_time_indexes_follow_long_touch_and_churn() {
        let mut store = SessionTicketStore::with_capacity(Duration::from_secs(30), 4);
        let ticket = [31_u8; 16];
        store.insert(ticket, test_entry());

        for _ in 0..128 {
            assert!(store.touch(&ticket));
        }
        assert_eq!(store.activity.len(), 1);
        assert_eq!(store.expirations.len(), 1);

        assert!(store.remove(&ticket));
        assert_eq!(store.activity.len(), 0);
        assert_eq!(store.expirations.len(), 0);

        for generation in 0..128_u8 {
            let ticket = [generation; 16];
            store.insert(ticket, test_entry());
            assert_eq!(store.activity.len(), store.entries.len());
            assert_eq!(store.expirations.len(), store.entries.len());
            assert!(store.remove(&ticket));
            assert!(store.entries.is_empty());
            assert_eq!(store.activity.len(), 0);
            assert_eq!(store.expirations.len(), 0);
        }
    }

    #[test]
    fn replay_set_enforces_capacity_limit() {
        let mut replay = TimedReplaySet::with_capacity(Duration::from_secs(300), 2);
        assert!(
            replay.insert_unique(b"first"),
            "first insert should succeed"
        );
        assert!(
            replay.insert_unique(b"second"),
            "second insert should succeed"
        );
        assert_eq!(replay.len_for_test(), 2, "cache should reach its capacity");

        assert!(
            replay.insert_unique(b"third"),
            "third insert should evict the oldest entry"
        );
        assert_eq!(replay.len_for_test(), 2, "cache should remain bounded");
        assert!(
            !replay.contains(b"first"),
            "oldest entry should be evicted once the cache is full"
        );
        assert!(
            replay.contains(b"second"),
            "newer entry should remain cached"
        );
        assert!(
            replay.contains(b"third"),
            "newly inserted entry should remain cached"
        );
    }

    #[test]
    fn replay_set_reuses_slots_after_fifo_eviction() {
        let mut replay = TimedReplaySet::with_capacity(Duration::from_secs(300), 3);
        for key in [b"first".as_slice(), b"second", b"third"] {
            assert!(replay.insert_unique(key));
        }
        let allocated_slots = replay.slot_count_for_test();

        for key in [b"fourth".as_slice(), b"fifth", b"sixth", b"seventh"] {
            assert!(replay.insert_unique(key));
            assert_eq!(
                replay.slot_count_for_test(),
                allocated_slots,
                "FIFO eviction should recycle replay slots"
            );
        }
    }

    #[test]
    fn replay_set_compares_full_keys_in_a_hash_collision_chain() {
        let mut replay = TimedReplaySet::with_capacity(Duration::from_secs(300), 3);
        let hash = 0x42_u64;

        assert!(replay.insert_unique_with_hash_for_test(b"collision-a", hash));
        assert!(replay.insert_unique_with_hash_for_test(b"collision-b", hash));
        assert!(replay.insert_unique_with_hash_for_test(b"collision-c", hash));
        assert!(!replay.insert_unique_with_hash_for_test(b"collision-b", hash));
        assert!(replay.contains_with_hash_for_test(b"collision-a", hash));
        assert!(replay.contains_with_hash_for_test(b"collision-b", hash));
        assert!(replay.contains_with_hash_for_test(b"collision-c", hash));

        assert!(replay.insert_unique_with_hash_for_test(b"collision-d", hash));
        assert!(!replay.contains_with_hash_for_test(b"collision-a", hash));
        assert!(replay.contains_with_hash_for_test(b"collision-b", hash));
        assert!(replay.contains_with_hash_for_test(b"collision-c", hash));
        assert!(replay.contains_with_hash_for_test(b"collision-d", hash));
    }

    #[test]
    fn replay_set_rejects_duplicate_key_within_window() {
        let mut replay = TimedReplaySet::with_capacity(Duration::from_secs(300), 4);
        assert!(replay.insert_unique(b"dup-key"));
        assert!(
            !replay.insert_unique(b"dup-key"),
            "second insert should be rejected within replay window"
        );
    }

    #[test]
    fn shared_replay_set_rejects_duplicates() {
        let replay = SharedReplaySet::new(Duration::from_secs(300));
        assert!(replay.insert_unique(b"shared-dup"));
        assert!(!replay.insert_unique(b"shared-dup"));
    }

    #[test]
    fn client_queue_enforces_connection_id_window() {
        let mut queue = ClientQueue::new(1000);
        assert!(queue.insert(1000), "initial id should be accepted");
        assert!(
            !queue.insert(1000),
            "duplicate connection id should be rejected"
        );
        assert!(
            !queue.insert(900),
            "ids older than the sliding front should be rejected"
        );
        assert!(
            !queue.insert(1000 + 0x5000),
            "far-future ids outside the acceptance window should be rejected"
        );
        assert!(queue.insert(1001), "next in-window id should be accepted");
    }

    #[test]
    fn user_client_registry_tracks_client_lifecycle() {
        let mut registry = UserClientRegistry::new(2);
        assert!(registry.insert(7, 11, 100));
        registry.update(7, 11);
        registry.remove(7, 11);

        let queue = registry
            .users
            .get(&7)
            .and_then(|local| local.get(&11))
            .expect("client queue");
        assert_eq!(queue.ref_count, 0, "remove should release one reference");
    }

    #[test]
    fn shared_user_registry_rejects_duplicate_connection_ids() {
        let registry = SharedUserRegistry::new(2);
        assert!(registry.insert(9, 15, 200));
        assert!(
            !registry.insert(9, 15, 200),
            "duplicate connection ids for the same user/client should be rejected"
        );
    }

    #[test]
    fn shared_session_ticket_store_reports_issued_age() {
        let store = SharedSessionTicketStore::new(Duration::from_secs(30));
        let ticket = [9_u8; 16];
        store.insert(ticket, test_entry());
        let old_issued_at = Instant::now() - Duration::from_secs(7);
        assert!(
            store.set_issued_at_for_test(&ticket, old_issued_at),
            "test ticket should allow issued-at override"
        );

        let age = store.issued_age(&ticket).expect("issued age");
        assert!(
            age >= Duration::from_secs(7),
            "issued age should reflect the overridden issue time: {age:?}"
        );
    }

    #[test]
    fn shared_session_ticket_store_reports_rotation_deadline_for_valid_ticket() {
        let store = SharedSessionTicketStore::new(Duration::from_secs(30));
        let ticket = [10_u8; 16];
        store.insert(ticket, test_entry());
        let issued_at = Instant::now() - Duration::from_secs(7);
        assert!(store.set_issued_at_for_test(&ticket, issued_at));

        assert_eq!(
            store.rotation_deadline(&ticket, Duration::from_secs(10)),
            issued_at.checked_add(Duration::from_secs(10))
        );
        assert!(store.remove(&ticket));
        assert_eq!(
            store.rotation_deadline(&ticket, Duration::from_secs(10)),
            None,
            "removed tickets must not retain a private rotation deadline"
        );
    }
}

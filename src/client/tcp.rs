use crate::buffer::PrefixBuffer;
use crate::client::{Client, ClientInner, TicketCache};
use crate::crypto::Aes128GcmCipher;
use crate::udp_wire::UDP_V2_DEFAULT_PACKET_SIZE;
use crate::wire::{
    AEAD_KEY_LEN, CLIENT_HELLO_FLAG_RESUME, CLIENT_HELLO_PREFIX_LEN, CLIENT_HELLO_SEED_LEN,
    COUNTER_WINDOW, ClientHello, FRAME_HEADER_LEN, FRAME_OUTER_LEN, FRAME_TAG_LEN,
    KEY_UPDATE_SALT_LEN, LenKey, MAX_FRAME_PLAIN_LEN, SERVER_FRAME_FLAG_KEY_UPDATE,
    SERVER_FRAME_FLAG_TICKET_UPDATE, SERVER_HELLO_FLAG_RESUME, SERVER_HELLO_LEN, ServerHello,
    TICKET_ROTATION_METADATA_LEN, TICKET_ROTATION_SECRET_LEN, TICKET_ROTATION_TICKET_LEN,
    TransportKeys, decode_frame_len, derive_master_secret, derive_resume_master_secret,
    derive_resumption_secret, derive_server_confirm_tag, derive_server_key_update,
    derive_transport_keys, encode_frame_len, frame_aad, frame_nonce, password_scalar,
    random_scalar, spake_point, transcript_hash,
};
use anyhow::{Result, anyhow, bail};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::{RngExt, rng};
use std::sync::Arc;

/// Client side of one auth_akarin_v2 TCP connection.
///
/// The session is sans-IO. Call [`encode`](Self::encode) with the first
/// payload (it returns the client hello and holds the payload back), write
/// the result, then feed server bytes to [`decode`](Self::decode). Once the
/// server hello verifies, [`take_pending_encoded`](Self::take_pending_encoded)
/// yields the held-back payload as records. Report every write through
/// [`on_flushed`](Self::on_flushed) before producing the next one.
pub struct TcpClientSession {
    client: Arc<ClientInner>,
    method: &'static str,
    user_id: Option<u32>,
    client_id: u32,
    connection_id: u32,
    client_overhead: u16,
    tcp_mss: u16,
    peer_tcp_mss: u16,
    unit_len: usize,
    recv_buf: PrefixBuffer,
    // Body ciphertext length for the frame at the front of `recv_buf`, decoded once and reused
    // until that frame is consumed or the rx key material changes.
    pending_frame_body_len: Option<usize>,
    handshake_sent: bool,
    handshake_done: bool,
    pending_plain: Vec<u8>,
    pending_wire: Option<Vec<u8>>,
    hello: Option<ClientHello>,
    client_scalar: Option<Scalar>,
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
    current_ticket: Option<[u8; 16]>,
    resumption_secret: Option<[u8; 32]>,
    admission_ticket: Option<[u8; 16]>,
    admission_resumption_secret: Option<[u8; 32]>,
    // A handshake-issued ticket waiting to be published to the shared cache. Set once
    // ServerHello is verified, and only published once this connection has actually sent its
    // first authenticated record, mirroring the server's own commit point.
    pending_handshake_ticket_publish: Option<([u8; 16], [u8; 32])>,
    master_secret: Option<[u8; 32]>,
    ticket_cache_revision: u64,
}

impl TcpClientSession {
    pub(crate) fn new(client: &Client, connection_id: u32) -> Self {
        let shared = client.inner.clone();
        let mut protocol = Self {
            method: shared.method.label(),
            user_id: shared.user_id,
            client_id: shared.client_id,
            connection_id,
            client_overhead: shared.overhead,
            tcp_mss: shared.tcp_mss,
            peer_tcp_mss: shared.tcp_mss,
            unit_len: MAX_FRAME_PLAIN_LEN,
            recv_buf: PrefixBuffer::new(),
            pending_frame_body_len: None,
            handshake_sent: false,
            handshake_done: false,
            pending_plain: Vec::new(),
            pending_wire: None,
            hello: None,
            client_scalar: None,
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
            current_ticket: None,
            resumption_secret: None,
            admission_ticket: None,
            admission_resumption_secret: None,
            pending_handshake_ticket_publish: None,
            master_secret: None,
            ticket_cache_revision: u64::MAX,
            client: shared,
        };
        protocol.load_ticket_cache();
        protocol
    }

    fn tickets(&self) -> &TicketCache {
        &self.client.tickets
    }

    fn load_ticket_cache(&mut self) {
        self.ticket_cache_revision = self.tickets().revision();
        let Some(cached) = self.tickets().load() else {
            self.current_ticket = None;
            self.resumption_secret = None;
            return;
        };
        self.current_ticket = Some(cached.ticket);
        self.resumption_secret = Some(cached.ticket_secret);
    }

    fn sync_ticket_cache(&mut self) {
        let revision = self.tickets().revision();
        if revision != self.ticket_cache_revision {
            // Ticket identity is shared across transports; TCP MSS remains connection-local.
            self.load_ticket_cache();
        }
    }

    fn publish_ticket_cache(&self, ticket: [u8; 16], resumption_secret: [u8; 32]) {
        // A TCP handshake learns nothing about the UDP path, so a ticket it
        // publishes carries the safe default datagram size.
        self.tickets()
            .publish_fresh(ticket, resumption_secret, UDP_V2_DEFAULT_PACKET_SIZE as u16);
        // The server minted this ticket in a hello whose confirmation tag was
        // verified before we got here, so it is proven the moment it is
        // published. Saying so spares the first association that picks it up a
        // liveness probe for something already known.
        self.tickets().confirm(&ticket);
    }

    fn build_client_hello(&mut self) -> Result<Vec<u8>> {
        let client_scalar = random_scalar();
        let resume_ticket = self.current_ticket.zip(self.resumption_secret);
        let client_share = if resume_ticket.is_some() {
            (RISTRETTO_BASEPOINT_POINT * client_scalar)
                .compress()
                .to_bytes()
        } else {
            let password_scalar =
                password_scalar(&self.client.user_key, self.method, self.user_id)?;
            (RISTRETTO_BASEPOINT_POINT * client_scalar + spake_point(b"M") * password_scalar)
                .compress()
                .to_bytes()
        };

        let mut prefix = [0_u8; CLIENT_HELLO_PREFIX_LEN];
        let mut client_nonce = [0_u8; 16];
        let mut hello_seed = [0_u8; CLIENT_HELLO_SEED_LEN];
        rng().fill(&mut prefix);
        rng().fill(&mut client_nonce);
        rng().fill(&mut hello_seed);

        let hello = ClientHello {
            prefix,
            flags: if resume_ticket.is_some() {
                CLIENT_HELLO_FLAG_RESUME
            } else {
                0
            },
            user_id: self.user_id.unwrap_or(0),
            client_id: self.client_id,
            connection_id: self.connection_id,
            client_overhead: self.client_overhead,
            tcp_mss: self.tcp_mss,
            client_nonce,
            ticket: resume_ticket
                .map(|(ticket, _)| ticket)
                .unwrap_or([0_u8; 16]),
            client_share,
            hello_seed,
        };
        let encoded = hello.encode();
        if let Some((ticket, secret)) = resume_ticket {
            self.admission_ticket = Some(ticket);
            self.admission_resumption_secret = Some(secret);
        } else {
            self.admission_ticket = None;
            self.admission_resumption_secret = None;
        }
        self.hello = Some(hello);
        self.client_scalar = Some(client_scalar);
        Ok(encoded)
    }

    fn init_transport_from_server_hello(&mut self, server_hello: &ServerHello) -> Result<()> {
        let hello = self
            .hello
            .as_ref()
            .ok_or_else(|| anyhow!("auth_akarin_v2 client hello missing"))?;
        let client_resumed = (hello.flags & CLIENT_HELLO_FLAG_RESUME) != 0;
        let server_resumed = (server_hello.flags & SERVER_HELLO_FLAG_RESUME) != 0;
        if client_resumed != server_resumed {
            bail!("auth_akarin_v2 resume acknowledgement mismatch");
        }
        let client_scalar = self
            .client_scalar
            .ok_or_else(|| anyhow!("auth_akarin_v2 client scalar missing"))?;
        let server_share = CompressedRistretto(server_hello.server_share)
            .decompress()
            .ok_or_else(|| anyhow!("invalid auth_akarin_v2 server share"))?;
        let transcript_hash = transcript_hash(self.method, self.user_id, hello, server_hello);
        let (master_secret, resumption_secret) = if server_resumed {
            let previous_secret = self
                .admission_resumption_secret
                .ok_or_else(|| anyhow!("auth_akarin_v2 resume secret missing"))?;
            let previous_ticket = self
                .admission_ticket
                .ok_or_else(|| anyhow!("auth_akarin_v2 resume ticket missing"))?;
            if server_hello.ticket != previous_ticket {
                bail!("auth_akarin_v2 resume acknowledgement ticket mismatch");
            }
            let shared = server_share * client_scalar;
            let master_secret =
                derive_resume_master_secret(&shared, &previous_secret, &transcript_hash)?;
            (master_secret, previous_secret)
        } else {
            let password_scalar =
                password_scalar(&self.client.user_key, self.method, self.user_id)?;
            let shared = (server_share - spake_point(b"N") * password_scalar) * client_scalar;
            let master_secret = derive_master_secret(&shared, &transcript_hash)?;
            let resumption_secret = derive_resumption_secret(&master_secret, &transcript_hash)?;
            (master_secret, resumption_secret)
        };
        let expected_tag = derive_server_confirm_tag(&master_secret, &transcript_hash)?;
        if expected_tag != server_hello.tag {
            bail!("auth_akarin_v2 server confirmation tag mismatch");
        }
        if server_resumed {
            // A valid tag on a resumed hello proves the server still recognizes this exact
            // ticket, so record it here once instead of every association sharing the cache
            // slot having to re-derive the same fact through a liveness probe.
            self.client.tickets.confirm(&server_hello.ticket);
        }

        let TransportKeys {
            c2s_key: tx_key,
            s2c_key: rx_key,
            c2s_len_key: tx_len_key,
            s2c_len_key: rx_len_key,
            c2s_nonce: tx_nonce,
            s2c_nonce: rx_nonce,
        } = derive_transport_keys(&master_secret, &transcript_hash)?;
        self.tx_cipher = Some(Aes128GcmCipher::new(&tx_key));
        self.rx_cipher = Some(Aes128GcmCipher::new(&rx_key));
        self.tx_key = Some(tx_key);
        self.rx_key = Some(rx_key);
        self.tx_len_key = Some(LenKey::new(tx_len_key));
        self.rx_len_key = Some(LenKey::new(rx_len_key));
        self.tx_nonce_prefix = tx_nonce;
        self.rx_nonce_prefix = rx_nonce;
        self.tx_counter = 1;
        self.rx_counter = 1;
        self.current_ticket = Some(server_hello.ticket);
        self.resumption_secret = Some(resumption_secret);
        self.master_secret = Some(master_secret);
        self.peer_tcp_mss = server_hello.tcp_mss;
        if !server_resumed {
            // A resumed ticket is unchanged and already in the shared cache (or is about to
            // be re-published from a rotation), so only a freshly issued ticket needs staging.
            self.pending_handshake_ticket_publish = Some((server_hello.ticket, resumption_secret));
        }
        self.admission_ticket = None;
        self.admission_resumption_secret = None;
        self.unit_len = MAX_FRAME_PLAIN_LEN;
        self.handshake_done = true;
        Ok(())
    }

    fn ensure_frame_counter_window(counter: u32) -> Result<()> {
        if counter > u32::MAX - COUNTER_WINDOW {
            bail!("auth_akarin_v2 frame counter exhausted");
        }
        Ok(())
    }

    fn encode_frame_into(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        Self::ensure_frame_counter_window(self.tx_counter)?;
        let cipher = self
            .tx_cipher
            .as_ref()
            .ok_or_else(|| anyhow!("auth_akarin_v2 tx cipher is not initialized"))?;
        let tx_len_key = self
            .tx_len_key
            .as_ref()
            .ok_or_else(|| anyhow!("auth_akarin_v2 tx length key is not initialized"))?;
        let payload_len = u16::try_from(payload.len()).map_err(|_| anyhow!("payload too large"))?;

        let mut header_plain = [0_u8; FRAME_HEADER_LEN];
        header_plain[0..2].copy_from_slice(&payload_len.to_le_bytes());
        let body_cipher_len = FRAME_HEADER_LEN + payload.len() + FRAME_TAG_LEN;
        let masked_len = encode_frame_len(
            &tx_len_key.cipher,
            &self.tx_nonce_prefix,
            self.tx_counter,
            body_cipher_len,
        )?;
        let body_nonce = frame_nonce(&self.tx_nonce_prefix, self.tx_counter);
        let body_aad = frame_aad(self.tx_counter, &masked_len);

        out.reserve(FRAME_OUTER_LEN + FRAME_HEADER_LEN + payload.len() + FRAME_TAG_LEN);
        out.extend_from_slice(&masked_len);
        let body_start = out.len();
        out.extend_from_slice(&header_plain);
        out.extend_from_slice(payload);
        let body_end = out.len();
        let body_tag =
            cipher.encrypt_detached(&body_nonce, &body_aad, &mut out[body_start..body_end])?;
        out.extend_from_slice(&body_tag);
        self.tx_counter += COUNTER_WINDOW;
        Ok(())
    }

    fn encode_frames_into(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        let mut start = 0_usize;
        while start < input.len() {
            let end = start + self.unit_len.min(input.len() - start);
            self.encode_frame_into(&input[start..end], out)?;
            start = end;
        }
        if input.is_empty() {
            self.encode_frame_into(input, out)?;
        }
        Ok(())
    }

    fn decode_frames(&mut self, out_buf: &mut Vec<u8>) -> Result<()> {
        loop {
            if self.recv_buf.len() < FRAME_OUTER_LEN {
                break;
            }
            Self::ensure_frame_counter_window(self.rx_counter)?;
            let masked_len: [u8; FRAME_OUTER_LEN] =
                self.recv_buf[..FRAME_OUTER_LEN].try_into().unwrap();
            let body_cipher_len = match self.pending_frame_body_len {
                Some(len) => len,
                None => {
                    let rx_len_key = self.rx_len_key.as_ref().ok_or_else(|| {
                        anyhow!("auth_akarin_v2 rx length key is not initialized")
                    })?;
                    let len = decode_frame_len(
                        &rx_len_key.cipher,
                        &self.rx_nonce_prefix,
                        self.rx_counter,
                        &masked_len,
                    );
                    self.pending_frame_body_len = Some(len);
                    len
                }
            };
            if body_cipher_len < FRAME_HEADER_LEN + FRAME_TAG_LEN {
                bail!("auth_akarin_v2 frame body is too short");
            }
            let max_body_cipher_len = FRAME_HEADER_LEN + MAX_FRAME_PLAIN_LEN + FRAME_TAG_LEN;
            if body_cipher_len > max_body_cipher_len {
                bail!("auth_akarin_v2 frame exceeds maximum plain length");
            }
            let frame_len = FRAME_OUTER_LEN + body_cipher_len;
            if self.recv_buf.len() < frame_len {
                break;
            }

            let cipher = self
                .rx_cipher
                .as_ref()
                .ok_or_else(|| anyhow!("auth_akarin_v2 rx cipher is not initialized"))?;
            let body_nonce = frame_nonce(&self.rx_nonce_prefix, self.rx_counter);
            let body_cipher_end = frame_len - FRAME_TAG_LEN;
            let body_tag: [u8; FRAME_TAG_LEN] = self.recv_buf[body_cipher_end..frame_len]
                .try_into()
                .unwrap();
            let body_aad = frame_aad(self.rx_counter, &masked_len);
            let mut next_ticket = None;
            let mut key_update_salt = None;
            {
                let recv_slice = self.recv_buf.as_mut_slice();
                let body_cipher = &mut recv_slice[FRAME_OUTER_LEN..body_cipher_end];
                cipher.decrypt_detached(&body_nonce, &body_aad, body_cipher, &body_tag)?;
                let header_plain: [u8; FRAME_HEADER_LEN] =
                    body_cipher[..FRAME_HEADER_LEN].try_into().unwrap();
                let payload_len =
                    u16::from_le_bytes(header_plain[0..2].try_into().unwrap()) as usize;
                let pad_len = u16::from_le_bytes(header_plain[2..4].try_into().unwrap()) as usize;
                let flags = header_plain[4];
                let metadata_len =
                    u16::from_le_bytes(header_plain[6..8].try_into().unwrap()) as usize;
                let body_plain_len = metadata_len + payload_len + pad_len;
                if body_plain_len > MAX_FRAME_PLAIN_LEN {
                    bail!("auth_akarin_v2 frame exceeds maximum plain length");
                }
                if body_cipher.len() != FRAME_HEADER_LEN + body_plain_len {
                    bail!("auth_akarin_v2 frame body length mismatch");
                }
                let mut offset = FRAME_HEADER_LEN;
                if (flags & SERVER_FRAME_FLAG_TICKET_UPDATE) != 0 {
                    if body_cipher.len() < offset + TICKET_ROTATION_METADATA_LEN {
                        bail!("auth_akarin_v2 ticket update metadata truncated");
                    }
                    let ticket: [u8; TICKET_ROTATION_TICKET_LEN] = body_cipher
                        [offset..offset + TICKET_ROTATION_TICKET_LEN]
                        .try_into()
                        .unwrap();
                    offset += TICKET_ROTATION_TICKET_LEN;
                    let secret: [u8; TICKET_ROTATION_SECRET_LEN] = body_cipher
                        [offset..offset + TICKET_ROTATION_SECRET_LEN]
                        .try_into()
                        .unwrap();
                    offset += TICKET_ROTATION_SECRET_LEN;
                    next_ticket = Some((ticket, secret));
                }
                if (flags & SERVER_FRAME_FLAG_KEY_UPDATE) != 0 {
                    if body_cipher.len() < offset + KEY_UPDATE_SALT_LEN {
                        bail!("auth_akarin_v2 key update metadata truncated");
                    }
                    key_update_salt = Some(
                        body_cipher[offset..offset + KEY_UPDATE_SALT_LEN]
                            .try_into()
                            .unwrap(),
                    );
                    offset += KEY_UPDATE_SALT_LEN;
                }
                if offset != FRAME_HEADER_LEN + metadata_len {
                    bail!("auth_akarin_v2 server metadata length mismatch");
                }
                let payload_start = FRAME_HEADER_LEN + metadata_len;
                out_buf.extend_from_slice(&body_cipher[payload_start..payload_start + payload_len]);
            }
            if let Some((ticket, secret)) = next_ticket {
                let expected_ticket = self.current_ticket;
                let advanced = expected_ticket
                    .is_some_and(|expected| self.client.tickets.advance(&expected, ticket, secret));
                // The authenticated connection always follows the server's successor. A CAS
                // failure only means a newer shared publication won the race; it must not make
                // this established connection switch to that competing branch.
                self.current_ticket = Some(ticket);
                self.resumption_secret = Some(secret);
                if advanced {
                    self.ticket_cache_revision = self.client.tickets.revision();
                }
            }
            if let Some(salt) = key_update_salt {
                let master_secret = self
                    .master_secret
                    .ok_or_else(|| anyhow!("auth_akarin_v2 master secret is missing"))?;
                let (rx_key, rx_len_key, rx_nonce) =
                    derive_server_key_update(self.method, &master_secret, &salt)?;
                self.rx_key = Some(rx_key);
                self.rx_len_key = Some(LenKey::new(rx_len_key));
                self.rx_cipher = Some(Aes128GcmCipher::new(&rx_key));
                self.rx_nonce_prefix = rx_nonce;
                self.rx_counter = 1;
                self.pending_frame_body_len = None;
            } else {
                self.rx_counter += COUNTER_WINDOW;
            }
            self.recv_buf.consume(frame_len);
            self.pending_frame_body_len = None;
        }
        Ok(())
    }
}

impl TcpClientSession {
    /// Whether the server hello verified and payload now flows as records.
    pub fn is_established(&self) -> bool {
        self.handshake_done
    }

    /// Call when the server closed the connection before its hello arrived.
    /// If this session tried to resume, the server most likely no longer
    /// knows the ticket, so it is dropped from the shared cache and the next
    /// session does a full handshake. Returns whether a ticket was dropped.
    pub fn discard_rejected_ticket(&mut self) -> bool {
        if self.handshake_done {
            return false;
        }
        let Some(ticket) = self.admission_ticket.take() else {
            return false;
        };
        self.admission_resumption_secret = None;
        self.client.tickets.discard(&ticket);
        true
    }

    /// Encodes `input` for the server into `out` (after clearing it).
    ///
    /// The first call emits the client hello and holds `input` back; until
    /// the handshake completes, further input is held back too and `out`
    /// stays empty.
    pub fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if !self.handshake_sent {
            self.sync_ticket_cache();
            self.handshake_sent = true;
            self.pending_plain.extend_from_slice(input);
            out.clear();
            out.extend_from_slice(&self.build_client_hello()?);
            return Ok(());
        }
        if !self.handshake_done {
            self.pending_plain.extend_from_slice(input);
            out.clear();
            return Ok(());
        }
        self.encode_frames_into(input, out)
    }

    /// Feeds bytes read from the server and writes every authenticated
    /// payload byte into `out` (after clearing it). When this input completes
    /// the handshake, check [`take_pending_encoded`](Self::take_pending_encoded).
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        self.recv_buf.extend_from_slice(input);
        if !self.handshake_done {
            if self.recv_buf.len() < SERVER_HELLO_LEN {
                return Ok(());
            }
            let server_hello = ServerHello::parse(&self.recv_buf[..SERVER_HELLO_LEN])?;
            self.recv_buf.consume(SERVER_HELLO_LEN);
            self.init_transport_from_server_hello(&server_hello)?;
            if !self.pending_plain.is_empty() {
                let pending = std::mem::take(&mut self.pending_plain);
                let mut pending_wire = Vec::new();
                self.encode_frames_into(&pending, &mut pending_wire)?;
                self.pending_wire = Some(pending_wire);
            }
        }
        self.decode_frames(out)?;
        Ok(())
    }

    /// Records for the payload held back during the handshake, available once
    /// the handshake completes. Write them before any later output.
    pub fn take_pending_encoded(&mut self) -> Option<Vec<u8>> {
        self.pending_wire.take()
    }

    /// Reports whether the bytes from the last write reached the socket. A
    /// ticket from a full handshake is shared with other sessions only after
    /// this connection's first record was delivered, matching the point at
    /// which the server commits it.
    pub fn on_flushed(&mut self, delivered: bool) {
        let Some((ticket, secret)) = self.pending_handshake_ticket_publish.take() else {
            return;
        };
        if delivered {
            self.publish_ticket_cache(ticket, secret);
        }
    }
}

# auth_akarin_v2 Protocol Specification

> **COPYRIGHT NOTICE & LEGAL RESTRICTIONS**
>
> **Copyright (c) 2026 新しい世界. All rights reserved.**
>
> This repository is published for reference only.
> No permission is granted to copy, redistribute, modify, or publish this document, except as permitted by applicable law.

### 1. Scope

This document specifies the protocol layer for:

* `auth_akarin_spec_a_v2`
* `auth_akarin_spec_time_v2`

Obfuscation is out of scope.

### 2. Design Goals

The `v2` design targets:

* removal of the legacy first-packet offline password-verification surface
* time-rotating traffic shaping
* a shared resumable session model for TCP and UDP
* resumable tickets, cross-transport reuse, and UDP 0-RTT

Protocol features:

* PAKE-style full handshakes
* cross-transport resumable ticket secrets
* AEAD-protected records
* ticket update metadata
* epoch-based traffic shaping

### 3. Methods and Parameters

#### 3.1 Methods

* `auth_akarin_spec_a_v2`
* `auth_akarin_spec_time_v2`

#### 3.2 Required Inputs

The names in parentheses are the corresponding fields of the reference implementation's `ServerConfig` and `ClientConfig`.

* `password` (`password`)
  Long-term protocol secret used when no per-user key is configured.

* `users` (`ServerConfig::users`, `ClientConfig::user`)
  Optional `uid -> user_key` mapping. A client configures at most one entry.

* `max_client` (`ServerConfig::max_client`)
  How many distinct client ids each user may hold at once; the default is 64.

* `interval` (`Method::SpecTime { interval_secs }`)
  For `spec_time_v2`, the shaping interval in seconds; the default is 3600 seconds. Both peers must use the same interval.

* `tcp_replay_window` (`ServerConfig::tcp_replay_window`)
  How long a TCP Client Hello replay key is remembered; the default is 300 seconds.

* `overhead` (`ClientConfig::overhead`)
  Legacy compatibility input carried in the TCP Client Hello. In v2 it is bound into the transcript as compatibility metadata; record sizing is controlled by the negotiated TCP MSS and v2 framing rules.

* `tcp_mss` (`tcp_mss`)
  Local TCP MSS fallback preference. `0` selects the default 1460, and non-zero values are clamped to `500..1500`. When the server can read TCP_MAXSEG from the accepted socket, that value replaces the configured fallback after the same normalization (`TcpServerSession::set_tcp_mss`).

* `udp_packet_size` (`udp_packet_size`)
  Local UDP Data Packet wire-size preference. `0` selects the default 1232, and non-zero values are clamped to `576..1500` before bootstrap negotiation.

#### 3.3 User Resolution

If `users` is empty:

* `selected_user_id = None`
* `user_key = password`

Otherwise:

* if `user_id_field` exists in `users`:

  * `selected_user_id = Some(user_id_field)`
  * `user_key = users[user_id_field]`

* otherwise:

  * `selected_user_id = Some(user_id_field)`
  * `user_key = HMAC-SHA256(password, method || 0xff || little_endian_u32(user_id_field))`

Unknown-user full TCP handshakes and UDP bootstrap exchanges use equivalent-cost behavior, but do not commit usable tickets or registry entries. The decoy key is computable from `password`, so in multi-user mode `password` is a master credential: a holder of it can complete a TCP handshake under any unknown `user_id_field` and send data on that connection. TCP resume first requires the presented ticket to exist in this method's ticket store and its stored `user_id` to match; an unknown ticket or user mismatch is rejected before fresh DH processing.

### 4. Time and Epochs

#### 4.1 `spec_a_v2`

```text
epoch = 0
```

#### 4.2 `spec_time_v2`

For TCP:

```text
raw_epoch        = floor(server_time / interval)
hysteresis_secs  = min(2, interval - 1)

if a previous TCP shape profile exists and
   raw_epoch > previous_profile_epoch and
   server_time % interval < hysteresis_secs:
  effective_tcp_epoch = previous_profile_epoch
else:
  effective_tcp_epoch = raw_epoch
```

The TCP epoch is not transmitted and is not part of the TCP handshake transcript. `effective_tcp_epoch` is used for TCP shaping (section 7.8); it is not an input to resume or to ticket rotation, which are both epoch-independent for TCP (section 6.3). With no previous profile, the current `raw_epoch` is used. The hysteresis period is 0 seconds for interval 1, 1 second for interval 2, and 2 seconds for intervals of at least 3 seconds.

For UDP:

* data packets carry an explicit `epoch`
* receivers accept:

  * `epoch - 1`
  * `epoch`
  * `epoch + 1`

### 5. Encryption and Authentication Parameters

Current implementation parameters:

* group: Ristretto255
* hash-to-group: SHA-512 + `RistrettoPoint::from_uniform_bytes`
* scalar derivation: HKDF-SHA256
* transcript hash: SHA-256
* AEAD: AES-128-GCM
* confirmation tag: HMAC-SHA256 truncated to 16 bytes

#### 5.1 Mask Points

```text
M = HashToGroup("ssrr-auth-akarin-v2-spake2:" || "M")
N = HashToGroup("ssrr-auth-akarin-v2-spake2:" || "N")
```

#### 5.2 Password-Derived Scalars

TCP full-handshake scalar:

```text
password_scalar_tcp =
  Scalar::from_bytes_mod_order_wide(
    HKDF-SHA256(
      ikm  = user_key,
      salt = method || 0x00 || user_id_context,
      info = "ssrr-auth-akarin-v2-password-scalar",
      L    = 64
    )
  )
```

UDP bootstrap scalar:

```text
password_scalar_udp =
  Scalar::from_bytes_mod_order_wide(
    HKDF-SHA256(
      ikm  = user_key,
      salt = method || 0x00 || user_id_context,
      info = "ssrr-auth-akarin-v2-udp-password-scalar",
      L    = 64
    )
  )
```

Where:

* single-user mode: `user_id_context = 0x00`
* multi-user mode: `user_id_context = 0x01 || little_endian_u32(uid)`

This is a SPAKE2-like construction. Received Ristretto points are strictly decoded and rejected on failure.

### 6. Session Model

`v2` uses a shared ticket family across transports.

Secrets:

* `master_secret`
  Application secret for the current TCP connection or UDP bootstrap result.

* `ticket_secret`
  Resumable secret stored under a session ticket. Used for TCP resume, UDP ticket-based 0-RTT, and ticket rotation.

* `next_ticket_secret`
  Successor secret for a rotated ticket. Generated at random by the server; never derived from `ticket_secret`, `current_ticket`, or any other existing value (section 6.3).

#### 6.1 Full Handshake

Full handshake flow:

* perform a fresh PAKE exchange
* derive a fresh `master_secret`
* derive:

```text
ticket_secret = HKDF(master_secret, transcript_hash, "ssrr-auth-akarin-v2-resumption")
```

* issue a fresh 16-byte opaque resume token
* store a `SessionEntry` with:

  * `master_secret = ticket_secret`
  * `user_id`
  * `udp_packet_size`

For TCP-issued tickets:

```text
udp_packet_size = 1232
```

For UDP-issued tickets, `udp_packet_size` is the negotiated `effective_udp_packet_size` from section 8.8.

TCP-issued tickets are staged until ServerHello delivery succeeds and committed after the first authenticated client record. UDP-issued tickets are staged after the bootstrap response is sent and committed after the first authenticated unfragmented UDP Data Packet, or after an authenticated fragment set completes reassembly, for that ticket. An authenticated fragment that leaves reassembly incomplete does not commit the ticket.

#### 6.2 Resume

Resume flow:

* present an existing ticket
* mix the stored `ticket_secret` with a fresh DH share
* derive a fresh connection `master_secret`
* echo the presented ticket unchanged; the connection's resumption secret remains the stored `ticket_secret`

Resume is read-only with respect to the shared ticket store beyond refreshing the presented ticket's activity: it does not derive or issue a successor ticket, and it does not remove or replace the presented ticket on any path. Ticket age is not reset by resume; rotation stays purely time-based from the ticket's issuance (section 6.3).

A ticket store holds the tickets of exactly one method, so a ticket issued under one method is never accepted under the other. TCP resume additionally validates `user_id`. UDP possession is proven by AEAD authentication under the stored ticket secret.

#### 6.3 Ticket Rotation

```text
rotation_interval = session_ticket_timeout / 2
```

`session_ticket_timeout` is the shared ticket store lifetime. It defaults to 1800 seconds (`ServerConfig::ticket_lifetime`).

A ticket rotates when its issued age — the time since it was inserted into the shared session ticket store, not the age of the TCP connection or UDP association currently presenting it — reaches `rotation_interval`. This rule is the same for TCP and UDP (see also section 8.5). A ticket's issuance timestamp is set once, at the moment it is committed to the store (section 6.1); resuming a ticket, or continuing to use it on a long-lived connection, does not reset that timestamp.

Successor ticket material is generated by the server, not derived:

* `next_ticket` is a fresh opaque resume token, generated the same way as a full-handshake ticket (section 6.1).
* `next_ticket_secret` is 32 random bytes from the same CSPRNG.

Neither value is a function of `current_ticket`, `current_ticket_secret`, `epoch`, the fresh DH share, or the resumed connection's `master_secret`. The client stores exactly the `next_ticket` and `next_ticket_secret` it receives; it performs no computation to accept or verify them.

Because `next_ticket_secret` is random server output carried under the current transport's protected keys rather than a function of `current_ticket_secret`, a party that later obtains an isolated `current_ticket_secret` cannot compute any successor material for that ticket family from it. For TCP, that protection is complete: successor material travels only inside a record protected by the connection's current transport keys (section 7.6), so recovering it requires those keys, not just the old ticket secret. For UDP, the protection is partial: a `next_ticket`/`next_ticket_secret` pair is carried inside a UDP Data Packet encrypted under `udp_epoch_key`, which is itself derived from the *current* `ticket_secret` (section 8.3). A party that already holds `current_ticket_secret` can therefore still decrypt a rotation it intercepts for that ticket, even though it cannot forge or predict the successor values in advance. Full UDP post-compromise recovery would require rotation to run under a freshly established (EC)DH secret instead of the current ticket secret; this design does not add that. An independently authenticated full handshake or UDP bootstrap creates a new ticket family unaffected by a compromise of a previous family's tickets.

For periodic TCP rotation, successor material is carried in a record protected by the current transport keys. The successor ticket is inserted into the shared store and becomes the connection's current ticket only after delivery of the encoded output succeeds; failed delivery discards the pending rotation, and the old ticket remains valid until normal expiry.

Opaque token encoding:

* wire length: 16 bytes
* entropy payload: 80 bits
* the 80-bit payload is encoded as 16 symbols from a 32-value low-density alphabet
* each emitted byte has popcount `<= 2`

#### 6.4 Concurrent Resumption

Resume is read-only (section 6.2), and old tickets remain valid until normal expiry (this section and section 8.5). Together these mean that two connections presenting the same ticket at nearly the same time do not race each other: neither one mutates or invalidates the ticket the other is using.

A handshake-issued ticket is different: it does not exist in any shared state until the issuing side commits it, and a second connection that observed it too early would find it unrecognized. The server commits a TCP handshake-issued ticket only after the first authenticated client record (section 6.1); a client mirrors that on its side and publishes a handshake-issued ticket to its shared local cache only after this connection has itself sent its first authenticated record, not merely after parsing ServerHello. A ticket learned from a rotation update, by contrast, is safe to publish to shared state as soon as it is received: the issuing side already committed it before that record or packet could leave the wire (sections 6.3, 8.5).

### 7. TCP Protocol

#### 7.1 TCP Client Hello

TCP Client Hello is 96 bytes:

```text
offset  size  field
0       4     client_prefix_seed
4       1     version = 0x01
5       1     flags
6       2     reserved = 0x0000
8       4     user_id_field_le
12      4     client_id_le
16      4     connection_id_le
20      2     client_overhead_le
22      2     tcp_mss_le
24      16    client_nonce
40      16    ticket
56      32    client_share
88      8     hello_seed
```

Flags:

* `0x00` = full handshake
* `0x01` = resume

Other flag bits are rejected. Full handshakes require `ticket = 0x00...00`; resume handshakes require a non-zero ticket.

##### 7.1.1 Full Handshake Share

```text
client_share = Compress(G * client_scalar + M * password_scalar_tcp)
ticket       = 0x00...00
```

##### 7.1.2 Resume Share

```text
client_share = Compress(G * client_scalar)
ticket       = current session ticket
flags        = 0x01
```

##### 7.1.3 Replay Key

```text
SHA256(method || 0x00 || ClientHello[0..96])
```

The replay key binds the exact canonical TCP Client Hello bytes, including `client_prefix_seed`, `client_id`, `connection_id`, `client_overhead`, and `tcp_mss`.

#### 7.2 TCP Server Hello

TCP Server Hello is 100 bytes:

```text
offset  size  field
0       4     server_prefix_seed
4       1     version = 0x01
5       1     flags
6       2     tcp_mss_le
8       12    server_seed
20      16    issued_ticket
36      16    server_nonce
52      32    server_share
84      16    server_confirm_tag
```

Flags:

* `0x00` = full handshake response
* `0x01` = resume response

Full handshake:

```text
server_share  = Compress(G * server_scalar + N * password_scalar_tcp)
issued_ticket = fresh opaque resume token
```

Resume:

```text
server_share  = Compress(G * server_scalar)
issued_ticket = the presented ticket, unchanged
```

#### 7.3 TCP Full Handshake Secret Schedule

The server computes:

```text
client_component = Decompress(client_share) - M * password_scalar_tcp
shared_point     = client_component * server_scalar
```

Transcript hash:

```text
SHA256(
  method || 0x00 ||
  selected_user_id_context ||
  client_prefix_seed ||
  client_flags ||
  user_id_field ||
  client_id ||
  connection_id ||
  client_overhead ||
  tcp_mss ||
  client_nonce ||
  ticket ||
  client_share ||
  hello_seed ||
  server_prefix_seed ||
  server_flags ||
  server_tcp_mss ||
  server_seed ||
  issued_ticket ||
  server_nonce ||
  server_share
)
```

```text
master_secret =
  HKDF-SHA256(
    ikm  = Compress(shared_point),
    salt = transcript_hash,
    info = "ssrr-auth-akarin-v2-master",
    L    = 32
  )

ticket_secret =
  HKDF-SHA256(
    ikm  = master_secret,
    salt = transcript_hash,
    info = "ssrr-auth-akarin-v2-resumption",
    L    = 32
  )
```

#### 7.4 TCP Resume Secret Schedule

The stored `ticket_secret` is looked up from the presented ticket.

The server computes:

```text
client_component = Decompress(client_share)
shared_point     = client_component * server_scalar
```

```text
master_secret =
  HKDF-SHA256(
    ikm  = Compress(shared_point) || ticket_secret,
    salt = transcript_hash,
    info = "ssrr-auth-akarin-v2-resume-master",
    L    = 32
  )
```

Resume produces no successor ticket or secret (section 6.2): `issued_ticket` echoes the presented ticket, and the connection's resumption secret remains the looked-up `ticket_secret`, unaffected by `shared_point` or the resumed connection's `master_secret`.

TCP resume uses the same transcript input layout as section 7.3:

```text
SHA256(
  method || 0x00 ||
  selected_user_id_context ||
  client_prefix_seed ||
  client_flags = 0x01 ||
  user_id_field ||
  client_id ||
  connection_id ||
  client_overhead ||
  tcp_mss ||
  client_nonce ||
  ticket ||
  client_share ||
  hello_seed ||
  server_prefix_seed ||
  server_flags = 0x01 ||
  server_tcp_mss ||
  server_seed ||
  issued_ticket ||
  server_nonce ||
  server_share
)
```

#### 7.5 TCP Confirmation Tag

```text
confirm_key =
  HKDF-SHA256(
    ikm  = master_secret,
    salt = transcript_hash,
    info = "ssrr-auth-akarin-v2-server-confirm",
    L    = 32
  )

server_confirm_tag =
  HMAC-SHA256(confirm_key, transcript_hash)[0..16]
```

Clients verify `server_confirm_tag` before completing the handshake or releasing protected data. A mismatch aborts the handshake.

#### 7.6 TCP Transport Keys

```text
tx_key =
  HKDF-SHA256(master_secret, transcript_hash, "ssrr-auth-akarin-v2-server->client-key", 16)

rx_key =
  HKDF-SHA256(master_secret, transcript_hash, "ssrr-auth-akarin-v2-client->server-key", 16)

tx_len_key =
  HKDF-SHA256(master_secret, transcript_hash, "ssrr-auth-akarin-v2-server->client-len-key", 16)

rx_len_key =
  HKDF-SHA256(master_secret, transcript_hash, "ssrr-auth-akarin-v2-client->server-len-key", 16)

tx_nonce_prefix =
  HKDF-SHA256(master_secret, transcript_hash, "ssrr-auth-akarin-v2-server->client-nonce", 8)

rx_nonce_prefix =
  HKDF-SHA256(master_secret, transcript_hash, "ssrr-auth-akarin-v2-client->server-nonce", 8)
```

Counters:

* initial `tx_counter = 1`
* initial `rx_counter = 1`
* each logical record consumes 1 counter value
* counters never wrap

##### 7.6.1 TCP Live Key Update

The server derives:

```text
next_tx_key =
  HKDF-SHA256(
    ikm  = master_secret,
    salt = method || 0x00 || key_update_salt,
    info = "ssrr-auth-akarin-v2-server->client-key-update-key",
    L    = 16
  )

next_tx_len_key =
  HKDF-SHA256(
    ikm  = master_secret,
    salt = method || 0x00 || key_update_salt,
    info = "ssrr-auth-akarin-v2-server->client-key-update-len-key",
    L    = 16
  )

next_tx_nonce_prefix =
  HKDF-SHA256(
    ikm  = master_secret,
    salt = method || 0x00 || key_update_salt,
    info = "ssrr-auth-akarin-v2-server->client-key-update-nonce",
    L    = 8
  )
```

`key_update_salt` is carried once in an AEAD-protected record metadata block. That update record, including its masked outer length, uses the current key state and current counter. The sender installs `next_tx_key`, `next_tx_len_key`, and `next_tx_nonce_prefix` immediately after encoding the update record; the receiver installs them after authenticating that complete record. Both sides reset the updated direction's counter to 1 and use the new state for the immediately following record, including when both records are delivered in one TCP write.

Trigger conditions:

* `tx_counter` approaches exhaustion
* key-update timer reaches `session_ticket_timeout / 2`

Key update happens before the next logical record would consume a counter beyond `2^32 - 1`. The update metadata is not repeated in later records from the same encoded batch. If key update cannot be sent or applied, the connection is closed.

#### 7.7 TCP Record Format

Each record contains:

1. 2-byte keyed masked outer length
2. one AEAD-protected body containing the encrypted inner header, metadata, payload, and padding

The fixed 96-byte TCP ClientHello is unchanged by this record format. TCP record keys are derived from the transcript that includes ServerHello and the server share. A client sends authenticated TCP records only after it can compute and verify ServerHello. The first authenticated client record acts as implicit client confirmation and may be sent immediately after ServerHello is verified, but it cannot be sent in the pre-ServerHello ClientHello flight. TCP does not define a separate ticket-based 0-RTT data path; ticket-based cryptographic 0-RTT is provided by UDP Data Packets in section 8.

##### 7.7.1 Inner Header Plaintext

```text
offset  size  field
0       2     payload_len_le
2       2     pad_len_le
4       1     flags
5       1     shape_class
6       2     metadata_len_le
```

Flags:

* `0x01` = body starts with `next_ticket || next_ticket_secret`
* `0x02` = body contains `key_update_salt`

##### 7.7.2 Body Plaintext

```text
inner_header_8 || [next_ticket_16 || next_ticket_secret_32]? || [key_update_salt_16]? || payload || zero_padding
```

Metadata order:

1. `next_ticket` (16 bytes) followed by `next_ticket_secret` (32 bytes), 48 bytes total, if `flags & 0x01 != 0`
2. `key_update_salt`, if `flags & 0x02 != 0`

Client-to-server records use `flags = 0x00` and `metadata_len = 0`.

##### 7.7.3 AEAD Layout

Length mask:

```text
len_mask_block = nonce_prefix || counter_le32 || "len!"
len_mask       = AES128-Encrypt(len_key, len_mask_block)[0..2]
```

`body_cipher_len` is the byte length of the AEAD ciphertext plus its 16-byte tag. It is encoded as:

```text
outer_len_masked = LE16(body_cipher_len) XOR len_mask
```

Body:

```text
body_plain = inner_header_8 || metadata || payload || zero_padding
body_nonce = nonce_prefix || counter_le32
body_aad   = counter_le32 || outer_len_masked
body_ct    = AEAD_Encrypt(tx_key, body_nonce, body_aad, body_plain)
record     = outer_len_masked || body_ct
```

Receivers first unmask `outer_len_masked` to learn how many bytes to read from the TCP stream, then authenticate and decrypt `body_ct`. Invalid lengths below `8 + 16` bytes or above `8 + MAX_FRAME_PLAIN_LEN + 16` bytes are rejected. `MAX_FRAME_PLAIN_LEN = 60 * 1024`.

#### 7.8 TCP Shaping

```text
shape_seed =
  HKDF-SHA256(
    ikm  = master_secret,
    salt = method || epoch_be64,
    info = "ssrr-auth-akarin-v2-shape",
    L    = 32
  )
```

Base bins:

```text
[192, 224, 256, 320, 384, 512, 704, 896, 1088, 1280, 1392]
```

Each bin is jittered by a XorShift128+ instance seeded from `shape_seed`. The jitter range is `-48..=48`, clamped to `160..1440`. A bin with value greater than 512 is skipped when `rng.next() % 7 == 0`. If no bin remains or the largest bin is below 1300, `1360` is added.

The effective TCP MSS is `min(local_tcp_mss, peer_tcp_mss)` after both values are normalized to `500..1500`. Candidate selection is weighted across all legal candidates not larger than the effective TCP MSS and biased toward smaller legal bins. If no bin is legal, padding is selected from `0..=min(96, spare_bytes)`.

### 8. UDP Protocol

#### 8.1 UDP Bootstrap Request

UDP Bootstrap Request is 60 bytes:

```text
offset  size  field
0       1     type = 0x01
1       1     version = 0x01
2       2     client_udp_packet_size_le
4       4     client_seed
8       4     user_id_field_le
12      16    client_nonce
28      32    client_share
```

`client_udp_packet_size` is the client's requested maximum UDP datagram size.

* `0` means the default value `1232`
* non-zero values are clamped to `576..1500`

```text
client_share = Compress(G * client_scalar + M * password_scalar_udp)
```

Replay key:

```text
SHA256(method || 0x01 || BootstrapRequest[0..60])
```

The bootstrap replay key binds the exact UDP Bootstrap Request bytes, including `client_udp_packet_size` and `client_seed`.

#### 8.2 UDP Bootstrap Response

UDP Bootstrap Response is 96 bytes:

```text
offset  size  field
0       1     type = 0x02
1       1     version = 0x01
2       2     server_udp_packet_size_le
4       12    server_seed
16      16    issued_ticket
32      16    server_nonce
48      32    server_share
80      16    server_confirm_tag
```

`server_udp_packet_size` is the server's advertised maximum UDP datagram size. The default value is `1232`.

UDP Bootstrap transcript hash:

```text
SHA256(
  method ||
  type = 0x01 ||
  version = 0x01 ||
  normalized_client_udp_packet_size_le ||
  normalized_server_udp_packet_size_le ||
  user_id_field_le ||
  selected_user_id_context ||
  client_seed ||
  client_nonce ||
  client_share ||
  server_seed ||
  issued_ticket ||
  server_nonce ||
  server_share
)
```

The server computes:

```text
client_component = Decompress(client_share) - M * password_scalar_udp
shared_point     = client_component * server_scalar
master_secret    = HKDF-SHA256(Compress(shared_point), transcript_hash, "ssrr-auth-akarin-v2-udp-master", 32)
ticket_secret    = HKDF-SHA256(master_secret, transcript_hash, "ssrr-auth-akarin-v2-resumption", 32)
```

UDP Bootstrap confirmation tag:

```text
confirm_key =
  HKDF-SHA256(
    ikm  = master_secret,
    salt = transcript_hash,
    info = "ssrr-auth-akarin-v2-udp-server-confirm",
    L    = 32
  )

server_confirm_tag =
  HMAC-SHA256(confirm_key, transcript_hash)[0..16]
```

Clients verify `server_confirm_tag` before storing ticket state or sending UDP Data Packets. A mismatch discards the response.

Session entry:

* `master_secret = ticket_secret`
* shared TCP/UDP ticket semantics
* `udp_packet_size = effective_udp_packet_size`

A UDP-issued ticket may be used for TCP resume. The bootstrap response stages the ticket; the ticket is committed only after the first authenticated unfragmented UDP Data Packet, or after an authenticated fragment set completes reassembly, for that ticket. An incomplete authenticated fragment only refreshes the pending entry.

#### 8.3 UDP Data Packet

Both directions use:

```text
offset  size  field
0       1     type = 0x03
1       16    ticket
17      8     epoch_le
25      12    nonce
37      ...   encrypted_payload
```

Client to server:

```text
udp_epoch_key =
  HKDF-SHA256(
    ikm  = ticket_secret,
    salt = method || 0x00 || epoch_be64,
    info = "ssrr-auth-akarin-v2-udp-epoch-key:client",
    L    = 16
  )
```

Server to client:

```text
udp_epoch_key =
  HKDF-SHA256(
    ikm  = ticket_secret,
    salt = method || 0x00 || epoch_be64,
    info = "ssrr-auth-akarin-v2-udp-epoch-key:server",
    L    = 16
  )
```

The 12-byte `nonce` is transmitted with every packet and used as the AEAD nonce. It is not mixed into UDP key derivation. The AEAD plaintext is the UDP Payload Plaintext from section 8.4. The AEAD associated data is the 37-byte UDP Data Packet header, `type || ticket || epoch_le || nonce`. The `encrypted_payload` field is the AEAD ciphertext followed by the 16-byte tag.

For each `(ticket_secret, epoch, direction)` key, senders must avoid nonce reuse. Senders use either CSPRNG-generated 96-bit nonces, relying on negligible collision probability, or a per-ticket/per-direction monotonic counter. The reference server uses CSPRNG-generated nonces and does not maintain a separate nonce-uniqueness set.

The total UDP Data Packet length, including the 37-byte data header and the 16-byte AEAD tag, must not exceed the session entry's `udp_packet_size`.

A client that already holds a valid ticket and `ticket_secret` can construct a UDP Data Packet without receiving a new server response in that exchange. This is the protocol's ticket-based cryptographic 0-RTT path.

UDP Data Packet validation looks the ticket up in this method's ticket store. It does not compare `user_id` because the UDP Data Packet does not carry a user id.

#### 8.4 UDP Payload Plaintext

Before AEAD, the encrypted payload format is:

```text
offset  size  field
0       2     payload_len_le
2       1     flags
3       1     shape_class
4       ...   optional metadata
...     ...   payload_or_fragment
...     ...   zero_padding
```

`payload_len_le` is the byte length of `payload_or_fragment`; padding is not counted.

UDP flags:

* `0x01` = `next_ticket || next_ticket_secret` is present immediately after the 4-byte metadata header
* `0x02` = fragment metadata is present after any ticket metadata

Ticket update metadata:

```text
next_ticket_16 || next_ticket_secret_32
```

Fragment metadata:

```text
offset  size  field
0       4     fragment_id_le
4       2     fragment_offset_le
6       2     fragment_total_len_le
```

Metadata order is fixed:

```text
payload_len_le16 || flags || shape_class || [next_ticket_16 || next_ticket_secret_32] || [fragment_metadata_8] || payload_or_fragment || zero_padding
```

Client-to-server packets may use `flags = 0x00` or `flags = 0x02`.
Server-to-client packets may use `flags = 0x00`, `flags = 0x01`, or `flags = 0x02`.
A ticket update is not combined with fragmentation; if a response must be fragmented, the server omits ticket-update metadata for that response.

Fragment metadata is encrypted and authenticated by AEAD together with the payload. Receivers reassemble fragments before forwarding the inner UDP datagram.

#### 8.5 UDP Ticket Update Delivery

A ticket rotates when its issued age reaches `rotation_interval` (section 6.3), i.e. approximately half of the shared ticket store timeout; the server may then rotate it in an outgoing UDP response. With the default 1800-second timeout, the rotation threshold is approximately 900 seconds.

The response may carry `next_ticket` and `next_ticket_secret` in encrypted UDP metadata. Both are generated at random by the server (section 6.3); neither is derived from the current ticket or its secret.

Old tickets remain valid until normal expiry.

Successor insertion is committed atomically in the shared ticket store only after outgoing response delivery succeeds. The current ticket is not removed by that commit.

#### 8.6 UDP Replay Handling

Bootstrap replay key:

```text
SHA256(method || 0x01 || BootstrapRequest[0..60])
```

Data replay key:

```text
is_spec_time_u8 || 0x03 || ticket || epoch_le64 || nonce
```

The server accepts a UDP Data Packet only if:

* the ticket exists
* the ticket belongs to this method's ticket store
* the packet epoch is within the accepted epoch window
* AEAD authentication succeeds
* `(is_spec_time, type, ticket, epoch, nonce)` is not present in the replay cache

For UDP Data Packets, replay cache insertion happens after AEAD authentication succeeds, so unauthenticated packets cannot poison the data replay cache.

The UDP replay cache scope is the ticket acceptance scope. Every worker or node that accepts the same ticket set uses the same replay state for Bootstrap Request and Data Packet replay keys. A deployment that cannot share replay state partitions ticket acceptance so each ticket is accepted by exactly one replay scope.

#### 8.7 UDP Shaping

```text
shape_seed =
  HKDF-SHA256(
    ikm  = ticket_secret,
    salt = method || epoch_be64,
    info = "ssrr-auth-akarin-v2-udp-shape",
    L    = 32
  )
```

Base bins:

```text
[112, 160, 224, 320, 448, 640, 896, 1184]
```

Each bin is jittered by `-32..=32`, clamped to `96..1232`, sorted, and deduplicated. Candidate selection is weighted across all legal bins and biased toward smaller bins. If no bin is legal, padding is selected from `0..=min(48, spare_bytes)`.

#### 8.8 UDP Packet Size and Fragmentation

UDP uses a per-session outer datagram budget negotiated during bootstrap. The budget is the maximum wire length of one UDP Data Packet, including the 37-byte data header and the 16-byte AEAD tag.

Constants:

```text
default_udp_packet_size      = 1232
min_udp_packet_size          = 576
max_udp_packet_size          = 1500
max_plain_udp_payload        = 65535
fragment_timeout             = 30 seconds
fragment_max_entries         = 8192
fragment_max_ticket_bytes    = max_plain_udp_payload * 32
fragment_max_total_bytes     = max_plain_udp_payload * 1024
fragment_accounting_bytes(n) = n * 2
```

Normalization:

```text
normalize_udp_packet_size(x):
  if x == 0:
    return default_udp_packet_size
  return clamp(x, min_udp_packet_size, max_udp_packet_size)
```

The client writes `client_udp_packet_size` in the bootstrap request.

The server writes `server_udp_packet_size` in the bootstrap response.

Both values are included in the UDP bootstrap transcript hash.

Effective packet size:

```text
effective_udp_packet_size =
  min(normalize_udp_packet_size(client_udp_packet_size),
      normalize_udp_packet_size(server_udp_packet_size))
```

For an unfragmented packet:

```text
max_payload = effective_udp_packet_size - 37 - metadata_len - 16
```

Here `metadata_len` includes the 4-byte base encrypted header plus any optional 48-byte ticket update (`next_ticket_16 || next_ticket_secret_32`) or 8-byte fragment metadata.

For a fragmented packet without ticket update metadata:

```text
max_fragment_payload = effective_udp_packet_size - 37 - 4 - 8 - 16
```

Where:

* `37` is the UDP data header length
* `4` is the base encrypted metadata length
* `8` is the encrypted fragment metadata length
* `16` is the AEAD tag length

If the inner UDP datagram fits in one packet, it is sent unfragmented.

If the inner UDP datagram is larger than the unfragmented payload capacity but not larger than `max_plain_udp_payload`, it is split into multiple UDP Data Packets with `flags & 0x02 != 0`.

All fragments belonging to one inner UDP datagram share the same `(ticket, fragment_id)` and carry their own `fragment_offset` and `fragment_total_len`.

Receivers keep a bounded reassembly table keyed by `(ticket, fragment_id)`. A fragment is accepted only if:

* `fragment_total_len` is non-zero and not larger than `max_plain_udp_payload`
* the fragment payload is non-empty
* `fragment_offset + payload_len <= fragment_total_len`
* overlapping bytes, if repeated, are identical
* creating a new incomplete fragment set fits within `fragment_max_entries`
* creating a new incomplete fragment set fits within `fragment_max_ticket_bytes` for that ticket
* creating a new incomplete fragment set fits within `fragment_max_total_bytes` across the receiver
* the fragment set completes before `fragment_timeout`

Incomplete fragment sets are not forwarded. A new incomplete fragment set charges `fragment_accounting_bytes(fragment_total_len)` against the ticket and receiver budgets. The charge is released when the fragment set completes or expires. Once all bytes are present, the receiver removes that active assembly, reconstructs the original inner UDP datagram, and forwards it once for that completion. Completed `(ticket, fragment_id)` values are not retained as tombstones; a newly authenticated fragment set using fresh nonces can create a new assembly with the same key and can therefore produce another forwarded datagram.

Shaping and padding length selection do not select a packet size larger than `effective_udp_packet_size` for either fragmented or unfragmented packets.

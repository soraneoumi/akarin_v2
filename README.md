# akarin_v2

A sans-IO Rust implementation of **auth_akarin_v2**, a proxy authentication and
transport protocol descended from the ShadowsocksR protocol family. It covers
both peers and both transports:

| | TCP | UDP |
|---|---|---|
| Client | `client::TcpClientSession` | `client::UdpClientSession` |
| Server | `server::TcpServerSession` | `server::UdpServer` |

The wire format is specified in [SPEC.md](SPEC.md).

## Protocol at a glance

- **Password-authenticated key exchange.** A full handshake is a SPAKE2-style
  exchange over Ristretto255, so the first packet offers no offline
  password-guessing oracle. Unknown user ids get an indistinguishable answer.
- **Authenticated encryption.** TCP records and UDP datagrams use AES-128-GCM.
  TCP record lengths are masked with a per-record AES keystream.
- **One resumable session for TCP and UDP.** A ticket from either transport
  resumes TCP or sends UDP data at 0-RTT, without a new handshake.
- **Ticket rotation and live key updates.** Tickets rotate at half their
  lifetime and TCP send keys update on the same schedule. Successor material
  is random, never derived from the old secret.
- **Traffic shaping.** Record and datagram sizes are padded toward
  session-specific size bins. With `auth_akarin_spec_time_v2` the bins rotate
  over time.
- **Replay protection.** The server keeps bounded replay filters for TCP
  hellos, UDP bootstraps and UDP data packets.

Transport obfuscation (for example, a TLS look-alike) is out of scope. Layer
it outside these sessions.

## Usage

The crate does no I/O. The host owns the sockets and moves bytes through the
sessions. Every write of session output must be reported back
(`on_flushed`, `UdpSendPlan::complete`, `on_bootstrap_data_sent`). Tickets
and key changes take effect only once their bytes are known to have left.

```rust
use akarin_v2::Method;
use akarin_v2::client::{Client, ClientConfig};
use akarin_v2::server::{Server, ServerConfig};

let server = Server::new(ServerConfig::new(Method::SpecA, "password"))?;
let client = Client::new(ClientConfig::new(Method::SpecA, "password"));

// One TCP connection.
let mut c = client.tcp_session();
let mut s = server.tcp_session();
let (mut wire, mut plain) = (Vec::new(), Vec::new());

c.encode(b"first payload", &mut wire)?; // client hello; payload is held back
c.on_flushed(true);

let hello_done = s.decode(&wire, &mut plain)?; // server must answer
assert!(hello_done);
s.encode(&[], &mut wire)?; // server hello
s.on_flushed(true)?;

c.decode(&wire, &mut plain)?; // verifies the server
let records = c.take_pending_encoded().unwrap(); // the held-back payload
c.on_flushed(true);

s.decode(&records, &mut plain)?;
assert_eq!(plain, b"first payload");
# Ok::<(), anyhow::Error>(())
```

Create every session from one `Server` (and one `Client`). They share the
ticket store or cache, so a ticket from one connection or transport resumes
the others. On the server, decode errors carry a `DecodeErrorKind`
(`akarin_v2::decode_error_kind`). A host can use it to decide how to treat
the peer, for example to keep serving a decoy rather than closing at once.

`tests/roundtrip.rs` drives complete exchanges: TCP handshake and resume,
UDP bootstrap and 0-RTT, fragmentation, multi-user, replay rejection,
ticket rotation and key updates.

## Status

This crate is the reference implementation of `auth_akarin_spec_a_v2` and
`auth_akarin_spec_time_v2` and interoperates with existing peers of those
methods. It has not had an independent security audit.

## License

Copyright (c) 2026 新しい世界. All rights reserved.

This repository is published for reference only. No permission is granted to
copy, redistribute, modify, or publish it, except as permitted by applicable
law. Portions derived from ShadowsocksR and Shadowsocks remain under the
Apache License, Version 2.0; see [LICENSE](LICENSE).

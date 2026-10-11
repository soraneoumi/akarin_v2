//! A sans-IO implementation of the auth_akarin_v2 proxy protocol.
//!
//! auth_akarin_v2 authenticates with a SPAKE2-style exchange over
//! Ristretto255, protects TCP records and UDP datagrams with AES-128-GCM, and
//! shares one resumable ticket family between TCP and UDP. `SPEC.md` in the
//! repository describes the wire format; this crate is the reference
//! implementation of both peers.
//!
//! Nothing here performs I/O. A host owns the sockets and moves bytes through
//! the session types:
//!
//! * [`server::Server`] holds the state every server connection shares (users,
//!   ticket store, replay filters, client registry) and creates a
//!   [`server::TcpServerSession`] per accepted connection plus one
//!   [`server::UdpServer`] for the datagram socket.
//! * [`client::Client`] holds the client's identity and the ticket cache that
//!   TCP and UDP resume from, and creates a [`client::TcpClientSession`] per
//!   connection and a [`client::UdpClientSession`] per UDP association.
//!
//! Transport obfuscation is out of scope; layer it outside these sessions.

mod buffer;
pub mod client;
mod crypto;
mod error;
mod method;
pub mod server;
mod udp_wire;
mod wire;

pub use error::{DecodeError, DecodeErrorKind, decode_error_kind};
pub use method::Method;

// Compiles and runs the README example as a doctest so it cannot drift.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

fn now_secs_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

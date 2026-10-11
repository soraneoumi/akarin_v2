use std::fmt;

/// Why a server rejected client input.
///
/// Server-side rejections of client input carry one of these inside the
/// returned `anyhow::Error`; read it back with [`decode_error_kind`]. Hosts
/// use it to choose a reaction (for example, keep serving a probe some decoy
/// content rather than closing at once) without matching on error strings.
/// An error without a kind is an internal or API-misuse failure, not a
/// verdict on the peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    ClientHelloMalformed,
    UnknownTicket,
    TicketMismatch,
    Replay,
    DuplicateClient,
    FrameMalformed,
    FrameAuthFailed,
    PacketMalformed,
    PacketAuthFailed,
    PacketSize,
    StateInvalid,
}

impl DecodeErrorKind {
    /// A stable, machine-friendly name for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientHelloMalformed => "client_hello_malformed",
            Self::UnknownTicket => "unknown_ticket",
            Self::TicketMismatch => "ticket_mismatch",
            Self::Replay => "replay",
            Self::DuplicateClient => "duplicate_client",
            Self::FrameMalformed => "frame_malformed",
            Self::FrameAuthFailed => "frame_auth_failed",
            Self::PacketMalformed => "packet_malformed",
            Self::PacketAuthFailed => "packet_auth_failed",
            Self::PacketSize => "packet_size",
            Self::StateInvalid => "state_invalid",
        }
    }
}

impl fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct DecodeError {
    kind: DecodeErrorKind,
    detail: anyhow::Error,
}

impl DecodeError {
    pub fn kind(&self) -> DecodeErrorKind {
        self.kind
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.detail, f)
    }
}

impl std::error::Error for DecodeError {}

/// The rejection reason attached to a server decode error, if any.
pub fn decode_error_kind(err: &anyhow::Error) -> Option<DecodeErrorKind> {
    err.downcast_ref::<DecodeError>().map(DecodeError::kind)
}

pub(crate) fn decode_error(
    kind: DecodeErrorKind,
    detail: impl Into<anyhow::Error>,
) -> anyhow::Error {
    DecodeError {
        kind,
        detail: detail.into(),
    }
    .into()
}

pub(crate) fn decode_result<T>(
    kind: DecodeErrorKind,
    detail: impl Into<anyhow::Error>,
) -> anyhow::Result<T> {
    Err(decode_error(kind, detail))
}

use akarin_v2::client::{
    Client, ClientConfig, TcpClientSession, UdpClientSession, UdpEncodeResult,
};
use akarin_v2::server::{Server, ServerConfig, TcpServerSession, UdpClientPacket, UdpSession};
use akarin_v2::{DecodeErrorKind, Method, decode_error_kind};
use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;

const CLIENT_HELLO_FLAGS: usize = 5;
const CLIENT_HELLO_TICKET: std::ops::Range<usize> = 40..56;
const SERVER_HELLO_TICKET: std::ops::Range<usize> = 20..36;
const UDP_BOOTSTRAP_TYPE: u8 = 0x01;
const UDP_DATA_TYPE: u8 = 0x03;

fn server_with(method: Method, password: &str, adjust: impl FnOnce(&mut ServerConfig)) -> Server {
    let mut config = ServerConfig::new(method, password);
    adjust(&mut config);
    Server::new(config).expect("valid server config")
}

fn client_with(method: Method, password: &str, adjust: impl FnOnce(&mut ClientConfig)) -> Client {
    let mut config = ClientConfig::new(method, password);
    adjust(&mut config);
    Client::new(config)
}

fn pair(method: Method) -> (Client, Server) {
    (
        client_with(method, "shared-secret", |_| {}),
        server_with(method, "shared-secret", |_| {}),
    )
}

struct TcpLink {
    client: TcpClientSession,
    server: TcpServerSession,
    client_hello: Vec<u8>,
    server_hello: Vec<u8>,
}

/// Runs a full TCP handshake that carries `first` from the client, and
/// returns the established pair plus what the server received.
fn tcp_connect(client: &Client, server: &Server, first: &[u8]) -> (TcpLink, Vec<u8>) {
    let mut client_session = client.tcp_session();
    let mut server_session = server.tcp_session();

    let mut client_hello = Vec::new();
    client_session.encode(first, &mut client_hello).unwrap();
    client_session.on_flushed(true);
    assert_eq!(
        client_hello.len(),
        96,
        "first flight is only the client hello"
    );

    let mut received = Vec::new();
    assert!(server_session.decode(&client_hello, &mut received).unwrap());
    assert!(received.is_empty());

    let mut server_hello = Vec::new();
    server_session.encode(&[], &mut server_hello).unwrap();
    server_session.on_flushed(true).unwrap();
    assert_eq!(server_hello.len(), 100);

    let mut client_plain = Vec::new();
    client_session
        .decode(&server_hello, &mut client_plain)
        .unwrap();
    assert!(client_session.is_established());
    assert!(client_plain.is_empty());

    if let Some(pending) = client_session.take_pending_encoded() {
        client_session.on_flushed(true);
        assert!(!server_session.decode(&pending, &mut received).unwrap());
    }

    (
        TcpLink {
            client: client_session,
            server: server_session,
            client_hello,
            server_hello,
        },
        received,
    )
}

fn client_to_server(link: &mut TcpLink, data: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    link.client.encode(data, &mut wire).unwrap();
    link.client.on_flushed(true);
    let mut plain = Vec::new();
    link.server.decode(&wire, &mut plain).unwrap();
    plain
}

fn server_to_client(link: &mut TcpLink, data: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    link.server.encode(data, &mut wire).unwrap();
    link.server.on_flushed(true).unwrap();
    let mut plain = Vec::new();
    link.client.decode(&wire, &mut plain).unwrap();
    plain
}

fn single(result: UdpEncodeResult) -> Vec<u8> {
    match result {
        UdpEncodeResult::Packet(packet) => packet,
        other => panic!("expected one datagram, got {other:?}"),
    }
}

fn server_data(packet: UdpClientPacket) -> (Vec<u8>, UdpSession) {
    match packet {
        UdpClientPacket::Data { plain, session } => (plain, session),
        other => panic!("expected data, got {other:?}"),
    }
}

/// Bootstraps a UDP association carrying `first` and returns what the server
/// received under which session.
fn udp_bootstrap(
    session: &mut UdpClientSession,
    server: &Server,
    first: &[u8],
) -> (Vec<u8>, UdpSession) {
    let bootstrap = single(session.encode(first, None).unwrap());
    assert_eq!(bootstrap[0], UDP_BOOTSTRAP_TYPE);
    assert!(session.bootstrap_pending());

    let plan = match server.udp().decode(&bootstrap).unwrap() {
        UdpClientPacket::HandshakeResponse(plan) => plan,
        other => panic!("expected handshake response, got {other:?}"),
    };
    let response = plan.packets()[0].clone();
    plan.complete(true);

    assert!(session.is_bootstrap_response(&response));
    let data = single(
        session
            .handle_bootstrap_response(&response, None)
            .unwrap()
            .unwrap(),
    );
    session.on_bootstrap_data_sent(true);
    assert!(session.has_ticket());

    server_data(server.udp().decode(&data).unwrap())
}

fn udp_reply(
    session: &mut UdpClientSession,
    server: &Server,
    to: &UdpSession,
    data: &[u8],
) -> Vec<u8> {
    let plan = server.udp().encode(data, to, None).unwrap();
    let packets = plan.packets().to_vec();
    plan.complete(true);
    let mut delivered = Vec::new();
    for packet in packets {
        let plain = session.decode(&packet).unwrap();
        if !plain.is_empty() {
            assert!(delivered.is_empty(), "one reply yields one datagram");
            delivered = plain;
        }
    }
    delivered
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn tcp_full_handshake_relays_both_directions() {
    let (client, server) = pair(Method::SpecA);
    let (mut link, received) = tcp_connect(&client, &server, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(link.client_hello[CLIENT_HELLO_FLAGS], 0);
    assert_eq!(received, b"GET / HTTP/1.1\r\n\r\n");

    assert_eq!(
        server_to_client(&mut link, b"HTTP/1.1 200 OK"),
        b"HTTP/1.1 200 OK"
    );
    assert_eq!(client_to_server(&mut link, b"more"), b"more");
}

#[test]
fn tcp_large_payloads_span_many_records() {
    let (client, server) = pair(Method::SpecA);
    let (mut link, _) = tcp_connect(&client, &server, b"hi");
    let big = pattern(300 * 1024);
    assert_eq!(client_to_server(&mut link, &big), big);
    assert_eq!(server_to_client(&mut link, &big), big);
}

#[test]
fn tcp_decode_accepts_input_split_at_every_boundary() {
    let (client, server) = pair(Method::SpecA);
    let (mut link, _) = tcp_connect(&client, &server, b"hi");
    let mut wire = Vec::new();
    link.server.encode(&pattern(5000), &mut wire).unwrap();
    link.server.on_flushed(true).unwrap();

    let mut delivered = Vec::new();
    let mut plain = Vec::new();
    for byte in wire {
        link.client.decode(&[byte], &mut plain).unwrap();
        delivered.extend_from_slice(&plain);
    }
    assert_eq!(delivered, pattern(5000));
}

#[test]
fn tcp_second_connection_resumes_with_the_issued_ticket() {
    let (client, server) = pair(Method::SpecA);
    let (first, _) = tcp_connect(&client, &server, b"one");
    let issued = &first.server_hello[SERVER_HELLO_TICKET];

    let (mut second, received) = tcp_connect(&client, &server, b"two");
    assert_eq!(
        second.client_hello[CLIENT_HELLO_FLAGS], 1,
        "second hello resumes"
    );
    assert_eq!(&second.client_hello[CLIENT_HELLO_TICKET], issued);
    assert_eq!(
        &second.server_hello[SERVER_HELLO_TICKET], issued,
        "resume echoes the ticket"
    );
    assert_eq!(received, b"two");
    assert_eq!(server_to_client(&mut second, b"ok"), b"ok");
}

#[test]
fn tcp_ticket_is_shared_only_after_the_first_record_is_delivered() {
    let (client, server) = pair(Method::SpecA);
    let mut session = client.tcp_session();
    let mut server_session = server.tcp_session();
    let mut wire = Vec::new();
    session.encode(b"payload", &mut wire).unwrap();
    session.on_flushed(true);
    let mut plain = Vec::new();
    server_session.decode(&wire, &mut plain).unwrap();
    server_session.encode(&[], &mut wire).unwrap();
    server_session.on_flushed(true).unwrap();
    session.decode(&wire, &mut plain).unwrap();
    let _ = session.take_pending_encoded().unwrap();
    session.on_flushed(false);

    let (next, _) = tcp_connect(&client, &server, b"x");
    assert_eq!(
        next.client_hello[CLIENT_HELLO_FLAGS], 0,
        "undelivered ticket was not shared"
    );
}

#[test]
fn tcp_wrong_password_fails_at_the_client() {
    let client = client_with(Method::SpecA, "guess", |_| {});
    let server = server_with(Method::SpecA, "real", |_| {});
    let mut session = client.tcp_session();
    let mut server_session = server.tcp_session();

    let mut hello = Vec::new();
    session.encode(b"secret", &mut hello).unwrap();
    let mut plain = Vec::new();
    assert!(server_session.decode(&hello, &mut plain).unwrap());
    let mut server_hello = Vec::new();
    server_session.encode(&[], &mut server_hello).unwrap();

    let err = session.decode(&server_hello, &mut plain).unwrap_err();
    assert!(err.to_string().contains("confirmation tag"), "{err}");
    assert!(!session.is_established());
}

#[test]
fn tcp_multi_user_admits_known_user_and_rejects_wrong_key() {
    let mut users = HashMap::new();
    users.insert(7, b"seven".to_vec());
    let server = server_with(Method::SpecA, "master", |config| config.users = users);

    let known = client_with(Method::SpecA, "unused", |config| {
        config.user = Some((7, b"seven".to_vec()));
    });
    let (mut link, received) = tcp_connect(&known, &server, b"hello");
    assert_eq!(received, b"hello");
    assert_eq!(server_to_client(&mut link, b"world"), b"world");

    // An unknown id still gets a well-formed server hello, keyed by a decoy
    // the client cannot match.
    let stranger = client_with(Method::SpecA, "master", |config| {
        config.user = Some((8, b"seven".to_vec()));
    });
    let mut session = stranger.tcp_session();
    let mut server_session = server.tcp_session();
    let mut hello = Vec::new();
    session.encode(b"x", &mut hello).unwrap();
    let mut plain = Vec::new();
    assert!(server_session.decode(&hello, &mut plain).unwrap());
    let mut server_hello = Vec::new();
    server_session.encode(&[], &mut server_hello).unwrap();
    assert_eq!(server_hello.len(), 100);
    assert!(session.decode(&server_hello, &mut plain).is_err());
}

#[test]
fn tcp_replayed_client_hello_is_rejected() {
    let (client, server) = pair(Method::SpecA);
    let mut session = client.tcp_session();
    let mut hello = Vec::new();
    session.encode(b"x", &mut hello).unwrap();

    let mut plain = Vec::new();
    assert!(server.tcp_session().decode(&hello, &mut plain).unwrap());
    let err = server.tcp_session().decode(&hello, &mut plain).unwrap_err();
    assert_eq!(decode_error_kind(&err), Some(DecodeErrorKind::Replay));
}

#[test]
fn tcp_tampered_record_fails_authentication() {
    let (client, server) = pair(Method::SpecA);
    let (mut link, _) = tcp_connect(&client, &server, b"x");
    let mut wire = Vec::new();
    link.client.encode(b"payload", &mut wire).unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 1;
    let mut plain = Vec::new();
    let err = link.server.decode(&wire, &mut plain).unwrap_err();
    assert_eq!(
        decode_error_kind(&err),
        Some(DecodeErrorKind::FrameAuthFailed)
    );
}

#[test]
fn tcp_ticket_rotation_and_key_update_take_effect_after_delivery() {
    let client = client_with(Method::SpecA, "secret", |_| {});
    let server = server_with(Method::SpecA, "secret", |config| {
        config.ticket_lifetime = Duration::from_millis(1000);
    });
    let (mut failing, _) = tcp_connect(&client, &server, b"x");
    let first_ticket = failing.server_hello[SERVER_HELLO_TICKET].to_vec();
    let (mut link, _) = tcp_connect(&client, &server, b"y");
    assert!(link.server.next_control_deadline().is_some());

    // Past half the ticket lifetime both connections owe a ticket rotation,
    // and `link` also owes a key update.
    sleep(Duration::from_millis(550));

    // A failed write commits nothing it staged: the rotated ticket never
    // reaches the shared store.
    let mut lost = Vec::new();
    failing.server.encode(b"lost", &mut lost).unwrap();
    failing.server.on_flushed(false).unwrap();
    let (still_first, _) = tcp_connect(&client, &server, b"z");
    assert_eq!(
        still_first.client_hello[CLIENT_HELLO_TICKET].to_vec(),
        first_ticket
    );

    // The control frame carries the rotation and key update by itself.
    let mut control = Vec::new();
    assert!(link.server.encode_control(&mut control).unwrap());
    link.server.on_flushed(true).unwrap();
    let mut plain = Vec::new();
    link.client.decode(&control, &mut plain).unwrap();
    assert!(plain.is_empty());
    let mut nothing_due = Vec::new();
    assert!(!link.server.encode_control(&mut nothing_due).unwrap());

    assert_eq!(
        server_to_client(&mut link, b"after update"),
        b"after update"
    );
    assert_eq!(client_to_server(&mut link, b"still fine"), b"still fine");

    let (resumed, received) = tcp_connect(&client, &server, b"next");
    assert_eq!(resumed.client_hello[CLIENT_HELLO_FLAGS], 1);
    assert_ne!(
        resumed.client_hello[CLIENT_HELLO_TICKET].to_vec(),
        first_ticket,
        "the client resumes with the rotated ticket"
    );
    assert_eq!(received, b"next");
}

#[test]
fn udp_bootstrap_then_bidirectional_data() {
    let (client, server) = pair(Method::SpecA);
    let mut session = client.udp_session();
    let (received, to) = udp_bootstrap(&mut session, &server, b"dns query");
    assert_eq!(received, b"dns query");
    assert_eq!(
        udp_reply(&mut session, &server, &to, b"dns answer"),
        b"dns answer"
    );

    let packet = single(session.encode(b"second", None).unwrap());
    assert_eq!(packet[0], UDP_DATA_TYPE);
    let (plain, again) = server_data(server.udp().decode(&packet).unwrap());
    assert_eq!(plain, b"second");
    assert_eq!(again.association_id(), to.association_id());
}

#[test]
fn udp_large_datagrams_fragment_both_ways() {
    let (client, server) = pair(Method::SpecA);
    let mut session = client.udp_session();
    let (_, to) = udp_bootstrap(&mut session, &server, b"x");

    let big = pattern(9000);
    let packets = match session.encode(&big, None).unwrap() {
        UdpEncodeResult::Packets(packets) => packets,
        other => panic!("expected fragments, got {other:?}"),
    };
    assert!(packets.iter().all(|packet| packet.len() <= 1232));
    let mut assembled = None;
    for packet in packets.iter().rev() {
        match server.udp().decode(packet).unwrap() {
            UdpClientPacket::Pending => {}
            UdpClientPacket::Data { plain, .. } => assembled = Some(plain),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(assembled.unwrap(), big);

    assert_eq!(udp_reply(&mut session, &server, &to, &big), big);
}

#[test]
fn udp_replayed_data_packet_is_rejected() {
    let (client, server) = pair(Method::SpecA);
    let mut session = client.udp_session();
    udp_bootstrap(&mut session, &server, b"x");
    let packet = single(session.encode(b"once", None).unwrap());
    server.udp().decode(&packet).unwrap();
    let err = server.udp().decode(&packet).unwrap_err();
    assert_eq!(decode_error_kind(&err), Some(DecodeErrorKind::Replay));
}

#[test]
fn udp_wrong_password_bootstrap_is_rejected_by_the_client() {
    let client = client_with(Method::SpecA, "guess", |_| {});
    let server = server_with(Method::SpecA, "real", |_| {});
    let mut session = client.udp_session();
    let bootstrap = single(session.encode(b"x", None).unwrap());
    let plan = match server.udp().decode(&bootstrap).unwrap() {
        UdpClientPacket::HandshakeResponse(plan) => plan,
        other => panic!("expected handshake response, got {other:?}"),
    };
    let response = plan.packets()[0].clone();
    plan.complete(true);
    assert!(session.handle_bootstrap_response(&response, None).is_err());
    assert!(!session.has_ticket());
}

#[test]
fn tcp_ticket_gives_udp_zero_rtt() {
    let (client, server) = pair(Method::SpecA);
    tcp_connect(&client, &server, b"tcp first");

    let mut session = client.udp_session();
    assert!(session.has_ticket());
    let packet = single(session.encode(b"no bootstrap", None).unwrap());
    assert_eq!(packet[0], UDP_DATA_TYPE);
    let (plain, to) = server_data(server.udp().decode(&packet).unwrap());
    assert_eq!(plain, b"no bootstrap");
    assert_eq!(udp_reply(&mut session, &server, &to, b"reply"), b"reply");
    assert!(session.take_authenticated_response_ticket().is_some());
}

#[test]
fn udp_ticket_resumes_tcp() {
    let (client, server) = pair(Method::SpecA);
    let mut session = client.udp_session();
    udp_bootstrap(&mut session, &server, b"udp first");

    let (mut link, received) = tcp_connect(&client, &server, b"tcp after udp");
    assert_eq!(link.client_hello[CLIENT_HELLO_FLAGS], 1);
    assert_eq!(received, b"tcp after udp");
    assert_eq!(server_to_client(&mut link, b"ok"), b"ok");
}

#[test]
fn udp_ticket_rotation_moves_the_client_forward() {
    let client = client_with(Method::SpecA, "secret", |_| {});
    let server = server_with(Method::SpecA, "secret", |config| {
        config.ticket_lifetime = Duration::from_millis(600);
    });
    let mut session = client.udp_session();
    let (_, to) = udp_bootstrap(&mut session, &server, b"x");
    assert_eq!(to.ticket_generation(), 0);

    sleep(Duration::from_millis(350));
    assert_eq!(
        udp_reply(&mut session, &server, &to, b"rotating"),
        b"rotating"
    );

    let packet = single(session.encode(b"under new ticket", None).unwrap());
    let (plain, rotated) = server_data(server.udp().decode(&packet).unwrap());
    assert_eq!(plain, b"under new ticket");
    assert_eq!(rotated.ticket_generation(), 1);
    assert_eq!(rotated.association_id(), to.association_id());
}

#[test]
fn spec_time_method_runs_tcp_and_udp() {
    let (client, server) = pair(Method::spec_time());
    let (mut link, received) = tcp_connect(&client, &server, b"timed");
    assert_eq!(received, b"timed");
    assert_eq!(server_to_client(&mut link, &pattern(4000)), pattern(4000));

    let mut session = client.udp_session();
    let packet = single(session.encode(b"zero rtt", None).unwrap());
    let (plain, to) = server_data(server.udp().decode(&packet).unwrap());
    assert_eq!(plain, b"zero rtt");
    assert_eq!(
        udp_reply(&mut session, &server, &to, b"timed reply"),
        b"timed reply"
    );
}

#[test]
fn methods_do_not_interoperate() {
    let client = client_with(Method::SpecA, "secret", |_| {});
    let server = server_with(Method::spec_time(), "secret", |_| {});
    let mut session = client.tcp_session();
    let mut hello = Vec::new();
    session.encode(b"x", &mut hello).unwrap();
    let mut plain = Vec::new();
    let mut server_session = server.tcp_session();
    server_session.decode(&hello, &mut plain).unwrap();
    let mut server_hello = Vec::new();
    server_session.encode(&[], &mut server_hello).unwrap();
    assert!(session.decode(&server_hello, &mut plain).is_err());
}

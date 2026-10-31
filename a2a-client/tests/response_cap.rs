// Copyright AGNTCY Contributors (https://github.com/agntcy)
// Copyright A2A Contributors (https://github.com/a2aproject)
// SPDX-License-Identifier: Apache-2.0
//! The client must not buffer an unbounded response body from a remote agent,
//! and must still read every body the cap allows exactly as before.

use std::time::Duration;

use a2a::{
    A2AError, AgentCapabilities, AgentCard, AgentInterface, GetTaskRequest, SubscribeToTaskRequest,
    TRANSPORT_PROTOCOL_JSONRPC,
};
use a2a_client::agent_card::AgentCardResolver;
use a2a_client::jsonrpc::{JsonRpcTransport, JsonRpcTransportFactory};
use a2a_client::rest::{RestTransport, RestTransportFactory};
use a2a_client::{
    A2AClientFactory, DEFAULT_MAX_RESPONSE_BODY_BYTES, ServiceParams, Transport,
    default_reqwest_client_with_read_timeout,
};
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SMALL_CAP: usize = 1024;
const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

const JSONRPC_TASK: &str = r#"{"jsonrpc":"2.0","id":"1","result":{"id":"t1","contextId":"c1","status":{"state":"TASK_STATE_COMPLETED"}}}"#;
const REST_TASK: &str = r#"{"id":"t1","contextId":"c1","status":{"state":"TASK_STATE_COMPLETED"}}"#;

/// How the response body is delimited on the wire.
#[derive(Clone, Copy)]
enum Framing {
    /// `Content-Length` declares the size up front.
    ContentLength,
    /// No length: the body ends when the connection closes.
    CloseDelimited,
    /// Real `Transfer-Encoding: chunked` framing, in 100-byte chunks.
    Chunked,
}

async fn read_request(socket: &mut tokio::net::TcpStream) {
    let mut buf = vec![0u8; 8192];
    let _ = socket.read(&mut buf).await.unwrap();
}

/// Serves one response and returns the base URL of the server.
async fn serve(status: &str, content_type: &str, body: Vec<u8>, framing: Framing) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status.to_string();
    let content_type = content_type.to_string();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        let framing_header = match framing {
            Framing::ContentLength => format!("Content-Length: {}\r\n", body.len()),
            Framing::CloseDelimited => String::new(),
            Framing::Chunked => "Transfer-Encoding: chunked\r\n".to_string(),
        };
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n{framing_header}Connection: close\r\n\r\n"
        );
        let _ = socket.write_all(head.as_bytes()).await;
        match framing {
            Framing::Chunked => {
                for piece in body.chunks(100) {
                    let _ = socket
                        .write_all(format!("{:x}\r\n", piece.len()).as_bytes())
                        .await;
                    let _ = socket.write_all(piece).await;
                    let _ = socket.write_all(b"\r\n").await;
                }
                let _ = socket.write_all(b"0\r\n\r\n").await;
            }
            _ => {
                let _ = socket.write_all(&body).await;
            }
        }
        let _ = socket.shutdown().await;
    });
    format!("http://{addr}")
}

/// Serves a response that promises `declared` body bytes and sends only
/// `body`, then closes: a truncated body.
async fn serve_truncated(status: &str, declared: usize, body: Vec<u8>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status.to_string();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
        );
        let _ = socket.write_all(head.as_bytes()).await;
        let _ = socket.write_all(&body).await;
        let _ = socket.shutdown().await;
    });
    format!("http://{addr}")
}

/// Serves response headers and a few body bytes, then stalls for a minute.
async fn serve_stalled() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        let head =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{";
        let _ = socket.write_all(head.as_bytes()).await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    format!("http://{addr}")
}

/// A JSON-RPC response whose JSON body is padded to `body_len` bytes.
fn padded_body(body_len: usize) -> Vec<u8> {
    let prefix = r#"{"jsonrpc":"2.0","id":"1","result":null,"pad":""#;
    let suffix = r#""}"#;
    let pad = body_len.saturating_sub(prefix.len() + suffix.len());
    format!("{prefix}{}{suffix}", "x".repeat(pad)).into_bytes()
}

fn with_bom(body: &str) -> Vec<u8> {
    let mut bytes = BOM.to_vec();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

fn get_task_request() -> GetTaskRequest {
    GetTaskRequest {
        id: "t1".to_string(),
        history_length: None,
        tenant: None,
    }
}

fn client() -> reqwest::Client {
    a2a_client::default_reqwest_client(None).unwrap()
}

fn jsonrpc(endpoint: String) -> JsonRpcTransport {
    JsonRpcTransport::new(client(), endpoint).with_max_response_bytes(SMALL_CAP)
}

fn rest(base: String) -> RestTransport {
    RestTransport::new(client(), base).with_max_response_bytes(SMALL_CAP)
}

fn assert_cap_error(err: &A2AError) {
    let text = err.to_string();
    assert!(text.contains("exceeds"), "{text}");
    assert!(text.contains(&SMALL_CAP.to_string()), "{text}");
}

fn card() -> AgentCard {
    AgentCard {
        name: "nXn".into(),
        description: "test agent".into(),
        version: "1.0".into(),
        supported_interfaces: vec![AgentInterface::new(
            "http://localhost/jsonrpc",
            TRANSPORT_PROTOCOL_JSONRPC,
        )],
        capabilities: AgentCapabilities::default(),
        default_input_modes: vec!["text".into()],
        default_output_modes: vec!["text".into()],
        skills: vec![],
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: None,
        security_requirements: None,
        signatures: None,
    }
}

fn card_json() -> Vec<u8> {
    serde_json::to_vec(&card()).unwrap()
}

const ALL_FRAMINGS: [Framing; 3] = [
    Framing::ContentLength,
    Framing::CloseDelimited,
    Framing::Chunked,
];

#[tokio::test]
async fn client_rejects_response_over_cap() {
    for framing in ALL_FRAMINGS {
        let endpoint = serve(
            "200 OK",
            "application/json",
            padded_body(SMALL_CAP * 8),
            framing,
        )
        .await;
        let err = jsonrpc(endpoint)
            .get_task(&ServiceParams::new(), &get_task_request())
            .await
            .expect_err("a response over the cap must be refused");
        assert_cap_error(&err);

        let base = serve(
            "200 OK",
            "application/json",
            padded_body(SMALL_CAP * 8),
            framing,
        )
        .await;
        let err = rest(base)
            .get_task(&ServiceParams::new(), &get_task_request())
            .await
            .expect_err("a response over the cap must be refused");
        assert_cap_error(&err);
    }
}

#[tokio::test]
async fn response_under_cap_is_still_read() {
    for framing in ALL_FRAMINGS {
        let endpoint = serve("200 OK", "application/json", JSONRPC_TASK.into(), framing).await;
        let task = jsonrpc(endpoint)
            .get_task(&ServiceParams::new(), &get_task_request())
            .await
            .expect("a valid response under the cap must be read");
        assert_eq!(task.id, "t1");

        let base = serve("200 OK", "application/json", REST_TASK.into(), framing).await;
        let task = rest(base)
            .get_task(&ServiceParams::new(), &get_task_request())
            .await
            .expect("a valid response under the cap must be read");
        assert_eq!(task.id, "t1");
    }
}

#[tokio::test]
async fn response_with_utf8_bom_is_still_read() {
    let endpoint = serve(
        "200 OK",
        "application/json",
        with_bom(JSONRPC_TASK),
        Framing::ContentLength,
    )
    .await;
    let task = jsonrpc(endpoint)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect("a BOM-prefixed body was accepted before the cap and still is");
    assert_eq!(task.id, "t1");

    let base = serve(
        "200 OK",
        "application/json",
        with_bom(REST_TASK),
        Framing::Chunked,
    )
    .await;
    let task = rest(base)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect("a BOM-prefixed body was accepted before the cap and still is");
    assert_eq!(task.id, "t1");
}

#[tokio::test]
async fn body_exactly_at_the_cap_is_read_and_one_byte_over_is_refused() {
    let at_cap = JSONRPC_TASK.len();
    let endpoint = serve(
        "200 OK",
        "application/json",
        JSONRPC_TASK.into(),
        Framing::CloseDelimited,
    )
    .await;
    let task = JsonRpcTransport::new(client(), endpoint)
        .with_max_response_bytes(at_cap)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect("a body of exactly the cap is allowed");
    assert_eq!(task.id, "t1");

    let endpoint = serve(
        "200 OK",
        "application/json",
        JSONRPC_TASK.into(),
        Framing::CloseDelimited,
    )
    .await;
    let err = JsonRpcTransport::new(client(), endpoint)
        .with_max_response_bytes(at_cap - 1)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("one byte over the cap is refused");
    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[tokio::test]
async fn agent_card_over_cap_is_refused() {
    for framing in ALL_FRAMINGS {
        let base = serve(
            "200 OK",
            "application/json",
            padded_body(SMALL_CAP * 8),
            framing,
        )
        .await;
        let err = AgentCardResolver::new(None)
            .with_max_response_bytes(SMALL_CAP)
            .resolve(&base)
            .await
            .expect_err("an agent card over the cap must be refused");
        assert_cap_error(&err);
        assert!(err.to_string().contains("agent card"), "{err}");
    }
}

#[tokio::test]
async fn agent_card_with_bom_is_accepted_and_invalid_utf8_is_rejected() {
    let base = serve(
        "200 OK",
        "application/json",
        {
            let mut bytes = BOM.to_vec();
            bytes.extend_from_slice(&card_json());
            bytes
        },
        Framing::ContentLength,
    )
    .await;
    let resolved = AgentCardResolver::new(None)
        .resolve(&base)
        .await
        .expect("a BOM-prefixed agent card is accepted");
    assert_eq!(resolved.name, "nXn");

    // The same card with one invalid UTF-8 byte inside a string value.
    let mut bytes = card_json();
    let at = bytes.iter().position(|b| *b == b'X').unwrap();
    bytes[at] = 0xFF;
    let base = serve("200 OK", "application/json", bytes, Framing::ContentLength).await;
    let err = AgentCardResolver::new(None)
        .resolve(&base)
        .await
        .expect_err("invalid UTF-8 must be rejected, not patched with U+FFFD");
    assert!(
        err.to_string().contains("failed to parse agent card"),
        "{err}"
    );
}

#[tokio::test]
async fn rest_error_keeps_its_http_status_when_the_body_is_unusable() {
    // A body that ends before the length it declared.
    let base = serve_truncated("404 Not Found", 500, b"{\"error\":".to_vec()).await;
    let err = rest(base)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("a 404 is an error");
    assert!(err.to_string().contains("HTTP 404"), "{err}");

    // A body over the cap, declared and undeclared.
    for framing in ALL_FRAMINGS {
        let base = serve(
            "404 Not Found",
            "application/json",
            padded_body(SMALL_CAP * 8),
            framing,
        )
        .await;
        let err = rest(base)
            .get_task(&ServiceParams::new(), &get_task_request())
            .await
            .expect_err("a 404 is an error");
        assert!(err.to_string().contains("HTTP 404"), "{err}");
        assert!(!err.to_string().contains("exceeds"), "{err}");
    }
}

#[tokio::test]
async fn rest_error_with_a_small_body_is_still_parsed() {
    let body = r#"{"error":{"code":404,"status":"NOT_FOUND","message":"no such task"}}"#;
    let base = serve(
        "404 Not Found",
        "application/json",
        body.into(),
        Framing::Chunked,
    )
    .await;
    let err = rest(base)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("a 404 is an error");
    assert!(err.to_string().contains("no such task"), "{err}");
}

#[tokio::test]
async fn sse_event_over_the_cap_ends_the_stream_with_an_error() {
    // 8 KiB of one event that never reaches a blank line.
    let body = format!("data: {}", "x".repeat(SMALL_CAP * 8)).into_bytes();
    let base = serve("200 OK", "text/event-stream", body, Framing::Chunked).await;
    let mut stream = rest(base)
        .subscribe_to_task(
            &ServiceParams::new(),
            &SubscribeToTaskRequest {
                id: "t1".into(),
                tenant: None,
            },
        )
        .await
        .expect("the stream opens");
    let first = stream
        .next()
        .await
        .expect("the stream reports the overflow");
    let err = first.expect_err("an event over the cap is an error");
    assert_cap_error(&err);
    assert!(
        stream.next().await.is_none(),
        "the stream ends after the error"
    );
}

#[tokio::test]
async fn factory_cap_reaches_the_default_transports() {
    let factory = A2AClientFactory::builder()
        .with_max_response_bytes(SMALL_CAP)
        .build();
    let endpoint = serve(
        "200 OK",
        "application/json",
        padded_body(SMALL_CAP * 8),
        Framing::Chunked,
    )
    .await;
    let mut card = card();
    card.supported_interfaces = vec![AgentInterface::new(&endpoint, TRANSPORT_PROTOCOL_JSONRPC)];
    let client = factory.create_from_card(&card).await.unwrap();
    let err = client
        .get_task(&get_task_request())
        .await
        .expect_err("the factory's cap applies");
    assert_cap_error(&err);
}

#[tokio::test]
async fn transport_factories_pass_their_cap_down() {
    let endpoint = serve(
        "200 OK",
        "application/json",
        padded_body(SMALL_CAP * 8),
        Framing::Chunked,
    )
    .await;
    let mut card = card();
    card.supported_interfaces = vec![AgentInterface::new(&endpoint, TRANSPORT_PROTOCOL_JSONRPC)];
    let factory = JsonRpcTransportFactory::new(None).with_max_response_bytes(SMALL_CAP);
    let transport =
        a2a_client::TransportFactory::create(&factory, &card, &card.supported_interfaces[0])
            .await
            .unwrap();
    let err = transport
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("the factory's cap applies");
    assert_cap_error(&err);

    let base = serve(
        "200 OK",
        "application/json",
        padded_body(SMALL_CAP * 8),
        Framing::Chunked,
    )
    .await;
    card.supported_interfaces = vec![AgentInterface::new(
        &base,
        a2a::TRANSPORT_PROTOCOL_HTTP_JSON,
    )];
    let factory = RestTransportFactory::new(None).with_max_response_bytes(SMALL_CAP);
    let transport =
        a2a_client::TransportFactory::create(&factory, &card, &card.supported_interfaces[0])
            .await
            .unwrap();
    let err = transport
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("the factory's cap applies");
    assert_cap_error(&err);
}

#[tokio::test]
async fn read_timeout_ends_a_stalled_response() {
    let endpoint = serve_stalled().await;
    let http =
        default_reqwest_client_with_read_timeout(None, Some(Duration::from_millis(300))).unwrap();
    let transport = JsonRpcTransport::new(http, endpoint);
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        transport.get_task(&ServiceParams::new(), &get_task_request()),
    )
    .await
    .expect("the read timeout must end the call long before the server does");
    let err = outcome.expect_err("a stalled body is an error");
    assert!(
        err.to_string()
            .contains("failed to parse JSON-RPC response"),
        "{err}"
    );
}

/// The default is 10 MiB, the same bound as the server's request cap
/// (`MAX_REQUEST_BODY_BYTES` in `a2a-server/src/jsonrpc.rs`; `a2a-client` does
/// not depend on `a2a-server`, so the value is pinned here, not read).
#[test]
fn default_cap_is_ten_mib() {
    assert_eq!(DEFAULT_MAX_RESPONSE_BODY_BYTES, 10 * 1024 * 1024);
}

/// A body that disagrees with its `Content-Length` is never counted against
/// the cap: the HTTP layer enforces the declared framing, so a longer body is
/// cut at the declared length and a shorter one fails to read. Either way the
/// client errors out without crossing the cap and without reading the excess.
#[tokio::test]
async fn body_that_disagrees_with_its_content_length_is_not_counted_against_the_cap() {
    // Understated: declares 64 bytes, then sends 64 KiB (far over the cap).
    let endpoint = serve_truncated("200 OK", 64, padded_body(SMALL_CAP * 64)).await;
    let err = jsonrpc(endpoint)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("a body cut at its declared length is not a valid response");
    let text = err.to_string();
    assert!(!text.contains("exceeds"), "{text}");

    // Overstated: declares 512 bytes (under the cap), sends 40 and closes.
    let endpoint = serve_truncated("200 OK", SMALL_CAP / 2, padded_body(40)).await;
    let err = jsonrpc(endpoint)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("a body shorter than its declared length fails to read");
    let text = err.to_string();
    assert!(!text.contains("exceeds"), "{text}");
}

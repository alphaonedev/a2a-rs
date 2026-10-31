// Copyright AGNTCY Contributors (https://github.com/agntcy)
// Copyright A2A Contributors (https://github.com/a2aproject)
// SPDX-License-Identifier: Apache-2.0
//! The client must not buffer an unbounded response body from a remote agent.

use a2a::GetTaskRequest;
use a2a_client::jsonrpc::JsonRpcTransport;
use a2a_client::rest::RestTransport;
use a2a_client::{DEFAULT_MAX_RESPONSE_BODY_BYTES, ServiceParams, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SMALL_CAP: usize = 1024;

/// Serves one HTTP response whose JSON body is padded to `body_len` bytes.
///
/// With `declare_length` the response carries `Content-Length`; without it
/// the body is delimited by closing the connection, so the client cannot
/// reject it from the header and has to count the bytes it reads.
async fn serve_padded_body(body_len: usize, declare_length: bool) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = socket.read(&mut buf).await.unwrap();
        let prefix = r#"{"jsonrpc":"2.0","id":"1","result":null,"pad":""#;
        let suffix = r#""}"#;
        let pad = body_len.saturating_sub(prefix.len() + suffix.len());
        let body = format!("{prefix}{}{suffix}", "x".repeat(pad));
        let length = if declare_length {
            format!("Content-Length: {}\r\n", body.len())
        } else {
            String::new()
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{length}Connection: close\r\n\r\n"
        );
        let _ = socket.write_all(head.as_bytes()).await;
        let _ = socket.write_all(body.as_bytes()).await;
        let _ = socket.shutdown().await;
    });
    format!("http://{addr}")
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

fn assert_cap_error(err: &a2a::A2AError) {
    let text = err.to_string();
    assert!(text.contains("exceeds"), "{text}");
    assert!(text.contains(&SMALL_CAP.to_string()), "{text}");
}

#[tokio::test]
async fn client_rejects_response_over_cap() {
    for declare_length in [true, false] {
        let endpoint = serve_padded_body(SMALL_CAP * 8, declare_length).await;
        let transport =
            JsonRpcTransport::new(client(), endpoint).with_max_response_bytes(SMALL_CAP);
        let err = transport
            .get_task(&ServiceParams::new(), &get_task_request())
            .await
            .expect_err("a response over the cap must be refused");
        assert_cap_error(&err);

        let base = serve_padded_body(SMALL_CAP * 8, declare_length).await;
        let transport = RestTransport::new(client(), base).with_max_response_bytes(SMALL_CAP);
        let err = transport
            .get_task(&ServiceParams::new(), &get_task_request())
            .await
            .expect_err("a response over the cap must be refused");
        assert_cap_error(&err);
    }
}

#[tokio::test]
async fn response_under_cap_is_still_read() {
    let endpoint = serve_padded_body(SMALL_CAP / 2, true).await;
    let transport = JsonRpcTransport::new(client(), endpoint).with_max_response_bytes(SMALL_CAP);
    let err = transport
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("the body has no task, so the call fails after the read");
    // Reaching the JSON-RPC layer proves the body was read in full.
    assert!(!err.to_string().contains("exceeds"), "{err}");
}

#[test]
fn default_cap_matches_the_server_request_cap() {
    assert_eq!(DEFAULT_MAX_RESPONSE_BODY_BYTES, 10 * 1024 * 1024);
}

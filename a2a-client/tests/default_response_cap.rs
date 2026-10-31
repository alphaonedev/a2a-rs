// Copyright AGNTCY Contributors (https://github.com/agntcy)
// Copyright A2A Contributors (https://github.com/a2aproject)
// SPDX-License-Identifier: Apache-2.0
//! Behavioural check of the default response cap, through constructors that
//! exist both before and after the cap: a transport built with `new` must
//! refuse a 20 MiB response instead of buffering it. Before the cap this file
//! compiles and the tests fail on their assertions, which is the red result.

use a2a::GetTaskRequest;
use a2a_client::agent_card::AgentCardResolver;
use a2a_client::jsonrpc::JsonRpcTransport;
use a2a_client::rest::RestTransport;
use a2a_client::{ServiceParams, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TWENTY_MIB: usize = 20 * 1024 * 1024;

/// Serves one close-delimited (no `Content-Length`) 200 response of
/// `body_len` bytes: the client can only refuse it by counting what it reads.
async fn serve_close_delimited(body_len: usize) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = socket.read(&mut buf).await.unwrap();
        let prefix = r#"{"jsonrpc":"2.0","id":"1","result":null,"pad":""#;
        let suffix = r#""}"#;
        let pad = body_len.saturating_sub(prefix.len() + suffix.len());
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
        let _ = socket.write_all(head.as_bytes()).await;
        let _ = socket.write_all(prefix.as_bytes()).await;
        let chunk = vec![b'x'; 64 * 1024];
        let mut left = pad;
        while left > 0 {
            let n = left.min(chunk.len());
            if socket.write_all(&chunk[..n]).await.is_err() {
                return;
            }
            left -= n;
        }
        let _ = socket.write_all(suffix.as_bytes()).await;
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

#[tokio::test]
async fn jsonrpc_transport_refuses_a_20_mib_body_by_default() {
    let endpoint = serve_close_delimited(TWENTY_MIB).await;
    let err = JsonRpcTransport::new(client(), endpoint)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("a 20 MiB response must be refused");
    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[tokio::test]
async fn rest_transport_refuses_a_20_mib_body_by_default() {
    let base = serve_close_delimited(TWENTY_MIB).await;
    let err = RestTransport::new(client(), base)
        .get_task(&ServiceParams::new(), &get_task_request())
        .await
        .expect_err("a 20 MiB response must be refused");
    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[tokio::test]
async fn agent_card_resolver_refuses_a_20_mib_body_by_default() {
    let base = serve_close_delimited(TWENTY_MIB).await;
    let err = AgentCardResolver::new(None)
        .resolve(&base)
        .await
        .expect_err("a 20 MiB agent card must be refused");
    assert!(err.to_string().contains("exceeds"), "{err}");
}

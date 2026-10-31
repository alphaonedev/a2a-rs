// Copyright AGNTCY Contributors (https://github.com/agntcy)
// Copyright A2A Contributors (https://github.com/a2aproject)
// SPDX-License-Identifier: Apache-2.0
//! Raw wire logging for the HTTP bindings, with credential redaction.
//!
//! Emits on the `a2a_client::wire` target at `DEBUG`; a consumer opts in by
//! installing a subscriber. Redaction happens where the line is built, so no
//! flag or filter can produce an unredacted header (`A2ACLI_AUTH_004`).

use a2a::A2AError;
use reqwest::header::{HeaderMap, HeaderName};

/// The tracing target every wire event carries; crate-private, so this
/// module is not public API. Consumers filter by the target's name.
pub(crate) const TARGET: &str = "a2a_client::wire";

const REDACTED: &str = "(redacted)";

/// Header names carrying protocol metadata rather than credentials.
///
/// An allowlist, not a denylist, so the default is fail-closed: `ServiceParams`
/// is this crate's auth channel, so an unrecognised name is more likely a
/// credential than not.
const VISIBLE_HEADERS: &[&str] = &[
    "a2a-version",
    "accept",
    "accept-encoding",
    "content-length",
    "content-type",
    "host",
    "user-agent",
];

fn is_visible(name: &HeaderName) -> bool {
    VISIBLE_HEADERS.contains(&name.as_str())
}

/// Renders headers, redacting by value and never by presence: the name stays
/// visible so a credential's attachment can still be confirmed.
fn render_headers(headers: &HeaderMap) -> String {
    let mut rendered: Vec<String> = headers
        .iter()
        .map(|(name, value)| {
            if is_visible(name) {
                // A non-UTF-8 header value cannot be printed, but its
                // presence still can be.
                let shown = value.to_str().unwrap_or("(binary)");
                format!("{name}: {shown}")
            } else {
                format!("{name}: {REDACTED}")
            }
        })
        .collect();
    // Sorted so a log line is reproducible: HeaderMap iteration order is not
    // guaranteed, and tests assert on this text.
    rendered.sort();
    rendered.join(", ")
}

/// Renders a body verbatim: §7.2 asks for the raw messages, and credentials
/// travel in headers rather than in A2A bodies.
fn render_body(body: &[u8]) -> String {
    match std::str::from_utf8(body) {
        Ok(text) => text.to_string(),
        Err(_) => format!("({} non-UTF-8 bytes)", body.len()),
    }
}

/// Sends a request, logging it first, and hands back the response untouched
/// so that a streaming caller can still consume it as a byte stream.
pub(crate) async fn send(
    client: &reqwest::Client,
    builder: reqwest::RequestBuilder,
) -> Result<reqwest::Response, A2AError> {
    // `build` rather than `send`, so the logged request is the one that goes
    // out, including the headers reqwest adds. A build failure carries the
    // same message as a send failure: a caller cannot act differently on them.
    let request = builder
        .build()
        .map_err(|e| A2AError::internal(format!("HTTP request failed: {e}")))?;

    // Values as statements rather than macro arguments, so coverage can see
    // them run; the `enabled!` guard keeps them lazy.
    if tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
        let method = request.method();
        let url = request.url();
        let headers = render_headers(request.headers());
        let body = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .map(render_body)
            .unwrap_or_default();
        tracing::debug!(target: TARGET, %method, %url, %headers, %body, "A2A wire request");
    }

    client
        .execute(request)
        .await
        .map_err(|e| A2AError::internal(format!("HTTP request failed: {e}")))
}

/// Reads a response body to text, logging status and body, so callers parse
/// from the string instead of `Response::json` — the raw bytes have to be seen
/// first. The error is unmapped so each caller keeps its own message.
pub(crate) async fn response_text(
    resp: reqwest::Response,
    max_bytes: usize,
    context: &str,
) -> Result<String, A2AError> {
    let status = resp.status();
    let text = read_capped_text(resp, max_bytes, context).await?;
    log_response(status, &text);
    Ok(text)
}

/// Default cap, in bytes, on a response body the client will buffer.
///
/// Sized like the server's request body limit (`MAX_REQUEST_BODY_BYTES`,
/// 10 MiB), so a peer is held to the same bound in both directions. Override
/// it per transport with `with_max_response_bytes`. The same bound caps one
/// buffered Server-Sent Events event on a streaming call.
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024;

/// The error for a body or event that crossed the cap; `context` names the
/// caller so the message says which read was refused.
pub(crate) fn response_too_large(context: &str, max_bytes: usize) -> A2AError {
    A2AError::internal(format!(
        "{context}: response body exceeds the {max_bytes} byte limit"
    ))
}

/// The UTF-8 byte order mark. `reqwest::Response::text` strips it while
/// decoding, so the capped reader does too.
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Reads a response body into bytes, never buffering more than `max_bytes`.
///
/// A declared `Content-Length` over the cap is refused before any body byte
/// is read. A body without one (chunked, or delimited by closing the
/// connection) is counted as it streams and abandoned the moment it crosses
/// the cap. A body that disagrees with its declared length cannot pass the cap
/// either: the HTTP layer enforces the framing, so a longer body is cut to the
/// declared length and a shorter one fails to read, and neither is counted
/// against the cap. The buffer is sized from
/// the declared length (bounded by the cap) and grows by doubling but never
/// past the cap, so the transient peak stays at the cap plus allocator
/// rounding. One leading UTF-8 byte order mark is removed. `context` prefixes
/// a transport read failure and the over-cap error, so each caller keeps its
/// own message.
pub(crate) async fn read_capped_bytes(
    mut resp: reqwest::Response,
    max_bytes: usize,
    context: &str,
) -> Result<Vec<u8>, A2AError> {
    let declared = resp.content_length();
    if declared.is_some_and(|declared| u64::try_from(max_bytes).is_ok_and(|cap| declared > cap)) {
        return Err(response_too_large(context, max_bytes));
    }

    let initial = declared.map_or(0, |n| usize::try_from(n).unwrap_or(max_bytes));
    let mut body: Vec<u8> = Vec::with_capacity(initial.min(max_bytes));
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| A2AError::internal(format!("{context}: {e}")))?
    {
        let needed = body.len().saturating_add(chunk.len());
        if needed > max_bytes {
            return Err(response_too_large(context, max_bytes));
        }
        if needed > body.capacity() {
            // Doubling, clamped to the cap, so `Vec`'s own growth cannot
            // reserve past the bound.
            let target = needed.max(body.capacity().saturating_mul(2)).min(max_bytes);
            body.reserve_exact(target - body.len());
        }
        body.extend_from_slice(&chunk);
    }

    if body.starts_with(&UTF8_BOM) {
        body.drain(..UTF8_BOM.len());
    }
    Ok(body)
}

/// Reads a capped response body to text, decoding invalid UTF-8 lossily as
/// `Response::text` does; used where the base behaviour is to tolerate it.
/// A caller that must reject invalid UTF-8 uses [`read_capped_bytes`].
pub(crate) async fn read_capped_text(
    resp: reqwest::Response,
    max_bytes: usize,
    context: &str,
) -> Result<String, A2AError> {
    let body = read_capped_bytes(resp, max_bytes, context).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Logs a response that the caller has already read the body of.
pub(crate) fn log_response(status: reqwest::StatusCode, body: &str) {
    let status = status.as_u16();
    tracing::debug!(target: TARGET, %status, %body, "A2A wire response");
}

/// Logs one raw SSE frame — the streaming counterpart of [`log_response`].
/// Called from the shared SSE parser, so both bindings get it from one site.
pub(crate) fn log_stream_event(event_text: &str) {
    tracing::debug!(target: TARGET, event = %event_text, "A2A wire stream event");
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderValue, InvalidHeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn credential_headers_are_redacted_by_value_not_by_presence() {
        let rendered = render_headers(&headers(&[
            ("authorization", "Bearer super-secret"),
            ("x-api-key", "key-12345"),
        ]));

        // The names survive so the log still shows the credential was
        // attached.
        assert!(rendered.contains("authorization:"), "{rendered}");
        assert!(rendered.contains("x-api-key:"), "{rendered}");
        // The values do not.
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(!rendered.contains("key-12345"), "{rendered}");
    }

    #[test]
    fn protocol_headers_stay_visible() {
        let rendered = render_headers(&headers(&[
            ("a2a-version", "1.0"),
            ("content-type", "application/json"),
            ("accept", "text/event-stream"),
        ]));

        assert!(rendered.contains("a2a-version: 1.0"), "{rendered}");
        assert!(
            rendered.contains("content-type: application/json"),
            "{rendered}"
        );
        assert!(rendered.contains("accept: text/event-stream"), "{rendered}");
    }

    /// An unknown service parameter is a credential until proven otherwise.
    #[test]
    fn an_unrecognised_header_is_redacted_rather_than_leaked() {
        let rendered = render_headers(&headers(&[("x-some-future-scheme", "tenant-secret")]));

        assert_eq!(rendered, format!("x-some-future-scheme: {REDACTED}"));
    }

    #[test]
    fn headers_render_in_a_stable_order() {
        let pairs = [
            ("x-api-key", "k"),
            ("a2a-version", "1.0"),
            ("content-type", "application/json"),
        ];
        let forward = render_headers(&headers(&pairs));
        let mut reversed = pairs;
        reversed.reverse();
        assert_eq!(forward, render_headers(&headers(&reversed)));
    }

    #[test]
    fn a_non_utf8_header_value_shows_its_presence_only() -> Result<(), InvalidHeaderValue> {
        let mut map = HeaderMap::new();
        // A visible name, so the value is the thing being tested.
        map.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        assert_eq!(render_headers(&map), "content-type: (binary)");
        Ok(())
    }

    #[test]
    fn a_non_utf8_body_is_summarised_rather_than_mangled() {
        assert_eq!(render_body(&[0xff, 0xfe, 0xfd]), "(3 non-UTF-8 bytes)");
        assert_eq!(render_body(b"{\"a\":1}"), "{\"a\":1}");
    }
}

// Copyright AGNTCY Contributors (https://github.com/agntcy)
// Copyright A2A Contributors (https://github.com/a2aproject)
// SPDX-License-Identifier: Apache-2.0
// Framing internals reached by the fuzz targets in fuzz/ — see #238.
// Thin wrappers, not re-exports: the originals stay crate-private.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_support {
    use a2a::{A2AError, StreamResponse};

    pub fn find_event_boundary(buf: &[u8]) -> Option<(usize, usize)> {
        crate::jsonrpc::find_event_boundary(buf)
    }

    pub fn parse_stream_tail(
        buf: &[u8],
        parse_event: &dyn Fn(&str) -> Option<Result<StreamResponse, A2AError>>,
    ) -> Option<Result<StreamResponse, A2AError>> {
        crate::jsonrpc::parse_stream_tail(buf, parse_event)
    }
}

pub mod agent_card;
pub mod auth;
pub mod client;
pub mod factory;
pub mod jsonrpc;
pub mod middleware;
mod push_config_compat;
pub mod rest;
pub mod transport;
mod wire;

pub use client::A2AClient;
pub use factory::A2AClientFactory;
pub use futures::stream::BoxStream;
pub use transport::{ServiceParams, Transport, TransportFactory};
pub use wire::DEFAULT_MAX_RESPONSE_BODY_BYTES;

#[cfg(any(feature = "rustls-tls", feature = "rustls-no-provider"))]
pub use rustls;

/// Build a `reqwest::Client` whose TLS layer matches this crate's feature
/// selection, optionally adding extra root certificates from a PEM bundle.
///
/// Sets no read timeout; see [`default_reqwest_client_with_read_timeout`].
pub fn default_reqwest_client(
    extra_root_pem: Option<&[u8]>,
) -> Result<reqwest::Client, a2a::A2AError> {
    default_reqwest_client_with_read_timeout(extra_root_pem, None)
}

/// [`default_reqwest_client`] with an optional read timeout.
///
/// `read_timeout` bounds the wait for each read of a response, headers and
/// every body chunk, not the whole call, so a peer that stalls or drips bytes
/// slower than that ends the call with an error. It is `None` by default so a
/// quiet Server-Sent Events stream is not cut: pick a value longer than the
/// longest gap the agent leaves between stream events. The response size cap
/// bounds memory; this bounds time.
pub fn default_reqwest_client_with_read_timeout(
    #[allow(unused_variables)] extra_root_pem: Option<&[u8]>,
    read_timeout: Option<std::time::Duration>,
) -> Result<reqwest::Client, a2a::A2AError> {
    let builder = reqwest::Client::builder();
    let builder = match read_timeout {
        Some(timeout) => builder.read_timeout(timeout),
        None => builder,
    };

    #[cfg(any(
        feature = "rustls-tls",
        feature = "rustls-no-provider",
        feature = "native-tls"
    ))]
    let builder = match extra_root_pem {
        Some(pem) => {
            let certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|e| a2a::A2AError::internal(format!("invalid PEM certificate: {e}")))?;
            builder.tls_certs_merge(certs)
        }
        None => builder,
    };

    builder
        .build()
        .map_err(|e| a2a::A2AError::internal(format!("failed to build HTTP client: {e}")))
}

pub(crate) fn a2a_error_from_details(
    code: i32,
    message: String,
    details: Vec<a2a::TypedDetail>,
) -> a2a::A2AError {
    use a2a::{error_code, errordetails, reason_to_error_code};
    use serde_json::Value;

    let mut code = code;
    let mut message = message;

    for detail in &details {
        match detail.type_url.as_str() {
            errordetails::BAD_REQUEST_TYPE => {
                if let Some(Value::Array(violations)) = detail.value.get("fieldViolations") {
                    let violation_strs: Vec<String> = violations
                        .iter()
                        .filter_map(|v| {
                            let field = v.get("field")?.as_str()?;
                            let desc = v.get("description")?.as_str()?;
                            if field.is_empty() {
                                Some(desc.to_string())
                            } else {
                                Some(format!("{field}: {desc}"))
                            }
                        })
                        .collect();
                    if !violation_strs.is_empty() {
                        message = format!("{}: {}", message, violation_strs.join("; "));
                    }
                }
                if code == error_code::INTERNAL_ERROR {
                    code = error_code::INVALID_PARAMS;
                }
            }
            errordetails::ERROR_INFO_TYPE => {
                if let Some(Value::String(domain)) = detail.value.get("domain") {
                    if domain == errordetails::PROTOCOL_DOMAIN {
                        if let Some(Value::String(reason)) = detail.value.get("reason") {
                            if let Some(c) = reason_to_error_code(reason) {
                                code = c;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    a2a::A2AError {
        code,
        message,
        details: (!details.is_empty()).then_some(details),
    }
}

#[cfg(all(test, any(feature = "rustls-tls", feature = "native-tls")))]
pub(crate) mod test_utils {
    pub fn rcgen_self_signed_ca_pem() -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem().into_bytes()
    }
}

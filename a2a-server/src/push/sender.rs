// Copyright AGNTCY Contributors (https://github.com/agntcy)
// Copyright A2A Contributors (https://github.com/a2aproject)
// SPDX-License-Identifier: Apache-2.0
use a2a::*;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// HTTP push notification sender.
///
/// Sends A2A streaming events to a push notification endpoint over HTTP POST.
pub struct HttpPushSender {
    client: reqwest::Client,
    fail_on_error: bool,
    validate_urls: bool,
    retry: RetryPolicy,
}

/// Capped exponential backoff with jitter, used between push delivery
/// attempts.
///
/// The wait before retry number `n` (counting from 1) is drawn uniformly from
/// the upper half of `min(initial * 2^(n - 1), max)`, so retries of many
/// deliveries that failed together do not all hit the webhook at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Backoff {
    /// Upper bound of the wait before the first retry.
    pub initial: Duration,
    /// Upper bound of the wait before any retry.
    pub max: Duration,
}

impl Backoff {
    /// Backoff growing from `initial` and never exceeding `max`.
    pub const fn new(initial: Duration, max: Duration) -> Self {
        Backoff { initial, max }
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff::new(Duration::from_millis(200), Duration::from_secs(5))
    }
}

/// How [`HttpPushSender`] retries a delivery that failed for a transient
/// reason.
///
/// Only connect errors, `429 Too Many Requests` and `5xx` responses are
/// retried; any other response (including every other `4xx`) and any other
/// transport error, such as a timeout after the request was sent, is final.
/// A `Retry-After` header given in seconds lengthens the wait, but never
/// beyond [`Backoff::max`]: a response asking for a longer pause is treated as
/// final and is not retried. A `Retry-After` given as an HTTP date is ignored
/// and the backoff alone applies.
///
/// Retries sleep inside [`HttpPushSender::send_push`], so a caller that awaits
/// it waits for them. [`DefaultRequestHandler`](crate::DefaultRequestHandler)
/// delivers on a background queue (since the push dispatcher), so there the
/// waiting does not delay the task; a custom caller of `send_push` must not
/// await it on a latency-sensitive path. A request-limiter permit is never held
/// during the wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// Total number of attempts, the first included. `0` and `1` both mean
    /// no retry.
    pub max_attempts: u32,
    /// Wait between attempts.
    pub backoff: Backoff,
}

impl RetryPolicy {
    /// A policy making up to `max_attempts` attempts with `backoff` between
    /// them.
    pub const fn new(max_attempts: u32, backoff: Backoff) -> Self {
        RetryPolicy {
            max_attempts,
            backoff,
        }
    }

    /// A policy that never retries.
    pub const fn none() -> Self {
        RetryPolicy::new(1, Backoff::new(Duration::ZERO, Duration::ZERO))
    }

    /// The number of attempts that will be made: [`Self::max_attempts`], at
    /// least 1.
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts.max(1)
    }

    /// The wait before retry number `retry` (1 for the first retry).
    pub fn delay_before_retry(&self, retry: u32) -> Duration {
        let doublings = retry.saturating_sub(1).min(31);
        let ceiling = self
            .backoff
            .initial
            .saturating_mul(1u32 << doublings)
            .min(self.backoff.max);
        let floor = ceiling / 2;
        floor + (ceiling - floor).mul_f64(random_unit())
    }
}

impl Default for RetryPolicy {
    /// Three attempts with [`Backoff::default`].
    fn default() -> Self {
        RetryPolicy::new(3, Backoff::default())
    }
}

/// A uniformly distributed value in `[0, 1)` that does not need a
/// cryptographic source: it only spreads retries apart.
fn random_unit() -> f64 {
    use std::hash::{BuildHasher, Hasher};
    let bits = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    (bits >> 11) as f64 / (1u64 << 53) as f64
}

fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// The `Retry-After` header when it is a whole number of seconds.
fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// Configuration for [`HttpPushSender`].
///
/// The struct is `#[non_exhaustive]` so that new settings are not breaking
/// changes. Outside this crate build it from [`Default`] and assign the fields
/// to change; a struct expression, even with `..Default::default()`, is not
/// allowed there:
///
/// ```
/// use a2a_server::HttpPushSenderConfig;
///
/// let mut config = HttpPushSenderConfig::default();
/// config.validate_urls = false;
/// ```
#[non_exhaustive]
pub struct HttpPushSenderConfig {
    /// HTTP request timeout (default: 30s).
    pub timeout: Duration,
    /// Timeout for establishing the connection of one attempt (default: 10s).
    /// A connect timeout counts as a connect error and is retried according to
    /// [`Self::retry`]; [`Self::timeout`] still bounds the whole request.
    pub connect_timeout: Duration,
    /// If true, push delivery errors reach the caller instead of only being
    /// logged.
    ///
    /// [`DefaultRequestHandler`](crate::DefaultRequestHandler) delivers
    /// pushes on a background queue. Two kinds of error exist:
    ///
    /// * Errors known before any request is sent (the push URL checks, the
    ///   CR/LF header checks, a config store that cannot be read) fail the
    ///   event synchronously whatever this flag says, as they did when
    ///   delivery was inline. They are checked against the configs the task
    ///   has when the event is queued; a config added after the event was
    ///   queued is checked at delivery, and its errors follow the delivery
    ///   rule below.
    /// * Delivery errors (a refused connection, a timeout, a non-success
    ///   status, a full queue, a failed delivery worker) are logged while the
    ///   flag is off and never delay or fail the event that caused them. With
    ///   the flag on they reach the caller:
    ///   * the execution stops at the first failed request: the error is
    ///     reported as soon as that request fails, without waiting for the
    ///     other configs of the event (their requests are cancelled or never
    ///     started), pushes still queued behind it are skipped, and the
    ///     stream ends with the error. A failure noticed while events are
    ///     still arriving ends the execution at the next event after it was
    ///     recorded, not necessarily the next event;
    ///   * the terminal event and the end of a run that stopped without one
    ///     wait until every push already queued for the task, their own
    ///     included, has been delivered or a failure is recorded; a
    ///     cancellation waits for all of them and returns the first error
    ///     (a failure recorded by a concurrent execution does not shorten
    ///     the cancellation's wait). That is a latency cost strict mode opts
    ///     into. With no failure the wait can reach the queue depth (64) x
    ///     ceil(configs / 4) x the time of one request;
    ///   * an event dropped because the task's queue was full is reported as
    ///     an error naming the full queue.
    pub fail_on_error: bool,
    /// If true (default), guard push URLs against SSRF. A string pre-check
    /// (scheme must be http/https; host must not be a loopback, private,
    /// link-local, multicast, unspecified, or cloud-metadata literal) fails
    /// before any network activity. A connect-time resolver then drops any
    /// resolved address in those ranges before dialing, so a hostname cannot
    /// reach a blocked address through DNS (split-horizon, attacker-controlled
    /// records, or rebinding). Redirects are re-screened per hop with the same
    /// string check, and the sender uses no system proxy, since either path
    /// would otherwise reach an address the guard never saw. Disable only when
    /// pushing to local webhooks in trusted test environments; that turns off
    /// the whole guard.
    pub validate_urls: bool,
    /// Retry of transient delivery failures (default: [`RetryPolicy::default`]).
    /// Use [`RetryPolicy::none`] to try each delivery once.
    pub retry: RetryPolicy,
}

impl Default for HttpPushSenderConfig {
    fn default() -> Self {
        HttpPushSenderConfig {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            fail_on_error: false,
            validate_urls: true,
            retry: RetryPolicy::default(),
        }
    }
}

impl HttpPushSender {
    pub fn new(config: Option<HttpPushSenderConfig>) -> Self {
        let config = config.unwrap_or_default();
        // When URL validation is on, the guard needs three things reqwest does
        // not do by default, because each one is a way a request reaches an
        // address the string check never saw:
        //   - a resolver that screens every resolved address at connect time
        //     (see SsrfGuardedResolver), since the string check cannot see
        //     where a hostname actually resolves;
        //   - a redirect policy that re-screens each hop with validate_push_url,
        //     since a redirect to a blocked literal IP skips DNS entirely and so
        //     never reaches the resolver, and the string check only ran on the
        //     original URL;
        //   - no system proxy, since a proxy would resolve and reach the target
        //     itself, leaving only the proxy address screened.
        // When validation is off (the single documented opt-out for local test
        // webhooks), keep reqwest's defaults so loopback targets still work.
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout);
        if config.validate_urls {
            builder = builder
                .dns_resolver(Arc::new(SsrfGuardedResolver))
                .no_proxy()
                .redirect(ssrf_guarded_redirect_policy());
        }
        let client = builder.build().expect("failed to create HTTP client");
        HttpPushSender {
            client,
            fail_on_error: config.fail_on_error,
            validate_urls: config.validate_urls,
            retry: config.retry,
        }
    }

    /// Whether delivery errors are returned rather than only logged.
    pub(crate) fn fail_on_error(&self) -> bool {
        self.fail_on_error
    }

    /// The checks that need no request: the URL guard (when enabled) and the
    /// CR/LF checks on credentials, so they cannot inject additional headers
    /// into the outgoing request (BUG-34). Run before an event is queued and
    /// again before every send.
    pub(crate) fn precheck(&self, config: &TaskPushNotificationConfig) -> Result<(), A2AError> {
        if self.validate_urls {
            validate_push_url(&config.url)?;
        }
        if let Some(ref token) = config.token {
            if token.contains('\r') || token.contains('\n') {
                return Err(A2AError::invalid_params(
                    "push notification token must not contain CR/LF",
                ));
            }
        }
        if let Some(ref auth) = config.authentication {
            if let Some(ref creds) = auth.credentials {
                if creds.contains('\r') || creds.contains('\n') {
                    return Err(A2AError::invalid_params(
                        "push credentials must not contain CR/LF",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Send an event to the push notification endpoint.
    pub async fn send_push(
        &self,
        config: &TaskPushNotificationConfig,
        event: StreamResponse,
    ) -> Result<(), A2AError> {
        self.send_push_gated(config, event, None).await
    }

    /// [`Self::send_push`] with an optional limiter on requests in flight.
    ///
    /// A permit of `gate` is held only while the HTTP request is in flight,
    /// never while validation runs and never between attempts, so a limiter
    /// shared by many deliveries bounds requests, not deliveries.
    pub(crate) async fn send_push_gated(
        &self,
        config: &TaskPushNotificationConfig,
        event: StreamResponse,
        gate: Option<&tokio::sync::Semaphore>,
    ) -> Result<(), A2AError> {
        self.precheck(config)?;

        let body = match serde_json::to_vec(&event) {
            Ok(b) => b,
            Err(e) => return self.handle_error(format!("failed to serialize event: {e}")),
        };

        let mut request = self
            .client
            .post(&config.url)
            .header("Content-Type", "application/json")
            .body(body);

        if let Some(ref token) = config.token {
            request = request.header("A2A-Notification-Token", token);
        }

        if let Some(ref auth) = config.authentication {
            if let Some(ref creds) = auth.credentials {
                match auth.scheme.to_lowercase().as_str() {
                    "bearer" => {
                        request = request.header("Authorization", format!("Bearer {creds}"));
                    }
                    "basic" => {
                        request = request.header("Authorization", format!("Basic {creds}"));
                    }
                    _ => {}
                }
            }
        }

        let request = match request.build() {
            Ok(request) => request,
            Err(e) => return self.handle_error(format!("failed to build push request: {e}")),
        };

        let max_attempts = self.retry.max_attempts();
        let mut attempt = 1;
        loop {
            let Some(this_attempt) = request.try_clone() else {
                return self.handle_error("push request body cannot be replayed".to_string());
            };
            // The permit is held for this one request only: never across
            // the retry sleep below. The semaphore is never closed, so
            // `acquire` cannot fail.
            let outcome = {
                let _permit = match gate {
                    Some(gate) => gate.acquire().await.ok(),
                    None => None,
                };
                self.client.execute(this_attempt).await
            };
            let (message, retry_after) = match outcome {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    let message = format!("push endpoint returned status: {}", resp.status());
                    if !is_retryable_status(resp.status()) {
                        return self.handle_error(message);
                    }
                    let retry_after = retry_after(&resp);
                    // A server that asks for a longer pause than the cap is
                    // not retried: waiting for it would hold this delivery
                    // (and the task's queue) past the configured bound.
                    if retry_after.is_some_and(|wait| wait > self.retry.backoff.max) {
                        return self.handle_error(format!(
                            "{message}; Retry-After exceeds the {:?} retry cap",
                            self.retry.backoff.max
                        ));
                    }
                    (message, retry_after)
                }
                Err(e) => {
                    let message = format!("failed to send push notification: {e}");
                    if !e.is_connect() {
                        return self.handle_error(message);
                    }
                    (message, None)
                }
            };
            if attempt >= max_attempts {
                return self.handle_error(message);
            }

            let delay = self
                .retry
                .delay_before_retry(attempt)
                .max(retry_after.unwrap_or_default());
            tracing::warn!(attempt, max_attempts, ?delay, "{message}; retrying");
            tokio::time::sleep(delay).await;
            attempt += 1;
        }
    }

    fn handle_error(&self, msg: String) -> Result<(), A2AError> {
        if self.fail_on_error {
            Err(crate::sanitized_internal_error(&msg))
        } else {
            tracing::error!("{}", msg);
            Ok(())
        }
    }
}

/// Validate a push notification URL against SSRF targets (BUG-54).
///
/// The URL scheme must be http/https and the host must not resolve to a
/// loopback, private, link-local, multicast, or unspecified address, nor to a
/// well-known cloud metadata endpoint.
pub(crate) fn validate_push_url(url: &str) -> Result<(), A2AError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| A2AError::invalid_params("invalid push notification URL"))?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(A2AError::invalid_params("push URL must be http or https"));
    }

    if let Some(host) = parsed.host_str() {
        // A trailing dot is an equivalent fully-qualified form: "localhost."
        // resolves exactly as "localhost" does. Normalise it away, or every
        // hostname below is bypassed by appending one character. IP literals
        // are unaffected either way -- Url::parse already strips the dot for
        // those, which is why "127.0.0.1." was blocked and "localhost." was
        // not.
        let host = host.strip_suffix('.').unwrap_or(host);
        // Block well-known loopback, metadata, and unspecified hosts.
        let blocked = [
            "127.0.0.1",
            "localhost",
            "::1",
            "[::1]",
            "169.254.169.254",
            "metadata.google.internal",
            "metadata.azure.com",
            "metadata.goog",
            "0.0.0.0",
        ];
        if blocked.contains(&host) {
            return Err(A2AError::invalid_params("push URL targets blocked host"));
        }
        // Block IP literals in restricted ranges (loopback, RFC 1918
        // private, link-local, ULA, unspecified, multicast). For IPv6 URLs
        // the host serializes WITH brackets ("[fc00::1]"), which never
        // parses as an IpAddr — strip them first or every range check
        // below is silently skipped.
        let host_unbracketed = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = host_unbracketed.parse::<std::net::IpAddr>() {
            if is_blocked_ip(ip) {
                return Err(A2AError::invalid_params(
                    "push URL targets private/loopback/link-local address",
                ));
            }
        }
    }

    Ok(())
}

/// Whether `ip` is loopback, RFC 1918/ULA private, link-local, unspecified,
/// or multicast -- the ranges a push URL must not target.
///
/// A standalone predicate rather than inline in `validate_push_url`, per
/// #224's own scope: the connect-time guard it asks for needs to check the
/// *resolved* address against these same ranges, and must reuse this rather
/// than duplicate it. It is also what makes target 4 of #238's fuzz plan
/// possible: fuzzing "does `validate_push_url` correctly extract an IP from
/// an arbitrary URL and apply this predicate" needs the predicate itself to
/// be callable as independent ground truth, not re-derived by the fuzz
/// target and risking drifting out of sync with the real one.
pub(crate) fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
        }
        std::net::IpAddr::V6(v6) => {
            // fc00::/7 unique local addresses (IPv6 "private").
            let is_ula = (v6.segments()[0] & 0xfe00) == 0xfc00;
            // IPv4-mapped IPv6 literals (::ffff:a.b.c.d) must be checked
            // against the IPv4 restrictions too, or they bypass the
            // loopback/private/link-local checks above.
            let mapped_v4_blocked = v6.to_ipv4_mapped().is_some_and(|v4| {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_multicast()
            });
            v6.is_loopback()
                || is_ula
                || mapped_v4_blocked
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
                || v6.is_multicast()
        }
    }
}

/// Retain only the socket addresses safe to dial, dropping any whose IP
/// [`is_blocked_ip`] rejects. Split out from [`SsrfGuardedResolver`] so the
/// connect-time filter is unit-testable without performing real DNS.
fn connectable_addrs(addrs: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addrs.filter(|addr| !is_blocked_ip(addr.ip())).collect()
}

/// A `reqwest` resolver that screens resolved addresses against
/// [`is_blocked_ip`] before the socket is dialed (#224).
///
/// `validate_push_url` screens the URL *string*, but a hostname can still
/// resolve to a loopback, private, or link-local address through split-horizon
/// DNS, an attacker-controlled A record, or DNS rebinding. This resolver is the
/// connect-time half of the guard: reqwest dials exactly the addresses returned
/// here, so filtering them is not subject to a resolve-then-reconnect TOCTOU.
/// Installed only when `validate_urls` is set.
///
/// This resolver only sees addresses reqwest resolves from a hostname. Two
/// paths reach an address without hitting it, so [`HttpPushSender::new`] closes
/// them alongside installing this resolver: a redirect to a blocked literal IP
/// skips DNS entirely (handled by re-screening every redirect hop with
/// `validate_push_url`), and a system proxy would resolve the target itself
/// (handled by disabling the proxy). All three are gated on the same
/// `validate_urls` flag.
struct SsrfGuardedResolver;

impl Resolve for SsrfGuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            // Port 0: reqwest replaces it with the request's port before
            // dialing; only the resolved IP matters for the range check.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed = connectable_addrs(resolved);
            if allowed.is_empty() {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    "push URL host resolves only to blocked (loopback, private, \
                     link-local, or metadata) addresses",
                ));
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

/// The redirect policy installed when `validate_urls` is set: re-screens
/// each hop with [`validate_push_url`], since a redirect to a blocked
/// literal IP skips DNS entirely and never reaches [`SsrfGuardedResolver`].
///
/// Split out from [`HttpPushSender::new`] so a test can attach it to a
/// client on its own, without the resolver -- `reqwest::redirect::Attempt`
/// has no public constructor, so driving a real HTTP redirect through this
/// policy is the only way to exercise it.
fn ssrf_guarded_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.stop();
        }
        if validate_push_url(attempt.url().as_str()).is_err() {
            attempt.error("push URL redirect target is blocked")
        } else {
            attempt.follow()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_util::install_crypto_provider;

    #[test]
    fn test_default_config() {
        let config = HttpPushSenderConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(!config.fail_on_error);
        assert!(config.validate_urls);
        assert_eq!(config.retry, RetryPolicy::default());
        assert_eq!(config.retry.max_attempts(), 3);
    }

    #[test]
    fn test_sender_new_default() {
        install_crypto_provider();
        let sender = HttpPushSender::new(None);
        assert!(!sender.fail_on_error);
        assert!(sender.validate_urls);
    }

    #[test]
    fn test_sender_new_custom() {
        install_crypto_provider();
        let config = HttpPushSenderConfig {
            timeout: Duration::from_secs(10),
            fail_on_error: true,
            validate_urls: false,
            retry: RetryPolicy::none(),
            ..Default::default()
        };
        let sender = HttpPushSender::new(Some(config));
        assert!(sender.fail_on_error);
        assert!(!sender.validate_urls);
    }

    #[test]
    fn test_handle_error_fail_on_error() {
        install_crypto_provider();
        let sender = HttpPushSender::new(Some(HttpPushSenderConfig {
            timeout: Duration::from_secs(5),
            fail_on_error: true,
            validate_urls: true,
            retry: RetryPolicy::none(),
            ..Default::default()
        }));
        let result = sender.handle_error("test error".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_error_ignore() {
        install_crypto_provider();
        let sender = HttpPushSender::new(None);
        let result = sender.handle_error("test error".to_string());
        assert!(result.is_ok());
    }

    fn sample_status_update() -> StreamResponse {
        use a2a::event::*;
        StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
            task_id: "t1".into(),
            context_id: "c1".into(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            metadata: None,
        })
    }

    fn sample_config(url: &str) -> TaskPushNotificationConfig {
        TaskPushNotificationConfig {
            task_id: String::new(),
            url: url.to_string(),
            id: None,
            token: None,
            authentication: None,
            tenant: None,
        }
    }

    #[tokio::test]
    async fn test_send_push_connection_refused_no_fail() {
        install_crypto_provider();
        let sender = HttpPushSender::new(Some(HttpPushSenderConfig {
            validate_urls: false,
            ..Default::default()
        }));
        let config = TaskPushNotificationConfig {
            task_id: String::new(),
            url: "http://127.0.0.1:1/callback".to_string(),
            id: None,
            token: Some("tok".to_string()),
            authentication: Some(AuthenticationInfo {
                scheme: "bearer".to_string(),
                credentials: Some("secret".to_string()),
            }),
            tenant: None,
        };
        let result = sender.send_push(&config, sample_status_update()).await;
        // Should be Ok because fail_on_error is false
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_send_push_connection_refused_fail() {
        install_crypto_provider();
        let sender = HttpPushSender::new(Some(HttpPushSenderConfig {
            timeout: std::time::Duration::from_millis(100),
            fail_on_error: true,
            validate_urls: false,
            retry: RetryPolicy::none(),
            ..Default::default()
        }));
        let config = sample_config("http://127.0.0.1:1/callback");
        let result = sender.send_push(&config, sample_status_update()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_push_with_basic_auth() {
        install_crypto_provider();
        let sender = HttpPushSender::new(Some(HttpPushSenderConfig {
            validate_urls: false,
            ..Default::default()
        }));
        let config = TaskPushNotificationConfig {
            task_id: String::new(),
            url: "http://127.0.0.1:1/callback".to_string(),
            id: None,
            token: None,
            authentication: Some(AuthenticationInfo {
                scheme: "basic".to_string(),
                credentials: Some("dXNlcjpwYXNz".to_string()),
            }),
            tenant: None,
        };
        let result = sender.send_push(&config, sample_status_update()).await;
        // Will fail to connect but exercises basic auth header path
        assert!(result.is_ok()); // fail_on_error=false
    }

    #[tokio::test]
    async fn test_send_push_with_unknown_auth_scheme() {
        install_crypto_provider();
        let sender = HttpPushSender::new(Some(HttpPushSenderConfig {
            validate_urls: false,
            ..Default::default()
        }));
        let config = TaskPushNotificationConfig {
            task_id: String::new(),
            url: "http://127.0.0.1:1/callback".to_string(),
            id: None,
            token: None,
            authentication: Some(AuthenticationInfo {
                scheme: "custom".to_string(),
                credentials: Some("cred".to_string()),
            }),
            tenant: None,
        };
        let result = sender.send_push(&config, sample_status_update()).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_push_url_rejects_non_http_schemes() {
        for url in [
            "file:///etc/passwd",
            "ftp://example.com/hook",
            "gopher://example.com/",
        ] {
            let err = validate_push_url(url).unwrap_err();
            assert_eq!(err.code, error_code::INVALID_PARAMS);
        }
    }

    #[test]
    fn test_validate_push_url_rejects_loopback() {
        for url in [
            "http://127.0.0.1:1/callback",
            "http://localhost/callback",
            "http://[::1]/callback",
            "http://0.0.0.0/callback",
        ] {
            assert!(
                validate_push_url(url).is_err(),
                "expected {url} to be rejected"
            );
        }
    }

    #[test]
    fn test_validate_push_url_rejects_private_and_link_local() {
        for url in [
            "http://10.0.0.1/callback",
            "http://192.168.1.1/callback",
            "http://172.16.0.1/callback",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.1.1/callback",
            "http://metadata.google.internal/callback",
        ] {
            assert!(
                validate_push_url(url).is_err(),
                "expected {url} to be rejected"
            );
        }
    }

    #[test]
    fn test_validate_push_url_rejects_trailing_dot_hosts() {
        // "localhost." is the fully-qualified spelling of "localhost" and
        // resolves identically, so it must not slip past the host blocklist.
        for url in [
            "http://localhost./hook",
            "http://LocalHost./hook",
            "https://localhost./hook",
            "http://metadata.google.internal./hook",
            "http://metadata.azure.com./hook",
        ] {
            assert!(
                validate_push_url(url).is_err(),
                "{url} must be blocked, but was allowed"
            );
        }
    }

    #[test]
    fn test_validate_push_url_rejects_alternate_ipv4_spellings() {
        // These are blocked only because Url::parse normalises them to
        // 127.0.0.1 before the range check sees them. Pin that, so the
        // normalisation cannot be regressed away unnoticed.
        for url in [
            "http://2130706433/hook",         // decimal
            "http://0x7f.0.0.1/hook",         // hex octet
            "http://127.1/hook",              // short form
            "http://127.0.0.1./hook",         // trailing dot on a literal
            "http://[::ffff:127.0.0.1]/hook", // IPv4-mapped IPv6
        ] {
            assert!(
                validate_push_url(url).is_err(),
                "{url} must be blocked, but was allowed"
            );
        }
    }

    #[test]
    fn test_is_blocked_ip_checks_every_range_through_an_ipv4_mapped_address() {
        // is_blocked_ip's IPv4-mapped-IPv6 branch applies every IPv4
        // predicate to the unwrapped address, not just is_loopback -- the
        // existing ::ffff:127.0.0.1 test case above only exercises that
        // first one, since a loopback address short-circuits the rest.
        // Each of these is chosen to be false on every earlier predicate,
        // so the run reaches its own line rather than returning early.
        for (ip, why) in [
            ("::ffff:169.254.1.1", "link-local"),
            ("::ffff:0.0.0.0", "unspecified"),
            ("::ffff:224.0.0.1", "multicast"),
        ] {
            let addr: std::net::IpAddr = ip.parse().unwrap();
            assert!(is_blocked_ip(addr), "{ip} ({why}) should be blocked");
        }

        // And the mapped address is not blocked when the underlying IPv4
        // address is none of these -- confirms the closure's result is
        // actually load-bearing, not a predicate that always returns true.
        let public: std::net::IpAddr = "::ffff:93.184.216.34".parse().unwrap();
        assert!(
            !is_blocked_ip(public),
            "a public mapped address was blocked"
        );
    }

    #[test]
    fn test_validate_push_url_rejects_blocked_hosts_regardless_of_case() {
        // Url::parse lowercases the host per the URL Standard before the
        // blocklist ever sees it, so this holds independent of the
        // trailing-dot case above -- pinned on its own rather than only as
        // a side effect of that test.
        for url in [
            "http://LOCALHOST/hook",
            "http://METADATA.GOOGLE.INTERNAL/hook",
            "http://Metadata.Azure.Com/hook",
        ] {
            assert!(
                validate_push_url(url).is_err(),
                "{url} must be blocked, but was allowed"
            );
        }
    }

    #[test]
    fn test_validate_push_url_accepts_public_urls() {
        for url in [
            "http://example.com/callback",
            "https://example.com/callback",
            "https://hooks.example.com/abc?x=1",
        ] {
            assert!(
                validate_push_url(url).is_ok(),
                "expected {url} to be accepted"
            );
        }
    }

    #[tokio::test]
    async fn test_send_push_rejects_blocked_url_even_without_fail_on_error() {
        install_crypto_provider();
        let sender = HttpPushSender::new(None); // validate_urls = true
        let config = sample_config("http://127.0.0.1:1/callback");
        let result = sender.send_push(&config, sample_status_update()).await;
        // Validation errors are always returned, regardless of fail_on_error.
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn test_send_push_rejects_crlf_credentials() {
        install_crypto_provider();
        let sender = HttpPushSender::new(None);
        let config = TaskPushNotificationConfig {
            task_id: String::new(),
            url: "https://example.com/callback".to_string(),
            id: None,
            token: None,
            authentication: Some(AuthenticationInfo {
                scheme: "bearer".to_string(),
                credentials: Some("secret\r\nX-Injected: 1".to_string()),
            }),
            tenant: None,
        };
        let result = sender.send_push(&config, sample_status_update()).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn test_send_push_rejects_crlf_token() {
        install_crypto_provider();
        let sender = HttpPushSender::new(None);
        let config = TaskPushNotificationConfig {
            task_id: String::new(),
            url: "https://example.com/callback".to_string(),
            id: None,
            token: Some("tok\nX-Injected: 1".to_string()),
            authentication: None,
            tenant: None,
        };
        let result = sender.send_push(&config, sample_status_update()).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, error_code::INVALID_PARAMS);
    }

    #[test]
    fn test_validate_push_url_rejects_invalid_url() {
        assert!(validate_push_url("not a url").is_err());
        assert!(validate_push_url("").is_err());
        // Empty authority fails URL parsing outright (EmptyHost).
        assert!(validate_push_url("http://").is_err());
    }

    #[test]
    fn test_validate_push_url_rejects_ipv6_restricted_ranges() {
        for url in [
            "http://[fc00::1]/cb",
            "http://[fd12:3456:789a::1]/cb",
            "http://[fe80::1]/cb",
            "http://[ff02::1]/cb",
            "http://[::]/cb",
        ] {
            let result = validate_push_url(url);
            assert!(result.is_err(), "expected {url} to be rejected");
            assert_eq!(result.unwrap_err().code, error_code::INVALID_PARAMS);
        }
    }

    #[test]
    fn test_validate_push_url_rejects_ipv4_mapped_ipv6() {
        // ::ffff:a.b.c.d literals must inherit the IPv4 restrictions.
        for url in [
            "http://[::ffff:127.0.0.1]/cb",
            "http://[::ffff:10.0.0.1]/cb",
        ] {
            let result = validate_push_url(url);
            assert!(result.is_err(), "expected {url} to be rejected");
            assert_eq!(result.unwrap_err().code, error_code::INVALID_PARAMS);
        }
    }

    #[test]
    fn test_validate_push_url_rejects_ipv4_multicast() {
        let result = validate_push_url("http://224.0.0.1/cb");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, error_code::INVALID_PARAMS);
    }

    #[test]
    fn test_validate_push_url_accepts_global_ipv6() {
        assert!(validate_push_url("http://[2606:4700::1111]/cb").is_ok());
    }

    #[test]
    fn test_connectable_addrs_drops_blocked_keeps_public() {
        // The connect-time filter (#224) must drop every restricted resolved
        // address and keep the routable ones, so a hostname that resolves to a
        // mix cannot reach the blocked members.
        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:443".parse().unwrap(),         // loopback
            "10.0.0.5:443".parse().unwrap(),          // RFC 1918
            "169.254.169.254:80".parse().unwrap(),    // link-local metadata
            "93.184.216.34:443".parse().unwrap(),     // public v4
            "[fc00::1]:443".parse().unwrap(),         // IPv6 ULA
            "[2606:4700::1111]:443".parse().unwrap(), // public v6
        ];
        let ips: Vec<std::net::IpAddr> = connectable_addrs(addrs.into_iter())
            .iter()
            .map(|a| a.ip())
            .collect();
        assert_eq!(
            ips,
            vec![
                "93.184.216.34".parse::<std::net::IpAddr>().unwrap(),
                "2606:4700::1111".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_connectable_addrs_all_blocked_is_empty() {
        let addrs: Vec<SocketAddr> = vec![
            "127.0.0.1:443".parse().unwrap(),
            "192.168.1.1:443".parse().unwrap(),
        ];
        assert!(connectable_addrs(addrs.into_iter()).is_empty());
    }

    #[tokio::test]
    async fn test_ssrf_resolver_rejects_host_resolving_to_loopback() {
        // A bare hostname that resolves only to loopback must be refused at
        // connect time, even though the resolver never sees an IP literal.
        // "localhost" resolves to 127.0.0.1 / ::1 without leaving the machine,
        // so this is deterministic.
        let name: Name = "localhost".parse().expect("localhost is a valid dns name");
        let result = SsrfGuardedResolver.resolve(name).await;
        assert!(
            result.is_err(),
            "a host resolving only to loopback must be refused at connect time"
        );
    }

    #[test]
    fn test_redirect_hop_check_rejects_blocked_targets() {
        // The custom redirect policy re-runs validate_push_url on each hop, so a
        // redirect to a blocked literal IP (which skips DNS and never reaches
        // SsrfGuardedResolver) is refused, while a public hop follows. This pins
        // the per-hop check the policy relies on.
        assert!(validate_push_url("http://127.0.0.1/").is_err());
        assert!(validate_push_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(validate_push_url("http://[::1]/").is_err());
        assert!(validate_push_url("https://example.com/next").is_ok());
    }

    /// Runs a local server that redirects `/` to `location`, so a real
    /// `reqwest::redirect::Attempt` reaches [`ssrf_guarded_redirect_policy`]
    /// -- the type has no public constructor, so this is the only way to
    /// drive it without faking reqwest's internals.
    async fn spawn_redirect_server(location: String) -> String {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let location = location.clone();
                async move { axum::response::Redirect::temporary(&location) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn test_redirect_policy_blocks_a_redirect_to_a_disallowed_target() {
        let server_url =
            spawn_redirect_server("http://169.254.169.254/latest/meta-data/".into()).await;
        let client = reqwest::Client::builder()
            .redirect(ssrf_guarded_redirect_policy())
            .build()
            .unwrap();
        let err = client
            .get(&server_url)
            .send()
            .await
            .expect_err("a redirect to a blocked target must fail");
        assert!(err.is_redirect(), "expected a redirect-policy error: {err}");
    }

    #[tokio::test]
    async fn test_redirect_policy_rejects_a_self_redirect_loop_immediately() {
        // A server that redirects to itself is a loopback target, so the
        // per-hop block check (not the separate 10-hop cap, which nothing
        // here can safely reach without a real allowed target to bounce
        // through) is what stops it -- on the very first hop.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let self_url = format!("http://{addr}/");
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let self_url = self_url.clone();
                async move { axum::response::Redirect::temporary(&self_url) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::builder()
            .redirect(ssrf_guarded_redirect_policy())
            .build()
            .unwrap();
        let err = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect_err("a loopback self-redirect must be refused, not followed");
        assert!(err.is_redirect(), "expected a redirect-policy error: {err}");
    }

    /// Webhook that answers `status` for its first `fail_first` requests and
    /// 202 afterwards. Returns its URL and a request counter.
    async fn flaky_webhook(
        status: u16,
        fail_first: usize,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move || {
                let counter = Arc::clone(&counter);
                async move {
                    let seen = counter.fetch_add(1, Ordering::SeqCst);
                    if seen < fail_first {
                        axum::http::StatusCode::from_u16(status).unwrap()
                    } else {
                        axum::http::StatusCode::ACCEPTED
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/"), hits)
    }

    fn retrying_sender(max_attempts: u32) -> HttpPushSender {
        HttpPushSender::new(Some(HttpPushSenderConfig {
            fail_on_error: true,
            validate_urls: false,
            retry: RetryPolicy::new(
                max_attempts,
                Backoff::new(Duration::from_millis(5), Duration::from_millis(20)),
            ),
            ..Default::default()
        }))
    }

    #[tokio::test]
    async fn push_retries_on_503_then_succeeds() {
        use std::sync::atomic::Ordering;
        install_crypto_provider();
        let (url, hits) = flaky_webhook(503, 2).await;
        let sender = retrying_sender(3);
        sender
            .send_push(&sample_config(&url), sample_status_update())
            .await
            .expect("the third attempt succeeds");
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn push_retries_on_429() {
        use std::sync::atomic::Ordering;
        install_crypto_provider();
        let (url, hits) = flaky_webhook(429, 1).await;
        let sender = retrying_sender(3);
        sender
            .send_push(&sample_config(&url), sample_status_update())
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn push_does_not_retry_on_4xx() {
        use std::sync::atomic::Ordering;
        install_crypto_provider();
        let (url, hits) = flaky_webhook(400, usize::MAX).await;
        let sender = retrying_sender(5);
        let result = sender
            .send_push(&sample_config(&url), sample_status_update())
            .await;
        assert!(result.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn push_gives_up_after_max_attempts() {
        use std::sync::atomic::Ordering;
        install_crypto_provider();
        let (url, hits) = flaky_webhook(500, usize::MAX).await;
        let sender = retrying_sender(3);
        let result = sender
            .send_push(&sample_config(&url), sample_status_update())
            .await;
        assert!(result.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn push_retries_connect_errors() {
        install_crypto_provider();
        // Nothing listens on port 1: every attempt is a connect error.
        let sender = HttpPushSender::new(Some(HttpPushSenderConfig {
            fail_on_error: true,
            validate_urls: false,
            retry: RetryPolicy::new(
                3,
                Backoff::new(Duration::from_millis(40), Duration::from_millis(40)),
            ),
            ..Default::default()
        }));
        let started = std::time::Instant::now();
        let result = sender
            .send_push(
                &sample_config("http://127.0.0.1:1/callback"),
                sample_status_update(),
            )
            .await;
        assert!(result.is_err());
        // Three attempts mean two waits, each at least half of the 40 ms
        // backoff: a sender that made fewer attempts finishes sooner.
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "fewer than three attempts were made: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn retry_policy_backoff_is_capped_and_jittered() {
        let policy = RetryPolicy::new(
            10,
            Backoff::new(Duration::from_millis(100), Duration::from_secs(1)),
        );
        for retry in 1..=20 {
            let delay = policy.delay_before_retry(retry);
            let ceiling = Duration::from_millis(100)
                .saturating_mul(1u32 << (retry - 1).min(10))
                .min(Duration::from_secs(1));
            assert!(delay <= ceiling, "retry {retry}: {delay:?} > {ceiling:?}");
            assert!(
                delay >= ceiling / 2,
                "retry {retry}: {delay:?} < half of {ceiling:?}"
            );
        }
    }

    #[test]
    fn retry_policy_backoff_varies_between_draws() {
        let policy = RetryPolicy::new(
            3,
            Backoff::new(Duration::from_millis(100), Duration::from_secs(1)),
        );
        let draws: std::collections::HashSet<_> =
            (0..200).map(|_| policy.delay_before_retry(1)).collect();
        // A constant delay would put every retry of a failed batch at the
        // same instant; 200 draws from a 50 ms window must not coincide.
        assert!(draws.len() > 20, "only {} distinct delays", draws.len());
    }

    /// Webhook that answers 503 with `Retry-After: seconds` and counts hits.
    async fn retry_after_webhook(
        seconds: &'static str,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        [("retry-after", seconds)],
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/"), hits)
    }

    #[tokio::test]
    async fn push_gives_up_when_retry_after_exceeds_cap() {
        use std::sync::atomic::Ordering;
        install_crypto_provider();
        // The cap is 20 ms; the server asks for an hour.
        let (url, hits) = retry_after_webhook("3600").await;
        let sender = retrying_sender(5);
        let started = std::time::Instant::now();
        let result = sender
            .send_push(&sample_config(&url), sample_status_update())
            .await;
        assert!(result.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "must not retry");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn push_honours_retry_after_within_the_cap() {
        use std::sync::atomic::Ordering;
        install_crypto_provider();
        let (url, hits) = retry_after_webhook("1").await;
        let sender = HttpPushSender::new(Some(HttpPushSenderConfig {
            fail_on_error: true,
            validate_urls: false,
            retry: RetryPolicy::new(
                2,
                Backoff::new(Duration::from_millis(5), Duration::from_secs(2)),
            ),
            ..Default::default()
        }));
        let started = std::time::Instant::now();
        let result = sender
            .send_push(&sample_config(&url), sample_status_update())
            .await;
        assert!(result.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "Retry-After: 1 was not waited for: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn push_ignores_an_http_date_retry_after() {
        use std::sync::atomic::Ordering;
        install_crypto_provider();
        let (url, hits) = retry_after_webhook("Wed, 21 Oct 2037 07:28:00 GMT").await;
        let sender = retrying_sender(2);
        let started = std::time::Instant::now();
        let result = sender
            .send_push(&sample_config(&url), sample_status_update())
            .await;
        assert!(result.is_err());
        // The date is ignored: the backoff alone applies and the retry happens.
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn config_defaults_include_a_connect_timeout() {
        assert_eq!(
            HttpPushSenderConfig::default().connect_timeout,
            Duration::from_secs(10)
        );
    }

    #[test]
    fn retry_policy_none_makes_one_attempt() {
        assert_eq!(RetryPolicy::none().max_attempts(), 1);
        assert_eq!(RetryPolicy::new(0, Backoff::default()).max_attempts(), 1);
    }
}

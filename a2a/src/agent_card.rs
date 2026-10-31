// Copyright AGNTCY Contributors (https://github.com/agntcy)
// Copyright A2A Contributors (https://github.com/a2aproject)
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

use crate::types::{ProtocolVersion, TRANSPORT_PROTOCOL_GRPC, TransportProtocol};

// ---------------------------------------------------------------------------
// AgentCard
// ---------------------------------------------------------------------------

/// Self-describing manifest for an agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub version: String,
    pub supported_interfaces: Vec<AgentInterface>,
    pub capabilities: AgentCapabilities,
    #[serde(default)]
    pub default_input_modes: Vec<String>,
    #[serde(default)]
    pub default_output_modes: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_vec_null_as_default")]
    pub skills: Vec<AgentSkill>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<AgentProvider>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "sorted_opt_map"
    )]
    pub security_schemes: Option<HashMap<String, SecurityScheme>>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_security_requirements",
        deserialize_with = "deserialize_optional_security_requirements"
    )]
    pub security_requirements: Option<Vec<SecurityRequirement>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<AgentCardSignature>>,
}

fn deserialize_vec_null_as_default<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_optional_security_requirements<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<SecurityRequirement>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<Vec<Value>>::deserialize(deserializer)?;

    raw.map(|items| {
        items
            .into_iter()
            .map(parse_security_requirement_value)
            .collect()
    })
    .transpose()
}

fn serialize_optional_security_requirements<S>(
    requirements: &Option<Vec<SecurityRequirement>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match requirements {
        Some(requirements) => requirements
            .iter()
            .map(|requirement| {
                let schemes = requirement
                    .iter()
                    .map(|(scheme, scopes)| {
                        (scheme.as_str(), SerializedSecurityScopes { list: scopes })
                    })
                    .collect();
                SerializedSecurityRequirement { schemes }
            })
            .collect::<Vec<_>>()
            .serialize(serializer),
        None => serializer.serialize_none(),
    }
}

// `BTreeMap` so the scheme names serialize in a stable (sorted) order. An
// empty requirement serializes as `{}`: ProtoJSON omits an empty map, and the
// reader below accepts `{}` as well as `{"schemes": {}}`.
#[derive(Serialize)]
struct SerializedSecurityRequirement<'a> {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    schemes: BTreeMap<&'a str, SerializedSecurityScopes<'a>>,
}

// An empty scope list serializes as `{}`, the canonical ProtoJSON form of an
// empty `StringList`; readers also accept `[..]` and `{"list": [..]}`.
#[derive(Serialize)]
struct SerializedSecurityScopes<'a> {
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    list: &'a [String],
}

/// Serializes a map with its keys in sorted order.
///
/// Public map fields stay `HashMap` (so constructing them is unchanged), but
/// `HashMap` iteration order differs per process, which would make the
/// serialized card byte-unstable. Sorting here keeps the output deterministic
/// for diffing and caching.
///
/// This is not RFC 8785 (JCS) canonicalization: `BTreeMap` orders keys by
/// code point, while JCS orders them by UTF-16 code unit, and the two differ for
/// keys that mix U+E000..U+FFFF with supplementary-plane characters. A signer
/// must still canonicalize the card with RFC 8785 (A2A section 8.4.1).
fn sorted_map<K, V, H, S>(map: &HashMap<K, V, H>, serializer: S) -> Result<S::Ok, S::Error>
where
    K: Ord + Serialize,
    V: Serialize,
    S: Serializer,
{
    serializer.collect_map(map.iter().collect::<BTreeMap<_, _>>())
}

/// [`sorted_map`] for an `Option`; pair with `skip_serializing_if = "Option::is_none"`.
fn sorted_opt_map<K, V, H, S>(
    map: &Option<HashMap<K, V, H>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    K: Ord + Serialize,
    V: Serialize,
    S: Serializer,
{
    match map {
        Some(map) => sorted_map(map, serializer),
        None => serializer.serialize_none(),
    }
}

fn parse_security_requirement_value<E>(value: Value) -> Result<SecurityRequirement, E>
where
    E: serde::de::Error,
{
    if let Ok(requirement) = serde_json::from_value::<SecurityRequirement>(value.clone()) {
        return Ok(requirement);
    }

    let Value::Object(mut object) = value else {
        return Err(E::custom("security requirement must be an object"));
    };

    if let Some(schemes) = object.remove("schemes") {
        return parse_security_requirement_map::<E>(schemes);
    }

    Err(E::custom("invalid security requirement shape"))
}

fn parse_security_requirement_map<E>(value: Value) -> Result<SecurityRequirement, E>
where
    E: serde::de::Error,
{
    let Value::Object(object) = value else {
        return Err(E::custom("security requirement schemes must be an object"));
    };

    let mut requirement = HashMap::new();
    for (scheme, scopes_value) in object {
        let scopes = match scopes_value {
            Value::Array(_) => serde_json::from_value::<Vec<String>>(scopes_value)
                .map_err(|e| E::custom(format!("invalid security scopes for {scheme}: {e}")))?,
            Value::Object(mut wrapped) => match wrapped.remove("list") {
                Some(list) => serde_json::from_value::<Vec<String>>(list).map_err(|e| {
                    E::custom(format!("invalid wrapped security scopes for {scheme}: {e}"))
                })?,
                // ProtoJSON omits an empty StringList, so {} is the same as {"list": []}.
                None if wrapped.is_empty() => Vec::new(),
                None => {
                    return Err(E::custom(format!(
                        "invalid wrapped security scopes for {scheme}"
                    )));
                }
            },
            _ => {
                return Err(E::custom(format!(
                    "security scopes for {scheme} must be a list"
                )));
            }
        };

        requirement.insert(scheme, scopes);
    }

    Ok(requirement)
}

// ---------------------------------------------------------------------------
// AgentInterface
// ---------------------------------------------------------------------------

/// A URL + protocol binding combination for reaching the agent.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentInterface {
    pub url: String,
    pub protocol_binding: TransportProtocol,
    pub protocol_version: ProtocolVersion,
    pub tenant: Option<String>,
}

// A derived `Arbitrary` would fill `url` independently of `protocol_binding`,
// producing combinations `new()` never does (e.g. a `grpc` binding paired
// with an un-normalized `http://` URL) -- valid per the type but not
// round-trip-stable, since `Serialize`/`Deserialize` always normalize.
// Route through the same normalization instead, so a fuzz-generated value
// is exactly as a real caller's `new()` would have built it.
#[cfg(feature = "fuzzing")]
impl<'a> arbitrary::Arbitrary<'a> for AgentInterface {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let url = String::arbitrary(u)?;
        let protocol_binding = TransportProtocol::arbitrary(u)?;
        Ok(AgentInterface {
            url: normalize_agent_interface_url(url, &protocol_binding),
            protocol_binding,
            protocol_version: ProtocolVersion::arbitrary(u)?,
            tenant: Option::<String>::arbitrary(u)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentInterfaceSerde {
    url: String,
    protocol_binding: TransportProtocol,
    protocol_version: ProtocolVersion,
    #[serde(default)]
    tenant: Option<String>,
}

fn normalize_agent_interface_url(url: String, protocol_binding: &str) -> String {
    if protocol_binding.eq_ignore_ascii_case(TRANSPORT_PROTOCOL_GRPC) {
        if let Some(stripped) = url.strip_prefix("http://") {
            return stripped.to_string();
        }
    }

    url
}

impl AgentInterface {
    pub fn new(url: impl Into<String>, protocol_binding: impl Into<String>) -> Self {
        let protocol_binding = protocol_binding.into();
        AgentInterface {
            url: normalize_agent_interface_url(url.into(), &protocol_binding),
            protocol_binding,
            protocol_version: crate::VERSION.to_string(),
            tenant: None,
        }
    }

    pub fn wire_url(&self) -> String {
        normalize_agent_interface_url(self.url.clone(), &self.protocol_binding)
    }
}

impl Serialize for AgentInterface {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut state = serializer
            .serialize_struct("AgentInterface", if self.tenant.is_some() { 4 } else { 3 })?;
        state.serialize_field("url", &self.wire_url())?;
        state.serialize_field("protocolBinding", &self.protocol_binding)?;
        state.serialize_field("protocolVersion", &self.protocol_version)?;
        if let Some(tenant) = &self.tenant {
            state.serialize_field("tenant", tenant)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for AgentInterface {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = AgentInterfaceSerde::deserialize(deserializer)?;

        Ok(Self {
            url: normalize_agent_interface_url(raw.url, &raw.protocol_binding),
            protocol_binding: raw.protocol_binding,
            protocol_version: raw.protocol_version,
            tenant: raw.tenant,
        })
    }
}

// ---------------------------------------------------------------------------
// AgentProvider
// ---------------------------------------------------------------------------

/// Information about the agent's service provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct AgentProvider {
    pub organization: String,
    pub url: String,
}

// ---------------------------------------------------------------------------
// AgentCapabilities
// ---------------------------------------------------------------------------

/// Optional capabilities supported by an agent.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_notifications: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<AgentExtension>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_agent_card: Option<bool>,
}

// ---------------------------------------------------------------------------
// AgentExtension
// ---------------------------------------------------------------------------

/// A protocol extension supported by the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct AgentExtension {
    pub uri: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,

    /// Extension parameters. The top-level keys serialize in sorted order;
    /// nested JSON values are written as they are held and are not
    /// canonicalized.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "sorted_opt_map"
    )]
    #[cfg_attr(feature = "fuzzing", arbitrary(default))]
    pub params: Option<HashMap<String, Value>>,
}

// ---------------------------------------------------------------------------
// AgentSkill
// ---------------------------------------------------------------------------

/// A distinct capability or function that an agent can perform.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_modes: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_modes: Option<Vec<String>>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_security_requirements",
        deserialize_with = "deserialize_optional_security_requirements"
    )]
    pub security_requirements: Option<Vec<SecurityRequirement>>,
}

// ---------------------------------------------------------------------------
// SecurityScheme (field-presence union)
// ---------------------------------------------------------------------------

/// A security scheme for authorizing requests, following OpenAPI 3.0.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub enum SecurityScheme {
    ApiKey(ApiKeySecurityScheme),
    HttpAuth(HttpAuthSecurityScheme),
    OAuth2(OAuth2SecurityScheme),
    OpenIdConnect(OpenIdConnectSecurityScheme),
    MutualTls(MutualTlsSecurityScheme),
}

impl Serialize for SecurityScheme {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            SecurityScheme::ApiKey(s) => map.serialize_entry("apiKeySecurityScheme", s)?,
            SecurityScheme::HttpAuth(s) => map.serialize_entry("httpAuthSecurityScheme", s)?,
            SecurityScheme::OAuth2(s) => map.serialize_entry("oauth2SecurityScheme", s)?,
            SecurityScheme::OpenIdConnect(s) => {
                map.serialize_entry("openIdConnectSecurityScheme", s)?
            }
            SecurityScheme::MutualTls(s) => map.serialize_entry("mtlsSecurityScheme", s)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for SecurityScheme {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: HashMap<String, Value> = HashMap::deserialize(deserializer)?;
        if let Some(v) = raw.get("apiKeySecurityScheme") {
            Ok(SecurityScheme::ApiKey(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else if let Some(v) = raw.get("httpAuthSecurityScheme") {
            Ok(SecurityScheme::HttpAuth(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else if let Some(v) = raw.get("oauth2SecurityScheme") {
            Ok(SecurityScheme::OAuth2(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else if let Some(v) = raw.get("openIdConnectSecurityScheme") {
            Ok(SecurityScheme::OpenIdConnect(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else if let Some(v) = raw.get("mtlsSecurityScheme") {
            Ok(SecurityScheme::MutualTls(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else {
            Err(serde::de::Error::custom("unknown security scheme variant"))
        }
    }
}

// ---------------------------------------------------------------------------
// Security scheme types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct ApiKeySecurityScheme {
    pub location: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct HttpAuthSecurityScheme {
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct OAuth2SecurityScheme {
    pub flows: OAuthFlows,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_metadata_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct OpenIdConnectSecurityScheme {
    pub open_id_connect_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct MutualTlsSecurityScheme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// OAuth flows (field-presence union)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub enum OAuthFlows {
    AuthorizationCode(AuthorizationCodeOAuthFlow),
    ClientCredentials(ClientCredentialsOAuthFlow),
    DeviceCode(DeviceCodeOAuthFlow),
    Implicit(ImplicitOAuthFlow),
    Password(PasswordOAuthFlow),
}

impl Serialize for OAuthFlows {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            OAuthFlows::AuthorizationCode(f) => map.serialize_entry("authorizationCode", f)?,
            OAuthFlows::ClientCredentials(f) => map.serialize_entry("clientCredentials", f)?,
            OAuthFlows::DeviceCode(f) => map.serialize_entry("deviceCode", f)?,
            OAuthFlows::Implicit(f) => map.serialize_entry("implicit", f)?,
            OAuthFlows::Password(f) => map.serialize_entry("password", f)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for OAuthFlows {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: HashMap<String, Value> = HashMap::deserialize(deserializer)?;
        if let Some(v) = raw.get("authorizationCode") {
            Ok(OAuthFlows::AuthorizationCode(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else if let Some(v) = raw.get("clientCredentials") {
            Ok(OAuthFlows::ClientCredentials(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else if let Some(v) = raw.get("deviceCode") {
            Ok(OAuthFlows::DeviceCode(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else if let Some(v) = raw.get("implicit") {
            Ok(OAuthFlows::Implicit(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else if let Some(v) = raw.get("password") {
            Ok(OAuthFlows::Password(
                serde_json::from_value(v.clone()).map_err(serde::de::Error::custom)?,
            ))
        } else {
            Err(serde::de::Error::custom("unknown OAuth flow variant"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationCodeOAuthFlow {
    pub authorization_url: String,
    pub token_url: String,
    #[serde(serialize_with = "sorted_map")]
    pub scopes: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkce_required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct ClientCredentialsOAuthFlow {
    pub token_url: String,
    #[serde(serialize_with = "sorted_map")]
    pub scopes: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct DeviceCodeOAuthFlow {
    pub device_authorization_url: String,
    pub token_url: String,
    #[serde(serialize_with = "sorted_map")]
    pub scopes: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct ImplicitOAuthFlow {
    pub authorization_url: String,
    #[serde(serialize_with = "sorted_map")]
    pub scopes: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct PasswordOAuthFlow {
    pub token_url: String,
    #[serde(serialize_with = "sorted_map")]
    pub scopes: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Security requirement
// ---------------------------------------------------------------------------

/// A security requirement: map of scheme name → required scopes.
pub type SecurityRequirement = HashMap<String, Vec<String>>;

// ---------------------------------------------------------------------------
// AgentCardSignature
// ---------------------------------------------------------------------------

/// JWS signature for an AgentCard (RFC 7515).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[serde(rename_all = "camelCase")]
pub struct AgentCardSignature {
    pub protected: String,
    pub signature: String,
    /// The JWS unprotected header. The top-level keys serialize in sorted
    /// order; nested JSON values are written as they are held and are not
    /// canonicalized.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "sorted_opt_map"
    )]
    #[cfg_attr(feature = "fuzzing", arbitrary(default))]
    pub header: Option<HashMap<String, Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_card_serde() {
        let card = AgentCard {
            name: "Test Agent".to_string(),
            description: "A test agent".to_string(),
            version: "1.0.0".to_string(),
            supported_interfaces: vec![AgentInterface::new("http://localhost:3000", "JSONRPC")],
            capabilities: AgentCapabilities {
                streaming: Some(true),
                push_notifications: Some(false),
                extensions: None,
                extended_agent_card: None,
            },
            default_input_modes: vec!["text/plain".to_string()],
            default_output_modes: vec!["text/plain".to_string()],
            skills: vec![AgentSkill {
                id: "echo".to_string(),
                name: "Echo".to_string(),
                description: "Echoes input".to_string(),
                tags: vec!["test".to_string()],
                examples: Some(vec!["hello".to_string()]),
                input_modes: None,
                output_modes: None,
                security_requirements: None,
            }],
            provider: Some(AgentProvider {
                organization: "Test Corp".to_string(),
                url: "https://test.com".to_string(),
            }),
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security_requirements: None,
            signatures: None,
        };

        let json = serde_json::to_string(&card).unwrap();
        let back: AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(card, back);
    }

    #[test]
    fn test_agent_interface_new() {
        let iface = AgentInterface::new("http://localhost:3000", "JSONRPC");
        assert_eq!(iface.url, "http://localhost:3000");
        assert_eq!(iface.protocol_binding, "JSONRPC");
        assert!(!iface.protocol_version.is_empty());
    }

    #[test]
    fn test_agent_interface_new_normalizes_grpc_http_scheme() {
        let iface = AgentInterface::new("http://localhost:50051", TRANSPORT_PROTOCOL_GRPC);
        assert_eq!(iface.url, "localhost:50051");
        assert_eq!(iface.protocol_binding, TRANSPORT_PROTOCOL_GRPC);
    }

    #[test]
    fn test_agent_interface_new_preserves_grpc_https_scheme() {
        let iface = AgentInterface::new("https://localhost:50051", TRANSPORT_PROTOCOL_GRPC);
        assert_eq!(iface.url, "https://localhost:50051");
        assert_eq!(iface.protocol_binding, TRANSPORT_PROTOCOL_GRPC);
    }

    #[test]
    fn test_agent_interface_serde_normalizes_grpc_http_scheme() {
        let iface = AgentInterface {
            url: "http://localhost:50051".to_string(),
            protocol_binding: TRANSPORT_PROTOCOL_GRPC.to_string(),
            protocol_version: crate::VERSION.to_string(),
            tenant: Some("tenant-a".to_string()),
        };

        let json = serde_json::to_string(&iface).unwrap();
        assert!(json.contains("\"url\":\"localhost:50051\""));

        let back: AgentInterface = serde_json::from_str(&json).unwrap();
        assert_eq!(back.url, "localhost:50051");
        assert_eq!(back.protocol_binding, TRANSPORT_PROTOCOL_GRPC);
        assert_eq!(back.tenant.as_deref(), Some("tenant-a"));
    }

    // `agent_card_roundtrip`'s fuzz oracle assumes any arbitrary-generated
    // AgentCard is serde-round-trip-identical; a derived Arbitrary broke that
    // for exactly the state above (grpc binding + un-normalized http:// url),
    // since it fills fields independently of `new()`. Hitting that exact
    // combination by chance is astronomically unlikely (protocol_binding has
    // to land on the literal string "grpc"), so this drives `arbitrary`
    // directly with a byte sequence hand-derived from arbitrary 1.4's own
    // length-then-content encoding (see arbitrary_byte_size/arbitrary_str in
    // its `Unstructured`) to force exactly that combination, rather than
    // relying on a fixed seed or many random ones to stumble onto it.
    #[cfg(feature = "fuzzing")]
    #[test]
    fn test_agent_interface_arbitrary_never_produces_unnormalized_grpc_url() {
        use arbitrary::{Arbitrary, Unstructured};

        #[rustfmt::skip]
        let bytes: [u8; 14] = [
            b'h', b't', b't', b'p', b':', b'/', b'/', b'x', // url content: "http://x"
            b'g', b'r', b'p', b'c',                          // protocol_binding: "grpc"
            4, 8, // trailing length bytes, consumed back-to-front: proto=4, url=8
        ];
        let mut u = Unstructured::new(&bytes);
        let iface = AgentInterface::arbitrary(&mut u).unwrap();
        assert!(
            iface
                .protocol_binding
                .eq_ignore_ascii_case(TRANSPORT_PROTOCOL_GRPC)
        );
        assert_eq!(
            iface.url, "x",
            "arbitrary() must normalize the seed's http:// prefix away, same as new() would"
        );

        let json = serde_json::to_string(&iface).unwrap();
        let back: AgentInterface = serde_json::from_str(&json).unwrap();
        assert_eq!(iface, back, "did not round-trip: {json}");
    }

    #[test]
    fn test_agent_card_deserialize_null_skills_as_default() {
        let json = serde_json::json!({
            "name": "Test Agent",
            "description": "A test agent",
            "version": "1.0.0",
            "supportedInterfaces": [
                {
                    "url": "http://localhost:3000",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": crate::VERSION
                }
            ],
            "capabilities": {},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": null
        });

        let card: AgentCard = serde_json::from_value(json).unwrap();
        assert!(card.skills.is_empty());
    }

    /// #275 (SHOULD-level): `description`, `defaultInputModes` and
    /// `defaultOutputModes` should default when absent rather than failing
    /// deserialization outright.
    #[test]
    fn test_agent_card_deserialize_defaults_optional_fields() {
        let json = serde_json::json!({
            "name": "Test Agent",
            "version": "1.0.0",
            "supportedInterfaces": [
                {
                    "url": "http://localhost:3000",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": crate::VERSION
                }
            ],
            "capabilities": {},
            "skills": []
        });

        let card: AgentCard = serde_json::from_value(json).unwrap();
        assert_eq!(card.description, "");
        assert!(card.default_input_modes.is_empty());
        assert!(card.default_output_modes.is_empty());
    }

    #[test]
    fn test_security_scheme_deserialize_unknown_variant_errors() {
        let err = serde_json::from_value::<SecurityScheme>(serde_json::json!({
            "unknown": {"value": true}
        }))
        .unwrap_err();

        assert!(err.to_string().contains("unknown security scheme variant"));
    }

    #[test]
    fn test_oauth_flows_deserialize_unknown_variant_errors() {
        let err = serde_json::from_value::<OAuthFlows>(serde_json::json!({
            "unknown": {"tokenUrl": "https://example.com/token"}
        }))
        .unwrap_err();

        assert!(err.to_string().contains("unknown OAuth flow variant"));
    }

    #[test]
    fn test_security_scheme_apikey_serde() {
        let ss = SecurityScheme::ApiKey(ApiKeySecurityScheme {
            location: "header".to_string(),
            name: "X-API-Key".to_string(),
            description: None,
        });
        let json = serde_json::to_string(&ss).unwrap();
        assert!(json.contains("apiKeySecurityScheme"));
        let back: SecurityScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(ss, back);
    }

    #[test]
    fn test_security_scheme_httpauth_serde() {
        let ss = SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
            scheme: "Bearer".to_string(),
            description: None,
            bearer_format: Some("JWT".to_string()),
        });
        let json = serde_json::to_string(&ss).unwrap();
        assert!(json.contains("httpAuthSecurityScheme"));
        let back: SecurityScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(ss, back);
    }

    #[test]
    fn test_security_scheme_oauth2_serde() {
        let ss = SecurityScheme::OAuth2(OAuth2SecurityScheme {
            flows: OAuthFlows::ClientCredentials(ClientCredentialsOAuthFlow {
                token_url: "https://auth.example.com/token".to_string(),
                scopes: [("read".to_string(), "Read access".to_string())]
                    .into_iter()
                    .collect(),
                refresh_url: None,
            }),
            description: None,
            oauth2_metadata_url: None,
        });
        let json = serde_json::to_string(&ss).unwrap();
        let back: SecurityScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(ss, back);
    }

    #[test]
    fn test_security_scheme_openidconnect_serde() {
        let ss = SecurityScheme::OpenIdConnect(OpenIdConnectSecurityScheme {
            open_id_connect_url: "https://example.com/.well-known/openid-configuration".to_string(),
            description: None,
        });
        let json = serde_json::to_string(&ss).unwrap();
        let back: SecurityScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(ss, back);
    }

    #[test]
    fn test_security_scheme_mtls_serde() {
        let ss = SecurityScheme::MutualTls(MutualTlsSecurityScheme {
            description: Some("mTLS auth".to_string()),
        });
        let json = serde_json::to_string(&ss).unwrap();
        let back: SecurityScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(ss, back);
    }

    #[test]
    fn test_oauth_flows_all_variants() {
        let flows = [
            OAuthFlows::AuthorizationCode(AuthorizationCodeOAuthFlow {
                authorization_url: "https://auth.example.com/authorize".to_string(),
                token_url: "https://auth.example.com/token".to_string(),
                scopes: HashMap::new(),
                refresh_url: None,
                pkce_required: Some(true),
            }),
            OAuthFlows::DeviceCode(DeviceCodeOAuthFlow {
                device_authorization_url: "https://auth.example.com/device".to_string(),
                token_url: "https://auth.example.com/token".to_string(),
                scopes: HashMap::new(),
                refresh_url: None,
            }),
            OAuthFlows::Implicit(ImplicitOAuthFlow {
                authorization_url: "https://auth.example.com/authorize".to_string(),
                scopes: HashMap::new(),
                refresh_url: None,
            }),
            OAuthFlows::Password(PasswordOAuthFlow {
                token_url: "https://auth.example.com/token".to_string(),
                scopes: HashMap::new(),
                refresh_url: None,
            }),
        ];
        for flow in flows {
            let json = serde_json::to_string(&flow).unwrap();
            let back: OAuthFlows = serde_json::from_str(&json).unwrap();
            assert_eq!(flow, back);
        }
    }

    #[test]
    fn test_agent_capabilities_default() {
        let caps = AgentCapabilities::default();
        assert_eq!(caps.streaming, None);
        assert_eq!(caps.push_notifications, None);
        assert_eq!(caps.extensions, None);
        assert_eq!(caps.extended_agent_card, None);
    }

    #[test]
    fn test_agent_card_with_security_schemes() {
        let mut schemes = HashMap::new();
        schemes.insert(
            "bearer".to_string(),
            SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
                scheme: "Bearer".to_string(),
                description: None,
                bearer_format: None,
            }),
        );
        let card = AgentCard {
            name: "Secure Agent".to_string(),
            description: "Agent with auth".to_string(),
            version: "1.0.0".to_string(),
            supported_interfaces: vec![],
            capabilities: AgentCapabilities::default(),
            default_input_modes: vec![],
            default_output_modes: vec![],
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: Some(schemes),
            security_requirements: Some(vec![
                [("bearer".to_string(), vec![])].into_iter().collect(),
            ]),
            signatures: None,
        };
        let value = serde_json::to_value(&card).unwrap();
        assert_eq!(
            value["securityRequirements"],
            serde_json::json!([{"schemes": {"bearer": {}}}])
        );
        let back: AgentCard = serde_json::from_value(value).unwrap();
        assert_eq!(card, back);
    }

    #[test]
    fn test_agent_skill_serializes_security_requirements() {
        let skill = AgentSkill {
            id: "secure-skill".to_string(),
            name: "Secure skill".to_string(),
            description: "Requires bearer authorization".to_string(),
            tags: vec![],
            examples: None,
            input_modes: None,
            output_modes: None,
            security_requirements: Some(vec![
                [("bearer".to_string(), vec!["read".to_string()])]
                    .into_iter()
                    .collect(),
            ]),
        };

        let value = serde_json::to_value(&skill).unwrap();
        assert_eq!(
            value["securityRequirements"],
            serde_json::json!([{"schemes": {"bearer": {"list": ["read"]}}}])
        );
        let back: AgentSkill = serde_json::from_value(value).unwrap();
        assert_eq!(skill, back);
    }

    #[test]
    fn test_agent_card_deserializes_null_skills_as_empty() {
        let card: AgentCard = serde_json::from_str(
            r#"{
                "name": "Test Agent",
                "description": "A test agent",
                "version": "1.0.0",
                "supportedInterfaces": [
                    {
                        "url": "http://localhost:3000",
                        "protocolBinding": "JSONRPC",
                        "protocolVersion": "1.0"
                    }
                ],
                "capabilities": {
                    "streaming": true
                },
                "defaultInputModes": ["text/plain"],
                "defaultOutputModes": ["text/plain"],
                "skills": null
            }"#,
        )
        .unwrap();

        assert!(card.skills.is_empty());
    }

    #[test]
    fn test_agent_card_deserializes_missing_skills_as_empty() {
        let card: AgentCard = serde_json::from_str(
            r#"{
                "name": "Test Agent",
                "description": "A test agent",
                "version": "1.0.0",
                "supportedInterfaces": [
                    {
                        "url": "http://localhost:3000",
                        "protocolBinding": "JSONRPC",
                        "protocolVersion": "1.0"
                    }
                ],
                "capabilities": {
                    "streaming": true
                },
                "defaultInputModes": ["text/plain"],
                "defaultOutputModes": ["text/plain"]
            }"#,
        )
        .unwrap();

        assert!(card.skills.is_empty());
    }

    #[test]
    fn test_agent_card_deserializes_wrapped_security_requirements() {
        let card: AgentCard = serde_json::from_str(
            r#"{
                "name": "Spec Agent",
                "description": "A test agent",
                "version": "1.0.0",
                "supportedInterfaces": [
                    {
                        "url": "https://example.com/spec",
                        "protocolBinding": "JSONRPC",
                        "protocolVersion": "1.0"
                    }
                ],
                "capabilities": {
                    "streaming": true
                },
                "defaultInputModes": ["text/plain"],
                "defaultOutputModes": ["text/plain"],
                "skills": [],
                "securityRequirements": [
                    {
                        "schemes": {
                            "bearer_token": {
                                "list": []
                            }
                        }
                    }
                ]
            }"#,
        )
        .unwrap();

        let requirements = card.security_requirements.unwrap();
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].get("bearer_token"), Some(&Vec::new()));
    }

    #[test]
    fn test_agent_card_deserializes_omitted_empty_security_scope_list() {
        let card: AgentCard = serde_json::from_str(
            r#"{
                "name": "Spec Agent",
                "description": "A test agent",
                "version": "1.0.0",
                "supportedInterfaces": [
                    {
                        "url": "https://example.com/spec",
                        "protocolBinding": "JSONRPC",
                        "protocolVersion": "1.0"
                    }
                ],
                "capabilities": {
                    "streaming": true
                },
                "defaultInputModes": ["text/plain"],
                "defaultOutputModes": ["text/plain"],
                "skills": [],
                "securityRequirements": [
                    {
                        "schemes": {
                            "bearerAuth": {}
                        }
                    }
                ]
            }"#,
        )
        .unwrap();

        let requirements = card.security_requirements.unwrap();
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].get("bearerAuth"), Some(&Vec::new()));
    }

    #[test]
    fn test_agent_card_rejects_security_scope_wrapper_without_list() {
        let err = serde_json::from_str::<AgentCard>(
            r#"{
                "name": "Spec Agent",
                "description": "A test agent",
                "version": "1.0.0",
                "supportedInterfaces": [
                    {
                        "url": "https://example.com/spec",
                        "protocolBinding": "JSONRPC",
                        "protocolVersion": "1.0"
                    }
                ],
                "capabilities": {},
                "defaultInputModes": ["text/plain"],
                "defaultOutputModes": ["text/plain"],
                "skills": [],
                "securityRequirements": [
                    {
                        "schemes": {
                            "bearerAuth": { "scopes": ["read"] }
                        }
                    }
                ]
            }"#,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid wrapped security scopes for bearerAuth"),
            "{err}"
        );
    }

    const SCHEME_NAMES: [&str; 6] = ["zeta", "alpha", "mu", "beta", "omega", "gamma"];

    fn bare_card() -> AgentCard {
        AgentCard {
            name: "Det Agent".to_string(),
            description: String::new(),
            version: "1.0.0".to_string(),
            supported_interfaces: vec![],
            capabilities: AgentCapabilities::default(),
            default_input_modes: vec![],
            default_output_modes: vec![],
            skills: vec![],
            provider: None,
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security_requirements: None,
            signatures: None,
        }
    }

    #[test]
    fn security_requirement_serialization_is_deterministic() {
        let outputs: std::collections::HashSet<String> = (0..60)
            .map(|_| {
                let requirement: SecurityRequirement = SCHEME_NAMES
                    .iter()
                    .map(|n| (n.to_string(), vec!["read".to_string(), "write".to_string()]))
                    .collect();
                let mut card = bare_card();
                card.security_requirements = Some(vec![requirement]);
                serde_json::to_string(&card).unwrap()
            })
            .collect();
        assert_eq!(outputs.len(), 1, "{outputs:#?}");
    }

    #[test]
    fn security_schemes_serialize_sorted() {
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..60 {
            let mut card = bare_card();
            card.security_schemes = Some(
                SCHEME_NAMES
                    .iter()
                    .map(|n| {
                        (
                            n.to_string(),
                            SecurityScheme::OAuth2(OAuth2SecurityScheme {
                                flows: OAuthFlows::ClientCredentials(ClientCredentialsOAuthFlow {
                                    token_url: "https://auth.example.com/token".to_string(),
                                    scopes: ["w", "r", "x", "a", "q", "m"]
                                        .iter()
                                        .map(|k| (k.to_string(), format!("{k} access")))
                                        .collect(),
                                    refresh_url: None,
                                }),
                                description: None,
                                oauth2_metadata_url: None,
                            }),
                        )
                    })
                    .collect(),
            );
            distinct.insert(serde_json::to_string(&card).unwrap());
        }
        assert_eq!(distinct.len(), 1, "{distinct:#?}");

        let json = distinct.into_iter().next().unwrap();
        let value: Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = value["securitySchemes"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
        // The serialized text itself must list the scope keys in order.
        let a = json.find("\"a\":\"a access\"").unwrap();
        let m = json.find("\"m\":\"m access\"").unwrap();
        let x = json.find("\"x\":\"x access\"").unwrap();
        assert!(a < m && m < x, "{json}");
    }

    #[test]
    fn empty_scope_list_serializes_as_empty_object() {
        let mut card = bare_card();
        card.security_requirements = Some(vec![
            [("bearerAuth".to_string(), Vec::<String>::new())]
                .into_iter()
                .collect(),
        ]);
        let value = serde_json::to_value(&card).unwrap();
        assert_eq!(
            value["securityRequirements"][0]["schemes"]["bearerAuth"],
            serde_json::json!({})
        );
        let back: AgentCard = serde_json::from_value(value).unwrap();
        assert_eq!(back, card);
    }

    #[test]
    fn security_scope_shapes_round_trip() {
        for (shape, expected) in [
            (r#"["read"]"#, vec!["read".to_string()]),
            (r#"{"list":["read"]}"#, vec!["read".to_string()]),
            (r#"{}"#, Vec::<String>::new()),
        ] {
            let json = format!(
                r#"{{"name":"n","version":"1","supportedInterfaces":[],"capabilities":{{}},"securityRequirements":[{{"schemes":{{"bearerAuth":{shape}}}}}]}}"#
            );
            let card: AgentCard = serde_json::from_str(&json).unwrap();
            let requirement = &card.security_requirements.as_ref().unwrap()[0];
            assert_eq!(requirement["bearerAuth"], expected, "shape {shape}");

            let again = serde_json::to_string(&card).unwrap();
            let back: AgentCard = serde_json::from_str(&again).unwrap();
            assert_eq!(back, card, "shape {shape}");
        }
    }

    /// A card carrying `securityRequirements` in the given input shape.
    fn card_with_requirements(shape: &str) -> AgentCard {
        let json = format!(
            r#"{{"name":"n","version":"1","supportedInterfaces":[],"capabilities":{{}},"securityRequirements":{shape}}}"#
        );
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("shape {shape}: {e}"))
    }

    /// Edge shapes of #361: each parses, serializes to the canonical form,
    /// parses back equal, and serializes again byte for byte.
    #[test]
    fn security_requirement_edge_cases_round_trip() {
        for (shape, canonical) in [
            // A scheme literally named `schemes`.
            (
                r#"[{"schemes":{"schemes":{"list":["a"]}}}]"#,
                r#"[{"schemes":{"schemes":{"list":["a"]}}}]"#,
            ),
            (
                r#"[{"schemes":["read"]}]"#,
                r#"[{"schemes":{"schemes":{"list":["read"]}}}]"#,
            ),
            // Nested wrapper with an empty scope list.
            (
                r#"[{"schemes":{"schemes":{}}}]"#,
                r#"[{"schemes":{"schemes":{}}}]"#,
            ),
            // An empty requirement, both input spellings, written as `{}`.
            (r#"[{}]"#, r#"[{}]"#),
            (r#"[{"schemes":{}}]"#, r#"[{}]"#),
            // Legacy flat input.
            (
                r#"[{"bearer":["read"]}]"#,
                r#"[{"schemes":{"bearer":{"list":["read"]}}}]"#,
            ),
            (
                r#"[{"bearer":["r"],"apiKey":[]}]"#,
                r#"[{"schemes":{"apiKey":{},"bearer":{"list":["r"]}}}]"#,
            ),
            (r#"[{"bearer":[]}]"#, r#"[{"schemes":{"bearer":{}}}]"#),
        ] {
            let card = card_with_requirements(shape);
            let out = serde_json::to_string(&card).unwrap();
            assert!(
                out.contains(&format!(r#""securityRequirements":{canonical}"#)),
                "shape {shape}: {out}"
            );
            let back: AgentCard = serde_json::from_str(&out).unwrap();
            assert_eq!(back, card, "shape {shape}");
            assert_eq!(serde_json::to_string(&back).unwrap(), out, "shape {shape}");
        }
    }

    /// The empty requirement is `{}` on the wire, as ProtoJSON and the JS SDK
    /// write it, and `{}` and `{"schemes":{}}` are the same requirement.
    #[test]
    fn empty_requirement_serializes_as_empty_object() {
        let mut card = bare_card();
        card.security_requirements = Some(vec![SecurityRequirement::new()]);
        let value = serde_json::to_value(&card).unwrap();
        assert_eq!(value["securityRequirements"], serde_json::json!([{}]));
        assert_eq!(
            card_with_requirements("[{}]"),
            card_with_requirements(r#"[{"schemes":{}}]"#)
        );
    }

    /// The card shapes other SDKs emit, recorded from their sources, parse and
    /// re-serialize to the same JSON.
    ///
    /// Python (a2a-python 6ca8593b): the card is served through
    /// `MessageToDict(card)` (`response_helpers.py:93`), which omits an empty
    /// repeated field, so an empty `StringList` is `{}` and an empty
    /// `SecurityRequirement` is `{}`. It reads with `ParseDict`
    /// (`card_resolver.py:32`), which accepts `{}` and `{"list": []}`.
    /// JS (a2a-js 9a28d501): `StringList.toJSON` writes `list` only when it is
    /// non-empty (`protojson.ts:937-942`) and `fromJSON` accepts a missing one
    /// (`protojson.ts:929-934`).
    ///
    /// The Python `a2a` package is not installed on the build host, so this is
    /// a fixture comparison rather than a run of the SDK parser.
    #[test]
    fn other_sdk_emitted_shapes_parse_and_re_serialize_identically() {
        let emitted = serde_json::json!([
            {"schemes": {"bearer": {"list": ["read", "write"]}, "apiKey": {}}},
            {},
        ]);
        let card = card_with_requirements(&emitted.to_string());
        let requirements = card.security_requirements.as_ref().unwrap();
        assert_eq!(requirements.len(), 2);
        assert_eq!(requirements[0]["bearer"], ["read", "write"]);
        assert!(requirements[0]["apiKey"].is_empty());
        assert!(requirements[1].is_empty());

        let value = serde_json::to_value(&card).unwrap();
        assert_eq!(value["securityRequirements"], emitted);

        // The ProtoJSON reader form `{"list": []}` reads as the same card.
        let spelled_out = card_with_requirements(
            r#"[{"schemes":{"bearer":{"list":["read","write"]},"apiKey":{"list":[]}}},{"schemes":{}}]"#,
        );
        assert_eq!(spelled_out, card);
    }

    fn assert_keys_in_order(json: &str, keys: &[&str]) {
        let mut at = 0;
        for key in keys {
            let found = json[at..]
                .find(&format!("\"{key}\":"))
                .unwrap_or_else(|| panic!("{key} missing or out of order in {json}"));
            at += found + key.len();
        }
    }

    const SIX_KEYS: [&str; 6] = ["w", "r", "x", "a", "q", "m"];
    const SIX_KEYS_SORTED: [&str; 6] = ["a", "m", "q", "r", "w", "x"];

    fn six_scopes() -> HashMap<String, String> {
        SIX_KEYS
            .iter()
            .map(|k| (k.to_string(), format!("{k} access")))
            .collect()
    }

    /// Every OAuth flow's `scopes` map serializes sorted, on every run.
    #[test]
    fn every_oauth_flow_serializes_scopes_sorted() {
        fn flows() -> Vec<(&'static str, OAuthFlows)> {
            vec![
                (
                    "authorizationCode",
                    OAuthFlows::AuthorizationCode(AuthorizationCodeOAuthFlow {
                        authorization_url: "https://auth.example.com/authorize".to_string(),
                        token_url: "https://auth.example.com/token".to_string(),
                        scopes: six_scopes(),
                        refresh_url: None,
                        pkce_required: None,
                    }),
                ),
                (
                    "deviceCode",
                    OAuthFlows::DeviceCode(DeviceCodeOAuthFlow {
                        device_authorization_url: "https://auth.example.com/device".to_string(),
                        token_url: "https://auth.example.com/token".to_string(),
                        scopes: six_scopes(),
                        refresh_url: None,
                    }),
                ),
                (
                    "implicit",
                    OAuthFlows::Implicit(ImplicitOAuthFlow {
                        authorization_url: "https://auth.example.com/authorize".to_string(),
                        scopes: six_scopes(),
                        refresh_url: None,
                    }),
                ),
                (
                    "password",
                    OAuthFlows::Password(PasswordOAuthFlow {
                        token_url: "https://auth.example.com/token".to_string(),
                        scopes: six_scopes(),
                        refresh_url: None,
                    }),
                ),
                (
                    "clientCredentials",
                    OAuthFlows::ClientCredentials(ClientCredentialsOAuthFlow {
                        token_url: "https://auth.example.com/token".to_string(),
                        scopes: six_scopes(),
                        refresh_url: None,
                    }),
                ),
            ]
        }

        for index in 0..5 {
            let mut distinct = std::collections::HashSet::new();
            let mut name = "";
            for _ in 0..40 {
                let (flow_name, flow) = flows().remove(index);
                name = flow_name;
                let mut card = bare_card();
                card.security_schemes = Some(
                    [(
                        "oauth".to_string(),
                        SecurityScheme::OAuth2(OAuth2SecurityScheme {
                            flows: flow,
                            description: None,
                            oauth2_metadata_url: None,
                        }),
                    )]
                    .into_iter()
                    .collect(),
                );
                distinct.insert(serde_json::to_string(&card).unwrap());
            }
            assert_eq!(distinct.len(), 1, "flow {name}: {distinct:#?}");
            let json = distinct.into_iter().next().unwrap();
            assert!(json.contains(name), "flow {name} missing: {json}");
            let sorted: Vec<String> = SIX_KEYS_SORTED
                .iter()
                .map(|k| format!("{k} access"))
                .collect();
            assert_keys_in_order(&json, &SIX_KEYS_SORTED);
            for text in &sorted {
                assert!(json.contains(text.as_str()), "{text} missing: {json}");
            }
        }
    }

    fn six_values() -> HashMap<String, Value> {
        SIX_KEYS
            .iter()
            .map(|k| (k.to_string(), serde_json::json!({ "v": k })))
            .collect()
    }

    /// `AgentExtension.params` and `AgentCardSignature.header` serialize
    /// sorted, on every run.
    #[test]
    fn extension_params_and_signature_header_serialize_sorted() {
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..40 {
            let mut card = bare_card();
            card.capabilities.extensions = Some(vec![AgentExtension {
                uri: "https://example.com/ext".to_string(),
                description: None,
                required: None,
                params: Some(six_values()),
            }]);
            card.signatures = Some(vec![AgentCardSignature {
                protected: "p".to_string(),
                signature: "s".to_string(),
                header: Some(six_values()),
            }]);
            distinct.insert(serde_json::to_string(&card).unwrap());
        }
        assert_eq!(distinct.len(), 1, "{distinct:#?}");

        let json = distinct.into_iter().next().unwrap();
        let params_at = json.find("\"params\":").expect("params serialized");
        let header_at = json.find("\"header\":").expect("header serialized");
        assert_keys_in_order(&json[params_at..], &SIX_KEYS_SORTED);
        assert_keys_in_order(&json[header_at..], &SIX_KEYS_SORTED);
    }
}

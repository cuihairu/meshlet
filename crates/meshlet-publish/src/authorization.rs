use meshlet_domain::Ipv4Cidr;
use std::net::SocketAddr;

use crate::PublishError;

#[derive(Debug, Clone)]
pub struct AuthorizedClient {
    pub remote: SocketAddr,
    pub auth_header: Option<String>,
}

impl AuthorizedClient {
    pub fn from_socket(remote: SocketAddr) -> Self {
        Self {
            remote,
            auth_header: None,
        }
    }

    pub fn with_auth_header(mut self, header: impl Into<String>) -> Self {
        self.auth_header = Some(header.into());
        self
    }
}

/// Authorization is checked before a service connection is opened. Empty
/// source networks do not grant access and a required bearer token cannot be
/// satisfied by IP allowlisting alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizationPolicy {
    #[serde(default)]
    pub allowed_source_cidrs: Vec<Ipv4Cidr>,
    #[serde(default)]
    pub allowed_bearer_tokens: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecision {
    Allowed,
    Denied,
}

impl AuthorizationPolicy {
    pub fn authorize(&self, client: &AuthorizedClient) -> AuthorizationDecision {
        let source_allowed = if let std::net::IpAddr::V4(ip) = client.remote.ip() {
            self.allowed_source_cidrs
                .iter()
                .any(|cidr| cidr.contains(ip))
        } else {
            false
        };
        if source_allowed {
            return AuthorizationDecision::Allowed;
        }
        let header = self.allowed_bearer_tokens.iter().any(|token| {
            client
                .auth_header
                .as_deref()
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(|value| value == token)
                .unwrap_or(false)
        });
        if header {
            AuthorizationDecision::Allowed
        } else {
            AuthorizationDecision::Denied
        }
    }
}

impl TryFrom<&str> for AuthorizationPolicy {
    type Error = PublishError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut cidrs = Vec::new();
        for raw in value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            let cidr: Result<Ipv4Cidr, _> = raw.parse();
            let cidr = cidr.map_err(|_| {
                PublishError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid allowed_source_cidr: {raw}"),
                ))
            })?;
            cidrs.push(cidr);
        }
        Ok(Self {
            allowed_source_cidrs: cidrs,
            allowed_bearer_tokens: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(ip: &str, header: Option<&str>) -> AuthorizedClient {
        let mut client = AuthorizedClient::from_socket(format!("{ip}:40000").parse().unwrap());
        if let Some(header) = header {
            client = client.with_auth_header(header);
        }
        client
    }

    #[test]
    fn allowlist_is_enforced_before_backend_connect() {
        let policy = AuthorizationPolicy {
            allowed_source_cidrs: vec!["10.240.0.0/16".parse().unwrap()],
            allowed_bearer_tokens: vec!["secret".into()],
        };

        assert_eq!(
            policy.authorize(&client("10.240.4.9", None)),
            AuthorizationDecision::Allowed
        );
        assert_eq!(
            policy.authorize(&client("10.240.0.2", Some("Bearer wrong"))),
            AuthorizationDecision::Allowed
        );
        assert_eq!(
            policy.authorize(&client("10.240.0.2", Some("Bearer secret"))),
            AuthorizationDecision::Allowed
        );
        assert_eq!(
            policy.authorize(&client("10.241.128.9", Some("Bearer wrong"))),
            AuthorizationDecision::Denied
        );
        assert_eq!(
            AuthorizationPolicy::default().authorize(&client("10.240.0.2", None)),
            AuthorizationDecision::Denied
        );
    }
}

use crate::{AuthorizationDecision, AuthorizationPolicy, AuthorizedClient, PublishError};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpRoute {
    pub id: String,
    pub network_id: String,
    pub hostname: String,
    pub path_prefix: String,
    pub backend_address: SocketAddr,
    pub policy: AuthorizationPolicy,
    pub tls_termination: bool,
}

impl HttpRoute {
    pub fn matches(&self, host: &str, path: &str) -> bool {
        self.hostname.eq_ignore_ascii_case(host) && path.starts_with(&self.path_prefix)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpRouteSet {
    routes: Vec<HttpRoute>,
}

impl HttpRouteSet {
    pub fn new(mut routes: Vec<HttpRoute>) -> Result<Self, PublishError> {
        routes.sort_by(|left, right| {
            (
                &left.hostname,
                std::cmp::Reverse(left.path_prefix.len()),
                &left.id,
            )
                .cmp(&(
                    &right.hostname,
                    std::cmp::Reverse(right.path_prefix.len()),
                    &right.id,
                ))
        });
        let mut seen = HashMap::new();
        for route in &routes {
            if route.id.trim().is_empty()
                || route.path_prefix.is_empty()
                || !route.path_prefix.starts_with('/')
            {
                return Err(invalid("route id/path_prefix is invalid"));
            }
            if route.backend_address.port() == 0 {
                return Err(invalid("backend port must not be zero"));
            }
            let key = (
                route.hostname.to_ascii_lowercase(),
                route.path_prefix.clone(),
            );
            if seen.insert(key, ()).is_some() {
                return Err(invalid("duplicate HTTP route hostname/path_prefix"));
            }
        }
        Ok(Self { routes })
    }

    pub fn routes(&self) -> &[HttpRoute] {
        &self.routes
    }

    fn select(&self, host: &str, path: &str) -> Option<&HttpRoute> {
        self.routes.iter().find(|route| route.matches(host, path))
    }
}

pub fn invalid(message: impl Into<String>) -> PublishError {
    PublishError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

#[derive(Debug)]
struct RequestHead {
    target: String,
    host: String,
    authorization: Option<String>,
    bytes: Vec<u8>,
}

async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Result<RequestHead, PublishError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let size = stream.read(&mut chunk).await?;
        if size == 0 {
            return Err(PublishError::ConnectionClosed);
        }
        bytes.extend_from_slice(&chunk[..size]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if bytes.len() > 32 * 1024 {
            return Err(invalid("request head exceeds 32 KiB"));
        }
    }
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("checked terminator");
    let head = String::from_utf8_lossy(&bytes[..split]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    parts.next().ok_or_else(|| invalid("missing method"))?;
    let target = parts
        .next()
        .ok_or_else(|| invalid("missing target"))?
        .to_string();
    let mut host = None;
    let mut authorization = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "host" {
                host = Some(value.rsplit(':').next().unwrap_or(value).to_string());
            } else if name == "authorization" {
                authorization = Some(value.to_string());
            }
        }
    }
    Ok(RequestHead {
        target,
        host: host.ok_or_else(|| invalid("missing Host header"))?,
        authorization,
        bytes,
    })
}

pub async fn bind_http(address: SocketAddr) -> Result<(TcpListener, SocketAddr), PublishError> {
    let listener = TcpListener::bind(address).await?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}

pub async fn run_http_router<S, B, F>(
    mut stream: S,
    routes: &HttpRouteSet,
    mode: RouteMode,
    remote: std::net::SocketAddr,
    connect_backend: impl Fn(SocketAddr) -> F,
) -> Result<(), PublishError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = Result<B, std::io::Error>>,
{
    if mode == RouteMode::TlsPassThrough {
        let sni = sniff_sni(&mut stream).await?;
        let Some(route) = routes.select(&sni, "/") else {
            return Err(invalid(format!("no TLS route for SNI {sni:?}")));
        };
        if route
            .policy
            .authorize(&AuthorizedClient::from_socket(remote))
            == AuthorizationDecision::Denied
        {
            return Err(invalid("unauthorized"));
        }
        let mut backend = connect_backend(route.backend_address).await?;
        return tokio::io::copy_bidirectional(&mut stream, &mut backend)
            .await
            .map(|_| ())
            .map_err(PublishError::from);
    }

    let request = read_head(&mut stream).await?;
    let path = request.target.split(['?', '#']).next().unwrap_or("/");
    let Some(route) = routes.select(&request.host, path) else {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await?;
        stream.flush().await?;
        stream.shutdown().await?;
        return Ok(());
    };
    let client = AuthorizedClient {
        remote,
        auth_header: request.authorization,
    };
    if route.policy.authorize(&client) == AuthorizationDecision::Denied {
        stream
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
        stream.shutdown().await?;
        return Ok(());
    }
    let mut backend = connect_backend(route.backend_address).await?;
    backend.write_all(&request.bytes).await?;
    backend.flush().await?;
    backend.shutdown().await?;
    tokio::io::copy(&mut backend, &mut stream)
        .await
        .map(|_| ())
        .map_err(PublishError::from)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    PlainHttp,
    TlsPassThrough,
}

pub async fn sniff_sni(stream: &mut (impl AsyncRead + Unpin)) -> Result<String, PublishError> {
    let mut buffer = [0_u8; 5];
    stream.read_exact(&mut buffer).await?;
    if buffer[0] != 0x16 || u16::from_be_bytes([buffer[1], buffer[2]]) != 0x0301 {
        return Err(invalid("TLS pass-through requires a TLS ClientHello"));
    }
    let size = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
    if !(43..=16 * 1024).contains(&size) {
        return Err(invalid("TLS ClientHello length is invalid"));
    }
    let mut body = vec![0_u8; size];
    stream.read_exact(&mut body).await?;
    let mut offset = 2 + 32;
    offset += 1 + body[offset] as usize;
    let cipher_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2 + cipher_len;
    let compression_len = body[offset] as usize;
    offset += 1 + compression_len;
    let mut extensions_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    while extensions_len >= 4 {
        let extension_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let extension_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        if extension_type == 0 {
            if extension_len < 6 {
                return Err(invalid("malformed SNI extension"));
            }
            let list_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
            let mut list_offset = offset + 2;
            let end = list_offset + list_len;
            if end > body.len() {
                return Err(invalid("SNI list exceeds ClientHello"));
            }
            while list_offset < end {
                let name_type = body[list_offset];
                let name_len =
                    u16::from_be_bytes([body[list_offset + 1], body[list_offset + 2]]) as usize;
                list_offset += 3;
                if name_type == 0 {
                    let name = &body[list_offset..list_offset + name_len];
                    return Ok(String::from_utf8_lossy(name).to_string());
                }
                list_offset += name_len;
            }
            return Err(invalid("TLS ClientHello contains no server_name"));
        }
        offset += extension_len;
        extensions_len -= 4 + extension_len;
    }
    Err(invalid("TLS ClientHello contains no extensions"))
}

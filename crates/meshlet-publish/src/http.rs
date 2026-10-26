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
    /// SNI sniffing plus raw TLS byte forwarding. The meshlet holds no
    /// certificate and never decrypts, so this is passthrough, not
    /// termination. The `tls_termination` alias keeps plans written under
    /// the old, misleading field name readable.
    #[serde(alias = "tls_termination")]
    pub tls_passthrough: bool,
}

impl HttpRoute {
    pub fn matches(&self, host: &str, path: &str) -> bool {
        self.hostname.eq_ignore_ascii_case(host) && path.starts_with(&self.path_prefix)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
        let (sni, hello) = sniff_sni(&mut stream).await?;
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
        // 嗅探已经消费掉客户端的 ClientHello；必须原样回灌，否则后端收不到握手。
        backend.write_all(&hello).await?;
        backend.flush().await?;
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

/// 读取并解析 ClientHello，返回 `(server_name, 消费掉的完整记录字节)`。
/// 调用方必须把返回的字节回灌给后端——嗅探本身吃掉了客户端的握手。
pub async fn sniff_sni(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<(String, Vec<u8>), PublishError> {
    let mut buffer = [0_u8; 5];
    stream.read_exact(&mut buffer).await?;
    if buffer[0] != 0x16 || u16::from_be_bytes([buffer[1], buffer[2]]) != 0x0301 {
        return Err(invalid("TLS pass-through requires a TLS ClientHello"));
    }
    let size = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
    if !(43..=16 * 1024).contains(&size) {
        return Err(invalid("TLS ClientHello length is invalid"));
    }
    let mut record = Vec::with_capacity(5 + size);
    record.extend_from_slice(&buffer);
    record.resize(5 + size, 0);
    stream.read_exact(&mut record[5..]).await?;
    let sni = parse_client_hello_sni(&record[5..])?;
    Ok((sni, record))
}

/// Cursor over one handshake message; every read is bounds-checked so a
/// malformed ClientHello yields an error instead of an index panic.
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], PublishError> {
        let end = self
            .position
            .checked_add(size)
            .ok_or_else(|| invalid("malformed TLS ClientHello"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid("malformed TLS ClientHello"))?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, PublishError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PublishError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

fn parse_client_hello_sni(record: &[u8]) -> Result<String, PublishError> {
    if record.len() < 4 || record[0] != 0x01 {
        return Err(invalid("TLS record is not a ClientHello handshake"));
    }
    let handshake_len = u32::from_be_bytes([0, record[1], record[2], record[3]]) as usize;
    let end = match 4usize
        .checked_add(handshake_len)
        .filter(|end| *end <= record.len())
    {
        Some(end) => end,
        None => return Err(invalid("TLS ClientHello length exceeds the record")),
    };
    let mut cursor = Cursor {
        bytes: &record[4..end],
        position: 0,
    };
    cursor.take(2)?; // client version
    cursor.take(32)?; // random
    let session_len = cursor.u8()? as usize;
    cursor.take(session_len)?;
    let cipher_len = cursor.u16()? as usize;
    cursor.take(cipher_len)?;
    let compression_len = cursor.u8()? as usize;
    cursor.take(compression_len)?;
    if cursor.position == cursor.bytes.len() {
        return Err(invalid("TLS ClientHello contains no extensions"));
    }
    let extensions_len = cursor.u16()? as usize;
    let extensions = cursor.take(extensions_len)?;
    let mut extensions = extensions;
    while !extensions.is_empty() {
        if extensions.len() < 4 {
            return Err(invalid("malformed TLS ClientHello extensions"));
        }
        let extension_type = u16::from_be_bytes([extensions[0], extensions[1]]);
        let extension_len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        let after = match 4usize
            .checked_add(extension_len)
            .filter(|after| *after <= extensions.len())
        {
            Some(after) => after,
            None => return Err(invalid("malformed TLS ClientHello extensions")),
        };
        let payload = &extensions[4..after];
        if extension_type == 0 {
            return parse_server_name(payload);
        }
        extensions = &extensions[after..];
    }
    Err(invalid("TLS ClientHello contains no extensions"))
}

fn parse_server_name(payload: &[u8]) -> Result<String, PublishError> {
    if payload.len() < 2 {
        return Err(invalid("malformed SNI extension"));
    }
    let list_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    let end = match 2usize
        .checked_add(list_len)
        .filter(|end| *end <= payload.len())
    {
        Some(end) => end,
        None => return Err(invalid("malformed SNI extension")),
    };
    let mut names = &payload[2..end];
    while !names.is_empty() {
        if names.len() < 3 {
            return Err(invalid("malformed SNI extension"));
        }
        let name_type = names[0];
        let name_len = u16::from_be_bytes([names[1], names[2]]) as usize;
        let after = match 3usize
            .checked_add(name_len)
            .filter(|after| *after <= names.len())
        {
            Some(after) => after,
            None => return Err(invalid("malformed SNI extension")),
        };
        if name_type == 0 {
            return Ok(String::from_utf8_lossy(&names[3..after]).to_string());
        }
        names = &names[after..];
    }
    Err(invalid("TLS ClientHello contains no server_name"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    /// 一个真实的 ClientHello 帧：record(5) + handshake(4) + hello body。
    /// extra 是插在 server_name 扩展之前的原始扩展字节，用于覆盖跳过路径。
    fn client_hello(sni: Option<&str>, extra: &[u8]) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(extra);
        if let Some(name) = sni {
            let mut names = Vec::new();
            names.push(0); // host_name
            names.extend_from_slice(&(name.len() as u16).to_be_bytes());
            names.extend_from_slice(name.as_bytes());
            let mut list = Vec::new();
            list.extend_from_slice(&(names.len() as u16).to_be_bytes());
            list.extend_from_slice(&names);
            extensions.extend_from_slice(&0_u16.to_be_bytes());
            extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&list);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version
        body.extend_from_slice(&[0x2a; 32]); // random
        body.push(0); // no session id
        body.extend_from_slice(&2_u16.to_be_bytes()); // cipher suites
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression methods
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        record.push(0x01); // handshake: ClientHello
        record.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        record.extend_from_slice(&body);
        record
    }

    /// 把一帧字节通过真实回环 socket 喂给嗅探器（与运行时相同的到达路径）。
    async fn sni(frame: &[u8]) -> Result<(String, Vec<u8>), PublishError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let payload = frame.to_vec();
        let sender = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // 写失败属预期（嗅探器可能提前断开），不让任务 panic。
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, &payload).await;
        });
        let mut stream = TcpStream::connect(local).await.unwrap();
        let result = sniff_sni(&mut stream).await;
        drop(stream);
        sender.await.unwrap();
        result
    }

    fn message(error: PublishError) -> String {
        error.to_string()
    }

    #[tokio::test]
    async fn reads_sni_from_a_well_formed_client_hello() {
        let frame = client_hello(Some("tls.mesh.internal"), &[]);
        let (sni, replay) = sni(&frame).await.unwrap();
        assert_eq!(sni, "tls.mesh.internal");
        // 消费掉的记录字节必须原样返回，供调用方回灌给后端。
        assert_eq!(replay, frame);
    }

    #[tokio::test]
    async fn skips_unknown_extensions_before_the_sni_extension() {
        // extension_type 10, payload 4 字节，必须被跳过而不是当作 SNI 解析。
        let frame = client_hello(
            Some("late.mesh.internal"),
            &[0x00, 0x0a, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef],
        );
        let (sni, _) = sni(&frame).await.unwrap();
        assert_eq!(sni, "late.mesh.internal");
    }

    #[tokio::test]
    async fn rejects_plain_http_in_pass_through_mode() {
        let error = sni(b"GET / HTTP/1.1\r\nHost: app.mesh.internal\r\n\r\n")
            .await
            .unwrap_err();
        assert!(message(error).contains("requires a TLS ClientHello"));
    }

    #[tokio::test]
    async fn rejects_a_record_that_is_not_a_client_hello() {
        let mut frame = client_hello(Some("tls.mesh.internal"), &[]);
        frame[5] = 0x02; // handshake type no longer ClientHello
        let error = sni(&frame).await.unwrap_err();
        assert!(message(error).contains("not a ClientHello handshake"));
    }

    #[tokio::test]
    async fn rejects_a_truncated_cipher_block_instead_of_panicking() {
        // cipher_suites 声明 100 字节但帧在压缩方法前截断：旧行为直接越界 panic。
        // 记录长度必须过 43 字节下限，否则在读到该字段前就被拒。
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x2a; 32]);
        body.push(0);
        body.extend_from_slice(&100_u16.to_be_bytes());
        body.extend_from_slice(&[0; 6]);
        let mut frame = vec![0x16, 0x03, 0x01];
        frame.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        frame.push(0x01);
        frame.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        frame.extend_from_slice(&body);
        let error = sni(&frame).await.unwrap_err();
        assert!(message(error).contains("malformed TLS ClientHello"));
    }

    #[tokio::test]
    async fn rejects_extensions_claiming_more_than_the_record_holds() {
        // 扩展区声明 2000 字节而记录只有几十字节：回归 sniff_sni 7157 越界 panic。
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x2a; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&2000_u16.to_be_bytes());
        let mut frame = vec![0x16, 0x03, 0x01];
        frame.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        frame.push(0x01);
        frame.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        frame.extend_from_slice(&body);
        let error = sni(&frame).await.unwrap_err();
        assert!(message(error).contains("malformed TLS ClientHello"));
    }

    #[tokio::test]
    async fn rejects_a_server_name_list_beyond_the_extension_payload() {
        // server_name_list 声明 8 字节但扩展负载只剩 2 字节。
        let frame = client_hello(None, &[0x00, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01]);
        let error = sni(&frame).await.unwrap_err();
        assert!(message(error).contains("malformed SNI extension"));
    }

    #[tokio::test]
    async fn rejects_a_name_entry_beyond_the_server_name_list() {
        // 前缀扩展 type=22 len=0 会被跳过；随后是真实的 server_name 扩展，
        // list_len=4 但列表只剩 1 字节（name_len 远超剩余长度）。
        let frame = client_hello(
            None,
            &[
                0x00, 0x16, 0x00, 0x00, // extension_type 22, empty
                0x00, 0x00, 0x00, 0x05, // extension_type 0, len 5
                0x00, 0x04, 0x00, 0x01, 0x61, // list_len 4, name_len 0x0061
            ],
        );
        let error = sni(&frame).await.unwrap_err();
        assert!(message(error).contains("malformed SNI extension"));
    }

    #[tokio::test]
    async fn rejects_a_server_name_list_without_a_host_name_entry() {
        // 唯一合法条目的类型是 1（user_fqdn），列表里没有 host_name。
        let frame = client_hello(
            None,
            &[
                0x00, 0x16, 0x00, 0x00, // extension_type 22, empty
                0x00, 0x00, 0x00, 0x06, // extension_type 0, len 6
                0x00, 0x04, 0x01, 0x00, 0x01, 0x63, // user_fqdn "c"
            ],
        );
        let error = sni(&frame).await.unwrap_err();
        assert!(message(error).contains("contains no server_name"));
    }

    #[tokio::test]
    async fn rejects_a_client_hello_without_any_extension() {
        let frame = client_hello(None, &[]);
        let error = sni(&frame).await.unwrap_err();
        assert!(message(error).contains("contains no extensions"));
    }

    #[tokio::test]
    async fn rejects_a_truncated_record_body() {
        let mut frame = client_hello(Some("tls.mesh.internal"), &[]);
        frame.truncate(30); // 记录头声明远多于 30 字节
        let error = sni(&frame).await.unwrap_err();
        assert!(matches!(error, PublishError::Io(_)));
    }
}

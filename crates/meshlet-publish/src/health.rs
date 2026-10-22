use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Unreachable,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProbeTarget {
    Tcp {
        address: SocketAddr,
        timeout: Duration,
    },
    Http {
        address: SocketAddr,
        path: String,
        expected_status: u16,
        timeout: Duration,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Healthy,
    Unreachable,
}

impl ProbeTarget {
    pub async fn probe(&self) -> ProbeOutcome {
        let result = match self {
            ProbeTarget::Tcp { address, timeout } => tcp_probe(*address, *timeout).await,
            ProbeTarget::Http {
                address,
                path,
                expected_status,
                timeout,
            } => http_check(*address, path, *expected_status, *timeout).await,
        };
        result.unwrap_or(ProbeOutcome::Unreachable)
    }
}
async fn tcp_probe(address: SocketAddr, timeout: Duration) -> Option<ProbeOutcome> {
    tokio::time::timeout(timeout, TcpStream::connect(address))
        .await
        .ok()?
        .ok()
        .map(|_| ProbeOutcome::Healthy)
}

async fn http_check(
    address: SocketAddr,
    path: &str,
    expected_status: u16,
    timeout: Duration,
) -> Option<ProbeOutcome> {
    let path = if path.starts_with('/') { path } else { "/" };
    let request = format!("GET {path} HTTP/1.1\r\nhost: {address}\r\nconnection: close\r\n\r\n");
    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        _ => return Some(ProbeOutcome::Unreachable),
    };
    if stream.write_all(request.as_bytes()).await.is_err() {
        return Some(ProbeOutcome::Unreachable);
    }
    let mut response = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        let size = match stream.read(&mut chunk).await {
            Ok(size) => size,
            Err(_) => return Some(ProbeOutcome::Unreachable),
        };
        if size == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..size]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if response.len() > 16 * 1024 {
            break;
        }
    }
    let status_line = std::str::from_utf8(&response).ok()?.lines().next()?;
    let actual = status_line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    Some(if actual == expected_status {
        ProbeOutcome::Healthy
    } else {
        ProbeOutcome::Unreachable
    })
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HealthStatus {
    pub state: Option<HealthState>,
    pub checked_at: Option<String>,
    pub detail: Option<String>,
}

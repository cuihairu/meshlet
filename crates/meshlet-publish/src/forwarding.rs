use crate::{AuthorizationDecision, AuthorizationPolicy, AuthorizedClient, PublishError};
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const UDP_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortForwardConfig {
    pub id: String,
    pub network_id: String,
    pub protocol: ForwardProtocol,
    pub listener_address: SocketAddr,
    pub backend_address: SocketAddr,
    pub policy: AuthorizationPolicy,
    pub enabled: bool,
}

impl PortForwardConfig {
    pub fn validate(&self) -> Result<(), PublishError> {
        if self.id.trim().is_empty() {
            return Err(invalid("id must not be empty"));
        }
        if self.listener_address.port() == 0 {
            return Err(invalid("listener address must not use port 0"));
        }
        if self.backend_address.port() == 0 {
            return Err(invalid("backend address must not use port 0"));
        }
        if self.listener_address.ip().to_string() == self.backend_address.ip().to_string()
            && self.listener_address.port() == self.backend_address.port()
        {
            return Err(invalid("listener and backend addresses must differ"));
        }
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> PublishError {
    PublishError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

pub async fn bind_tcp(address: SocketAddr) -> Result<(TcpListener, SocketAddr), PublishError> {
    let listener = TcpListener::bind(address).await?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}

pub fn spawn_tcp_forwarder(
    listener: TcpListener,
    target: SocketAddr,
    policy: AuthorizationPolicy,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut inbound, remote)) = listener.accept().await {
            if policy.authorize(&AuthorizedClient::from_socket(remote))
                == AuthorizationDecision::Denied
            {
                let _ = inbound.shutdown().await;
                continue;
            }
            match TcpStream::connect(target).await {
                Ok(outbound) => {
                    tokio::spawn(copy_bidirectional_tcp(inbound, outbound));
                }
                Err(error) => {
                    tracing::error!(error = %error, target = %target, "backend connect failed");
                    let _ = inbound.shutdown().await;
                }
            }
        }
    })
}

async fn copy_bidirectional_tcp(
    mut inbound: TcpStream,
    mut outbound: TcpStream,
) -> std::io::Result<u64> {
    let copied = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    let _ = inbound.shutdown().await;
    let _ = outbound.shutdown().await;
    copied.map(|(client_to_backend, backend_to_client)| client_to_backend + backend_to_client)
}

pub async fn bind_udp(address: SocketAddr) -> Result<(UdpSocket, SocketAddr), PublishError> {
    let socket = UdpSocket::bind(address).await?;
    let local = socket.local_addr()?;
    Ok((socket, local))
}

pub async fn run_udp_forwarder(
    inbound: UdpSocket,
    target: SocketAddr,
    policy: AuthorizationPolicy,
) -> Result<(), PublishError> {
    let outbound_address = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let outbound = UdpSocket::bind(outbound_address).await?;
    let mut buffer = vec![0_u8; UDP_BUFFER_SIZE];
    loop {
        let (size, remote) = inbound.recv_from(&mut buffer).await?;
        if policy.authorize(&AuthorizedClient::from_socket(remote)) == AuthorizationDecision::Denied
        {
            continue;
        }
        outbound.send_to(&buffer[..size], target).await?;
        let (size, backend) = outbound.recv_from(&mut buffer).await?;
        if backend != target {
            continue;
        }
        inbound.send_to(&buffer[..size], remote).await?;
    }
}

pub fn spawn_udp_forwarder(
    inbound: UdpSocket,
    target: SocketAddr,
    policy: AuthorizationPolicy,
) -> tokio::task::JoinHandle<Result<(), PublishError>> {
    tokio::spawn(async move { run_udp_forwarder(inbound, target, policy).await })
}

use meshlet_publish::{AuthorizationPolicy, ForwardProtocol, PortForwardConfig};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn allowed_policy() -> AuthorizationPolicy {
    AuthorizationPolicy {
        allowed_source_cidrs: vec!["127.0.0.0/8".parse().unwrap()],
        allowed_bearer_tokens: Vec::new(),
    }
}

fn config(listener: SocketAddr, backend: SocketAddr) -> PortForwardConfig {
    PortForwardConfig {
        id: "svc".into(),
        network_id: "net-1".into(),
        protocol: ForwardProtocol::Tcp,
        listener_address: listener,
        backend_address: backend,
        policy: allowed_policy(),
        enabled: true,
    }
}

#[tokio::test]
async fn config_rejects_invalid_forward_target() {
    let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
    assert!(config(address, address).validate().is_err());
}

#[tokio::test]
async fn tcp_forwarder_carries_bidirectional_traffic_and_denies_other_clients() {
    let denied_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let denied_address = denied_backend.local_addr().unwrap();
    let (listener, published) = meshlet_publish::bind_tcp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(listener.local_addr().unwrap(), published);

    let mut denied = tokio::net::TcpStream::connect(published).await.unwrap();
    let denied_forwarder = meshlet_publish::spawn_tcp_forwarder(
        listener,
        denied_address,
        AuthorizationPolicy::default(),
    );
    denied.writable().await.unwrap();
    let accepted_denied =
        tokio::time::timeout(Duration::from_millis(50), denied_backend.accept()).await;
    assert!(accepted_denied.is_err());
    denied_forwarder.abort();
    denied.shutdown().await.unwrap();

    let allowed_backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let allowed_address = allowed_backend.local_addr().unwrap();
    let (listener, published) = meshlet_publish::bind_tcp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let forwarder =
        meshlet_publish::spawn_tcp_forwarder(listener, allowed_address, allowed_policy());

    let mut client = tokio::net::TcpStream::connect(published).await.unwrap();
    let (backend_reply_tx, backend_reply_rx) = tokio::sync::oneshot::channel();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = allowed_backend.accept().await.unwrap();
        let mut backend_reply = [0_u8; 4];
        stream.read_exact(&mut backend_reply).await.unwrap();
        stream.write_all(b"pong").await.unwrap();
        backend_reply_tx.send(backend_reply).unwrap();
    });
    client.write_all(b"ping").await.unwrap();
    let mut buffer = [0_u8; 4];
    client.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"pong");
    client.shutdown().await.unwrap();
    backend_task.await.unwrap();
    assert_eq!(backend_reply_rx.await.unwrap(), *b"ping");
    forwarder.abort();
}

#[tokio::test]
async fn udp_forwarder_round_trips_a_datagram() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    tokio::spawn(async move {
        let mut packet = [0_u8; 4];
        let (_, source) = backend.recv_from(&mut packet).await.unwrap();
        assert_eq!(&packet, b"ping");
        backend.send_to(b"pong", source).await.unwrap();
    });

    let (inbound, published) = meshlet_publish::bind_udp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let forwarder =
        meshlet_publish::spawn_udp_forwarder(inbound, backend_address, allowed_policy());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"ping", published).await.unwrap();
    let mut packet = [0_u8; 4];
    let size = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(size, 4);
    assert_eq!(&packet, b"pong");
    forwarder.abort();
}

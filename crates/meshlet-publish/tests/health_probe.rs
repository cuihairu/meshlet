use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use meshlet_publish::health::{ProbeOutcome, ProbeTarget};

const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 256];
    loop {
        let size = stream.read(&mut chunk).await.unwrap();
        assert!(size > 0, "client closed before sending a complete request");
        request.extend_from_slice(&chunk[..size]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(request).unwrap()
}

#[tokio::test]
async fn tcp_probe_detects_reachable_backend() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = backend.local_addr().unwrap();
    let probe_task = tokio::spawn(async move {
        ProbeTarget::Tcp {
            address,
            timeout: PROBE_TIMEOUT,
        }
        .probe()
        .await
    });
    let (_stream, remote) = backend.accept().await.unwrap();
    assert_eq!(remote.ip().to_string(), "127.0.0.1");
    assert_eq!(probe_task.await.unwrap(), ProbeOutcome::Healthy);
}

#[tokio::test]
async fn http_probe_matches_expected_and_rejects_unexpected_status() {
    let healthy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unhealthy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let healthy_address = healthy.local_addr().unwrap();
    let unhealthy_address = unhealthy.local_addr().unwrap();

    let healthy_task = tokio::spawn(async move {
        ProbeTarget::Http {
            address: healthy_address,
            path: "/healthz".to_string(),
            expected_status: 204,
            timeout: PROBE_TIMEOUT,
        }
        .probe()
        .await
    });
    let (mut stream, _) = healthy.accept().await.unwrap();
    let request = read_http_request(&mut stream).await;
    assert!(request.starts_with("GET /healthz HTTP/1.1\r\n"));
    assert!(request.contains("host: "));
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(healthy_task.await.unwrap(), ProbeOutcome::Healthy);

    let unhealthy_task = tokio::spawn(async move {
        ProbeTarget::Http {
            address: unhealthy_address,
            path: "/healthz".to_string(),
            expected_status: 204,
            timeout: PROBE_TIMEOUT,
        }
        .probe()
        .await
    });
    let (mut stream, _) = unhealthy.accept().await.unwrap();
    read_http_request(&mut stream).await;
    stream
        .write_all(
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(unhealthy_task.await.unwrap(), ProbeOutcome::Unreachable);
}

#[tokio::test]
async fn probes_report_connection_refusal_and_http_transport_failure() {
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_address = unused.local_addr().unwrap();
    drop(unused);

    let tcp = ProbeTarget::Tcp {
        address: closed_address,
        timeout: PROBE_TIMEOUT,
    }
    .probe()
    .await;
    assert_eq!(tcp, ProbeOutcome::Unreachable);

    let http = timeout(
        PROBE_TIMEOUT,
        ProbeTarget::Http {
            address: closed_address,
            path: "/healthz".to_string(),
            expected_status: 200,
            timeout: PROBE_TIMEOUT,
        }
        .probe(),
    )
    .await
    .unwrap();
    assert_eq!(http, ProbeOutcome::Unreachable);
}

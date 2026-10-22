use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use meshlet_publish::{
    http::{bind_http, run_http_router},
    AuthorizationPolicy, HttpRoute, HttpRouteSet, RouteMode,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(1);

fn policy() -> AuthorizationPolicy {
    AuthorizationPolicy {
        allowed_source_cidrs: vec![],
        allowed_bearer_tokens: vec!["route-token".into()],
    }
}

fn routes(backend: SocketAddr) -> HttpRouteSet {
    HttpRouteSet::new(vec![HttpRoute {
        id: "api".into(),
        network_id: "net-1".into(),
        hostname: "api.mesh.internal".into(),
        path_prefix: "/".into(),
        backend_address: backend,
        policy: policy(),
        tls_termination: true,
    }])
    .unwrap()
}

async fn read_request_and_respond(mut backend: TcpStream) {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 256];
    loop {
        let size = backend.read(&mut chunk).await.unwrap();
        assert!(size > 0, "router closed before sending a complete request");
        request.extend_from_slice(&chunk[..size]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8(request).unwrap();
    assert!(request.starts_with("POST /orders?source=test HTTP/1.1\r\n"));
    assert!(request.contains("host: api.mesh.internal\r\n"));
    assert!(request.contains("x-request-id: request-1\r\n"));
    assert!(!request.contains("x-backend:"));
    backend
        .write_all(b"HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: 21\r\nconnection: close\r\n\r\n{\"status\":\"created\"}")
        .await
        .unwrap();
    backend.shutdown().await.unwrap();
}

#[tokio::test]
async fn http_router_forwards_request_and_returns_exact_response() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let routes = routes(backend_address);
    let (listener, published) = bind_http("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let route_address = listener.local_addr().unwrap();
    let router = tokio::spawn(async move {
        loop {
            let Ok((stream, remote)) = listener.accept().await else {
                break;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                run_http_router(
                    stream,
                    &routes,
                    RouteMode::PlainHttp,
                    remote,
                    |address| async move { TcpStream::connect(address).await },
                )
                .await
                .unwrap();
            });
        }
    });

    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(route_address))
        .await
        .unwrap()
        .unwrap();
    client
        .write_all(
            concat!(
                "POST /orders?source=test HTTP/1.1\r\n",
                "host: api.mesh.internal\r\n",
                "authorization: Bearer route-token\r\n",
                "x-request-id: request-1\r\n",
                "content-length: 0\r\n",
                "connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    client.flush().await.unwrap();

    let (backend_stream, _) = timeout(TEST_TIMEOUT, backend.accept())
        .await
        .unwrap()
        .unwrap();
    read_request_and_respond(backend_stream).await;

    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        String::from_utf8(response).unwrap(),
        "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: 21\r\nconnection: close\r\n\r\n{\"status\":\"created\"}".to_string()
    );
    assert_eq!(published, route_address);
    assert_eq!(backend.local_addr().unwrap(), backend_address);
    router.abort();
}

#[tokio::test]
async fn http_router_enforces_bearer_token_before_connecting_backend() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let routes = routes(backend_address);
    let (listener, _) = bind_http("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let route_address = listener.local_addr().unwrap();
    let router = tokio::spawn(async move {
        while let Ok((stream, remote)) = listener.accept().await {
            let routes = routes.clone();
            tokio::spawn(async move {
                run_http_router(
                    stream,
                    &routes,
                    RouteMode::PlainHttp,
                    remote,
                    |address| async move { TcpStream::connect(address).await },
                )
                .await
                .unwrap();
            });
        }
    });

    let mut rejected = TcpStream::connect(route_address).await.unwrap();
    rejected
        .write_all(
            concat!(
                "GET /orders HTTP/1.1\r\n",
                "host: api.mesh.internal\r\n",
                "authorization: Bearer wrong-token\r\n",
                "connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(TEST_TIMEOUT, rejected.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
    assert!(timeout(Duration::from_millis(50), backend.accept())
        .await
        .is_err());

    let mut allowed = TcpStream::connect(route_address).await.unwrap();
    allowed
        .write_all(
            concat!(
                "GET /orders HTTP/1.1\r\n",
                "host: api.mesh.internal\r\n",
                "authorization: Bearer route-token\r\n",
                "connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (mut backend_stream, _) = timeout(TEST_TIMEOUT, backend.accept())
        .await
        .unwrap()
        .unwrap();
    let mut forwarded = Vec::new();
    timeout(TEST_TIMEOUT, backend_stream.read_to_end(&mut forwarded))
        .await
        .unwrap()
        .unwrap();
    let forwarded = String::from_utf8(forwarded).unwrap();
    assert!(forwarded.starts_with("GET /orders HTTP/1.1\r\n"));
    assert!(forwarded.contains("authorization: Bearer route-token\r\n"));
    router.abort();
}

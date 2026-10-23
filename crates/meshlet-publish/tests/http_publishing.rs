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

/// 真实 ClientHello 帧：record(5) + handshake(4) + hello body（含 server_name 扩展）。
fn client_hello(hostname: &str) -> Vec<u8> {
    let mut names = vec![0_u8]; // host_name
    names.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
    names.extend_from_slice(hostname.as_bytes());
    let mut list = Vec::new();
    list.extend_from_slice(&(names.len() as u16).to_be_bytes());
    list.extend_from_slice(&names);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0_u16.to_be_bytes());
    extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&list);
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x55; 32]);
    body.push(0);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
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

fn tls_routes(backend: SocketAddr) -> HttpRouteSet {
    HttpRouteSet::new(vec![HttpRoute {
        id: "tls".into(),
        network_id: "net-1".into(),
        hostname: "api.mesh.internal".into(),
        path_prefix: "/".into(),
        backend_address: backend,
        policy: AuthorizationPolicy {
            allowed_source_cidrs: vec!["127.0.0.0/8".parse().unwrap()],
            allowed_bearer_tokens: vec![],
        },
        tls_termination: true,
    }])
    .unwrap()
}

async fn router_task(listener: TcpListener, routes: HttpRouteSet, mode: RouteMode) {
    while let Ok((stream, remote)) = listener.accept().await {
        let routes = routes.clone();
        tokio::spawn(async move {
            // 被拒绝的握手会返回 Err，这是预期行为。
            let _ = run_http_router(stream, &routes, mode, remote, |address| async move {
                TcpStream::connect(address).await
            })
            .await;
        });
    }
}

#[tokio::test]
async fn tls_pass_through_hands_the_client_hello_to_the_backend_untouched() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let (listener, _) = bind_http("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let route_address = listener.local_addr().unwrap();
    let router = tokio::spawn(router_task(
        listener,
        tls_routes(backend_address),
        RouteMode::TlsPassThrough,
    ));
    let hello = client_hello("api.mesh.internal");

    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(route_address))
        .await
        .unwrap()
        .unwrap();
    client.write_all(&hello).await.unwrap();
    client.flush().await.unwrap();

    let (mut backend_stream, _) = timeout(TEST_TIMEOUT, backend.accept())
        .await
        .unwrap()
        .unwrap();
    let mut forwarded = vec![0_u8; hello.len()];
    timeout(TEST_TIMEOUT, backend_stream.read_exact(&mut forwarded))
        .await
        .unwrap()
        .unwrap();
    // 直通模式：后端拿到客户端原始字节，代理既不解密也不注入头。
    assert!(forwarded.starts_with(&[0x16, 0x03, 0x01]));
    assert_eq!(forwarded, hello);
    backend_stream
        .write_all(b"\x17\x03\x03\x00\x0aHello!back")
        .await
        .unwrap();
    let mut response = vec![0_u8; 15];
    timeout(TEST_TIMEOUT, client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"\x17\x03\x03\x00\x0aHello!back");
    client.shutdown().await.unwrap();
    router.abort();
}

#[tokio::test]
async fn tls_pass_through_rejects_plain_http_and_leaves_the_backend_alone() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let (listener, _) = bind_http("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let route_address = listener.local_addr().unwrap();
    let router = tokio::spawn(router_task(
        listener,
        tls_routes(backend_address),
        RouteMode::TlsPassThrough,
    ));

    let mut client = TcpStream::connect(route_address).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: api.mesh.internal\r\n\r\n")
        .await
        .unwrap();
    client.flush().await.unwrap();
    let mut response = Vec::new();
    // 握手被拒：连接立即断开（EOF 或 RST），不返回任何 HTTP 响应。
    let _ = timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .unwrap();
    assert!(
        response.is_empty(),
        "a rejected handshake must not get an HTTP response: {response:?}"
    );
    assert!(
        timeout(Duration::from_millis(50), backend.accept())
            .await
            .is_err(),
        "the backend must not be contacted"
    );
    router.abort();
}

#[tokio::test]
async fn tls_pass_through_rejects_an_unknown_sni_and_leaves_the_backend_alone() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let (listener, _) = bind_http("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let route_address = listener.local_addr().unwrap();
    let router = tokio::spawn(router_task(
        listener,
        tls_routes(backend_address),
        RouteMode::TlsPassThrough,
    ));

    let mut client = TcpStream::connect(route_address).await.unwrap();
    client
        .write_all(&client_hello("unknown.mesh.internal"))
        .await
        .unwrap();
    client.flush().await.unwrap();
    let mut response = Vec::new();
    let _ = timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
        .await
        .unwrap();
    assert!(response.is_empty());
    assert!(
        timeout(Duration::from_millis(50), backend.accept())
            .await
            .is_err(),
        "an unknown SNI must not reach the backend"
    );
    router.abort();
}

/// 真机验收暴露的可用性形态：一个畸形握手在连接任务里 panic 后，整台发布平面
/// 静默（accept 停止接收、探针停止上报）。解析越界已在嗅探器内修掉，这里断言
/// 第二道防线——某个连接任务 panic 时，accept 循环仍必须继续接收新连接。
#[test]
fn a_panicking_connection_does_not_wedge_the_router() {
    // 与 agent 完全相同的运行时形状：单 worker 线程，外部同步线程 block_on 驱动。
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("meshlet-publish")
        .enable_all()
        .build()
        .unwrap();
    let worker =
        std::thread::spawn(move || runtime.block_on(router_survives_a_panicking_connection()));
    // 断言失败会 panic 出 block_on，join() 把它带回断言现场。
    worker
        .join()
        .expect("the router must keep serving after a connection panic");
}

async fn router_survives_a_panicking_connection() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    drop(backend);
    let (listener, local) = bind_http(backend_address).await.unwrap();
    let routes = routes(backend_address);
    let connects = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let router_connects = connects.clone();

    tokio::spawn(async move {
        let connects = router_connects.clone();
        while let Ok((stream, remote)) = listener.accept().await {
            let routes = routes.clone();
            let connects = connects.clone();
            tokio::spawn(async move {
                let _ = run_http_router(stream, &routes, RouteMode::PlainHttp, remote, |address| {
                    if connects.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        panic!("injected connection failure");
                    }
                    TcpStream::connect(address)
                })
                .await;
            });
        }
    });

    // 第一条连接命中路由并在 connect 处 panic：任务被 tokio 兜住，流被关闭。
    {
        let mut first = TcpStream::connect(local).await.unwrap();
        first
            .write_all(
                b"GET /orders HTTP/1.1\r\nhost: api.mesh.internal\r\nauthorization: Bearer route-token\r\n\r\n",
            )
            .await
            .unwrap();
        let mut drained = Vec::new();
        let _ = timeout(TEST_TIMEOUT, first.read_to_end(&mut drained))
            .await
            .map(|_| ());
        assert!(
            drained.is_empty(),
            "a panicking task must send no partial response"
        );
        assert_eq!(
            connects.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the first connection must have panicked at the backend connect"
        );
    }

    // 第二条连接走 404 路径（不触后端），必须仍然收到响应。
    let mut second = TcpStream::connect(local).await.unwrap();
    second
        .write_all(b"GET / HTTP/1.1\r\nhost: nobody.mesh.internal\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut chunk = [0_u8; 128];
    timeout(Duration::from_secs(2), async {
        while second.read(&mut chunk).await.unwrap() > 0 {
            response.extend_from_slice(&chunk);
            if response.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await
    .expect("the accept loop must keep serving new connections");
    assert!(
        response.starts_with(b"HTTP/1.1 404 Not Found"),
        "the second connection must still be served, got {response:?}"
    );
}

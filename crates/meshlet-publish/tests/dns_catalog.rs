use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use meshlet_publish::dns::{DnsCatalog, DnsRecord};

const TEST_TIMEOUT: Duration = Duration::from_secs(1);

fn encoded_name(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes
}

#[tokio::test]
async fn udp_catalog_answers_internal_a_question_with_address_bytes() {
    let catalog = DnsCatalog::new("net-1", "mesh.internal").unwrap();
    catalog
        .insert(DnsRecord {
            service_id: "api".into(),
            name: "api.mesh.internal".into(),
            address: Ipv4Addr::new(100, 64, 12, 7),
            ttl: 30,
            priority: 0,
        })
        .unwrap();

    let socket = catalog
        .serve_udp("127.0.0.1:0".parse().unwrap(), None)
        .await
        .unwrap();
    let address: SocketAddr = socket.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut query = Vec::new();
    query.extend_from_slice(&0x4d21u16.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend(encoded_name("api.mesh.internal"));
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());

    client.send_to(&query, address).await.unwrap();
    let mut response = vec![0_u8; 1024];
    let size = timeout(TEST_TIMEOUT, client.recv(&mut response))
        .await
        .unwrap()
        .unwrap();
    response.truncate(size);

    assert_eq!(&response[0..2], &0x4d21u16.to_be_bytes());
    assert_eq!(&response[2..4], &0x8180u16.to_be_bytes());
    assert_eq!(&response[4..6], &1u16.to_be_bytes());
    assert_eq!(&response[6..8], &1u16.to_be_bytes());
    assert!(response.windows(4).any(|window| window == [100, 64, 12, 7]));
    let name = encoded_name("api.mesh.internal");
    let question_offset = 12;
    assert!(response[question_offset..].starts_with(&name));
    let answer_start = question_offset + name.len() + 4;
    assert_eq!(&response[answer_start..answer_start + 2], &[0xc0, 0x0c]);
    assert_eq!(
        &response[answer_start + 2..answer_start + 4],
        &1u16.to_be_bytes()
    );
    assert_eq!(
        &response[answer_start + 4..answer_start + 6],
        &1u16.to_be_bytes()
    );
    assert_eq!(
        &response[answer_start + 6..answer_start + 10],
        &30u32.to_be_bytes()
    );
    assert_eq!(
        &response[answer_start + 10..answer_start + 12],
        &4u16.to_be_bytes()
    );
    assert_eq!(
        &response[answer_start + 12..answer_start + 16],
        &[100, 64, 12, 7]
    );

    catalog.remove("api");
    client.send_to(&query, address).await.unwrap();
    let receive = timeout(TEST_TIMEOUT, client.recv(&mut response)).await;
    assert!(
        receive.is_err(),
        "unknown internal names must not leak upstream"
    );
}

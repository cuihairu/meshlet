use crate::PublishError;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::net::UdpSocket;

const MAX_QUESTION_LABELS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsClass {
    Internet,
    Chaos,
    None,
}

impl DnsClass {
    fn parse(code: u16) -> Option<Self> {
        match code {
            0 => Some(DnsClass::None),
            1 => Some(DnsClass::Internet),
            3 => Some(DnsClass::Chaos),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsQuestionType {
    A,
    CNAME,
}

impl DnsQuestionType {
    const fn code(self) -> u16 {
        match self {
            DnsQuestionType::A => 1,
            DnsQuestionType::CNAME => 5,
        }
    }

    fn parse(code: u16) -> Option<Self> {
        match code {
            1 => Some(DnsQuestionType::A),
            5 => Some(DnsQuestionType::CNAME),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DnsRecord {
    pub service_id: String,
    pub name: String,
    pub address: Ipv4Addr,
    pub ttl: u32,
    pub priority: u16,
}

#[derive(Clone)]
pub struct DnsCatalog {
    pub network_id: String,
    pub internal_suffix: String,
    records: Arc<Mutex<Vec<DnsRecord>>>,
}

impl serde::Serialize for DnsCatalog {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let records = self.records.lock().expect("DNS catalog mutex");
        let mut state = serializer.serialize_struct("DnsCatalog", 3)?;
        state.serialize_field("network_id", &self.network_id)?;
        state.serialize_field("internal_suffix", &self.internal_suffix)?;
        state.serialize_field("records", &*records)?;
        state.end()
    }
}

impl DnsCatalog {
    pub fn new(
        network_id: impl Into<String>,
        internal_suffix: impl Into<String>,
    ) -> Result<Self, PublishError> {
        let suffix = internal_suffix.into();
        if suffix.is_empty()
            || suffix.starts_with('.')
            || suffix.ends_with('.')
            || suffix.contains("..")
        {
            return Err(invalid("internal DNS suffix must be a relative suffix"));
        }
        Ok(Self {
            network_id: network_id.into(),
            internal_suffix: suffix.to_ascii_lowercase(),
            records: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.records.lock().expect("DNS catalog mutex").is_empty()
    }

    pub fn insert(&self, mut record: DnsRecord) -> Result<(), PublishError> {
        if record.service_id.is_empty() || record.name.trim().is_empty() || record.ttl == 0 {
            return Err(invalid(
                "DNS record service/name/ttl must be non-empty and non-zero",
            ));
        }
        record.name = record
            .name
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !record.name.ends_with(&self.internal_suffix) {
            return Err(invalid("DNS record must be under internal suffix"));
        }
        let mut records = self.records.lock().expect("DNS catalog mutex");
        if records.iter().any(|existing| {
            existing.service_id == record.service_id && existing.name == record.name
        }) {
            return Err(invalid("duplicate DNS record for service/name"));
        }
        records.push(record);
        Ok(())
    }

    pub fn remove(&self, service_id: &str) -> usize {
        let mut records = self.records.lock().expect("DNS catalog mutex");
        let before = records.len();
        records.retain(|record| record.service_id != service_id);
        before - records.len()
    }

    pub fn resolve(&self, name: &str) -> Vec<DnsRecord> {
        let query = fqdn(name, &self.internal_suffix);
        self.records
            .lock()
            .expect("DNS catalog mutex")
            .iter()
            .filter(|record| record.name == query)
            .cloned()
            .collect()
    }

    pub async fn serve_udp(
        &self,
        address: SocketAddr,
        upstream: Option<Arc<dyn UpstreamDns + Send + Sync>>,
    ) -> Result<Arc<UdpSocket>, PublishError> {
        let socket = UdpSocket::bind(address).await?;
        let catalog = self.clone();
        let shared = Arc::new(socket);
        let runtime = shared.clone();
        tokio::spawn(async move { serve_udp(catalog, runtime, upstream).await });
        Ok(shared)
    }
}

pub async fn serve_udp(
    catalog: DnsCatalog,
    socket: Arc<UdpSocket>,
    upstream: Option<Arc<dyn UpstreamDns + Send + Sync>>,
) -> Result<(), PublishError> {
    let mut buffer = vec![0_u8; 4096];
    loop {
        let (size, source) = socket.recv_from(&mut buffer).await?;
        let question = match parse_question(&buffer[..size]) {
            Ok(question) => question,
            Err(_) => continue,
        };
        if question.question_type != DnsQuestionType::A || question.class != DnsClass::Internet {
            continue;
        }
        let records = catalog.resolve(&question.name);
        let response = if records.is_empty() {
            if let Some(upstream) = &upstream {
                upstream.resolve(question, source).await.unwrap_or_default()
            } else {
                None
            }
        } else {
            Some(build_response(&question, &records))
        };
        if let Some(response) = response {
            socket.send_to(&response, source).await?;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DnsQuestion {
    pub transaction_id: u16,
    pub name: String,
    pub question_type: DnsQuestionType,
    pub class: DnsClass,
    pub recursion_desired: bool,
}

pub trait UpstreamDns {
    fn resolve(
        &self,
        question: DnsQuestion,
        source: SocketAddr,
    ) -> BoxFuture<'static, Result<Option<Vec<u8>>, PublishError>>;
}

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub fn fqdn(name: &str, internal_suffix: &str) -> String {
    let suffix = internal_suffix.trim_start_matches('.');
    let mut name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if !name.ends_with(suffix) {
        name = format!("{name}.{suffix}");
    }
    name
}

fn parse_question(bytes: &[u8]) -> Result<DnsQuestion, PublishError> {
    let mut cursor = Cursor::new(bytes);
    let transaction_id = cursor.read_u16()?;
    let flags = cursor.read_u16()?;
    let question_count = cursor.read_u16()?;
    if question_count != 1 {
        return Err(invalid("DNS question count must be one"));
    }
    let _answer_count = cursor.read_u16()?;
    let _authority_count = cursor.read_u16()?;
    let _additional_count = cursor.read_u16()?;
    let name = read_name(&mut cursor, 0)?;
    let question_type = cursor.read_u16()?;
    let class = cursor.read_u16()?;
    Ok(DnsQuestion {
        transaction_id,
        name,
        question_type: DnsQuestionType::parse(question_type)
            .ok_or_else(|| invalid("unsupported DNS question type"))?,
        class: DnsClass::parse(class).ok_or_else(|| invalid("unsupported DNS class"))?,
        recursion_desired: flags & 0x0100 != 0,
    })
}

fn build_response(question: &DnsQuestion, records: &[DnsRecord]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&question.transaction_id.to_be_bytes());
    packet.extend_from_slice(&0x8180u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&(records.len() as u16).to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&mut packet, &question.name, false);
    packet.extend_from_slice(&question.question_type.code().to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    for record in records {
        packet.extend_from_slice(&0xc00cu16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&record.ttl.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&record.address.octets());
    }
    packet
}

fn read_name(cursor: &mut Cursor<'_>, start: usize) -> Result<String, PublishError> {
    let mut name = String::new();
    let mut seen = false;
    let mut guard = 0;
    loop {
        let length = cursor.read_u8()?;
        if length & 0xc0 == 0xc0 {
            let offset = ((length & 0x3f) as usize) << 8 | cursor.read_u8()? as usize;
            let tail_cursor = &mut Cursor::new(&cursor.bytes[start..]);
            let _ = offset;
            let tail = read_name(tail_cursor, 0)?;
            name.push_str(&tail);
            return Ok(name);
        }
        if length == 0 {
            if name.is_empty() {
                return Ok("*".to_string());
            }
            break;
        }
        guard += 1;
        if guard > MAX_QUESTION_LABELS {
            return Err(invalid("DNS name is too long"));
        }
        let label = cursor.read_exact(length as usize)?;
        let label = std::str::from_utf8(label).map_err(|_| invalid("DNS name is not UTF-8"))?;
        if !label.is_empty() {
            if seen {
                name.push('.');
            }
            name.push_str(label);
            seen = true;
        }
    }
    Ok(name)
}

fn encode_name(packet: &mut Vec<u8>, name: &str, add_dot: bool) {
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    let _ = add_dot;
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, PublishError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| invalid("truncated DNS packet"))?;
        self.position += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, PublishError> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_exact(&mut self, size: usize) -> Result<&'a [u8], PublishError> {
        let end = self
            .position
            .checked_add(size)
            .ok_or_else(|| invalid("DNS packet too large"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid("truncated DNS packet"))?;
        self.position = end;
        Ok(bytes)
    }
}

fn invalid(message: impl Into<String>) -> PublishError {
    PublishError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

use super::domain_name::{DomainName, LabelEncodable};
use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum RecordData {
    IpAddress(Ipv4Addr),
}

#[derive(Debug)]
pub struct DnsAnswer {
    pub domain_name: DomainName,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: RecordData,
}

impl Default for DnsAnswer {
    fn default() -> Self {
        Self {
            domain_name: DomainName::Str("".to_string()),
            record_type: 1,
            class: 1,
            ttl: 60,
            rdlength: 4,
            rdata: RecordData::IpAddress(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}

impl From<DnsAnswer> for Vec<u8> {
    fn from(answer: DnsAnswer) -> Self {
        let mut buf: Vec<u8> = Vec::new();

        buf.extend(&answer.domain_name.to_encoded_label());
        buf.extend_from_slice(&answer.record_type.to_be_bytes());
        buf.extend_from_slice(&answer.class.to_be_bytes());
        buf.extend_from_slice(&answer.ttl.to_be_bytes());
        buf.extend_from_slice(&answer.rdlength.to_be_bytes());

        let encoded_ip_addr = match answer.rdata {
            RecordData::IpAddress(ip_addr) => ip_addr.octets(),
        };
        buf.extend(&encoded_ip_addr);

        buf
    }
}

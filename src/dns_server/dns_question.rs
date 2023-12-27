use super::domain_name::{DomainName, LabelEncodable};

#[derive(Debug)]
pub struct DnsQuestion {
    pub domain_name: DomainName,
    pub query_type: u16,
    pub query_class: u16,
}

impl Default for DnsQuestion {
    fn default() -> Self {
        Self {
            domain_name: "".to_string(),
            query_type: 1,
            query_class: 1,
        }
    }
}

impl From<DnsQuestion> for Vec<u8> {
    fn from(question: DnsQuestion) -> Self {
        let mut buf = Vec::new();

        buf.extend(&question.domain_name.to_encoded_label());
        buf.extend_from_slice(&question.query_type.to_be_bytes());
        buf.extend_from_slice(&question.query_class.to_be_bytes());

        buf
    }
}

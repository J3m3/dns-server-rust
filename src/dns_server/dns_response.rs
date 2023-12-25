#[derive(Debug)]
pub struct DnsResponse {
    pub dns_header: DnsHeader,
    pub dns_questions: Vec<DnsQuestion>,
    pub dns_answer: DnsAnswer,
}

impl From<DnsResponse> for Vec<u8> {
    fn from(response: DnsResponse) -> Self {
        [
            Vec::from(response.dns_header),
            response
                .dns_questions
                .into_iter()
                .fold(Vec::<u8>::new(), |mut acc, dns_query| {
                    acc.extend(Vec::from(dns_query));
                    acc
                }),
            Vec::from(response.dns_answer),
        ]
        .concat()
    }
}

mod dns_answer;
mod dns_header;
mod dns_question;

pub use dns_answer::{DnsAnswer, RecordData};
pub use dns_header::DnsHeader;
pub use dns_question::DnsQuestion;

type DomainName = String;
trait LabelEncodable {
    fn to_encoded_label(&self) -> Vec<u8>;
}

impl LabelEncodable for DomainName {
    fn to_encoded_label(&self) -> Vec<u8> {
        format!("{}.", self)
            .split('.')
            .fold(Vec::<u8>::new(), |mut acc, byte_str| {
                let len_byte = (byte_str.len() as u8).to_be_bytes().into_iter();
                let content_bytes = byte_str.bytes();
                acc.extend(len_byte.chain(content_bytes));
                acc
            })
    }
}

use super::dns_answer::DnsAnswer;
use super::dns_header::DnsHeader;
use super::dns_question::{self, DnsQuestion};
use super::domain_name;

#[derive(Debug)]
pub struct DnsMessage {
    pub dns_header: DnsHeader,
    pub dns_questions: Vec<DnsQuestion>,
    pub dns_answer: DnsAnswer,
}

impl DnsMessage {
    fn parse_header(header_bytes: &[u8]) -> Option<DnsHeader> {
        println!("Header received: {:?}", header_bytes);
        Some(DnsHeader {
            id: DnsMessage::to_u16(&header_bytes[0..2]),
            qr: DnsMessage::mask_bits(header_bytes[2], 0, 1)?,
            opcode: DnsMessage::mask_bits(header_bytes[2], 1, 5)?,
            aa: DnsMessage::mask_bits(header_bytes[2], 5, 6)?,
            tc: DnsMessage::mask_bits(header_bytes[2], 6, 7)?,
            rd: DnsMessage::mask_bits(header_bytes[2], 7, 8)?,
            ra: DnsMessage::mask_bits(header_bytes[3], 0, 1)?,
            z: DnsMessage::mask_bits(header_bytes[3], 1, 4)?,
            rcode: DnsMessage::mask_bits(header_bytes[3], 4, 8)?,
            qdcount: DnsMessage::to_u16(&header_bytes[4..6]),
            ancount: DnsMessage::to_u16(&header_bytes[6..8]),
            nscount: DnsMessage::to_u16(&header_bytes[8..10]),
            arcount: DnsMessage::to_u16(&header_bytes[10..12]),
        })
    }

    fn parse_question(question_bytes: &[u8]) -> Option<(Vec<DnsQuestion>, DnsAnswer)> {
        use super::dns_answer::RecordData;
        use domain_name::DomainName;
        use std::net::Ipv4Addr;

        let domain_name: Vec<u8> = question_bytes
            .iter()
            .map(|&b| b)
            .take_while(|&b| b == 0)
            .collect();

        let dns_questions = vec![DnsQuestion {
            domain_name: DomainName::Vec(domain_name.clone()),
            query_type: 1,
            query_class: 1,
        }];

        let dns_answer = DnsAnswer {
            domain_name: DomainName::Vec(domain_name),
            record_type: 1,
            class: 1,
            ttl: 60,
            rdlength: 4,
            rdata: RecordData::IpAddress(Ipv4Addr::new(8, 8, 8, 8)),
        };

        Some((dns_questions, dns_answer))
    }

    fn to_u16(bytes: &[u8]) -> u16 {
        ((bytes[0] as u16) << 8) + bytes[1] as u16
    }

    fn mask_bits(byte: u8, start: u32, end: u32) -> Option<u8> {
        if start >= end {
            None
        } else {
            let mask_max = 7;
            let mask: u8 = (start..end).map(|i| 2u8.pow(mask_max - i)).sum();
            Some((byte & mask) >> mask_max - end + 1)
        }
    }
}

impl From<DnsMessage> for Vec<u8> {
    fn from(message: DnsMessage) -> Self {
        [
            Vec::from(message.dns_header),
            message
                .dns_questions
                .into_iter()
                .fold(Vec::<u8>::new(), |mut acc, dns_question| {
                    acc.extend(Vec::from(dns_question));
                    acc
                }),
            Vec::from(message.dns_answer),
        ]
        .concat()
    }
}

impl From<Vec<u8>> for DnsMessage {
    fn from(byte_vec: Vec<u8>) -> Self {
        let dns_header = DnsMessage::parse_header(&byte_vec[0..12]).unwrap_or_default();
        let (dns_questions, dns_answer) = DnsMessage::parse_question(&byte_vec[12..])
            .expect("Error while parsing request question");

        Self {
            dns_header,
            dns_questions,
            dns_answer,
        }
    }
}

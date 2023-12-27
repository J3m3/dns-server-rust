use super::dns_answer::DnsAnswer;
use super::dns_header::DnsHeader;
use super::dns_question::DnsQuestion;
use super::domain_name;

#[derive(Debug, Default)]
pub struct DnsMessageForm {
    pub dns_header: DnsHeader,
    pub dns_questions: Vec<DnsQuestion>,
    pub dns_answer: Option<DnsAnswer>,
}

#[derive(Debug)]
pub enum DnsMessage {
    DnsRequest(DnsMessageForm),
    DnsResponse(DnsMessageForm),
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

    fn parse_question(question_bytes: &[u8]) -> Option<Vec<DnsQuestion>> {
        use domain_name::DomainName;

        let domain_name: Vec<u8> = question_bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b)
            .collect();

        let dns_questions = vec![DnsQuestion {
            domain_name: DomainName::Vec(domain_name),
            query_type: 1,
            query_class: 1,
        }];

        Some(dns_questions)
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

impl TryFrom<DnsMessage> for Vec<u8> {
    type Error = &'static str;

    fn try_from(message: DnsMessage) -> Result<Self, Self::Error> {
        match message {
            DnsMessage::DnsRequest(_) => {
                Err("Only DnsMessage::DnsResponse can be converted to Vec<u8>")
            }
            DnsMessage::DnsResponse(message) => {
                let dns_header = Vec::from(message.dns_header);
                let dns_questions = message.dns_questions.into_iter().fold(
                    Vec::<u8>::new(),
                    |mut acc, dns_question| {
                        acc.extend(Vec::from(dns_question));
                        acc
                    },
                );
                let dns_answer = Vec::from(message.dns_answer.expect("No answer in response"));

                Ok([dns_header, dns_questions, dns_answer].concat())
            }
        }
    }
}

impl From<Vec<u8>> for DnsMessage {
    fn from(byte_vec: Vec<u8>) -> Self {
        let dns_header = DnsMessage::parse_header(&byte_vec[0..12]).unwrap_or_default();
        let dns_questions = DnsMessage::parse_question(&byte_vec[12..])
            .expect("Error while parsing request question");

        Self::DnsRequest(DnsMessageForm {
            dns_header,
            dns_questions,
            dns_answer: None,
        })
    }
}

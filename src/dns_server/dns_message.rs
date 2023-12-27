use super::dns_answer::DnsAnswer;
use super::dns_header::DnsHeader;
use super::dns_question::DnsQuestion;

#[derive(Debug)]
pub struct DnsMessage {
    pub dns_header: DnsHeader,
    pub dns_questions: Vec<DnsQuestion>,
    pub dns_answer: DnsAnswer,
}

impl DnsMessage {
    fn parse_header(header_bytes: &[u8]) -> Option<DnsHeader> {
        println!("Header received: {:?}", header_bytes);
        let id = DnsMessage::to_u16(&header_bytes[0..2]);
        let qr = DnsMessage::mask_bits(header_bytes[2], 0, 1)?;
        let opcode = DnsMessage::mask_bits(header_bytes[2], 1, 5)?;
        let aa = DnsMessage::mask_bits(header_bytes[2], 5, 6)?;
        let tc = DnsMessage::mask_bits(header_bytes[2], 6, 7)?;
        let rd = DnsMessage::mask_bits(header_bytes[2], 7, 8)?;
        let ra = DnsMessage::mask_bits(header_bytes[3], 0, 1)?;
        let z = DnsMessage::mask_bits(header_bytes[3], 1, 4)?;
        let rcode = DnsMessage::mask_bits(header_bytes[3], 4, 8)?;
        let qdcount = DnsMessage::to_u16(&header_bytes[4..6]);
        let ancount = DnsMessage::to_u16(&header_bytes[6..8]);
        let nscount = DnsMessage::to_u16(&header_bytes[8..10]);
        let arcount = DnsMessage::to_u16(&header_bytes[10..12]);
        Some(DnsHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    // fn parse_question(question_bytes: &[u8]) -> Option<DnsQuestion> {
    //     todo!()
    // }

    // fn parse_answer(answer_bytes: &[u8]) -> Option<DnsAnswer> {
    //     todo!()
    // }

    fn to_u16(bytes: &[u8]) -> u16 {
        bytes[0] as u16 + ((bytes[1] as u16) << 8)
    }

    fn mask_bits(byte: u8, start: u32, end: u32) -> Option<u8> {
        if start >= end {
            None
        } else {
            let mask: u8 = (start..end).map(|i| 2u8.pow(7 - i)).sum();
            Some(byte & mask)
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
        let dns_header = DnsMessage::parse_header(&byte_vec[0..12]).unwrap();
        let dns_questions = vec![DnsQuestion::default()];
        let dns_answer = DnsAnswer::default();

        Self {
            dns_header,
            dns_questions,
            dns_answer,
        }
    }
}

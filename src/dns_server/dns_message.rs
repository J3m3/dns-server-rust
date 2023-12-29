use super::dns_answer::DnsAnswer;
use super::dns_header::DnsHeader;
use super::dns_question::DnsQuestion;
use std::iter::Peekable;

#[derive(Debug, Default)]
pub struct DnsMessageForm {
    pub dns_header: DnsHeader,
    pub dns_questions: Vec<DnsQuestion>,
    pub dns_answers: Option<Vec<DnsAnswer>>,
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
            id: Self::to_u16(&header_bytes[0..2]),
            qr: Self::mask_bits(header_bytes[2], 0, 1)?,
            opcode: Self::mask_bits(header_bytes[2], 1, 5)?,
            aa: Self::mask_bits(header_bytes[2], 5, 6)?,
            tc: Self::mask_bits(header_bytes[2], 6, 7)?,
            rd: Self::mask_bits(header_bytes[2], 7, 8)?,
            ra: Self::mask_bits(header_bytes[3], 0, 1)?,
            z: Self::mask_bits(header_bytes[3], 1, 4)?,
            rcode: Self::mask_bits(header_bytes[3], 4, 8)?,
            qdcount: Self::to_u16(&header_bytes[4..6]),
            ancount: Self::to_u16(&header_bytes[6..8]),
            nscount: Self::to_u16(&header_bytes[8..10]),
            arcount: Self::to_u16(&header_bytes[10..12]),
        })
    }

    fn parse_question(question_bytes: &[u8]) -> Option<Vec<DnsQuestion>> {
        use super::domain_name::DomainName;

        let mut dns_questions = Vec::<DnsQuestion>::new();

        let mut question_bytes_it = question_bytes.iter().peekable();
        fn consume_field<'a, T: Iterator<Item = &'a u8>>(it: &mut T) -> Option<u16> {
            Some(DnsMessage::to_u16(&[*it.next()?, *it.next()?]))
        }

        while question_bytes_it.len() > 0 {
            let domain_name: Vec<u8> = Self::decode_domain(&mut question_bytes_it, question_bytes)?;

            let query_type = consume_field(&mut question_bytes_it)?;
            let query_class = consume_field(&mut question_bytes_it)?;

            dns_questions.push(DnsQuestion {
                domain_name: DomainName::Vec(domain_name),
                query_type,
                query_class,
            });
        }

        Some(dns_questions)
    }

    fn to_u16(bytes: &[u8]) -> u16 {
        ((bytes[0] as u16) << 8) + bytes[1] as u16
    }

    fn mask_bits(byte: u8, start: u32, end: u32) -> Option<u8> {
        let max_len = 8;
        if start >= end || end > max_len {
            None
        } else {
            let mask_max = 7;
            let mask: u8 = (start..end).map(|i| 2u8.pow(mask_max - i)).sum();
            Some((byte & mask) >> mask_max - end + 1)
        }
    }

    fn decode_domain<'a, I>(
        question_bytes_it: &mut Peekable<I>,
        question_bytes: &[u8],
    ) -> Option<Vec<u8>>
    where
        I: Iterator<Item = &'a u8>,
    {
        let mask = 0b11000000u8;
        let first_byte = **question_bytes_it.peek()?;
        fn mask_first_2bits(first_byte: u8) -> Option<u8> {
            DnsMessage::mask_bits(first_byte, 0, 2)
        }
        fn collect_domain<'a, T: Iterator<Item = &'a u8>>(it: T) -> Vec<u8> {
            it.take_while(|&&b| b != 0).cloned().chain(0..1).collect()
        }

        if mask_first_2bits(first_byte)? == 0 {
            // domain name not compressed
            Some(collect_domain(question_bytes_it.by_ref()))
        } else if mask_first_2bits(first_byte)? == mask {
            // domain name compressed
            let second_byte = *question_bytes_it.next()?;
            let start_idx = Self::to_u16(&[first_byte & !mask, second_byte]) as usize;
            Some(collect_domain(question_bytes.iter().skip(start_idx)))
        } else {
            None
        }
    }

    fn fold_section<T: Into<Vec<u8>>>(section: Vec<T>) -> Vec<u8> {
        section.into_iter().flat_map(|e| e.into()).collect()
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
                let dns_questions = DnsMessage::fold_section(message.dns_questions);
                let dns_answers = match message.dns_answers {
                    Some(dns_answers) => DnsMessage::fold_section(dns_answers),
                    None => {
                        eprintln!("DnsMessage::DnsResponse should contain answer section");
                        Default::default()
                    }
                };
                Ok([dns_header, dns_questions, dns_answers].concat())
            }
        }
    }
}

impl From<Vec<u8>> for DnsMessage {
    fn from(byte_vec: Vec<u8>) -> Self {
        let header_length = 12;
        let dns_header = Self::parse_header(&byte_vec[0..header_length]).unwrap_or_default();
        let dns_questions = Self::parse_question(&byte_vec[header_length..])
            .expect("Error while parsing request question");

        Self::DnsRequest(DnsMessageForm {
            dns_header,
            dns_questions,
            dns_answers: None,
        })
    }
}

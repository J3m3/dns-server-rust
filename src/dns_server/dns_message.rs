use std::net::Ipv4Addr;

use super::dns_answer::DnsAnswer;
use super::dns_header::DnsHeader;
use super::dns_question::DnsQuestion;

#[derive(Debug, Default, Clone)]
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

const HEADER_LENGTH: usize = 12;

impl DnsMessage {
    fn parse_header(bytes: &[u8]) -> Option<DnsHeader> {
        println!("Header received: {:?}", bytes);
        Some(DnsHeader {
            id: Self::to_u16(&bytes[0..2]),
            qr: Self::slice_byte(bytes[2], 0, 1)?,
            opcode: Self::slice_byte(bytes[2], 1, 5)?,
            aa: Self::slice_byte(bytes[2], 5, 6)?,
            tc: Self::slice_byte(bytes[2], 6, 7)?,
            rd: Self::slice_byte(bytes[2], 7, 8)?,
            ra: Self::slice_byte(bytes[3], 0, 1)?,
            z: Self::slice_byte(bytes[3], 1, 4)?,
            rcode: Self::slice_byte(bytes[3], 4, 8)?,
            qdcount: Self::to_u16(&bytes[4..6]),
            ancount: Self::to_u16(&bytes[6..8]),
            nscount: Self::to_u16(&bytes[8..10]),
            arcount: Self::to_u16(&bytes[10..12]),
        })
    }

    fn parse_question(bytes: &[u8], num_of_question: u16) -> Option<(Vec<DnsQuestion>, usize)> {
        use super::domain_name::DomainName;
        println!("Question received: {:?}", bytes);

        let mut dns_questions = Vec::<DnsQuestion>::new();

        let mut subbytes_it = bytes.iter().skip(HEADER_LENGTH);
        let initial_length = subbytes_it.len();
        for _ in 0..num_of_question {
            let domain_name: Vec<u8> = Self::decode_domain(&mut subbytes_it, bytes)?;
            println!("Domain Name in parse_question: {domain_name:?}");

            let query_type = Self::consume_2bytes_fields(&mut subbytes_it)?;
            let query_class = Self::consume_2bytes_fields(&mut subbytes_it)?;

            dns_questions.push(DnsQuestion {
                domain_name: DomainName::Vec(domain_name),
                query_type,
                query_class,
            });
        }

        Some((dns_questions, initial_length - subbytes_it.len()))
    }

    fn parse_answer(
        bytes: &[u8],
        num_of_question: u16,
        consumed_amount: usize,
    ) -> Option<Vec<DnsAnswer>> {
        use super::domain_name::DomainName;
        use super::RecordData;
        println!("Answer received: {:?}", bytes);

        let mut dns_answers = Vec::<DnsAnswer>::new();

        let mut subbytes_it = bytes.iter().skip(HEADER_LENGTH + consumed_amount);
        if subbytes_it.len() <= 0 {
            return None;
        }

        for _ in 0..num_of_question {
            let domain_name: Vec<u8> = Self::decode_domain(&mut subbytes_it, bytes)?;
            println!("Domain Name in parse_question: {domain_name:?}");

            let record_type = Self::consume_2bytes_fields(&mut subbytes_it)?;
            let class = Self::consume_2bytes_fields(&mut subbytes_it)?;
            let ttl = Self::consume_4bytes_fields(&mut subbytes_it)?;
            let rdlength = Self::consume_2bytes_fields(&mut subbytes_it)?;
            let rdata_bits = Self::consume_4bytes_fields(&mut subbytes_it)?;

            dns_answers.push(DnsAnswer {
                domain_name: DomainName::Vec(domain_name),
                record_type,
                class,
                ttl,
                rdlength,
                rdata: RecordData::IpAddress(Ipv4Addr::from(rdata_bits)),
            });
        }

        Some(dns_answers)
    }

    fn to_u16(bytes: &[u8]) -> u16 {
        ((bytes[0] as u16) << 8) + bytes[1] as u16
    }

    fn to_u32(bytes: &[u8]) -> u32 {
        ((bytes[0] as u32) << 24)
            | ((bytes[1] as u32) << 16)
            | ((bytes[2] as u32) << 8)
            | bytes[3] as u32
    }

    fn slice_byte(byte: u8, start: u32, end: u32) -> Option<u8> {
        let max_len = 8;
        if start >= end || end > max_len {
            None
        } else {
            let mask_max = 7;
            let mask: u8 = (start..end).map(|i| 2u8.pow(mask_max - i)).sum();
            Some((byte & mask) >> mask_max - end + 1)
        }
    }

    fn consume_2bytes_fields<'a, T: Iterator<Item = &'a u8>>(it: &mut T) -> Option<u16> {
        Some(DnsMessage::to_u16(&[*it.next()?, *it.next()?]))
    }

    fn consume_4bytes_fields<'a, T: Iterator<Item = &'a u8>>(it: &mut T) -> Option<u32> {
        Some(DnsMessage::to_u32(&[
            *it.next()?,
            *it.next()?,
            *it.next()?,
            *it.next()?,
        ]))
    }

    fn decode_domain<'a, I>(subbytes_it: &mut I, original_bytes: &[u8]) -> Option<Vec<u8>>
    where
        I: Iterator<Item = &'a u8>,
    {
        let mask = 0b11000000u8;
        fn slice_first_2bits(first_byte: u8) -> Option<u8> {
            DnsMessage::slice_byte(first_byte, 0, 2)
        }

        let mut domain_name = Vec::<u8>::new();
        while let Some(&first_byte) = subbytes_it.next() {
            if first_byte == 0 {
                break;
            }
            if slice_first_2bits(first_byte)? == 0 {
                // label not compressed
                let length = first_byte as usize;
                domain_name.push(first_byte);
                domain_name.extend(subbytes_it.by_ref().take(length));
            } else if slice_first_2bits(first_byte)? == (mask >> 6) {
                // label compressed
                let second_byte = *subbytes_it.next()?;
                let offset = Self::to_u16(&[first_byte & !mask, second_byte]) as usize;
                let it = original_bytes.iter().skip(offset);
                domain_name.extend(it.take_while(|&&b| b != 0).cloned());
                break;
            }
        }

        domain_name.push(0);
        Some(domain_name)
    }

    fn fold_section<T: Into<Vec<u8>>>(section: Vec<T>) -> Vec<u8> {
        section.into_iter().flat_map(|e| e.into()).collect()
    }
}

impl From<DnsMessage> for Vec<u8> {
    fn from(message: DnsMessage) -> Self {
        match message {
            DnsMessage::DnsRequest(message) => {
                let dns_header = Vec::from(message.dns_header);
                let dns_questions = DnsMessage::fold_section(message.dns_questions);
                [dns_header, dns_questions].concat()
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
                [dns_header, dns_questions, dns_answers].concat()
            }
        }
    }
}

impl From<Vec<u8>> for DnsMessage {
    fn from(byte_vec: Vec<u8>) -> Self {
        let dns_header = Self::parse_header(&byte_vec).unwrap_or_default();
        let (dns_questions, consumed_amount) = Self::parse_question(&byte_vec, dns_header.qdcount)
            .expect("Error while parsing request question");
        let dns_answers = Self::parse_answer(&byte_vec, dns_header.qdcount, consumed_amount);

        Self::DnsRequest(DnsMessageForm {
            dns_header,
            dns_questions,
            dns_answers,
        })
    }
}

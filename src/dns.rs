type IpAddress = String;
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

#[derive(Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: u8,
    pub opcode: u8,
    pub aa: u8,
    pub tc: u8,
    pub rd: u8,
    pub ra: u8,
    pub z: u8,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl From<DnsHeader> for Vec<u8> {
    fn from(header: DnsHeader) -> Self {
        let mut buf = Vec::new();

        buf.extend_from_slice(&header.id.to_be_bytes());
        let qr_opcode_aa_tc_rd = (header.qr << 7)
            | (header.opcode << 3)
            | (header.aa << 2)
            | (header.tc << 1)
            | header.rd;
        buf.extend_from_slice(&qr_opcode_aa_tc_rd.to_be_bytes());
        let ra_z_rcode = (header.ra << 7) | (header.z << 4) | header.rcode;
        buf.extend_from_slice(&ra_z_rcode.to_be_bytes());
        buf.extend_from_slice(&header.qdcount.to_be_bytes());
        buf.extend_from_slice(&header.ancount.to_be_bytes());
        buf.extend_from_slice(&header.nscount.to_be_bytes());
        buf.extend_from_slice(&header.arcount.to_be_bytes());

        buf
    }
}

#[derive(Debug)]
pub struct DnsQuestion {
    pub domain_name: DomainName,
    pub query_type: u16,
    pub query_class: u16,
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

#[derive(Debug)]
pub struct DnsAnswer {
    pub domain_name: DomainName,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: IpAddress,
}

impl From<DnsAnswer> for Vec<u8> {
    fn from(answer: DnsAnswer) -> Self {
        let mut buf: Vec<u8> = Vec::new();

        buf.extend(&answer.domain_name.to_encoded_label());
        buf.extend_from_slice(&answer.record_type.to_be_bytes());
        buf.extend_from_slice(&answer.class.to_be_bytes());
        buf.extend_from_slice(&answer.ttl.to_be_bytes());
        buf.extend_from_slice(&answer.rdlength.to_be_bytes());
        let encoded_ip_addr =
            answer
                .rdata
                .split('.')
                .fold(Vec::<u8>::new(), |mut acc, byte_str| {
                    acc.extend(byte_str.parse::<u8>().map(|i| i.to_be_bytes()).expect(
                        "expected 8 bit unsigned integer for each splitted ip address number",
                    ));
                    acc
                });
        buf.extend(&encoded_ip_addr);

        buf
    }
}

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

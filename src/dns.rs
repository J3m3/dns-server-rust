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

impl DnsHeader {
    pub fn to_be_bytes_vector(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.id.to_be_bytes());
        let qr_opcode_aa_tc_rd =
            (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;
        buf.extend_from_slice(&qr_opcode_aa_tc_rd.to_be_bytes());
        let ra_z_rcode = (self.ra << 7) | (self.z << 4) | self.rcode;
        buf.extend_from_slice(&ra_z_rcode.to_be_bytes());
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());

        buf
    }
}

pub struct DnsQuestion {
    pub domain_name: String,
    pub query_type: u16,
    pub query_class: u16,
}

impl DnsQuestion {
    pub fn to_be_bytes_vector(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend(self.get_encoded_name());
        buf.extend_from_slice(&self.query_type.to_be_bytes());
        buf.extend_from_slice(&self.query_class.to_be_bytes());

        buf
    }

    fn get_encoded_name(&self) -> Vec<u8> {
        format!("{}.", self.domain_name)
            .split('.')
            .map(|e| {
                let len_byte = (e.len() as u8).to_be_bytes().to_vec();
                let content_bytes = e.as_bytes().to_vec();
                [len_byte, content_bytes].concat()
            })
            .collect::<Vec<Vec<u8>>>()
            .concat()
    }
}

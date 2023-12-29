#[derive(Debug, Clone)]
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

impl Default for DnsHeader {
    fn default() -> Self {
        Self {
            id: 1234,
            qr: 1,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            rcode: 0,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        }
    }
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

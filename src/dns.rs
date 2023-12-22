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
    pub fn into_be_bytes_vector(self) -> Vec<u8> {
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

mod dns_answer;
mod dns_header;
mod dns_message;
mod dns_question;
mod domain_name;

use dns_answer::{DnsAnswer, RecordData};
use dns_header::DnsHeader;
use dns_message::DnsMessage;
use dns_question::DnsQuestion;

use std::{
    io::Result,
    net::{Ipv4Addr, UdpSocket},
};

pub struct DnsServer {
    udp_socket: UdpSocket,
}

impl DnsServer {
    pub fn new(on: &str) -> Result<Self> {
        let udp_socket = UdpSocket::bind(on)?;
        Ok(Self { udp_socket })
    }

    pub fn start(&self, buff_size: usize) {
        let mut buf = vec![0 as u8; buff_size];

        loop {
            match self.udp_socket.recv_from(&mut buf) {
                Ok((size, source)) => {
                    println!("Received {} bytes from {}", size, source);

                    let filled_buf: Vec<u8> = buf[..size].to_vec();
                    let request = DnsMessage::from(filled_buf);

                    let domain_name = "codecrafters.io";
                    let ip_addr = Ipv4Addr::new(8, 8, 8, 8);

                    let dns_questions = vec![DnsQuestion {
                        domain_name: String::from(domain_name),
                        ..Default::default()
                    }];
                    let dns_header = DnsHeader {
                        id: request.dns_header.id,
                        qr: 1,
                        opcode: request.dns_header.opcode,
                        rd: request.dns_header.rd,
                        rcode: if request.dns_header.opcode == 0 { 0 } else { 4 },
                        qdcount: dns_questions.len() as u16,
                        ancount: 1,
                        ..Default::default()
                    };
                    let dns_answer = DnsAnswer {
                        domain_name: String::from(domain_name),
                        ttl: 60,
                        rdlength: 4,
                        rdata: RecordData::IpAddress(ip_addr),
                        ..Default::default()
                    };
                    let dns_response = DnsMessage {
                        dns_header,
                        dns_questions,
                        dns_answer,
                    };

                    let dns_response = Vec::from(dns_response);
                    println!("Response: {:?}", dns_response);
                    self.udp_socket
                        .send_to(&dns_response, source)
                        .expect("Failed to send response");
                }
                Err(e) => {
                    eprintln!("Error receiving data: {e}");
                    break;
                }
            }
        }
    }
}

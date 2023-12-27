mod dns_answer;
mod dns_header;
mod dns_message;
mod dns_question;
mod domain_name;

use dns_answer::{DnsAnswer, RecordData};
use dns_header::DnsHeader;
use dns_message::{DnsMessage, DnsMessageForm};
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
                    let request = match DnsMessage::from(filled_buf) {
                        DnsMessage::DnsRequest(request) => request,
                        DnsMessage::DnsResponse(_) => {
                            eprintln!("Only DnsMessage::DnsRequest can be generated from Vec<u8>");
                            Default::default()
                        }
                    };

                    let dns_response = self.create_response(&request);
                    let dns_response = match Vec::<u8>::try_from(dns_response) {
                        Ok(byte_vector) => byte_vector,
                        Err(e) => {
                            eprintln!("{e}");
                            Default::default()
                        }
                    };

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

    fn create_response(&self, request: &DnsMessageForm) -> DnsMessage {
        println!("Request: {:?}", request);

        let domain_name = request.dns_questions[0].domain_name.clone();
        let ip_addr = Ipv4Addr::new(8, 8, 8, 8);

        let dns_questions = vec![DnsQuestion {
            domain_name: domain_name.clone(),
            query_type: 1,
            query_class: 1,
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
            domain_name,
            record_type: 1,
            class: 1,
            ttl: 60,
            rdlength: ip_addr.octets().len() as u16,
            rdata: RecordData::IpAddress(ip_addr),
            ..Default::default()
        };

        let dns_response = DnsMessageForm {
            dns_header,
            dns_questions,
            dns_answer: Some(dns_answer),
        };

        println!("Response: {:?}", dns_response);
        DnsMessage::DnsResponse(dns_response)
    }
}

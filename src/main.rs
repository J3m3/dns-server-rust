mod dns_response;

use dns_response::*;
use std::net::{Ipv4Addr, UdpSocket};

fn main() {
    println!("Start DNS server");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                let domain_name = "codecrafters.io";
                let ip_addr = Ipv4Addr::new(8, 8, 8, 8);

                let dns_questions = vec![DnsQuestion {
                    domain_name: String::from(domain_name),
                    ..Default::default()
                }];
                let question_count = dns_questions.len() as u16;
                let dns_header = DnsHeader {
                    id: 1234,
                    qr: 1,
                    qdcount: question_count,
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
                let dns_response = DnsResponse {
                    dns_header,
                    dns_questions,
                    dns_answer,
                };

                let dns_response = Vec::from(dns_response);

                println!("Response: {:?}", dns_response);
                udp_socket
                    .send_to(&dns_response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

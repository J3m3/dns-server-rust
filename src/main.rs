mod dns;

use dns::*;
use std::net::UdpSocket;

fn main() {
    println!("Start DNS server");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let question = [DnsQuestion {
                    domain_name: String::from("codecrafters.io"),
                    query_type: 1,
                    query_class: 1,
                }];
                let question_count = question.len() as u16;
                let header = DnsHeader {
                    id: 1234,
                    qr: 1,
                    opcode: 0,
                    aa: 0,
                    tc: 0,
                    rd: 0,
                    ra: 0,
                    z: 0,
                    rcode: 0,
                    qdcount: question_count,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                };

                let response = [
                    header.to_be_bytes_vector(),
                    question
                        .iter()
                        .flat_map(|dns_question| dns_question.to_be_bytes_vector())
                        .collect(),
                ]
                .concat();

                println!("Response: {:?}", response);
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

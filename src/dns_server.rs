mod dns_answer;
mod dns_header;
mod dns_message;
mod dns_question;
mod domain_name;

use super::config_arguments::Config;
use dns_answer::{DnsAnswer, RecordData};
use dns_header::DnsHeader;
use dns_message::{DnsMessage, DnsMessageForm};
use dns_question::DnsQuestion;

use std::{
    io::Result,
    net::{ToSocketAddrs, UdpSocket},
};

pub struct DnsServer {
    udp_socket: UdpSocket,
    config: Config,
}

impl DnsServer {
    pub fn new<T: ToSocketAddrs>(on: T, config: Config) -> Result<Self> {
        let udp_socket = UdpSocket::bind(on)?;
        Ok(Self { udp_socket, config })
    }

    fn forward_request_and_return(&self, dns_request: &DnsMessageForm) -> Result<Vec<u8>> {
        let udp_socket = UdpSocket::bind("127.0.0.1:0")?;

        let data: Vec<u8> = DnsMessage::DnsRequest(dns_request.clone()).into();
        udp_socket.send_to(data.as_slice(), self.config.target_server.as_str())?;

        let mut buf = vec![0 as u8; 512];
        let (size, _source) = udp_socket.recv_from(&mut buf)?;
        let filled_buf = buf[..size].to_vec();

        Ok(filled_buf)
    }

    fn split_request(&self, dns_request: &DnsMessageForm) -> Vec<DnsMessage> {
        dns_request
            .dns_questions
            .iter()
            .map(|dns_question| {
                DnsMessage::DnsRequest(DnsMessageForm {
                    dns_header: dns_request.dns_header.clone(),
                    dns_questions: vec![dns_question.clone()],
                    dns_answers: None,
                })
            })
            .collect()
    }

    pub fn start(&self, buff_size: usize) -> Result<()> {
        let mut buf = vec![0 as u8; buff_size];

        loop {
            let (size, source) = self.udp_socket.recv_from(&mut buf)?;
            let filled_buf: Vec<u8> = buf[..size].to_vec();
            println!("Raw Request: {filled_buf:?}");

            let request = match DnsMessage::from(filled_buf) {
                DnsMessage::DnsRequest(request) => request,
                DnsMessage::DnsResponse(_) => {
                    eprintln!("Only DnsMessage::DnsRequest can be generated from Vec<u8>");
                    Default::default()
                }
            };

            let dns_response: Vec<u8> = self.create_response(&request).into();
            println!("Raw Response: {:?}", dns_response);

            self.udp_socket.send_to(&dns_response, source)?;
        }
    }

    fn create_response(&self, request: &DnsMessageForm) -> DnsMessage {
        println!("Request: {:?}", request);

        let dns_header = self.create_response_header(&request);
        let dns_questions = self.create_response_questions(&request);
        let dns_answers = self.create_response_answers(&request);

        let dns_response = DnsMessageForm {
            dns_header,
            dns_questions,
            dns_answers: Some(dns_answers),
        };

        println!("Response: {:?}", dns_response);
        DnsMessage::DnsResponse(dns_response)
    }

    fn create_response_header(&self, request: &DnsMessageForm) -> DnsHeader {
        DnsHeader {
            id: request.dns_header.id,
            qr: 1,
            opcode: request.dns_header.opcode,
            rd: request.dns_header.rd,
            rcode: if request.dns_header.opcode == 0 { 0 } else { 4 },
            qdcount: request.dns_questions.len() as u16,
            ancount: request.dns_questions.len() as u16,
            ..Default::default()
        }
    }

    fn create_response_questions(&self, request: &DnsMessageForm) -> Vec<DnsQuestion> {
        request.dns_questions.as_slice().to_vec()
    }

    fn create_response_answers(&self, request: &DnsMessageForm) -> Vec<DnsAnswer> {
        let forwarded_it = self
            .split_request(&request)
            .into_iter()
            .flat_map(|dns_message| {
                let DnsMessage::DnsRequest(dns_request) = dns_message else {
                    eprintln!("Only DnsMessage::DnsRequest can be returned");
                    unreachable!()
                };
                self.forward_request_and_return(&dns_request)
            })
            .map(|raw_response| DnsMessage::from(raw_response));

        let dns_answers = forwarded_it
            .flat_map(|transparent_response| {
                let DnsMessage::DnsResponse(response) = transparent_response else {
                    eprintln!("Only DnsMessage::DnsResponse can be returned");
                    unreachable!()
                };
                response.dns_answers.unwrap_or_default()
            })
            .collect();

        dns_answers
    }
}

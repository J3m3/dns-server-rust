mod dns_server;

use std::io::Result;

use dns_server::DnsServer;

fn main() -> Result<()> {
    println!("Start DNS server");

    let server = DnsServer::new("127.0.0.1:2053")?;
    server.start(1024);

    Ok(())
}

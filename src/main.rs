mod dns_server;

use dns_server::DnsServer;
use std::io::Result;

fn main() -> Result<()> {
    println!("Start DNS server");

    let server = DnsServer::new("127.0.0.1:2053")?;
    server.start(512);

    Ok(())
}

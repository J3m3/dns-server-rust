mod config_arguments;
mod dns_server;

use config_arguments::Config;
use dns_server::DnsServer;
use std::{
    env,
    io::{Error, ErrorKind, Result},
};

fn main() -> Result<()> {
    println!("Start DNS server");
    let target_server = env::args().nth(1).ok_or(Error::new(
        ErrorKind::InvalidInput,
        "No target server provided",
    ))?;
    let config = Config::new(target_server);

    let server = DnsServer::new("127.0.0.1:2053", config)?;
    match server.start(512) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("{e}");
            Err(e)
        }
    }
}

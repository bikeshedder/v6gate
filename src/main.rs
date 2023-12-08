use clap::Parser;

use v6gate::addr::watch_ipv6addr;
use v6gate::cli::Args;
use v6gate::duckdns::Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // Open the netlink socket
    let mut addr_watch = watch_ipv6addr(&args.dev)?;
    let duckdns = v6gate::duckdns::Duckdns {
        domains: args.domains.clone(),
        token: args.duckdns_token.clone(),
    };
    loop {
        let addr = *addr_watch.borrow_and_update();
        println!("Got new address: {addr:?}");
        // https://www.duckdns.org/update?domains={YOURVALUE}&token={YOURVALUE}[&ip={YOURVALUE}][&ipv6={YOURVALUE}][&verbose=true][&clear=true]
        if let Some(addr) = addr {
            println!("Updating DNS...");
            let rsp = duckdns
                .addr(Address::Set {
                    ipv4: None,
                    ipv6: Some(addr),
                })
                .await?;
            println!("{:?}", String::from_utf8_lossy(&rsp.bytes().await?));
        }
        if addr_watch.changed().await.is_err() {
            break;
        }
    }

    Ok(())
}

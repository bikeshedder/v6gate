use std::sync::Arc;

use clap::Parser;

use v6gate::addr::watch_ipv6addr;
use v6gate::cli::Args;
use v6gate::config::Config;
use v6gate::duckdns::Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let config = Arc::new(Config {
        domains: args.domains,
        duckdns_token: args.duckdns_token,
    });

    v6gate::tls::start_provider(config.clone()).await?;

    /*
    let challenges = v6gate::acme::start_order(&args.domains).await?;
    for challenge in &challenges.challenges {
        let duckdns = v6gate::duckdns::Duckdns {
            domains: challenge.domain.clone(),
            token: args.duckdns_token.clone(),
        };
        duckdns.txt(Some(&challenge.txt)).await?;
    }
    let cert = v6gate::acme::complete_order(challenges).await?;
    println!("{:?}", cert);
    */

    // Open the netlink socket
    let mut addr_watch = watch_ipv6addr(&args.dev)?;
    let duckdns = v6gate::duckdns::Duckdns {
        domains: config.domains.join(","),
        token: config.duckdns_token.clone(),
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

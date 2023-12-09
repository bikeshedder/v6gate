use std::{sync::Arc, time::Duration};

use anyhow::Error;
use tokio::{fs, io, sync::watch, time::sleep};
use tracing::{info, warn};

use crate::config::Config;

const PRIVKEY_FILE: &str = "tls_privkey.pem";
const CHAIN_FILE: &str = "tls_chain.pem";

pub struct Certificate {
    pub privkey: String,
    pub chain: String,
}

impl Certificate {
    pub async fn load() -> Result<Option<Self>, Error> {
        if fs::try_exists(PRIVKEY_FILE).await? && fs::try_exists(CHAIN_FILE).await? {
            let privkey = String::from_utf8(fs::read(PRIVKEY_FILE).await?)?;
            let chain = String::from_utf8(fs::read(CHAIN_FILE).await?)?;
            Ok(Some(Certificate { privkey, chain }))
        } else {
            Ok(None)
        }
    }
    pub async fn save(&self) -> Result<(), io::Error> {
        fs::write(PRIVKEY_FILE, &self.privkey).await?;
        fs::write(CHAIN_FILE, &self.chain).await?;
        Ok(())
    }
}

pub async fn start_provider(
    config: Arc<Config>,
) -> Result<watch::Receiver<Option<Certificate>>, Error> {
    let certificate = Certificate::load().await?;
    let (tx, rx) = watch::channel(certificate);
    tokio::spawn(worker(config, tx));
    Ok(rx)
}

pub async fn worker(config: Arc<Config>, tx: watch::Sender<Option<Certificate>>) {
    loop {
        let mut has_cert = false;
        if let Some(cert) = tx.borrow().as_ref() {
            info!("Loaded certificate");
            if let Ok((_rem, pem)) = x509_parser::pem::parse_x509_pem(cert.chain.as_bytes()) {
                let x509 = pem.parse_x509().unwrap();
                if x509.validity.is_valid() {
                    has_cert = true;
                }
            } else {
                println!("Certificate invalid. :-/");
            }
        }
        if !has_cert {
            match get_certificate(&config).await {
                Ok(cert) => {
                    info!("Got new certificate! :-)");
                    cert.save().await.unwrap(); // FIXME error handling, how?
                }
                Err(e) => {
                    warn!("Could not get certificate: {}", e);
                }
            }
        }
        info!("Sleeping 60s...");
        sleep(Duration::from_secs(60)).await;
    }
}

pub async fn get_certificate(config: &Config) -> Result<Certificate, Error> {
    let challenges = crate::acme::start_order(&config.domains).await?;
    for challenge in &challenges.challenges {
        let duckdns = crate::duckdns::Duckdns {
            domains: challenge.domain.clone(),
            token: config.duckdns_token.clone(),
        };
        duckdns.txt(Some(&challenge.txt)).await?;
    }
    let cert = crate::acme::complete_order(challenges).await?;
    Ok(cert)
}

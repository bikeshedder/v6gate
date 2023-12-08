use std::time::Duration;

use anyhow::Result;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    Order, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName};
use tokio::time::sleep;
use tracing::{error, info};

#[derive(Debug)]
pub struct Certificate {
    pub private_key: String,
    pub chain: String,
}

pub struct Challenges {
    order: Order,
    pub challenges: Vec<Challenge>,
}

#[derive(Debug)]
pub struct Challenge {
    pub domain: String,
    /// Set this TXT record for _acme-challenge.{domain}
    pub txt: String,
    url: String,
}

pub async fn start_order(domains: &[String]) -> Result<Challenges> {
    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Staging.url(),
        None,
    )
    .await?;
    info!(
        "account credentials:\n\n{}",
        serde_json::to_string_pretty(&credentials).unwrap()
    );

    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .unwrap();

    let state = order.state();
    info!("order state: {:#?}", state);
    assert!(matches!(state.status, OrderStatus::Pending));

    let authorizations = order.authorizations().await.unwrap();
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let challenge = authz
            .challenges
            .into_iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("no dns01 challenge found"))?;

        let Identifier::Dns(identifier) = &authz.identifier;

        challenges.push(Challenge {
            domain: identifier.clone(),
            txt: order.key_authorization(&challenge).dns_value(),
            url: challenge.url,
        });
    }
    Ok(Challenges { order, challenges })
}

pub async fn complete_order(
    Challenges {
        mut order,
        challenges,
    }: Challenges,
) -> Result<Certificate> {
    for Challenge { url, .. } in &challenges {
        order.set_challenge_ready(url).await.unwrap();
    }

    // Exponentially back off until the order becomes ready or invalid.
    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    loop {
        sleep(delay).await;
        let state = order.refresh().await.unwrap();
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            info!("order state: {:#?}", state);
            break;
        }

        delay *= 2;
        tries += 1;
        match tries < 5 {
            true => info!(?state, tries, "order is not ready, waiting {delay:?}"),
            false => {
                error!(tries, "order is not ready: {state:#?}");
                return Err(anyhow::anyhow!("order is not ready"));
            }
        }
    }

    let state = order.state();
    if state.status != OrderStatus::Ready {
        return Err(anyhow::anyhow!(
            "unexpected order status: {:?}",
            state.status
        ));
    }

    let mut names = Vec::with_capacity(challenges.len());
    for Challenge { domain, .. } in challenges {
        names.push(domain.to_owned());
    }

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.

    let mut params = CertificateParams::new(names.clone());
    params.distinguished_name = DistinguishedName::new();
    let cert = rcgen::Certificate::from_params(params).unwrap();
    let csr = cert.serialize_request_der()?;

    // Finalize the order and print certificate chain, private key and account credentials.

    order.finalize(&csr).await.unwrap();
    let cert_chain_pem = loop {
        match order.certificate().await.unwrap() {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };

    info!("certficate chain:\n\n{}", cert_chain_pem);
    info!("private key:\n\n{}", cert.serialize_private_key_pem());

    Ok(Certificate {
        private_key: cert.serialize_private_key_pem(),
        chain: cert_chain_pem,
    })
}

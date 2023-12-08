use std::net::{Ipv4Addr, Ipv6Addr};

use reqwest::{Error, Response};
use serde::Serialize;

const UPDATE_URL: &str = "https://www.duckdns.org/update";

pub struct Duckdns {
    pub domains: String,
    pub token: String,
}

pub enum Address {
    Set {
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    },
    Clear,
}

#[derive(Debug, Default, Serialize)]
pub struct UpdateParams<'a> {
    pub domains: &'a str,
    pub token: &'a str,
    pub ip: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub txt: Option<&'a str>,
    pub clear: Option<bool>,
    pub verbose: Option<bool>,
}

impl Duckdns {
    pub async fn addr(&self, addr: Address) -> Result<Response, Error> {
        let mut params = self._params();
        match addr {
            Address::Set { ipv4, ipv6 } => {
                params.ip = ipv4;
                params.ipv6 = ipv6;
            }
            Address::Clear => {
                params.clear = Some(true);
            }
        }
        self._req(params).await
    }
    pub async fn txt(&self, txt: Option<&str>) -> Result<Response, Error> {
        let mut params = self._params();
        params.txt = txt;
        params.clear = txt.is_none().then_some(true);
        self._req(params).await
    }
    fn _params(&self) -> UpdateParams<'_> {
        UpdateParams {
            domains: &self.domains,
            token: &self.token,
            verbose: None,
            ..Default::default()
        }
    }
    async fn _req(&self, params: UpdateParams<'_>) ->  Result<Response, Error> {
        let client = reqwest::Client::new();
        let req = client.get(UPDATE_URL).query(&params);
        req.send().await
    }
}

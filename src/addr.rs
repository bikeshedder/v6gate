use std::net::Ipv6Addr;

use futures::stream::TryStreamExt;
use futures::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::address::Nla;
use netlink_packet_route::AddressMessage;
use netlink_packet_route::RtnlMessage;
use netlink_packet_route::AF_INET6;
use netlink_packet_route::IFA_F_DEPRECATED;
use netlink_packet_route::IFA_F_SECONDARY;
use netlink_packet_route::RT_SCOPE_UNIVERSE;
use netlink_sys::AsyncSocket;
use netlink_sys::SocketAddr;
use rtnetlink::constants::RTMGRP_IPV6_IFADDR;
use rtnetlink::new_connection;
use rtnetlink::{Error, Handle};
use tokio::io;
use tokio::sync::watch;

// https://doc.rust-lang.org/stable/std/net/struct.Ipv6Addr.html#method.is_unique_local
pub const fn is_unique_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

pub fn watch_ipv6addr(device: &str) -> io::Result<watch::Receiver<Option<Ipv6Addr>>> {
    // establish netlink connection for IPv6 address changes
    let (mut connection, handle, mut messages) = new_connection()?;
    connection
        .socket_mut()
        .socket_mut()
        .bind(&SocketAddr::new(0, RTMGRP_IPV6_IFADDR))?;
    tokio::spawn(connection);

    let mut last_known_addr: Option<Ipv6Addr> = None;
    let (tx, rx) = watch::channel(last_known_addr);

    tokio::spawn({
        let device = device.to_owned();

        async move {
            let addr = get_current_ipv6addr(handle, &device).await.unwrap();
            if addr != last_known_addr {
                last_known_addr = addr;
                let _ = tx.send(addr);
            }

            while let Some((message, _)) = messages.next().await {
                let payload = message.payload;
                match payload {
                    NetlinkPayload::InnerMessage(RtnlMessage::NewAddress(msg)) => {
                        let Some(addr) = addr_from_msg(&msg) else {
                            continue;
                        };
                        if addr.is_current()
                            && Some(addr.address) != last_known_addr
                            && !is_unique_local(&addr.address)
                        {
                            last_known_addr = Some(addr.address);
                            let _ = tx.send(Some(addr.address));
                        }
                    }
                    NetlinkPayload::InnerMessage(RtnlMessage::DelAddress(msg)) => {
                        let Some(addr) = addr_from_msg(&msg) else {
                            continue;
                        };
                        if last_known_addr == Some(addr.address) {
                            last_known_addr = None;
                            let _ = tx.send(None);
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    Ok(rx)
}

#[derive(Debug)]
struct Addr {
    pub universe: bool,
    pub deprecated: bool,
    pub primary: bool,
    pub address: Ipv6Addr,
}

impl Addr {
    pub fn is_current(&self) -> bool {
        self.universe && !self.deprecated && self.primary
    }
}

fn parse_ipv6addr(bytes: &[u8]) -> Option<Ipv6Addr> {
    let array = <&[u8; 16]>::try_from(bytes).unwrap();
    Some(Ipv6Addr::from(array.to_owned()))
}

fn addr_from_msg(msg: &AddressMessage) -> Option<Addr> {
    // Filter non-IPv6 addresses
    if AF_INET6 != msg.header.family as u16 {
        return None;
    }
    let Nla::Address(addr_bytes) = msg.nlas.first()? else {
        return None;
    };
    Some(Addr {
        universe: msg.header.scope == RT_SCOPE_UNIVERSE,
        deprecated: msg.header.flags as u32 & IFA_F_DEPRECATED == IFA_F_DEPRECATED,
        primary: msg.header.flags as u32 & IFA_F_SECONDARY != IFA_F_SECONDARY,
        address: parse_ipv6addr(addr_bytes)?,
    })
}

async fn get_current_ipv6addr(handle: Handle, device: &str) -> Result<Option<Ipv6Addr>, Error> {
    let mut links = handle.link().get().match_name(device.to_owned()).execute();
    if let Some(link) = links.try_next().await? {
        let mut addresses = handle
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .execute();
        while let Some(msg) = addresses.try_next().await? {
            let Some(addr) = addr_from_msg(&msg) else {
                continue;
            };
            if addr.is_current() && !is_unique_local(&addr.address) {
                return Ok(Some(addr.address));
            }
        }
        Ok(None)
    } else {
        eprintln!("Device {device} not found");
        Ok(None)
    }
}

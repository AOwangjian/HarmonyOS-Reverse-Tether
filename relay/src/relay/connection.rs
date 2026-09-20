/*
 * Copyright (C) 2017 Genymobile
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use super::client::ClientChannel;
use super::ip_packet::IpPacket;
use super::ipv4_header::{Ipv4HeaderData, Protocol};
use super::net;
use super::selector::Selector;
use super::transport_header::TransportHeaderData;

const LOCALHOST_FORWARD: u32 = 0x0A_00_02_02; // 10.0.2.2
const LOCALHOST: u32 = 0x7F_00_00_01; // 127.0.0.1

pub trait Connection {
    fn id(&self) -> &ConnectionId;
    fn send_to_network(
        &mut self,
        selector: &mut Selector,
        client_channel: &mut ClientChannel,
        packet: &IpPacket,
    );
    fn close(&mut self, selector: &mut Selector);
    /// Called by the reaper when the flow has been idle for too long.
    /// Receives a ClientChannel so implementations can push a terminal
    /// packet (e.g. TCP RST) back to the client without having to
    /// re-borrow the Client -- which would panic, since the reaper is
    /// already holding it mutably.
    fn expire(&mut self, selector: &mut Selector, _client_channel: &mut ClientChannel) {
        self.close(selector);
    }
    fn is_expired(&self) -> bool;
    fn is_closed(&self) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ConnectionId {
    protocol: Protocol,
    source: SocketAddr,
    destination: SocketAddr,
    id_string: String,
}

impl ConnectionId {
    pub fn new(protocol: Protocol, source: SocketAddr, destination: SocketAddr) -> Self {
        let id_string = format!("{} -> {}", source, destination);
        Self {
            protocol,
            source,
            destination,
            id_string,
        }
    }

    pub fn from_headers(
        ipv4_header_data: &Ipv4HeaderData,
        transport_header_data: &TransportHeaderData,
    ) -> Self {
        Self::new(
            ipv4_header_data.protocol(),
            net::to_socket_addr(ipv4_header_data.source(), transport_header_data.source_port())
                .into(),
            net::to_socket_addr(
                ipv4_header_data.destination(),
                transport_header_data.destination_port(),
            )
            .into(),
        )
    }

    pub fn from_packet(packet: &IpPacket) -> Option<Self> {
        match packet {
            IpPacket::Ipv4(packet) => {
                let (header, transport) = packet.headers_data();
                transport.map(|transport| Self::from_headers(header, transport))
            }
            IpPacket::Ipv6(packet) => {
                let header = packet.ipv6_header_data();
                let transport = packet.transport_header_data();
                let protocol = match header.next_header() {
                    6 => Protocol::Tcp,
                    17 => Protocol::Udp,
                    _ => return None,
                };
                let source = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(header.source())),
                    transport.source_port(),
                );
                let destination = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(header.destination())),
                    transport.destination_port(),
                );
                Some(Self::new(protocol, source, destination))
            }
        }
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn rewritten_destination(&self) -> SocketAddr {
        match self.destination {
            SocketAddr::V4(destination)
                if u32::from(*destination.ip()) == crate::dns::VIRTUAL_DNS
                    && destination.port() == 53 =>
            {
                crate::dns::upstream().into()
            }
            SocketAddr::V4(destination)
                if u32::from(*destination.ip()) == LOCALHOST_FORWARD =>
            {
                net::to_socket_addr(LOCALHOST, destination.port()).into()
            }
            _ => self.destination,
        }
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.id_string)
    }
}

// macros to log connection id along with the message

macro_rules! cx_format {
    ($id:tt, $str:tt, $($arg:tt)+) => {
        format!(concat!("{} ", $str), $id, $($arg)+)
    };
    ($id:tt, $str:tt) => {
        format!(concat!("{} ", $str), $id)
    };
}

macro_rules! cx_trace {
    (target: $target:expr, $id:expr, $($arg:tt)*) => {
        log::trace!(target: $target, "{}", cx_format!($id, $($arg)+))
    }
}

macro_rules! cx_debug {
    (target: $target:expr, $id:expr, $($arg:tt)*) => {
        log::debug!(target: $target, "{}", cx_format!($id, $($arg)+))
    }
}

macro_rules! cx_info {
    (target: $target:expr, $id:expr, $($arg:tt)*) => {
        log::info!(target: $target, "{}", cx_format!($id, $($arg)+))
    }
}

macro_rules! cx_warn {
    (target: $target:expr, $id:expr, $($arg:tt)*) => {
        log::warn!(target: $target, "{}", cx_format!($id, $($arg)+))
    }
}

macro_rules! cx_error {
    (target: $target:expr, $id:expr, $($arg:tt)*) => {
        log::error!(target: $target, "{}", cx_format!($id, $($arg)+))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn connection_id_keeps_ipv4_and_ipv6_flows_with_the_same_ports_distinct() {
        let source_port = 40000;
        let destination_port = 443;
        let ipv4 = ConnectionId::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), source_port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), destination_port),
        );
        let ipv6 = ConnectionId::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), source_port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), destination_port),
        );

        assert_ne!(ipv4, ipv6);
        let mut ids = HashSet::new();
        ids.insert(ipv4);
        ids.insert(ipv6);
        assert_eq!(2, ids.len());
    }
}

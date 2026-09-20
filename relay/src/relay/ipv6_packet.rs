/*
 * Copyright (C) 2026
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

use super::ip_packet::{PacketParseError, UnsupportedPacket};
use super::ipv4_header::Protocol;
use super::ipv6_header::{Ipv6Header, Ipv6HeaderData, Ipv6HeaderError, IPV6_HEADER_LENGTH};
use super::transport_header::{TransportHeader, TransportHeaderData};

pub struct Ipv6Packet<'a> {
    raw: &'a mut [u8],
    ipv6_header_data: Ipv6HeaderData,
    transport_header_data: TransportHeaderData,
}

impl<'a> Ipv6Packet<'a> {
    pub fn parse(raw: &'a mut [u8]) -> Result<Self, PacketParseError> {
        let ipv6_header_data = Ipv6HeaderData::parse(raw).map_err(PacketParseError::from)?;
        let payload_length = usize::from(ipv6_header_data.payload_length());
        let total_length = ipv6_header_data.total_length();
        let next_header = ipv6_header_data.next_header();
        let protocol = match next_header {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            44 => return Err(PacketParseError::Unsupported(UnsupportedPacket::Ipv6FragmentHeader)),
            0 | 43 | 50 | 51 | 60 | 135 => {
                return Err(PacketParseError::Unsupported(
                    UnsupportedPacket::Ipv6ExtensionHeader(next_header),
                ));
            }
            _ => {
                return Err(PacketParseError::Unsupported(
                    UnsupportedPacket::Ipv6NextHeader(next_header),
                ));
            }
        };

        let payload = &raw[IPV6_HEADER_LENGTH..total_length];
        if protocol == Protocol::Tcp {
            if payload_length < 20 {
                return Err(PacketParseError::Malformed("truncated TCP header"));
            }
            let tcp_header_length = usize::from(payload[12] >> 4) * 4;
            if tcp_header_length < 20 || tcp_header_length > payload_length {
                return Err(PacketParseError::Malformed("invalid TCP header length"));
            }
        } else if protocol == Protocol::Udp {
            if payload_length < 8 {
                return Err(PacketParseError::Malformed("truncated UDP header"));
            }
            let udp_length = (usize::from(payload[4]) << 8) | usize::from(payload[5]);
            if udp_length != payload_length {
                return Err(PacketParseError::Malformed("invalid UDP length"));
            }
        }

        let transport_header_data = match TransportHeaderData::parse(protocol, payload) {
            Some(header) => header,
            None => return Err(PacketParseError::Malformed("unsupported transport header")),
        };
        Ok(Self {
            raw: &mut raw[..total_length],
            ipv6_header_data,
            transport_header_data,
        })
    }

    #[inline]
    pub fn raw(&self) -> &[u8] {
        self.raw
    }

    #[inline]
    pub fn length(&self) -> usize {
        self.raw.len()
    }

    #[inline]
    pub fn ipv6_header_data(&self) -> &Ipv6HeaderData {
        &self.ipv6_header_data
    }

    #[inline]
    pub fn ipv6_header(&self) -> Ipv6Header<'_> {
        self.ipv6_header_data.bind(&self.raw[..IPV6_HEADER_LENGTH])
    }

    #[inline]
    pub fn transport_header_data(&self) -> &TransportHeaderData {
        &self.transport_header_data
    }

    #[inline]
    pub fn transport_header(&self) -> TransportHeader<'_> {
        let end = IPV6_HEADER_LENGTH + usize::from(self.transport_header_data.header_length());
        self.transport_header_data.bind(&self.raw[IPV6_HEADER_LENGTH..end])
    }

    pub fn payload(&self) -> Option<&[u8]> {
        let start = IPV6_HEADER_LENGTH + usize::from(self.transport_header_data.header_length());
        Some(&self.raw[start..])
    }
}

impl From<Ipv6HeaderError> for PacketParseError {
    fn from(error: Ipv6HeaderError) -> Self {
        match error {
            Ipv6HeaderError::TruncatedHeader | Ipv6HeaderError::TruncatedPayload => {
                PacketParseError::Malformed("truncated IPv6 packet")
            }
            Ipv6HeaderError::InvalidVersion => PacketParseError::Malformed("invalid IPv6 version"),
        }
    }
}

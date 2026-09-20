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

use super::ipv4_packet::Ipv4Packet;
use super::ipv6_header::IPV6_HEADER_LENGTH;
use super::ipv6_packet::Ipv6Packet;

pub const MAX_IP_PACKET_LENGTH: usize = IPV6_HEADER_LENGTH + u16::MAX as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsupportedPacket {
    Ipv4Fragment,
    Ipv6ExtensionHeader(u8),
    Ipv6FragmentHeader,
    Ipv6NextHeader(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacketParseError {
    Malformed(&'static str),
    Unsupported(UnsupportedPacket),
}

pub enum IpPacket<'a> {
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
}

impl<'a> IpPacket<'a> {
    pub fn parse(raw: &'a mut [u8]) -> Result<Self, PacketParseError> {
        match raw.first().map(|value| value >> 4) {
            Some(4) => {
                validate_ipv4(raw)?;
                Ok(IpPacket::Ipv4(Ipv4Packet::parse(raw)))
            }
            Some(6) => Ok(IpPacket::Ipv6(Ipv6Packet::parse(raw)?)),
            Some(_) => Err(PacketParseError::Malformed("unsupported IP version")),
            None => Err(PacketParseError::Malformed("truncated IP packet")),
        }
    }

    #[inline]
    pub fn raw(&self) -> &[u8] {
        match self {
            IpPacket::Ipv4(packet) => packet.raw(),
            IpPacket::Ipv6(packet) => packet.raw(),
        }
    }

    #[inline]
    pub fn length(&self) -> usize {
        self.raw().len()
    }
}

pub fn front_packet_length(raw: &[u8]) -> Result<Option<usize>, PacketParseError> {
    if raw.is_empty() {
        return Ok(None);
    }
    match raw[0] >> 4 {
        4 => {
            if raw.len() < 4 {
                return Ok(None);
            }
            let header_length = usize::from(raw[0] & 15) * 4;
            let total_length = (usize::from(raw[2]) << 8) | usize::from(raw[3]);
            if header_length < 20 || total_length < header_length {
                return Err(PacketParseError::Malformed("invalid IPv4 packet length"));
            }
            if raw.len() < total_length {
                Ok(None)
            } else {
                Ok(Some(total_length))
            }
        }
        6 => {
            if raw.len() < 6 {
                return Ok(None);
            }
            let payload_length = (usize::from(raw[4]) << 8) | usize::from(raw[5]);
            let total_length = 40 + payload_length;
            if raw.len() < total_length {
                Ok(None)
            } else {
                Ok(Some(total_length))
            }
        }
        _ => Err(PacketParseError::Malformed("unsupported IP version")),
    }
}

fn validate_ipv4(raw: &[u8]) -> Result<(), PacketParseError> {
    if raw.len() < 4 {
        return Err(PacketParseError::Malformed("truncated IPv4 packet"));
    }
    let header_length = usize::from(raw[0] & 15) * 4;
    let total_length = (usize::from(raw[2]) << 8) | usize::from(raw[3]);
    if raw.len() < total_length || header_length < 20 || total_length < header_length {
        return Err(PacketParseError::Malformed("invalid IPv4 packet length"));
    }
    let more_fragments = raw[6] & 0x20 != 0;
    let fragment_offset = raw[6] & 0x1f != 0 || raw[7] != 0;
    if more_fragments || fragment_offset {
        return Err(PacketParseError::Unsupported(UnsupportedPacket::Ipv4Fragment));
    }
    let payload_length = total_length - header_length;
    let payload = &raw[header_length..total_length];
    match raw[9] {
        6 => {
            if payload_length < 20 {
                return Err(PacketParseError::Malformed("truncated TCP header"));
            }
            let tcp_header_length = usize::from(payload[12] >> 4) * 4;
            if tcp_header_length < 20 || tcp_header_length > payload_length {
                return Err(PacketParseError::Malformed("invalid TCP header length"));
            }
        }
        17 => {
            if payload_length < 8 {
                return Err(PacketParseError::Malformed("truncated UDP header"));
            }
            let udp_length = (usize::from(payload[4]) << 8) | usize::from(payload[5]);
            if udp_length != payload_length {
                return Err(PacketParseError::Malformed("invalid UDP length"));
            }
        }
        _ => (),
    }
    Ok(())
}

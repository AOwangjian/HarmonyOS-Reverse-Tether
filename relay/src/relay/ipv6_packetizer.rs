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

use byteorder::{BigEndian, ByteOrder};
use std::io;

use super::datagram::{DatagramReceiver, ReadAdapter};
use super::ipv4_header::Protocol;
use super::ipv4_packet::MAX_PACKET_LENGTH;
use super::ipv6_header::{Ipv6Header, Ipv6HeaderData, IPV6_HEADER_LENGTH};
use super::ipv6_packet::Ipv6Packet;
use super::transport_header::{TransportHeader, TransportHeaderData};

/// Offset of the UDP checksum field inside the UDP header.
const UDP_CHECKSUM_OFFSET: usize = 6;
/// Offset of the TCP checksum field inside the TCP header.
const TCP_CHECKSUM_OFFSET: usize = 16;

/// Convert from level 5 to level 3 by appending correct IPv6 and transport headers.
///
/// This is the IPv6 counterpart of [`super::packetizer::Packetizer`]. It cannot reuse
/// `TransportHeaderMut::update_checksum`, because that helper folds an IPv4 (12-byte)
/// pseudo header; IPv6 mandates the 40-byte pseudo header defined in RFC 8200 §8.1.
pub struct Ipv6Packetizer {
    buffer: Box<[u8; MAX_PACKET_LENGTH]>,
    payload_index: usize,
    ipv6_header_data: Ipv6HeaderData,
    transport_header_data: TransportHeaderData,
    protocol: Protocol,
}

impl Ipv6Packetizer {
    pub fn new(
        reference_ipv6_header: &Ipv6Header,
        reference_transport_header: &TransportHeader,
    ) -> Self {
        let mut buffer = Box::new([0; MAX_PACKET_LENGTH]);

        let transport_header_length = usize::from(reference_transport_header.header_length());
        let payload_index = IPV6_HEADER_LENGTH + transport_header_length;

        let mut transport_header_data = reference_transport_header.data_clone();
        let protocol = match reference_ipv6_header.next_header() {
            6 => Protocol::Tcp,
            _ => Protocol::Udp,
        };

        {
            // Copy the reference IPv6 header, then swap the endpoints so the synthesized
            // packet travels back towards the client.
            let ipv6_header_raw = &mut buffer[..IPV6_HEADER_LENGTH];
            ipv6_header_raw.copy_from_slice(reference_ipv6_header.raw());
            let source = reference_ipv6_header.source();
            let destination = reference_ipv6_header.destination();
            ipv6_header_raw[8..24].copy_from_slice(&destination);
            ipv6_header_raw[24..40].copy_from_slice(&source);
        }

        {
            let transport_header_raw = &mut buffer[IPV6_HEADER_LENGTH..payload_index];
            transport_header_raw.copy_from_slice(reference_transport_header.raw());
            let mut transport_header = transport_header_data.bind_mut(transport_header_raw);
            transport_header.swap_source_and_destination();
        }

        // The cached header data must describe the swapped buffer. Parsing here would
        // fail, because the reference payload length still refers to bytes the buffer
        // does not hold yet; `build` rewrites that field for every synthesized packet.
        let ipv6_header_data = Ipv6HeaderData::parse_header_only(&buffer[..IPV6_HEADER_LENGTH])
            .expect("the reference IPv6 header must stay well-formed after swapping endpoints");

        Self {
            buffer,
            payload_index,
            ipv6_header_data,
            transport_header_data,
            protocol,
        }
    }

    pub fn packetize_empty_payload(&mut self) -> Ipv6Packet {
        self.build(0)
    }

    pub fn packetize<R: DatagramReceiver>(&mut self, source: &mut R) -> io::Result<Ipv6Packet> {
        let r = source.recv(&mut self.buffer[self.payload_index..])?;
        Ok(self.build(r as u16))
    }

    /// Packetize from a stream (`Read`) source.
    ///
    /// `Ok(Some(_))` when a packet is available,
    /// `Ok(None)` on EOF (read 0 byte),
    /// `Err(_)` on error.
    pub fn packetize_read<R: io::Read>(
        &mut self,
        source: &mut R,
        max_chunk_size: Option<usize>,
    ) -> io::Result<Option<Ipv6Packet>> {
        let mut adapter = ReadAdapter::new(source, max_chunk_size);
        let r = adapter.recv(&mut self.buffer[self.payload_index..])?;
        let option = if r > 0 { Some(self.build(r as u16)) } else { None };
        Ok(option)
    }

    fn build(&mut self, payload_length: u16) -> Ipv6Packet {
        let transport_length = (self.payload_index - IPV6_HEADER_LENGTH) as u16 + payload_length;
        let total_length = IPV6_HEADER_LENGTH + usize::from(transport_length);

        // The IPv6 payload length counts every byte after the 40-byte fixed header.
        BigEndian::write_u16(&mut self.buffer[4..6], transport_length);

        {
            let transport_header_raw = &mut self.buffer[IPV6_HEADER_LENGTH..self.payload_index];
            let mut transport_header = self.transport_header_data.bind_mut(transport_header_raw);
            transport_header.set_payload_length(payload_length);
        }

        self.update_checksum(total_length);

        let raw = &mut self.buffer[..total_length];
        Ipv6Packet::parse(raw).expect("a synthesized IPv6 packet must be parsable")
    }

    /// Compute the transport checksum over the RFC 8200 §8.1 pseudo header.
    fn update_checksum(&mut self, total_length: usize) {
        let checksum_offset = match self.protocol {
            Protocol::Tcp => TCP_CHECKSUM_OFFSET,
            _ => UDP_CHECKSUM_OFFSET,
        };
        let checksum_index = IPV6_HEADER_LENGTH + checksum_offset;

        // Zero the field before folding, otherwise the stale value pollutes the sum.
        BigEndian::write_u16(&mut self.buffer[checksum_index..checksum_index + 2], 0);

        let transport_length = total_length - IPV6_HEADER_LENGTH;
        let next_header = self.ipv6_header_data.next_header();
        let mut sum = 0u32;

        // Pseudo header: 16-byte source, 16-byte destination, 32-bit upper-layer
        // length, 24 zero bits and the 8-bit next header.
        for index in (8..40).step_by(2) {
            sum += u32::from(BigEndian::read_u16(&self.buffer[index..index + 2]));
        }
        sum += (transport_length as u32) >> 16;
        sum += (transport_length as u32) & 0xffff;
        sum += u32::from(next_header);

        let transport = &self.buffer[IPV6_HEADER_LENGTH..total_length];
        let mut chunks = transport.chunks_exact(2);
        for pair in &mut chunks {
            sum += u32::from(BigEndian::read_u16(pair));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += u32::from(last) << 8;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        // RFC 768: a computed UDP checksum of zero is transmitted as all ones.
        let checksum = match !(sum as u16) {
            0 if self.protocol == Protocol::Udp => 0xffff,
            value => value,
        };
        BigEndian::write_u16(&mut self.buffer[checksum_index..checksum_index + 2], checksum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::datagram::tests::MockDatagramSocket;
    use crate::relay::ip_packet::IpPacket;

    fn reference(next_header: u8, transport: &[u8]) -> Vec<u8> {
        let mut raw = Vec::with_capacity(IPV6_HEADER_LENGTH + transport.len());
        raw.extend_from_slice(&[0x60, 0, 0, 0]);
        raw.extend_from_slice(&(transport.len() as u16).to_be_bytes());
        raw.push(next_header);
        raw.push(64);
        raw.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        raw.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);
        raw.extend_from_slice(transport);
        raw
    }

    /// Fold a synthesized packet exactly the way a receiver validates it: a correct
    /// checksum makes the whole pseudo-header sum collapse to 0xffff.
    fn verify(raw: &[u8], next_header: u8) -> u16 {
        let mut sum = 0u32;
        for index in (8..40).step_by(2) {
            sum += u32::from(BigEndian::read_u16(&raw[index..index + 2]));
        }
        let transport = &raw[IPV6_HEADER_LENGTH..];
        sum += transport.len() as u32;
        sum += u32::from(next_header);
        let mut chunks = transport.chunks_exact(2);
        for pair in &mut chunks {
            sum += u32::from(BigEndian::read_u16(pair));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += u32::from(last) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    fn packetize(next_header: u8, transport: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut input = reference(next_header, transport);
        let packet = match IpPacket::parse(&mut input).unwrap() {
            IpPacket::Ipv6(packet) => packet,
            IpPacket::Ipv4(_) => panic!("expected an IPv6 packet"),
        };
        let header = packet.ipv6_header();
        let transport_header = packet.transport_header();
        let mut packetizer = Ipv6Packetizer::new(&header, &transport_header);
        let mut host = MockDatagramSocket::from_data(payload);
        packetizer.packetize(&mut host).unwrap().raw().to_vec()
    }

    #[test]
    fn tcp_response_carries_a_valid_pseudo_header_checksum() {
        let tcp = [
            0x04, 0xd2, 0x16, 0x2e, // ports
            0, 0, 0, 1, // sequence
            0, 0, 0, 0, // ack
            0x50, 0x10, 0x20, 0x00, // data offset, flags, window
            0, 0, 0, 0, // checksum, urgent
        ];
        let raw = packetize(6, &tcp, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(0xffff, verify(&raw, 6));
        // The checksum must actually have been written.
        assert_ne!(0, BigEndian::read_u16(&raw[IPV6_HEADER_LENGTH + 16..][..2]));
    }

    #[test]
    fn odd_length_payload_is_padded_when_folding() {
        let udp = [0x04, 0xd2, 0x16, 0x2e, 0, 8, 0, 0];
        let raw = packetize(17, &udp, &[0x01, 0x02, 0x03]);
        assert_eq!(0xffff, verify(&raw, 17));
        assert_eq!(11, BigEndian::read_u16(&raw[4..6]));
    }

    #[test]
    fn payload_length_is_rewritten_for_every_packet() {
        let udp = [0x04, 0xd2, 0x16, 0x2e, 0, 8, 0, 0];
        let mut input = reference(17, &udp);
        let packet = match IpPacket::parse(&mut input).unwrap() {
            IpPacket::Ipv6(packet) => packet,
            IpPacket::Ipv4(_) => panic!("expected an IPv6 packet"),
        };
        let header = packet.ipv6_header();
        let transport_header = packet.transport_header();
        let mut packetizer = Ipv6Packetizer::new(&header, &transport_header);

        // A long packet followed by a short one must not leave stale length bytes.
        let long = packetizer
            .packetize(&mut MockDatagramSocket::from_data(&[0x11; 40]))
            .unwrap()
            .raw()
            .to_vec();
        assert_eq!(48, BigEndian::read_u16(&long[4..6]));
        assert_eq!(0xffff, verify(&long, 17));

        let short = packetizer
            .packetize(&mut MockDatagramSocket::from_data(&[0x22]))
            .unwrap()
            .raw()
            .to_vec();
        assert_eq!(9, BigEndian::read_u16(&short[4..6]));
        assert_eq!(0xffff, verify(&short, 17));
    }

    /// Mirrors `Ipv6Checksum` in app/entry/src/main/cpp/icmpv6.cpp.
    ///
    /// The app cannot run unit tests, so the shared folding rule is pinned here:
    /// a receiver folding a correct packet always arrives at 0xffff.
    fn icmpv6_checksum(source: &[u8], destination: &[u8], payload: &[u8]) -> u16 {
        let mut sum = 0u32;
        for index in (0..16).step_by(2) {
            sum += u32::from(u16::from_be_bytes([source[index], source[index + 1]]));
            sum += u32::from(u16::from_be_bytes([destination[index], destination[index + 1]]));
        }
        sum += payload.len() as u32;
        sum += 58; // ICMPv6
        let mut chunks = payload.chunks_exact(2);
        for pair in &mut chunks {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += u32::from(last) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn icmpv6_checksum_folds_to_all_ones_at_the_receiver() {
        let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        // Type 1, code 1, zeroed checksum, unused word, then an odd-length quote.
        let mut icmp = vec![1u8, 1, 0, 0, 0, 0, 0, 0, 0x60, 0x11, 0x22];
        let checksum = icmpv6_checksum(&source, &destination, &icmp);
        icmp[2] = (checksum >> 8) as u8;
        icmp[3] = (checksum & 0xff) as u8;

        let mut verify = 0u32;
        for index in (0..16).step_by(2) {
            verify += u32::from(u16::from_be_bytes([source[index], source[index + 1]]));
            verify += u32::from(u16::from_be_bytes([destination[index], destination[index + 1]]));
        }
        verify += icmp.len() as u32;
        verify += 58;
        let mut chunks = icmp.chunks_exact(2);
        for pair in &mut chunks {
            verify += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            verify += u32::from(last) << 8;
        }
        while verify >> 16 != 0 {
            verify = (verify & 0xffff) + (verify >> 16);
        }
        assert_eq!(0xffff, verify as u16);
    }

    #[test]
    fn endpoints_are_swapped_towards_the_client() {
        let udp = [0x04, 0xd2, 0x16, 0x2e, 0, 8, 0, 0];
        let raw = packetize(17, &udp, &[0xaa]);
        // Source/destination addresses are mirrored.
        assert_eq!(&raw[8..24], &reference(17, &udp)[24..40]);
        assert_eq!(&raw[24..40], &reference(17, &udp)[8..24]);
        // Ports are mirrored too.
        assert_eq!(0x162e, BigEndian::read_u16(&raw[IPV6_HEADER_LENGTH..][..2]));
        assert_eq!(0x04d2, BigEndian::read_u16(&raw[IPV6_HEADER_LENGTH + 2..][..2]));
    }
}

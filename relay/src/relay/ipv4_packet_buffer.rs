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

use super::binary;
use super::byte_buffer::ByteBuffer;
use super::ipv4_header;
use super::ipv4_packet::{Ipv4Packet, MAX_PACKET_LENGTH};

use log::*;
use std::io;

pub struct Ipv4PacketBuffer {
    buf: ByteBuffer,
}

impl Ipv4PacketBuffer {
    pub fn new() -> Self {
        Self {
            buf: ByteBuffer::new(MAX_PACKET_LENGTH),
        }
    }

    pub fn read_from<R: io::Read>(&mut self, source: &mut R) -> io::Result<bool> {
        self.buf.read_from(source)
    }

    // Validate every frame before the inherited zero-copy parsers index it.
    // A bad stream is a client error, never a process-wide assertion failure.
    pub fn validate_front(&self) -> io::Result<()> {
        let b = self.buf.peek();
        if b.len() < 4 { return Ok(()); }
        let header = usize::from(b[0] & 15) * 4;
        let length = (usize::from(b[2]) << 8) | usize::from(b[3]);
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "Malformed IP/transport frame");
        if b[0] >> 4 != 4 || header < 20 || length < header { return Err(bad()); }
        if b.len() < length { return Ok(()); }
        // Fragments are well-formed but not supported; the caller drops them.
        if self.is_fragmented() { return Ok(()); }
        let payload = length - header;
        match b[9] {
            6 => {
                if payload < 20 { return Err(bad()); }
                let tcp_header = usize::from(b[header + 12] >> 4) * 4;
                if tcp_header < 20 || tcp_header > payload { return Err(bad()); }
            }
            17 => {
                if payload < 8 { return Err(bad()); }
                let udp_length = (usize::from(b[header + 4]) << 8) | usize::from(b[header + 5]);
                if udp_length != payload { return Err(bad()); }
            }
            _ => (),
        }
        Ok(())
    }

    pub fn is_fragmented(&self) -> bool {
        let b = self.buf.peek();
        b.len() >= 20 && self.available_packet_length().is_some() && (b[6] & 0x3f != 0 || b[7] != 0)
    }

    fn available_packet_length(&self) -> Option<u16> {
        let data = self.buf.peek();
        trace!("Parse packet: {}", binary::build_packet_string(data));
        if let Some((version, length)) = ipv4_header::peek_version_length(data) {
            assert!(version == 4, "Not an Ipv4 packet, version={}", version);
            if length as usize <= data.len() {
                // full packet available
                Some(length)
            } else {
                // no full packet available
                None
            }
        } else {
            // no packet
            None
        }
    }

    pub fn as_ipv4_packet(&mut self) -> Option<Ipv4Packet> {
        if self.available_packet_length().is_some() {
            let data = self.buf.peek_mut();
            Some(Ipv4Packet::parse(data))
        } else {
            None
        }
    }

    pub fn next(&mut self) {
        // remove the packet in front of the buffer
        let length = self
            .available_packet_length()
            .expect("next() called while there was no packet") as usize;
        self.buf.consume(length);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::ip_packet::{IpPacket, PacketParseError, UnsupportedPacket};
    use crate::relay::ip_packet_buffer::IpPacketBuffer;
    use crate::relay::ipv6_packetizer::Ipv6Packetizer;
    use crate::relay::datagram::tests::MockDatagramSocket;
    use crate::relay::ipv4_header::Protocol;
    use crate::relay::transport_header::TransportHeaderData;
    use byteorder::{BigEndian, WriteBytesExt};
    use std::convert::TryInto;
    use std::io;

    #[test]
    fn malformed_stream_cannot_reach_unchecked_parsers() {
        for raw in [vec![0x60, 0, 0, 20], vec![0x45, 0, 0, 0], vec![0x4f, 0, 0, 20]] {
            let mut buffer = Ipv4PacketBuffer::new();
            buffer.read_from(&mut io::Cursor::new(raw)).unwrap();
            assert!(buffer.validate_front().is_err());
        }
        let mut raw = create_packet();
        raw[24] = 0; raw[25] = 7;
        let mut buffer = Ipv4PacketBuffer::new();
        buffer.read_from(&mut io::Cursor::new(raw)).unwrap();
        assert!(buffer.validate_front().is_err());
    }

    #[test]
    fn validates_next_coalesced_frame_and_identifies_fragments() {
        let mut raw = create_packet();
        raw[6] = 0x20;
        raw.extend_from_slice(&[0x45, 0, 0, 0]);
        let mut buffer = Ipv4PacketBuffer::new();
        buffer.read_from(&mut io::Cursor::new(raw)).unwrap();
        assert!(buffer.validate_front().is_ok());
        assert!(buffer.is_fragmented());
        buffer.next();
        assert!(buffer.validate_front().is_err());
    }

    fn create_packet() -> Vec<u8> {
        let mut raw = Vec::new();
        write_packet_to(&mut raw);
        raw
    }

    fn write_packet_to(raw: &mut Vec<u8>) {
        raw.write_u8(4u8 << 4 | 5).unwrap();
        raw.write_u8(0).unwrap(); // ToS
        raw.write_u16::<BigEndian>(32).unwrap(); // total length 20 + 8 + 4
        raw.write_u32::<BigEndian>(0).unwrap(); // id_flags_fragment_offset
        raw.write_u8(0).unwrap(); // TTL
        raw.write_u8(17).unwrap(); // protocol (UDP)
        raw.write_u16::<BigEndian>(0).unwrap(); // checksum
        raw.write_u32::<BigEndian>(0x12345678).unwrap(); // source address
        raw.write_u32::<BigEndian>(0x42424242).unwrap(); // destination address

        raw.write_u16::<BigEndian>(1234).unwrap(); // source port
        raw.write_u16::<BigEndian>(5678).unwrap(); // destination port
        raw.write_u16::<BigEndian>(12).unwrap(); // length
        raw.write_u16::<BigEndian>(0).unwrap(); // checksum

        raw.write_u32::<BigEndian>(0x11223344).unwrap(); // payload
    }

    fn write_another_packet_to(raw: &mut Vec<u8>) {
        raw.write_u8(4u8 << 4 | 5).unwrap();
        raw.write_u8(0).unwrap(); // ToS
        raw.write_u16::<BigEndian>(29).unwrap(); // total length 20 + 8 + 1
        raw.write_u32::<BigEndian>(0).unwrap(); // id_flags_fragment_offset
        raw.write_u8(0).unwrap(); // TTL
        raw.write_u8(17).unwrap(); // protocol (UDP)
        raw.write_u16::<BigEndian>(0).unwrap(); // checksum
        raw.write_u32::<BigEndian>(0x11111111).unwrap(); // source address
        raw.write_u32::<BigEndian>(0x22222222).unwrap(); // destination address

        raw.write_u16::<BigEndian>(1111).unwrap(); // source port
        raw.write_u16::<BigEndian>(2222).unwrap(); // destination port
        raw.write_u16::<BigEndian>(9).unwrap(); // length
        raw.write_u16::<BigEndian>(0).unwrap(); // checksum

        raw.write_u8(0x99).unwrap(); // payload
    }

    fn check_packet_headers(ipv4_packet: &Ipv4Packet) {
        let ipv4_header = ipv4_packet.ipv4_header();
        assert_eq!(20, ipv4_header.header_length());
        assert_eq!(32, ipv4_header.total_length());
        assert_eq!(Protocol::Udp, ipv4_header.protocol());
        assert_eq!(0x12345678, ipv4_header.source());
        assert_eq!(0x42424242, ipv4_header.destination());

        if let Some(&TransportHeaderData::Udp(ref udp_header)) = ipv4_packet.transport_header_data()
        {
            assert_eq!(1234, udp_header.source_port());
            assert_eq!(5678, udp_header.destination_port());
        } else {
            panic!("No UDP transport header");
        }
    }

    fn check_another_packet_headers(ipv4_packet: &Ipv4Packet) {
        let ipv4_header = ipv4_packet.ipv4_header();
        assert_eq!(20, ipv4_header.header_length());
        assert_eq!(29, ipv4_header.total_length());
        assert_eq!(Protocol::Udp, ipv4_header.protocol());
        assert_eq!(0x11111111, ipv4_header.source());
        assert_eq!(0x22222222, ipv4_header.destination());

        if let Some(&TransportHeaderData::Udp(ref udp_header)) = ipv4_packet.transport_header_data()
        {
            assert_eq!(1111, udp_header.source_port());
            assert_eq!(2222, udp_header.destination_port());
        } else {
            panic!("No UDP transport header");
        }
    }

    #[test]
    fn parse_ipv4_packet_buffer() {
        let raw = create_packet();
        let mut packet_buffer = Ipv4PacketBuffer::new();

        let mut cursor = io::Cursor::new(raw);
        packet_buffer.read_from(&mut cursor).unwrap();

        let packet = packet_buffer.as_ipv4_packet().unwrap();
        check_packet_headers(&packet);
    }

    #[test]
    fn parse_fragmented_ipv4_packet_buffer() {
        let raw = create_packet();
        let mut packet_buffer = Ipv4PacketBuffer::new();

        let mut cursor = io::Cursor::new(&raw[..14]);
        packet_buffer.read_from(&mut cursor).unwrap();

        assert!(packet_buffer.as_ipv4_packet().is_none());

        let mut cursor = io::Cursor::new(&raw[14..]);
        packet_buffer.read_from(&mut cursor).unwrap();

        let packet = packet_buffer.as_ipv4_packet().unwrap();
        check_packet_headers(&packet);
    }

    fn create_multi_packets() -> Vec<u8> {
        let mut raw = Vec::new();
        write_packet_to(&mut raw);
        write_another_packet_to(&mut raw);
        write_packet_to(&mut raw);
        raw
    }

    #[test]
    fn parse_multi_packets() {
        let raw = create_multi_packets();
        let mut packet_buffer = Ipv4PacketBuffer::new();

        let mut cursor = io::Cursor::new(raw);
        packet_buffer.read_from(&mut cursor).unwrap();

        check_packet_headers(&packet_buffer.as_ipv4_packet().unwrap());
        packet_buffer.next();
        check_another_packet_headers(&packet_buffer.as_ipv4_packet().unwrap());
        packet_buffer.next();
        check_packet_headers(&packet_buffer.as_ipv4_packet().unwrap());
        packet_buffer.next();

        assert!(packet_buffer.as_ipv4_packet().is_none());
    }

    fn ipv6_packet(next_header: u8, transport: &[u8]) -> Vec<u8> {
        let mut raw = Vec::with_capacity(40 + transport.len());
        raw.extend_from_slice(&[0x60, 0, 0, 0]);
        raw.write_u16::<BigEndian>(transport.len() as u16).unwrap();
        raw.write_u8(next_header).unwrap();
        raw.write_u8(64).unwrap();
        raw.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        raw.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        raw.extend_from_slice(transport);
        raw
    }

    #[test]
    fn unified_framing_parses_fragmented_ipv6_udp() {
        let udp = [0x04, 0xd2, 0x16, 0x2e, 0, 12, 0, 0, 0x11, 0x22, 0x33, 0x44];
        let raw = ipv6_packet(17, &udp);
        let mut buffer = IpPacketBuffer::new();
        buffer.read_from(&mut io::Cursor::new(&raw[..40])).unwrap();
        assert!(buffer.packet().unwrap().is_none());

        buffer.read_from(&mut io::Cursor::new(&raw[40..])).unwrap();
        match buffer.packet().unwrap().unwrap() {
            IpPacket::Ipv6(packet) => {
                let header = packet.ipv6_header();
                assert_eq!(52, packet.length());
                assert_eq!(17, header.next_header());
                assert_eq!(0x20010db8, u32::from_be_bytes(header.source()[..4].try_into().unwrap()));
                assert_eq!([0x11, 0x22, 0x33, 0x44], packet.payload().unwrap());
            }
            IpPacket::Ipv4(_) => panic!("expected an IPv6 packet"),
        }
    }

    #[test]
    fn unified_framing_parses_ipv6_tcp() {
        let mut tcp = [0; 20];
        tcp[..4].copy_from_slice(&[0x04, 0xd2, 0x16, 0x2e]);
        tcp[12] = 0x50;
        let raw = ipv6_packet(6, &tcp);
        let mut buffer = IpPacketBuffer::new();
        buffer.read_from(&mut io::Cursor::new(raw)).unwrap();

        match buffer.packet().unwrap().unwrap() {
            IpPacket::Ipv6(packet) => {
                assert_eq!(60, packet.length());
                let transport = packet.transport_header();
                assert_eq!(1234, transport.source_port());
                assert_eq!(5678, transport.destination_port());
                assert_eq!(Some(&[][..]), packet.payload());
            }
            IpPacket::Ipv4(_) => panic!("expected an IPv6 packet"),
        }
    }

    #[test]
    fn unified_framing_accepts_ipv4_dont_fragment_packets() {
        let mut raw = create_packet();
        raw[6] = 0x40; // DF only; MF and the fragment offset are clear.
        let mut buffer = IpPacketBuffer::new();
        buffer.read_from(&mut io::Cursor::new(raw)).unwrap();

        match buffer.packet().unwrap().unwrap() {
            IpPacket::Ipv4(packet) => assert_eq!(32, packet.length()),
            IpPacket::Ipv6(_) => panic!("expected an IPv4 packet"),
        }
    }

    #[test]
    fn unified_framing_accepts_the_largest_non_jumbo_ipv6_udp_packet() {
        let mut udp = vec![0; u16::MAX as usize];
        udp[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
        let raw = ipv6_packet(17, &udp);
        let mut buffer = IpPacketBuffer::new();
        buffer.read_from(&mut io::Cursor::new(raw)).unwrap();

        match buffer.packet().unwrap().unwrap() {
            IpPacket::Ipv6(packet) => assert_eq!(40 + u16::MAX as usize, packet.length()),
            IpPacket::Ipv4(_) => panic!("expected an IPv6 packet"),
        }
    }

    #[test]
    fn unified_framing_reports_ipv6_extension_and_fragment_headers_as_unsupported() {
        for (next_header, expected) in [
            (0, UnsupportedPacket::Ipv6ExtensionHeader(0)),
            (44, UnsupportedPacket::Ipv6FragmentHeader),
        ] {
            let raw = ipv6_packet(next_header, &[0; 8]);
            let mut buffer = IpPacketBuffer::new();
            buffer.read_from(&mut io::Cursor::new(raw)).unwrap();
            assert!(matches!(
                buffer.packet(),
                Err(PacketParseError::Unsupported(actual)) if actual == expected
            ));
            assert!(buffer.next().unwrap());
        }
    }

    #[test]
    fn unified_framing_rejects_malformed_ipv6_transport_without_panicking() {
        let raw = ipv6_packet(6, &[0; 8]);
        let mut buffer = IpPacketBuffer::new();
        buffer.read_from(&mut io::Cursor::new(raw)).unwrap();
        assert!(matches!(
            buffer.packet(),
            Err(PacketParseError::Malformed("truncated TCP header"))
        ));
    }

    #[test]
    fn unified_packet_parser_rejects_short_ipv4_input_without_panicking() {
        let mut raw = [0x45, 0];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            IpPacket::parse(&mut raw).map(|_| ())
        }));
        assert!(matches!(
            result,
            Ok(Err(PacketParseError::Malformed("truncated IPv4 packet")))
        ));
    }

    #[test]
    fn ipv6_packetizer_swaps_udp_endpoints_and_writes_a_pseudo_header_checksum() {
        let input = ipv6_packet(17, &[0x04, 0xd2, 0x16, 0x2e, 0, 8, 0, 0]);
        let mut input = input;
        let packet = match IpPacket::parse(&mut input).unwrap() {
            IpPacket::Ipv6(packet) => packet,
            IpPacket::Ipv4(_) => panic!("expected an IPv6 packet"),
        };
        let header = packet.ipv6_header();
        let transport = packet.transport_header();
        let mut packetizer = Ipv6Packetizer::new(&header, &transport);
        let mut host = MockDatagramSocket::from_data(&[0xaa, 0xbb]);
        let response = packetizer.packetize(&mut host).unwrap();

        assert_eq!(header.destination(), response.ipv6_header().source());
        assert_eq!(header.source(), response.ipv6_header().destination());
        assert_eq!(Some(&[0xaa, 0xbb][..]), response.payload());
        let raw = response.raw();
        assert_eq!(10, u16::from_be_bytes([raw[44], raw[45]]));
        assert_ne!(0, u16::from_be_bytes([raw[46], raw[47]]));
        assert_eq!(0xffff, checksum_words(&raw[8..24], &raw[24..40], &raw[40..]));
    }

    fn checksum_words(source: &[u8], destination: &[u8], transport: &[u8]) -> u16 {
        let mut sum = 0u32;
        for bytes in [source, destination] {
            for pair in bytes.chunks(2) {
                sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
            }
        }
        let length = transport.len() as u32;
        sum += length >> 16;
        sum += length & 0xffff;
        sum += 17; // next-header UDP
        for pair in transport.chunks(2) {
            sum += if pair.len() == 2 {
                u32::from(u16::from_be_bytes([pair[0], pair[1]]))
            } else {
                u32::from(pair[0]) << 8
            };
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }
}

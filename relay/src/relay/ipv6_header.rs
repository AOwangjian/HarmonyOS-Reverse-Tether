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

pub const IPV6_HEADER_LENGTH: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ipv6HeaderError {
    TruncatedHeader,
    InvalidVersion,
    TruncatedPayload,
}

pub struct Ipv6Header<'a> {
    raw: &'a [u8],
    data: &'a Ipv6HeaderData,
}

#[derive(Clone)]
pub struct Ipv6HeaderData {
    payload_length: u16,
    next_header: u8,
    source: [u8; 16],
    destination: [u8; 16],
}

impl Ipv6HeaderData {
    pub fn parse(raw: &[u8]) -> Result<Self, Ipv6HeaderError> {
        if raw.len() < IPV6_HEADER_LENGTH {
            return Err(Ipv6HeaderError::TruncatedHeader);
        }
        if raw[0] >> 4 != 6 {
            return Err(Ipv6HeaderError::InvalidVersion);
        }

        let payload_length = BigEndian::read_u16(&raw[4..6]);
        if raw.len() < IPV6_HEADER_LENGTH + usize::from(payload_length) {
            return Err(Ipv6HeaderError::TruncatedPayload);
        }

        let mut source = [0; 16];
        source.copy_from_slice(&raw[8..24]);
        let mut destination = [0; 16];
        destination.copy_from_slice(&raw[24..40]);
        Ok(Self {
            payload_length,
            next_header: raw[6],
            source,
            destination,
        })
    }

    /// Parse the 40-byte fixed header without requiring the payload to be present.
    ///
    /// A packetizer swaps the endpoints of a reference header before it knows how many
    /// payload bytes the host will return, so [`Self::parse`] would reject that buffer.
    pub fn parse_header_only(raw: &[u8]) -> Result<Self, Ipv6HeaderError> {
        if raw.len() < IPV6_HEADER_LENGTH {
            return Err(Ipv6HeaderError::TruncatedHeader);
        }
        if raw[0] >> 4 != 6 {
            return Err(Ipv6HeaderError::InvalidVersion);
        }

        let mut source = [0; 16];
        source.copy_from_slice(&raw[8..24]);
        let mut destination = [0; 16];
        destination.copy_from_slice(&raw[24..40]);
        Ok(Self {
            payload_length: BigEndian::read_u16(&raw[4..6]),
            next_header: raw[6],
            source,
            destination,
        })
    }

    #[inline]
    pub fn bind<'c, 'a: 'c, 'b: 'c>(&'a self, raw: &'b [u8]) -> Ipv6Header<'c> {
        Ipv6Header { raw, data: self }
    }

    #[inline]
    pub fn payload_length(&self) -> u16 {
        self.payload_length
    }

    #[inline]
    pub fn total_length(&self) -> usize {
        IPV6_HEADER_LENGTH + usize::from(self.payload_length)
    }

    #[inline]
    pub fn next_header(&self) -> u8 {
        self.next_header
    }

    #[inline]
    pub fn source(&self) -> [u8; 16] {
        self.source
    }

    #[inline]
    pub fn destination(&self) -> [u8; 16] {
        self.destination
    }
}

impl<'a> Ipv6Header<'a> {
    #[inline]
    pub fn raw(&self) -> &[u8] {
        self.raw
    }

    #[inline]
    pub fn data(&self) -> &Ipv6HeaderData {
        self.data
    }

    #[inline]
    pub fn payload_length(&self) -> u16 {
        self.data.payload_length()
    }

    #[inline]
    pub fn next_header(&self) -> u8 {
        self.data.next_header()
    }

    #[inline]
    pub fn source(&self) -> [u8; 16] {
        self.data.source()
    }

    #[inline]
    pub fn destination(&self) -> [u8; 16] {
        self.data.destination()
    }
}

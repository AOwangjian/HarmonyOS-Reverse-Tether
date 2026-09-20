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

use std::io;

use super::byte_buffer::ByteBuffer;
use super::ip_packet::{front_packet_length, IpPacket, PacketParseError, MAX_IP_PACKET_LENGTH};

pub struct IpPacketBuffer {
    buf: ByteBuffer,
}

impl IpPacketBuffer {
    pub fn new() -> Self {
        Self {
            buf: ByteBuffer::new(MAX_IP_PACKET_LENGTH),
        }
    }

    pub fn read_from<R: io::Read>(&mut self, source: &mut R) -> io::Result<bool> {
        self.buf.read_from(source)
    }

    pub fn packet(&mut self) -> Result<Option<IpPacket<'_>>, PacketParseError> {
        let length = match front_packet_length(self.buf.peek())? {
            Some(length) => length,
            None => return Ok(None),
        };
        let raw = &mut self.buf.peek_mut()[..length];
        IpPacket::parse(raw).map(Some)
    }

    pub fn next(&mut self) -> Result<bool, PacketParseError> {
        let length = match front_packet_length(self.buf.peek())? {
            Some(length) => length,
            None => return Ok(false),
        };
        self.buf.consume(length);
        Ok(true)
    }
}

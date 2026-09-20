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

use log::*;
use mio::net::{TcpStream, UdpSocket};
use mio::{Event, PollOpt, Ready, Token};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::rc::{Rc, Weak};
use std::time::Instant;

use super::client::{Client, ClientChannel};
use super::connection::{Connection, ConnectionId};
use super::ip_packet::IpPacket;
use super::ipv4_header::Protocol;
use super::ipv6_packetizer::Ipv6Packetizer;
use super::selector::Selector;

const TAG: &str = "Ipv6Connection";
const IDLE_TIMEOUT_SECONDS: u64 = 2 * 60;

enum Socket {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

/// Bidirectional IPv6 flow owner.
///
/// Outbound payloads are written straight to the host socket; inbound bytes are turned
/// back into well-formed IPv6 packets (including the RFC 8200 pseudo-header checksum)
/// by [`Ipv6Packetizer`] and pushed to the client.
pub struct Ipv6Connection {
    id: ConnectionId,
    client: Weak<RefCell<Client>>,
    socket: Socket,
    network_to_client: Ipv6Packetizer,
    token: Token,
    closed: bool,
    idle_since: Instant,
}

impl Ipv6Connection {
    pub fn create(
        selector: &mut Selector,
        id: ConnectionId,
        client: Weak<RefCell<Client>>,
        packetizer: Ipv6Packetizer,
    ) -> io::Result<Rc<RefCell<Self>>> {
        let destination = id.rewritten_destination();
        let socket = match id.protocol() {
            Protocol::Tcp => Socket::Tcp(TcpStream::connect(&destination)?),
            Protocol::Udp => {
                let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
                let socket = UdpSocket::bind(&bind)?;
                socket.connect(destination)?;
                Socket::Udp(socket)
            }
            Protocol::Other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported protocol",
                ));
            }
        };
        info!(target: TAG, "{} Open outbound IPv6 connection", id);

        let interests = Ready::readable();
        let rc = Rc::new(RefCell::new(Self {
            id,
            client,
            socket,
            network_to_client: packetizer,
            token: Token(0), // default value, will be set afterwards
            closed: false,
            idle_since: Instant::now(),
        }));

        {
            let mut self_ref = rc.borrow_mut();
            let rc2 = rc.clone();
            let handler =
                move |selector: &mut Selector, event| rc2.borrow_mut().on_ready(selector, event);
            let token = match self_ref.socket {
                Socket::Tcp(ref socket) => {
                    selector.register(socket, handler, interests, PollOpt::level())?
                }
                Socket::Udp(ref socket) => {
                    selector.register(socket, handler, interests, PollOpt::level())?
                }
            };
            self_ref.token = token;
        }
        Ok(rc)
    }

    fn remove_from_router(&self) {
        let client_rc = self.client.upgrade().expect("Expected client not found");
        let mut client = client_rc.borrow_mut();
        client.router().remove(self);
    }

    fn on_ready(&mut self, selector: &mut Selector, event: Event) {
        match self.process(selector, event) {
            Ok(_) => (),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                debug!(target: TAG, "{} Spurious event, ignoring", self.id)
            }
            Err(err) => {
                // Do not panic: crashing the relay kills every other flow.
                error!(
                    target: TAG,
                    "{} Unexpected error in on_ready, closing connection: [{:?}] {}",
                    self.id,
                    err.kind(),
                    err
                );
                if !self.closed {
                    self.close(selector);
                }
                self.remove_from_router();
            }
        }
    }

    fn process(&mut self, selector: &mut Selector, event: Event) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        if event.readiness().is_readable() {
            self.process_receive(selector)?;
        }
        if self.closed {
            self.remove_from_router();
        }
        Ok(())
    }

    // return Err(err) with err.kind() == io::ErrorKind::WouldBlock on spurious event
    fn process_receive(&mut self, selector: &mut Selector) -> io::Result<()> {
        match self.read(selector) {
            Ok(_) => (),
            Err(err) => {
                if err.kind() == io::ErrorKind::WouldBlock {
                    // rethrow
                    return Err(err);
                }
                error!(
                    target: TAG,
                    "{} Cannot read: [{:?}] {}",
                    self.id,
                    err.kind(),
                    err
                );
                self.close(selector);
            }
        }
        Ok(())
    }

    fn read(&mut self, selector: &mut Selector) -> io::Result<()> {
        // Synthesize the response packet first, then hand its bytes to the client.
        let raw = {
            let packet = match self.socket {
                Socket::Tcp(ref mut socket) => {
                    self.network_to_client.packetize_read(socket, None)?
                }
                Socket::Udp(ref mut socket) => {
                    Some(self.network_to_client.packetize(socket)?)
                }
            };
            match packet {
                Some(packet) => packet.raw().to_vec(),
                None => {
                    // EOF on a TCP host socket: nothing left to relay.
                    self.close(selector);
                    return Ok(());
                }
            }
        };

        self.idle_since = Instant::now();
        let client_rc = self.client.upgrade().expect("Expected client not found");
        match client_rc
            .borrow_mut()
            .send_raw_to_client(selector, &raw)
        {
            Ok(_) => {
                debug!(
                    target: TAG,
                    "{} IPv6 packet ({} bytes) sent to client",
                    self.id,
                    raw.len()
                );
            }
            Err(err) => {
                warn!(
                    target: TAG,
                    "{} Cannot send to client, dropping packet: {}", self.id, err
                );
            }
        }
        Ok(())
    }
}

impl Connection for Ipv6Connection {
    fn id(&self) -> &ConnectionId {
        &self.id
    }

    fn send_to_network(
        &mut self,
        _: &mut Selector,
        _: &mut ClientChannel,
        packet: &IpPacket,
    ) {
        let payload = match packet {
            IpPacket::Ipv6(packet) => packet.payload().unwrap_or(&[]),
            IpPacket::Ipv4(_) => return,
        };
        self.idle_since = Instant::now();
        if payload.is_empty() {
            return;
        }
        let result = match self.socket {
            Socket::Tcp(ref mut socket) => socket.write(payload),
            Socket::Udp(ref mut socket) => socket.send(payload),
        };
        if let Err(error) = result {
            if error.kind() != io::ErrorKind::WouldBlock {
                warn!(target: TAG, "{} Cannot write IPv6 payload: {}", self.id, error);
                self.closed = true;
            }
        }
    }

    fn close(&mut self, selector: &mut Selector) {
        if self.closed {
            return;
        }
        self.closed = true;
        match self.socket {
            Socket::Tcp(ref socket) => selector.deregister(socket, self.token).ok(),
            Socket::Udp(ref socket) => selector.deregister(socket, self.token).ok(),
        };
    }

    fn is_expired(&self) -> bool {
        self.idle_since.elapsed().as_secs() > IDLE_TIMEOUT_SECONDS
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

// `Read` is required by `packetize_read`, which drives the TCP host socket.
impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Socket::Tcp(socket) => socket.read(buf),
            Socket::Udp(socket) => socket.recv(buf),
        }
    }
}

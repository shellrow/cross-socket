use std::net::{IpAddr, SocketAddr};
use pnet::packet::Packet;

/// UDP Header Length
pub const UDP_HEADER_LEN: usize = 8;
/// UDP BASE Destination Port. Usually used for traceroute.
pub const UDP_BASE_DST_PORT: u16 = 33435;

/// Represents the UDP packet.
#[derive(Clone, Debug, PartialEq)]
pub struct UdpPacket {
    /// Source Port
    pub source: u16,
    /// Destination Port
    pub destination: u16,
    /// Length
    pub length: u16,
    /// Checksum
    pub checksum: u16,
    /// Payload
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub(crate) fn from_pnet_packet(packet: &pnet::packet::udp::UdpPacket) -> UdpPacket {
        UdpPacket {
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.get_length(),
            checksum: packet.get_checksum(),
            payload: packet.payload().to_vec(),
        }
    }
    /// Constructs a new UdpPacket from bytes
    pub fn from_bytes(packet: &[u8]) -> UdpPacket {
        let udp_packet = pnet::packet::udp::UdpPacket::new(packet).unwrap();
        UdpPacket::from_pnet_packet(&udp_packet)
    }
}

pub(crate) fn build_udp_packet(
    udp_packet: &mut pnet::packet::udp::MutableUdpPacket,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) {
    udp_packet.set_length(8);
    udp_packet.set_source(src_port);
    udp_packet.set_destination(dst_port);
    match src_ip {
        IpAddr::V4(src_ip) => match dst_ip {
            IpAddr::V4(dst_ip) => {
                let checksum =
                    pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
                udp_packet.set_checksum(checksum);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(src_ip) => match dst_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(dst_ip) => {
                let checksum =
                    pnet::packet::udp::ipv6_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
                udp_packet.set_checksum(checksum);
            }
        },
    }
}

/// UDP Packet Builder
#[derive(Clone, Debug)]
pub struct UdpPacketBuilder {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Source Port
    pub src_port: u16,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Destination Port
    pub dst_port: u16,
    /// Payload
    pub payload: Vec<u8>,
}

impl UdpPacketBuilder {
    /// Constructs a new UdpPacketBuilder
    pub fn new(src_addr: SocketAddr, dst_addr: SocketAddr) -> Self {
        UdpPacketBuilder {
            src_ip: src_addr.ip(),
            src_port: src_addr.port(),
            dst_ip: dst_addr.ip(),
            dst_port: dst_addr.port(),
            payload: Vec::new(),
        }
    }
    /// Builds a new UdpPacket and return bytes
    pub fn build(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; UDP_HEADER_LEN + self.payload.len()];
        let mut udp_packet = pnet::packet::udp::MutableUdpPacket::new(&mut buffer).unwrap();
        udp_packet.set_source(self.src_port);
        udp_packet.set_destination(self.dst_port);
        if self.payload.len() > 0 {
            udp_packet.set_payload(&self.payload);
        }
        udp_packet.set_length(UDP_HEADER_LEN as u16 + self.payload.len() as u16);
        match self.src_ip {
            IpAddr::V4(src_ip) => match self.dst_ip {
                IpAddr::V4(dst_ip) => {
                    let checksum =
                        pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
                    udp_packet.set_checksum(checksum);
                }
                IpAddr::V6(_) => {}
            },
            IpAddr::V6(src_ip) => match self.dst_ip {
                IpAddr::V4(_) => {}
                IpAddr::V6(dst_ip) => {
                    let checksum =
                        pnet::packet::udp::ipv6_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
                    udp_packet.set_checksum(checksum);
                }
            },
        }
        udp_packet.packet().to_vec()
    }
}
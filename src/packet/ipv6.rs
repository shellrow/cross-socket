use std::net::Ipv6Addr;
use pnet::packet::Packet;
use super::ip::IpNextLevelProtocol;

/// IPv6 Header Length
pub const IPV6_HEADER_LEN: usize = pnet::packet::ipv6::MutableIpv6Packet::minimum_packet_size();

/// Represents the IPv6 options.
#[derive(Clone, Debug, PartialEq)]
pub struct Ipv6Packet {
    /// IP Version
    pub version: u8,
    /// Traffic Class
    pub traffic_class: u8,
    /// Flow Label
    pub flow_label: u32,
    /// Payload Length
    pub payload_length: u16,
    /// Next Header
    pub next_header: IpNextLevelProtocol,
    /// Hop Limit
    pub hop_limit: u8,
    /// Source IPv6 Address
    pub source: Ipv6Addr,
    /// Destination IPv6 Address
    pub destination: Ipv6Addr,
    /// Payload. Next level protocol packet.
    pub payload: Vec<u8>,
}

impl Ipv6Packet {
    pub(crate) fn from_pnet_packet(packet: &pnet::packet::ipv6::Ipv6Packet) -> Ipv6Packet {
        Ipv6Packet {
            version: packet.get_version(),
            traffic_class: packet.get_traffic_class(),
            flow_label: packet.get_flow_label(),
            payload_length: packet.get_payload_length(),
            next_header: IpNextLevelProtocol::from_u8(packet.get_next_header().0),
            hop_limit: packet.get_hop_limit(),
            source: packet.get_source(),
            destination: packet.get_destination(),
            payload: packet.payload().to_vec(),
        }
    }
    /// Constructs a new Ipv6Packet from bytes
    pub fn from_bytes(packet: &[u8]) -> Ipv6Packet {
        let ipv6_packet = pnet::packet::ipv6::Ipv6Packet::new(packet).unwrap();
        Ipv6Packet::from_pnet_packet(&ipv6_packet)
    }
}

pub(crate) fn build_ipv6_packet(
    ipv6_packet: &mut pnet::packet::ipv6::MutableIpv6Packet,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    next_protocol: IpNextLevelProtocol,
) {
    ipv6_packet.set_source(src_ip);
    ipv6_packet.set_destination(dst_ip);
    ipv6_packet.set_version(6);
    ipv6_packet.set_hop_limit(64);
    match next_protocol {
        IpNextLevelProtocol::Tcp => {
            ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
            ipv6_packet.set_payload_length(32);
        }
        IpNextLevelProtocol::Udp => {
            ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Udp);
            ipv6_packet.set_payload_length(8);
        }
        IpNextLevelProtocol::Icmpv6 => {
            ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Icmpv6);
            ipv6_packet.set_payload_length(8);
        }
        _ => {}
    }
}

/// IPv6 Packet Builder
#[derive(Clone, Debug)]
pub struct Ipv6PacketBuilder {
    /// Source IPv6 address
    pub src_ip: Ipv6Addr,
    /// Destination IPv6 address
    pub dst_ip: Ipv6Addr,
    /// Next level protocol
    pub next_protocol: IpNextLevelProtocol,
    /// Hop Limit
    pub hop_limit: Option<u8>,
}

impl Ipv6PacketBuilder {
    /// Constructs a new Ipv6PacketBuilder
    pub fn new(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, next_protocol: IpNextLevelProtocol) -> Self {
        Ipv6PacketBuilder {
            src_ip,
            dst_ip,
            next_protocol,
            hop_limit: None,
        }
    }
    /// Buid IPv6 packet and return bytes
    pub fn build(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; IPV6_HEADER_LEN];
        let mut ipv6_packet = pnet::packet::ipv6::MutableIpv6Packet::new(&mut buffer).unwrap();
        build_ipv6_packet(
            &mut ipv6_packet,
            self.src_ip,
            self.dst_ip,
            self.next_protocol,
        );
        if let Some(hop_limit) = self.hop_limit {
            ipv6_packet.set_hop_limit(hop_limit);
        }
        ipv6_packet.packet().to_vec()
    }
}
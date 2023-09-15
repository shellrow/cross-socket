use std::net::Ipv6Addr;
use pnet::packet::Packet;
use super::ip::IpNextLevelProtocol;

#[derive(Clone, Debug, PartialEq)]
pub struct Ipv6Packet {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: IpNextLevelProtocol,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub payload: Vec<u8>,
}

impl Ipv6Packet {
    pub fn from_pnet_packet(packet: &pnet::packet::ipv6::Ipv6Packet) -> Ipv6Packet {
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
}

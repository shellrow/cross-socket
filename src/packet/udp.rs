use std::net::IpAddr;
use pnet::packet::Packet;

pub const UDP_HEADER_LEN: usize = 8;
pub const UDP_BASE_DST_PORT: u16 = 33435;

#[derive(Clone, Debug, PartialEq)]
pub struct UdpPacket {
    pub source: u16,
    pub destination: u16,
    pub length: u16,
    pub checksum: u16,
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
}

pub fn build_udp_packet(
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

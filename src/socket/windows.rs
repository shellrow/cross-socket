use std::{io, net::IpAddr};
use crate::packet::{self, PacketInfo, builder};

fn build_packet(packet_info: PacketInfo, tmp_packet: &mut [u8]) {
    let packet = builder::build_tcp_syn_packet(packet_info);
    tmp_packet.copy_from_slice(&packet);
}

pub(crate) fn build_and_send_packet(tx: &mut Box<dyn pnet::datalink::DataLinkSender>, packet_info: PacketInfo) -> io::Result<usize> {
    let packet_size: usize = match packet_info.dst_ip {
        IpAddr::V4(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
            + packet::ipv4::IPV4_HEADER_LEN
            + packet::tcp::TCP_HEADER_LEN
            + packet::tcp::TCP_DEFAULT_OPTION_LEN,
        IpAddr::V6(_ip) => packet::ethernet::ETHERNET_HEADER_LEN
            + packet::ipv6::IPV6_HEADER_LEN
            + packet::tcp::TCP_HEADER_LEN
            + packet::tcp::TCP_DEFAULT_OPTION_LEN,
    };
    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
        build_packet(packet_info.clone(), packet);
    });
    Ok(packet_size)
}

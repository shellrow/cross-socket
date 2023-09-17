use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use pnet::packet::Packet;
use crate::packet;

pub fn build_arp_packet(packet_info: packet::PacketInfo) -> Vec<u8> {
    let src_ip: Ipv4Addr = match packet_info.src_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv4Addr = match packet_info.dst_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::arp::ARP_HEADER_LEN];
    let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    packet::ethernet::build_ethernet_arp_packet(&mut ethernet_packet, packet_info.src_mac.clone(), packet_info.ether_type);
    let mut arp_buffer = [0u8; packet::arp::ARP_HEADER_LEN];
    let mut arp_packet = pnet::packet::arp::MutableArpPacket::new(&mut arp_buffer).unwrap();
    packet::arp::build_arp_packet(&mut arp_packet, packet_info.src_mac, packet_info.dst_mac, src_ip, dst_ip);
    ethernet_packet.set_payload(arp_packet.packet());
    ethernet_packet.packet().to_vec()
}

pub fn build_icmp_packet(packet_info: packet::PacketInfo) -> Vec<u8> {
    let src_ip: Ipv4Addr = match packet_info.src_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv4Addr = match packet_info.dst_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::icmp::ICMPV4_HEADER_LEN];
    let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_info.src_mac.clone(), packet_info.dst_mac.clone(), packet_info.ether_type);
    let mut ipv4_buffer = [0u8; packet::ipv4::IPV4_HEADER_LEN + packet::icmp::ICMPV4_HEADER_LEN];
    let mut ipv4_packet = pnet::packet::ipv4::MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    packet::ipv4::build_ipv4_packet(&mut ipv4_packet, src_ip, dst_ip, packet_info.ip_protocol.unwrap());
    let mut icmp_buffer = [0u8; packet::icmp::ICMPV4_HEADER_LEN];
    let mut icmp_packet = pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(
        &mut icmp_buffer,
    )
    .unwrap();
    packet::icmp::build_icmp_echo_packet(&mut icmp_packet);
    ipv4_packet.set_payload(icmp_packet.packet());
    ethernet_packet.set_payload(ipv4_packet.packet());
    ethernet_packet.packet().to_vec()
}

pub fn build_icmpv6_packet(packet_info: packet::PacketInfo) -> Vec<u8> {
    let src_ip: Ipv6Addr = match packet_info.src_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv6Addr = match packet_info.dst_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + packet::icmpv6::ICMPV6_HEADER_LEN];
    let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_info.src_mac.clone(), packet_info.dst_mac.clone(), packet_info.ether_type);
    let mut ipv6_buffer = [0u8; packet::ipv6::IPV6_HEADER_LEN + packet::icmpv6::ICMPV6_HEADER_LEN];
    let mut ipv6_packet = pnet::packet::ipv6::MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
    packet::ipv6::build_ipv6_packet(&mut ipv6_packet, src_ip, dst_ip, packet_info.ip_protocol.unwrap());
    let mut icmpv6_buffer = [0u8; packet::icmpv6::ICMPV6_HEADER_LEN];
    let mut icmpv6_packet = pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket::new(
        &mut icmpv6_buffer,
    )
    .unwrap();
    packet::icmpv6::build_icmpv6_echo_packet(&mut icmpv6_packet, src_ip, dst_ip);
    ipv6_packet.set_payload(icmpv6_packet.packet());
    ethernet_packet.set_payload(ipv6_packet.packet());
    ethernet_packet.packet().to_vec()
}

pub fn build_tcp_syn_packet(packet_info: packet::PacketInfo) -> Vec<u8> {
    match packet_info.src_ip {
        IpAddr::V4(src_ip) => match packet_info.dst_ip {
            IpAddr::V4(dst_ip) => {
                let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_info.src_mac.clone(), packet_info.dst_mac.clone(), packet_info.ether_type);
                let mut ipv4_buffer = [0u8; packet::ipv4::IPV4_HEADER_LEN + packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut ipv4_packet = pnet::packet::ipv4::MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
                packet::ipv4::build_ipv4_packet(&mut ipv4_packet, src_ip, dst_ip, packet_info.ip_protocol.unwrap());
                let mut tcp_buffer = [0u8; packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(&mut tcp_buffer).unwrap();
                packet::tcp::build_tcp_packet(&mut tcp_packet, packet_info.src_ip, packet_info.src_port.unwrap(), packet_info.dst_ip, packet_info.dst_port.unwrap());
                ipv4_packet.set_payload(tcp_packet.packet());
                ethernet_packet.set_payload(ipv4_packet.packet());
                ethernet_packet.packet().to_vec()
            }
            IpAddr::V6(_) => {
                return Vec::new()
            }
        },
        IpAddr::V6(src_ip) => match packet_info.dst_ip {
            IpAddr::V4(_) => {
                return Vec::new()
            }
            IpAddr::V6(dst_ip) => {
                let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_info.src_mac.clone(), packet_info.dst_mac.clone(), packet_info.ether_type);
                let mut ipv6_buffer = [0u8; packet::ipv6::IPV6_HEADER_LEN + packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut ipv6_packet = pnet::packet::ipv6::MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
                packet::ipv6::build_ipv6_packet(&mut ipv6_packet, src_ip, dst_ip, packet_info.ip_protocol.unwrap());
                let mut tcp_buffer = [0u8; packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(&mut tcp_buffer).unwrap();
                packet::tcp::build_tcp_packet(&mut tcp_packet, packet_info.src_ip, packet_info.src_port.unwrap(), packet_info.dst_ip, packet_info.dst_port.unwrap());
                ipv6_packet.set_payload(tcp_packet.packet());
                ethernet_packet.set_payload(ipv6_packet.packet());
                ethernet_packet.packet().to_vec()
            }
        }
    }
}

pub fn build_udp_packet(packet_info: packet::PacketInfo) -> Vec<u8> {
    match packet_info.src_ip {
        IpAddr::V4(src_ip) => match packet_info.dst_ip {
            IpAddr::V4(dst_ip) => {
                let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::udp::UDP_HEADER_LEN];
                let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_info.src_mac.clone(), packet_info.dst_mac.clone(), packet_info.ether_type);
                let mut ipv4_buffer = [0u8; packet::ipv4::IPV4_HEADER_LEN + packet::udp::UDP_HEADER_LEN];
                let mut ipv4_packet = pnet::packet::ipv4::MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
                packet::ipv4::build_ipv4_packet(&mut ipv4_packet, src_ip, dst_ip, packet_info.ip_protocol.unwrap());
                let mut udp_buffer = [0u8; packet::udp::UDP_HEADER_LEN];
                let mut udp_packet = pnet::packet::udp::MutableUdpPacket::new(&mut udp_buffer).unwrap();
                packet::udp::build_udp_packet(&mut udp_packet, packet_info.src_ip, packet_info.src_port.unwrap(), packet_info.dst_ip, packet_info.dst_port.unwrap());
                ipv4_packet.set_payload(udp_packet.packet());
                ethernet_packet.set_payload(ipv4_packet.packet());
                ethernet_packet.packet().to_vec()
            }
            IpAddr::V6(_) => {
                return Vec::new()
            }
        },
        IpAddr::V6(src_ip) => match packet_info.dst_ip {
            IpAddr::V4(_) => {
                return Vec::new()
            }
            IpAddr::V6(dst_ip) => {
                let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + packet::udp::UDP_HEADER_LEN];
                let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_info.src_mac.clone(), packet_info.dst_mac.clone(), packet_info.ether_type);
                let mut ipv6_buffer = [0u8; packet::ipv6::IPV6_HEADER_LEN + packet::udp::UDP_HEADER_LEN];
                let mut ipv6_packet = pnet::packet::ipv6::MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
                packet::ipv6::build_ipv6_packet(&mut ipv6_packet, src_ip, dst_ip, packet_info.ip_protocol.unwrap());
                let mut udp_buffer = [0u8; packet::udp::UDP_HEADER_LEN];
                let mut udp_packet = pnet::packet::udp::MutableUdpPacket::new(&mut udp_buffer).unwrap();
                packet::udp::build_udp_packet(&mut udp_packet, packet_info.src_ip, packet_info.src_port.unwrap(), packet_info.dst_ip, packet_info.dst_port.unwrap());
                ipv6_packet.set_payload(udp_packet.packet());
                ethernet_packet.set_payload(ipv6_packet.packet());
                ethernet_packet.packet().to_vec()
            }
        }
    }
}
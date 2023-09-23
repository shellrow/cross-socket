use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use pnet::packet::Packet;
use crate::packet;
use crate::packet::{ethernet, ip};
use crate::datalink;

#[derive(Clone, Debug)]
pub struct PacketBuilder {
    packet: Vec<u8>,
}

impl PacketBuilder {
    pub fn new() -> Self {
        PacketBuilder {
            packet: Vec::new(),
        }
    }
    pub fn packet(&self) -> Vec<u8> {
        self.packet.clone()
    }
    pub fn set_ethernet(&mut self, packet_builder: packet::ethernet::EthernetPacketBuilder) {
        if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN {
            self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN, 0);
        }
        self.packet[0..packet::ethernet::ETHERNET_HEADER_LEN].copy_from_slice(&packet_builder.build());
    }
    pub fn set_arp(&mut self, packet_builder: packet::arp::ArpPacketBuilder) {
        let arp_packet = packet_builder.build();
        if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN + arp_packet.len() {
            self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN + arp_packet.len(), 0);
        }
        self.packet[packet::ethernet::ETHERNET_HEADER_LEN..packet::ethernet::ETHERNET_HEADER_LEN + arp_packet.len()].copy_from_slice(&arp_packet);
    }
    pub fn set_ipv4(&mut self, packet_builder: packet::ipv4::Ipv4PacketBuilder) {
        let ipv4_packet = packet_builder.build();
        if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN + ipv4_packet.len() {
            self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN + ipv4_packet.len(), 0);
        }
        self.packet[packet::ethernet::ETHERNET_HEADER_LEN..packet::ethernet::ETHERNET_HEADER_LEN + ipv4_packet.len()].copy_from_slice(&ipv4_packet);
    }
    pub fn set_ipv6(&mut self, packet_builder: packet::ipv6::Ipv6PacketBuilder) {
        let ipv6_packet = packet_builder.build();
        if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN + ipv6_packet.len() {
            self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN + ipv6_packet.len(), 0);
        }
        self.packet[packet::ethernet::ETHERNET_HEADER_LEN..packet::ethernet::ETHERNET_HEADER_LEN + ipv6_packet.len()].copy_from_slice(&ipv6_packet);
    }
    pub fn set_icmp(&mut self, packet_builder: packet::icmp::IcmpPacketBuilder) {
        let icmp_packet = packet_builder.build();
        if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + icmp_packet.len() {
            self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + icmp_packet.len(), 0);
        }
        self.packet[packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN..packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + icmp_packet.len()].copy_from_slice(&icmp_packet);
    }
    pub fn set_icmpv6(&mut self, packet_builder: packet::icmpv6::Icmpv6PacketBuilder) {
        let icmpv6_packet = packet_builder.build();
        if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + icmpv6_packet.len() {
            self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + icmpv6_packet.len(), 0);
        }
        self.packet[packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN..packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + icmpv6_packet.len()].copy_from_slice(&icmpv6_packet);
    }
    pub fn set_tcp(&mut self, packet_builder: packet::tcp::TcpPacketBuilder) {
        let tcp_packet = packet_builder.build();
        if packet_builder.dst_ip.is_ipv4() {
            if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + tcp_packet.len() {
                self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + tcp_packet.len(), 0);
            }
            self.packet[packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN..packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + tcp_packet.len()].copy_from_slice(&tcp_packet);
        } else if packet_builder.dst_ip.is_ipv6() {
            if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + tcp_packet.len() {
                self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + tcp_packet.len(), 0);
            }
            self.packet[packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN..packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + tcp_packet.len()].copy_from_slice(&tcp_packet);
        }
    }
    pub fn set_udp(&mut self, packet_builder: packet::udp::UdpPacketBuilder) {
        let udp_packet = packet_builder.build();
        if packet_builder.dst_ip.is_ipv4() {
            if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + udp_packet.len() {
                self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + udp_packet.len(), 0);
            }
            self.packet[packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN..packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + udp_packet.len()].copy_from_slice(&udp_packet);
        } else if packet_builder.dst_ip.is_ipv6() {
            if self.packet.len() < packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + udp_packet.len() {
                self.packet.resize(packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + udp_packet.len(), 0);
            }
            self.packet[packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN..packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + udp_packet.len()].copy_from_slice(&udp_packet);
        }
    }
}

/// Higher level packet build option.
/// For building, use PacketBuilder or protocol specific packet builder.
#[derive(Clone, Debug)]
pub struct PacketBuildOption {
    pub src_mac: datalink::MacAddr,
    pub dst_mac: datalink::MacAddr,
    pub ether_type: ethernet::EtherType,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ip_protocol: Option<ip::IpNextLevelProtocol>,
    pub payload: Vec<u8>,
}

impl PacketBuildOption {
    pub fn new() -> Self {
        PacketBuildOption {
            src_mac: datalink::MacAddr::zero(),
            dst_mac: datalink::MacAddr::zero(),
            ether_type: ethernet::EtherType::Ipv4,
            src_ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            dst_ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            src_port: None,
            dst_port: None,
            ip_protocol: None,
            payload: Vec::new(),
        }
    }
}

/// Build ARP Packet from PacketInfo
pub fn build_full_arp_packet(packet_builder: PacketBuildOption) -> Vec<u8> {
    let src_ip: Ipv4Addr = match packet_builder.src_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv4Addr = match packet_builder.dst_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::arp::ARP_HEADER_LEN];
    let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    packet::ethernet::build_ethernet_arp_packet(&mut ethernet_packet, packet_builder.src_mac.clone());
    let mut arp_buffer = [0u8; packet::arp::ARP_HEADER_LEN];
    let mut arp_packet = pnet::packet::arp::MutableArpPacket::new(&mut arp_buffer).unwrap();
    packet::arp::build_arp_packet(&mut arp_packet, packet_builder.src_mac, packet_builder.dst_mac, src_ip, dst_ip);
    ethernet_packet.set_payload(arp_packet.packet());
    ethernet_packet.packet().to_vec()
}

/// Build ICMP Packet from PacketInfo. Build full packet with ethernet and ipv4 header.
pub fn build_full_icmp_packet(packet_builder: PacketBuildOption) -> Vec<u8> {
    let src_ip: Ipv4Addr = match packet_builder.src_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv4Addr = match packet_builder.dst_ip {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        _ => return Vec::new(),
    };
    let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::icmp::ICMPV4_HEADER_LEN];
    let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_builder.src_mac.clone(), packet_builder.dst_mac.clone(), packet_builder.ether_type);
    let mut ipv4_buffer = [0u8; packet::ipv4::IPV4_HEADER_LEN + packet::icmp::ICMPV4_HEADER_LEN];
    let mut ipv4_packet = pnet::packet::ipv4::MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    packet::ipv4::build_ipv4_packet(&mut ipv4_packet, src_ip, dst_ip, packet_builder.ip_protocol.unwrap());
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

/// Build ICMP Packet from PacketInfo. Build only icmp packet.
pub fn build_icmp_packet() -> Vec<u8> {
    let mut icmp_buffer = [0u8; packet::icmp::ICMPV4_HEADER_LEN];
    let mut icmp_packet = pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(
        &mut icmp_buffer,
    )
    .unwrap();
    packet::icmp::build_icmp_echo_packet(&mut icmp_packet);
    icmp_packet.packet().to_vec()
}

/// Build ICMPv6 Packet from PacketInfo. Build full packet with ethernet and ipv6 header.
pub fn build_full_icmpv6_packet(packet_builder: PacketBuildOption) -> Vec<u8> {
    let src_ip: Ipv6Addr = match packet_builder.src_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv6Addr = match packet_builder.dst_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + packet::icmpv6::ICMPV6_HEADER_LEN];
    let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_builder.src_mac.clone(), packet_builder.dst_mac.clone(), packet_builder.ether_type);
    let mut ipv6_buffer = [0u8; packet::ipv6::IPV6_HEADER_LEN + packet::icmpv6::ICMPV6_HEADER_LEN];
    let mut ipv6_packet = pnet::packet::ipv6::MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
    packet::ipv6::build_ipv6_packet(&mut ipv6_packet, src_ip, dst_ip, packet_builder.ip_protocol.unwrap());
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

/// Build ICMPv6 Packet from PacketInfo. Build only icmpv6 packet.
pub fn build_icmpv6_packet(packet_builder: PacketBuildOption) -> Vec<u8> {
    let src_ip: Ipv6Addr = match packet_builder.src_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let dst_ip: Ipv6Addr = match packet_builder.dst_ip {
        IpAddr::V6(ipv6_addr) => ipv6_addr,
        _ => return Vec::new(),
    };
    let mut icmpv6_buffer = [0u8; packet::icmpv6::ICMPV6_HEADER_LEN];
    let mut icmpv6_packet = pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket::new(
        &mut icmpv6_buffer,
    )
    .unwrap();
    packet::icmpv6::build_icmpv6_echo_packet(&mut icmpv6_packet, src_ip, dst_ip);
    icmpv6_packet.packet().to_vec()
}

/// Build TCP Packet from PacketInfo. Build full packet with ethernet and ipv4 header.
pub fn build_full_tcp_syn_packet(packet_builder: PacketBuildOption) -> Vec<u8> {
    match packet_builder.src_ip {
        IpAddr::V4(src_ip) => match packet_builder.dst_ip {
            IpAddr::V4(dst_ip) => {
                let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_builder.src_mac.clone(), packet_builder.dst_mac.clone(), packet_builder.ether_type);
                let mut ipv4_buffer = [0u8; packet::ipv4::IPV4_HEADER_LEN + packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut ipv4_packet = pnet::packet::ipv4::MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
                packet::ipv4::build_ipv4_packet(&mut ipv4_packet, src_ip, dst_ip, packet_builder.ip_protocol.unwrap());
                let mut tcp_buffer = [0u8; packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(&mut tcp_buffer).unwrap();
                packet::tcp::build_tcp_packet(&mut tcp_packet, packet_builder.src_ip, packet_builder.src_port.unwrap(), packet_builder.dst_ip, packet_builder.dst_port.unwrap());
                ipv4_packet.set_payload(tcp_packet.packet());
                ethernet_packet.set_payload(ipv4_packet.packet());
                ethernet_packet.packet().to_vec()
            }
            IpAddr::V6(_) => {
                return Vec::new()
            }
        },
        IpAddr::V6(src_ip) => match packet_builder.dst_ip {
            IpAddr::V4(_) => {
                return Vec::new()
            }
            IpAddr::V6(dst_ip) => {
                let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_builder.src_mac.clone(), packet_builder.dst_mac.clone(), packet_builder.ether_type);
                let mut ipv6_buffer = [0u8; packet::ipv6::IPV6_HEADER_LEN + packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut ipv6_packet = pnet::packet::ipv6::MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
                packet::ipv6::build_ipv6_packet(&mut ipv6_packet, src_ip, dst_ip, packet_builder.ip_protocol.unwrap());
                let mut tcp_buffer = [0u8; packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
                let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(&mut tcp_buffer).unwrap();
                packet::tcp::build_tcp_packet(&mut tcp_packet, packet_builder.src_ip, packet_builder.src_port.unwrap(), packet_builder.dst_ip, packet_builder.dst_port.unwrap());
                ipv6_packet.set_payload(tcp_packet.packet());
                ethernet_packet.set_payload(ipv6_packet.packet());
                ethernet_packet.packet().to_vec()
            }
        }
    }
}

/// Build TCP Packet from PacketInfo. Build only tcp packet.
pub fn build_tcp_syn_packet(packet_builder: PacketBuildOption) -> Vec<u8> {
    let mut tcp_buffer = [0u8; packet::tcp::TCP_HEADER_LEN + packet::tcp::TCP_DEFAULT_OPTION_LEN];
    let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    packet::tcp::build_tcp_packet(&mut tcp_packet, packet_builder.src_ip, packet_builder.src_port.unwrap(), packet_builder.dst_ip, packet_builder.dst_port.unwrap());
    tcp_packet.packet().to_vec()
}

/// Build UDP Packet from PacketInfo. Build full packet with ethernet and ipv4 header.
pub fn build_full_udp_packet(packet_builder: PacketBuildOption) -> Vec<u8> {
    match packet_builder.src_ip {
        IpAddr::V4(src_ip) => match packet_builder.dst_ip {
            IpAddr::V4(dst_ip) => {
                let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv4::IPV4_HEADER_LEN + packet::udp::UDP_HEADER_LEN];
                let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_builder.src_mac.clone(), packet_builder.dst_mac.clone(), packet_builder.ether_type);
                let mut ipv4_buffer = [0u8; packet::ipv4::IPV4_HEADER_LEN + packet::udp::UDP_HEADER_LEN];
                let mut ipv4_packet = pnet::packet::ipv4::MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
                packet::ipv4::build_ipv4_packet(&mut ipv4_packet, src_ip, dst_ip, packet_builder.ip_protocol.unwrap());
                let mut udp_buffer = [0u8; packet::udp::UDP_HEADER_LEN];
                let mut udp_packet = pnet::packet::udp::MutableUdpPacket::new(&mut udp_buffer).unwrap();
                packet::udp::build_udp_packet(&mut udp_packet, packet_builder.src_ip, packet_builder.src_port.unwrap(), packet_builder.dst_ip, packet_builder.dst_port.unwrap());
                ipv4_packet.set_payload(udp_packet.packet());
                ethernet_packet.set_payload(ipv4_packet.packet());
                ethernet_packet.packet().to_vec()
            }
            IpAddr::V6(_) => {
                return Vec::new()
            }
        },
        IpAddr::V6(src_ip) => match packet_builder.dst_ip {
            IpAddr::V4(_) => {
                return Vec::new()
            }
            IpAddr::V6(dst_ip) => {
                let mut ethernet_buffer = [0u8; packet::ethernet::ETHERNET_HEADER_LEN + packet::ipv6::IPV6_HEADER_LEN + packet::udp::UDP_HEADER_LEN];
                let mut ethernet_packet:pnet::packet::ethernet::MutableEthernetPacket = pnet::packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
                packet::ethernet::build_ethernet_packet(&mut ethernet_packet, packet_builder.src_mac.clone(), packet_builder.dst_mac.clone(), packet_builder.ether_type);
                let mut ipv6_buffer = [0u8; packet::ipv6::IPV6_HEADER_LEN + packet::udp::UDP_HEADER_LEN];
                let mut ipv6_packet = pnet::packet::ipv6::MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
                packet::ipv6::build_ipv6_packet(&mut ipv6_packet, src_ip, dst_ip, packet_builder.ip_protocol.unwrap());
                let mut udp_buffer = [0u8; packet::udp::UDP_HEADER_LEN];
                let mut udp_packet = pnet::packet::udp::MutableUdpPacket::new(&mut udp_buffer).unwrap();
                packet::udp::build_udp_packet(&mut udp_packet, packet_builder.src_ip, packet_builder.src_port.unwrap(), packet_builder.dst_ip, packet_builder.dst_port.unwrap());
                ipv6_packet.set_payload(udp_packet.packet());
                ethernet_packet.set_payload(ipv6_packet.packet());
                ethernet_packet.packet().to_vec()
            }
        }
    }
}

/// Build UDP Packet from PacketInfo. Build only udp packet.
pub fn build_udp_packet(packet_builder: PacketBuildOption) -> Vec<u8> {
    let mut udp_buffer = [0u8; packet::udp::UDP_HEADER_LEN];
    let mut udp_packet = pnet::packet::udp::MutableUdpPacket::new(&mut udp_buffer).unwrap();
    packet::udp::build_udp_packet(&mut udp_packet, packet_builder.src_ip, packet_builder.src_port.unwrap(), packet_builder.dst_ip, packet_builder.dst_port.unwrap());
    udp_packet.packet().to_vec()
}

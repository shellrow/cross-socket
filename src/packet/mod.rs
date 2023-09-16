pub mod arp;
pub mod dhcp;
pub mod ethernet;
pub mod gre;
pub mod ip;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;
pub mod icmp;
pub mod icmpv6;
pub mod builder;

use std::net::IpAddr;
use crate::datalink;

/// Packet Capture information
#[derive(Clone, Debug, PartialEq)]
pub struct CaptureInfo {
    /// Capture number
    pub capture_no: usize,
    /// Capture datetime
    pub datatime: String,
    /// Capture length
    pub capture_len: usize,
    /// interface index
    pub interface_index: u32,
    /// Interface name
    pub interface_name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PacketFrame {
    pub capture_info: CaptureInfo,
    pub ethernet_packet: Option<ethernet::EthernetPacket>,
    pub arp_packet: Option<arp::ArpPacket>,
    pub ipv4_packet: Option<ipv4::Ipv4Packet>,
    pub ipv6_packet: Option<ipv6::Ipv6Packet>,
    pub icmp_packet: Option<icmp::IcmpPacket>,
    pub icmpv6_packet: Option<icmpv6::Icmpv6Packet>,
    pub tcp_packet: Option<tcp::TcpPacket>,
    pub udp_packet: Option<udp::UdpPacket>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PacketInfo {
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

use std::net::{IpAddr, Ipv4Addr};
use serde::{Deserialize, Serialize};
use crate::sys;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketFrame {
    /// Capture number.
    pub capture_no: usize,
    // Packet arrival time. RFC3339 format.
    pub timestamp: String,
    /// interface index
    pub if_index: u32,
    /// interface name.
    pub if_name: String,
    /// src mac address.
    pub src_mac: String,
    /// dst mac address.
    pub dst_mac: String,
    /// src ip address.
    pub src_ip: IpAddr,
    /// dst ip address.
    pub dst_ip: IpAddr,
    /// src port.
    pub src_port: u16,
    /// dst port.
    pub dst_port: u16,
    /// Protocol.
    pub protocol: String,
    /// Packet length.
    pub packet_len: usize,
}

impl PacketFrame {
    pub fn new() -> Self {
        PacketFrame {
            capture_no: 0,
            timestamp: String::new(),
            if_index: 0,
            if_name: String::new(),
            src_mac: String::new(),
            dst_mac: String::new(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            protocol: String::new(),
            packet_len: 0,
        }
    }
    pub fn from_xenet_frame(capture_no: usize, if_index: u32, if_name: String, frame: xenet::packet::frame::Frame) -> PacketFrame {
        let mut simple_frame = PacketFrame::new();
        simple_frame.capture_no = capture_no;
        simple_frame.timestamp = sys::get_sysdate();
        simple_frame.if_index = if_index;
        simple_frame.if_name = if_name;
        if let Some(datalink) = frame.datalink {
            if let Some(ethernet) = datalink.ethernet {
                simple_frame.src_mac = ethernet.source.address();
                simple_frame.dst_mac = ethernet.destination.address();
                simple_frame.protocol = ethernet.ethertype.name().to_string();
            }
            if let Some(arp) = datalink.arp {
                simple_frame.src_mac = arp.sender_hw_addr.address();
                simple_frame.dst_mac = arp.target_hw_addr.address();
                simple_frame.src_ip = IpAddr::V4(arp.sender_proto_addr);
                simple_frame.dst_ip = IpAddr::V4(arp.target_proto_addr);
                simple_frame.protocol = "ARP".to_string();
            }
        }
        if let Some(ip) = frame.ip {
            if let Some(ipv4) = ip.ipv4 {
                simple_frame.src_ip = IpAddr::V4(ipv4.source);
                simple_frame.dst_ip = IpAddr::V4(ipv4.destination);
                simple_frame.protocol = ipv4.next_level_protocol.as_str().to_uppercase();
            }
            if let Some(ipv6) = ip.ipv6 {
                simple_frame.src_ip = IpAddr::V6(ipv6.source);
                simple_frame.dst_ip = IpAddr::V6(ipv6.destination);
                simple_frame.protocol = ipv6.next_header.as_str().to_uppercase();
            }
        }
        if let Some(transport) = frame.transport {
            if let Some(tcp) = transport.tcp {
                simple_frame.src_port = tcp.source;
                simple_frame.dst_port = tcp.destination;
                simple_frame.protocol = "TCP".to_string();
            }
            if let Some(udp) = transport.udp {
                simple_frame.src_port = udp.source;
                simple_frame.dst_port = udp.destination;
                simple_frame.protocol = "UDP".to_string();
            }
        }
        if simple_frame.protocol.is_empty() {
            simple_frame.protocol = "UNKNOWN".to_string();
        }
        simple_frame.packet_len = frame.packet_len;
        simple_frame
    }
}
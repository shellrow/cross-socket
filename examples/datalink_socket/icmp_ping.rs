use std::net::IpAddr;

use cross_socket::socket::DataLinkSocket;
use cross_socket::packet::ethernet::EtherType;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::PacketInfo;
use cross_socket::datalink::interface::Interface;
// Send ICMP Echo Request packets to 1.1.1.1 and check reply
fn main() {
    let interface: Interface = cross_socket::datalink::interface::get_default_interface().unwrap();
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Create packet info
    let mut packet_info = PacketInfo::new();
    packet_info.src_mac = socket.interface.mac_addr.clone().unwrap();
    packet_info.dst_mac = socket.interface.gateway.clone().unwrap().mac_addr;
    packet_info.ether_type = EtherType::Ipv4;
    packet_info.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_info.dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
    packet_info.src_port = None;
    packet_info.dst_port = None;
    packet_info.ip_protocol = Some(IpNextLevelProtocol::Icmp);
    packet_info.payload = vec![0; 0];

    // Send ICMP Echo Request packets to 1.1.1.1
    match socket.send(packet_info) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Receive packets
    println!("Waiting for ICMP Echo Reply... ");
    loop {
        match socket.receive() {
            Ok(packet) => {
                let ethernet_packet = cross_socket::packet::ethernet::EthernetPacket::from_bytes(&packet);
                if ethernet_packet.ethertype != EtherType::Ipv4 {
                    continue;
                }
                let ip_packet = cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&ethernet_packet.payload);
                if ip_packet.next_level_protocol != IpNextLevelProtocol::Icmp || ip_packet.source != std::net::Ipv4Addr::new(1, 1, 1, 1) {
                    continue;
                }
                println!("Received {} bytes from {}", packet.len(), ip_packet.source);
                let icmp_packet = cross_socket::packet::icmp::IcmpPacket::from_bytes(&ip_packet.payload);
                println!("Packet: {:?}", icmp_packet);
                break;
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    
}

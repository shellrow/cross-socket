use std::net::IpAddr;

use cross_socket::socket::DataLinkSocket;
use cross_socket::packet::ethernet;
use cross_socket::packet::builder::PacketBuildOption;
use cross_socket::datalink::interface::Interface;
use cross_socket::datalink::MacAddr;

// Send ARP request to default gateway and check mac address
fn main() {
    let interface: Interface = cross_socket::datalink::interface::get_default_interface().unwrap();
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Packet option for ARP request
    let mut packet_option = PacketBuildOption::new();
    packet_option.src_mac = socket.interface.mac_addr.clone().unwrap();
    packet_option.dst_mac = MacAddr::zero();
    packet_option.ether_type = cross_socket::packet::ethernet::EtherType::Arp;
    packet_option.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_option.dst_ip = socket.interface.gateway.clone().unwrap().ip_addr;

    // Send ARP request to default gateway
    match socket.send(packet_option) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
    let src_mac = socket.interface.mac_addr.clone().unwrap();
    // Receive packets
    println!("Waiting for ARP reply... ");
    loop {
        match socket.receive() {
            Ok(packet) => {
                let ethernet_packet = ethernet::EthernetPacket::from_bytes(&packet);
                if ethernet_packet.ethertype != cross_socket::packet::ethernet::EtherType::Arp {
                    continue;
                }
                let arp_packet = cross_socket::packet::arp::ArpPacket::from_bytes(&ethernet_packet.payload);
                if arp_packet.sender_hw_addr.address() != src_mac.address() {
                    println!("Received {} bytes from {}", packet.len(), arp_packet.sender_hw_addr.address());
                    println!("Packet: {:?}", arp_packet);
                    break;
                }
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

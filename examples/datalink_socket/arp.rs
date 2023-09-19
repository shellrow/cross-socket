use std::net::IpAddr;

use cross_socket::socket::DataLinkSocket;
use cross_socket::packet::{ethernet, builder};
use cross_socket::packet::builder::PacketBuilder;
use cross_socket::datalink::interface::Interface;
use cross_socket::datalink::MacAddr;

// Send ARP request to default gateway and check mac address
fn main() {
    let interface: Interface = cross_socket::datalink::interface::get_default_interface().unwrap();
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Packet builder for ARP request
    let mut packet_buider = PacketBuilder::new();
    packet_buider.src_mac = socket.interface.mac_addr.clone().unwrap();
    packet_buider.dst_mac = MacAddr::zero();
    packet_buider.ether_type = cross_socket::packet::ethernet::EtherType::Arp;
    packet_buider.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_buider.dst_ip = socket.interface.gateway.clone().unwrap().ip_addr;

    // Build ARP packet
    let arp_packet = builder::build_arp_packet(packet_buider);

    // Send ARP request to default gateway
    match socket.send_to(&arp_packet) {
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

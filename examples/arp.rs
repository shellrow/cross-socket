use std::net::IpAddr;

use cross_socket::socket::DataLinkSocket;
use cross_socket::packet::PacketInfo;
use cross_socket::interface::Interface;
use cross_socket::datalink::MacAddr;

// Send ARP request to default gateway and check mac address
fn main() {
    let interface: Interface = cross_socket::interface::get_default_interface().unwrap();
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Create packet info for ARP request
    let mut packet_info = PacketInfo::new();
    packet_info.src_mac = socket.interface.mac_addr.clone().unwrap();
    packet_info.dst_mac = MacAddr::zero();
    packet_info.ether_type = cross_socket::packet::ethernet::EtherType::Arp;
    packet_info.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_info.dst_ip = socket.interface.gateway.clone().unwrap().ip_addr;

    // Send ARP request to default gateway
    match socket.send(packet_info) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Receive packets
    match socket.receive() {
        Ok(packet) => {
            println!("Received {} bytes", packet.len());
            println!("Packet: {:?}", packet);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
    for _x in 0..2 {
        match socket.receive() {
            Ok(packet) => {
                println!("Received {} bytes", packet.len());
                println!("Packet: {:?}", packet);
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

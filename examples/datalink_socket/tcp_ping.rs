use std::net::IpAddr;

use cross_socket::socket::DataLinkSocket;
use cross_socket::packet::ethernet::EtherType;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::builder::PacketBuilder;
use cross_socket::datalink::interface::Interface;
// Send TCP SYN packets to 1.1.1.1:80 and check if the port is open
fn main() {
    let interface: Interface = cross_socket::datalink::interface::get_default_interface().unwrap();
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Packet builder for TCP SYN
    let mut packet_builder = PacketBuilder::new();
    packet_builder.src_mac = socket.interface.mac_addr.clone().unwrap();
    packet_builder.dst_mac = socket.interface.gateway.clone().unwrap().mac_addr;
    packet_builder.ether_type = EtherType::Ipv4;
    packet_builder.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_builder.dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
    packet_builder.src_port = Some(53443);
    packet_builder.dst_port = Some(80);
    packet_builder.ip_protocol = Some(IpNextLevelProtocol::Tcp);
    packet_builder.payload = vec![0; 0];

    // Send TCP SYN packets to 1.1.1.1:80
    match socket.send(packet_builder) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Receive packets
    println!("Waiting for TCP SYN+ACK... ");
    loop {
        match socket.receive() {
            Ok(packet) => {
                let ethernet_packet = cross_socket::packet::ethernet::EthernetPacket::from_bytes(&packet);
                if ethernet_packet.ethertype != EtherType::Ipv4 {
                    continue;
                }
                let ip_packet = cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&ethernet_packet.payload);
                if ip_packet.next_level_protocol != IpNextLevelProtocol::Tcp || ip_packet.source != std::net::Ipv4Addr::new(1, 1, 1, 1) {
                    continue;
                }
                println!("Received {} bytes from {}", packet.len(), ip_packet.source);
                let tcp_packet = cross_socket::packet::tcp::TcpPacket::from_bytes(&ip_packet.payload);
                println!("Packet: {:?}", tcp_packet);
                break;
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    
}

use std::net::IpAddr;
use std::env;
use cross_socket::datalink::interface::Interface;
use cross_socket::packet::builder::PacketBuildOption;
use cross_socket::packet::ethernet::EtherType;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::socket::DataLinkSocket;
// Send TCP SYN packets to 1.1.1.1:80 and check if the port is open
fn main() {
    let interface: Interface = match env::args().nth(1) {
        Some(n) => {
            // Use interface specified by user
            let interfaces: Vec<Interface> = default_net::get_interfaces();
            let interface: Interface = interfaces
                .into_iter()
                .find(|interface| interface.name == n)
                .expect("Failed to get interface information");
            interface
        },
        None => {
            // Use default interface
            default_net::get_default_interface().expect("Failed to get default interface information")
        }
    };
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Packet builder for TCP SYN
    let mut packet_option = PacketBuildOption::new();
    packet_option.src_mac = socket.interface.mac_addr.clone().unwrap();
    packet_option.dst_mac = socket.interface.gateway.clone().unwrap().mac_addr;
    packet_option.ether_type = EtherType::Ipv4;
    packet_option.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_option.dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
    packet_option.src_port = Some(53443);
    packet_option.dst_port = Some(80);
    packet_option.ip_protocol = Some(IpNextLevelProtocol::Tcp);
    packet_option.payload = vec![0; 0];

    // Send TCP SYN packets to 1.1.1.1:80
    match socket.send(packet_option) {
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
                let ethernet_packet =
                    cross_socket::packet::ethernet::EthernetPacket::from_bytes(&packet);
                if ethernet_packet.ethertype != EtherType::Ipv4 {
                    continue;
                }
                let ip_packet =
                    cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&ethernet_packet.payload);
                if ip_packet.next_protocol != IpNextLevelProtocol::Tcp
                    || ip_packet.source != std::net::Ipv4Addr::new(1, 1, 1, 1)
                {
                    continue;
                }
                println!("Received {} bytes from {}", packet.len(), ip_packet.source);
                let tcp_packet =
                    cross_socket::packet::tcp::TcpPacket::from_bytes(&ip_packet.payload);
                println!("Packet: {:?}", tcp_packet);
                break;
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

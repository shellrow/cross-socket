use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::env;
use cross_socket::datalink::interface::Interface;
use cross_socket::packet::builder::PacketBuilder;
use cross_socket::packet::ethernet::{EtherType, EthernetPacketBuilder};
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::ipv4::Ipv4PacketBuilder;
use cross_socket::packet::tcp::{TcpFlag, TcpOption, TcpPacketBuilder};
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
    let is_tun: bool = interface.is_tun();
    let dst_ip: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    //
    // Packet builder for TCP SYN
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: socket.interface.mac_addr.clone().unwrap(),
        dst_mac: socket.interface.gateway.clone().unwrap().mac_addr,
        ether_type: EtherType::Ipv4,
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    let ipv4_packet_builder = Ipv4PacketBuilder::new(
        socket.interface.ipv4[0].addr,
        dst_ip,
        IpNextLevelProtocol::Tcp,
    );
    packet_builder.set_ipv4(ipv4_packet_builder);
    let mut tcp_packet_builder = TcpPacketBuilder::new(
        SocketAddr::new(IpAddr::V4(socket.interface.ipv4[0].addr), 53443),
        SocketAddr::new(IpAddr::V4(dst_ip), 80),
    );
    tcp_packet_builder.flags = vec![TcpFlag::Syn];
    tcp_packet_builder.options = vec![
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(7),
    ];
    packet_builder.set_tcp(tcp_packet_builder);

    // Send TCP SYN packets to 1.1.1.1:80
    match socket.send_to(&packet_builder.packet()) {
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
                if is_tun {
                    let ip_packet =
                        cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&packet);
                    if ip_packet.next_protocol != IpNextLevelProtocol::Tcp
                        || ip_packet.source != dst_ip
                    {
                        continue;
                    }
                    println!("Received {} bytes from {}", packet.len(), ip_packet.source);
                    let tcp_packet =
                        cross_socket::packet::tcp::TcpPacket::from_bytes(&ip_packet.payload);
                    println!("Packet: {:?}", tcp_packet);
                    break;
                } else {
                    let ethernet_packet =
                    cross_socket::packet::ethernet::EthernetPacket::from_bytes(&packet);
                    if ethernet_packet.ethertype != EtherType::Ipv4 {
                        continue;
                    }
                    let ip_packet =
                        cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&ethernet_packet.payload);
                    if ip_packet.next_protocol != IpNextLevelProtocol::Tcp
                        || ip_packet.source != dst_ip
                    {
                        continue;
                    }
                    println!("Received {} bytes from {}", packet.len(), ip_packet.source);
                    let tcp_packet =
                        cross_socket::packet::tcp::TcpPacket::from_bytes(&ip_packet.payload);
                    println!("Packet: {:?}", tcp_packet);
                    break;
                }
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

use std::net::{IpAddr, Ipv4Addr};
use std::env;
use cross_socket::datalink::interface::Interface;
use cross_socket::packet::builder::PacketBuildOption;
use cross_socket::packet::ethernet::EtherType;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::socket::DataLinkSocket;
use default_net::interface::MacAddr;
// Send UDP packets to 1.1.1.1:33435 and check ICMP Port Unreachable reply
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
    let use_tun: bool = interface.is_tun();
    let dst_ip: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Packet builder for UDP packet. Expect ICMP Destination (Port) Unreachable.
    let mut packet_option = PacketBuildOption::new();
    packet_option.use_tun = use_tun;
    packet_option.src_mac = if use_tun { MacAddr::zero() } else { socket.interface.mac_addr.clone().unwrap() };
    packet_option.dst_mac = if use_tun { MacAddr::zero() } else { socket.interface.gateway.clone().unwrap().mac_addr };
    packet_option.ether_type = EtherType::Ipv4;
    packet_option.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_option.dst_ip = IpAddr::V4(dst_ip);
    packet_option.src_port = Some(53443);
    packet_option.dst_port = Some(33435);
    packet_option.ip_protocol = Some(IpNextLevelProtocol::Udp);
    packet_option.payload = vec![0; 0];

    // Send UDP packets to 1.1.1.1:33435
    match socket.send(packet_option) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Receive packets
    println!("Waiting for ICMP Destination (Port) Unreachable...");
    loop {
        match socket.receive() {
            Ok(packet) => {
                if use_tun {
                    let ip_packet =
                        cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&packet);
                    if ip_packet.next_protocol != IpNextLevelProtocol::Icmp
                        || ip_packet.source != dst_ip
                    {
                        continue;
                    }
                    println!("Received {} bytes from {}", packet.len(), ip_packet.source);
                    let icmp_packet =
                        cross_socket::packet::icmp::IcmpPacket::from_bytes(&ip_packet.payload);
                    println!("Packet: {:?}", icmp_packet);
                    break;
                } else {
                    let ethernet_packet =
                    cross_socket::packet::ethernet::EthernetPacket::from_bytes(&packet);
                    if ethernet_packet.ethertype != EtherType::Ipv4 {
                        continue;
                    }
                    let ip_packet =
                        cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&ethernet_packet.payload);
                    if ip_packet.next_protocol != IpNextLevelProtocol::Icmp
                        || ip_packet.source != dst_ip
                    {
                        continue;
                    }
                    println!("Received {} bytes from {}", packet.len(), ip_packet.source);
                    let icmp_packet =
                        cross_socket::packet::icmp::IcmpPacket::from_bytes(&ip_packet.payload);
                    println!("Packet: {:?}", icmp_packet);
                    break;
                }
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

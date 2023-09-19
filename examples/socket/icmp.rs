use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use cross_socket::socket::{Socket, SocketOption, IpVersion, SocketType};
use cross_socket::packet::{PacketInfo, ip::IpNextLevelProtocol};
use cross_socket::datalink::interface::Interface;

// Send ICMP Echo Request packets to 1.1.1.1 and check reply
fn main() {
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let interface: Interface = cross_socket::datalink::interface::get_default_interface().unwrap();
    let socket_option = SocketOption {
        ip_version: IpVersion::V4,
        socket_type: SocketType::Raw,
        protocol: Some(IpNextLevelProtocol::Icmp),
        timeout: None,
        ttl: None,
        non_blocking: false,
    };
    let socket: Socket = Socket::new(socket_option).unwrap();
    // Create packet info
    let mut packet_info = PacketInfo::new();
    packet_info.src_ip = IpAddr::V4(interface.ipv4[0].addr);
    packet_info.dst_ip = dst_ip;
    packet_info.ip_protocol = Some(IpNextLevelProtocol::Icmp);
    packet_info.payload = vec![0; 0];

    // Build ICMP Echo Request packet
    let icmp_packet = cross_socket::packet::builder::build_icmp_packet();

    // Send ICMP Echo Request packets to 1.1.1.1
    let socket_addr = SocketAddr::new(dst_ip, 0);
    match socket.send_to(&icmp_packet, socket_addr) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Receive ICMP Echo Reply packets from 1.1.1.1
    println!("Waiting for ICMP Echo Reply... ");
    let mut buf = vec![0; 512];
    let (packet_len, _) = socket.receive_from(&mut buf).unwrap();
    let ip_packet = cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&buf[..packet_len]);
    println!("Received {} bytes from {}", packet_len, ip_packet.source);
    let icmp_packet = cross_socket::packet::icmp::IcmpPacket::from_bytes(&ip_packet.payload);
    println!("Packet: {:?}", icmp_packet);
}

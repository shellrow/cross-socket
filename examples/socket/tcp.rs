use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use cross_socket::socket::{Socket, SocketOption, IpVersion, SocketType};
use cross_socket::packet::{PacketInfo, ip::IpNextLevelProtocol};
use cross_socket::interface::Interface;

// Send TCP SYN packets to 1.1.1.1:80 and check reply
fn main() {
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let socket_addr: SocketAddr = SocketAddr::new(dst_ip, 80);
    let interface: Interface = cross_socket::interface::get_default_interface().unwrap();
    let socket_option = SocketOption {
        ip_version: IpVersion::V4,
        socket_type: SocketType::Raw,
        protocol: Some(IpNextLevelProtocol::Tcp),
        timeout: None,
        ttl: None,
    };
    let socket: Socket = Socket::new(socket_option).unwrap();
    // Create packet info
    let mut packet_info = PacketInfo::new();
    packet_info.src_ip = IpAddr::V4(interface.ipv4[0].addr);
    packet_info.dst_ip = socket_addr.ip();
    packet_info.src_port = Some(53443);
    packet_info.dst_port = Some(socket_addr.port());
    packet_info.ip_protocol = Some(IpNextLevelProtocol::Tcp);
    packet_info.payload = vec![0; 0];

    // Build TCP SYN packet
    let tcp_packet = cross_socket::packet::builder::build_tcp_syn_packet(packet_info);

    // Send TCP SYN packet to 1.1.1.1
    match socket.send_to(&tcp_packet, socket_addr) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Receive TCP SYN packets from 1.1.1.1
    println!("Waiting for TCP SYN+ACK... ");
    let mut buf = vec![0; 512];
    let (packet_len, _) = socket.receive_from(&mut buf).unwrap();
    let ip_packet = cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&buf[..packet_len]);
    println!("Received {} bytes from {}", packet_len, ip_packet.source);
    let tcp_packet = cross_socket::packet::tcp::TcpPacket::from_bytes(&ip_packet.payload);
    println!("Packet: {:?}", tcp_packet);
}

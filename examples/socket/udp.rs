use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use cross_socket::socket::{Socket, SocketOption, IpVersion, SocketType, ListenerSocket};
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::builder::PacketBuilder;
use cross_socket::datalink::interface::Interface;

// Send UDP packets to 1.1.1.1:33435 and check ICMP Port Unreachable reply
fn main() {
    let interface: Interface = cross_socket::datalink::interface::get_default_interface().unwrap();
    let src_ip: IpAddr = IpAddr::V4(interface.ipv4[0].addr);
    let src_socket_addr: SocketAddr = SocketAddr::new(src_ip, 0);
    let dst_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let dst_socket_addr: SocketAddr = SocketAddr::new(dst_ip, 33435);
    let socket_option = SocketOption {
        ip_version: IpVersion::V4,
        socket_type: SocketType::Dgram,
        protocol: Some(IpNextLevelProtocol::Udp),
        timeout: None,
        ttl: None,
        non_blocking: false,
    };
    // Sender socket
    let socket: Socket = Socket::new(socket_option).unwrap();

    // Receiver socket
    let listener_socket: ListenerSocket = ListenerSocket::new(src_socket_addr, IpVersion::V4, None, Some(Duration::from_millis(1000))).unwrap();

    // Packet builder for UDP packet. Expect ICMP Destination (Port) Unreachable.
    let mut packet_builder = PacketBuilder::new();
    packet_builder.src_ip = src_ip;
    packet_builder.dst_ip = dst_socket_addr.ip();
    packet_builder.src_port = Some(53443);
    packet_builder.dst_port = Some(dst_socket_addr.port());
    packet_builder.ip_protocol = Some(IpNextLevelProtocol::Udp);
    packet_builder.payload = vec![0; 0];

    // Build UDP packet
    let udp_packet = cross_socket::packet::builder::build_udp_packet(packet_builder);

    // Send UDP packets to 1.1.1.1:33435
    match socket.send_to(&udp_packet, dst_socket_addr) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Receive ICMP Port Unreachable packets
    println!("Waiting for ICMP Destination (Port) Unreachable...");
    let mut buf = vec![0; 512];
    loop {
        match listener_socket.receive_from(&mut buf){
            Ok((packet_len, _)) => {
                let ip_packet = cross_socket::packet::ipv4::Ipv4Packet::from_bytes(&buf[..packet_len]);
                if ip_packet.next_level_protocol != IpNextLevelProtocol::Icmp || ip_packet.source != std::net::Ipv4Addr::new(1, 1, 1, 1) {
                    continue;
                }
                println!("Received {} bytes from {}", packet_len, ip_packet.source);
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

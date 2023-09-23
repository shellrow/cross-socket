use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use cross_socket::socket::{Socket, SocketOption, IpVersion, SocketType};
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::icmp::IcmpPacketBuilder;
use cross_socket::datalink::interface::Interface;

// Send ICMP Echo Request packets to 1.1.1.1 and check reply
fn main() {
    let interface: Interface = cross_socket::datalink::interface::get_default_interface().unwrap();
    let src_ip: Ipv4Addr = interface.ipv4[0].addr;
    let dst_ip: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    let socket_option = SocketOption {
        ip_version: IpVersion::V4,
        socket_type: SocketType::Raw,
        protocol: Some(IpNextLevelProtocol::Icmp),
        timeout: None,
        ttl: None,
        non_blocking: false,
    };
    let socket: Socket = Socket::new(socket_option).unwrap();
    // Packet builder for ICMP Echo Request
    let mut packet_builder = IcmpPacketBuilder::new(src_ip, dst_ip);
    packet_builder.icmp_type = cross_socket::packet::icmp::IcmpType::EchoRequest;

    // Build ICMP Echo Request packet
    let icmp_packet = packet_builder.build();

    // Send ICMP Echo Request packets to 1.1.1.1
    let socket_addr = SocketAddr::new(IpAddr::V4(dst_ip), 0);
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

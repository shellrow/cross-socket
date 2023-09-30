use cross_socket::datalink::interface::Interface;
use cross_socket::packet::builder::PacketBuilder;
use cross_socket::packet::ethernet::{EtherType, EthernetPacketBuilder};
use cross_socket::packet::icmpv6::Icmpv6PacketBuilder;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::ipv6::Ipv6PacketBuilder;
use cross_socket::socket::DataLinkSocket;
use std::net::Ipv6Addr;
// Send ICMP Echo Request packets to 2606:4700:4700::1111 and check reply
fn main() {
    let interface: Interface = cross_socket::datalink::interface::get_default_interface().unwrap();
    let src_ip: Ipv6Addr = interface.ipv6[0].addr;
    let dst_ip: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Packet builder for ICMP Echo Request
    let mut packet_builder = PacketBuilder::new();
    let ethernet_packet_builder = EthernetPacketBuilder {
        src_mac: socket.interface.mac_addr.clone().unwrap(),
        dst_mac: socket.interface.gateway.clone().unwrap().mac_addr,
        ether_type: EtherType::Ipv6,
    };
    packet_builder.set_ethernet(ethernet_packet_builder);
    let ipv6_packet_builder = Ipv6PacketBuilder::new(src_ip, dst_ip, IpNextLevelProtocol::Icmpv6);
    packet_builder.set_ipv6(ipv6_packet_builder);
    let mut icmpv6_packet_builder = Icmpv6PacketBuilder::new(src_ip, dst_ip);
    icmpv6_packet_builder.icmpv6_type = cross_socket::packet::icmpv6::Icmpv6Type::EchoRequest;
    packet_builder.set_icmpv6(icmpv6_packet_builder);

    // Send ICMP Echo Request packets to 2606:4700:4700::1111
    match socket.send_to(&packet_builder.packet()) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Receive packets
    println!("Waiting for ICMP Echo Reply... ");
    loop {
        match socket.receive() {
            Ok(packet) => {
                let ethernet_packet =
                    cross_socket::packet::ethernet::EthernetPacket::from_bytes(&packet);
                if ethernet_packet.ethertype != EtherType::Ipv6 {
                    continue;
                }
                let ip_packet =
                    cross_socket::packet::ipv6::Ipv6Packet::from_bytes(&ethernet_packet.payload);
                if ip_packet.next_protocol != IpNextLevelProtocol::Icmpv6
                    || ip_packet.source != dst_ip
                {
                    continue;
                }
                println!("Received {} bytes from {}", packet.len(), ip_packet.source);
                let icmp_packet =
                    cross_socket::packet::icmpv6::Icmpv6Packet::from_bytes(&ip_packet.payload);
                println!("Packet: {:?}", icmp_packet);
                break;
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

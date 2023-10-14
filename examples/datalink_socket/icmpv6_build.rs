use cross_socket::datalink::interface::Interface;
use cross_socket::packet::builder::PacketBuilder;
use cross_socket::packet::ethernet::{EtherType, EthernetPacketBuilder};
use cross_socket::packet::icmpv6::Icmpv6PacketBuilder;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::ipv6::Ipv6PacketBuilder;
use cross_socket::socket::DataLinkSocket;
use std::net::Ipv6Addr;
use std::env;

fn is_global_ipv6(ipv6_addr: &Ipv6Addr) -> bool {
    !(ipv6_addr.is_unspecified()
        || ipv6_addr.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(ipv6_addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(ipv6_addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(ipv6_addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(ipv6_addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(
                // Port Control Protocol Anycast (`2001:1::1`)
                u128::from_be_bytes(ipv6_addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                || u128::from_be_bytes(ipv6_addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                // AMT (`2001:3::/32`)
                || matches!(ipv6_addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                // AS112-v6 (`2001:4:112::/48`)
                || matches!(ipv6_addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                // ORCHIDv2 (`2001:20::/28`)
                || matches!(ipv6_addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
            ))
        // Reserved for documentation
        || ((ipv6_addr.segments()[0] == 0x2001) && (ipv6_addr.segments()[1] == 0x2) && (ipv6_addr.segments()[2] == 0))
        // Unique Local Address
        || ((ipv6_addr.segments()[0] & 0xfe00) == 0xfc00)
        // unicast address with link-local scope (`fc00::/7`)
        || ((ipv6_addr.segments()[0] & 0xffc0) == 0xfe80))
}

fn get_global_ipv6(interface: &Interface) -> Option<Ipv6Addr> {
    interface.ipv6.iter().find(|ipv6| is_global_ipv6(&ipv6.addr)).map(|ipv6| ipv6.addr)
}

// Send ICMP Echo Request packets to 2606:4700:4700::1111 and check reply
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
    let src_ip: Ipv6Addr = get_global_ipv6(&interface).expect("Failed to get global IPv6 address");
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
    let packet = if use_tun {packet_builder.ip_packet()} else {packet_builder.packet()};
    match socket.send_to(&packet) {
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
                if use_tun {
                    let ip_packet =
                        cross_socket::packet::ipv6::Ipv6Packet::from_bytes(&packet);
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
                } else {
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
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

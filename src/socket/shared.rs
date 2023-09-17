use std::io;
use crate::packet::{self, PacketInfo, builder};

fn build_packet(packet_info: PacketInfo, tmp_packet: &mut [u8]) {
    match packet_info.ether_type {
        packet::ethernet::EtherType::Arp => {
            let packet = builder::build_arp_packet(packet_info);
            tmp_packet.copy_from_slice(&packet);
            return;
        }
        packet::ethernet::EtherType::Ipv4 => {
            match packet_info.ip_protocol {
                Some(packet::ip::IpNextLevelProtocol::Icmp) => {
                    let packet = builder::build_icmp_packet(packet_info);
                    tmp_packet.copy_from_slice(&packet);
                    return;
                }
                Some(packet::ip::IpNextLevelProtocol::Tcp) => {
                    let packet = builder::build_tcp_syn_packet(packet_info);
                    tmp_packet.copy_from_slice(&packet);
                    return;
                }
                Some(packet::ip::IpNextLevelProtocol::Udp) => {
                    let packet = builder::build_udp_packet(packet_info);
                    tmp_packet.copy_from_slice(&packet);
                    return;
                }
                _ => {
                    return;
                }
            }
        }
        packet::ethernet::EtherType::Ipv6 => {
            match packet_info.ip_protocol {
                Some(packet::ip::IpNextLevelProtocol::Icmpv6) => {
                    let packet = builder::build_icmpv6_packet(packet_info);
                    tmp_packet.copy_from_slice(&packet);
                    return;
                }
                Some(packet::ip::IpNextLevelProtocol::Tcp) => {
                    let packet = builder::build_tcp_syn_packet(packet_info);
                    tmp_packet.copy_from_slice(&packet);
                    return;
                }
                Some(packet::ip::IpNextLevelProtocol::Udp) => {
                    let packet = builder::build_udp_packet(packet_info);
                    tmp_packet.copy_from_slice(&packet);
                    return;
                }
                _ => {
                    return;
                }
            }
        }
        _ => {
            return;
        }
    }
}

pub(crate) fn build_and_send_packet(tx: &mut Box<dyn pnet::datalink::DataLinkSender>, packet_info: PacketInfo) -> io::Result<usize> {
    match packet_info.ether_type {
        packet::ethernet::EtherType::Arp => {
            let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN + packet::arp::ARP_HEADER_LEN;
            tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                build_packet(packet_info.clone(), packet);
            });
            return Ok(packet_size);
        }
        packet::ethernet::EtherType::Ipv4 => {
            match packet_info.ip_protocol {
                Some(packet::ip::IpNextLevelProtocol::Icmp) => {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv4::IPV4_HEADER_LEN
                        + packet::icmp::ICMPV4_HEADER_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_packet(packet_info.clone(), packet);
                    });
                    return Ok(packet_size);
                }
                Some(packet::ip::IpNextLevelProtocol::Tcp) => {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN
                    + packet::ipv4::IPV4_HEADER_LEN
                    + packet::tcp::TCP_HEADER_LEN
                    + packet::tcp::TCP_DEFAULT_OPTION_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_packet(packet_info.clone(), packet);
                    });
                    return Ok(packet_size);
                }
                Some(packet::ip::IpNextLevelProtocol::Udp) => {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN
                    + packet::ipv4::IPV4_HEADER_LEN
                    + packet::udp::UDP_HEADER_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_packet(packet_info.clone(), packet);
                    });
                    return Ok(packet_size);
                }
                _ => {
                    return Err(io::Error::new(io::ErrorKind::Other, "Invalid IP Protocol"));
                }
            }
        }
        packet::ethernet::EtherType::Ipv6 => {
            match packet_info.ip_protocol {
                Some(packet::ip::IpNextLevelProtocol::Icmpv6) => {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv6::IPV6_HEADER_LEN
                        + packet::icmpv6::ICMPV6_HEADER_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_packet(packet_info.clone(), packet);
                    });
                    return Ok(packet_size);
                }
                Some(packet::ip::IpNextLevelProtocol::Tcp) => {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv6::IPV6_HEADER_LEN
                        + packet::tcp::TCP_HEADER_LEN
                        + packet::tcp::TCP_DEFAULT_OPTION_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_packet(packet_info.clone(), packet);
                    });
                    return Ok(packet_size);
                }
                Some(packet::ip::IpNextLevelProtocol::Udp) => {
                    let packet_size: usize = packet::ethernet::ETHERNET_HEADER_LEN
                        + packet::ipv6::IPV6_HEADER_LEN
                        + packet::udp::UDP_HEADER_LEN;
                    tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                        build_packet(packet_info.clone(), packet);
                    });
                    return Ok(packet_size);
                }
                _ => {
                    return Err(io::Error::new(io::ErrorKind::Other, "Invalid IP Protocol"));
                }
            }
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid EtherType"));
        }
    }
}

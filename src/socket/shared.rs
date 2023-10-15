use crate::packet::builder::PacketBuildOption;
use crate::packet::{self, builder};
use std::io;

fn build_packet(packet_option: PacketBuildOption, tmp_packet: &mut [u8]) {
    match packet_option.ether_type {
        packet::ethernet::EtherType::Arp => {
            let packet = builder::build_full_arp_packet(packet_option);
            tmp_packet.copy_from_slice(&packet);
            return;
        }
        packet::ethernet::EtherType::Ipv4 => match packet_option.ip_protocol {
            Some(packet::ip::IpNextLevelProtocol::Icmp) => {
                let packet = builder::build_full_icmp_packet(packet_option);
                tmp_packet.copy_from_slice(&packet);
                return;
            }
            Some(packet::ip::IpNextLevelProtocol::Tcp) => {
                let packet = builder::build_full_tcp_syn_packet(packet_option);
                tmp_packet.copy_from_slice(&packet);
                return;
            }
            Some(packet::ip::IpNextLevelProtocol::Udp) => {
                let packet = builder::build_full_udp_packet(packet_option);
                tmp_packet.copy_from_slice(&packet);
                return;
            }
            _ => {
                return;
            }
        },
        packet::ethernet::EtherType::Ipv6 => match packet_option.ip_protocol {
            Some(packet::ip::IpNextLevelProtocol::Icmpv6) => {
                let packet = builder::build_full_icmpv6_packet(packet_option);
                tmp_packet.copy_from_slice(&packet);
                return;
            }
            Some(packet::ip::IpNextLevelProtocol::Tcp) => {
                let packet = builder::build_full_tcp_syn_packet(packet_option);
                tmp_packet.copy_from_slice(&packet);
                return;
            }
            Some(packet::ip::IpNextLevelProtocol::Udp) => {
                let packet = builder::build_full_udp_packet(packet_option);
                tmp_packet.copy_from_slice(&packet);
                return;
            }
            _ => {
                return;
            }
        },
        _ => {
            return;
        }
    }
}

pub(crate) fn build_and_send_packet(
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
    packet_option: PacketBuildOption,
) -> io::Result<usize> {
    match packet_option.ether_type {
        packet::ethernet::EtherType::Arp => {
            let packet_size: usize =
                packet::ethernet::ETHERNET_HEADER_LEN + packet::arp::ARP_HEADER_LEN;
            tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                build_packet(packet_option.clone(), packet);
            });
            return Ok(packet_size);
        }
        packet::ethernet::EtherType::Ipv4 => match packet_option.ip_protocol {
            Some(packet::ip::IpNextLevelProtocol::Icmp) => {
                let packet_size: usize = if packet_option.use_tun {packet::icmp::ICMPV4_IP_PACKET_LEN} else {packet::icmp::ICMPV4_PACKET_LEN};
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_packet(packet_option.clone(), packet);
                });
                return Ok(packet_size);
            }
            Some(packet::ip::IpNextLevelProtocol::Tcp) => {
                let packet_size: usize = if packet_option.use_tun {packet::tcp::TCPV4_DEFAULT_IP_PACKET_LEN} else {packet::tcp::TCPV4_DEFAULT_PACKET_LEN};
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_packet(packet_option.clone(), packet);
                });
                return Ok(packet_size);
            }
            Some(packet::ip::IpNextLevelProtocol::Udp) => {
                let packet_size: usize = if packet_option.use_tun {packet::udp::UDPV4_IP_PACKET_LEN} else {packet::udp::UDPV4_PACKET_LEN};
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_packet(packet_option.clone(), packet);
                });
                return Ok(packet_size);
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::Other, "Invalid IP Protocol"));
            }
        },
        packet::ethernet::EtherType::Ipv6 => match packet_option.ip_protocol {
            Some(packet::ip::IpNextLevelProtocol::Icmpv6) => {
                let packet_size: usize = if packet_option.use_tun {packet::icmpv6::ICMPV6_IP_PACKET_LEN} else {packet::icmpv6::ICMPV6_PACKET_LEN};
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_packet(packet_option.clone(), packet);
                });
                return Ok(packet_size);
            }
            Some(packet::ip::IpNextLevelProtocol::Tcp) => {
                let packet_size: usize = if packet_option.use_tun {packet::tcp::TCPV6_DEFAULT_IP_PACKET_LEN} else {packet::tcp::TCPV6_DEFAULT_PACKET_LEN};
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_packet(packet_option.clone(), packet);
                });
                return Ok(packet_size);
            }
            Some(packet::ip::IpNextLevelProtocol::Udp) => {
                let packet_size: usize = if packet_option.use_tun {packet::udp::UDPV6_IP_PACKET_LEN} else {packet::udp::UDPV6_PACKET_LEN};
                tx.build_and_send(1, packet_size, &mut |packet: &mut [u8]| {
                    build_packet(packet_option.clone(), packet);
                });
                return Ok(packet_size);
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::Other, "Invalid IP Protocol"));
            }
        },
        _ => {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid EtherType"));
        }
    }
}

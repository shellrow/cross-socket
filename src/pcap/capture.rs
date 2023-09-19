use crate::pcap::PacketCaptureOptions;
use crate::packet::ethernet::EthernetPacket;
use crate::packet::{
    CaptureInfo, 
    PacketFrame, 
    ethernet::EtherType, 
    ip::IpNextLevelProtocol, 
    tcp::TcpPacket, 
    udp::UdpPacket, 
    icmp::IcmpPacket, 
    icmpv6::Icmpv6Packet, 
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    arp::ArpPacket};
use chrono::Local;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::time::Instant;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

pub fn start_capture(capture_options: PacketCaptureOptions, msg_tx: &Arc<Mutex<Sender<PacketFrame>>>, stop: &Arc<Mutex<bool>>) -> Vec<PacketFrame> {
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|interface: &pnet::datalink::NetworkInterface| {
            interface.index == capture_options.interface_index
        })
        .next()
        .expect("Failed to get Interface");
    let config = pnet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: capture_options.promiscuous,
    };
    let (mut _tx, mut rx) = match pnet::datalink::channel(&interface, config) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let packets: Vec<PacketFrame> = receive_packets(&mut rx, capture_options, msg_tx, stop);
    packets
}

fn receive_packets(
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>,
    capture_options: PacketCaptureOptions,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    stop: &Arc<Mutex<bool>>
) -> Vec<PacketFrame> {
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(Vec::new()));
    let start_time = Instant::now();
    let mut cnt = 1;
    loop {
        match rx.next() {
            Ok(frame) => {
                let capture_info = CaptureInfo {
                    capture_no: cnt,
                    datatime: Local::now().format("%Y%m%d%H%M%S%.3f").to_string(),
                    capture_len: frame.len(),
                    interface_index: capture_options.interface_index,
                    interface_name: capture_options.interface_name.clone(),
                };
                let mut packet_frame: PacketFrame = PacketFrame {
                    capture_info: capture_info.clone(),
                    ethernet_packet: None,
                    arp_packet: None,
                    ipv4_packet: None,
                    ipv6_packet: None,
                    icmp_packet: None,
                    icmpv6_packet: None,
                    tcp_packet: None,
                    udp_packet: None,
                };
                if let Some(frame) = pnet::packet::ethernet::EthernetPacket::new(frame) {
                    packet_frame.ethernet_packet = Some(EthernetPacket::from_pnet_packet(&frame));
                    match frame.get_ethertype() {
                        pnet::packet::ethernet::EtherTypes::Ipv4 => {
                            if filter_ether_type(EtherType::Ipv4, &capture_options) {
                                ipv4_handler(&frame, &capture_options, &mut packet_frame, msg_tx, &packets);
                            }
                        }
                        pnet::packet::ethernet::EtherTypes::Ipv6 => {
                            if filter_ether_type(EtherType::Ipv6, &capture_options) {
                                ipv6_handler(&frame, &capture_options, &mut packet_frame, msg_tx, &packets);
                            }
                        }
                        pnet::packet::ethernet::EtherTypes::Arp => {
                            if filter_ether_type(EtherType::Arp, &capture_options) {
                                arp_handler(&frame, &capture_options, &mut packet_frame, msg_tx, &packets);
                            }
                        }
                        pnet::packet::ethernet::EtherTypes::Rarp => {
                            if filter_ether_type(EtherType::Rarp, &capture_options) {
                                rarp_handler(&frame, &capture_options, &mut packet_frame, msg_tx, &packets);
                            }
                        }
                        _ => {
                            if capture_options.receive_undefined {
                                eth_handler(&frame, &capture_options, &mut packet_frame, msg_tx, &packets);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Failed to read: {}", e);
            }
        }
        if *stop.lock().unwrap() {
            return packets.lock().unwrap().clone();
        }
        if Instant::now().duration_since(start_time) > capture_options.duration {
            return packets.lock().unwrap().clone();
        }
        cnt += 1;
    }
}

fn ipv4_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    if let Some(packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()) {
        packet_frame.ipv4_packet = Some(Ipv4Packet::from_pnet_packet(&packet));
        if filter_host(
            IpAddr::V4(packet.get_source()),
            IpAddr::V4(packet.get_destination()),
            capture_options,
        ) {
            match packet.get_next_level_protocol() {
                pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                    if filter_ip_protocol(IpNextLevelProtocol::Tcp, &capture_options) {
                        tcp_handler(&packet, &capture_options, packet_frame, msg_tx, &packets);
                    }
                }
                pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                    if filter_ip_protocol(IpNextLevelProtocol::Udp, &capture_options) {
                        udp_handler(&packet, &capture_options, packet_frame, msg_tx, &packets);
                    }
                }
                pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                    if filter_ip_protocol(IpNextLevelProtocol::Icmp, &capture_options) {
                        icmp_handler(&packet, &capture_options, packet_frame, msg_tx, &packets);
                    }
                }
                _ => {}
            }
        }
    }
}

fn ipv6_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    if let Some(packet) = pnet::packet::ipv6::Ipv6Packet::new(ethernet.payload()) {
        packet_frame.ipv6_packet = Some(Ipv6Packet::from_pnet_packet(&packet));
        if filter_host(
            IpAddr::V6(packet.get_source()),
            IpAddr::V6(packet.get_destination()),
            capture_options,
        ) {
            match packet.get_next_header() {
                pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                    if filter_ip_protocol(IpNextLevelProtocol::Tcp, &capture_options) {
                        tcp_handler_v6(&packet, &capture_options, packet_frame, msg_tx, &packets);
                    }
                }
                pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                    if filter_ip_protocol(IpNextLevelProtocol::Udp, &capture_options) {
                        udp_handler_v6(&packet, &capture_options, packet_frame, msg_tx, &packets);
                    }
                }
                pnet::packet::ip::IpNextHeaderProtocols::Icmpv6 => {
                    if filter_ip_protocol(IpNextLevelProtocol::Icmpv6, &capture_options) {
                        icmpv6_handler(&packet, &capture_options, packet_frame, msg_tx, &packets);
                    }
                }
                _ => {}
            }
        }
    }
}

fn eth_handler(
    _ethernet: &pnet::packet::ethernet::EthernetPacket,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
    if capture_options.store && packets.lock().unwrap().len() < capture_options.store_limit as usize {
        packets.lock().unwrap().push(packet_frame.clone());
    }
}

fn arp_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
        if filter_host(
            IpAddr::V4(arp.get_sender_proto_addr()),
            IpAddr::V4(arp.get_target_proto_addr()),
            capture_options,
        ) {
            packet_frame.arp_packet = Some(ArpPacket::from_pnet_packet(arp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && packets.lock().unwrap().len() < capture_options.store_limit as usize {
                packets.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn rarp_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
        if filter_host(
            IpAddr::V4(arp.get_sender_proto_addr()),
            IpAddr::V4(arp.get_target_proto_addr()),
            capture_options,
        ) {
            packet_frame.arp_packet = Some(ArpPacket::from_pnet_packet(arp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && packets.lock().unwrap().len() < capture_options.store_limit as usize {
                packets.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn tcp_handler(
    packet: &pnet::packet::ipv4::Ipv4Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        if filter_port(tcp.get_source(), tcp.get_destination(), capture_options) {
            packet_frame.tcp_packet = Some(TcpPacket::from_pnet_packet(&tcp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && packets.lock().unwrap().len() < capture_options.store_limit as usize {
                packets.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn tcp_handler_v6(
    packet: &pnet::packet::ipv6::Ipv6Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        if filter_port(tcp.get_source(), tcp.get_destination(), capture_options) {
            packet_frame.tcp_packet = Some(TcpPacket::from_pnet_packet(&tcp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && packets.lock().unwrap().len() < capture_options.store_limit as usize {
                packets.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn udp_handler(
    packet: &pnet::packet::ipv4::Ipv4Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        if filter_port(udp.get_source(), udp.get_destination(), capture_options) {
            packet_frame.udp_packet = Some(UdpPacket::from_pnet_packet(&udp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && packets.lock().unwrap().len() < capture_options.store_limit as usize {
                packets.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn udp_handler_v6(
    packet: &pnet::packet::ipv6::Ipv6Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        if filter_port(udp.get_source(), udp.get_destination(), capture_options) {
            packet_frame.udp_packet = Some(UdpPacket::from_pnet_packet(&udp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && packets.lock().unwrap().len() < capture_options.store_limit as usize {
                packets.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn icmp_handler(
    packet: &pnet::packet::ipv4::Ipv4Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    if let Some(icmp) = pnet::packet::icmp::IcmpPacket::new(packet.payload()) {
        packet_frame.icmp_packet = Some(IcmpPacket::from_pnet_packet(&icmp));
        msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
        if capture_options.store && packets.lock().unwrap().len() < capture_options.store_limit as usize {
            packets.lock().unwrap().push(packet_frame.clone());
        }
    }
}

fn icmpv6_handler(
    packet: &pnet::packet::ipv6::Ipv6Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    packets: &Arc<Mutex<Vec<PacketFrame>>>
) {
    if let Some(icmp) = pnet::packet::icmpv6::Icmpv6Packet::new(packet.payload()) {
        packet_frame.icmpv6_packet = Some(Icmpv6Packet::from_pnet_packet(&icmp));
        msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
        if capture_options.store && packets.lock().unwrap().len() < capture_options.store_limit as usize {
            packets.lock().unwrap().push(packet_frame.clone());
        }
    }
}

fn filter_host(src_ip: IpAddr, dst_ip: IpAddr, capture_options: &PacketCaptureOptions) -> bool {
    if capture_options.src_ips.len() == 0 && capture_options.dst_ips.len() == 0 {
        return true;
    }
    if capture_options.src_ips.contains(&src_ip) || capture_options.dst_ips.contains(&dst_ip) {
        return true;
    } else {
        return false;
    }
}

fn filter_port(src_port: u16, dst_port: u16, capture_options: &PacketCaptureOptions) -> bool {
    if capture_options.src_ports.len() == 0 && capture_options.dst_ports.len() == 0 {
        return true;
    }
    if capture_options.src_ports.contains(&src_port) || capture_options.dst_ports.contains(&dst_port) {
        return true;
    } else {
        return false;
    }
}

fn filter_ether_type(ether_type: EtherType, capture_options: &PacketCaptureOptions) -> bool {
    if capture_options.ether_types.len() == 0
        || capture_options.ether_types.contains(&ether_type)
    {
        return true;
    } else {
        return false;
    }
}

fn filter_ip_protocol(protocol: IpNextLevelProtocol, capture_options: &PacketCaptureOptions) -> bool {
    if capture_options.ip_protocols.len() == 0
        || capture_options.ip_protocols.contains(&protocol)
    {
        return true;
    } else {
        return false;
    }
}

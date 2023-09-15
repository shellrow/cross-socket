use crate::option::PacketCaptureOptions;
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
    ipv6::Ipv6Packet};
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
    let fingerprints: Vec<PacketFrame> = receive_packets(&mut rx, capture_options, msg_tx, stop);
    fingerprints
}

fn receive_packets(
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>,
    capture_options: PacketCaptureOptions,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    stop: &Arc<Mutex<bool>>
) -> Vec<PacketFrame> {
    let fingerprints: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(Vec::new()));
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
                            if filter_ether_type(EtherType::IPv4, &capture_options) {
                                ipv4_handler(&frame, &capture_options, &mut packet_frame, msg_tx, &fingerprints);
                            }
                        }
                        pnet::packet::ethernet::EtherTypes::Ipv6 => {
                            if filter_ether_type(EtherType::IPv6, &capture_options) {
                                ipv6_handler(&frame, &capture_options, &mut packet_frame, msg_tx, &fingerprints);
                            }
                        }
                        /* pnet::packet::ethernet::EtherTypes::Vlan => {
                            if capture_options.default {
                                vlan_handler(&frame, &capture_options, capture_info);
                            }
                        } */
                        /* pnet::packet::ethernet::EtherTypes::Arp => {
                            if filter_protocol("ARP", &capture_options) {
                                arp_handler(&frame, &capture_options, capture_info);
                            }
                        } */
                        /* pnet::packet::ethernet::EtherTypes::Rarp => {
                            if filter_protocol("RARP", &capture_options) {
                                rarp_handler(&frame, &capture_options, capture_info);
                            }
                        } */
                        _ => {
                            /* if capture_options.default {
                                eth_handler(&frame, &capture_options, capture_info);
                            } */
                        }
                    }
                }
            }
            Err(e) => {
                println!("Failed to read: {}", e);
            }
        }
        if *stop.lock().unwrap() {
            return fingerprints.lock().unwrap().clone();
        }
        if Instant::now().duration_since(start_time) > capture_options.duration {
            return fingerprints.lock().unwrap().clone();
        }
        cnt += 1;
    }
}

fn ipv4_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    fingerprints: &Arc<Mutex<Vec<PacketFrame>>>
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
                        tcp_handler(&packet, &capture_options, packet_frame, msg_tx, &fingerprints);
                    }
                }
                pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                    if filter_ip_protocol(IpNextLevelProtocol::Udp, &capture_options) {
                        udp_handler(&packet, &capture_options, packet_frame, msg_tx, &fingerprints);
                    }
                }
                pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                    if filter_ip_protocol(IpNextLevelProtocol::Icmp, &capture_options) {
                        icmp_handler(&packet, &capture_options, packet_frame, msg_tx, &fingerprints);
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
    fingerprints: &Arc<Mutex<Vec<PacketFrame>>>
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
                        tcp_handler_v6(&packet, &capture_options, packet_frame, msg_tx, &fingerprints);
                    }
                }
                pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                    if filter_ip_protocol(IpNextLevelProtocol::Udp, &capture_options) {
                        udp_handler_v6(&packet, &capture_options, packet_frame, msg_tx, &fingerprints);
                    }
                }
                pnet::packet::ip::IpNextHeaderProtocols::Icmpv6 => {
                    if filter_ip_protocol(IpNextLevelProtocol::Icmpv6, &capture_options) {
                        icmpv6_handler(&packet, &capture_options, packet_frame, msg_tx, &fingerprints);
                    }
                }
                _ => {}
            }
        }
    }
}

/* fn eth_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    _capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo,
) {
    print!("[{}] [{}] ", capture_info.capture_no, capture_info.datatime);
    println!(
        "[{}, {} -> {}, Length {}]",
        packet::get_ethertype_string(ethernet.get_ethertype()),
        ethernet.get_source(),
        ethernet.get_destination(),
        ethernet.payload().len()
    );
} */

/* fn vlan_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    _capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo,
) {
    if let Some(vlan) = pnet::packet::vlan::VlanPacket::new(ethernet.payload()) {
        print!("[{}] [{}] ", capture_info.capture_no, capture_info.datatime);
        println!(
            "[VLAN, {} -> {}, ID {}, Length {}]",
            ethernet.get_source(),
            ethernet.get_destination(),
            vlan.get_vlan_identifier(),
            vlan.payload().len()
        );
    }
} */

/* fn arp_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo,
) {
    if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
        if filter_host(
            IpAddr::V4(arp.get_sender_proto_addr()),
            IpAddr::V4(arp.get_target_proto_addr()),
            capture_options,
        ) {
            print!("[{}] [{}] ", capture_info.capture_no, capture_info.datatime);
            println!(
                "[ARP, {}({}) -> {}({}), Length {}]",
                arp.get_sender_proto_addr().to_string(),
                arp.get_sender_hw_addr().to_string(),
                arp.get_target_proto_addr().to_string(),
                arp.get_target_hw_addr().to_string(),
                arp.payload().len()
            );
        }
    }
} */

/* fn rarp_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    _capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo,
) {
    if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
        print!("[{}] [{}] ", capture_info.capture_no, capture_info.datatime);
        println!(
            "[RARP, {}({}) -> {}({}), Length {}]",
            arp.get_sender_proto_addr().to_string(),
            arp.get_sender_hw_addr().to_string(),
            arp.get_target_proto_addr().to_string(),
            arp.get_target_hw_addr().to_string(),
            arp.payload().len()
        );
    }
} */

fn tcp_handler(
    packet: &pnet::packet::ipv4::Ipv4Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    fingerprints: &Arc<Mutex<Vec<PacketFrame>>>
) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        if filter_port(tcp.get_source(), tcp.get_destination(), capture_options) {
            packet_frame.tcp_packet = Some(TcpPacket::from_pnet_packet(&tcp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && fingerprints.lock().unwrap().len() < capture_options.store_limit as usize {
                fingerprints.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn tcp_handler_v6(
    packet: &pnet::packet::ipv6::Ipv6Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    fingerprints: &Arc<Mutex<Vec<PacketFrame>>>
) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        if filter_port(tcp.get_source(), tcp.get_destination(), capture_options) {
            packet_frame.tcp_packet = Some(TcpPacket::from_pnet_packet(&tcp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && fingerprints.lock().unwrap().len() < capture_options.store_limit as usize {
                fingerprints.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn udp_handler(
    packet: &pnet::packet::ipv4::Ipv4Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    fingerprints: &Arc<Mutex<Vec<PacketFrame>>>
) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        if filter_port(udp.get_source(), udp.get_destination(), capture_options) {
            packet_frame.udp_packet = Some(UdpPacket::from_pnet_packet(&udp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && fingerprints.lock().unwrap().len() < capture_options.store_limit as usize {
                fingerprints.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn udp_handler_v6(
    packet: &pnet::packet::ipv6::Ipv6Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    fingerprints: &Arc<Mutex<Vec<PacketFrame>>>
) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        if filter_port(udp.get_source(), udp.get_destination(), capture_options) {
            packet_frame.udp_packet = Some(UdpPacket::from_pnet_packet(&udp));
            msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
            if capture_options.store && fingerprints.lock().unwrap().len() < capture_options.store_limit as usize {
                fingerprints.lock().unwrap().push(packet_frame.clone());
            }
        }
    }
}

fn icmp_handler(
    packet: &pnet::packet::ipv4::Ipv4Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    fingerprints: &Arc<Mutex<Vec<PacketFrame>>>
) {
    if let Some(icmp) = pnet::packet::icmp::IcmpPacket::new(packet.payload()) {
        packet_frame.icmp_packet = Some(IcmpPacket::from_pnet_packet(&icmp));
        msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
        if capture_options.store && fingerprints.lock().unwrap().len() < capture_options.store_limit as usize {
            fingerprints.lock().unwrap().push(packet_frame.clone());
        }
    }
}

fn icmpv6_handler(
    packet: &pnet::packet::ipv6::Ipv6Packet,
    capture_options: &PacketCaptureOptions,
    packet_frame: &mut PacketFrame,
    msg_tx: &Arc<Mutex<Sender<PacketFrame>>>,
    fingerprints: &Arc<Mutex<Vec<PacketFrame>>>
) {
    if let Some(icmp) = pnet::packet::icmpv6::Icmpv6Packet::new(packet.payload()) {
        packet_frame.icmpv6_packet = Some(Icmpv6Packet::from_pnet_packet(&icmp));
        msg_tx.lock().unwrap().send(packet_frame.clone()).unwrap();
        if capture_options.store && fingerprints.lock().unwrap().len() < capture_options.store_limit as usize {
            fingerprints.lock().unwrap().push(packet_frame.clone());
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

/* fn parse_ip_packet(packet: &pnet::packet::ipv4::Ipv4Packet, next_level_protocol: IpNextLevelProtocol) -> IpFingerprint {
    let ip_fingerprint = IpFingerprint {
        source_ip: IpAddr::V4(packet.get_source()),
        destination_ip: IpAddr::V4(packet.get_destination()),
        version: packet.get_version(),
        ttl: packet.get_ttl(),
        tos: packet.get_dscp(),
        id: packet.get_identification(),
        df: packet.get_flags() & 0b010 == 0b010,
        flags: packet.get_flags() & 0b111,
        fragment_offset: packet.get_fragment_offset(),
        header_length: packet.get_header_length(),
        total_length: packet.get_total_length(),
        next_level_protocol: next_level_protocol,
    };
    ip_fingerprint
} */

/* fn parse_ipv6_packet(packet: &pnet::packet::ipv6::Ipv6Packet, next_level_protocol: IpNextLevelProtocol) -> IpFingerprint {
    let ip_fingerprint = IpFingerprint {
        source_ip: IpAddr::V6(packet.get_source()),
        destination_ip: IpAddr::V6(packet.get_destination()),
        version: packet.get_version(),
        ttl: packet.get_hop_limit(),
        tos: packet.get_traffic_class(),
        id: 0,
        df: false,
        flags: 0,
        fragment_offset: 0,
        header_length: 0,
        total_length: packet.get_payload_length(),
        next_level_protocol: next_level_protocol,
    };
    ip_fingerprint
} */

/* fn parse_tcp_packet(packet: &pnet::packet::tcp::TcpPacket) -> TcpPacket {
    let mut tcp_options: Vec<TcpOption> = vec![];
    for opt in packet.get_options_iter() {
        match opt.get_number() {
            TcpOptionNumbers::EOL => tcp_options.push(TcpOption::Eol),
            TcpOptionNumbers::NOP => tcp_options.push(TcpOption::Nop),
            TcpOptionNumbers::MSS => tcp_options.push(TcpOption::Mss),
            TcpOptionNumbers::WSCALE => tcp_options.push(TcpOption::Wscale),
            TcpOptionNumbers::SACK_PERMITTED => tcp_options.push(TcpOption::SackParmitted),
            TcpOptionNumbers::SACK => tcp_options.push(TcpOption::Sack),
            TcpOptionNumbers::TIMESTAMPS => tcp_options.push(TcpOption::Timestamp),
            _ => {}
        }
    }
    let mut tcp_flags: Vec<TcpFlag> = vec![];
    if packet.get_flags() & TcpFlag::Syn.number() == TcpFlag::Syn.number() {
        tcp_flags.push(TcpFlag::Syn);
    }
    if packet.get_flags() & TcpFlag::Fin.number() == TcpFlag::Fin.number() {
        tcp_flags.push(TcpFlag::Fin);
    }
    if packet.get_flags() & TcpFlag::Rst.number() == TcpFlag::Rst.number() {
        tcp_flags.push(TcpFlag::Rst);
    }
    if packet.get_flags() & TcpFlag::Psh.number() == TcpFlag::Psh.number() {
        tcp_flags.push(TcpFlag::Psh);
    }
    if packet.get_flags() & TcpFlag::Ack.number() == TcpFlag::Ack.number() {
        tcp_flags.push(TcpFlag::Ack);
    }
    if packet.get_flags() & TcpFlag::Urg.number() == TcpFlag::Urg.number() {
        tcp_flags.push(TcpFlag::Urg);
    }
    if packet.get_flags() & TcpFlag::Ece.number() == TcpFlag::Ece.number() {
        tcp_flags.push(TcpFlag::Ece);
    }
    if packet.get_flags() & TcpFlag::Cwr.number() == TcpFlag::Cwr.number() {
        tcp_flags.push(TcpFlag::Cwr);
    }
    let tcp_fingerprint = TcpPacket {
        source: packet.get_source(),
        destination: packet.get_destination(),
        flags: tcp_flags,
        window: packet.get_window(),
        options: tcp_options,
        sequence: packet.get_sequence(),
        acknowledgement: packet.get_acknowledgement(),
        checksum: packet.get_checksum(),
        data_offset: packet.get_data_offset(),
        reserved: packet.get_reserved(),
        urgent_ptr: packet.get_urgent_ptr(),
        payload: packet.payload().to_vec(),
    };
    tcp_fingerprint
} */

/* fn parse_udp_packet(packet: &pnet::packet::udp::UdpPacket) -> UdpPacket {
    let udp_fingerprint = UdpPacket {
        source: packet.get_source(),
        destination: packet.get_destination(),
        length: packet.get_length(),
        checksum: packet.get_checksum(),
        payload: packet.payload().to_vec(),
    };
    udp_fingerprint
} */

/* fn parse_icmp_packet(packet: &pnet::packet::icmp::IcmpPacket) -> IcmpPacket {
    let icmp_fingerprint: IcmpPacket = IcmpPacket {
        icmp_type: IcmpType::from_pnet_type(packet.get_icmp_type()),
        icmp_code: crate::packet::icmp::IcmpCode::from_u8(packet.get_icmp_code().0),
        checksum: packet.get_checksum(),
        payload: packet.payload().to_vec(),
    };
    icmp_fingerprint
} */

/* fn parse_icmpv6_packet(packet: &pnet::packet::icmpv6::Icmpv6Packet) -> Icmpv6Packet {
    let icmp_fingerprint: Icmpv6Packet = Icmpv6Packet {
        icmpv6_type: Icmpv6Type::from_pnet_type(packet.get_icmpv6_type()),
        icmpv6_code: crate::packet::icmpv6::Icmpv6Code::from_u8(packet.get_icmpv6_code().0),
        checksum: packet.get_checksum(),
        payload: packet.payload().to_vec(),
    };
    icmp_fingerprint
}
 */
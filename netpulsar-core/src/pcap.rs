use std::net::IpAddr;
use rusqlite::{Connection, Transaction};
use tokio::sync::mpsc::Sender as TokioSender;
use crossbeam_channel::Sender as CrossbeamSender;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::time::Instant;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use xenet::packet::{ip::IpNextLevelProtocol, ethernet::EtherType};
use xenet::net::interface::Interface;
use xenet::packet::frame::Frame;
use xenet::packet::frame::ParseOption;
use crate::db::{DB_NAME, connect_db};
use crate::db::table::DbPacketFrame;
use crate::interface;
use crate::sys;
use crate::models::packet::PacketFrame;

/// Packet capture message
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CaptureReport {
    pub bytes: usize,
    pub packets: usize,
    pub start_time: String,
    pub end_time: String,
    pub duration: Duration,
}

impl CaptureReport {
    pub fn new() -> CaptureReport {
        CaptureReport {
            bytes: 0,
            packets: 0,
            start_time: String::new(),
            end_time: String::new(),
            duration: Duration::from_secs(0),
        }
    }
}

/// Packet capture options
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PacketCaptureOptions {
    /// Interface index
    pub interface_index: u32,
    /// Interface name
    #[allow(dead_code)]
    pub interface_name: String,
    /// Source IP addresses to filter. If empty, all source IP addresses will be captured
    pub src_ips: HashSet<IpAddr>,
    /// Destination IP addresses to filter. If empty, all destination IP addresses will be captured
    pub dst_ips: HashSet<IpAddr>,
    /// Source ports to filter. If empty, all source ports will be captured
    pub src_ports: HashSet<u16>,
    /// Destination ports to filter. If empty, all destination ports will be captured
    pub dst_ports: HashSet<u16>,
    /// Ether types to filter. If empty, all ether types will be captured
    pub ether_types: HashSet<EtherType>,
    /// IP protocols to filter. If empty, all IP protocols will be captured
    pub ip_protocols: HashSet<IpNextLevelProtocol>,
    /// Capture duration limit
    pub capture_timeout: Duration,
    /// Read Timeout for read next packet (Linux, BPF only)
    pub read_timeout: Duration,
    /// Capture in promiscuous mode
    pub promiscuous: bool,
    /// Receive undefined packets
    pub receive_undefined: bool,
    /// Use TUN interface
    pub tunnel: bool,
    /// Loopback interface
    pub loopback: bool,
}

impl PacketCaptureOptions {
    pub fn default() -> Result<PacketCaptureOptions, String> {
        let iface = default_net::get_default_interface()?;
        let options = PacketCaptureOptions {
            interface_index: iface.index,
            interface_name: iface.name.clone(),
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            capture_timeout: Duration::MAX,
            read_timeout: Duration::from_millis(200),
            promiscuous: false,
            receive_undefined: true,
            tunnel: iface.is_tun(),
            loopback: iface.is_loopback(),
        };
        Ok(options)
    }
    pub fn from_interface_index(if_index: u32) -> Option<PacketCaptureOptions> {
        let iface = interface::get_interface_by_index(if_index)?;
        let options = PacketCaptureOptions {
            interface_index: if_index,
            interface_name: iface.name.clone(),
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            capture_timeout: Duration::MAX,
            read_timeout: Duration::from_millis(200),
            promiscuous: false,
            receive_undefined: true,
            tunnel: iface.is_tun(),
            loopback: iface.is_loopback(),
        };
        Some(options)
    }
    pub fn from_interface_name(if_name: String) -> PacketCaptureOptions {
        let iface = interface::get_interface_by_name(if_name).unwrap();
        let options = PacketCaptureOptions {
            interface_index: iface.index,
            interface_name: iface.name.clone(),
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            capture_timeout: Duration::MAX,
            read_timeout: Duration::from_millis(200),
            promiscuous: false,
            receive_undefined: true,
            tunnel: iface.is_tun(),
            loopback: iface.is_loopback(),
        };
        options
    }
}

/// Start packet capture
pub fn start_capture(
    capture_options: PacketCaptureOptions,
    msg_tx: Sender<PacketFrame>,
    stop: &Arc<Mutex<bool>>,
) -> CaptureReport {
    let mut report = CaptureReport::new();
    let interfaces = xenet::net::interface::get_interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|interface: &Interface| interface.index == capture_options.interface_index)
        .next()
        .expect("Failed to get Interface");
    let config = xenet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(capture_options.read_timeout),
        write_timeout: None,
        channel_type: xenet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: capture_options.promiscuous,
    };
    let (mut _tx, mut rx) = match xenet::datalink::channel(&interface, config) {
        Ok(xenet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let start_time = Instant::now();
    report.start_time = sys::get_sysdate();
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun() {
                    let payload_offset;
                    if interface.is_loopback() {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                report.bytes = report.bytes.saturating_add(packet.len());
                report.packets = report.packets.saturating_add(1);
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                if filter_packet(&frame, &capture_options) {
                    let packet_frame = PacketFrame::from_xenet_frame(report.packets,interface.index, interface.name.clone(), frame);
                    match msg_tx.send(packet_frame) {
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
            }
            Err(_) => {}
        }
        match stop.lock() {
            Ok(stop) => {
                if *stop {
                    break;
                }
            }
            Err(_) => {}
        }
        if Instant::now().duration_since(start_time) > capture_options.capture_timeout {
            break;
        }
    }
    report.end_time = sys::get_sysdate();
    report.duration = Instant::now().duration_since(start_time);
    report
}

/// Start packet capture with crossbeam channel
pub fn start_capture_crossbeam(
    capture_options: PacketCaptureOptions,
    msg_tx: CrossbeamSender<Frame>,
    stop: &Arc<Mutex<bool>>,
) -> CaptureReport {
    let mut report = CaptureReport::new();
    let interfaces = xenet::net::interface::get_interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|interface: &Interface| interface.index == capture_options.interface_index)
        .next()
        .expect("Failed to get Interface");
    let config = xenet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(capture_options.read_timeout),
        write_timeout: None,
        channel_type: xenet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: capture_options.promiscuous,
    };
    let (mut _tx, mut rx) = match xenet::datalink::channel(&interface, config) {
        Ok(xenet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let start_time = Instant::now();
    report.start_time = sys::get_sysdate();
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun() {
                    let payload_offset;
                    if interface.is_loopback() {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                if filter_packet(&frame, &capture_options) {
                    /* match msg_tx.lock() {
                        Ok(msg_tx) => match msg_tx.send(frame) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    } */
                    match msg_tx.send(frame) {
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
                report.bytes = report.bytes.saturating_add(packet.len());
                report.packets = report.packets.saturating_add(1);
            }
            Err(_) => {}
        }
        match stop.lock() {
            Ok(stop) => {
                if *stop {
                    break;
                }
            }
            Err(_) => {}
        }
        if Instant::now().duration_since(start_time) > capture_options.capture_timeout {
            break;
        }
    }
    report.end_time = sys::get_sysdate();
    report.duration = Instant::now().duration_since(start_time);
    report
}

/// Start packet capture with tokio channel
pub async fn start_capture_async(
    capture_options: PacketCaptureOptions,
    //msg_tx: &Arc<Mutex<Sender<Frame>>>,
    msg_tx: TokioSender<Frame>,
    stop: &Arc<Mutex<bool>>,
) -> CaptureReport {
    let mut report = CaptureReport::new();
    let interfaces = xenet::net::interface::get_interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|interface: &Interface| interface.index == capture_options.interface_index)
        .next()
        .expect("Failed to get Interface");
    let config = xenet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(capture_options.read_timeout),
        write_timeout: None,
        channel_type: xenet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: capture_options.promiscuous,
    };
    let (mut _tx, mut rx) = match xenet::datalink::channel(&interface, config) {
        Ok(xenet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let start_time = Instant::now();
    report.start_time = sys::get_sysdate();
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun() {
                    let payload_offset;
                    if interface.is_loopback() {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                if filter_packet(&frame, &capture_options) {
                    /* match msg_tx.lock() {
                        Ok(msg_tx) => match msg_tx.send(frame) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    } */
                    match msg_tx.send(frame).await {
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
                report.bytes = report.bytes.saturating_add(packet.len());
                report.packets = report.packets.saturating_add(1);
            }
            Err(_) => {}
        }
        match stop.lock() {
            Ok(stop) => {
                if *stop {
                    break;
                }
            }
            Err(_) => {}
        }
        if Instant::now().duration_since(start_time) > capture_options.capture_timeout {
            break;
        }
    }
    report.end_time = sys::get_sysdate();
    report.duration = Instant::now().duration_since(start_time);
    report
}

pub fn start_background_capture(
    capture_options: PacketCaptureOptions,
    stop: &Arc<Mutex<bool>>,
) -> CaptureReport {
    let mut report = CaptureReport::new();
    let mut conn: Connection = match connect_db(DB_NAME) {
        Ok(c)=> c, 
        Err(e) => {
            println!("Error: {:?}", e);
            return report;
        },
    };
    let interfaces = xenet::net::interface::get_interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|interface: &Interface| interface.index == capture_options.interface_index)
        .next()
        .expect("Failed to get Interface");
    let config = xenet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(capture_options.read_timeout),
        write_timeout: None,
        channel_type: xenet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: capture_options.promiscuous,
    };
    let (mut _tx, mut rx) = match xenet::datalink::channel(&interface, config) {
        Ok(xenet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let start_time = Instant::now();
    report.start_time = sys::get_sysdate();
    loop {
        match rx.next() {
            Ok(packet) => {
                let mut parse_option: ParseOption = ParseOption::default();
                if interface.is_tun() {
                    let payload_offset;
                    if interface.is_loopback() {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    parse_option.from_ip_packet = true;
                    parse_option.offset = payload_offset;
                }
                report.bytes = report.bytes.saturating_add(packet.len());
                report.packets = report.packets.saturating_add(1);
                let frame: Frame = Frame::from_bytes(&packet, parse_option);
                if filter_packet(&frame, &capture_options) {
                    let packet_frame = DbPacketFrame::from_xenet_frame(report.packets,interface.index, interface.name.clone(), frame);
                    let tran: Transaction = conn.transaction().unwrap();
                    match packet_frame.insert(&tran) {
                        Ok(_) => {}
                        Err(e) => {
                            println!("Error: {:?}", e);
                        }
                    }
                    match tran.commit() {
                        Ok(_) => {}
                        Err(e) => {
                            println!("Error: {:?}", e);
                        }
                    }
                }
            }
            Err(_) => {}
        }
        match stop.lock() {
            Ok(stop) => {
                if *stop {
                    break;
                }
            }
            Err(_) => {}
        }
        if Instant::now().duration_since(start_time) > capture_options.capture_timeout {
            break;
        }
    }
    report.end_time = sys::get_sysdate();
    report.duration = Instant::now().duration_since(start_time);
    report
}

fn filter_packet(frame: &Frame, capture_options: &PacketCaptureOptions) -> bool {
    if let Some(datalink) = &frame.datalink {
        if let Some(ethernet_header) = &datalink.ethernet {
            if !filter_ether_type(ethernet_header.ethertype, capture_options) {
                return false;
            }
        }
        if let Some(arp_header) = &datalink.arp {
            if !filter_host(
                IpAddr::V4(arp_header.sender_proto_addr),
                IpAddr::V4(arp_header.target_proto_addr),
                capture_options,
            ) {
                return false;
            }
        }
    }
    if let Some(ip) = &frame.ip {
        if let Some(ipv4_header) = &ip.ipv4 {
            if !filter_host(
                IpAddr::V4(ipv4_header.source),
                IpAddr::V4(ipv4_header.destination),
                capture_options,
            ) {
                return false;
            }
            if !filter_ip_protocol(ipv4_header.next_level_protocol, capture_options) {
                return false;
            }
        }
        if let Some(ipv6_header) = &ip.ipv6 {
            if !filter_host(
                IpAddr::V6(ipv6_header.source),
                IpAddr::V6(ipv6_header.destination),
                capture_options,
            ) {
                return false;
            }
            if !filter_ip_protocol(ipv6_header.next_header, capture_options) {
                return false;
            }
        }
    }
    if let Some(transport) = &frame.transport {
        if let Some(tcp_header) = &transport.tcp {
            if !filter_port(tcp_header.source, tcp_header.destination, capture_options) {
                return false;
            }
        }
        if let Some(udp_header) = &transport.udp {
            if !filter_port(udp_header.source, udp_header.destination, capture_options) {
                return false;
            }
        }
    }
    true
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
    if capture_options.src_ports.contains(&src_port)
        || capture_options.dst_ports.contains(&dst_port)
    {
        return true;
    } else {
        return false;
    }
}

fn filter_ether_type(ether_type: EtherType, capture_options: &PacketCaptureOptions) -> bool {
    if capture_options.ether_types.len() == 0 || capture_options.ether_types.contains(&ether_type) {
        return true;
    } else {
        return false;
    }
}

fn filter_ip_protocol(
    protocol: IpNextLevelProtocol,
    capture_options: &PacketCaptureOptions,
) -> bool {
    if capture_options.ip_protocols.len() == 0 || capture_options.ip_protocols.contains(&protocol) {
        return true;
    } else {
        return false;
    }
}

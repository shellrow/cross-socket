mod capture;
pub mod listener;

use crate::packet::ethernet::EtherType;
use crate::packet::ip::IpNextLevelProtocol;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

/// Packet capture options
#[derive(Clone, Debug)]
pub struct PacketCaptureOptions {
    /// Interface index
    pub interface_index: u32,
    /// Interface name
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
    pub duration: Duration,
    /// Read Timeout for read next packet (Linux, BPF, Netmap only)
    pub read_timeout: Duration,
    /// Capture in promiscuous mode
    pub promiscuous: bool,
    /// Store captured packets in memory
    pub store: bool,
    /// Store limit
    pub store_limit: u32,
    /// Receive undefined packets
    pub receive_undefined: bool,
    /// Use TUN interface
    pub use_tun: bool,
    /// Loopback interface
    pub loopback: bool,
}

impl PacketCaptureOptions {
    /// Constructs a new PacketCaptureOptions
    pub fn new() -> PacketCaptureOptions {
        PacketCaptureOptions {
            interface_index: 0,
            interface_name: String::new(),
            src_ips: HashSet::new(),
            dst_ips: HashSet::new(),
            src_ports: HashSet::new(),
            dst_ports: HashSet::new(),
            ether_types: HashSet::new(),
            ip_protocols: HashSet::new(),
            duration: Duration::from_secs(30),
            read_timeout: Duration::from_secs(2),
            promiscuous: false,
            store: false,
            store_limit: u32::MAX,
            receive_undefined: false,
            use_tun: false,
            loopback: false,
        }
    }
    /// Set interface index
    pub fn with_interface_index(mut self, interface_index: u32) -> PacketCaptureOptions {
        self.interface_index = interface_index;
        self
    }
    /// Set source IP addresses to filter
    pub fn set_src_ips(&mut self, ips: Vec<IpAddr>) {
        for ip in ips {
            self.src_ips.insert(ip);
        }
    }
    /// Set destination IP addresses to filter
    pub fn set_dst_ips(&mut self, ips: Vec<IpAddr>) {
        for ip in ips {
            self.dst_ips.insert(ip);
        }
    }
    /// Set source ports to filter
    pub fn set_src_ports(&mut self, ports: Vec<u16>) {
        for port in ports {
            self.src_ports.insert(port);
        }
    }
    /// Set destination ports to filter
    pub fn set_dst_ports(&mut self, ports: Vec<u16>) {
        for port in ports {
            self.dst_ports.insert(port);
        }
    }
    /// Set ether types to filter
    pub fn set_ether_types(&mut self, ether_types: Vec<EtherType>) {
        for ether_type in ether_types {
            self.ether_types.insert(ether_type);
        }
    }
    /// Set IP protocols to filter
    pub fn set_ip_protocols(&mut self, ip_protocols: Vec<IpNextLevelProtocol>) {
        for ip_protocol in ip_protocols {
            self.ip_protocols.insert(ip_protocol);
        }
    }
}

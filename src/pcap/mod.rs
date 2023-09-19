pub mod listener;
mod capture;

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use crate::packet::ethernet::EtherType;
use crate::packet::ip::IpNextLevelProtocol;

#[derive(Clone, Debug)]
pub struct PacketCaptureOptions {
    pub interface_index: u32,
    pub interface_name: String,
    pub src_ips: HashSet<IpAddr>,
    pub dst_ips: HashSet<IpAddr>,
    pub src_ports: HashSet<u16>,
    pub dst_ports: HashSet<u16>,
    pub ether_types: HashSet<EtherType>,
    pub ip_protocols: HashSet<IpNextLevelProtocol>,
    pub duration: Duration,
    pub promiscuous: bool,
    pub store: bool,
    pub store_limit: u32,
    pub receive_undefined: bool,
}

impl PacketCaptureOptions {
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
            promiscuous: false,
            store: false,
            store_limit: u32::MAX,
            receive_undefined: false,
        }
    }
    pub fn with_interface_index(mut self, interface_index: u32) -> PacketCaptureOptions {
        self.interface_index = interface_index;
        self
    }
    pub fn set_src_ips(&mut self, ips: Vec<IpAddr>) {
        for ip in ips {
            self.src_ips.insert(ip);
        }
    }
    pub fn set_dst_ips(&mut self, ips: Vec<IpAddr>) {
        for ip in ips {
            self.dst_ips.insert(ip);
        }
    }
    pub fn set_src_ports(&mut self, ports: Vec<u16>) {
        for port in ports {
            self.src_ports.insert(port);
        }
    }
    pub fn set_dst_ports(&mut self, ports: Vec<u16>) {
        for port in ports {
            self.dst_ports.insert(port);
        }
    }
    pub fn set_ether_types(&mut self, ether_types: Vec<EtherType>) {
        for ether_type in ether_types {
            self.ether_types.insert(ether_type);
        }
    }
    pub fn set_ip_protocols(&mut self, ip_protocols: Vec<IpNextLevelProtocol>) {
        for ip_protocol in ip_protocols {
            self.ip_protocols.insert(ip_protocol);
        }
    }
}


use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum CommandType {
    PortScan,
    HostScan,
    Ping,
    Traceroute,
    DomainScan
}

impl CommandType {
    pub fn id(&self) -> String {
        match *self {
            CommandType::PortScan => String::from("port_scan"),
            CommandType::HostScan => String::from("host_scan"),
            CommandType::Ping => String::from("ping"),
            CommandType::Traceroute => String::from("traceroute"),
            CommandType::DomainScan => String::from("domain_scan"),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            CommandType::PortScan => String::from("Port scan"),
            CommandType::HostScan => String::from("Host scan"),
            CommandType::Ping => String::from("Ping"),
            CommandType::Traceroute => String::from("Traceroute"),
            CommandType::DomainScan => String::from("Domain scan"),
        }
    }
    pub fn description(&self) -> String {
        match *self {
            CommandType::PortScan => String::from("Port scan"),
            CommandType::HostScan => String::from("Host scan"),
            CommandType::Ping => String::from("Ping"),
            CommandType::Traceroute => String::from("Traceroute"),
            CommandType::DomainScan => String::from("Domain scan"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Oui {
    pub mac_prefix: String,
    pub vendor_name: String,
    pub vendor_name_detail: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpService {
    pub port: u16, 
    pub service_name: String, 
    pub service_description: String,   
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpService {
    pub port: u16,
    pub service_name: String,
    pub service_description: String,   
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsFingerprint {
    pub cpe: String,
    pub os_name: String,
    pub os_vendor: String,
    pub os_family: String,
    pub os_generation: String,
    pub device_type: String,
    pub tcp_window_size: u16,
    pub tcp_option_pattern: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsTtl {
    pub os_family: String,
    pub os_description: String,
    pub initial_ttl: u8,
}

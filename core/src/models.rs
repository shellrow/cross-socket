use std::vec;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct OSFingerprint {
    pub id: String,
    pub os_name: String,
    pub version: String,
    pub icmp_echo_code: u8,
    pub icmp_ip_ttl: u8,
    pub icmp_echo_ip_df: bool,
    pub icmp_unreach_ip_df: bool,
    pub icmp_unreach_ip_len: String,
    pub icmp_unreach_data_ip_id_byte_order: String,
    pub tcp_ip_ttl: u8,
    pub tcp_ip_df: bool,
    pub tcp_window_size: Vec<u16>,
    pub tcp_option_order: Vec<String>,
    pub tcp_rst_text_payload: bool,
    pub tcp_ecn_support: bool,
}

impl OSFingerprint {
    pub fn new() -> OSFingerprint {
        OSFingerprint {
            id: String::new(),
            os_name: String::new(),
            version: String::new(),
            icmp_echo_code: 0,
            icmp_ip_ttl: 0,
            icmp_echo_ip_df: false,
            icmp_unreach_ip_df: false,
            icmp_unreach_ip_len: String::from("EQ"),
            icmp_unreach_data_ip_id_byte_order: String::from("EQ"),
            tcp_ip_ttl: 0,
            tcp_ip_df: false,
            tcp_window_size: vec![],
            tcp_option_order: vec![],
            tcp_rst_text_payload: false,
            tcp_ecn_support: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OuiData {
    pub mac_prefix: String,
    pub vendor_name: String,
    pub vendor_name_detail: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PortData {
    pub port_number: String,
    pub service_name: String,
    pub description: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct OsTtl {
    pub initial_ttl: u8,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SynFingerprint {
    pub tcp_window_size: u16,
    pub tcp_options: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EcnFingerprint {
    pub tcp_ecn_support: bool,
    pub ip_df: bool,
    pub tcp_window_size: u16,
    pub tcp_options: Vec<String>,
}

impl EcnFingerprint {
    pub fn new() -> EcnFingerprint {
        EcnFingerprint {
            tcp_ecn_support: false,
            ip_df: false,
            tcp_window_size: 0,
            tcp_options: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsClass {
    pub vendor: String,
    pub family: String,
    pub generation: String,
    pub device_type: String,
}

impl OsClass {
    pub fn new() -> OsClass {
        OsClass {
            vendor: String::new(),
            family: String::new(),
            generation: String::new(),
            device_type: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TCPFingerprint {
    pub cpe: String,
    pub os_name: String,
    pub class: OsClass,
    pub syn_fingerprints: Vec<SynFingerprint>,
    pub ecn_fingerprint: EcnFingerprint,
}

impl TCPFingerprint {
    pub fn new() -> TCPFingerprint {
        TCPFingerprint {
            cpe: String::new(),
            os_name: String::new(),
            class: OsClass::new(),
            syn_fingerprints: vec![],
            ecn_fingerprint: EcnFingerprint::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
    pub friendly_name: String,
    pub description: String,
    pub if_type: String,
    pub mac_addr: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateway_mac_addr: String,
    pub gateway_ip_addr: String,
}

impl NetworkInterface {
    pub fn new() -> NetworkInterface {
        NetworkInterface {
            index: 0,
            name: String::new(),
            friendly_name: String::new(),
            description: String::new(),
            if_type: String::new(),
            mac_addr: String::new(),
            ipv4: vec![],
            ipv6: vec![],
            gateway_mac_addr: String::new(),
            gateway_ip_addr: String::new(),
        }
    }
}

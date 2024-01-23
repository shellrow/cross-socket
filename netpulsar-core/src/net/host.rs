use std::{collections::HashMap, net::IpAddr};

use serde::{Serialize, Deserialize};

use crate::sys;

use super::{protocol::Protocol, traffic::TrafficInfo};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoteHostInfo {
    pub if_index: u32,
    pub if_name: String,
    pub mac_addr: String,
    pub ip_addr: IpAddr,
    pub hostname: String,
    pub country_code: String,
    pub country_name: String,
    pub asn: String,
    pub as_name: String,
    pub traffic_info: TrafficInfo,
    pub protocol_stat: HashMap<Protocol, TrafficInfo>,
    pub first_seen: String,
    pub updated_at: String,
}

impl RemoteHostInfo {
    pub fn new(if_index: u32, if_name: String, mac_addr: String, ip_addr: IpAddr) -> Self {
        RemoteHostInfo {
            if_index: if_index,
            if_name: if_name,
            mac_addr: mac_addr,
            ip_addr: ip_addr,
            hostname: String::new(),
            country_code: String::new(),
            country_name: String::new(),
            asn: String::new(),
            as_name: String::new(),
            traffic_info: TrafficInfo::new(),
            protocol_stat: HashMap::new(),
            first_seen: sys::get_sysdate(),
            updated_at: sys::get_sysdate(),
        }
    }
}

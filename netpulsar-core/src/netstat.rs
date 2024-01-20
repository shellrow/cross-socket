use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use crate::models::socket::SocketInfo;
use crate::models::process::ProcessInfo;
use crate::procs;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessSocketInfo {
    pub index: usize,
    pub socket_info: SocketInfo,
    pub process_info: ProcessInfo,
}

pub fn get_netstat() -> Vec<ProcessSocketInfo> {
    let af_flags: AddressFamilyFlags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags: ProtocolFlags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let process_map: HashMap<u32, ProcessInfo> = procs::get_process_map();
    let sockets_info: Vec<netstat2::SocketInfo> = get_sockets_info(af_flags, proto_flags).unwrap();

    let mut socket_infos: Vec<ProcessSocketInfo> = Vec::new();
    let mut index: usize = 0;

    for si in sockets_info {
        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_si) => {
                let socket_info = ProcessSocketInfo {
                    index: index,
                    socket_info: SocketInfo {
                        local_ip_addr: tcp_si.local_addr.to_string(),
                        local_port: tcp_si.local_port,
                        remote_ip_addr: Some(tcp_si.remote_addr.to_string()),
                        remote_port: Some(tcp_si.remote_port),
                        protocol: "TCP".to_string(),
                        state: Some(tcp_si.state.to_string()),
                        ip_version: if tcp_si.local_addr.is_ipv4() {4} else {6},
                    },
                    process_info: process_map.get(&si.associated_pids[0]).unwrap().to_owned(),
                };
                socket_infos.push(socket_info);
            },
            ProtocolSocketInfo::Udp(udp_si) => {
                let socket_info = ProcessSocketInfo {
                    index: index,
                    socket_info: SocketInfo {
                        local_ip_addr: udp_si.local_addr.to_string(),
                        local_port: udp_si.local_port,
                        remote_ip_addr: None,
                        remote_port: None,
                        protocol: "UDP".to_string(),
                        state: None,
                        ip_version: if udp_si.local_addr.is_ipv4() {4} else {6},
                    },
                    process_info: process_map.get(&si.associated_pids[0]).unwrap().to_owned(),
                };
                socket_infos.push(socket_info);
            },
        }
        index += 1;
    }
    socket_infos
}

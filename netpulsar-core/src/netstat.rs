use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sysinfo::{PidExt, ProcessExt, SystemExt, ProcessRefreshKind, UserExt};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use chrono::{DateTime, TimeZone, NaiveDateTime, Local};
use crate::models::socket::SocketInfo;
use crate::models::process::ProcessInfo;
use crate::models::user::UserInfo;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessSocketInfo {
    pub index: usize,
    pub socket_info: SocketInfo,
    pub process_info: ProcessInfo,
}

pub fn get_process_map() -> HashMap<u32, ProcessInfo> {
    let mut process_map: HashMap<u32, ProcessInfo> = HashMap::new();
    let system: sysinfo::System = sysinfo::System::new_with_specifics(sysinfo::RefreshKind::new().with_processes(ProcessRefreshKind::everything()).with_users_list());
    for (pid, proc) in system.processes() {
        let user_info: Option<UserInfo> = 
        if let Some(user_id) = proc.user_id() {
            let user = system.get_user_by_id(user_id);
            if let Some(user) = user {
                Some(UserInfo { 
                    id: user.id().to_string(), 
                    name: user.name().to_string(), 
                    group_id: user.group_id().to_string(), 
                    groups: user.groups().to_owned(), 
                })
            }else{
                None
            }
        }else {
            None
        };
        //let _start_time: DateTime<Utc> = Utc.timestamp_opt(proc.start_time() as i64, 0).unwrap();
        let naive_start_time: NaiveDateTime = NaiveDateTime::from_timestamp_opt(proc.start_time() as i64, 0).unwrap();
        let local_start_time: DateTime<Local> = Local.from_utc_datetime(&naive_start_time);
        let process_info: ProcessInfo = ProcessInfo { 
            pid: pid.as_u32(), 
            name: proc.name().to_string(), 
            exe_path: proc.exe().to_str().unwrap().to_string(),
            cmd: proc.cmd().to_owned(), 
            status: proc.status().to_string(), 
            user_info: user_info, 
            start_time: local_start_time.to_rfc3339(),
            elapsed_time: proc.run_time(), 
        };
        process_map.insert(pid.as_u32(), process_info);
    }
    process_map
}

pub fn get_netstat() -> Vec<ProcessSocketInfo> {
    let af_flags: AddressFamilyFlags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags: ProtocolFlags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let process_map: HashMap<u32, ProcessInfo> = get_process_map();
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

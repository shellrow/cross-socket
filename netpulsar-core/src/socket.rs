use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use serde::{Serialize, Deserialize};
use xenet::packet::tcp::TcpFlags;
use std::collections::HashMap;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use crate::net::stat::NetStatStrage;
use crate::process;
use crate::process::ProcessInfo;
use crate::net::protocol::Protocol;

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord, Copy)]
pub struct SocketConnection {
    pub local_socket: SocketAddr,
    pub remote_socket: SocketAddr,
    pub protocol: Protocol,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq)]
pub enum SocketStatus {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl SocketStatus {
    pub fn from_netstat2_state(state: netstat2::TcpState) -> Self {
        match state {
            netstat2::TcpState::Closed => SocketStatus::Closed,
            netstat2::TcpState::Listen => SocketStatus::Listen,
            netstat2::TcpState::SynSent => SocketStatus::SynSent,
            netstat2::TcpState::SynReceived => SocketStatus::SynReceived,
            netstat2::TcpState::Established => SocketStatus::Established,
            netstat2::TcpState::FinWait1 => SocketStatus::FinWait1,
            netstat2::TcpState::FinWait2 => SocketStatus::FinWait2,
            netstat2::TcpState::CloseWait => SocketStatus::CloseWait,
            netstat2::TcpState::Closing => SocketStatus::Closing,
            netstat2::TcpState::LastAck => SocketStatus::LastAck,
            netstat2::TcpState::TimeWait => SocketStatus::TimeWait,
            netstat2::TcpState::DeleteTcb => SocketStatus::DeleteTcb,
            _ => SocketStatus::Unknown,
        }
    }
    pub fn from_xenet_tcp_flags(flags: u8) -> Self {        
        // match is cause unreachable pattern. so use if-else.
        if flags == TcpFlags::SYN {
            SocketStatus::SynSent
        } else if flags == TcpFlags::SYN | TcpFlags::ACK {
            SocketStatus::SynReceived
        } else if flags == TcpFlags::ACK {
            SocketStatus::Established
        } else if flags == TcpFlags::FIN | TcpFlags::ACK {
            SocketStatus::Closing
        } else if flags == TcpFlags::FIN {
            SocketStatus::FinWait1
        } else {
            SocketStatus::Unknown
        }
    }
}

impl std::fmt::Display for SocketStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SocketStatus::Closed => "CLOSED",
                SocketStatus::Listen => "LISTEN",
                SocketStatus::SynSent => "SYN_SENT",
                SocketStatus::SynReceived => "SYN_RCVD",
                SocketStatus::Established => "ESTABLISHED",
                SocketStatus::FinWait1 => "FIN_WAIT_1",
                SocketStatus::FinWait2 => "FIN_WAIT_2",
                SocketStatus::CloseWait => "CLOSE_WAIT",
                SocketStatus::Closing => "CLOSING",
                SocketStatus::LastAck => "LAST_ACK",
                SocketStatus::TimeWait => "TIME_WAIT",
                SocketStatus::DeleteTcb => "DELETE_TCB",
                SocketStatus::Unknown => "UNKNOWN",
            }
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocketConnectionInfo {
    pub if_index: u32,
    pub if_name: String,
    pub packet_sent: usize,
    pub packet_received: usize,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub status: SocketStatus,
    pub processes: Vec<ProcessInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocketInfo {
    pub local_ip_addr: IpAddr,
    pub local_port: u16,
    pub remote_ip_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub protocol: Protocol,
    pub status: SocketStatus,
    pub ip_version: AddressFamily,
    pub processes: Vec<ProcessInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AddressFamily {
    IPv4,
    IPv6
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TransportProtocol {
    TCP,
    UDP
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocketInfoOption {
    pub address_family: Vec<AddressFamily>,
    pub transport_protocol: Vec<TransportProtocol>
}

impl Default for SocketInfoOption {
    fn default() -> SocketInfoOption {
        SocketInfoOption {
            address_family: vec![AddressFamily::IPv4, AddressFamily::IPv6],
            transport_protocol: vec![TransportProtocol::TCP, TransportProtocol::UDP],
        }
    }
}

impl SocketInfoOption {
    pub fn new(address_family: Vec<AddressFamily>, transport_protocol: Vec<TransportProtocol>) -> SocketInfoOption {
        SocketInfoOption {
            address_family: address_family,
            transport_protocol: transport_protocol,
        }
    }
    pub fn get_address_family_flags(&self) -> AddressFamilyFlags {
        let mut flags: AddressFamilyFlags = AddressFamilyFlags::empty();
        for af in &self.address_family {
            match af {
                AddressFamily::IPv4 => {
                    flags |= AddressFamilyFlags::IPV4;
                }
                AddressFamily::IPv6 => {
                    flags |= AddressFamilyFlags::IPV6;
                }
            }
        }
        flags
    }
    pub fn get_protocol_flags(&self) -> ProtocolFlags {
        let mut flags: ProtocolFlags = ProtocolFlags::empty();
        for tp in &self.transport_protocol {
            match tp {
                TransportProtocol::TCP => {
                    flags |= ProtocolFlags::TCP;
                }
                TransportProtocol::UDP => {
                    flags |= ProtocolFlags::UDP;
                }
            }
        }
        flags
    }
}

pub fn get_sockets_info(opt: SocketInfoOption) -> Vec<SocketInfo> {
    let af_flags: AddressFamilyFlags = opt.get_address_family_flags();
    let proto_flags: ProtocolFlags = opt.get_protocol_flags();
    let process_map: HashMap<u32, ProcessInfo> = process::get_process_map();
    let sockets: Vec<netstat2::SocketInfo> = netstat2::get_sockets_info(af_flags, proto_flags).unwrap();
    let mut sockets_info: Vec<SocketInfo> = Vec::new();

    for si in sockets {
        let mut processes: Vec<ProcessInfo> = vec![];
        for pid in &si.associated_pids {
            if let Some(process_info) = process_map.get(pid) {
                processes.push(process_info.to_owned());
            }
        }
        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_si) => {
                let socket_info = SocketInfo {
                    local_ip_addr: tcp_si.local_addr,
                    local_port: tcp_si.local_port,
                    remote_ip_addr: Some(tcp_si.remote_addr),
                    remote_port: Some(tcp_si.remote_port),
                    protocol: Protocol::TCP,
                    status: SocketStatus::from_netstat2_state(tcp_si.state),
                    ip_version: if tcp_si.local_addr.is_ipv4() {AddressFamily::IPv4} else {AddressFamily::IPv6},
                    processes: processes,
                };
                sockets_info.push(socket_info);
            },
            ProtocolSocketInfo::Udp(udp_si) => {
                let socket_info = SocketInfo {
                    local_ip_addr: udp_si.local_addr,
                    local_port: udp_si.local_port,
                    remote_ip_addr: None,
                    remote_port: None,
                    protocol: Protocol::UDP,
                    status: SocketStatus::Unknown,
                    ip_version: if udp_si.local_addr.is_ipv4() {AddressFamily::IPv4} else {AddressFamily::IPv6},
                    processes: processes,
                };
                sockets_info.push(socket_info);
            },
        }
    }
    sockets_info
}

pub fn start_socket_info_update(netstat_strage: &mut Arc<Mutex<NetStatStrage>>) {
    loop {
        let sockets_info = get_sockets_info(SocketInfoOption::default());
        match netstat_strage.try_lock() {
            Ok(mut netstat_strage) => {
                // remove old connections
                let mut remove_keys: Vec<SocketConnection> = vec![];
                for conn in netstat_strage.connections.iter() {
                    if !sockets_info.iter().any(|si| si.local_ip_addr == conn.0.local_socket.ip() && si.local_port == conn.0.local_socket.port()) {
                        remove_keys.push(conn.0.to_owned());
                    }
                }
                for key in remove_keys {
                    netstat_strage.connections.remove(&key);
                }
                // update connections
                for socket_info in sockets_info {
                    match socket_info.protocol {
                        Protocol::TCP => {
                            let remote_ip_addr: IpAddr = if let Some(ip) = socket_info.remote_ip_addr { ip } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) };
                            let socket_connection: SocketConnection = SocketConnection {
                                local_socket: SocketAddr::new(socket_info.local_ip_addr, socket_info.local_port),
                                remote_socket: SocketAddr::new(remote_ip_addr, socket_info.remote_port.unwrap_or(0)),
                                protocol: Protocol::TCP,
                            };
                            let socket_conn_info: &mut SocketConnectionInfo = netstat_strage.connections.entry(socket_connection).or_insert(SocketConnectionInfo {
                                if_index: 0,
                                if_name: "".to_string(),
                                packet_sent: 0,
                                packet_received: 0,
                                bytes_sent: 0,
                                bytes_received: 0,
                                status: SocketStatus::Unknown,
                                processes: vec![],
                            });
                            socket_conn_info.status = socket_info.status;
                            socket_conn_info.processes = socket_info.processes;
                        }
                        Protocol::UDP => {
                            // UDP is not a connection-oriented protocol.
                            // pcap thread can get the Destination IP address and port number from the packet.
                            // But we want to know which process is using the socket.
                            // So we use local_socket as a key and update SocketConnectionInfo.
                            for conn in netstat_strage.connections.iter_mut() {
                                if conn.0.local_socket.ip() == socket_info.local_ip_addr && conn.0.local_socket.port() == socket_info.local_port {
                                    conn.1.processes = socket_info.processes;
                                    break;
                                }
                            }
                        }
                        _ => {},
                    }
                }
                println!("[socket_info_update] total connections: {}", netstat_strage.connections.keys().len());
            }
            Err(e) => {
                println!("socket_info_update lock error{}", e);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

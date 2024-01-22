use std::{collections::{HashMap, HashSet}, net::{IpAddr, SocketAddr}, sync::{Arc, Mutex}};
use default_net::mac::MacAddr;
use serde::{Serialize, Deserialize};
use xenet::packet::tcp::TcpFlags;
use crate::{db::{self, table}, models::packet::PacketFrame, sys};
use rusqlite::{params, Connection, Statement, Rows};

use super::table::DbRemoteHost;

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord, Copy)]
pub enum Direction {
    Egress,
    Ingress,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrafficInfo {
    pub packet_sent: usize,
    pub packet_received: usize,
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

impl TrafficInfo {
    pub fn new() -> Self {
        TrafficInfo {
            packet_sent: 0,
            packet_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord, Copy)]
pub enum Protocol {
    ARP,
    NDP,
    ICMP,
    TCP,
    UDP
}

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

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord, Copy)]
pub struct SocketConnection {
    pub local_socket: SocketAddr,
    pub remote_socket: SocketAddr,
    pub protocol: Protocol,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserInfo {
    pub id: String,
    pub group_id: String,
    pub name: String,
    pub groups: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmd: Vec<String>,
    pub status: String,
    pub user_info: Option<UserInfo>,
    pub start_time: String,
    pub elapsed_time: u64,
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
    pub fn from_xenet_tcp_flags(flags: u8) -> Self {        
        // match is cause unreachable pattern. so use if-else.
        if flags == TcpFlags::SYN {
            SocketStatus::SynSent
        } else if flags == TcpFlags::SYN | TcpFlags::ACK {
            SocketStatus::SynReceived
        } else if flags == TcpFlags::ACK {
            SocketStatus::Established
        } else if flags == TcpFlags::FIN | TcpFlags::ACK {
            SocketStatus::CloseWait
        } else if flags == TcpFlags::FIN {
            SocketStatus::FinWait1
        } else if flags == TcpFlags::FIN | TcpFlags::ACK {
            SocketStatus::FinWait2
        } else if flags == TcpFlags::FIN | TcpFlags::ACK {
            SocketStatus::Closing
        } else if flags == TcpFlags::FIN | TcpFlags::ACK {
            SocketStatus::LastAck
        } else if flags == TcpFlags::FIN | TcpFlags::ACK {
            SocketStatus::TimeWait
        } else if flags == TcpFlags::FIN | TcpFlags::ACK {
            SocketStatus::DeleteTcb
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
                SocketStatus::Unknown => "__UNKNOWN",
            }
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocketInfo {
    pub if_index: u32,
    pub if_name: String,
    pub packet_sent: usize,
    pub packet_received: usize,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub status: SocketStatus,
    pub process_info: Option<ProcessInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetStatStrage {
    pub remote_hosts: HashMap<IpAddr, RemoteHostInfo>,
    pub connections: HashMap<SocketConnection, SocketInfo>,
    pub reverse_dns_map: HashMap<IpAddr, String>,
    pub local_ips: HashSet<IpAddr>,
}

impl NetStatStrage {
    pub fn new() -> Self {
        NetStatStrage {
            remote_hosts: HashMap::new(),
            connections: HashMap::new(),
            reverse_dns_map: HashMap::new(),
            local_ips: crate::interface::get_default_local_ips(),
        }
    }
    pub fn reset(&mut self) {
        self.remote_hosts.clear();
        self.connections.clear();
        self.reverse_dns_map.clear();
    }
    pub fn change_interface(&mut self, if_index: u32) {
        self.reset();
        self.local_ips = crate::interface::get_local_ips(if_index);
    }
    pub fn update(&mut self, frame: PacketFrame) {
        let datalink_layer = match frame.datalink {
            Some(datalink) => datalink,
            None => return,
        };
        let ip_layer = match frame.ip {
            Some(ip) => ip,
            None => return,
        };
        // Determine if the packet is incoming or outgoing.
        let direction: Direction = if let Some(ipv4) = &ip_layer.ipv4 {
            if self.local_ips.contains(&IpAddr::V4(ipv4.source)) {
                Direction::Egress
            } else if self.local_ips.contains(&IpAddr::V4(ipv4.destination)) {
                Direction::Ingress
            } else {
                return;
            }
        } else if let Some(ipv6) = &ip_layer.ipv6 {
            if self.local_ips.contains(&IpAddr::V6(ipv6.source)) {
                Direction::Egress
            } else if self.local_ips.contains(&IpAddr::V6(ipv6.destination)) {
                Direction::Ingress
            } else {
                return;
            }
        } else {
            return;
        };
        let mac_addr: String = match direction {
            Direction::Egress => {
                if let Some(ethernet) = datalink_layer.ethernet {
                    ethernet.destination.address()
                } else {
                    MacAddr::zero().to_string()
                }
            },
            Direction::Ingress => {
                if let Some(ethernet) = datalink_layer.ethernet {
                    ethernet.source.address()
                } else {
                    MacAddr::zero().to_string()
                }
            },
        };
        let remote_ip_addr: IpAddr = match direction {
            Direction::Egress => {
                if let Some(ipv4) = ip_layer.ipv4 {
                    IpAddr::V4(ipv4.destination)
                } else if let Some(ipv6) = ip_layer.ipv6 {
                    IpAddr::V6(ipv6.destination)
                } else {
                    return;
                }
            },
            Direction::Ingress => {
                if let Some(ipv4) = ip_layer.ipv4 {
                    IpAddr::V4(ipv4.source)
                } else if let Some(ipv6) = ip_layer.ipv6 {
                    IpAddr::V6(ipv6.source)
                } else {
                    return;
                }
            },
        };
        // Update or Insert RemoteHostInfo
        let remote_host: &mut RemoteHostInfo = self.remote_hosts.entry(remote_ip_addr).or_insert(RemoteHostInfo::new(
            frame.if_index,
            frame.if_name.clone(),
            mac_addr,
            remote_ip_addr,
        ));
        match direction {
            Direction::Egress => {
                remote_host.traffic_info.packet_sent += 1;
                remote_host.traffic_info.bytes_sent += frame.packet_len;
            },
            Direction::Ingress => {
                remote_host.traffic_info.packet_received += 1;
                remote_host.traffic_info.bytes_received += frame.packet_len;
            },
        }
        // Update SocketInfo if the packet is TCP or UDP.
        if let Some(transport) = frame.transport {
            if let Some(tcp) = transport.tcp {
                let tcp_traffic_info: &mut TrafficInfo = remote_host.protocol_stat.entry(Protocol::TCP).or_insert(TrafficInfo::new());
                match direction {
                    Direction::Egress => {
                        tcp_traffic_info.packet_sent += 1;
                        tcp_traffic_info.bytes_sent += frame.packet_len;
                    },
                    Direction::Ingress => {
                        tcp_traffic_info.packet_received += 1;
                        tcp_traffic_info.bytes_received += frame.packet_len;
                    },
                }
                // Update SocketInfo
                let socket_connection: SocketConnection = SocketConnection {
                    local_socket: SocketAddr::new(remote_ip_addr, tcp.source),
                    remote_socket: SocketAddr::new(remote_ip_addr, tcp.destination),
                    protocol: Protocol::TCP,
                };
                let socket_info: &mut SocketInfo = self.connections.entry(socket_connection).or_insert(SocketInfo {
                    if_index: frame.if_index,
                    if_name: frame.if_name.clone(),
                    packet_sent: 0,
                    packet_received: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    status: SocketStatus::from_xenet_tcp_flags(tcp.flags),
                    process_info: None,
                });
                match direction {
                    Direction::Egress => {
                        socket_info.packet_sent += 1;
                        socket_info.bytes_sent += frame.packet_len;
                    },
                    Direction::Ingress => {
                        socket_info.packet_received += 1;
                        socket_info.bytes_received += frame.packet_len;
                    },
                }
            }
            if let Some(udp) = transport.udp {
                let udp_traffic_info: &mut TrafficInfo = remote_host.protocol_stat.entry(Protocol::UDP).or_insert(TrafficInfo::new());
                match direction {
                    Direction::Egress => {
                        udp_traffic_info.packet_sent += 1;
                        udp_traffic_info.bytes_sent += frame.packet_len;
                    },
                    Direction::Ingress => {
                        udp_traffic_info.packet_received += 1;
                        udp_traffic_info.bytes_received += frame.packet_len;
                    },
                }
                // Update SocketInfo
                let socket_connection: SocketConnection = SocketConnection {
                    local_socket: SocketAddr::new(remote_ip_addr, udp.source),
                    remote_socket: SocketAddr::new(remote_ip_addr, udp.destination),
                    protocol: Protocol::UDP,
                };
                let socket_info: &mut SocketInfo = self.connections.entry(socket_connection).or_insert(SocketInfo {
                    if_index: frame.if_index,
                    if_name: frame.if_name.clone(),
                    packet_sent: 0,
                    packet_received: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    status: SocketStatus::Unknown,
                    process_info: None,
                });
                match direction {
                    Direction::Egress => {
                        socket_info.packet_sent += 1;
                        socket_info.bytes_sent += frame.packet_len;
                    },
                    Direction::Ingress => {
                        socket_info.packet_received += 1;
                        socket_info.bytes_received += frame.packet_len;
                    },
                }
            }
        }
    }
}

pub fn get_traffic_summary() -> Vec<table::DbRemoteHost> {
    let mut traffic_summary: Vec<table::DbRemoteHost> = Vec::new();
    let iface: default_net::Interface = default_net::get_default_interface().unwrap();
    let local_ips = crate::interface::get_interface_ips(&iface);
    let conn: Connection = match db::connect_db(db::DB_NAME) {
        Ok(c)=> c, 
        Err(e) => {
            println!("Error: {:?}", e);
            return traffic_summary;
        },
    };
    let mut stmt: Statement = conn.prepare("
        SELECT
            remote_address,
            SUM(CASE WHEN direction = 'in' THEN packet_count ELSE 0 END) AS in_packet_count,
            SUM(CASE WHEN direction = 'out' THEN packet_count ELSE 0 END) AS out_packet_count,
            SUM(CASE WHEN direction = 'in' THEN byte_count ELSE 0 END) AS in_byte_count,
            SUM(CASE WHEN direction = 'out' THEN byte_count ELSE 0 END) AS out_byte_count
        FROM (
            SELECT
                CASE
                    WHEN src_ip IN rarray(?1) THEN dst_ip
                    WHEN dst_ip IN rarray(?1) THEN src_ip
                    ELSE '0.0.0.0'
                END AS remote_address,
                CASE
                    WHEN src_ip IN rarray(?1) THEN 'out'
                    WHEN dst_ip IN rarray(?1) THEN 'in'
                    ELSE '0.0.0.0'
                END AS direction,
                COUNT(*) AS packet_count,
                SUM(packet_len) AS byte_count
            FROM packet_frame
            GROUP BY remote_address, direction
        ) AS subquery
        GROUP BY remote_address
    ").unwrap();
    let values:Vec<rusqlite::types::Value> = local_ips.into_iter().map(rusqlite::types::Value::from).collect();
    let ptr = std::rc::Rc::new(values);
    let mut rows: Rows = stmt.query(params![ptr]).unwrap();
    let sysdate: String = sys::get_sysdate();
    while let Some(row) = rows.next().unwrap() {
        let remote_address: String = row.get(0).unwrap();
        let in_packet_count: usize = row.get(1).unwrap();
        let out_packet_count: usize = row.get(2).unwrap();
        let in_byte_count: usize = row.get(3).unwrap();
        let out_byte_count: usize = row.get(4).unwrap();
        let remote_host: table::DbRemoteHost = table::DbRemoteHost {
            ip_addr: remote_address,
            hostname: String::new(),
            country_code: String::new(),
            country_name: String::new(),
            asn: String::new(),
            as_name: String::new(),
            packet_received: in_packet_count,
            packet_sent: out_packet_count,
            bytes_received: in_byte_count,
            bytes_sent: out_byte_count,
            first_seen: sysdate.clone(),
            updated_at: sysdate.clone(),
        };
        traffic_summary.push(remote_host);
    }
    traffic_summary
}

pub fn start_stat_updater(netstat_strage: &mut Arc<Mutex<db::stat::NetStatStrage>>) {
    loop {
        let mut remote_ips: Vec<IpAddr> = vec![];
        match netstat_strage.try_lock() {
            Ok(netstat_strage) => {
                println!("Total remotehost {}", netstat_strage.remote_hosts.keys().len());
                netstat_strage.remote_hosts.keys().for_each(|ip_addr| {
                    if !netstat_strage.reverse_dns_map.contains_key(ip_addr) {
                        remote_ips.push(*ip_addr);
                    }
                });
            }
            Err(_) => {
                println!("netstat_strage_updater locked failed");
            }
        }
        let dns_map = crate::dns::lookup_ips(remote_ips);
        match netstat_strage.try_lock() {
            Ok(mut netstat_strage) => {
                for (ip_addr, hostname) in dns_map {
                    if let Some(remote_host) = netstat_strage.remote_hosts.get_mut(&ip_addr) {
                        remote_host.hostname = hostname.clone();
                    }
                    netstat_strage.reverse_dns_map.insert(ip_addr, hostname);
                }
                println!("DNS Map updated {:?}", netstat_strage.reverse_dns_map);
            }
            Err(_) => {
                println!("netstat_strage_updater locked failed");
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

pub fn get_remote_hosts() -> Vec<DbRemoteHost> {
    let conn: Connection = match db::connect_db(db::DB_NAME) {
        Ok(c)=> c, 
        Err(e) => {
            println!("Error: {:?}", e);
            return Vec::new();
        },
    };
    let mut stmt: Statement = conn.prepare("
        SELECT
            ip_addr,
            hostname,
            country_code,
            country_name,
            asn,
            as_name,
            packet_received,
            packet_sent,
            bytes_received,
            bytes_sent,
            first_seen,
            updated_at
        FROM remote_host
    ").unwrap();
    let mut rows: Rows = stmt.query(params![]).unwrap();
    let mut remote_hosts: Vec<DbRemoteHost> = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        let remote_host: DbRemoteHost = DbRemoteHost {
            ip_addr: row.get(0).unwrap(),
            hostname: row.get(1).unwrap(),
            country_code: row.get(2).unwrap(),
            country_name: row.get(3).unwrap(),
            asn: row.get(4).unwrap(),
            as_name: row.get(5).unwrap(),
            packet_received: row.get(6).unwrap(),
            packet_sent: row.get(7).unwrap(),
            bytes_received: row.get(8).unwrap(),
            bytes_sent: row.get(9).unwrap(),
            first_seen: row.get(10).unwrap(),
            updated_at: row.get(11).unwrap(),
        };
        remote_hosts.push(remote_host);
    }
    remote_hosts
}
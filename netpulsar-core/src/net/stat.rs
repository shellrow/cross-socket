use default_net::mac::MacAddr;
use serde::{Serialize, Deserialize};
use std::{collections::{HashMap, HashSet}, net::{IpAddr, SocketAddr}};
use super::{host::RemoteHostInfo, protocol::Protocol, traffic::{Direction, TrafficInfo}, packet::PacketFrame};
use super::interface;
use crate::socket::{SocketConnection, SocketConnectionInfo, SocketStatus};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetStatStrage {
    pub remote_hosts: HashMap<IpAddr, RemoteHostInfo>,
    pub connections: HashMap<SocketConnection, SocketConnectionInfo>,
    pub reverse_dns_map: HashMap<IpAddr, String>,
    pub local_ips: HashSet<IpAddr>,
}

impl NetStatStrage {
    pub fn new() -> Self {
        NetStatStrage {
            remote_hosts: HashMap::new(),
            connections: HashMap::new(),
            reverse_dns_map: HashMap::new(),
            local_ips: interface::get_default_local_ips(),
        }
    }
    pub fn reset(&mut self) {
        self.remote_hosts.clear();
        self.connections.clear();
        self.reverse_dns_map.clear();
    }
    pub fn change_interface(&mut self, if_index: u32) {
        self.reset();
        self.local_ips = interface::get_local_ips(if_index);
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
                let socket_info: &mut SocketConnectionInfo = self.connections.entry(socket_connection).or_insert(SocketConnectionInfo {
                    if_index: frame.if_index,
                    if_name: frame.if_name.clone(),
                    packet_sent: 0,
                    packet_received: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    status: SocketStatus::from_xenet_tcp_flags(tcp.flags),
                    process: None,
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
                let socket_info: &mut SocketConnectionInfo = self.connections.entry(socket_connection).or_insert(SocketConnectionInfo {
                    if_index: frame.if_index,
                    if_name: frame.if_name.clone(),
                    packet_sent: 0,
                    packet_received: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    status: SocketStatus::Unknown,
                    process: None,
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

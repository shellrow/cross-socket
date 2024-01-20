use std::net::Ipv4Addr;
use serde::{Serialize, Deserialize};
use rusqlite::{Connection, Result, params, Transaction, Statement, Rows};
use crate::sys;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbPacketFrame {
    /// Capture number.
    pub capture_no: usize,
    // Packet arrival time. RFC3339 format.
    pub timestamp: String,
    /// interface index
    pub if_index: u32,
    /// interface name.
    pub if_name: String,
    /// src mac address.
    pub src_mac: String,
    /// dst mac address.
    pub dst_mac: String,
    /// src ip address.
    pub src_ip: String,
    /// dst ip address.
    pub dst_ip: String,
    /// IP version.
    pub ip_version: u8,
    /// src port.
    pub src_port: u16,
    /// dst port.
    pub dst_port: u16,
    /// Protocol.
    pub protocol: String,
    /// Packet length.
    pub packet_len: usize,
}

impl DbPacketFrame {
    pub fn new() -> Self {
        DbPacketFrame {
            capture_no: 0,
            timestamp: String::new(),
            if_index: 0,
            if_name: String::new(),
            src_mac: String::new(),
            dst_mac: String::new(),
            src_ip: Ipv4Addr::UNSPECIFIED.to_string(),
            dst_ip: Ipv4Addr::UNSPECIFIED.to_string(),
            ip_version: 4,
            src_port: 0,
            dst_port: 0,
            protocol: String::new(),
            packet_len: 0,
        }
    }
    pub fn from_xenet_frame(capture_no: usize, if_index: u32, if_name: String, frame: xenet::packet::frame::Frame) -> DbPacketFrame {
        let mut simple_frame = DbPacketFrame::new();
        simple_frame.capture_no = capture_no;
        simple_frame.timestamp = sys::get_sysdate();
        simple_frame.if_index = if_index;
        simple_frame.if_name = if_name;
        if let Some(datalink) = frame.datalink {
            if let Some(ethernet) = datalink.ethernet {
                simple_frame.src_mac = ethernet.source.address();
                simple_frame.dst_mac = ethernet.destination.address();
                simple_frame.protocol = ethernet.ethertype.name().to_string();
            }
            if let Some(arp) = datalink.arp {
                simple_frame.src_mac = arp.sender_hw_addr.address();
                simple_frame.dst_mac = arp.target_hw_addr.address();
                simple_frame.src_ip = arp.sender_proto_addr.to_string();
                simple_frame.dst_ip = arp.target_proto_addr.to_string();
                simple_frame.protocol = "ARP".to_string();
            }
        }
        if let Some(ip) = frame.ip {
            if let Some(ipv4) = ip.ipv4 {
                simple_frame.src_ip = ipv4.source.to_string();
                simple_frame.dst_ip = ipv4.destination.to_string();
                simple_frame.ip_version = 4;
                simple_frame.protocol = ipv4.next_level_protocol.as_str().to_uppercase();
            }
            if let Some(ipv6) = ip.ipv6 {
                simple_frame.src_ip = ipv6.source.to_string();
                simple_frame.dst_ip = ipv6.destination.to_string();
                simple_frame.ip_version = 6;
                simple_frame.protocol = ipv6.next_header.as_str().to_uppercase();
            }
        }
        if let Some(transport) = frame.transport {
            if let Some(tcp) = transport.tcp {
                simple_frame.src_port = tcp.source;
                simple_frame.dst_port = tcp.destination;
                simple_frame.protocol = "TCP".to_string();
            }
            if let Some(udp) = transport.udp {
                simple_frame.src_port = udp.source;
                simple_frame.dst_port = udp.destination;
                simple_frame.protocol = "UDP".to_string();
            }
        }
        if simple_frame.protocol.is_empty() {
            simple_frame.protocol = "UNKNOWN".to_string();
        }
        simple_frame.packet_len = frame.packet_len;
        simple_frame
    }
    pub fn create(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS packet_frame (
                capture_no INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                if_index INTEGER NOT NULL,
                if_name TEXT NOT NULL,
                src_mac TEXT NOT NULL,
                dst_mac TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                packet_len INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmd: Vec<String>,
    pub status: String,
    pub user_id: String,
    pub start_time: String,
    pub elapsed_time: u64,
    pub packet_sent: usize,
    pub packet_received: usize,
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

impl DbProcessInfo {
    pub fn new() -> Self {
        DbProcessInfo {
            pid: 0,
            name: String::new(),
            exe_path: String::new(),
            cmd: Vec::new(),
            status: String::new(),
            user_id: String::new(),
            start_time: String::new(),
            elapsed_time: 0,
            packet_sent: 0,
            packet_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
    pub fn create(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS process_info (
                pid INTEGER NOT NULL,
                name TEXT NOT NULL,
                exe_path TEXT NOT NULL,
                cmd TEXT NOT NULL,
                status TEXT NOT NULL,
                user_id TEXT NOT NULL,
                start_time TEXT NOT NULL,
                elapsed_time INTEGER NOT NULL,
                packet_sent INTEGER NOT NULL,
                packet_received INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbSocketInfo {
    pub local_ip_addr: String,
    pub local_port: u16,
    pub remote_ip_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub ip_version: u8,
    pub packet_sent: usize,
    pub packet_received: usize,
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

impl DbSocketInfo {
    pub fn new() -> Self {
        DbSocketInfo {
            local_ip_addr: String::new(),
            local_port: 0,
            remote_ip_addr: String::new(),
            remote_port: 0,
            protocol: String::new(),
            state: String::new(),
            ip_version: 0,
            packet_sent: 0,
            packet_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
    pub fn create(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS socket_info (
                local_ip_addr TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_ip_addr TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                ip_version INTEGER NOT NULL,
                packet_sent INTEGER NOT NULL,
                packet_received INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbUserInfo {
    pub id: String,
    pub name: String,
}

impl DbUserInfo {
    pub fn new() -> Self {
        DbUserInfo {
            id: String::new(),
            name: String::new(),
        }
    }
    pub fn create(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_info (
                id TEXT NOT NULL,
                name TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbUserGroup {
    pub user_id: String,
    pub group_id: String,
}

impl DbUserGroup {
    pub fn new() -> Self {
        DbUserGroup {
            user_id: String::new(),
            group_id: String::new(),
        }
    }
    pub fn create(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_group (
                user_id TEXT NOT NULL,
                group_id TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbGroupInfo {
    pub group_id: String,
    pub group_name: String,
}

impl DbGroupInfo {
    pub fn new() -> Self {
        DbGroupInfo {
            group_id: String::new(),
            group_name: String::new(),
        }
    }
    pub fn create(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS group_info (
                group_id TEXT NOT NULL,
                group_name TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbRemoteHost {
    pub ip_addr: String,
    pub hostname: String,
    pub country_code: String,
    pub country_name: String,
    pub asn: String,
    pub as_name: String,
    pub packet_sent: usize,
    pub packet_received: usize,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub first_seen: String,
    pub updated_at: String,
}

impl DbRemoteHost {
    pub fn new() -> Self {
        DbRemoteHost {
            ip_addr: String::new(),
            hostname: String::new(),
            country_code: String::new(),
            country_name: String::new(),
            asn: String::new(),
            as_name: String::new(),
            packet_sent: 0,
            packet_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            first_seen: String::new(),
            updated_at: String::new(),
        }
    }
    pub fn create(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS remote_host (
                ip_addr TEXT NOT NULL,
                hostname TEXT NOT NULL,
                country_code TEXT NOT NULL,
                country_name TEXT NOT NULL,
                asn TEXT NOT NULL,
                as_name TEXT NOT NULL,
                packet_sent INTEGER NOT NULL,
                packet_received INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_received INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbRemoteService {
    pub ip_addr: String,
    pub hostname: String,
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub service_info: String,
    pub cpe: String,
    pub first_seen: String,
    pub updated_at: String,
}

impl DbRemoteService {
    pub fn new() -> Self {
        DbRemoteService {
            ip_addr: String::new(),
            hostname: String::new(),
            port: 0,
            protocol: String::new(),
            service_name: String::new(),
            service_info: String::new(),
            cpe: String::new(),
            first_seen: String::new(),
            updated_at: String::new(),
        }
    }
    pub fn create(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS remote_service (
                ip_addr TEXT NOT NULL,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT NOT NULL,
                service_info TEXT NOT NULL,
                cpe TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }
}

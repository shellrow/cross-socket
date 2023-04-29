use std::{vec};
use serde::{Deserialize, Serialize};
use rusqlite::{Result, params, Transaction};

use crate::db;

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

// DB models

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeType {
    pub probe_type_id: String,
    pub probe_type_name: String,
    pub probe_type_description: String,
}

impl ProbeType {
    pub fn new() -> ProbeType {
        ProbeType {
            probe_type_id: String::new(),
            probe_type_name: String::new(),
            probe_type_description: String::new(),
        }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS probe_type (
            probe_type_id TEXT PRIMARY KEY,
            probe_type_name TEXT NOT NULL,
            probe_type_description TEXT NULL);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn init(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let mut count: usize = 0;
        let mut probe_type: ProbeType = ProbeType::new();
        probe_type.probe_type_id = CommandType::PortScan.id();
        probe_type.probe_type_name = CommandType::PortScan.name();
        probe_type.probe_type_description = CommandType::PortScan.description();
        count += probe_type.insert(tran)?;
        probe_type.probe_type_id = CommandType::HostScan.id();
        probe_type.probe_type_name = CommandType::HostScan.name();
        probe_type.probe_type_description = CommandType::HostScan.description();
        count += probe_type.insert(tran)?;
        probe_type.probe_type_id = CommandType::Ping.id();
        probe_type.probe_type_name = CommandType::Ping.name();
        probe_type.probe_type_description = CommandType::Ping.description();
        count += probe_type.insert(tran)?;
        probe_type.probe_type_id = CommandType::Traceroute.id();
        probe_type.probe_type_name = CommandType::Traceroute.name();
        probe_type.probe_type_description = CommandType::Traceroute.description();
        count += probe_type.insert(tran)?;
        //probe_type.probe_type_id = CommandType::DomainScan.id();
        //probe_type.probe_type_name = CommandType::DomainScan.name();
        //probe_type.probe_type_description = CommandType::DomainScan.description();
        //count += probe_type.insert(tran)?;
        Ok(count)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT OR IGNORE INTO probe_type (probe_type_id, probe_type_name, probe_type_description) VALUES (?1, ?2, ?3);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.probe_type_id, self.probe_type_name, self.probe_type_description];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        // Omit!
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM probe_type WHERE probe_type_id = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.probe_type_id];
        tran.execute(sql, params_vec)
    }
}

// DB Models
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProbeResult {
    pub id: u32,
    pub probe_id: String,
    pub probe_type_id: String,
    pub probe_target_addr: String,
    pub probe_target_name: String,
    pub protocol_id: String,
    pub probe_option: Option<String>,
    pub scan_time: Option<u64>,
    pub service_detection_time: Option<u64>,
    pub os_detection_time: Option<u64>,
    pub probe_time: Option<u64>,
    pub transmitted_count: Option<u64>,
    pub received_count: Option<u64>,
    pub min_value: Option<u64>,
    pub avg_value: Option<u64>,
    pub max_value: Option<u64>,
    pub issued_at: String,
}

impl ProbeResult {
    pub fn new() -> ProbeResult {
        ProbeResult { 
            id: 0, 
            probe_id: String::new(), 
            probe_type_id: String::new(), 
            probe_target_addr: String::new(), 
            probe_target_name: String::new(), 
            protocol_id: String::new(), 
            probe_option: None, 
            scan_time: None, 
            service_detection_time: None, 
            os_detection_time: None, 
            probe_time: None, 
            transmitted_count: None, 
            received_count: None, 
            min_value: None, 
            avg_value: None, 
            max_value: None, 
            issued_at: String::new() 
        }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS probe_result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            probe_id TEXT NOT NULL,
            probe_type_id TEXT NOT NULL,
            probe_target_addr TEXT NOT NULL,
            probe_target_name TEXT NOT NULL,
            protocol_id TEXT NOT NULL,
            probe_option TEXT NULL,
            scan_time INTEGER NULL, 
            service_detection_time INTEGER NULL, 
            os_detection_time INTEGER NULL, 
            probe_time INTEGER NULL, 
            transmitted_count INTEGER NULL,
            received_count INTEGER NULL,
            min_value INTEGER NULL,
            avg_value INTEGER NULL,
            max_value INTEGER NULL,
            issued_at TEXT NOT NULL);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PortScanResult {
    pub id: u32,
    pub probe_id: String,
    pub socket_addr: String,
    pub ip_addr: String,
    pub host_name: String,
    pub port: u16,
    pub port_status_id: String,
    pub service_id: String,
    pub service_version: String,
    pub protocol_id: String,
    pub issued_at: String,
}
impl PortScanResult {
    pub fn new() -> PortScanResult {
        PortScanResult { 
            id: 0, 
            probe_id: String::new(), 
            socket_addr: String::new(), 
            ip_addr: String::new(), 
            host_name: String::new(), 
            port: 0, 
            port_status_id: String::new(), 
            service_id: String::new(), 
            service_version: String::new(),
            protocol_id: String::new(),
            issued_at: String::new() 
        }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS port_scan_result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            probe_id TEXT NOT NULL,
            socket_addr TEXT NOT NULL,
            ip_addr TEXT NOT NULL,
            host_name TEXT NOT NULL,
            port INTEGER NOT NULL,
            port_status_id TEXT NOT NULL,
            protocol_id TEXT NOT NULL,
            service_id TEXT NULL,
            service_version TEXT NULL,
            issued_at TEXT NOT NULL);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostScanResult {
    pub id: u32,
    pub probe_id: String,
    pub ip_addr: String,
    pub host_name: String,
    pub port: u16,
    pub protocol_id: String,
    pub issued_at: String,
}

impl HostScanResult {
    pub fn new() -> HostScanResult {
        HostScanResult { 
            id: 0, 
            probe_id: String::new(), 
            ip_addr: String::new(), 
            host_name: String::new(), 
            port: 0, 
            protocol_id: String::new(), 
            issued_at: String::new() 
        }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS host_scan_result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            probe_id TEXT NOT NULL,
            ip_addr TEXT NOT NULL,
            host_name TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol_id TEXT NOT NULL,
            issued_at TEXT NOT NULL);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

pub struct PingResult {
    pub id: u32,
    pub probe_id: String,
    pub seq: u16,
    pub ip_addr: String,
    pub host_name: String,
    pub port: u16,
    pub port_status_id: String,
    pub ttl: u16,
    pub hop: u16,
    pub rtt: u64,
    pub issued_at: String,
}

impl PingResult {
    pub fn new() -> PingResult {
        PingResult { 
            id: 0, 
            probe_id: String::new(), 
            seq: 0,
            ip_addr: String::new(), 
            host_name: String::new(), 
            port: 0, 
            port_status_id: String::new(), 
            ttl: 0, 
            hop: 0, 
            rtt: 0, 
            issued_at: String::new() 
        }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS ping_result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            probe_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            ip_addr TEXT NOT NULL,
            host_name TEXT NOT NULL,
            port INTEGER NOT NULL,
            port_status_id TEXT NOT NULL,
            ttl INTEGER NOT NULL,
            hop INTEGER NOT NULL,
            rtt INTEGER NOT NULL,
            issued_at TEXT NOT NULL);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TracerouteResult {
    pub id: u32,
    pub probe_id: String,
    pub seq: u16,
    pub ip_addr: String,
    pub host_name: String,
    pub port: u16,
    pub ttl: u16,
    pub hop: u16,
    pub rtt: u64,
    pub issued_at: String,
}

impl TracerouteResult {
    pub fn new() -> TracerouteResult {
        TracerouteResult { 
            id: 0, 
            probe_id: String::new(), 
            seq: 0,
            ip_addr: String::new(), 
            host_name: String::new(), 
            port: 0, 
            ttl: 0, 
            hop: 0, 
            rtt: 0, 
            issued_at: String::new() 
        }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS traceroute_result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            probe_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            ip_addr TEXT NOT NULL,
            host_name TEXT NOT NULL,
            port INTEGER NOT NULL,
            ttl INTEGER NOT NULL,
            hop INTEGER NOT NULL,
            rtt INTEGER NOT NULL,
            issued_at TEXT NOT NULL);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapInfo {
    pub map_id: u32,
    pub map_name: String,
    pub display_order: u32,
    pub created_at: String,
}

impl MapInfo {
    pub fn new() -> MapInfo {
        MapInfo { map_id: 0, map_name: String::new(), display_order: 0, created_at: String::new() }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS map_info (
            map_id INTEGER PRIMARY KEY AUTOINCREMENT,
            map_name TEXT NULL, 
            display_order INTEGER NULL,
            created_at TEXT NULL 
        );";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapNode {
    pub map_id: u32,
    pub node_id: String,
    pub node_name: String,
    pub ip_addr: String,
    pub host_name: String,
}

impl MapNode {
    pub fn new() -> MapNode {
        MapNode { map_id: 0, node_id: String::new(), node_name: String::new(), ip_addr: String::new(), host_name: String::new() }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS map_node (
            map_id INTEGER NOT NULL, 
            node_id TEXT NOT NULL,
            node_name TEXT NULL,
            ip_addr TEXT NULL, 
            host_name TEXT NULL, 
            PRIMARY KEY(map_id, node_id) 
        );";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapEdge {
    pub map_id: u32,
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_label: String,
}

impl MapEdge {
    pub fn new() -> MapEdge {
        MapEdge { map_id: 0, edge_id: String::new(), source_node_id: String::new(), target_node_id: String::new(), edge_label: String::new() }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS map_edge (
            map_id INTEGER NOT NULL,  
            edge_id TEXT NOT NULL,
            source_node_id TEXT NOT NULL,
            target_node_id TEXT NOT NULL, 
            edge_label TEXT NULL, 
            PRIMARY KEY(map_id, edge_id) 
        );";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapLayout {
    pub map_id: u32,
    pub node_id: String,
    pub x_value: f32,
    pub y_value: f32
}

impl MapLayout {
    pub fn new() -> MapLayout {
        MapLayout { map_id: 0, node_id: String::new(), x_value: 0.0, y_value: 0.0 }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS map_layout (
            map_id INTEGER NOT NULL, 
            node_id TEXT NOT NULL,
            x_value INTEGER NOT NULL,
            y_value INTEGER NOT NULL, 
            PRIMARY KEY(map_id, node_id)
        );";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Oui {
    pub mac_prefix: String,
    pub vendor_name: String,
    pub vendor_name_detail: String,
}

impl Oui {
    pub fn new() -> Oui {
        Oui { mac_prefix: String::new(), vendor_name: String::new(), vendor_name_detail: String::new() }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS oui (
            mac_prefix TEXT NOT NULL, 
            vendor_name TEXT NOT NULL,
            vendor_name_detail TEXT NULL, 
            PRIMARY KEY(mac_prefix) 
        );";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO oui (mac_prefix, vendor_name, vendor_name_detail)
        VALUES (?1,?2,?3);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.mac_prefix, self.vendor_name, self.vendor_name_detail];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM oui WHERE mac_prefix = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.mac_prefix];
        tran.execute(sql, params_vec)
    }
    pub fn get_oui_list() -> Vec<Oui> {
        let mut oui_list: Vec<Oui> = Vec::new();
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT mac_prefix, vendor_name, vendor_name_detail FROM oui;").unwrap();
        let oui_iter = stmt.query_map(params![], |row| {
            Ok(Oui {
                mac_prefix: row.get(0)?,
                vendor_name: row.get(1)?,
                vendor_name_detail: row.get(2)?,
            })
        }).unwrap();
        for oui in oui_iter {
            oui_list.push(oui.unwrap());
        }
        oui_list
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpService {
    pub port: u16, 
    pub service_name: String, 
    pub service_description: String,   
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

impl TcpService {
    pub fn new() -> TcpService {
        TcpService { port: 0, service_name: String::new(), service_description: String::new(), wellknown_flag: 0, default_flag: 0}
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS tcp_service (
            port INTEGER NOT NULL, 
            service_name TEXT NOT NULL,
            service_description TEXT NULL, 
            wellknown_flag INTEGER NOT NULL,
            default_flag INTEGER NOT NULL,
            PRIMARY KEY(port) 
        );";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO tcp_service (port, service_name, service_description, wellknown_flag, default_flag) VALUES (?1,?2,?3,?4,?5);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.port, self.service_name, self.service_description, self.wellknown_flag, self.default_flag];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update_wellknown_flag(tran:&Transaction, port: u16, wellknown_flag: u32) -> Result<usize,rusqlite::Error>{
        let sql: &str = "UPDATE tcp_service SET wellknown_flag = ?1 WHERE port = ?2;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![wellknown_flag, port];
        tran.execute(sql, params_vec)
    }
    pub fn update_default_flag(tran:&Transaction, port: u16, default_flag: u32) -> Result<usize,rusqlite::Error>{
        let sql: &str = "UPDATE tcp_service SET default_flag = ?1 WHERE port = ?2;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![default_flag, port];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM tcp_service WHERE port = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.port];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpTag {
    pub port: u16,
    pub tag: String,
}

impl TcpTag {
    pub fn new() -> TcpTag {
        TcpTag { port: 0, tag: String::new() }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS tcp_tag (
            port INTEGER NOT NULL, 
            tag TEXT NOT NULL,
            PRIMARY KEY(port, tag) 
        );";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO tcp_tag (port, tag) VALUES (?1,?2);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.port, self.tag];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM tcp_tag WHERE port = ?1 AND tag = ?2;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.port, self.tag];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpService {
    pub port: u16,
    pub service_name: String,
    pub service_description: String,   
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

impl UdpService {
    pub fn new() -> UdpService {
        UdpService { port: 0, service_name: String::new(), service_description: String::new(), wellknown_flag: 0, default_flag: 0}
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS udp_service (
            port INTEGER NOT NULL, 
            service_name TEXT NOT NULL,
            service_description TEXT NULL, 
            wellknown_flag INTEGER NOT NULL,
            default_flag INTEGER NOT NULL,
            PRIMARY KEY(port) 
        );";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO udp_service (port, service_name, service_description, wellknown_flag, default_flag) VALUES (?1,?2,?3,?4,?5);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.port, self.service_name, self.service_description, self.wellknown_flag, self.default_flag];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update_wellknown_flag(tran:&Transaction, port: u16, wellknown_flag: u32) -> Result<usize,rusqlite::Error>{
        let sql: &str = "UPDATE udp_service SET wellknown_flag = ?1 WHERE port = ?2;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![wellknown_flag, port];
        tran.execute(sql, params_vec)
    }
    pub fn update_default_flag(tran:&Transaction, port: u16, default_flag: u32) -> Result<usize,rusqlite::Error>{
        let sql: &str = "UPDATE udp_service SET default_flag = ?1 WHERE port = ?2;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![default_flag, port];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM udp_service WHERE port = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.port];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpTag {
    pub port: u16,
    pub tag: String,
}

impl UdpTag {
    pub fn new() -> UdpTag {
        UdpTag { port: 0, tag: String::new() }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS udp_tag (
            port INTEGER NOT NULL, 
            tag TEXT NOT NULL,
            PRIMARY KEY(port, tag) 
        );";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO udp_tag (port, tag) VALUES (?1,?2);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.port, self.tag];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM udp_tag WHERE port = ?1 AND tag = ?2;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.port, self.tag];
        tran.execute(sql, params_vec)
    }
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

impl OsFingerprint {
    pub fn new() -> OsFingerprint {
        OsFingerprint { 
            cpe: String::new(), 
            os_name: String::new(), 
            os_vendor: String::new(), 
            os_family: String::new(), 
            os_generation: String::new(), 
            device_type: String::new(), 
            tcp_window_size: 0, 
            tcp_option_pattern: String::new() 
        }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS os_fingerprint (
            cpe TEXT NOT NULL,
            os_name TEXT NOT NULL,
            os_vendor TEXT NOT NULL,
            os_family TEXT NOT NULL,
            os_generation TEXT NOT NULL,
            device_type TEXT NOT NULL,
            tcp_window_size INTEGER NOT NULL,
            tcp_option_pattern TEXT NOT NULL,
            PRIMARY KEY (cpe)
        )";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO os_fingerprint (cpe, os_name, os_vendor, os_family, os_generation, device_type, tcp_window_size, tcp_option_pattern) VALUES (?1,?2,?3,?4,?5,?6,?7,?8);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.cpe, self.os_name, self.os_vendor, self.os_family, self.os_generation, self.device_type, self.tcp_window_size, self.tcp_option_pattern];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM os_fingerprint WHERE cpe = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.cpe];
        tran.execute(sql, params_vec)
    }
    pub fn get() -> OsFingerprint {
        // Omit!
        OsFingerprint::new()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsTtl {
    pub os_family: String,
    pub os_description: String,
    pub initial_ttl: u8,
}

impl OsTtl {
    pub fn new() -> OsTtl {
        OsTtl { os_family: String::new(), os_description: String::new(), initial_ttl: 0 }
    }
    pub fn create(tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "CREATE TABLE IF NOT EXISTS os_ttl (
            os_family TEXT NOT NULL,
            os_description TEXT NOT NULL,
            initial_ttl INTEGER NOT NULL,
            PRIMARY KEY (os_family, initial_ttl)
        )";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO os_ttl (os_family, os_description, initial_ttl) VALUES (?1,?2,?3);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.os_family, self.os_description, self.initial_ttl];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM os_ttl WHERE os_family = ?1 AND initial_ttl = ?2;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.os_family, self.initial_ttl];
        tran.execute(sql, params_vec)
    }
    pub fn get() -> OsTtl {
        // Omit!
        OsTtl::new()
    }
}

// Model for frontend
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapData {
    pub map_info: MapInfo,
    pub nodes: Vec<MapNode>,
    pub edges: Vec<MapEdge>,
    pub layouts: Vec<MapLayout>,
}

impl MapData {
    pub fn new() -> MapData {
        MapData {
            map_info: MapInfo {
                map_id: 0,
                map_name: String::new(),
                display_order: 0,
                created_at: String::new(),
            },
            nodes: vec![],
            edges: vec![],
            layouts: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProbeLog {
    pub id: u32,
    pub probe_id: String,
    pub probe_type_id: String,
    pub probe_type_name: String,
    pub probe_target_addr: String,
    pub probe_target_name: String,
    pub protocol_id: String,
    pub probe_option: Option<String>,
    pub issued_at: String 
}

impl ProbeLog {
    pub fn new() -> ProbeLog {
        ProbeLog { 
            id: 0, 
            probe_id: String::new(), 
            probe_type_id: String::new(), 
            probe_type_name: String::new(), 
            probe_target_addr: String::new(), 
            probe_target_name: String::new(), 
            protocol_id: String::new(), 
            probe_option: None, 
            issued_at: String::new() 
        }
    }
    pub fn create(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProbeStat {
    pub portscan_count: u32,
    pub hostscan_count: u32,
    pub ping_count: u32,
    pub traceroute_count: u32,
}

impl ProbeStat {
    pub fn new() -> ProbeStat {
        ProbeStat { portscan_count: 0, hostscan_count: 0, ping_count: 0, traceroute_count: 0 }
    }
    pub fn create(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn update(&self, tran:&Transaction) -> Result<usize,rusqlite::Error>{
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "";
        let params_vec: &[&dyn rusqlite::ToSql] = params![];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataSetItem {
    pub id: String,
    pub name: String,
}

impl DataSetItem {
    pub fn new() -> DataSetItem {
        DataSetItem { id: String::new(), name: String::new() }
    }
}

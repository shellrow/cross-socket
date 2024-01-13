use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocketInfo {
    pub local_ip_addr: String,
    pub local_port: u16,
    pub remote_ip_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub protocol: String,
    pub state: Option<String>,
    pub ip_version: u8,
}

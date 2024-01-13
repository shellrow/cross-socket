use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocketInfo {
    pub local_socket_addr: String,
    pub remote_socket_addr: Option<String>,
    pub protocol: String,
    pub state: Option<String>,
    pub ip_version: u8,
}

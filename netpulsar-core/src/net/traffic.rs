use serde::{Serialize, Deserialize};

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

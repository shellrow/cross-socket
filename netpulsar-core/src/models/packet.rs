use serde::{Deserialize, Serialize};
use xenet::packet::frame::{DatalinkLayer, IpLayer, TransportLayer};
use crate::sys;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketFrame {
    /// Capture number.
    pub capture_no: usize,
    /// The datalink layer.
    pub datalink: Option<DatalinkLayer>,
    /// The IP layer.
    pub ip: Option<IpLayer>,
    /// The transport layer.
    pub transport: Option<TransportLayer>,
    /// Rest of the packet that could not be parsed as a header. (Usually payload)
    pub payload: Vec<u8>,
    /// Packet length.
    pub packet_len: usize,
    /// Packet arrival time. RFC3339 format.
    pub timestamp: String,
}

impl PacketFrame {
    pub fn new() -> Self {
        PacketFrame {
            capture_no: 0,
            datalink: None,
            ip: None,
            transport: None,
            payload: Vec::new(),
            packet_len: 0,
            timestamp: String::new(),
        }
    }
    pub fn from_xenet_frame(capture_no: usize, frame: xenet::packet::frame::Frame) -> PacketFrame {
        PacketFrame {
            capture_no: capture_no,
            datalink: frame.datalink,
            ip: frame.ip,
            transport: frame.transport,
            payload: frame.payload,
            packet_len: frame.packet_len,
            timestamp: sys::get_sysdate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UdpFingerprint {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload_length: u16,
    pub payload: Vec<u8>,
}

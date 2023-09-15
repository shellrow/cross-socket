use pnet::packet::Packet;

#[derive(Clone, Debug, PartialEq)]
pub struct UdpPacket {
    pub source: u16,
    pub destination: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn from_pnet_packet(packet: &pnet::packet::udp::UdpPacket) -> UdpPacket {
        UdpPacket {
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.get_length(),
            checksum: packet.get_checksum(),
            payload: packet.payload().to_vec(),
        }
    }
}

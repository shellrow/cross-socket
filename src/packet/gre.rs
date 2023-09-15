pub struct GrePacket {
    pub checksum_present: u8,
    pub routing_present: u8,
    pub key_present: u8,
    pub sequence_present: u8,
    pub strict_source_route: u8,
    pub recursion_control: u8,
    pub zero_flags: u8,
    pub version: u8,
    pub protocol_type: u16,
    pub checksum: Vec<u16>,
    pub offset: Vec<u16>,
    pub key: Vec<u16>,
    pub sequence: Vec<u32>,
    pub routing: Vec<u8>,
    pub payload: Vec<u8>,
}

impl GrePacket {
    pub fn gre_checksum_length(gre: &Self) -> usize {
        (gre.checksum_present | gre.routing_present) as usize * 2
    }
    pub fn gre_offset_length(gre: &Self) -> usize {
        (gre.checksum_present | gre.routing_present) as usize * 2
    }
    pub fn gre_key_length(gre: &Self) -> usize {
        gre.key_present as usize * 4
    }
    pub fn gre_sequence_length(gre: &Self) -> usize {
        gre.sequence_present as usize * 4
    }
    pub fn gre_routing_length(gre: &Self) -> usize {
        if 0 == gre.routing_present {
            0
        } else {
            panic!("Source routed GRE packets not supported")
        }
    }
}

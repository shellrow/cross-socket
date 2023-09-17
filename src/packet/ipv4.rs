use std::net::Ipv4Addr;
use pnet::packet::Packet;
use crate::packet::ip::IpNextLevelProtocol;

pub const IPV4_HEADER_LEN: usize = pnet::packet::ipv4::MutableIpv4Packet::minimum_packet_size();
pub const IPV4_HEADER_BYTES: usize = 4;

#[derive(Clone, Debug, PartialEq)]
pub enum Ipv4Flags {
    Reserved,
    DontFragment,
    MoreFragments,
}

impl Ipv4Flags {
    pub fn from_u8(n: u8) -> Ipv4Flags {
        match n {
            0b010 => Ipv4Flags::DontFragment,
            0b001 => Ipv4Flags::MoreFragments,
            _ => Ipv4Flags::Reserved,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Ipv4Option {
    EndOfOptionsList,
    NoOperation,
    Security,
    LooseSourceRoute,
    TimeStamp,
    ExtendedSecurity,
    CommercialSecurity,
    RecordRoute,
    StreamId,
    StrictSourceRoute,
    ExperimentalMeasurement,
    MtuProbe,
    MtuReply,
    ExperimentalFlowControl,
    ExperimentalAccessControl,
    Encode,
    ImiTrafficDescriptor,
    ExtendedInternetProtocol,
    Traceroute,
    AddressExtension,
    RouterAlert,
    SelectiveDirectedBroadcast,
    DynamicPacketState,
    UpstreamMulticastPacket,
    QuickStart,
    Rfc3692StyleExperiment,
    Unknown(u8),
}

impl Ipv4Option {
    pub fn from_u8(n: u8) -> Ipv4Option {
        match n {
            0 => Ipv4Option::EndOfOptionsList,
            1 => Ipv4Option::NoOperation,
            2 => Ipv4Option::Security,
            3 => Ipv4Option::LooseSourceRoute,
            4 => Ipv4Option::TimeStamp,
            5 => Ipv4Option::ExtendedSecurity,
            6 => Ipv4Option::CommercialSecurity,
            7 => Ipv4Option::RecordRoute,
            8 => Ipv4Option::StreamId,
            9 => Ipv4Option::StrictSourceRoute,
            10 => Ipv4Option::ExperimentalMeasurement,
            11 => Ipv4Option::MtuProbe,
            12 => Ipv4Option::MtuReply,
            13 => Ipv4Option::ExperimentalFlowControl,
            14 => Ipv4Option::ExperimentalAccessControl,
            15 => Ipv4Option::Encode,
            16 => Ipv4Option::ImiTrafficDescriptor,
            17 => Ipv4Option::ExtendedInternetProtocol,
            18 => Ipv4Option::Traceroute,
            19 => Ipv4Option::AddressExtension,
            20 => Ipv4Option::RouterAlert,
            21 => Ipv4Option::SelectiveDirectedBroadcast,
            23 => Ipv4Option::DynamicPacketState,
            24 => Ipv4Option::UpstreamMulticastPacket,
            25 => Ipv4Option::QuickStart,
            30 => Ipv4Option::Rfc3692StyleExperiment,
            _ => Ipv4Option::Unknown(n),
        }
    }
    pub fn number(&self) -> u8 {
        match *self {
            Ipv4Option::EndOfOptionsList => 0,
            Ipv4Option::NoOperation => 1,
            Ipv4Option::Security => 2,
            Ipv4Option::LooseSourceRoute => 3,
            Ipv4Option::TimeStamp => 4,
            Ipv4Option::ExtendedSecurity => 5,
            Ipv4Option::CommercialSecurity => 6,
            Ipv4Option::RecordRoute => 7,
            Ipv4Option::StreamId => 8,
            Ipv4Option::StrictSourceRoute => 9,
            Ipv4Option::ExperimentalMeasurement => 10,
            Ipv4Option::MtuProbe => 11,
            Ipv4Option::MtuReply => 12,
            Ipv4Option::ExperimentalFlowControl => 13,
            Ipv4Option::ExperimentalAccessControl => 14,
            Ipv4Option::Encode => 15,
            Ipv4Option::ImiTrafficDescriptor => 16,
            Ipv4Option::ExtendedInternetProtocol => 17,
            Ipv4Option::Traceroute => 18,
            Ipv4Option::AddressExtension => 19,
            Ipv4Option::RouterAlert => 20,
            Ipv4Option::SelectiveDirectedBroadcast => 21,
            Ipv4Option::DynamicPacketState => 23,
            Ipv4Option::UpstreamMulticastPacket => 24,
            Ipv4Option::QuickStart => 25,
            Ipv4Option::Rfc3692StyleExperiment => 30,
            Ipv4Option::Unknown(n) => n,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ipv4Packet {
    pub version: u8,
    pub header_length: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub next_level_protocol: IpNextLevelProtocol,
    pub checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: Vec<Ipv4Option>,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    pub(crate) fn from_pnet_packet(packet: &pnet::packet::ipv4::Ipv4Packet) -> Ipv4Packet {
        Ipv4Packet {
            version: packet.get_version(),
            header_length: packet.get_header_length(),
            dscp: packet.get_dscp(),
            ecn: packet.get_ecn(),
            total_length: packet.get_total_length(),
            identification: packet.get_identification(),
            flags: packet.get_flags(),
            fragment_offset: packet.get_fragment_offset(),
            ttl: packet.get_ttl(),
            next_level_protocol: IpNextLevelProtocol::from_u8(packet.get_next_level_protocol().0),
            checksum: packet.get_checksum(),
            source: packet.get_source(),
            destination: packet.get_destination(),
            options: packet
                .get_options_iter()
                .map(|opt| Ipv4Option::from_u8(opt.get_number().0))
                .collect(),
            payload: packet.payload().to_vec(),
        }
    }
    pub fn from_bytes(packet: &[u8]) -> Ipv4Packet {
        let ipv4_packet = pnet::packet::ipv4::Ipv4Packet::new(packet).unwrap();
        Ipv4Packet::from_pnet_packet(&ipv4_packet)
    }
}

pub fn build_ipv4_packet(
    ipv4_packet: &mut pnet::packet::ipv4::MutableIpv4Packet,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    next_protocol: IpNextLevelProtocol,
) {
    ipv4_packet.set_header_length((IPV4_HEADER_LEN / IPV4_HEADER_BYTES) as u8);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dst_ip);
    ipv4_packet.set_identification(rand::random::<u16>());
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_version(4);
    ipv4_packet.set_flags(pnet::packet::ipv4::Ipv4Flags::DontFragment);
    match next_protocol {
        IpNextLevelProtocol::Tcp => {
            ipv4_packet.set_total_length(52);
            ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
        }
        IpNextLevelProtocol::Udp => {
            ipv4_packet.set_total_length(28);
            ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
        }
        IpNextLevelProtocol::Icmp => {
            ipv4_packet.set_total_length(28);
            ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Icmp);
        }
        _ => {}
    }
    let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);
}

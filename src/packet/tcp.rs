use std::net::{IpAddr, SocketAddr};
use pnet::packet::Packet;

pub const TCP_HEADER_LEN: usize = pnet::packet::tcp::MutableTcpPacket::minimum_packet_size();
pub const TCP_DEFAULT_OPTION_LEN: usize = 12;
pub const DEFAULT_SRC_PORT: u16 = 53443;

/// TCP Option Kind
/// <https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1>
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TcpOption {
    Eol,
    Nop,
    Mss,
    Wscale,
    SackParmitted,
    Sack,
    Timestamp,
}

impl TcpOption {
    pub fn from_u8(n: u8) -> TcpOption {
        match n {
            0 => TcpOption::Eol,
            1 => TcpOption::Nop,
            2 => TcpOption::Mss,
            3 => TcpOption::Wscale,
            4 => TcpOption::SackParmitted,
            5 => TcpOption::Sack,
            8 => TcpOption::Timestamp,
            _ => panic!("Unknown TCP option kind: {}", n),
        }
    }
    /// Get the number of the TCP option kind
    pub fn number(&self) -> u8 {
        match *self {
            TcpOption::Eol => 0,
            TcpOption::Nop => 1,
            TcpOption::Mss => 2,
            TcpOption::Wscale => 3,
            TcpOption::SackParmitted => 4,
            TcpOption::Sack => 5,
            TcpOption::Timestamp => 8,
        }
    }
    /// Get the ID of the TCP option kind
    pub fn id(&self) -> String {
        match *self {
            TcpOption::Eol => String::from("EOL"),
            TcpOption::Nop => String::from("NOP"),
            TcpOption::Mss => String::from("MSS"),
            TcpOption::Wscale => String::from("WSCALE"),
            TcpOption::SackParmitted => String::from("SACK_PERMITTED"),
            TcpOption::Sack => String::from("SACK"),
            TcpOption::Timestamp => String::from("TIMESTAMPS"),
        }
    }
    /// Get the name of the TCP option kind
    pub fn name(&self) -> String {
        match *self {
            TcpOption::Eol => String::from("EOL"),
            TcpOption::Nop => String::from("NOP"),
            TcpOption::Mss => String::from("MSS"),
            TcpOption::Wscale => String::from("WSCALE"),
            TcpOption::SackParmitted => String::from("SACK_PERMITTED"),
            TcpOption::Sack => String::from("SACK"),
            TcpOption::Timestamp => String::from("TIMESTAMPS"),
        }
    }
}

/// TCP Flag Kind
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TcpFlag {
    Syn,
    Fin,
    Rst,
    Psh,
    Ack,
    Urg,
    Ece,
    Cwr,
    Unknown(u8),
}

impl TcpFlag {
    pub fn from_u8(n: u8) -> TcpFlag {
        match n {
            pnet::packet::tcp::TcpFlags::SYN => TcpFlag::Syn,
            pnet::packet::tcp::TcpFlags::FIN => TcpFlag::Fin,
            pnet::packet::tcp::TcpFlags::RST => TcpFlag::Rst,
            pnet::packet::tcp::TcpFlags::PSH => TcpFlag::Psh,
            pnet::packet::tcp::TcpFlags::ACK => TcpFlag::Ack,
            pnet::packet::tcp::TcpFlags::URG => TcpFlag::Urg,
            pnet::packet::tcp::TcpFlags::ECE => TcpFlag::Ece,
            pnet::packet::tcp::TcpFlags::CWR => TcpFlag::Cwr,
            _ => TcpFlag::Unknown(n),
        }
    }
    /// Get the number of the TCP flag kind
    pub fn number(&self) -> u8 {
        match *self {
            TcpFlag::Syn => pnet::packet::tcp::TcpFlags::SYN,
            TcpFlag::Fin => pnet::packet::tcp::TcpFlags::FIN,
            TcpFlag::Rst => pnet::packet::tcp::TcpFlags::RST,
            TcpFlag::Psh => pnet::packet::tcp::TcpFlags::PSH,
            TcpFlag::Ack => pnet::packet::tcp::TcpFlags::ACK,
            TcpFlag::Urg => pnet::packet::tcp::TcpFlags::URG,
            TcpFlag::Ece => pnet::packet::tcp::TcpFlags::ECE,
            TcpFlag::Cwr => pnet::packet::tcp::TcpFlags::CWR,
            TcpFlag::Unknown(n) => n,
        }
    }
    /// Get the ID of the TCP flag kind
    pub fn id(&self) -> String {
        match *self {
            TcpFlag::Syn => String::from("SYN"),
            TcpFlag::Fin => String::from("FIN"),
            TcpFlag::Rst => String::from("RST"),
            TcpFlag::Psh => String::from("PSH"),
            TcpFlag::Ack => String::from("ACK"),
            TcpFlag::Urg => String::from("URG"),
            TcpFlag::Ece => String::from("ECE"),
            TcpFlag::Cwr => String::from("CWR"),
            TcpFlag::Unknown(n) => format!("UNKNOWN_{}", n),
        }
    }
    /// Get the name of the TCP flag kind
    pub fn name(&self) -> String {
        match *self {
            TcpFlag::Syn => String::from("SYN"),
            TcpFlag::Fin => String::from("FIN"),
            TcpFlag::Rst => String::from("RST"),
            TcpFlag::Psh => String::from("PSH"),
            TcpFlag::Ack => String::from("ACK"),
            TcpFlag::Urg => String::from("URG"),
            TcpFlag::Ece => String::from("ECE"),
            TcpFlag::Cwr => String::from("CWR"),
            TcpFlag::Unknown(n) => format!("Unknown({})", n),
        }
    }
}

/// Represents a TCP packet.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpPacket {
    pub source: u16,
    pub destination: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: Vec<TcpFlag>,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<TcpOption>,
    pub payload: Vec<u8>,
}

impl TcpPacket {
    pub(crate) fn from_pnet_packet(packet: &pnet::packet::tcp::TcpPacket) -> TcpPacket {
        let mut tcp_options: Vec<TcpOption> = vec![];
        for opt in packet.get_options_iter() {
            tcp_options.push(TcpOption::from_u8(opt.get_number().0));
        }
        let mut tcp_flags: Vec<TcpFlag> = vec![];
        if packet.get_flags() & TcpFlag::Syn.number() == TcpFlag::Syn.number() {
            tcp_flags.push(TcpFlag::Syn);
        }
        if packet.get_flags() & TcpFlag::Fin.number() == TcpFlag::Fin.number() {
            tcp_flags.push(TcpFlag::Fin);
        }
        if packet.get_flags() & TcpFlag::Rst.number() == TcpFlag::Rst.number() {
            tcp_flags.push(TcpFlag::Rst);
        }
        if packet.get_flags() & TcpFlag::Psh.number() == TcpFlag::Psh.number() {
            tcp_flags.push(TcpFlag::Psh);
        }
        if packet.get_flags() & TcpFlag::Ack.number() == TcpFlag::Ack.number() {
            tcp_flags.push(TcpFlag::Ack);
        }
        if packet.get_flags() & TcpFlag::Urg.number() == TcpFlag::Urg.number() {
            tcp_flags.push(TcpFlag::Urg);
        }
        if packet.get_flags() & TcpFlag::Ece.number() == TcpFlag::Ece.number() {
            tcp_flags.push(TcpFlag::Ece);
        }
        if packet.get_flags() & TcpFlag::Cwr.number() == TcpFlag::Cwr.number() {
            tcp_flags.push(TcpFlag::Cwr);
        }
        TcpPacket {
            source: packet.get_source(),
            destination: packet.get_destination(),
            sequence: packet.get_sequence(),
            acknowledgement: packet.get_acknowledgement(),
            data_offset: packet.get_data_offset(),
            reserved: packet.get_reserved(),
            flags: tcp_flags,
            window: packet.get_window(),
            checksum: packet.get_checksum(),
            urgent_ptr: packet.get_urgent_ptr(),
            options: tcp_options,
            payload: packet.payload().to_vec(),
        }
    }
    pub fn from_bytes(packet: &[u8]) -> TcpPacket {
        let tcp_packet = pnet::packet::tcp::TcpPacket::new(packet).unwrap();
        TcpPacket::from_pnet_packet(&tcp_packet)
    }
}

pub(crate) fn build_tcp_packet(
    tcp_packet: &mut pnet::packet::tcp::MutableTcpPacket,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) {
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(8);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_sequence(0);
    tcp_packet.set_options(&[
        pnet::packet::tcp::TcpOption::mss(1460),
        pnet::packet::tcp::TcpOption::sack_perm(),
        pnet::packet::tcp::TcpOption::nop(),
        pnet::packet::tcp::TcpOption::nop(),
        pnet::packet::tcp::TcpOption::wscale(7),
    ]);
    tcp_packet.set_flags(pnet::packet::tcp::TcpFlags::SYN);
    match src_ip {
        IpAddr::V4(src_ip) => match dst_ip {
            IpAddr::V4(dst_ip) => {
                let checksum =
                    pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                tcp_packet.set_checksum(checksum);
            }
            IpAddr::V6(_) => {}
        },
        IpAddr::V6(src_ip) => match dst_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(dst_ip) => {
                let checksum =
                    pnet::packet::tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                tcp_packet.set_checksum(checksum);
            }
        },
    }
}

/// TCP Packet Builder
#[derive(Clone, Debug)]
pub struct TcpPacketBuilder {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub window: u16,
    pub data_offset: u8,
    pub flags: Vec<TcpFlag>,
    pub options: Vec<TcpOption>,
    pub payload: Vec<u8>,
}

impl TcpPacketBuilder {
    pub fn new(src_addr: SocketAddr, dst_addr: SocketAddr) -> TcpPacketBuilder {
        TcpPacketBuilder {
            src_ip: src_addr.ip(),
            src_port: src_addr.port(),
            dst_ip: dst_addr.ip(),
            dst_port: dst_addr.port(),
            window: 64240,
            data_offset: 8,
            flags: vec![TcpFlag::Syn],
            options: vec![
                TcpOption::Mss,
                TcpOption::SackParmitted,
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Wscale,
            ],
            payload: vec![],
        }
    }
    pub fn build(&mut self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; TCP_HEADER_LEN];
        let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(&mut buffer).unwrap();
        tcp_packet.set_source(self.src_port);
        tcp_packet.set_destination(self.dst_port);
        tcp_packet.set_window(self.window);
        tcp_packet.set_data_offset(self.data_offset);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_sequence(0);
        let mut tcp_flags: u8 = 0;
        for flag in &self.flags {
            tcp_flags |= flag.number();
        }
        tcp_packet.set_flags(tcp_flags);
        let mut tcp_options: Vec<pnet::packet::tcp::TcpOption> = vec![];
        for opt in &self.options {
            match *opt {
                TcpOption::Mss => {
                    tcp_options.push(pnet::packet::tcp::TcpOption::mss(1460));
                }
                TcpOption::Wscale => {
                    tcp_options.push(pnet::packet::tcp::TcpOption::wscale(7));
                }
                TcpOption::SackParmitted => {
                    tcp_options.push(pnet::packet::tcp::TcpOption::sack_perm());
                }
                TcpOption::Nop => {
                    tcp_options.push(pnet::packet::tcp::TcpOption::nop());
                }
                _ => {}
            }
        }
        tcp_packet.set_options(&tcp_options);
        tcp_packet.set_payload(&self.payload);
        match self.src_ip {
            IpAddr::V4(src_ip) => match self.dst_ip {
                IpAddr::V4(dst_ip) => {
                    let checksum =
                        pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                    tcp_packet.set_checksum(checksum);
                }
                IpAddr::V6(_) => {}
            },
            IpAddr::V6(src_ip) => match self.dst_ip {
                IpAddr::V4(_) => {}
                IpAddr::V6(dst_ip) => {
                    let checksum =
                        pnet::packet::tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                    tcp_packet.set_checksum(checksum);
                }
            },
        }
        tcp_packet.packet().to_vec()
    }
}
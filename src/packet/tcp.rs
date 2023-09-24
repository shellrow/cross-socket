use pnet::packet::Packet;
use std::net::{IpAddr, SocketAddr};

/// Minimum TCP Header Length
pub const TCP_HEADER_LEN: usize = pnet::packet::tcp::MutableTcpPacket::minimum_packet_size();
/// Minimum TCP Data Offset
pub const TCP_MIN_DATA_OFFSET: u8 = 5;
/// Maximum TCP Option Length
pub const TCP_OPTION_MAX_LEN: usize = 40;
/// Maximum TCP Header Length (with options)
pub const TCP_HEADER_MAX_LEN: usize = TCP_HEADER_LEN + TCP_OPTION_MAX_LEN;
/// Default TCP Option Length
pub const TCP_DEFAULT_OPTION_LEN: usize = 12;
/// Default TCP Source Port
pub const DEFAULT_SRC_PORT: u16 = 53443;

/// TCP Option Kind
/// <https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1>
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TcpOptionKind {
    Eol,
    Nop,
    Mss,
    Wscale,
    SackParmitted,
    Sack,
    Timestamp,
}

impl TcpOptionKind {
    pub fn from_u8(n: u8) -> TcpOptionKind {
        match n {
            0 => TcpOptionKind::Eol,
            1 => TcpOptionKind::Nop,
            2 => TcpOptionKind::Mss,
            3 => TcpOptionKind::Wscale,
            4 => TcpOptionKind::SackParmitted,
            5 => TcpOptionKind::Sack,
            8 => TcpOptionKind::Timestamp,
            _ => panic!("Unknown TCP option kind: {}", n),
        }
    }
    /// Get the number of the TCP option kind
    pub fn number(&self) -> u8 {
        match *self {
            TcpOptionKind::Eol => 0,
            TcpOptionKind::Nop => 1,
            TcpOptionKind::Mss => 2,
            TcpOptionKind::Wscale => 3,
            TcpOptionKind::SackParmitted => 4,
            TcpOptionKind::Sack => 5,
            TcpOptionKind::Timestamp => 8,
        }
    }
    /// Get the ID of the TCP option kind
    pub fn id(&self) -> String {
        match *self {
            TcpOptionKind::Eol => String::from("EOL"),
            TcpOptionKind::Nop => String::from("NOP"),
            TcpOptionKind::Mss => String::from("MSS"),
            TcpOptionKind::Wscale => String::from("WSCALE"),
            TcpOptionKind::SackParmitted => String::from("SACK_PERMITTED"),
            TcpOptionKind::Sack => String::from("SACK"),
            TcpOptionKind::Timestamp => String::from("TIMESTAMPS"),
        }
    }
    /// Get the name of the TCP option kind
    pub fn name(&self) -> String {
        match *self {
            TcpOptionKind::Eol => String::from("EOL"),
            TcpOptionKind::Nop => String::from("NOP"),
            TcpOptionKind::Mss => String::from("MSS"),
            TcpOptionKind::Wscale => String::from("WSCALE"),
            TcpOptionKind::SackParmitted => String::from("SACK_PERMITTED"),
            TcpOptionKind::Sack => String::from("SACK"),
            TcpOptionKind::Timestamp => String::from("TIMESTAMPS"),
        }
    }
    /// Get size (bytes) of the TCP option
    pub fn size(&self) -> usize {
        match *self {
            TcpOptionKind::Eol => 1,
            TcpOptionKind::Nop => 1,
            TcpOptionKind::Mss => 4,
            TcpOptionKind::Wscale => 3,
            TcpOptionKind::SackParmitted => 2,
            TcpOptionKind::Sack => 10,
            TcpOptionKind::Timestamp => 10,
        }
    }
}

/// TCP Option
#[derive(Clone, Debug, PartialEq)]
pub struct TcpOption {
    /// TCP Option Kind
    pub kind: TcpOptionKind,
    /// TCP Option Data
    pub data: Vec<u8>,
}

impl TcpOption {
    /// No Operation (NOP) TCP option.
    pub fn nop() -> Self {
        TcpOption {
            kind: TcpOptionKind::Nop,
            data: vec![],
        }
    }
    /// Timestamp TCP option
    pub fn timestamp(my: u32, their: u32) -> Self {
        let mut data = vec![];
        data.extend_from_slice(&my.to_be_bytes());
        data.extend_from_slice(&their.to_be_bytes());

        TcpOption {
            kind: TcpOptionKind::Timestamp,
            data: data,
        }
    }
    /// Get the timestamp of the TCP option
    pub fn get_timestamp(&self) -> (u32, u32) {
        let mut my: [u8; 4] = [0; 4];
        my.copy_from_slice(&self.data[0..4]);
        let mut their: [u8; 4] = [0; 4];
        their.copy_from_slice(&self.data[4..8]);
        (u32::from_be_bytes(my), u32::from_be_bytes(their))
    }
    /// Maximum Segment Size (MSS) TCP option
    pub fn mss(val: u16) -> Self {
        let mut data = vec![];
        data.extend_from_slice(&val.to_be_bytes());

        TcpOption {
            kind: TcpOptionKind::Mss,
            data: data,
        }
    }
    /// Get the MSS of the TCP option
    pub fn get_mss(&self) -> u16 {
        let mut mss: [u8; 2] = [0; 2];
        mss.copy_from_slice(&self.data[0..2]);
        u16::from_be_bytes(mss)
    }
    /// Window Scale (WSCALE) TCP option
    pub fn wscale(val: u8) -> Self {
        TcpOption {
            kind: TcpOptionKind::Wscale,
            data: vec![val],
        }
    }
    /// Get the WSCALE of the TCP option
    pub fn get_wscale(&self) -> u8 {
        self.data[0]
    }
    /// Selective Acknowledgement Permitted (SACK_PERMITTED) TCP option
    pub fn sack_perm() -> Self {
        TcpOption {
            kind: TcpOptionKind::SackParmitted,
            data: vec![],
        }
    }
    /// Selective Acknowledgement (SACK) TCP option
    pub fn selective_ack(acks: &[u32]) -> Self {
        let mut data = vec![];
        for ack in acks {
            data.extend_from_slice(&ack.to_be_bytes());
        }
        TcpOption {
            kind: TcpOptionKind::Sack,
            data: data,
        }
    }

    pub(crate) fn from_pnet_type(opt: pnet::packet::tcp::TcpOptionPacket) -> TcpOption {
        TcpOption {
            kind: TcpOptionKind::from_u8(opt.get_number().0),
            data: opt.payload().to_vec(),
        }
    }

    pub(crate) fn to_pnet_type(&self) -> pnet::packet::tcp::TcpOption {
        match self.kind {
            TcpOptionKind::Nop => pnet::packet::tcp::TcpOption::nop(),
            TcpOptionKind::Mss => pnet::packet::tcp::TcpOption::mss(self.get_mss()),
            TcpOptionKind::Wscale => pnet::packet::tcp::TcpOption::wscale(self.get_wscale()),
            TcpOptionKind::SackParmitted => pnet::packet::tcp::TcpOption::sack_perm(),
            TcpOptionKind::Sack => {
                let mut acks: Vec<u32> = vec![];
                for i in 0..self.data.len() / 4 {
                    let mut ack: [u8; 4] = [0; 4];
                    ack.copy_from_slice(&self.data[i * 4..i * 4 + 4]);
                    acks.push(u32::from_be_bytes(ack));
                }
                pnet::packet::tcp::TcpOption::selective_ack(&acks)
            }
            TcpOptionKind::Timestamp => {
                let (my, their) = self.get_timestamp();
                pnet::packet::tcp::TcpOption::timestamp(my, their)
            }
            _ => pnet::packet::tcp::TcpOption::nop(),
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
    /// Get the TCP flag kind from u8
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

/// Get the length of TCP options from TCP data offset
pub fn get_tcp_options_length(data_offset: u8) -> usize {
    if data_offset > 5 {
        data_offset as usize * 4 - TCP_HEADER_LEN
    } else {
        0
    }
}

/// Get the TCP data offset from TCP options
pub fn get_tcp_data_offset(opstions: Vec<TcpOption>) -> u8 {
    let mut total_size: u8 = 0;
    for opt in opstions {
        total_size += opt.kind.size() as u8;
    }
    if total_size % 4 == 0 {
        total_size / 4 + TCP_MIN_DATA_OFFSET
    } else {
        total_size / 4 + TCP_MIN_DATA_OFFSET + 1
    }
}

/// Represents a TCP packet.
#[derive(Clone, Debug, PartialEq)]
pub struct TcpPacket {
    /// Source port
    pub source: u16,
    /// Destination port
    pub destination: u16,
    /// Sequence number
    pub sequence: u32,
    /// Acknowledgement number
    pub acknowledgement: u32,
    /// Data offset
    pub data_offset: u8,
    /// Reserved
    pub reserved: u8,
    /// TCP flags
    pub flags: Vec<TcpFlag>,
    /// Window size
    pub window: u16,
    /// Checksum
    pub checksum: u16,
    /// Urgent pointer
    pub urgent_ptr: u16,
    /// TCP options
    pub options: Vec<TcpOption>,
    /// TCP Payload
    pub payload: Vec<u8>,
}

impl TcpPacket {
    pub(crate) fn from_pnet_packet(packet: &pnet::packet::tcp::TcpPacket) -> TcpPacket {
        let mut tcp_options: Vec<TcpOption> = vec![];
        for opt in packet.get_options_iter() {
            tcp_options.push(TcpOption::from_pnet_type(opt));
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
    /// Source IP address
    pub src_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Window size
    pub window: u16,
    /// TCP flags
    pub flags: Vec<TcpFlag>,
    /// TCP options
    pub options: Vec<TcpOption>,
    /// TCP payload
    pub payload: Vec<u8>,
}

impl TcpPacketBuilder {
    /// Constructs a new TcpPacketBuilder from Source SocketAddr and Destination SocketAddr with default options.
    pub fn new(src_addr: SocketAddr, dst_addr: SocketAddr) -> TcpPacketBuilder {
        TcpPacketBuilder {
            src_ip: src_addr.ip(),
            src_port: src_addr.port(),
            dst_ip: dst_addr.ip(),
            dst_port: dst_addr.port(),
            window: 64240,
            flags: vec![TcpFlag::Syn],
            options: vec![
                TcpOption::mss(1460),
                TcpOption::sack_perm(),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ],
            payload: vec![],
        }
    }
    /// Build a TCP packet and return bytes
    pub fn build(&self) -> Vec<u8> {
        let data_offset = get_tcp_data_offset(self.options.clone());
        let tcp_options_len = get_tcp_options_length(data_offset);
        let mut buffer: Vec<u8> = vec![0; TCP_HEADER_LEN + tcp_options_len + self.payload.len()];
        let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(&mut buffer).unwrap();
        tcp_packet.set_source(self.src_port);
        tcp_packet.set_destination(self.dst_port);
        tcp_packet.set_window(self.window);
        tcp_packet.set_data_offset(data_offset);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_sequence(0);
        let mut tcp_flags: u8 = 0;
        for flag in &self.flags {
            if tcp_flags == 0 {
                tcp_flags = flag.number();
            } else {
                tcp_flags |= flag.number();
            }
        }
        tcp_packet.set_flags(tcp_flags);
        let mut tcp_options: Vec<pnet::packet::tcp::TcpOption> = vec![];
        for opt in &self.options {
            tcp_options.push(opt.to_pnet_type());
        }
        tcp_packet.set_options(&tcp_options);
        if self.payload.len() > 0 {
            tcp_packet.set_payload(&self.payload);
        }
        match self.src_ip {
            IpAddr::V4(src_ip) => match self.dst_ip {
                IpAddr::V4(dst_ip) => {
                    let checksum = pnet::packet::tcp::ipv4_checksum(
                        &tcp_packet.to_immutable(),
                        &src_ip,
                        &dst_ip,
                    );
                    tcp_packet.set_checksum(checksum);
                }
                IpAddr::V6(_) => {}
            },
            IpAddr::V6(src_ip) => match self.dst_ip {
                IpAddr::V4(_) => {}
                IpAddr::V6(dst_ip) => {
                    let checksum = pnet::packet::tcp::ipv6_checksum(
                        &tcp_packet.to_immutable(),
                        &src_ip,
                        &dst_ip,
                    );
                    tcp_packet.set_checksum(checksum);
                }
            },
        }
        tcp_packet.packet().to_vec()
    }
}

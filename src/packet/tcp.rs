use pnet::packet::Packet;

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
}

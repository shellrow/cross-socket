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
            TcpOptionKind::Eol => String::from("eol"),
            TcpOptionKind::Nop => String::from("nop"),
            TcpOptionKind::Mss => String::from("mss"),
            TcpOptionKind::Wscale => String::from("wscale"),
            TcpOptionKind::SackParmitted => String::from("sack_permitted"),
            TcpOptionKind::Sack => String::from("sack"),
            TcpOptionKind::Timestamp => String::from("timestamp"),
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
}

/// TCP Flag Kind
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TcpFlagKind {
    Syn,
    Fin,
    Rst,
    Psh,
    Ack,
    Urg,
    Ece,
    Cwr,
}

impl TcpFlagKind {
    /// Get the number of the TCP flag kind
    pub fn number(&self) -> u8 {
        match *self {
            TcpFlagKind::Syn => pnet::packet::tcp::TcpFlags::SYN,
            TcpFlagKind::Fin => pnet::packet::tcp::TcpFlags::FIN,
            TcpFlagKind::Rst => pnet::packet::tcp::TcpFlags::RST,
            TcpFlagKind::Psh => pnet::packet::tcp::TcpFlags::PSH,
            TcpFlagKind::Ack => pnet::packet::tcp::TcpFlags::ACK,
            TcpFlagKind::Urg => pnet::packet::tcp::TcpFlags::URG,
            TcpFlagKind::Ece => pnet::packet::tcp::TcpFlags::ECE,
            TcpFlagKind::Cwr => pnet::packet::tcp::TcpFlags::CWR,
        }
    }
    /// Get the ID of the TCP flag kind
    pub fn id(&self) -> String {
        match *self {
            TcpFlagKind::Syn => String::from("syn"),
            TcpFlagKind::Fin => String::from("fin"),
            TcpFlagKind::Rst => String::from("rst"),
            TcpFlagKind::Psh => String::from("psh"),
            TcpFlagKind::Ack => String::from("ack"),
            TcpFlagKind::Urg => String::from("urg"),
            TcpFlagKind::Ece => String::from("ece"),
            TcpFlagKind::Cwr => String::from("cwr"),
        }
    }
    /// Get the name of the TCP flag kind
    pub fn name(&self) -> String {
        match *self {
            TcpFlagKind::Syn => String::from("SYN"),
            TcpFlagKind::Fin => String::from("FIN"),
            TcpFlagKind::Rst => String::from("RST"),
            TcpFlagKind::Psh => String::from("PSH"),
            TcpFlagKind::Ack => String::from("ACK"),
            TcpFlagKind::Urg => String::from("URG"),
            TcpFlagKind::Ece => String::from("ECE"),
            TcpFlagKind::Cwr => String::from("CWR"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TcpFingerprint {
    pub source_port: u16,
    pub destination_port: u16,
    pub flags: Vec<TcpFlagKind>,
    pub window_size: u16,
    pub options: Vec<TcpOptionKind>,
    pub payload_length: u16,
    pub payload: Vec<u8>,
}

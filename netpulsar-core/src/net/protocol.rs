use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Hash, Eq, Clone, PartialOrd, Ord, Copy)]
pub enum Protocol {
    ARP,
    NDP,
    ICMP,
    TCP,
    UDP
}
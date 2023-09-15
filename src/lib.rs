pub mod option;
pub mod packet;
pub mod datalink;
pub mod socket;
mod pcap;
pub mod listener;

pub use default_net as interface;

#[cfg(feature = "setup")]
extern crate cross_socket_deps;

#[cfg(feature = "setup")]
pub mod deps {
    pub use cross_socket_deps::*;
}

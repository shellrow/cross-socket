pub mod packet;
pub mod datalink;
pub mod socket;
pub mod pcap;

#[cfg(feature = "setup")]
extern crate cross_socket_deps;

#[cfg(feature = "setup")]
pub mod deps {
    pub use cross_socket_deps::*;
}

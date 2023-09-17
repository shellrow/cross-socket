use std::net::IpAddr;

use cross_socket::socket::DataLinkSocket;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::packet::PacketInfo;
use cross_socket::interface::Interface;
// Send TCP SYN packets to 1.1.1.1:80 and check if the port is open
fn main() {
    let interface: Interface = cross_socket::interface::get_default_interface().unwrap();
    // Create new socket
    let mut socket: DataLinkSocket = DataLinkSocket::new(interface, false).unwrap();
    // Create packet info
    let mut packet_info = PacketInfo::new();
    packet_info.src_mac = socket.interface.mac_addr.clone().unwrap();
    packet_info.dst_mac = socket.interface.gateway.clone().unwrap().mac_addr;
    packet_info.src_ip = IpAddr::V4(socket.interface.ipv4[0].addr);
    packet_info.dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
    packet_info.src_port = Some(53443);
    packet_info.dst_port = Some(80);
    packet_info.ip_protocol = Some(IpNextLevelProtocol::Tcp);
    packet_info.payload = vec![0; 0];

    // Send TCP SYN packets to 1.1.1.1:80
    match socket.send(packet_info) {
        Ok(packet_len) => {
            println!("Sent {} bytes", packet_len);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Receive packets
    match socket.receive() {
        Ok(packet) => {
            println!("Received {} bytes", packet.len());
            println!("Packet: {:?}", packet);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}

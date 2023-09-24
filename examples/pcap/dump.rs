use cross_socket::pcap::listener::Listner;
use cross_socket::pcap::PacketCaptureOptions;
use default_net::Interface;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;

// Start capturing all packets (TCP, UDP, ICMP only) on the default interface
fn main() {
    // Get default interface information
    let default_interface: Interface =
        default_net::get_default_interface().expect("Failed to get default interface information");
    // No filter. Capture all packets.
    let capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: default_interface.index,
        interface_name: default_interface.name,
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        duration: Duration::from_secs(30),
        promiscuous: false,
        store: false,
        store_limit: 0,
        receive_undefined: true,
    };
    // Create new listener
    let listener: Listner = Listner::new(capture_options);
    let rx = listener.get_receiver();
    // Start capturing packets
    let handle = thread::spawn(move || listener.start());
    // Print captured packets
    while let Ok(msg) = rx.lock().unwrap().recv() {
        println!("{:?}", msg);
    }
    let _result = handle.join().unwrap();
}

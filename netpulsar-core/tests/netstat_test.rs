extern crate netpulsar_core;

#[test]
fn show_netstat() {
    let netstat = netpulsar_core::netstat::get_netstat();
    for ns in netstat.iter() {
        println!("{:?}", ns);
    }
    assert!(netstat.len() > 0);
}

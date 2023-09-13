use cross_socket::deps::setup;

#[cfg(target_os = "windows")]
fn main() {
    match setup::windows::npcap::install_npcap() {
        Ok(_) => println!("Npcap installed successfully"),
        Err(e) => println!("Error: {}", e),
    }
    match setup::windows::npcap::install_npcap_sdk() {
        Ok(_) => println!("Npcap sdk installed successfully"),
        Err(e) => println!("Error: {}", e),
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("This example is only for windows");
}

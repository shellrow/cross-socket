use netpulsar_core::netstat::ProcessSocketInfo;

#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
pub fn get_netstat() -> Vec<ProcessSocketInfo> {
    netpulsar_core::netstat::get_netstat()
}

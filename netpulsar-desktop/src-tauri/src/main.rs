// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod sys;

use std::sync::{Arc, Mutex};
use netpulsar_core::db::stat::NetStatStrage;
use commands::{greet, get_netstat, start_packet_capture, get_remote_hosts};

fn main() {
    let netstat_strage: Arc<Mutex<NetStatStrage>> = Arc::new(Mutex::new(NetStatStrage::new()));
    tauri::Builder::default()
        .manage(netstat_strage)
        .invoke_handler(tauri::generate_handler![
            greet,
            get_netstat,
            start_packet_capture,
            get_remote_hosts
            ])
        .setup(|app| {
            let app_handle = app.handle();
            sys::init(app_handle);
            Ok(())
            })
        .on_window_event(|event| match event.event() {
            tauri::WindowEvent::Destroyed => {
                sys::cleanup();
            },
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod sys;

use commands::{greet, get_netstat, start_packet_capture, start_packet_capture_crossbeam};

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            greet,
            get_netstat,
            start_packet_capture,
            start_packet_capture_crossbeam
            ])
        .setup(|app| {
            let app_handle = app.handle();
            sys::init(app_handle);
            Ok(())
            })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

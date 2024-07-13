#![allow(unused)]

use std::path::PathBuf;
use std::fs::File;
use std::path::Path;
use std::error::Error;
use crate::thread_log;
use crate::config::AppConfig;

#[cfg(not(target_os = "windows"))]
mod unix;
#[allow(unused_imports)]
#[cfg(not(target_os = "windows"))]
pub use self::unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

pub const USER_CONFIG_DIR_NAME: &str = ".netpulsar";
pub const DOWNLOAD_DIR_NAME: &str = "Downloads";

#[cfg(target_os = "windows")]
pub fn get_os_type() -> String {
    "windows".to_owned()
}

#[cfg(target_os = "linux")]
pub fn get_os_type() -> String {
    "linux".to_owned()
}

#[cfg(target_os = "macos")]
pub fn get_os_type() -> String {
    "macos".to_owned()
}

pub fn get_sysdate() -> String {
    let now = chrono::Local::now();
    now.to_rfc3339()
}

pub fn get_config_dir_path() -> Option<PathBuf> {
    match home::home_dir() {
        Some(mut path) => {
            path.push(USER_CONFIG_DIR_NAME);
            if !path.exists() {
                match std::fs::create_dir_all(&path) {
                    Ok(_) => {}
                    Err(e) => {
                        thread_log!(error, "{:?}", e);
                        return None;
                    }
                }
            }
            Some(path)
        }
        None => None,
    }
}

pub fn get_user_file_path(file_name: &str) -> Option<PathBuf> {
    match get_config_dir_path() {
        Some(mut path) => {
            path.push(file_name);
            Some(path)
        }
        None => None,
    }
}

pub fn get_download_dir_path() -> Option<PathBuf> {
    match home::home_dir() {
        Some(mut path) => {
            path.push(DOWNLOAD_DIR_NAME);
            Some(path)
        }
        None => None,
    }
}

pub fn init(_handle: &tauri::AppHandle) -> Result<(), Box<dyn Error>> {
    log::info!("Init netpulsar");
    // Check .netpulsar directory
    match crate::sys::get_config_dir_path() {
        Some(_config_dir) => {
            // TODO!
        }
        None => {
            return Err("Error: Could not get config directory path".into());
        }
    }

    // Load AppConfig
    let config = AppConfig::load();

    // Init logger
    let log_file_path = if let Some(file_path) = &config.logging.file_path {
        // Convert to PathBuf
        Path::new(&file_path).to_path_buf()
    } else {
        crate::sys::get_user_file_path(crate::thread_log::DEFAULT_LOG_FILE_PATH).unwrap()
    };
    let log_file: File = if log_file_path.exists() {
        File::options().write(true).open(&log_file_path)?
    } else {
        File::create(&log_file_path)?
    };
    let mut log_config_builder = simplelog::ConfigBuilder::default();
    log_config_builder.set_time_format_rfc3339();
    if let Some(offset) = crate::time::get_local_offset() {
        log_config_builder.set_time_offset(offset);
    }
    let default_log_config = log_config_builder.build();
    simplelog::CombinedLogger::init(vec![
        simplelog::TermLogger::new(
            simplelog::LevelFilter::Info,
            default_log_config.clone(),
            simplelog::TerminalMode::Mixed,
            simplelog::ColorChoice::Auto,
        ),
        simplelog::WriteLogger::new(
            config.logging.level.to_level_filter(),
            default_log_config,
            log_file,
        ),
    ])?;
    log::info!("Init complete");
    Ok(())
}

pub fn cleanup() {
    log::info!("Cleanup");
}

#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
pub use self::unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

/// Application information on system
#[derive(Debug, Clone)]
pub struct AppInfo {
    pub display_name: String,
    pub display_version: String,
    pub uninstall_string: String,
}

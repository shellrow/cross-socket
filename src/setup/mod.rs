#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
pub(crate) use self::unix::*;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub(crate) use self::windows::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AppInfo {
    pub display_name: String,
    pub display_version: String,
    pub uninstall_string: String,
}

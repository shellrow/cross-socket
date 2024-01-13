use serde::{Deserialize, Serialize};
use crate::models::user::UserInfo;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmd: Vec<String>,
    pub status: String,
    pub user_info: Option<UserInfo>,
    pub start_time: String,
    pub elapsed_time: u64,
}

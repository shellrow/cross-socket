use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use sysinfo::{PidExt, ProcessExt, SystemExt, ProcessRefreshKind, UserExt};
use chrono::{DateTime, TimeZone, NaiveDateTime, Local};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserInfo {
    pub id: String,
    pub group_id: String,
    pub name: String,
    pub groups: Vec<String>,
}

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

pub fn get_process_map() -> HashMap<u32, ProcessInfo> {
    let mut process_map: HashMap<u32, ProcessInfo> = HashMap::new();
    let system: sysinfo::System = sysinfo::System::new_with_specifics(sysinfo::RefreshKind::new().with_processes(ProcessRefreshKind::everything()).with_users_list());
    for (pid, proc) in system.processes() {
        let user_info: Option<UserInfo> = 
        if let Some(user_id) = proc.user_id() {
            let user = system.get_user_by_id(user_id);
            if let Some(user) = user {
                Some(UserInfo { 
                    id: user.id().to_string(), 
                    name: user.name().to_string(), 
                    group_id: user.group_id().to_string(), 
                    groups: user.groups().to_owned(), 
                })
            }else{
                None
            }
        }else {
            None
        };
        //let _start_time: DateTime<Utc> = Utc.timestamp_opt(proc.start_time() as i64, 0).unwrap();
        let naive_start_time: NaiveDateTime = NaiveDateTime::from_timestamp_opt(proc.start_time() as i64, 0).unwrap();
        let local_start_time: DateTime<Local> = Local.from_utc_datetime(&naive_start_time);
        let process_info: ProcessInfo = ProcessInfo { 
            pid: pid.as_u32(), 
            name: proc.name().to_string(), 
            exe_path: proc.exe().to_str().unwrap().to_string(),
            cmd: proc.cmd().to_owned(), 
            status: proc.status().to_string(), 
            user_info: user_info, 
            start_time: local_start_time.to_rfc3339(),
            elapsed_time: proc.run_time(), 
        };
        process_map.insert(pid.as_u32(), process_info);
    }
    process_map
}

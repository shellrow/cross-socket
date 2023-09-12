use crate::setup::AppInfo;
use std::collections::HashMap;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

pub fn get_os_bit() -> String {
    if cfg!(target_pointer_width = "32") {
        return "32-bit".to_owned();
    } else if cfg!(target_pointer_width = "64") {
        return "64-bit".to_owned();
    } else {
        return "unknown".to_owned();
    }
}

// Get software installation status
pub fn software_installed(software_name: String) -> bool {
    let hklm: RegKey = RegKey::predef(HKEY_LOCAL_MACHINE);
    let os_bit: String = get_os_bit();
    let npcap_key: RegKey = 
    if os_bit == "32-bit" {
        match hklm.open_subkey(format!("SOFTWARE\\{}", software_name)) {
            Ok(key) => key,
            Err(_) => return false,
        }
    }else{
        match hklm.open_subkey(format!("SOFTWARE\\WOW6432Node\\{}", software_name)) {
            Ok(key) => key,
            Err(_) => return false,
        }
    };
    let _version: String = npcap_key.get_value("").unwrap_or(String::new());
    true
}

#[allow(dead_code)]
pub fn get_installed_apps() {
    let hklm: RegKey = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let uninstall_key: RegKey = hklm
        .open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        .expect("key is missing");

    let mut apps: HashMap<String, AppInfo> = HashMap::new();
    for key in uninstall_key.enum_keys() {
        let key = match key {
            Ok(key) => key,
            Err(_) => continue,
        };
        //let key = key.unwrap();
        let subkey: RegKey = uninstall_key
            .open_subkey(key.clone())
            .expect("key is missing");
        let app: AppInfo = AppInfo {
            display_name: subkey.get_value("DisplayName").unwrap_or(String::new()),
            display_version: subkey.get_value("DisplayVersion").unwrap_or(String::new()),
            uninstall_string: subkey.get_value("UninstallString").unwrap_or(String::new()),
        };
        apps.insert(key, app);
    }
    for v in apps.values() {
        println!("{:?}", v);
    }
}

#[allow(dead_code)]
pub fn app_installed(app_name: String) -> bool {
    let hklm: RegKey = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let uninstall_key: RegKey = hklm
        .open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        .expect("key is missing");

    for key in uninstall_key.enum_keys() {
        let key = match key {
            Ok(key) => key,
            Err(_) => continue,
        };
        //let key = key.unwrap();
        let subkey: RegKey = uninstall_key
            .open_subkey(key.clone())
            .expect("key is missing");
        let display_name: String = subkey.get_value("DisplayName").unwrap_or(String::new());
        if display_name == app_name {
            return true;
        }
    }
    false
}

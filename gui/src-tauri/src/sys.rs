use std::{fs, env};
use std::path::PathBuf;

pub fn init(handle: tauri::AppHandle) {
    crate::sys::copy_db_from_resource(handle);
}

pub fn copy_db_from_resource(handle: tauri::AppHandle) {
    let resource_path = handle.path_resolver()
    .resolve_resource(format!("resources/{}", nesmap_core::define::DB_NAME))
    .expect("failed to resolve resource");
    let mut path: PathBuf = env::current_exe().unwrap();
    path.pop();
    path.push(nesmap_core::define::DB_NAME);

    if resource_path.exists() && !path.exists() {
        match fs::copy(resource_path, path) {
            Ok(_) => println!("Database copied successfully"),
            Err(e) => println!("Error copying database: {}", e),
        }
    }
}

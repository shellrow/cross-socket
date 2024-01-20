pub mod models;

use std::env;
use std::path::PathBuf;
use rusqlite::{Connection, Result};

pub const DB_NAME: &str = "netpulsar.db";
pub const IP_DB_NAME: &str = "ip.db";

pub fn connect_db(db_name: &str) -> Result<Connection, rusqlite::Error> {
    let mut path: PathBuf = env::current_exe().unwrap();
    path.pop();
    path.push(db_name);
    /* if !path.exists() {
        copy_db();
    } */
    let conn = Connection::open(path)?;
    Ok(conn)
}

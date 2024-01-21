pub mod table;
pub mod stat;
use std::env;
use std::path::PathBuf;
use rusqlite::{Connection, Result, Transaction};

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
    rusqlite::vtab::array::load_module(&conn)?;
    Ok(conn)
}

pub fn init_db() -> Result<usize, rusqlite::Error> {
    let mut affected_row_count: usize = 0;
    let mut conn: Connection = match connect_db(DB_NAME) {
        Ok(c)=> c, 
        Err(e) => return Err(e),
    };
    let tran: Transaction = conn.transaction().unwrap();
    // packet_frame
    match table::DbPacketFrame::create(&tran) {
        Ok(count) => {
            affected_row_count += count;
        },
        Err(e) => {
            return Err(e);
        }
    }
    match table::DbPacketFrame::truncate(&tran) {
        Ok(count) => {
            affected_row_count += count;
        },
        Err(e) => {
            return Err(e);
        }
    }
    // process_info
    match table::DbProcessInfo::create(&tran) {
        Ok(count) => {
            affected_row_count += count;
        },
        Err(e) => {
            return Err(e);
        }
    }
    // socket_info
    match table::DbSocketInfo::create(&tran) {
        Ok(count) => {
            affected_row_count += count;
        },
        Err(e) => {
            return Err(e);
        }
    }
    // user_info
    match table::DbUserInfo::create(&tran) {
        Ok(count) => {
            affected_row_count += count;
        },
        Err(e) => {
            return Err(e);
        }
    }
    // user_group
    match table::DbUserGroup::create(&tran) {
        Ok(count) => {
            affected_row_count += count;
        },
        Err(e) => {
            return Err(e);
        }
    }
    // group_info
    match table::DbGroupInfo::create(&tran) {
        Ok(count) => {
            affected_row_count += count;
        },
        Err(e) => {
            return Err(e);
        }
    }
    // watch_list
    match table::DbWatchList::create(&tran) {
        Ok(count) => {
            affected_row_count += count;
        },
        Err(e) => {
            return Err(e);
        }
    }
    match tran.commit() {
        Ok(_) => {
            return Ok(affected_row_count);
        },
        Err(e) => {
            return Err(e);
        }
    } 
}

pub fn cleanup_db() -> Result<usize, rusqlite::Error> {
    let mut affected_row_count: usize = 0;
    let mut conn: Connection = match connect_db(DB_NAME) {
        Ok(c)=> c, 
        Err(e) => return Err(e),
    };
    let tran: Transaction = conn.transaction().unwrap();
    // packet_frame
    match table::DbPacketFrame::truncate(&tran) {
        Ok(count) => {
            affected_row_count += count;
        },
        Err(e) => {
            return Err(e);
        }
    }
    match tran.commit() {
        Ok(_) => {
            return Ok(affected_row_count);
        },
        Err(e) => {
            return Err(e);
        }
    } 
}

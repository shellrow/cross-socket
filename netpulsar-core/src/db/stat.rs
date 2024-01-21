use std::net::IpAddr;

use crate::{db::{self, table}, sys};
use rusqlite::{Result, params, Connection, Statement, Rows, Transaction};

pub fn get_traffic_summary(local_ips: Vec<String>) -> Result<Vec<table::DbRemoteHost>, rusqlite::Error> {
    let conn: Connection = match db::connect_db(db::DB_NAME) {
        Ok(c)=> c, 
        Err(e) => return Err(e),
    };
    let mut stmt: Statement = conn.prepare("
        SELECT
            remote_address,
            SUM(CASE WHEN direction = 'in' THEN packet_count ELSE 0 END) AS in_packet_count,
            SUM(CASE WHEN direction = 'out' THEN packet_count ELSE 0 END) AS out_packet_count,
            SUM(CASE WHEN direction = 'in' THEN byte_count ELSE 0 END) AS in_byte_count,
            SUM(CASE WHEN direction = 'out' THEN byte_count ELSE 0 END) AS out_byte_count
        FROM (
            SELECT
                CASE
                    WHEN src_ip IN rarray(?1) THEN dst_ip
                    WHEN dst_ip IN rarray(?1) THEN src_ip
                    ELSE '0.0.0.0'
                END AS remote_address,
                CASE
                    WHEN src_ip IN rarray(?1) THEN 'out'
                    WHEN dst_ip IN rarray(?1) THEN 'in'
                    ELSE '0.0.0.0'
                END AS direction,
                COUNT(*) AS packet_count,
                SUM(packet_len) AS byte_count
            FROM packet_frame
            GROUP BY remote_address, direction
        ) AS subquery
        GROUP BY remote_address
    ").unwrap();
    let values:Vec<rusqlite::types::Value> = local_ips.into_iter().map(rusqlite::types::Value::from).collect();
    let ptr = std::rc::Rc::new(values);
    let mut rows: Rows = stmt.query(params![ptr]).unwrap();
    let mut traffic_summary: Vec<table::DbRemoteHost> = Vec::new();
    let sysdate: String = sys::get_sysdate();
    while let Some(row) = rows.next().unwrap() {
        let remote_address: String = row.get(0).unwrap();
        let in_packet_count: usize = row.get(1).unwrap();
        let out_packet_count: usize = row.get(2).unwrap();
        let in_byte_count: usize = row.get(3).unwrap();
        let out_byte_count: usize = row.get(4).unwrap();
        let remote_host: table::DbRemoteHost = table::DbRemoteHost {
            ip_addr: remote_address,
            hostname: String::new(),
            country_code: String::new(),
            country_name: String::new(),
            asn: String::new(),
            as_name: String::new(),
            packet_received: in_packet_count,
            packet_sent: out_packet_count,
            bytes_received: in_byte_count,
            bytes_sent: out_byte_count,
            first_seen: sysdate.clone(),
            updated_at: sysdate.clone(),
        };
        traffic_summary.push(remote_host);
    }
    Ok(traffic_summary)
}

pub async fn start_stat_updater() {
    let iface: default_net::Interface = default_net::get_default_interface().unwrap();
    let local_ips = crate::interface::get_interface_ips(&iface);
    loop {
        match get_traffic_summary(local_ips.clone()) {
            Ok(mut traffic_summary) => {
                let remote_ips: Vec<IpAddr> = traffic_summary.iter()
                .filter(|x| crate::ip::is_global_addr(x.ip_addr.parse::<IpAddr>().unwrap()))
                .map(|x| x.ip_addr.parse::<IpAddr>().unwrap()).collect();
                let dns_map = crate::dns::lookup_ips_async(remote_ips).await;
                // set hostname to traffic_summary
                for remote_host in traffic_summary.iter_mut() {
                    if let Some(hostname) = dns_map.get(&remote_host.ip_addr.parse::<IpAddr>().unwrap()) {
                        remote_host.hostname = hostname.clone();
                    }
                }
                let mut affected_row_count: usize = 0;
                let mut conn: Connection = match db::connect_db(db::DB_NAME) {
                    Ok(c)=> c, 
                    Err(e) => {
                        println!("Error: {:?}", e);
                        continue;
                    },
                };
                let tran: Transaction = conn.transaction().unwrap();
                // update traffic_summary
                for remote_host in traffic_summary {
                    match remote_host.merge(&tran) {
                        Ok(row_count) => {
                            affected_row_count += row_count;
                        },
                        Err(e) => {
                            println!("Error: {:?}", e);
                        }
                    }
                }
                match tran.commit() {
                    Ok(_) => {},
                    Err(e) => {
                        println!("Error: {:?}", e);
                    }
                }
                if affected_row_count > 0 {
                    match db::optimize_db() {
                        Ok(_) => {},
                        Err(e) => {
                            println!("Error: {:?}", e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

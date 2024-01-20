CREATE TABLE IF NOT EXISTS packet_frame (
    capture_no INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    if_index INTEGER NOT NULL,
    if_name TEXT NOT NULL,
    src_mac TEXT NOT NULL,
    dst_mac TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packet_len INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS process_info (
    pid INTEGER NOT NULL,
    name TEXT NOT NULL,
    exe_path TEXT NOT NULL,
    cmd TEXT NOT NULL,
    status TEXT NOT NULL,
    user_id TEXT NOT NULL,
    start_time TEXT NOT NULL,
    elapsed_time INTEGER NOT NULL,
    packet_sent INTEGER NOT NULL,
    packet_received INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS socket_info (
    local_ip_addr TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_ip_addr TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    ip_version INTEGER NOT NULL,
    packet_sent INTEGER NOT NULL,
    packet_received INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_info (
    id TEXT NOT NULL,
    name TEXT NOT NULL,
);

CREATE TABLE IF NOT EXISTS user_group (
    user_id TEXT NOT NULL,
    group_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_info (
    group_id TEXT NOT NULL,
    group_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remote_host (
    ip_addr TEXT NOT NULL,
    hostname TEXT NOT NULL,
    country_code TEXT NOT NULL,
    country_name TEXT NOT NULL,
    asn TEXT NOT NULL,
    as_name TEXT NOT NULL,
    packet_sent INTEGER NOT NULL,
    packet_received INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remote_service (
    ip_addr TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service_name TEXT NOT NULL,
    service_info TEXT NOT NULL,
    cpe TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

// TypeScript types from the Rust types
export interface SocketInfo {
    local_ip_addr: string,
    local_port: number,
    remote_ip_addr: string | null,
    remote_port: number | null,
    protocol: string,
    state: string | null,
    ip_version: number,
}

export interface UserInfo {
    id: string,
    group_id: string,
    name: string,
    groups: string[],
}

export interface ProcessInfo {
    pid: number,
    name: string,
    exe_path: string,
    cmd: string[],
    status: string,
    user_info: UserInfo | null,
    start_time: string,
    elapsed_time: number,
}

export interface ProcessSocketInfo {
    index: number,
    socket_info: SocketInfo,
    process_info: ProcessInfo,
}

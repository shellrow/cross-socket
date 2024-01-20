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



export interface DatalinkLayer {
    ethernet: EthernetHeader | null,
    arp: ArpHeader | null,
}

export interface EthernetHeader {
    destination: string,
    source: string,
    ethertype: string,
}

export interface ArpHeader {
    hardware_type: string,
    protocol_type: string,
    hw_addr_len: number,
    proto_addr_len: number,
    operation: string,
    sender_hw_addr: string,
    sender_proto_addr: string,
    target_hw_addr: string,
    target_proto_addr: string,
}

export interface Ipv4OptionHeader {
    copied: number,
    class: number,
    number: string,
    length: number | null,
}

export interface Ipv4Header {
    version: number,
    header_length: number,
    dscp: number,
    ecn: number,
    total_length: number,
    identification: number,
    flags: number,
    fragment_offset: number,
    ttl: number,
    next_level_protocol: string,
    checksum: number,
    source: string,
    destination: string,
    options: Ipv4OptionHeader[],
}

export interface Ipv6Header {
    version: number,
    traffic_class: number,
    flow_label: number,
    payload_length: number,
    next_header: string,
    hop_limit: number,
    source: string,
    destination: string,
}

export interface IcmpHeader {
    icmp_type: string,
    icmp_code: string,
    checksum: number,
}

export interface Icmpv6Header {
    icmpv6_type: string,
    icmpv6_code: string,
    checksum: number,
}

export interface TcpOptionHeader {
    kind: string,
    length: number | null,
    data: number[],
}

export interface TcpHeader {
    source: number,
    destination: number,
    sequence: number,
    acknowledgement: number,
    data_offset: number,
    reserved: number,
    flags: number,
    window: number,
    checksum: number,
    urgent_ptr: number,
    options: TcpOptionHeader[],
}

export interface UdpHeader {
    source: number,
    destination: number,
    length: number,
    checksum: number,
}

export interface IpLayer {
    ipv4: Ipv4Header | null,
    ipv6: Ipv6Header | null,
    icmp: IcmpHeader | null,
    icmpv6: Icmpv6Header | null,
}

export interface TransportLayer {
    tcp: TcpHeader | null,
    udp: UdpHeader | null,
}

export interface PacketFrame {
    capture_no: number,
    if_index: number,
    if_name: string,
    datalink: DatalinkLayer | null,
    ip: IpLayer | null,
    transport: TransportLayer | null,
    packet_len: number,
    timestamp: string,
}

export interface PacketDisplayData {
    capture_no: number,
    timestamp: string,
    if_index: number,
    if_name: string,
    src_addr: string,
    dst_addr: string,
    src_port: number | null,
    dst_port: number | null,
    protocol: string,
    packet_len: number,
    info: string,
}

export interface PacketFrameExt {
    capture_no: number,
    timestamp: string,
    if_index: number,
    if_name: string,
    src_addr: string,
    dst_addr: string,
    src_port: number | null,
    dst_port: number | null,
    protocol: string,
    packet_len: number,
    info: string,
    datalink: DatalinkLayer | null,
    ip: IpLayer | null,
    transport: TransportLayer | null,
}

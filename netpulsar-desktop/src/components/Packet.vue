<script setup lang="ts">
import { ref } from 'vue';

const sample_data = ref(
    [
        {
            capture_no: 1,
            timestamp: '2024-01-10 00:00:00',
            src_ip: '192.168.1.10',
            src_port: 53443,
            dst_ip: '1.1.1.1',
            dst_port: 443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: SYN',
        },
        {
            capture_no: 2,
            timestamp: '2024-01-10 00:00:01',
            src_ip: '1.1.1.1',
            src_port: 443,
            dst_ip: '192.168.1.10',
            dst_port: 53443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: SYN-ACK',
        },
        {
            capture_no: 3,
            timestamp: '2024-01-10 00:00:02',
            src_ip: '192.168.1.10',
            src_port: 53443,
            dst_ip: '1.1.1.1',
            dst_port: 443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: ACK',
        },
        {
            capture_no: 1,
            timestamp: '2024-01-10 00:00:00',
            src_ip: '192.168.1.10',
            src_port: 53443,
            dst_ip: '1.1.1.1',
            dst_port: 443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: SYN',
        },
        {
            capture_no: 2,
            timestamp: '2024-01-10 00:00:01',
            src_ip: '1.1.1.1',
            src_port: 443,
            dst_ip: '192.168.1.10',
            dst_port: 53443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: SYN-ACK',
        },
        {
            capture_no: 3,
            timestamp: '2024-01-10 00:00:02',
            src_ip: '192.168.1.10',
            src_port: 53443,
            dst_ip: '1.1.1.1',
            dst_port: 443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: ACK',
        },
        {
            capture_no: 1,
            timestamp: '2024-01-10 00:00:00',
            src_ip: '192.168.1.10',
            src_port: 53443,
            dst_ip: '1.1.1.1',
            dst_port: 443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: SYN',
        },
        {
            capture_no: 2,
            timestamp: '2024-01-10 00:00:01',
            src_ip: '1.1.1.1',
            src_port: 443,
            dst_ip: '192.168.1.10',
            dst_port: 53443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: SYN-ACK',
        },
        {
            capture_no: 3,
            timestamp: '2024-01-10 00:00:02',
            src_ip: '192.168.1.10',
            src_port: 53443,
            dst_ip: '1.1.1.1',
            dst_port: 443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: ACK',
        },
        {
            capture_no: 1,
            timestamp: '2024-01-10 00:00:00',
            src_ip: '192.168.1.10',
            src_port: 53443,
            dst_ip: '1.1.1.1',
            dst_port: 443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: SYN',
        },
        {
            capture_no: 2,
            timestamp: '2024-01-10 00:00:01',
            src_ip: '1.1.1.1',
            src_port: 443,
            dst_ip: '192.168.1.10',
            dst_port: 53443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: SYN-ACK',
        },
        {
            capture_no: 3,
            timestamp: '2024-01-10 00:00:02',
            src_ip: '192.168.1.10',
            src_port: 53443,
            dst_ip: '1.1.1.1',
            dst_port: 443,
            protocol: 'TCP',
            length: 74,
            info: 'TCP Handshake: ACK',
        },
    ]
);

// Nodes for demo.
const sampleTreeNodes = [
    {
        key: '0',
        label: 'Frame',
        data: 'Frame',
        icon: '',
        children: [
            {
                key: '0-0',
                label: 'Interface',
                data: '1',
                icon: '',
                children: [
                    { key: '0-0-0', label: 'Interface Index: 1', icon: '', data: '1' },
                    { key: '0-0-1', label: 'Interface Name: eth0', icon: '', data: 'eth0' }
                ]
            },
            {
                key: '0-1',
                label: 'Timestamp: 2024-01-10 00:00:00',
                data: '2024-01-10 00:00:00',
                icon: '',
                children: []
            }
        ]
    },
    {
        key: '1',
        label: 'Ethernet II, Src: 00:00:00:00:00:00, Dst: 00:00:00:00:00:00',
        data: 'Ethernet II, Src: 00:00:00:00:00:00, Dst: 00:00:00:00:00:00',
        icon: '',
        children: [
            {
                key: '1-0',
                label: 'Destination: 00:00:00:00:00:00',
                data: '00:00:00:00:00:00',
                icon: '',
                children: []
            },
            {
                key: '1-1',
                label: 'Source: 00:00:00:00:00:00',
                data: '00:00:00:00:00:00',
                icon: '',
                children: []
            }
        ]
    }
];
</script>

<style scoped>
.p-card, .p-card-title, .p-card-content {
    background-color: var(--surface-ground);
}
</style>

<template>
    <Card class="mt-2">
        <template #title> Capture Interface: eth0 </template>
        <template #content>
            <DataTable :value="sample_data" scrollable scrollHeight="400px" tableStyle="min-width: 50rem">
                <Column field="capture_no" header="No" ></Column>
                <Column field="timestamp" header="Timestamp" ></Column>
                <Column field="src_ip" header="SRC IP" ></Column>
                <Column field="src_port" header="SRC Port" ></Column>
                <Column field="dst_ip" header="DST IP" ></Column>
                <Column field="dst_port" header="DST Port" ></Column>
                <Column field="protocol" header="Protocol" ></Column>
                <Column field="length" header="Length" ></Column>
                <Column field="info" header="Info" ></Column>
            </DataTable>
        </template>
    </Card>
    <Card class="mt-2">
        <template #title> No: 4 </template>
        <template #content>
            <Tree :value="sampleTreeNodes" class="w-full"></Tree>
        </template>
    </Card>
</template>

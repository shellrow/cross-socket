<script setup lang="ts">
import { ref } from 'vue';

const sampleData = ref(
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
            capture_no: 4,
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
            capture_no: 5,
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
            capture_no: 6,
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
            capture_no: 7,
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
            capture_no: 8,
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
            capture_no: 9,
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
            capture_no: 10,
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
            capture_no: 11,
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
            capture_no: 12,
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

const selectedPacket = ref<any>();

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

const dialogVisible = ref(false);

const onRowSelect = (event: any) => {
    dialogVisible.value = true;
    console.log(event.data);
};

const onRowUnselect = (event: any) => {
    dialogVisible.value = false;
    console.log(event.data);
}

</script>

<style scoped>
.p-card, .p-card-title, .p-card-content {
    background-color: var(--surface-ground);
}
</style>

<template>
    <Card>
        <template #title> Capturing from eth0. Click row for more detail.</template>
        <template #content>
            <DataTable :value="sampleData" v-model:selection="selectedPacket" selectionMode="single" dataKey="capture_no" @rowSelect="onRowSelect" @rowUnselect="onRowUnselect" scrollable scrollHeight="70vh" tableStyle="min-width: 50rem">
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
    <Dialog v-model:visible="dialogVisible" :modal="false" :closable="true" header="Detail" :showHeader="true" :breakpoints="{'960px': '75vw', '640px': '100vw'}" :style="{width: '45vw'}">
        <div class="flex justify-content-between align-items-center w-full">
            <p class="font-medium text-lg text-700 mt-0">No. 8</p>
            <span class="text-500 flex align-items-center"><i class="pi pi-check-square text-lg mr-2"></i>1/4</span>
        </div>
        <Tree :value="sampleTreeNodes" class="w-full mt-2"></Tree>
        <template #footer>
            <div class="flex border-top-1 pt-5 surface-border justify-content-end align-items-center">
                <Button @click="dialogVisible = false" icon="pi pi-check" label="OK" class="m-0"></Button>
            </div>
        </template>
    </Dialog>
</template>

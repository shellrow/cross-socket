<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { emit, listen } from '@tauri-apps/api/event';
import { WindowUtil } from '../libnp/window-util';
import { PacketFrame, PacketDisplayData } from '../types/np-types';
import { DataTableRowSelectEvent } from 'primevue/datatable';

const packetDataTable = ref();
const maxPacketCount = 1000;
const windowUtil = new WindowUtil();
const tableData = ref<PacketFrame[]>([]);
const virtualTableData = ref<PacketFrame[]>([]);
const selectedPacket = ref<any>();
const caputuring = ref(false);
const tableBlocked = ref(false);
const totalRecords = ref(0);

interface TreeNode {
    key: string;
    label: string;
    data: any;
    icon: string;
    children: TreeNode[];
}

// Nodes for demo.
const packetTreeNodes = ref<TreeNode[]>([]);

const dialogVisible = ref(false);

const parsePacketFrame = (packetFrame: PacketFrame): PacketDisplayData => {
    const packetSummary: PacketDisplayData = {
        capture_no: packetFrame.capture_no,
        if_index: packetFrame.if_index,
        if_name: packetFrame.if_name,
        timestamp: packetFrame.timestamp,
        src_mac: packetFrame.src_mac,
        dst_mac: packetFrame.dst_mac,
        src_ip: packetFrame.src_ip,
        dst_ip: packetFrame.dst_ip,
        src_addr: "",
        dst_addr: "",
        src_port: packetFrame.src_port,
        dst_port: packetFrame.dst_port,
        protocol: packetFrame.protocol,
        packet_len: packetFrame.packet_len,
        info: "",
    };
    if (packetFrame.src_ip === "0.0.0.0" || packetFrame.dst_ip === "0.0.0.0") {
        packetSummary.src_addr = packetFrame.src_mac;
        packetSummary.dst_addr = packetFrame.dst_mac;
    }else {
        packetSummary.src_addr = packetFrame.src_ip;
        packetSummary.dst_addr = packetFrame.dst_ip;
    }
    return packetSummary;
};

// Culculate the displayable table data count.
// for performance. 
const culcDisplayableCount = (): number => {
    const tableHeight = (windowUtil.windowSize.innerHeight - 200);
    const rowHeight = 28;
    return Math.floor(tableHeight / rowHeight);
};

const startPacketCapture = async() => {
    console.log('start packet capture');
    tableBlocked.value = true;
    // Clear table data.
    tableData.value = [];
    virtualTableData.value = [];
    const unlisten = await listen<PacketFrame>('packet_frame', (event) => {
        let packet: PacketDisplayData = parsePacketFrame(event.payload);
        //let packet: PacketFrame = event.payload;
        //tableData.value.push(packet);
        
        // for performance, limit the table data count.
        // check each packet.
        virtualTableData.value.push(packet);
        if (virtualTableData.value.length > culcDisplayableCount()) {
            virtualTableData.value.shift();
        }
        if (tableData.value.length > maxPacketCount) {
            tableData.value.shift();
        }
        totalRecords.value = virtualTableData.value.length;
    });
    console.log('start packet_frame listener');
    invoke('start_packet_capture').then((report) => {
        console.log(report);
        unlisten();
    });
};

const stopPacketCapture = async() => {
    emit('stop_pcap', {
        message: 'stop_pcap',
    });
    tableBlocked.value = false;
};

const onChengeCapture = () => {
    if (caputuring.value) {
        startPacketCapture();
        console.log('start capture');
    }else {
        stopPacketCapture();
        console.log('stop capture');
    }
};

const onRowSelect = (event: DataTableRowSelectEvent) => {
    const packet: PacketFrame = event.data;
    // Update tree nodes. clear and add new nodes.
    packetTreeNodes.value = [];
    // Frame
    packetTreeNodes.value.push({
        key: '0',
        label: 'Frame',
        data: 'Frame',
        icon: '',
        children: []
    });
    packetTreeNodes.value[0].children.push({
        key: '0-0',
        label: 'Interface',
        data: '',
        icon: '',
        children: [
            { key: '0-0-0', label: 'Interface Index: ' + packet.if_index, icon: '', data: packet.if_index, children: [] },
            { key: '0-0-1', label: 'Interface Name: ' + packet.if_name, icon: '', data: packet.if_name, children: [] }
        ]
    });
    packetTreeNodes.value[0].children.push({
        key: '0-1',
        label: 'Timestamp: ' + packet.timestamp,
        data: packet.timestamp,
        icon: '',
        children: []
    });
    // Ethernet
    packetTreeNodes.value.push({
        key: '1',
        label: 'Ethernet',
        data: '',
        icon: '',
        children: []
    });
    packetTreeNodes.value[1].children.push({
        key: '1-0',
        label: 'Destination: ' + packet.dst_mac,
        data: packet.dst_mac,
        icon: '',
        children: []
    });
    packetTreeNodes.value[1].children.push({
        key: '1-1',
        label: 'Source: ' + packet.src_mac,
        data: packet.src_mac,
        icon: '',
        children: []
    });
    // IP
    if (packet.src_ip != "0.0.0.0" && packet.dst_ip != "0.0.0.0") {
        packetTreeNodes.value.push({
            key: '2',
            label: 'Internet Protocol',
            data: 'Internet Protocol',
            icon: '',
            children: []
        });
        packetTreeNodes.value[2].children.push({
            key: '2-0',
            label: 'Source: ' + packet.src_ip,
            data: packet.src_ip,
            icon: '',
            children: []
        });
        packetTreeNodes.value[2].children.push({
            key: '2-1',
            label: 'Destination: ' + packet.dst_ip,
            data: packet.dst_ip,
            icon: '',
            children: []
        });
    }
    // Transport
    if (packet.protocol === 'TCP' || packet.protocol === 'UDP') {
        if (packet.protocol === 'TCP') {
            packetTreeNodes.value.push({
                key: '3',
                label: 'Transmission Control Protocol',
                data: 'Transmission Control Protocol',
                icon: '',
                children: []
            });
        }else if (packet.protocol === 'UDP') {
            packetTreeNodes.value.push({
                key: '3',
                label: 'User Datagram Protocol',
                data: 'User Datagram Protocol',
                icon: '',
                children: []
            });
        }
        packetTreeNodes.value[3].children.push({
            key: '3-0',
            label: 'Source Port: ' + packet.src_port,
            data: packet.src_port.toString(),
            icon: '',
            children: []
        });
        packetTreeNodes.value[3].children.push({
            key: '3-1',
            label: 'Destination Port: ' + packet.dst_port,
            data: packet.dst_port.toString(),
            icon: '',
            children: []
        });
    }
    dialogVisible.value = true;
    console.log(event.data);
};

const onRowUnselect = (event: DataTableRowSelectEvent) => {
    dialogVisible.value = false;
    console.log(event.data);
}

onMounted(() => {
    windowUtil.mount();
    //startPacketCapture();
});

onUnmounted(() => {
    windowUtil.unmount();
    stopPacketCapture();
});

</script>

<style scoped>
.p-card, .p-card-title, .p-card-content {
    background-color: var(--surface-ground);
}
</style>

<template>
    <Card class="flex-auto" >
        <template #title>  
            <div class="flex justify-content-between">
                <div class="flex">
                    Capturing from eth0.
                </div>
                <div class="flex">
                    <ToggleButton v-model="caputuring" onLabel="Captureing" offLabel="Stop" onIcon="pi pi-play" offIcon="pi pi-pause" class="mr-2" @change="onChengeCapture" />
                </div>
            </div>
        </template>
        <template #content>
            <BlockUI :blocked="tableBlocked">
                <DataTable ref="packetDataTable" :value="virtualTableData" v-model:selection="selectedPacket" selectionMode="single" dataKey="capture_no" @rowSelect="onRowSelect" @rowUnselect="onRowUnselect" size="small" scrollable :scrollHeight="(windowUtil.windowSize.innerHeight - 200).toString() + 'px'" tableStyle="min-width: 50rem">
                    <Column field="capture_no" header="No" ></Column>
                    <Column field="timestamp" header="Timestamp" ></Column>
                    <Column field="src_addr" header="SRC Addr" ></Column>
                    <Column field="src_port" header="SRC Port" ></Column>
                    <Column field="dst_addr" header="DST Addr" ></Column>
                    <Column field="dst_port" header="DST Port" ></Column>
                    <Column field="protocol" header="Protocol" ></Column>
                    <Column field="packet_len" header="Length" ></Column>
                    <!-- <Column field="info" header="Info" ></Column> -->
                </DataTable>
            </BlockUI>
        </template>
    </Card>
    <Dialog v-model:visible="dialogVisible" :modal="false" :closable="true" header="Detail" :showHeader="true" :breakpoints="{'960px': '75vw', '640px': '100vw'}" :style="{width: '45vw'}">
        <div class="flex justify-content-between align-items-center w-full">
            <p class="font-medium text-lg text-700 mt-0">No. 8</p>
            <span class="text-500 flex align-items-center"><i class="pi pi-check-square text-lg mr-2"></i>1/4</span>
        </div>
        <Tree :value="packetTreeNodes" class="w-full mt-2"></Tree>
        <template #footer>
            <div class="flex border-top-1 pt-5 surface-border justify-content-end align-items-center">
                <Button @click="dialogVisible = false" icon="pi pi-check" label="OK" class="m-0"></Button>
            </div>
        </template>
    </Dialog>
</template>

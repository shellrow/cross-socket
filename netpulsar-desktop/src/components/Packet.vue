<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { emit, listen } from '@tauri-apps/api/event';
import { WindowUtil } from '../libnp/window-util';
import { PacketFrame, PacketFrameExt, PacketSummary } from '../types/np-types';
//import DataTableProps from 'primevue/datatable';

const windowUtil = new WindowUtil();
const tableData = ref<PacketFrameExt[]>([]);
const selectedPacket = ref<any>();
const caputuring = ref(false);
//const dataTableRef = document.getElementById('packet-datatable');

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

const parsePacketFrame = (packetFrame: PacketFrame): PacketFrameExt => {
    const packetSummary: PacketSummary = {
        src_addr: "",
        src_port: null,
        dst_addr: "",
        dst_port: null,
        protocol: "",
        info: "",
    };
    if (packetFrame.ip) {
        if (packetFrame.ip.ipv4) {
            packetSummary.src_addr = packetFrame.ip.ipv4.source;
            packetSummary.dst_addr = packetFrame.ip.ipv4.destination;
            packetSummary.protocol = packetFrame.ip.ipv4.next_level_protocol;
        }
        if (packetFrame.ip.ipv6) {
            packetSummary.src_addr = packetFrame.ip.ipv6.source;
            packetSummary.dst_addr = packetFrame.ip.ipv6.destination;
            packetSummary.protocol = packetFrame.ip.ipv6.next_header;
        }
    }
    if (!packetSummary.protocol) {
        if (packetFrame.datalink) {
            if (packetFrame.datalink.ethernet) {
                packetSummary.protocol = packetFrame.datalink.ethernet.ethertype;
            }
        }
    }
    if (packetFrame.transport) {
        if (packetFrame.transport.tcp) {
            packetSummary.src_port = packetFrame.transport.tcp.source;
            packetSummary.dst_port = packetFrame.transport.tcp.destination;
        }
        if (packetFrame.transport.udp) {
            packetSummary.src_port = packetFrame.transport.udp.source;
            packetSummary.dst_port = packetFrame.transport.udp.destination;
        }
    }
    if (!packetSummary.src_addr || !packetSummary.dst_addr) {
        if (packetFrame.datalink) {
            if (packetFrame.datalink.arp) {
                packetSummary.src_addr = packetFrame.datalink.arp.sender_proto_addr;
                packetSummary.dst_addr = packetFrame.datalink.arp.target_proto_addr;
            }else {
                if (packetFrame.datalink.ethernet) {
                    packetSummary.src_addr = packetFrame.datalink.ethernet.source;
                    packetSummary.dst_addr = packetFrame.datalink.ethernet.destination;
                }
            }
        }
    }
    packetSummary.protocol = packetSummary.protocol.toUpperCase();
    const frameExt: PacketFrameExt = {
        capture_no: packetFrame.capture_no,
        datalink: packetFrame.datalink,
        ip: packetFrame.ip,
        transport: packetFrame.transport,
        payload: packetFrame.payload,
        packet_len: packetFrame.packet_len,
        timestamp: packetFrame.timestamp,
        summary: packetSummary,
    };
    return frameExt;
};

const startPacketCapture = async() => {
    console.log('start packet capture');
    /* const unlisten = await listen<any>('packet_frame', (event) => {
        console.log(event.payload);
    }); */
    await listen<PacketFrame>('packet_frame', (event) => {
        let packet = parsePacketFrame(event.payload);
        tableData.value.push(packet);
        // if tableData.value.length > 50, remove the first element.
        /* if (tableData.value.length > 50) {
            tableData.value.shift();
        } */
    });
    console.log('start packet_frame listener');
    invoke('start_packet_capture').then((report) => {
        console.log(report);
        //unlisten();
    });
};

const stopPacketCapture = async() => {
    emit('stop_pcap', {
        message: 'stop_pcap',
    });
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

const onRowSelect = (event: any) => {
    dialogVisible.value = true;
    console.log(event.data);
};

const onRowUnselect = (event: any) => {
    dialogVisible.value = false;
    console.log(event.data);
}

onMounted(() => {
    windowUtil.mount();
    //startPacketCapture();
});

onUnmounted(() => {
    windowUtil.unmount();
});

</script>

<style scoped>
.p-card, .p-card-title, .p-card-content {
    background-color: var(--surface-ground);
}
</style>

<template>
    <Card>
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
            <DataTable :value="tableData" v-model:selection="selectedPacket" selectionMode="single" dataKey="capture_no" @rowSelect="onRowSelect" @rowUnselect="onRowUnselect" size="small" scrollable :scrollHeight="(windowUtil.windowSize.innerHeight-100).toString() + 'px'" tableStyle="min-width: 50rem">
                <Column field="capture_no" header="No" ></Column>
                <Column field="timestamp" header="Timestamp" ></Column>
                <Column field="summary.src_addr" header="SRC Addr" ></Column>
                <Column field="summary.src_port" header="SRC Port" ></Column>
                <Column field="summary.dst_addr" header="DST Addr" ></Column>
                <Column field="summary.dst_port" header="DST Port" ></Column>
                <Column field="summary.protocol" header="Protocol" ></Column>
                <Column field="packet_len" header="Length" ></Column>
                <Column field="summary.info" header="Info" ></Column>
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

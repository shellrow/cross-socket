<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
//import { listen } from '@tauri-apps/api/event';
import { ProcessSocketInfo } from '../types/np-types';

interface ConnectionInfo {
    conn_id: number;
    protocol: string;
    local_ip_addr: string;
    local_hostname: string;
    local_port: number;
    remote_ip_addr: string | null;
    remote_hostname: string | null;
    remote_port: number | null;
    status: string;
    process_id: number;
    process_name: string;
}

const GetNetStat = async() => {
    const result = await invoke<ProcessSocketInfo[]>('get_netstat');
    console.log(result);
    // convert ProcessSocketInfo[] to ConnectionInfo[]
    const connInfo: ConnectionInfo[] = [];
    result.forEach((item, index) => {
        connInfo.push({
            conn_id: index,
            protocol: item.socket_info.protocol,
            local_ip_addr: item.socket_info.local_ip_addr,
            local_hostname: "",
            local_port: item.socket_info.local_port,
            remote_ip_addr: item.socket_info.remote_ip_addr,
            remote_hostname: "",
            remote_port: item.socket_info.remote_port,
            status: item.socket_info.state || "",
            process_id: item.process_info.pid,
            process_name: item.process_info.name,
        });
    });
    tableData.value = connInfo;
}

/* function getRandomPort(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
} */

const tableData = ref<ConnectionInfo[]>([
/*   {
    conn_id: 1,
    protocol: 'TCP',
    src_ip_addr: '192.168.11.9',
    src_hostname: 'localhost',
    src_port: getRandomPort(49152, 65535),
    dst_ip_addr: '8.8.8.8',
    dst_hostname: 'dns.google',
    dst_port: 53,
    status: 'ESTABLISHED',
    process_id: 82,
    process_name: 'exampleProcess0',
  },
  {
    conn_id: 2,
    protocol: 'TCP',
    src_ip_addr: '192.168.11.9',
    src_hostname: 'localhost',
    src_port: getRandomPort(49152, 65535),
    dst_ip_addr: '1.1.1.1',
    dst_hostname: 'one.one.one.one',
    dst_port: 80,
    status: 'CLOSE_WAIT',
    process_id: 123,
    process_name: 'exampleProcess1',
  },
  {
    conn_id: 3,
    protocol: 'TCP',
    src_ip_addr: '192.168.11.9',
    src_hostname: 'localhost',
    src_port: getRandomPort(49152, 65535),
    dst_ip_addr: '203.0.113.2',
    dst_hostname: 'example.com',
    dst_port: 443,
    status: 'SYN_SENT',
    process_id: 456,
    process_name: 'anotherProcess2',
  },
  {
    conn_id: 4,
    protocol: 'TCP',
    src_ip_addr: '192.168.11.9',
    src_hostname: 'localhost',
    src_port: getRandomPort(49152, 65535),
    dst_ip_addr: '104.244.42.130',
    dst_hostname: 'twitter.com',
    dst_port: 443,
    status: 'TIME_WAIT',
    process_id: 789,
    process_name: 'thirdProcess3',
  },
  {
    conn_id: 5,
    protocol: 'TCP',
    src_ip_addr: '192.168.11.9',
    src_hostname: 'localhost',
    src_port: getRandomPort(49152, 65535),
    dst_ip_addr: '185.199.108.153',
    dst_hostname: 'github.com',
    dst_port: 443,
    status: 'FIN_WAIT_1',
    process_id: 1011,
    process_name: 'processFour',
  },
  {
    conn_id: 6,
    protocol: 'TCP',
    src_ip_addr: '192.168.11.9',
    src_hostname: 'localhost',
    src_port: getRandomPort(49152, 65535),
    dst_ip_addr: '93.184.216.34',
    dst_hostname: 'example.com',
    dst_port: 80,
    status: 'ESTABLISHED',
    process_id: 1213,
    process_name: 'sampleProcess5',
  },
  {
    conn_id: 7,
    protocol: 'TCP',
    src_ip_addr: '192.168.11.9',
    src_hostname: 'localhost',
    src_port: getRandomPort(49152, 65535),
    dst_ip_addr: '208.67.222.222',
    dst_hostname: 'resolver1.opendns.com',
    dst_port: 53,
    status: 'CLOSED',
    process_id: 1415,
    process_name: 'processSix',
  },
  {
    conn_id: 8,
    protocol: 'TCP',
    src_ip_addr: '192.168.11.9',
    src_hostname: 'localhost',
    src_port: getRandomPort(49152, 65535),
    dst_ip_addr: '185.199.108.153',
    dst_hostname: 'developer.mozilla.org',
    dst_port: 443,
    status: 'ESTABLISHED',
    process_id: 1617,
    process_name: 'processSeven',
  }, */
]);

const selectedHostKv = ref(
    [
        {
            key: 'IP Address',
            value: '1.1.1.1',
        },
        {
            key: 'Hostname',
            value: 'one.one.one.one',
        },
        {
            key: 'Port',
            value: '53',
        },
        {
            key: 'Protocol',
            value: 'UDP',
        },
        {
            key: 'Packets',
            value: '24',
        },
        {
            key: 'Bytes',
            value: '4488',
        },
        {
            key: 'Country',
            value: 'US',
        },
        {
            key: 'ASN',
            value: 'AS13335 Cloudflare, Inc.',
        },
        {
            key: 'Info',
            value: 'DNS Query',
        },
    ]
);

const selectedHost = ref<any>();

const dialogVisible = ref(false);

const onRowSelect = (event: any) => {
    dialogVisible.value = true;
    console.log(event.data);
};

const onRowUnselect = (event: any) => {
    dialogVisible.value = false;
    console.log(event.data);
}

onMounted(() => {
    GetNetStat();
});

onUnmounted(() => {

});

</script>

<style scoped>
.p-card, .p-card-title, .p-card-content {
    background-color: var(--surface-ground);
}
</style>

<template>
    <Card>
        <template #title> Active TCP connections and the TCP and UDP ports on which is listening. Click row for more detail.  </template>
        <template #content>
            <DataTable :value="tableData" v-model:selection="selectedHost" selectionMode="single" dataKey="conn_id" @rowSelect="onRowSelect" @rowUnselect="onRowUnselect" scrollable scrollHeight="70vh" tableStyle="min-width: 50rem">
                <Column field="conn_id" header="No" sortable></Column>
                <Column field="local_ip_addr" header="SRC IP Address" sortable></Column>
                <!-- <Column field="local_hostname" header="SRC Host Name"></Column> -->
                <Column field="local_port" header="SRC Port" sortable></Column>
                <Column field="remote_ip_addr" header="DST IP Address" sortable></Column>
                <!-- <Column field="remote_hostname" header="DST Host Name"></Column> -->
                <Column field="remote_port" header="DST Port" sortable></Column>
                <Column field="protocol" header="Protocol" sortable></Column>
                <Column field="status" header="Status" sortable></Column>
                <Column field="process_id" header="Process ID" sortable></Column>
                <Column field="process_name" header="Process Name" sortable></Column>
            </DataTable>
        </template>
    </Card>
    <Dialog v-model:visible="dialogVisible" :modal="false" :closable="true" header="Detail" :showHeader="true" :breakpoints="{'960px': '75vw', '640px': '100vw'}" :style="{width: '45vw'}">
        <DataTable :value="selectedHostKv"  scrollable scrollHeight="70vh" tableStyle="min-width: 50rem">
                <Column field="key" header="Key" ></Column>
                <Column field="value" header="Value" ></Column>
            </DataTable>
        <template #footer>
            <div class="flex border-top-1 pt-5 surface-border justify-content-end align-items-center">
                <Button @click="dialogVisible = false" icon="pi pi-check" label="OK" class="m-0"></Button>
            </div>
        </template>
    </Dialog>
</template>

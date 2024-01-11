<script setup lang="ts">
import { ref } from 'vue';

function getRandomPort(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const sampleData = ref([
  {
    conn_id: 1,
    protocol: 'TCP',
    src_ip_addr: '192.168.11.9',
    src_hostname: 'localhost',
    src_port: getRandomPort(49152, 65535),
    dst_ip_addr: '8.8.8.8',
    dst_hostname: 'dns.google',
    dst_port: 53,
    status: 'ESTABLISHED',
    pid: 82,
    pname: 'exampleProcess0',
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
    pid: 123,
    pname: 'exampleProcess1',
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
    pid: 456,
    pname: 'anotherProcess2',
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
    pid: 789,
    pname: 'thirdProcess3',
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
    pid: 1011,
    pname: 'processFour',
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
    pid: 1213,
    pname: 'sampleProcess5',
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
    pid: 1415,
    pname: 'processSix',
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
    pid: 1617,
    pname: 'processSeven',
  },
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
            <DataTable :value="sampleData" v-model:selection="selectedHost" selectionMode="single" dataKey="conn_id" @rowSelect="onRowSelect" @rowUnselect="onRowUnselect" scrollable scrollHeight="70vh" tableStyle="min-width: 50rem">
                <Column field="conn_id" header="No"></Column>
                <Column field="src_ip_addr" header="Source IP Address"></Column>
                <Column field="src_hostname" header="Source Host Name"></Column>
                <Column field="src_port" header="Source Port"></Column>
                <Column field="dst_ip_addr" header="Destination IP Address"></Column>
                <Column field="dst_hostname" header="Destination Host Name"></Column>
                <Column field="dst_port" header="Destination Port"></Column>
                <Column field="protocol" header="Protocol"></Column>
                <Column field="status" header="Status"></Column>
                <Column field="pid" header="Process ID"></Column>
                <Column field="pname" header="Process Name"></Column>
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

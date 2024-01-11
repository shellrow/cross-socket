<script setup lang="ts">
import { ref } from 'vue';

const sampleData = ref([
  {
    pid: 123,
    pname: 'exampleProcess1',
    bytes_sent: 2048,
    bytes_received: 1024,
    packets_sent: 50,
    packets_received: 25,
    user: 'john_doe',
  },
  {
    pid: 456,
    pname: 'anotherProcess2',
    bytes_sent: 40960,
    bytes_received: 8192,
    packets_sent: 200,
    packets_received: 40,
    user: 'roor',
  },
  {
    pid: 789,
    pname: 'thirdProcess3',
    bytes_sent: 8192,
    bytes_received: 2048,
    packets_sent: 30,
    packets_received: 15,
    user: 'john_doe',
  },
  {
    pid: 1011,
    pname: 'processFour',
    bytes_sent: 16384,
    bytes_received: 4096,
    packets_sent: 80,
    packets_received: 20,
    user: 'john_doe',
  },
  {
    pid: 1213,
    pname: 'sampleProcess5',
    bytes_sent: 3072,
    bytes_received: 10240,
    packets_sent: 60,
    packets_received: 30,
    user: 'john_doe',
  },
  {
    pid: 1415,
    pname: 'processSix',
    bytes_sent: 5120,
    bytes_received: 2560,
    packets_sent: 25,
    packets_received: 12,
    user: 'john_doe',
  },
  {
    pid: 1617,
    pname: 'processSeven',
    bytes_sent: 20480,
    bytes_received: 6144,
    packets_sent: 100,
    packets_received: 50,
    user: 'roor',
  },
  {
    pid: 1819,
    pname: 'processEight',
    bytes_sent: 1024,
    bytes_received: 512,
    packets_sent: 10,
    packets_received: 5,
    user: 'root',
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
        <template #title> Active processes and their communication details. Click row for more detail. </template>
        <template #content>
            <DataTable :value="sampleData" v-model:selection="selectedHost" selectionMode="single" dataKey="pid" @rowSelect="onRowSelect" @rowUnselect="onRowUnselect" scrollable scrollHeight="70vh" tableStyle="min-width: 50rem">
                <Column field="pid" header="Process ID"></Column>
                <Column field="pname" header="Process Name"></Column>
                <Column field="bytes_sent" header="Bytes Sent"></Column>
                <Column field="bytes_received" header="Bytes Received"></Column>
                <Column field="packets_sent" header="Packets Sent"></Column>
                <Column field="packets_received" header="Packets Received"></Column>
                <Column field="user" header="User"></Column>
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

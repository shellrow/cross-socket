<script setup lang="ts">
import { ref } from 'vue';

const sampleData = ref(
    [
        {
            host_id: 1,
            ip_addr: '1.1.1.1',
            hostname: 'one.one.one.one',
            port: 53,
            protocol: 'UDP',
            packets: 24,
            bytes: 4488,
            country: 'US',
            asn: 'AS13335 Cloudflare, Inc.',
            info: 'DNS Query',
        },
        {
            host_id: 2,
            ip_addr: '8.8.8.8',
            hostname: 'dns.google',
            port: 53,
            protocol: 'UDP',
            packets: 50,
            bytes: 2048,
            country: 'US',
            asn: 'AS15169 Google LLC',
            info: 'DNS Query',
        },
        {
            host_id: 3,
            ip_addr: '216.58.214.46',
            hostname: 'google.com',
            port: 443,
            protocol: 'TCP',
            packets: 200,
            bytes: 40960,
            country: 'US',
            asn: 'AS15169 Google LLC',
            info: 'HTTPS Request',
        },
        {
            "host_id": 4,
            "ip_addr": "208.67.222.222",
            "hostname": "resolver1.opendns.com",
            "port": 53,
            "protocol": "UDP",
            "packets": 30,
            "bytes": 5120,
            "country": "US",
            "asn": "AS36692 OpenDNS, LLC",
            "info": "DNS Query"
        },
        {
            "host_id": 5,
            "ip_addr": "185.199.108.153",
            "hostname": "github.com",
            "port": 443,
            "protocol": "TCP",
            "packets": 150,
            "bytes": 30720,
            "country": "US",
            "asn": "AS54113 Fastly",
            "info": "HTTPS Request"
        },
        {
            "host_id": 6,
            "ip_addr": "93.184.216.34",
            "hostname": "example.com",
            "port": 80,
            "protocol": "TCP",
            "packets": 100,
            "bytes": 20480,
            "country": "US",
            "asn": "AS15133 Edgecast Networks, Inc.",
            "info": "HTTP Request"
        },
        {
            "host_id": 7,
            "ip_addr": "104.244.42.130",
            "hostname": "twitter.com",
            "port": 443,
            "protocol": "TCP",
            "packets": 120,
            "bytes": 24576,
            "country": "US",
            "asn": "AS13414 Twitter Inc.",
            "info": "HTTPS Request"
        },
        {
            "host_id": 8,
            "ip_addr": "185.199.108.153",
            "hostname": "developer.mozilla.org",
            "port": 443,
            "protocol": "TCP",
            "packets": 80,
            "bytes": 16384,
            "country": "US",
            "asn": "AS54113 Fastly",
            "info": "HTTPS Request"
        }
    ]
);

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
        <template #title> Detected RemoteAddress. Click row for more detail. </template>
        <template #content>
            <DataTable :value="sampleData" v-model:selection="selectedHost" selectionMode="single" dataKey="host_id" @rowSelect="onRowSelect" @rowUnselect="onRowUnselect" scrollable scrollHeight="70vh" tableStyle="min-width: 50rem">
                <Column field="host_id" header="No" ></Column>
                <Column field="ip_addr" header="IP Address" ></Column>
                <Column field="hostname" header="Host Name" ></Column>
                <Column field="port" header="Port" ></Column>
                <Column field="protocol" header="Protocol" ></Column>
                <Column field="packets" header="Packets" ></Column>
                <Column field="bytes" header="Bytes" ></Column>
                <Column field="country" header="Country" ></Column>
                <Column field="asn" header="ASN" ></Column>
                <Column field="info" header="Info" ></Column>
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

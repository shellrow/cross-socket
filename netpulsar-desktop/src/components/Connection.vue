<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
//import { listen } from '@tauri-apps/api/event';
import { KVItem, OptionItem } from '../types/common';
import { ProcessSocketInfo, SocketInfoOption } from '../types/np-types';
import { setRoutine } from '../libnp/routine';
import { WindowUtil } from '../libnp/window-util';
import { DataTableRowSelectEvent } from 'primevue/datatable';

const tableData = ref<ProcessSocketInfo[]>([]);
const selectedHostKv = ref<KVItem[]>([]);
const selectedHost = ref<any>();
const selectedAddressFamily = ref<OptionItem[]>([]);
const selectedTransportProtocol = ref<OptionItem[]>([]);
const dialogVisible = ref(false);
const isLoading = ref(false);
const autoUpdate = ref(false);
const windowUtil = new WindowUtil();

const GetNetStat = async() => {
    console.log(selectedAddressFamily.value);
    console.log(selectedTransportProtocol.value);
    isLoading.value = true;
    let options: SocketInfoOption = {
        address_family: [],
        transport_protocol: [],
    };
    if (selectedAddressFamily.value) {
        selectedAddressFamily.value.forEach((item) => {
            options.address_family?.push(item.id);
        });
    } else {
        options.address_family = ['IPv4', 'IPv6'];
    }
    if (selectedTransportProtocol.value) {
        selectedTransportProtocol.value.forEach((item) => {
            options.transport_protocol?.push(item.id);
        });
    } else {
        options.transport_protocol = ['TCP'];
    }
    console.log(options);
    const result = await invoke<ProcessSocketInfo[]>('get_netstat', {opt: options});
    tableData.value = result;
    isLoading.value = false;
}

const routine = setRoutine({
  interval: 5000,
  callback: () => { 
        if (autoUpdate.value) {
            GetNetStat(); 
            console.log('updated');
            console.log(windowUtil.windowSize);
        }
    }
});

const setDefaultOptions = () => {
    selectedAddressFamily.value = [
        { id: 'IPv4', name: ' IPv4' },
        { id: 'IPv6', name: ' IPv6' }
    ];
    selectedTransportProtocol.value = [
        { id: 'TCP', name: ' TCP' }
    ];
}

const address_families: OptionItem[] = [
    { id: 'IPv4', name: ' IPv4' },
    { id: 'IPv6', name: ' IPv6' }
];

const transport_protocols: OptionItem[] = [
    { id: 'TCP', name: ' TCP' },
    { id: 'UDP', name: ' UDP' }
];

const onRowSelect = (event: DataTableRowSelectEvent) => {
    dialogVisible.value = true;
    const ps: ProcessSocketInfo = event.data;
    selectedHostKv.value = [
        {
            key: 'IP Address',
            value: ps.socket_info.remote_ip_addr || '',
        },
        {
            key: 'Hostname',
            value: '',
        },
        {
            key: 'Port',
            value: ps.socket_info.remote_port?.toString() || '',
        },
        {
            key: 'Protocol',
            value: ps.socket_info.protocol,
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
    ];
};

const onRowUnselect = (_event: DataTableRowSelectEvent) => {
    dialogVisible.value = false;
}

onMounted(() => {
    windowUtil.mount();
    setDefaultOptions();
    GetNetStat();
    routine.start();
});

onUnmounted(() => {
    windowUtil.unmount();
    routine.stop();
});

</script>

<style scoped>
.p-card, .p-card-title, .p-card-content {
    background-color: var(--surface-ground);
}
</style>

<template>
    <Card class="flex-auto">
        <template #title> 
            <div class="flex justify-content-between">
                <div class="flex">
                    Network sockets information
                </div>
                <div class="flex">
                    <MultiSelect v-model="selectedAddressFamily" :options="address_families" optionLabel="name" placeholder="AddressFamily" :maxSelectedLabels="2" class="flex mr-2" />
                    <MultiSelect v-model="selectedTransportProtocol" :options="transport_protocols" optionLabel="name" placeholder="TransportProtocol" :maxSelectedLabels="2" class="mr-2" />
                    <ToggleButton v-model="autoUpdate" onLabel="Auto" offLabel="Manual" onIcon="pi pi-play" offIcon="pi pi-pause" class="mr-2" />
                    <Button type="button" icon="pi pi-refresh" outlined :loading="isLoading" @click="GetNetStat" :disabled="autoUpdate" />
                </div>
            </div>
        </template>
        <template #content>
            <DataTable :value="tableData" v-model:selection="selectedHost" :loading="isLoading" :virtualScrollerOptions="{ itemSize: 20 }" selectionMode="single" dataKey="index" @rowSelect="onRowSelect" @rowUnselect="onRowUnselect" size="small" scrollable :scrollHeight="(windowUtil.windowSize.innerHeight-200).toString() + 'px'" tableStyle="min-width: 50rem">
                <Column field="index" header="No" sortable></Column>
                <Column field="socket_info.local_ip_addr" header="SRC IP Address" sortable></Column>
                <!-- <Column field="local_hostname" header="SRC Host Name"></Column> -->
                <Column field="socket_info.local_port" header="SRC Port" sortable></Column>
                <Column field="socket_info.remote_ip_addr" header="DST IP Address" sortable></Column>
                <!-- <Column field="remote_hostname" header="DST Host Name"></Column> -->
                <Column field="socket_info.remote_port" header="DST Port" sortable></Column>
                <Column field="socket_info.protocol" header="Protocol" sortable></Column>
                <Column field="socket_info.state" header="Status" sortable></Column>
                <Column field="process_info.pid" header="Process ID" sortable></Column>
                <Column field="process_info.name" header="Process Name" sortable></Column>
            </DataTable>
        </template>
    </Card>
    <Dialog v-model:visible="dialogVisible" :modal="false" :closable="true" header="RemoteHost Detail" :showHeader="true" :breakpoints="{'960px': '75vw', '640px': '100vw'}" :style="{width: '45vw'}">
        <DataTable :value="selectedHostKv" size="small"  scrollable scrollHeight="70vh" tableStyle="min-width: 50rem">
                <Column field="key" header="" ></Column>
                <Column field="value" header="" ></Column>
            </DataTable>
        <template #footer>
            <div class="flex border-top-1 pt-5 surface-border justify-content-end align-items-center">
                <Button @click="dialogVisible = false" icon="pi pi-check" label="OK" class="m-0"></Button>
            </div>
        </template>
    </Dialog>
</template>

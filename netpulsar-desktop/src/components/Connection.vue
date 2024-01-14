<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
//import { listen } from '@tauri-apps/api/event';
import { KVItem } from '../types/common';
import { ProcessSocketInfo } from '../types/np-types';
import { setRoutine } from '../libnp/routine';
import { WindowUtil } from '../libnp/window-util';
import { DataTableRowSelectEvent } from 'primevue/datatable';

const tableData = ref<ProcessSocketInfo[]>([]);
const selectedHostKv = ref<KVItem[]>([]);
const selectedHost = ref<any>();
const dialogVisible = ref(false);
const isLoading = ref(false);
const autoUpdate = ref(false);
const windowUtil = new WindowUtil();

const GetNetStat = async() => {
    isLoading.value = true;
    const result = await invoke<ProcessSocketInfo[]>('get_netstat');
    //console.log(result);
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
})

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
/* .overlay {
    position:fixed !important;
    top: 0;
    left: 0;
    width: 100% !important;
    height: 100% !important;
    z-index: 100;
} */
</style>

<template>
    <!-- <BlockUI :blocked="isLoading" :fullScreen="true"></BlockUI>
    <ProgressSpinner v-show="isLoading" class="overlay"/> -->
    <Card>
        <template #title> 
            <div class="flex justify-content-between">
                <div class="flex">
                    Active TCP connections and the TCP and UDP ports on which is listening.  
                </div>
                <div class="flex">
                    <ToggleButton v-model="autoUpdate" onLabel="Auto" offLabel="Manual" onIcon="pi pi-play" offIcon="pi pi-pause" class="mr-2" />
                    <Button type="button" icon="pi pi-refresh" outlined :loading="isLoading" @click="GetNetStat" :disabled="autoUpdate" />
                </div>
            </div>
        </template>
        <template #content>
            <DataTable :value="tableData" v-model:selection="selectedHost" :loading="isLoading" selectionMode="single" dataKey="index" @rowSelect="onRowSelect" @rowUnselect="onRowUnselect" size="small" scrollable :scrollHeight="(windowUtil.windowSize.innerHeight-100).toString() + 'px'" tableStyle="min-width: 50rem">
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

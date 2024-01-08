<script setup lang="ts">
import { ref } from 'vue';

const sample_data = ref(
    [
        {
            uuid: '68bfe509-8efc-403d-af5a-c1af9fbec74f',
            id: 'sample1',
            name: 'Sample 1',
            description: 'Some user description',
            profile_image: '68bfe509-8efc-403d-af5a-c1af9fbec74f.png',
            age: 24,
        },
        {
            uuid: 'bdc9d151-1b1d-4acc-9d80-2ea489c4a96a',
            id: 'sample2',
            name: 'Sample 2',
            description: 'Some user description',
            profile_image: 'bdc9d151-1b1d-4acc-9d80-2ea489c4a96a.png',
            age: 25,
        },
        {
            uuid: '96f90b23-d55e-4521-bdcc-43cfdb304a7a',
            id: 'sample3',
            name: 'Sample 3',
            description: 'Some user description',
            profile_image: '96f90b23-d55e-4521-bdcc-43cfdb304a7a.png',
            age: 26,
        },
        {
            uuid: '96ff0b23-d85e-6511-bacb-43wadb304a7a',
            id: 'sample4',
            name: 'Sample 4',
            description: 'Some user description',
            profile_image: '96ff0b23-d85e-6511-bacb-43wadb304a7a.png',
            age: 27,
        }
    ]
    );

</script>

<style scoped>
.p-card, .p-card-title, .p-card-content {
    background-color: var(--surface-ground);
}
</style>

<template>
    <Card>
        <template #title> Basic Table </template>
        <template #content>
            <DataTable :value="sample_data" tableStyle="min-width: 50rem">
                <Column field="id" header="ID"></Column>
                <Column field="name" header="Name"></Column>
                <Column field="description" header="Description"></Column>
                <Column field="age" header="Age"></Column>
            </DataTable>
        </template>
    </Card>
    <Card class="mt-2">
        <template #title> Grid </template>
        <template #content>
            <DataTable :value="sample_data" showGridlines tableStyle="min-width: 50rem">
                <Column field="id" header="ID"></Column>
                <Column field="name" header="Name"></Column>
                <Column field="description" header="Description"></Column>
                <Column field="age" header="Age"></Column>
            </DataTable>
        </template>
    </Card>
    <Card class="mt-2">
        <template #title> Sort </template>
        <template #content>
            <DataTable :value="sample_data" removableSort tableStyle="min-width: 50rem">
                <Column field="id" header="ID" sortable style="width: 25%"></Column>
                <Column field="name" header="Name" sortable style="width: 25%"></Column>
                <Column field="description" header="Description" sortable style="width: 25%"></Column>
                <Column field="age" header="Age" sortable style="width: 25%"></Column>
            </DataTable>
        </template>
    </Card>
    <Card class="mt-2">
        <template #title> Scroll </template>
        <template #content>
            <DataTable :value="sample_data" scrollable scrollHeight="100px" tableStyle="min-width: 50rem">
                <Column field="id" header="ID" ></Column>
                <Column field="name" header="Name" ></Column>
                <Column field="description" header="Description" ></Column>
                <Column field="age" header="Age" ></Column>
            </DataTable>
        </template>
    </Card>
</template>

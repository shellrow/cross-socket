<script lang="ts" setup>
import {ref} from 'vue'
import { invoke } from "@tauri-apps/api/tauri";
import { useToast } from "primevue/usetoast";

const greetMsg = ref("");
const name = ref("");
const toast = useToast();

async function greet() {
  // Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
  greetMsg.value = await invoke("greet", { name: name.value });
  toast.add({severity:'success', summary: 'Greet', detail: greetMsg.value, life: 3000});
}
</script>

<template>
  <div class="greetings">
    <Toast />
    <h1>
      <a href="https://tauri.app/" target="_blank" rel="noopener">Tauri</a> +
      <a href="https://vitejs.dev/" target="_blank" rel="noopener">Vite</a> +
      <a href="https://vuejs.org/" target="_blank" rel="noopener">Vue 3</a> +
      <a href="https://www.primefaces.org/primevue/" target="_blank" rel="noopener">PrimeVue</a>.
    </h1>
    <div class="surface-card border-round shadow-2 p-4">
      <div class="text-900 font-medium mb-2 text-xl">Command</div>
      <p class="mt-0 mb-4 p-0 line-height-3">Calling Rust from the frontend</p>
      <div class="flex">
          <InputText class="mr-3" v-model="name" placeholder="Enter a name..." />
          <Button label="Greet" @click="greet"></Button>
      </div>
  </div>
  <p class="text-xl">{{ greetMsg }}</p>
  </div>
</template>

<style scoped>

</style>

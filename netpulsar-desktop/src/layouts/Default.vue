<script setup lang="ts">
import {ref ,onMounted, onUnmounted} from 'vue';
import { usePrimeVue } from 'primevue/config';
import {useRoute} from 'vue-router';

const route = useRoute();
const innerWidth = ref(window.innerWidth);
const innerHeight = ref(window.innerHeight);

const DARK_THEME_NAME = 'lara-dark-teal';
const LIGHT_THEME_NAME = 'lara-light-teal';
const currentTheme = ref(DARK_THEME_NAME);
const currentMode = ref(false);
const PrimeVue = usePrimeVue();

const checkWindowSize = () => {
    innerWidth.value = window.innerWidth;
    innerHeight.value = window.innerHeight;
};

if (!localStorage.theme) {
    localStorage.theme = DARK_THEME_NAME;
}

if (localStorage.theme === DARK_THEME_NAME) {
    currentTheme.value = DARK_THEME_NAME;
    currentMode.value = false;
} else {
    PrimeVue.changeTheme(DARK_THEME_NAME, LIGHT_THEME_NAME, 'theme-link', () => {});
    currentTheme.value = LIGHT_THEME_NAME;
    currentMode.value = true;
}

const changeMode = () => {
    let prevTheme = LIGHT_THEME_NAME;
    let nextTheme = DARK_THEME_NAME;
    if (currentMode.value) {
        prevTheme = DARK_THEME_NAME;
        nextTheme = LIGHT_THEME_NAME;
        currentTheme.value = LIGHT_THEME_NAME;
    }else{
        prevTheme = LIGHT_THEME_NAME;
        nextTheme = DARK_THEME_NAME;
        currentTheme.value = DARK_THEME_NAME; 
    }
    PrimeVue.changeTheme(prevTheme, nextTheme, 'theme-link', () => {});
    localStorage.theme = currentTheme.value;
};

onMounted(() => {
    window.addEventListener('resize', checkWindowSize);
});

onUnmounted(() => {
    window.removeEventListener('resize', checkWindowSize);
});
</script>

<style scoped>

</style>

<template>
<div class="min-h-screen flex relative lg:static surface-ground">
    <div id="app-sidebar-1" class="surface-section h-screen hidden lg:block flex-shrink-0 absolute lg:static left-0 top-0 z-1 border-right-1 surface-border select-none" style="width:280px">
        <div class="flex flex-column h-full">
            <div class="flex align-items-center px-5 flex-shrink-0" style="height:60px">
                <a v-ripple class="cursor-pointer block lg:hidden text-700 mr-3 mt-1 p-ripple"
                    v-styleclass="{ selector: '#app-sidebar-1', enterClass: 'hidden', enterActiveClass: 'fadeinleft', leaveToClass: 'hidden', leaveActiveClass: 'fadeoutleft', hideOnOutsideClick: true }">
                    <i class="pi pi-bars text-4xl"></i>
                </a>
                <span class="font-medium" style="color: var(--highlight-text-color)">
                    NetPulsar
                </span>
            </div>
            <div class="overflow-y-auto">
                <ul class="list-none p-3 m-0">
                    <li>
                        <router-link to="/">
                            <a v-ripple class="flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple">
                                <i class="pi pi-home mr-2"></i>
                                <span class="font-medium">Dashboard</span>
                            </a>
                        </router-link>
                    </li>
                    <li>
                        <a v-ripple class="flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple"
                            v-styleclass="{ selector: '@next', enterClass: 'hidden', enterActiveClass: 'slidedown', leaveToClass: 'hidden', leaveActiveClass: 'slideup' }">
                            <i class="pi pi-desktop mr-2"></i>
                            <span class="font-medium">Monitoring</span>
                            <i class="pi pi-chevron-down ml-auto"></i>
                        </a>
                        <ul class="list-none py-0 pl-3 pr-0 m-0 hidden overflow-y-hidden transition-all transition-duration-400 transition-ease-in-out">
                            <li>
                                <router-link to="/packet">
                                    <a v-ripple class="flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple">
                                        <i class="pi pi-arrow-right-arrow-left mr-2"></i>
                                        <span class="font-medium">Packet</span>
                                    </a>
                                </router-link>
                            </li>
                            <li>
                                <router-link to="/">
                                    <a v-ripple class="flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple">
                                        <i class="pi pi-globe mr-2"></i>
                                        <span class="font-medium">Address</span>
                                    </a>
                                </router-link>
                            </li>
                            <li>
                                <router-link to="/">
                                    <a v-ripple class="flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple">
                                        <i class="pi pi-link mr-2"></i>
                                        <span class="font-medium">Connection</span>
                                    </a>
                                </router-link>
                            </li>
                            <li>
                                <router-link to="/">
                                    <a v-ripple class="flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple">
                                        <i class="pi pi-list mr-2"></i>
                                        <span class="font-medium">Process</span>
                                    </a>
                                </router-link>
                            </li>
                        </ul>
                    </li>
                    <li>
                        <a v-ripple class="flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple"
                            v-styleclass="{ selector: '@next', enterClass: 'hidden', enterActiveClass: 'slidedown', leaveToClass: 'hidden', leaveActiveClass: 'slideup' }">
                            <i class="pi pi-eye mr-2"></i>
                            <span class="font-medium">Probe</span>
                            <i class="pi pi-chevron-down ml-auto"></i>
                        </a>
                        <ul class="list-none py-0 pl-3 pr-0 m-0 hidden overflow-y-hidden transition-all transition-duration-400 transition-ease-in-out">
                            <li>
                                <router-link to="/packet">
                                    <a v-ripple class="flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple">
                                        <i class="pi pi-send mr-2"></i>
                                        <span class="font-medium">Ping</span>
                                    </a>
                                </router-link>
                            </li>
                            <li>
                                <router-link to="/">
                                    <a v-ripple class="flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple">
                                        <i class="pi pi-share-alt mr-2"></i>
                                        <span class="font-medium">Traceroute</span>
                                    </a>
                                </router-link>
                            </li>
                        </ul>
                    </li>
                </ul>
            </div>
            <div class="mt-auto">
                <hr class="mb-3 mx-3 border-top-1 border-none surface-border" />
                <router-link to="/">
                    <a v-ripple class="m-3 flex align-items-center cursor-pointer p-3 border-round text-700 hover:surface-100 transition-duration-150 transition-colors p-ripple">
                        <i class="pi pi-cog mr-2"></i>
                        <span class="font-medium">Settings</span>
                    </a>
                </router-link>
            </div>
        </div>
    </div>
    <div class="min-h-screen flex flex-column relative flex-auto" style="z-index: 0;">
        <div class="flex justify-content-between align-items-center px-5 surface-0 border-bottom-1 surface-border relative lg:static" style="height:60px">
            <div class="flex">
                <a v-ripple class="cursor-pointer block lg:hidden text-700 mr-3 mt-1 p-ripple"
                    v-styleclass="{ selector: '#app-sidebar-1', enterClass: 'hidden', enterActiveClass: 'fadeinleft', leaveToClass: 'hidden', leaveActiveClass: 'fadeoutleft', hideOnOutsideClick: true }">
                    <i class="pi pi-bars text-4xl"></i>
                </a>
                <span class="font-medium" style="color: var(--highlight-text-color)">
                    {{ route.name }}
                </span>
            </div>
            <div class="flex">
                <ToggleButton v-model="currentMode" @click="changeMode" onLabel="" offLabel="" onIcon="pi pi-sun" offIcon="pi pi-moon" class="text-base mr-2" />
                <Button label="" icon="pi pi-bell" severity="secondary" outlined class="text-base mr-2" />
                <Button label="" icon="pi pi-question-circle" severity="secondary" outlined class="text-base mr-2" />
            </div>
        </div>
        <div class="p-5 flex flex-column flex-auto" style="z-index: -1;">
            <div class="border-2 border-dashed surface-border border-round surface-section flex-auto">
                <ScrollPanel :style="{width: '100%', height: innerHeight-100+'px'}" >
                    <router-view></router-view>
                </ScrollPanel>
            </div>
        </div>
    </div>
</div>
</template>

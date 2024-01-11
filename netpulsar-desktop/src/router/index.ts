import { createRouter, createWebHistory } from 'vue-router';
import Dashboard from '../components/Dashboard.vue';
import Packet from '../components/Packet.vue';
import RemoteAddress from '../components/RemoteAddress.vue';
import Connection from '../components/Connection.vue';
import Process from '../components/Process.vue';

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard,
  },
  {
    path: '/dashboard',
    name: 'Dashboard2',
    component: Dashboard,
  },
  {
    path: '/packet',
    name: 'Packet',
    component: Packet,
  },
  {
    path: '/remote',
    name: 'RemoteAddress',
    component: RemoteAddress,
  },
  {
    path: '/connection',
    name: 'Connection',
    component: Connection,
  },
  {
    path: '/process',
    name: 'Process',
    component: Process,
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;

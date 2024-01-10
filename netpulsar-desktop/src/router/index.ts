import { createRouter, createWebHistory } from 'vue-router';
import Dashboard from '../components/Dashboard.vue';
//import HelloWorld from '../components/HelloWorld.vue';
import Packet from '../components/Packet.vue';
import RemoteAddress from '../components/RemoteAddress.vue';

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
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;

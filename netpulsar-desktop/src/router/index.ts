import { createRouter, createWebHistory } from 'vue-router';
import Dashboard from '../components/Dashboard.vue';
//import HelloWorld from '../components/HelloWorld.vue';
import BasicTable from '../components/BasicTable.vue';

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Dashboard,
  },
  {
    path: '/dashboard',
    name: 'Dashboard',
    component: Dashboard,
  },
  {
    path: '/basictable',
    name: 'BasicTable',
    component: BasicTable,
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;

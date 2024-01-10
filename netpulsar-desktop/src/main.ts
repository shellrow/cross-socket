import { createApp } from 'vue';
import App from "./App.vue";
import router from './router';
import PrimeVue from 'primevue/config';
import BadgeDirective from 'primevue/badgedirective';
import Badge from 'primevue/badge';
import Button from 'primevue/button';
import Toast from 'primevue/toast';
import ToastService from 'primevue/toastservice';
import InputText from 'primevue/inputtext';
import Ripple from 'primevue/ripple';
import StyleClass from 'primevue/styleclass';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import ColumnGroup from 'primevue/columngroup';
import Row from 'primevue/row';
import Card from 'primevue/card';
import ScrollPanel from 'primevue/scrollpanel';
import ToggleButton from 'primevue/togglebutton';
import Tree from 'primevue/tree';
import Dialog from 'primevue/dialog';

import 'primeflex/primeflex.css';

import './assets/main.css';
import 'primevue/resources/themes/lara-dark-teal/theme.css';
import 'primevue/resources/primevue.min.css';
import 'primeicons/primeicons.css';   

const app = createApp(App);
app.use(router);
app.use(PrimeVue);
app.use(ToastService);

app.component('Badge', Badge);
app.component('Button', Button);
app.component('Toast', Toast);
app.component('InputText', InputText);
app.component('DataTable', DataTable);
app.component('Column', Column);
app.component('ColumnGroup', ColumnGroup);
app.component('Row', Row);
app.component('Card', Card);
app.component('ScrollPanel', ScrollPanel);
app.component('ToggleButton', ToggleButton);
app.component('Tree', Tree);
app.component('Dialog', Dialog);
app.directive('badge', BadgeDirective);
app.directive('ripple', Ripple);
app.directive('styleclass', StyleClass);

app.mount('#app');

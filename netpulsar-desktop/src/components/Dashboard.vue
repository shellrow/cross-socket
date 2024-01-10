<script setup lang="ts">

</script>
<template>
    <div class="flex flex-column flex-auto">
        
        <div class="p-5">
            <div class="grid">
                <div class="col-12 lg:col-6 xl:col-3">
                    <div class="surface-card shadow-2 p-3 border-1 border-50 border-round">
                        <div class="flex justify-content-between mb-3">
                            <div>
                                <span class="block text-500 font-medium mb-3">Packets</span>
                                <div class="text-900 font-medium text-xl">64338</div>
                            </div>
                            <div class="flex align-items-center justify-content-center bg-blue-100 border-round" style="width:2.5rem;height:2.5rem">
                                <i class="pi pi-arrow-right-arrow-left text-blue-500 text-xl"></i>
                            </div>
                        </div>
                        <span class="text-green-500 font-medium">4322 captured </span>
                        <span class="text-500">since last run</span>
                    </div>
                </div>
                <div class="col-12 lg:col-6 xl:col-3">
                    <div class="surface-card shadow-2 p-3 border-1 border-50 border-round">
                        <div class="flex justify-content-between mb-3">
                            <div>
                                <span class="block text-500 font-medium mb-3">Network Interface</span>
                                <div class="text-900 font-medium text-xl">eth0</div>
                            </div>
                            <div class="flex align-items-center justify-content-center bg-orange-100 border-round" style="width:2.5rem;height:2.5rem">
                                <i class="pi pi-cog text-orange-500 text-xl"></i>
                            </div>
                        </div>
                        <span class="text-green-500 font-medium">12 </span>
                        <span class="text-500">Interface found</span>
                    </div>
                </div>
                <div class="col-12 lg:col-6 xl:col-3">
                    <div class="surface-card shadow-2 p-3 border-1 border-50 border-round">
                        <div class="flex justify-content-between mb-3">
                            <div>
                                <span class="block text-500 font-medium mb-3">Ingress</span>
                                <div class="text-900 font-medium text-xl">8441.5 MB</div>
                            </div>
                            <div class="flex align-items-center justify-content-center bg-cyan-100 border-round" style="width:2.5rem;height:2.5rem">
                                <i class="pi pi-download text-cyan-500 text-xl"></i>
                            </div>
                        </div>
                        <span class="text-green-500 font-medium">124.5 MB </span>
                        <span class="text-500">new inbound</span>
                    </div>
                </div>
                <div class="col-12 lg:col-6 xl:col-3">
                    <div class="surface-card shadow-2 p-3 border-1 border-50 border-round">
                        <div class="flex justify-content-between mb-3">
                            <div>
                                <span class="block text-500 font-medium mb-3">Egress</span>
                                <div class="text-900 font-medium text-xl">6551.2 MB </div>
                            </div>
                            <div class="flex align-items-center justify-content-center bg-purple-100 border-round" style="width:2.5rem;height:2.5rem">
                                <i class="pi pi-upload text-purple-500 text-xl"></i>
                            </div>
                        </div>
                        <span class="text-green-500 font-medium">85.1 MB </span>
                        <span class="text-500">new outbound</span>
                    </div>
                </div>
                <div class="col-12 xl:col-6">
                    <div class="surface-card shadow-2 border-round p-4">
                        <div class="text-xl text-900 font-medium mb-4">Top Protocols</div>
                        <ul class="list-none p-0 m-0">
                            <li class="pb-3 border-bottom-1 surface-border">
                                <div class="font-medium text-900 mb-2">TCP</div>
                                <div class="line-height-3 text-600" style="max-width: 30rem">HTTP, HTTPS, SSH, Application Data</div>
                            </li>
                            <li class="py-3 border-bottom-1 surface-border">
                                <div class="font-medium text-900 mb-2">UDP</div>
                                <div class="line-height-3 text-600" style="max-width: 30rem">DNS, QUIC, Application Data</div>
                            </li>
                            <li class="py-3 border-bottom-1 surface-border">
                                <div class="font-medium text-900 mb-2">ICMP</div>
                                <div class="line-height-3 text-600" style="max-width: 30rem">Destination unreachable, Echo Request, Echo Response</div>
                            </li>
                            <li class="py-3 border-bottom-1 surface-border">
                                <div class="font-medium text-900 mb-2">SSDP</div>
                                <div class="line-height-3 text-600" style="max-width: 30rem">Destination unreachable, Echo Request, Echo Response</div>
                            </li>
                        </ul>
                        <div class="flex justify-content-between pt-3">
                            <Button label="Protocols" class="p-button-outlined p-button-secondary w-6 mr-2"></Button>
                            <Button label="Applications" class="p-button-outlined w-6 ml-2"></Button>
                        </div>
                    </div>
                </div>
                <div class="col-12 xl:col-6">
                    <div class="surface-card shadow-2 border-round p-4">
                        <div class="flex justify-content-between align-items-center mb-5">
                            <span class="text-xl text-900 font-medium">Top Remote Addresses</span>
                        </div>
                        <ul class="list-none p-0 m-0">
                            <li class="flex flex-column md:flex-row md:align-items-center md:justify-content-between mb-4">
                                <div class="flex">
                                    
                                    <div>
                                        <span class="block text-900 font-medium mb-1">1.1.1.1</span>
                                        <div class="text-600">one.one.one.one</div>
                                    </div>
                                </div>
                                <div class="mt-2 md:mt-0 flex flex-nowrap">
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-send"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-share-alt"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-info-circle"></Button>
                                </div>
                            </li>
                            <li class="flex flex-column md:flex-row md:align-items-center md:justify-content-between mb-4">
                                <div class="flex">
                                    
                                    <div>
                                        <span class="block text-900 font-medium mb-1">2606:4700:4700::1111</span>
                                        <div class="text-600">one.one.one.one</div>
                                    </div>
                                </div>
                                <div class="mt-2 md:mt-0 flex flex-nowrap">
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-send"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-share-alt"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-info-circle"></Button>
                                </div>
                            </li>
                            <li class="flex flex-column md:flex-row md:align-items-center md:justify-content-between mb-4">
                                <div class="flex">
                                    
                                    <div>
                                        <span class="block text-900 font-medium mb-1">8.8.8.8</span>
                                        <div class="text-600">dns.google</div>
                                    </div>
                                </div>
                                <div class="mt-2 md:mt-0 flex flex-nowrap">
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-send"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-share-alt"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-info-circle"></Button>
                                </div>
                            </li>
                            <li class="flex flex-column md:flex-row md:align-items-center md:justify-content-between mb-4">
                                <div class="flex">
                                    
                                    <div>
                                        <span class="block text-900 font-medium mb-1">2001:4860:4860::8888</span>
                                        <div class="text-600">dns.google</div>
                                    </div>
                                </div>
                                <div class="mt-2 md:mt-0 flex flex-nowrap">
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-send"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-share-alt"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-info-circle"></Button>
                                </div>
                            </li>
                            <li class="flex flex-column md:flex-row md:align-items-center md:justify-content-between mb-4">
                                <div class="flex">
                                    
                                    <div>
                                        <span class="block text-900 font-medium mb-1">35.186.224.25</span>
                                        <div class="text-600">play.spotify.com</div>
                                    </div>
                                </div>
                                <div class="mt-2 md:mt-0 flex flex-nowrap">
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-send"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-share-alt"></Button>
                                    <Button class="p-button-text p-button-plain p-button-rounded mr-1" icon="pi pi-info-circle"></Button>
                                </div>
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-12">
                    <div class="border-round p-4">
                        <div class="text-xl text-900 font-medium mb-5">Timeline</div>
                        <div class="mb-5 flex">
                            <div class="flex flex-column align-items-center" style="width:2rem">
                                <span class="bg-blue-500 text-0 flex align-items-center justify-content-center border-circle p-2">
                                    <i class="pi pi-send text-xl"></i>
                                </span>
                                <div class="h-full bg-blue-500" style="width: 2px; min-height: 4rem"></div>
                            </div>
                            <div class="ml-5 surface-card shadow-2 border-round p-3 flex-auto">
                                <div class="mb-3">
                                    <span class="text-900 font-medium inline-block mr-3">1.1.1.1</span>
                                    <span class="text-500 text-sm">1 minute ago</span>
                                </div>
                                <div class="line-height-3 text-700 mb-3">
                                    TCP Ping for 1.1.1.1:80
                                </div>
                                <div class="text-500 flex align-items-center gap-4">
                                    <div class="flex align-items-center gap-1">
                                        <i class="pi pi-send"></i>
                                        <span>0</span>
                                    </div>
                                    <div class="flex align-items-center gap-1">
                                        <i class="pi pi-share-alt"></i>
                                        <span>1</span>
                                    </div>
                                    <div class="flex align-items-center gap-1">
                                        <i class="pi pi-info-circle"></i>
                                        <span>24</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="mb-5 flex">
                            <div class="flex flex-column align-items-center" style="width:2rem">
                                <span class="bg-orange-500 text-0 flex align-items-center justify-content-center border-circle p-2">
                                    <i class="pi pi-send text-xl"></i>
                                </span>
                                <div class="h-full bg-orange-500" style="width: 2px; min-height: 4rem"></div>
                            </div>
                            <div class="ml-5 surface-card shadow-2 border-round p-3 flex-auto">
                                <div class="mb-3">
                                    <span class="text-900 font-medium inline-block mr-3">1.1.1.1</span>
                                    <span class="text-500 text-sm">1 minute ago</span>
                                </div>
                                <div class="line-height-3 text-700 mb-3">
                                    UDP Ping for 1.1.1.1
                                </div>
                                <div class="text-500 flex align-items-center gap-4">
                                    <div class="flex align-items-center gap-1">
                                        <i class="pi pi-send"></i>
                                        <span>0</span>
                                    </div>
                                    <div class="flex align-items-center gap-1">
                                        <i class="pi pi-share-alt"></i>
                                        <span>1</span>
                                    </div>
                                    <div class="flex align-items-center gap-1">
                                        <i class="pi pi-info-circle"></i>
                                        <span>24</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="mb-5 flex">
                            <div class="flex flex-column align-items-center" style="width:2rem">
                                <span class="bg-purple-500 text-0 flex align-items-center justify-content-center border-circle p-2">
                                    <i class="pi pi-send text-xl"></i>
                                </span>
                                <div class="h-full bg-purple-500" style="width: 2px; min-height: 4rem"></div>
                            </div>
                            <div class="ml-5 surface-card shadow-2 border-round p-3 flex-auto">
                                <div class="mb-3">
                                    <span class="text-900 font-medium inline-block mr-3">1.1.1.1</span>
                                    <span class="text-500 text-sm">1 minute ago</span>
                                </div>
                                <div class="line-height-3 text-700 mb-3">
                                    ICMP Ping for 1.1.1.1
                                </div>
                                <div class="text-500 flex align-items-center gap-4">
                                    <div class="flex align-items-center gap-1">
                                        <i class="pi pi-send"></i>
                                        <span>0</span>
                                    </div>
                                    <div class="flex align-items-center gap-1">
                                        <i class="pi pi-share-alt"></i>
                                        <span>1</span>
                                    </div>
                                    <div class="flex align-items-center gap-1">
                                        <i class="pi pi-info-circle"></i>
                                        <span>24</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
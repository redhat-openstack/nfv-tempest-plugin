# Tempest NFV plugin installation steps:

## environment setup
### NFV tester environment:
By default nfv-tempest-plugin planned to run from TripleO Undercloud host (used as a tester), but it could be run and tested from any host that has access to the OSP external api network.  

1. Create external network and subnet with: 

   `$ openstack network create --external --share --enable --project admin --mtu 9000 --no-default --provider-network-type vlan --provider-physical-network <PHYSNET> --provider-segment <PROVIDER_VLAN> <NETWORK_NAME>`  
   `$ openstack subnet create --allocation-pool start=<START>,end=<END> --subnet-range <SUBNET_CIDER> --dns-nameserver <DNS_SERVER> --dns-nameserver <DNS_SERVER> --dhcp --gateway <GATEWAY> --ip-version 4 --network <NETWORK_NAME> <SUBNET_NAME>`
2. create router and port connected to the external network:

   `$ openstack router create --ha router1`  
   `$ openstack router set --external-gateway <NETWORK_NAME> router1` 
3. Create required flavors with:  
   `$ openstack flavor create --ram 8192 --disk 20 --vcpus 6 --property "hw:mem_page_size=1GB" --property "hw:numa_mem.0=8192" --property "hw:numa_mempolicy=strict" --property "hw:numa_cpus.0=0,1,2,3,4,5" --property "hw:cpu_policy=dedicated" --property "hw:emulator_threads_policy=share" m1.medium.huge_pages_cpu_pinning_numa_node-0`    
   `$ openstack flavor create --ram 8192 --disk 20 --vcpus 6  --property "hw:mem_page_size=1GB" --property "hw:numa_mem.1=8192" --property "hw:numa_mempolicy=strict" --property "hw:numa_cpus.1=0,1,2,3,4,5" --property "hw:cpu_policy=dedicated" --property "hw:emulator_threads_policy=share"  m1.medium.huge_pages_cpu_pinning_numa_node-1`  
   `$ openstack flavor create --ram 8192 --disk 20 --vcpus 6  --property "hw:numa_nodes=2"      --property "hw:mem_page_size=1GB"      --property "hw:numa_mem.0=4096"      --property "hw:numa_mem.1=4096"      --property "hw:numa_mempolicy=strict"      --property "hw:numa_cpus.0=0,1,2"      --property "hw:numa_cpus.1=3,4,5"      --property "hw:cpu_policy=dedicated"      --property "hw:emulator_threads_policy=share" m1.medium.huge_pages_cpu_pinning_numa_node-mix`    
   `$ openstack flavor create --ram 8192 --disk 20 --vcpus 6 --property "hw:mem_page_size=large" --property "hw:cpu_policy=dedicated" --property "hw:emulator_threads_policy=share" nfv_qe_base_flavor`  
  **Note:** the flavor names should be corresponding with the flavor names in the external_config_file


## Install from Git
### Prerequisites:
* Installed [Upstream tempest](https://github.com/openstack/tempest) repository.  
  NFV plugin currently works with `17.2.0` tag.
* Installed [Python-tempestconf](https://opendev.org/openstack/python-tempestconf/) repository (tempest.conf configuration).  
  NFV plugin currently works with `1.1.3` tag.


### NFV plugin setup:
1. The nfv-tempeset-plugin repository should be cloned near to the main tempest directory.  
   `$ git clone https://github.com/redhat-openstack/nfv-tempest-plugin.git`
2. Activate the tempest virtual env.
3. Browse to the nfv-tempest-plugin cloned directory and install the nfv plugin:  
   `$ pip install --upgrade -e .`
4. Generate tempest.conf with [tempestconf cli-option](https://docs.openstack.org/python-tempestconf/latest/cli/cli_options.html)
Copy [tempest-sample-input-file](./tempest-deployer-input.conf.sample) and rename to tempest-deployer-input.conf  
**Note:** for tempest-deployer-input.conf parameter required, please visit  
[tests-description](./tests.md) and [tests-pre-requisites](./tests_prerequisites_config.md)  

`$ source overcloudrc`  
`$ discover-tempest-config --out <OUTPUT_PATH>/tempest.conf --deployer-input <PATH>/tempest-deployer-input.conf --debug --create --image "<IMAGE_PATH>/rhel-guest-image-7-6-210-x86-64-qcow2"   --network-id $(openstack network show <NETWORK_NAME> -f value -c id) compute.flavor_ref $(openstack flavor show <nfv-flavor> -c id -f value)`  

**Note:** nfv-flavor used tests use Centos/Rhel images with the following:  
flavor disk >= 20, ram >= 2048, vcpus >=4  
`hw:cpu_policy='dedicated`  
`hw:emulator_threads_policy='share'`  

**Note:** for dpdk tests set extraspecs in flavors  
`hw:mem_page_size": "1GB"`   

5. Test the installed plugin:  
   `$ pip list | grep -i nfv`  
   Expected output:  
   `nfv-plugin (1.0.0.dev67, /root/tempest/nfv-tempest-plugin)`
5. Browse to the main tempest directory and list NFV tests:  
   `$ testr list-tests | grep -i nfv`  
   Expected output:  
   `(output omitted)
   nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_max_queues_functionality
   nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_min_queues_functionality
   nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_odd_queues_functionality
   (output omitted)`
   
## Automatic installation, configuration and tests run:
Automatic installation, configuration and tests running is available by using ansible playbook from [Ansible NFV](https://github.com/redhat-openstack/ansible-nfv) repository.

For the comprehensive explanation of this playbook, refer to the following documentation:  
[Ansible NFV Tempest](https://github.com/redhat-openstack/ansible-nfv/blob/master/docs/tripleo/tester/tempest.md)

Basic playbook execution:  
`ansible-playbook -i tripleo_inventory playbooks/tripleo/tester/tempest.yml -e @tests_config.yml`

## pip installtion
### prerequisites
1. Get python3 pip:  
RHEL: `$ sudo yum install python3-pip`  
CentOS: `$ sudo yum install python34-setuptools ; sudo easy_install pip`  
Debian/Ubuntu: `$ sudo apt-get install python3-pip`  

### NFV plugin installation and configuration generation:
1. Install nfv-plugin and Python-tempestconf using pip:  
`$ pip3.6 install tempest-nfv-plugin python-tempestconf`
4. Generate tempest.conf with [tempestconf cli-option](https://docs.openstack.org/python-tempestconf/latest/cli/cli_options.html)
Copy [tempest-sample-input-file](./tempest-deployer-input.conf.sample) and rename to tempest-deployer-input.conf  
**Note:** for tempest-deployer-input.conf parameter required, please visit  
[tests-description](./tests.md) and [tests-pre-requisites](./tests_prerequisites_config.md)  

`$ source overcloudrc`  
`$ discover-tempest-config --out <OUTPUT_PATH>/tempest.conf --deployer-input <PATH>/tempest-deployer-input.conf --debug --create --image "<IMAGE_PATH>/rhel-guest-image-7-6-210-x86-64-qcow2"   --network-id $(openstack network show <NETWORK_NAME> -f value -c id) compute.flavor_ref $(openstack flavor show <nfv-flavor> -c id -f value)`  

**Note:** nfv-flavor used tests use Centos/Rhel images with the following:  
flavor disk >= 20, ram >= 2048, vcpus >=4  
`hw:cpu_policy='dedicated`  
`hw:emulator_threads_policy='share'`  

**Note:** for dpdk tests set extraspecs in flavors  
`hw:mem_page_size": "1GB"`   

2. Test the installed plugin:  
`$ pip list | grep -i nfv`  
3. Validate plugin is visable to tempest:  
`$ tempest list-plugins`  
   Expected output:  
```
+--------------------+--------------------------------------------+
|        Name        |                 EntryPoint                 |
+--------------------+--------------------------------------------+
| nfv_tempest_plugin | nfv_tempest_plugin.plugin:NfvTempestPlugin |
+--------------------+--------------------------------------------+
```

## Containerized installation
1. Get podman using the suitable command for your distro [here](https://podman.io/getting-started/installation)
2. Pull tempest-nfv container:    
`podman pull nfvtempest/nfv-tempest`
3. Create the following directories and files. Get [tempest-sample-input-file](./tempest-deployer-input.conf.sample) 
and copy it into tempest_etc:   
`mkdir tempest_etc container_tempest`    
`cp /home/stack/.ssh/id_rsa* <PATH>/overcloudrc <PATH>/stackrc <PATH>/ci_network_config.yml <PATH>/<IMAGE> container_tempest`    
4. Edit tempest input to have the nfv_plugin_options to look like the following:  
    `[nfv_plugin_options]
    overcloud_node_pkey_file = /opt/app-root/src/tempest/container_tempest/id_rsa
    external_config_file = /opt/app-root/src/tempest/etc/ci_network_config.yml
    test_all_provider_networks = true
    undercloud_rc_file = /opt/app-root/src/tempest/container_tempest/stackrc
    `  
5. To run rootless without using '--privileged=true' please use the following command:
`echo "user.max_user_namespaces=28633" | sudo tee -a /etc/sysctl.d/userns.conf`  
`sudo sysctl -p /etc/sysctl.d/userns.conf`  
`podman unshare chown -R 1001:1001 tempest_etc container_tempest`  
5. Generate tempest.config running the following command:  
`podman run -i -v ./container_tempest:/opt/app-root/src/tempest/container_tempest:Z -v ./tempest_etc:/opt/app-root/src/tempest/etc:Z eshulman/nfv-tempest /bin/bash -c './config_generate.sh'`  
You can see the config_generate.sh script in the tools directory all parameters can be override using '-e parameter=value' the parameters are as following

|parameter |default value |
|----------|:--------------:|
|external_network |access |
|flavor |nfv_qe_base_flavor |
|deployer_input |tempest-deployer-input.conf |
|image_name |rhel7.6 |
| additional_params|"" |
6. Create alias for running the container:    
`alias nfv-tempest='podman run -i -v ./container_tempest:/opt/app-root/src/tempest/container_tempest:Z -v ./tempest_etc:/opt/app-root/src/tempest/etc:Z eshulman/nfv-tempest /bin/bash'`
7. Use the alias for example:  
`nfv-tempest -c 'tempest run -r nfv'`
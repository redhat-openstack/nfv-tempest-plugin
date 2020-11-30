# Tempest NFV plugin installation steps:

### NFV tester environment:
By default nfv-tempest-plugin planned to run from TripleO Undercloud host (used as a tester), but it could be run and tested from any host that has access to the OSP external api network.  

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
4. create external network and subnet with: 

   `$ openstack network create --external --share --enable --project admin --mtu 9000 --no-default --provider-network-type vlan --provider-physical-network <PHYSNET> --provider-segment <PROVIDER_VLAN> <NETWORK_NAME>`  
   `$ openstack subnet create --allocation-pool start=<START>,end=<END> --subnet-range <SUBNET_CIDER> --dns-nameserver <DNS_SERVER> --dns-nameserver <DNS_SERVER> --dhcp --gateway <GATEWAY> --ip-version 4 --network <NETWORK_NAME> <SUBNET_NAME>`
5. create router and port connected to the external network:

   `$ openstack router create --ha router1`  
   `$ openstack router set --external-gateway <NETWORK_NAME> router1` 
6. Generate tempest.conf with [tempestconf cli-option](https://docs.openstack.org/python-tempestconf/latest/cli/cli_options.html)
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

7. Test the installed plugin:  
   `$ pip list | grep -i nfv`  
   Expected output:  
   `nfv-plugin (1.0.0.dev67, /root/tempest/nfv-tempest-plugin)`
8. Browse to the main tempest directory and list NFV tests:  
   `$ testr list-tests | grep -i nfv`  
   Expected output:  
   `(output omitted)
   nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_max_queues_functionality
   nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_min_queues_functionality
   nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_odd_queues_functionality
   (output omitted)`

### Automatic installation, configuration and tests run:
Automatic installation, configuration and tests running is available by using ansible playbook from [Ansible NFV](https://github.com/redhat-openstack/ansible-nfv) repository.

For the comprehensive explanation of this playbook, refer to the following documentation:  
[Ansible NFV Tempest](https://github.com/redhat-openstack/ansible-nfv/blob/master/docs/tripleo/tester/tempest.md)

Basic playbook execution:  
`ansible-playbook -i tripleo_inventory playbooks/tripleo/tester/tempest.yml -e @tests_config.yml`

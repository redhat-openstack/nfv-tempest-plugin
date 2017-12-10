# Tempest NFV plugin installation steps:

### NFV tester environment:
By default tempest-nfv-plugin planned to run from TripleO Undercloud host (used as a tester), but it could be run and tested from any host that has access to the OSP external api network.  

### Prerequisites:
* Installed [Upstream tempest](https://github.com/openstack/tempest) repository.  
  NFV plugin currently works with `16.1.0` tag.
* Installed [Python-tempestconf](https://github.com/redhat-openstack/python-tempestconf) repository (tempest.conf configuration).  
  NFV plugin currently works with `1.1.3` tag.


### NFV plugin setup:
1. The tempeset-nfv-plugin repository should be cloned near to the main tempest directory.  
   `$ git clone https://github.com/redhat-openstack/tempest-nfv-plugin.git`
2. Activate the tempest virtual env.
3. Browse to the nfv_tempest_plugin directory and install the nfv plugin:  
   `$ pip install --upgrade -e .`
4. Test the installed plugin:  
   `$ pip list | grep -i nfv`  
   Expected output:  
   `nfv-plugin (1.0.0.dev67, /root/tempest/tempest-nfv-plugin/tempest_plugin)`
5. Browse to the main tempest directory and list NFV tests:  
   `$ testr list-tests | grep -i nfv`  
   Expected output:  
   `(output omitted)
   tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_max_queues_functionality
   tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_min_queues_functionality
   tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_odd_queues_functionality
   (output omitted)`

### Automatic installation, configuration and tests run:
Automatic installation, configuration and tests running is available by using ansible playbook from [Ansible NFV](https://github.com/redhat-openstack/ansible-nfv) repository.

For the comprehensive explanation of this playbook, refer to the following documentation:  
[Ansible NFV Tempest](https://github.com/redhat-openstack/ansible-nfv/blob/master/docs/tripleo/tester/tempest.md)

Basic playbook execution:  
`ansible-playbook -i tripleo_inventory playbooks/tripleo/tester/tempest.yml -e @network_config.yml`

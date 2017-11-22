Tempest Integration of NfvTest
==============================

This directory contains Tempest tests to cover the NfvTest project.

# Setup steps:
## Prerequisites:
* Cloned/Installed upstream tempest repository.
* Cloned and executes python-tempestconf

## NFV plugin setup:

1. The tempeset-nfv-plugin repository should be cloned near to the main tempest directory.

`$ git clone https://review.gerrithub.io/redhat-openstack/tempest-nfv-plugin`

2. Activate the tempest virtual env.
3. Browse to the nfv_tempest_plugin directory and install the nfv plugin:

`$ pip install --upgrade -e .`

4. Test the installed plugin:

`$ pip list |grep -i nfv`

5. Browse to the main tempest directory and check the newly installed nfv plugin:

`$ testr list-tests |grep -i nfv`

## NFV tester environment:
The plugin planned to run from TripleO Undercloud host (Used as a tester).
In case ssh connection to overcloud computes needed:
ssh keys defined in tempest.conf
ssh from undercloud as user heat-admin to overcloud

[hypervisor]
private_key_file = /home/stack/.ssh/id_rsa
user = heat-admin

# NFV plugin tempest configuration extensions
*  network_config.yml
This file ignored if tempest.conf does not include the following parameter
[hypervisor]
external_config_file = network_config.yml

## NFV plugin automatic configuration, setup and run:

* Plugin env setup, install running tests could be automated with the following ansible
 nfv repository: https://github.com/redhat-openstack/ansible-nfv

 run playbook as follow:
 ansible-playbook -i ${TRIPLEO_TOPOLOGY}/keys/hosts
 playbooks/tripleo/tester/tempest.yml -e @${ROOT_DIR}/ansible-nfv/network_config.yml

 see network_config.yml.sample file

## NFV test cases

* Tests included in test_nfv_epa.py
  
  - Testing numa topology by booting an instance on numa0/numa1/numamix by demand
    used by insertion of the following under tests-setup at network_config.yml
    `- name: numa0
       flavor: nfv-test-flavor
       availability-zone: normal
       router: true `
  - Testing of tuned - checking exsitence of tuned package, tuned service state
    and current tuned profile.
    used by insertion of the following under tests-setup at network_config.yml
    ` - name: check-compute-packges
        package-names: tuned-2.8.0-5.el7.noarch
        service-names: tuned.service
        tuned-profile: cpu-partitioning 
        availability-zone: normal `
    Optional:
    Could be used for another package name:
    ` - name: check-compute-packges
        package-names: tuned-profiles-cpu-partitioning-2.8.0-5.el7.noarch `
  - Test multi-queue functionality.
    Calculates the number of queues * the number of PMDs.
    Boot instances using 4 different flavors, bigger, smaller, equal and odd
    number of vCPUs.
    ` - name: check-multiqueue-func
        flavor: nfv-test-flavor
        router: false
        availability-zone: normal `

* Tests included in test_nfv_dpdk_usecases.py

  - Testing live migration with ovs-dpdk.
    Boots instance, migrate it to next available hypervisor,
    checks if the instance located on wished hypervisor.
    ` - name: test_instance_migration
        flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
        router: false `

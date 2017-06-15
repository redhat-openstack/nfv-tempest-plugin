Tempest Integration of NfvTest
==============================

This directory contains Tempest tests to cover the NfvTest project.

# Setup steps:
## Prerequisites:
* Installed tempest virtual environment.
* Cloned tempest repository.

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
The plugin planned to run from TripleO undercloud compute
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
external_config_file = ${}network_config.yml


## NFV plugin automatic configuration, setup and run:

* Plugin env setup, install running tests could be automated with the following ansible
 nfv repository: https://github.com/redhat-openstack/ansible-nfv

 run playbook as follow:
 ansible-playbook -i ${OOO_TOPOLOGY}/keys/hosts
 playbooks/tripleo/tester/tempest.yml -e @${ROOT_DIR}/ansible-nfv/network_config.yml

 see network_config.yml.sample file



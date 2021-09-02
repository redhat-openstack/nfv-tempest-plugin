# Tempest NFV plugin installation steps:

**NOTE:** nfv-tempest-plugin was designed to run from the Undercloud node of any node that has access to the external api and provisioning network.

### Prerequisites:

1. Pre-create external network and subnet:
```
openstack network create \
   --external \
   --share \
   --enable \
   --project admin \
   --mtu 9000 \
   --no-default \
   --provider-network-type vlan \
   --provider-physical-network <PHYSNET> \
   --provider-segment <PROVIDER_VLAN> <NETWORK_NAME>

openstack subnet create \
   --allocation-pool start=<START>,end=<END> \
   --subnet-range <SUBNET_CIDER> \
   --dns-nameserver <DNS_SERVER> \
   --dhcp \
   --gateway <GATEWAY> \
   --ip-version 4 \
   --network <NETWORK_NAME> <SUBNET_NAME>
```

2. Create router and set default gateway:
```
openstack router create --ha router1

openstack router set --external-gateway <EXTERNAL_NETWORK_NAME> router1
```

3. Upload test image:
```
openstack image create \
   --container-format bare \
   --disk-format qcow2 \
   --public \
   --file <path_to_image_file> \
   test_image
```

**Note** - NFV testing requires the following image - rhel/centos.

4. Create test flavor:
```
openstack flavor create \
   --ram 8192 \
   --disk 20 \
   --vcpus 6 \
   --property "hw:mem_page_size=large" \
   --property "hw:cpu_policy=dedicated" \
   --property "hw:emulator_threads_policy=share" \
   nfv_qe_base_flavor
```

**Note** - DPDK tests require flavor extra-spec - "hw:mem_page_size=large" to be set.


## Install from Git
### Install Upstream tempest and python-tempestconf:
```
mkdir tempest && virtualenv tempest/venv && source tempest/venv/bin/activate

git clone https://opendev.org/openstack/tempest
git clone https://git.openstack.org/openstack/python-tempestconf -b 2.5.0
```


### NFV plugin setup:
1. The nfv-tempeset-plugin repository should be cloned near to the main tempest directory.
```
git clone https://github.com/redhat-openstack/nfv-tempest-plugin.git
```
2. Browse to the nfv-tempest-plugin cloned directory and install the nfv plugin:
```
pip install --upgrade -e .
```


### Tempest configuration:
Generate tempest.conf with [tempestconf cli-option](https://docs.openstack.org/python-tempestconf/latest/cli/cli_options.html)
Copy [tempest-sample-input-file](./tempest-deployer-input.conf.sample) and rename to tempest-deployer-input.conf  
**Note:** for tempest-deployer-input.conf parameter required, please visit  
[deployer-input.ini](./tempest-deployer-input.conf.sample) and [tests-pre-requisites](./tests_prerequisites_config.md)  

```
source overcloudrc

discover-tempest-config \
   --out <OUTPUT_PATH>/tempest.conf \
   --deployer-input <PATH>/tempest-deployer-input.conf \
   --debug \
   --create \
   --image <IMAGE_PATH> \
   --network-id $(openstack network show <NETWORK_NAME> -f value -c id) \
   compute.flavor_ref $(openstack flavor show <nfv-flavor> -c id -f value)
```


### Test installed plugin:
```
pip list | grep -i nfv

Expected output:  
nfv-plugin (1.0.0.dev67, /root/tempest/nfv-tempest-plugin)
```

**Note** - Version number will be different.  
List nfv tests:
```
stestr list nfv


Expected output:
(output omitted)
nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_mtu_ping_test
nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_cold_migration
nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_emulatorpin
(output omitted)
```


## Containerized installation
1. Get podman using the suitable command for your distro [here](https://podman.io/getting-started/installation)
2. Pull tempest-nfv container:
```
podman pull quay.io/rhos-dfg-nfv/tempest-nfv-plugin
```
3. Create the following directories and files. Get [tempest-sample-input-file](./tempest-deployer-input.conf.sample) 
and copy it into tempest_etc:
```
mkdir -p tempest/etc

cp /home/stack/.ssh/id_rsa* <PATH>/overcloudrc <PATH>/stackrc <PATH>/tempest_config.yml <PATH>/<IMAGE> tempest
```
4. Prepare the deployer-input.ini file by using the [sample](./tempest-deployer-input.conf.sample)
5. To run rootless without using '--privileged=true' please use the following command:
```
echo "user.max_user_namespaces=28633" | sudo tee -a /etc/sysctl.d/userns.conf

sudo sysctl -p /etc/sysctl.d/userns.conf

podman unshare chown -R 1001:1001 tempest
```
5. Generate tempest.conf file:
The script that performs tempest configuration in containerization environment - "config_generate.sh",  
gets the parameters from the environment variables.  
Export the parameters for the script.
```
export external_network='access'
export image_name=<IMAGE_NAME>
export flavor_name=<FLAVOR_NAME>

podman run -i \
   -v ./tempest:/opt/app-root/src/tempest/container_tempest:Z \
   -v ./tempest/etc:/opt/app-root/src/tempest/etc:Z \
   quay.io/rhos-dfg-nfv/tempest-nfv-plugin \
   /bin/bash -c './config_generate.sh'
```
6. Create alias for running the container:
```
alias nfv-tempest='podman run -i \
   -v ./tempest:/opt/app-root/src/tempest/container_tempest:Z \
   -v ./tempest/etc:/opt/app-root/src/tempest/etc:Z \
   quay.io/rhos-dfg-nfv/tempest-nfv-plugin /bin/bash'
```
7. Use the alias for example:
```
nfv-tempest -c 'tempest run -r nfv'
```


## Automatic installation, configuration and tests run:
Automatic installation, configuration and tests running is available by using ansible playbook from [Ansible NFV](https://github.com/redhat-openstack/ansible-nfv) repository.

For the comprehensive explanation of this playbook, refer to the following documentation:  
[Ansible NFV Tempest](https://github.com/redhat-openstack/ansible-nfv/blob/master/docs/tripleo/tester/tempest.md)

Basic playbook execution:  
`ansible-playbook -i tripleo_inventory playbooks/tripleo/tester/tempest.yml -e @tests_config.yml`

### Configuration of nfv-tempest-plugin related parameters in tempest.conf

The nfv-tempest-plugin uses deployer-input file to set specific tempest parameters.  
Refer to the sample file of deployer input - [sample](./tempest-deployer-input.conf.sample).  

**Note** - Below are explanation for some specific parameters required by the nfv tempest plugin.

```
[compute]
min_microversion = 2.32
max_microversion = 2.32
```

Nova uses a framework called ‘API Microversions’ for allowing changes to the API while preserving backward compatibility.  
The nova microversion used by the nfv plugin is - "2.32".  
For more information:  
  - Refer to [OpenStack's official Nova documentation regarding microversions](https://docs.openstack.org/nova/latest/contributor/microversions.html)
  - Refer to [OpenStack's official Nova documentation regarding API microversions](https://docs.openstack.org/nova/latest/reference/api-microversion-history.html)

```
[placement]
min_microversion = 1.12
max_microversion = 1.12
```

Placement api is used by Openstack to fetch resources from the overcloud nodes.  
Setting microversion for placement is required by nfv tempest plugin.  
The placement api version used by nfv plugin is - "1.12".

```
[nfv_plugin_options]
external_config_file = /home/stack/tempest_config.yml
```

The nfv-tempest-plugin uses external config file for the execution.  
The nfv-tempest-plugin locates the file by supplied path within the deployer-input file.  
The file should be located on the Undercloud host or any other host that has rc file and an access to provision network.  
The external config file contains the following parameters that required by the plugin:
  - test-networks - Should contain test networks related to the tested environment. May contains the following network types - (DPDK, SRIOV VF, SRIOV PF).
  - test-flavors - Optional parameter. Required if test flavors are not pre-created.

Refer to the sample file of tempest_config.yml - [sample](./tempest_config.yml.sample).

```
[nfv_plugin_options]
test_all_provider_networks = true
```

During instance creation, plugin can verify all provider networks attached to guest instance.  
The verification process includes:
  - Checking if guest interface are configured with layer3 settings
  - If multiple servers are created, tests ICMP traffic across all provider networks

The verification procedure requires guests instances to have a floating ip attached.

- **Note 1** - Tempest require a predefined (public api) network that will be used as an access point for the tests execution.  
All other networks used by the test will be created during the test execution and taken from the provided tempest_config.yml file.

- **Note 2** - In order to utilize Trusted VF in this plugin, custom Neutron API Policies must be set for 'create_port:binding:profile' and 'get_port:binding:profile'.

In order to minimize the pre-configuration effort, there is an automation for the environment preparation, which uses dedicated tempest ansible playbook that will install, configure and execute the tests on selected environment.
Tempest ansible playbook belongs to the [ansible-nfv](https://github.com/redhat-openstack/ansible-nfv) repository which contains different plays for various tasks on the OpenStack environment.  
For more information regarding tempest install, configuration and execution playbook, refer to the playbook [documentation](https://github.com/redhat-openstack/ansible-nfv/blob/master/docs/tripleo/tester/tempest.md).

### Configuration of the environment for tests execution

The nfv-tempest-plugin requires some pre-configuration steps in order to run the tests.  

**Note!** - Tempest-nfv-plugin uses external file that holds specific tests configuration. For the tests configuration refer to the tests doc file and sample tests config file.

In case of manual environment configuration, be aware of the following:
- Tets in nfv-tempest-plugin support nova microversions. By default the microversion is 2.1, this can be overriden by including the following parameters in tempest.conf and their values should be in the format "X.Y" or equal to 'latest'.
**Note!** - The nfv-tempest-plugin use the following min and max microversion - 2.32 in Queens release

  ```
  [compute]
  min_microversion = latest
  max_microversion = latest
  ```

  Refer to [OpenStack's official Nova documentation regarding microversions](https://docs.openstack.org/nova/latest/contributor/microversions.html)

  Refer to [OpenStack's official Nova documentation regarding API microversions](https://docs.openstack.org/nova/latest/reference/api-microversion-history.html)

- Tempest-nfv-plugin uses external tests configuration file.  
  The file should reside on the tester host and path of the file should be provided within the tempest.conf file under hypervisor section.
  ```
  [nfv_plugin_options]
  external_config_file = /root/tempest/tests_config.yml
  ```
  The file name is not restricted to a specific name.

- nfv-tempest-plugin can use a custom user_data during instance booting by supplying the file within tempest.conf under hyervisor group.
  The file should reside on the tester host and path of the file should be provided within the tempest.conf file under hypervisor section.
  ```
  [nfv_plugin_options]
  user_data = /path/to/user_data.yml
  ```
  The file name is not restricted to a specific name.

- Some of the tests will require to perform checks on the hypervisors.  
  For such case, specify the user and private key for the hypervisor ssh access under hypervisor section.
  ```
  [nfv_plugin_options]
  private_key_file = /home/stack/.ssh/id_rsa
  user = heat-admin
  ```

- Files can be transferred from tester node to guest instance using nova's personality API via metadata server.  
  Refer to [server personality documentation](https://developer.openstack.org/api-ref/compute/#servers-servers).  
  Specify a list of dictionaries in **string** with the corresponding values under nfv_plugin_options.
  NOTE: Personality is deprecated from compute microversion 2.57 and onwards and should be replaced by user_data.
  ```
  [nfv_plugin_options]
  transfer_files = '[{"client_source": "/path/to/source.txt", "guest_destination": "/path/to/dest.txt"}]'
  ```

- During instance creation, the plugin can verify all provider networks attached to guest.  
  The verification process includes:
  - Checking if guest interface are configured with layer3 settings
  - If multiple servers are created, tests ICMP traffic across all provider networks

  The verification procedure requires guests instances to have a floating ip attached to them.  
  In order to enable the verification, configure the following attribute under nfv_plugin_options section in tempest:

  **Note:** This may significantly increase test duration.
  ```
  [nfv_plugin_options]
  test_all_provider_networks = true
  ```

- Live migration test requires explicit parameter enabled within the tempest.conf file.
  ```
  [compute-feature-enabled]
  live_migration = true
  ```

- Config drive allows to access Nova's metadata server via CD-ROM device instead of via network connectivity. By Default is True.  
  Refer to [config drive documentation](https://docs.openstack.org/nova/queens/user/config-drive.html)  
  To disable the use of config_drive, set the parameter to false
  ```
  [compute-feature-enabled]
  config_drive = false
  ```

- **Note 1** - Tempest require a predefined (public api) network that will be used as an access point for the tests execution.  
All other networks used by the test will be created during the test execution.

- **Note 2** - Running test will take the flavor name within the test configuration.  
The test will look for the exist flavor.  
In case the flavor exists, the test will use it.  
Otherwise the test will create a flavor based on the parameters defined at the test-flavors within the tests-config.yml.

- **Note 3** - In order to utilize Trusted VF in this plugin, custom Neutron API Policies must be set for 'create_port:binding:profile' and 'get_port:binding:profile'.

In order to minimize the pre-configuration effort, there is an automation for the environment preparation, which uses dedicated tempest ansible playbook that will install, configure and execute the tests on selected environment.
Tempest ansible playbook belongs to the [ansible-nfv](https://github.com/redhat-openstack/ansible-nfv) repository which contains different plays for various tasks on the OpenStack environment.  
For more information regarding tempest install, configuration and execution playbook, refer to the playbook [documentation](https://github.com/redhat-openstack/ansible-nfv/blob/master/docs/tripleo/tester/tempest.md).

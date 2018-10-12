### Configuration of the environment for tests execution

The nfv-tempest-plugin requires some pre-configuration steps in order to run the tests.  

**Note!** - Tempest-nfv-plugin uses external file that holds specific tests configuration. For the tests configuration refer to the tests doc file and sample tests config file.

In case of manual environment configuration, be aware of the following:
- Tets in nfv-tempest-plugin support nova microversions. By default the microversion is 2.1, this can be overriden by including the following parameters in tempest.conf and their values should be in the format "X.Y" or equal to 'latest'.
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
  [hypervisor]
  external_config_file = /root/tempest/tests_config.yml
  ```
  The file name is not restricted to a specific name.

- nfv-tempest-plugin can use a custom user_data during instance booting by supplying the file within tempest.conf under hyervisor group.
  The file should reside on the tester host and path of the file should be provided within the tempest.conf file under hypervisor section.
  ```
  [hypervisor]
  user_data = /path/to/user_data.yml
  ```
  The file name is not restricted to a specific name.

- Some of the tests will require to perform checks on the hypervisors.  
  For such case, specify the user and private key for the hypervisor ssh access under hypervisor section.
  ```
  [hypervisor]
  private_key_file = /home/stack/.ssh/id_rsa
  user = heat-admin
  ```

- Live migration test requires explicit parameter enabled within the tempest.conf file.
  ```
  [compute-feature-enabled]
  live_migration = true
  ```

- **Note 1** - Tempest require a predefined (public api) network that will be used as an access point for the tests execution.  
All other networks used by the test will be created during the test execution.

- **Note 2** - Running test will take the flavor name within the test configuration.  
The test will look for the exist flavor.  
In case the flavor exists, the test will use it.  
Otherwise the test will create a flavor based on the parameters defined at the test-flavors within the tests-config.yml.

In order to minimize the pre-configuration effort, there is an automation for the environment preparation, which uses dedicated tempest ansible playbook that will install, configure and execute the tests on selected environment.
Tempest ansible playbook belongs to the [ansible-nfv](https://github.com/redhat-openstack/ansible-nfv) repository which contains different plays for various tasks on the OpenStack environment.  
For more information regarding tempest install, configuration and execution playbook, refer to the playbook [documentation](https://github.com/redhat-openstack/ansible-nfv/blob/master/docs/tripleo/tester/tempest.md).

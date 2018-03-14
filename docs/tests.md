### Tests of the nfv-tempest-plugin

The detailed explanation of the tests and tests configuration.

Current supported tests:
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_numa0_provider_network
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_numa1_provider_network
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_numamix_provider_network
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_packages_compute
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_mtu_ping_test
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_min_queues_functionality
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_equal_queues_functionality
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_max_queues_functionality
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_odd_queues_functionality
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_live_migration_block
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_multicast

### Tests configuration
The nfv-tempest-plugin uses external configuration file in order to provide the proper configuration of the test execution to the tempest.  
For the details explanation of the file location and configuration, refer to the tests_prerequisites_config doc file.

Following explanation will cover the content of the external configuration file.  
For the full version of the external configuration file sample, refer to the sample file at the docs directory.

### Tests:
----------
#### TestBasicEpa:  
Tests included:
- test_numa0_provider_network
- test_numa1_provider_network
- test_numamix_provider_network  
  Test explanation:  
  Numa tests are testing the proper allocation and reservation of the virtual cores within numa nodes of the compute hypervisor according to the provided flavor with numa config specs.  

  ```
  Test config:
  - name: numa0
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true

  - name: numa1
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-1
    router: true

  - name: numamix
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-mix
    router: true
  ```

  flavor - specifies the flavor that the instance should boot with.  
  router - Sets if the booted instance will get floating ip or direct access config.

- test_packages_compute  
  Test explanation:  
  Package test:
    - Checks if package exists on hypervisor.
    - If provided - checks the active state of the service.
    - If provided - checks the active state of the tuned profile.

  ```
  Test config:
  - name: check-compute-packages
    package-names: tuned-2.8.0-5.el7.noarch
    service-names: tuned.service
    tuned-profile: cpu-partitioning
    availability-zone: normal
  ```

- test_mtu_ping_test  
  Test explanation:  
  The MTU test boots an instance with given args from external_config_file, connect to the instance using ssh, and ping with given MTU to GW.  
  **Note 1** - This tests depend on MTU configured at running environment.  

  ```
  Test config:  
  - name: test-ping-mtu
    flavor: nfv-test-flavor
    router: false
    mtu: 2972
    availability-zone: normal
  ```

  flavor - specifies the flavor that the instance should boot with.  
  router - Sets if the booted instance will get floating ip or direct access config.  
  mtu - Specify the required mtu for the test. The calculation of testing mtu should be based on the deployed mtu size.  
  availability-zone - Sets the zone in which the hypervisor exists (Parameter not required).

----------
#### TestDpdkScenarios:  
Tests included:
- test_min_queues_functionality
- test_equal_queues_functionality
- test_max_queues_functionality
- test_odd_queues_functionality  
- multicast  
  Test explanation:  
  Test multi-queue functionality.  
  Calculates the number of queues multiply by the number of PMDs.  
  Boot instances with different amount of vCpus: bigger, smaller, equal and odd.  

  ```
  Test config:  
  - name: check-multiqueue-func
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
  ```

- test_setup_migration  
  Test explanation:  
  The test boot an instance, checks availability and migrates the instance to the next available hypervisor.  

  ```
  Test config:  
  - name: test_setup_migration
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
  ```

- multicast
  Test explanation:
  The test boot three instances and send from one instance multicast traffic to other instances.

  ```
  - name: multicast
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
  ```

**Note** - Running test will take the flavor name within the test configuration.  
The test will look for the exist flavor.  
In case the flavor exists, the test will use it.  
Otherwise the test will create a flavor based on the parameters defined at the test-flavors within the tests-config.yml.

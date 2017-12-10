### Tests of the tempest-nfv-plugin

The detailed explanation of the tests and tests configuration.

Current supported tests:
- tests.scenario.test_nfv_epa.TestBasicEpa.test_numa0_provider_network
- tests.scenario.test_nfv_epa.TestBasicEpa.test_numa1_provider_network
- tests.scenario.test_nfv_epa.TestBasicEpa.test_numamix_provider_network
- tests.scenario.test_nfv_epa.TestBasicEpa.test_packages_compute
- tests.scenario.test_nfv_epa.TestBasicEpa.test_mtu_ping_test
- tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_min_queues_functionality
- tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_equal_queues_functionality
- tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_max_queues_functionality
- tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_odd_queues_functionality
- tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_live_migration_block

### Tests configuration
Tempest-nfv-plugin uses external configuration file in order to provide the proper configuration of the test execution to the tempest.  
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
  **Note** - Predefined flavor should be exists. Refer to the sample file.

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
  - name: check-compute-packges
    package-names: tuned-2.8.0-5.el7.noarch
    service-names: tuned.service
    tuned-profile: cpu-partitioning
    availability-zone: normal
  ```

- test_mtu_ping_test  
  Test explanation:  
  The MTU test boots an instance with given args from external_config_file, connect to the instance using ssh, and ping with given MTU to GW.  
  **Note 1** - This tests depend on MTU configured at running environment.  
  **Note 2** - Predefined flavor should be exists. Refer to the sample file.

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
  mtu - Specify the required mtu for the test.
  availability-zone - Sets the zone in which the hypervisor exists (Parameter not required).

----------
#### TestDpdkScenarios:  
Tests included:
- test_min_queues_functionality
- test_equal_queues_functionality
- test_max_queues_functionality
- test_odd_queues_functionality  
  Test explanation:  
  Test multi-queue functionality.  
  Calculates the number of queues multiply by the number of PMDs.  
  Boot instances with different amount of vCpus: bigger, smaller, equal and odd.  
  **Note** - Predefined flavor is not required.  

  ```
  Test config:  
  - name: check-multiqueue-func
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
  ```

- test_setup_migration  
  Test explanation:  
  The test boot an instance, checks availability and migrates the instance to the next available hypervisor.  
  **Note** - Predefined flavor should be exists. Refer to the sample file.

  ```
  Test config:  
  - name: test_setup_migration
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
  ```

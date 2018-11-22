### Tests of the nfv-tempest-plugin

The detailed explanation of the tests and tests configuration.

Current supported tests:
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_numa0_provider_network
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_numa1_provider_network
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_numamix_provider_network
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_packages_compute
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_mtu_ping_test
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_cold_migration
<<<<<<< HEAD
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_emulatorpin
||||||| merged common ancestors
=======
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_rx_tx
>>>>>>> Create RX/TX test
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
- test_cold_migration
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

  - name: cold-migration
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
    package-names:
      - tuned-2.8.0-5.el7.noarch
      - openvswitch-2.6.1-16.git20161206.el7ost.x86_64
    service-names:
      - tuned
      - openvswitch
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

- test_emulatorpin  
  Test explanation:  
  The test boots instances, takes the emulatorpin value from the dumpxml of the running instance and compares
  it to the emulatorpin values from the overcloud nova configuration.  
  **Note** - The test suit only for RHOS version 14 and up, since the emulatorpin feature was implemented only in version 14.
  **Note** - The following extra spec should be added to the flavor on this test execution - "hw:emulator_threads_policy": "share"
  
  ```
  Test config:
  - name: emulatorpin
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
    emulatorpin_config:
      - config_path: '/var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf'
        check_section: 'compute'
        check_value: 'cpu_shared_set'
  ```

- rx_tx
  Test explanation:
  The test boots instances, takes the rx/tx value from the dumpxml of the running instance and compares
  it to the rx/tx values from the overcloud nova configuration.  
  **Note** - The test suit only for RHOS version 14 and up, since the rx/tx feature was implemented only in version 14.

  ```
  Test config:
  - name: rx_tx
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
    rx_tx_config:
      - config_path: '/var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf'
        check_section: 'libvirt'
        check_value: 'rx_queue_size,tx_queue_size'
  ```

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

  ```
  Test config:  
  - name: check-multiqueue-func
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
  ```

- test_live_migration_basic  
  Test explanation:  
  The test boot an instance, checks availability and migrates the instance to the next available hypervisor.  

  ```
  Test config:  
  - name: test_live_migration_basic
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

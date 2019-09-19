### Tests of the nfv-tempest-plugin

The detailed explanation of the tests and tests configuration.

Current supported tests:
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_numa0_provider_network
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_numa1_provider_network
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_numamix_provider_network
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_packages_compute
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_mtu_ping_test
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_cold_migration
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_emulatorpin
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_min_queues_functionality
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_equal_queues_functionality
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_max_queues_functionality
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_odd_queues_functionality
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_live_migration_block
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_multicast
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_rx_tx
- nfv_tempest_plugin.tests.scenario.test_nfv_sriov_usecases.TestSriovScenarios.test_sriov_trusted_vfs
- nfv_tempest_plugin.tests.scenario.test_nfv_advanced_usecases.TestAdvancedScenarios.test_numa_aware_vswitch
- nfv_tempest_plugin.tests.scenario.test_nfv_lacp_usecases.TestLacpScenarios.test_deployment_lacp
- nfv_tempest_plugin.tests.scenario.test_nfv_lacp_usecases.TestLacpScenarios.test_balance_tcp
- nfv_tempest_plugin.tests.scenario.test_nfv_lacp_usecases.TestLacpScenarios.test_restart_ovs


### Tests configuration
The nfv-tempest-plugin uses external configuration file in order to provide the proper configuration of the test execution to the tempest.  
For the details explanation of the file location and configuration, refer to the tests_prerequisites_config doc file.

Following explanation will cover the content of the external configuration file.  
For the full version of the external configuration file sample, refer to the sample file at the docs directory.

### Common test configs
-----------------------
All the tests share some common configuration. Some of them are mandatory and some are optional.
``` 
flavor: name
```
- The name of the flavor that the test should use.
```
router: true
```
- Boolean var. Specify if the instance will get floating ip or direct SSH access.
```
aggregate:
   hosts:
     - computeovsdpdksriov-0
   metadata: test=numa_aware_vswitch
```
- Aggregate config:  
  Specify the hosts that should be attached to the aggregate.  
  Specify the metadata flag that should be set on the aggregate.  
  **Note!** - The "AggregateInstanceExtraSpecsFilter" is required for aggregate use.  
  **Note!** - The metadata specified for the aggregate should be added as the extra specs to the flavor. 

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
  ```

  flavor - specifies the flavor that the instance should boot with.  
  router - Sets if the booted instance will get floating ip or direct access config.  
  mtu - Specify the required mtu for the test. The calculation of testing mtu should be based on the deployed mtu size.  

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
#### TestSriovScenarios:  
Tests included:
- test_sriov_trusted_vfs
  Test explanation:  
  Test Trusted Virtual Function capabilities
  This test tells neutron to create SR-IOV ports in trusted mode which unlock additional capabilities
  **Note** This test requires nova to allow creation of trusted VFs, refer to [upstream documentation](https://docs.openstack.org/neutron/rocky/admin/config-sriov#whitelist-pci-devices-nova-compute-compute)
  **Note** By default Trusted VF requires admininstrative user, this test relies on custom Neutron API policies which allows non-administrative users to perform these actions (**TODO: Add Neutron API policies reference after agreeing on an internal solution**)

  ```
  Test config:  
  - name: trustedvfs
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
  ```

**Note** - Running test will take the flavor name within the test configuration.  
The test will look for the exist flavor.  
In case the flavor exists, the test will use it.  
Otherwise the test will create a flavor based on the parameters defined at the test-flavors within the tests-config.yml.

----------
#### TestAdvancedScenarios:
Tests included:
- test_numa_aware_vswitch
  Test explanation:  
  Test Numa aware vswitch feature.  
  The feature allows to boot an instance in the selected numa node according to the config during the deployment.
  
  Prerequisites for the test:  
  Overcloud feature configuration for the deployment.  
  For more information, refer to the [feature spec doc](https://specs.openstack.org/openstack/nova-specs/specs/rocky/implemented/numa-aware-vswitches.html).
  
  ```
  - name: numa_aware_vswitch
    flavor: numa_aware_vswitch
    router: true
    aggregate:
      hosts:
        - computeovsdpdksriov-0
      metadata: test=numa_aware_vswitch
  ```

**Note** - The test config require to use the aggregate during the test.  
Definition of the aggregate should be in the test config **and** the flavor, as aggregate feature works.

**Note** - The test suit only for OSP Rocky version and above, since the numa aware vswitch feature was implemented only in OSP Stein version and backported to OSP Rocky.

----------
#### TestLacpScenarios
Tests included:
- test_deployment_lacp

  Test explanation:
  Test that balance-tcp and lacp is properly configured after deployment. Following values are checked:
  * bond_name: There must be a bonding configured
  * bond_mode: It must be set to balance-tcp
  * lacp_status: It must be set to negotiated which indicates that the switch is properly configured too
  * lacp_time: It must be set to fast (lacp messages sent very frecuently)
  * lacp_fallback_ab: It must be set to true (change to active-backup if no lacp messages)

  Test config:
  - name: deployment_lacp
    bonding_config:
      - bond_name: 'dpdkbond1'
        bond_mode: 'balance-tcp'
        lacp_status: 'negotiated'
        lacp_time: 'fast'
        lacp_fallback_ab: 'true'

- test_balance_tcp

  Test explanation:
  Check that ovs is balancing properly the traffic when balance-tcp is configured. 
  - 1 flow: all the traffic through the same interface in the bonding, the other one is not used
  - 2 flows: half of the traffic in each interface
  - 3 flows: 33% in one interface and 66% in the other interface
 
  Test config:
  - name: balance_tcp
    flavor: m1.medium.huge_pages_cpu_pinning_numa_node-0
    router: true
    package-names:
      - iperf
    bonding_config:
      - bond_name: 'dpdkbond1'
        ports: [ 'dpdk2', 'dpdk3']

- test_restart_ovs

  Test explanation:
  Check that lacp configuration is not lost after ovs restart. 
  Restart ovs and then execute test_deployment_lacp 

  Test config:
  - name: restart_ovs

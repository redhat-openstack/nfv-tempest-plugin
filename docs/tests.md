## Tests of the nfv-tempest-plugin

### TestNfvBasic
- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_hypervisor_tuning

    Test tuning state of hypervisor.  
    Test the following states:  
    - Packages (given in config)  
    - Active services (given in config)  
    - Tuned active profile (given in config)  
    - Kernel arguments (given in config)

- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_mtu_ping_test

    Test MTU by pinging instance gateway.  
    The test boots and instance, connects to the instance by ssh and  
    pings the network gateway address with the appropriate MTU size.

    **Note** - The size of the mtu discovered automatically from the running  
    environment. The value may differ between deployments.  
    Custom mtu size could be provided wia the plugin defaults.

- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_cold_migration

    Test cold migration.  
    The test shuts down the instance, migrates it to a different hypervisor  
    and brings it up to verify resize state.

- nfv_tempest_plugin.tests.scenario.test_nfv_basic.TestNfvBasic.test_emulatorpin

    Test emulatorpin on the running instance vs nova configuration.  
    The test compares emulatorpin value from the dumpxml of the running  
    instance with values of the overcloud nova configuration.

    **Note** - The test suit only for RHOS version 14 and up, since the  
    emulatorpin feature was implemented only in version 14.

### TestDpdkScenarios
- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_multicast

    The method boots three instances, runs multicast traffic between them.  
    First instance serves as traffic runner and two other instances as listeners.  
    The traffic captured on both listeners and ensures it's received.

- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_min_queues_functionality

    Checks DPDK min queues functionality.  
    Calculates the number of queues multiply by the number of PMDs.  
    Boot instances with different amount of vCpus: bigger, smaller, equal and odd.  

- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_equal_queues_functionality

    Checks DPDK equal queues functionality.  
    Calculates the number of queues multiply by the number of PMDs.  
    Boot instances with different amount of vCpus: bigger, smaller, equal and odd.  

- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_max_queues_functionality

    Checks DPDK max queues functionality.  
    Calculates the number of queues multiply by the number of PMDs.  
    Boot instances with different amount of vCpus: bigger, smaller, equal and odd.  

- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_odd_queues_functionality

    Checks DPDK odd queues functionality.  
    Calculates the number of queues multiply by the number of PMDs.  
    Boot instances with different amount of vCpus: bigger, smaller, equal and odd.  

- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_rx_tx

    Test RX/TX on the instance vs nova configuration.  
    The test compares RX/TX value from the dumpxml of the running  
    instance with values of the overcloud nova configuration.

- nfv_tempest_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_dpdk_max_qos

    Test DPDK MAX QoS functionality.  
    The test deploys 3 instances and creates qos policy that applied to the instances.  
    One iperf server receives traffic from two iperf clients with max_qos parameter  
    defined run against iperf server.  
    The test searches for "traffic per second" and compares against ports settings.

    **Note** - The test require the following plugin parameter to be set in tempest.conf:  
    [nfv_plugin_options]  
    use_neutron_api_v2 = true  
    Neutron QoS settings should be applied during the overcloud deployment.

### TestSriovScenarios
- nfv_tempest_plugin.tests.scenario.test_nfv_sriov_usecases.TestSriovScenarios.test_sriov_trusted_vfs

    Verify trusted virtual functions.  
    This test tells neutron to create SR-IOV ports in trusted mode which unlock additional capabilities
    **Note** This test requires nova to allow creation of trusted VFs, refer to [upstream documentation](https://docs.openstack.org/neutron/rocky/admin/config-sriov#whitelist-pci-devices-nova-compute-compute)  
    **Note** By default Trusted VF requires admininstrative user, this test relies on custom Neutron API policies which allows non-administrative users to perform these actions.

- nfv_tempest_plugin.tests.scenario.test_nfv_sriov_usecases.TestSriovScenarios.test_sriov_double_tagging

    Test SRIOV double tagging functionality.  
    The double tagging feature allows the vm on the sriov port to use a permitted list of vlans.  
    This test runs scapy icmp and mpls traffic on the instances with vlan based virtual interfaces set within the instances.  
    Refer to the following links for more information:  
    https://bugs.launchpad.net/neutron/+bug/1693240  
    https://bugzilla.redhat.com/show_bug.cgi?id=1497887

    **Note** - The test requires resource creator to setup initial test resources.  
    **Note** - Both of the vlans should be allowed on the switch ports.

- nfv_tempest_plugin.tests.scenario.test_nfv_sriov_usecases.TestSriovScenarios.test_guests_with_min_bw

    Test Nova SRIOV min BW capabilities.  
    This test creates vm with port direct port set with min_qos policy.

    **Note** - Network capable Min Qos must be marked in test_network as min_qos=true/false.  
    **Note** - Train release test requires:
               - tempest microversion set to 2.72
               - nova parameter resource_provider_bandwidths

- nfv_tempest_plugin.tests.scenario.test_nfv_sriov_usecases.TestSriovScenarios.test_guests_set_min_qos

    Test Neutron SRIOV min QoS capabilities.
    This test tells neutron to create min_qos on sriov ports, provider.

    **Note** - Network capable Min Qos must be marked in test_network as min_qos=true/false.

- nfv_tempest_plugin.tests.scenario.test_nfv_sriov_usecases.TestSriovScenarios.test_sriov_free_resource

    Test_sriov_free_resources.  
    Instance with SRIOV ports spawned and deleted.  
    The test checks if sriov nics are released after guest/port deletion.  
    Verification is run before test starts and at the end.

- nfv_tempest_plugin.tests.scenario.test_nfv_sriov_usecases.TestSriovScenarios.test_sriov_max_qos

    Test SRIOV MAX QoS functionality.  
    The test performs max qos testing by using iperf tool.  
    The test deploys 3 vms. one iperf server receive traffic from  
    two iperf clients, with max_qos defined run against iperf server.  
    The test searches for Traffic per second and compare against ports settings.

    **Note** - Test requires configuration in tempest.conf to be set.  
    [nfv_plugin_options]  
    use_neutron_api_v2 = true

    Provided with the vf network details:  
    min_qos: true

- nfv_tempest_plugin.tests.scenario.test_nfv_sriov_usecases.TestSriovScenarios.test_sriov_min_qos

    Test SRIOV MIN QoS functionality.  
    **Note** - SUPPORTED: Mellanox NICS only.  
    **Note** - Test also requires QoS neutron settings.

    The test deploys 3 vms. one iperf server receive traffic from two iperf clients,  
    with min_qos defined run against iperf server.  
    The test search for Traffic per second and compare against ports seeings.

    **Note** - Test requires configuration in tempest.conf to be set.  
    [nfv_plugin_options]  
    use_neutron_api_v2 = true

### TestAdvancedScenarios
- nfv_tempest_plugin.tests.scenario.test_nfv_advanced_usecases.TestAdvancedScenarios.test_numa_aware_vswitch

    The test will verify the "Numa aware vswitch" feature by the following steps:
    - Fill up the appropriate numa node by booting the instances using the "numa aware net".
    - Try to boot another instance using the "numa aware net" and verify that it fails.
    - Verify the instances placement in appropriate numa node.
    - Boot another instance using the "non numa aware net".
    - Ensure the instance boots successfully.
    - Live migrate the numa aware net instance to another hypervisor and verify migration.

    In case, "non numa aware" network does not exist, skip that step in the test.

    **Note** - Prerequisites for the test:  
    Overcloud feature configuration for the deployment.  
    For more information, refer to the [feature spec doc](https://specs.openstack.org/openstack/nova-specs/specs/rocky/implemented/numa-aware-vswitches.html).

- nfv_tempest_plugin.tests.scenario.test_nfv_advanced_usecases.TestAdvancedScenarios.test_pinned_srv_live_migration

    Test live migration of pinned instances.  
    The test performs the following actions:  
    - Boot the cpu pinned instance on the first hypervisor
    - Live migrate the cpu pinned instance to the second hypervisor. Expect live migration to success.
    - Boot seconds pinned instance on the first hypervisor
    - Live migrate the first instance back to the first hypervisor
    - Verify by the virsh xml that the first vm was rescheduled on the cpu.

- nfv_tempest_plugin.tests.scenario.test_nfv_advanced_usecases.TestAdvancedScenarios.test_pinned_and_non_pinned_srv

    Test pinned and non pinned instances on the same compute.  
    The test performs the following actions:
    - Boot pinned instance (using specific flavor)
    - Boot non pinned instance (using specific flavor) on the same host
    - Ensure the instances booted on the same hypervisor
    - Takes the allocated cpu for the intstances
    - Takes the dedicated and shared cpu set from hypervisor
    - Compares between them to ensure that instances uses proper cpu

### TestLacpScenarios
- nfv_tempest_plugin.tests.scenario.test_nfv_lacp_usecases.TestLacpScenarios.test_deployment_lacp

    Check that lacp bonding is properly configured.  
    The test uses the following configuration options example set in the plugin defaults:
    ```
    bond_mode: 'balance-tcp'
    lacp_status: 'negotiated'
    lacp_time: 'fast'
    lacp_fallback_ab: 'true'
    ```

    The "bond_name" is auto discovered.

    **Note** - Switch lacp configuration must be set for the deployment and test.

- nfv_tempest_plugin.tests.scenario.test_nfv_lacp_usecases.TestLacpScenarios.test_balance_tcp

    Test balance-tcp traffic distribution.  
    The test boots two instances connected through a balance_tcp bond,  
    runs traffic between them and checks that traffic goes through the right interface.
    - 1 flow: all the traffic through the same interface, the other one is not used
    - 2 flows: 50% of the traffic in each interface
    - 3 flows: 66% in one interface, 33% in the other one

    **Note** - The test uses "bond name" and "bond ports" as parameters.  
               These options discovered automatically.

- nfv_tempest_plugin.tests.scenario.test_nfv_lacp_usecases.TestLacpScenarios.test_restart_ovs

    Test restart_ovs.  
    Checks that config is loaded properly after reboot.

### TestIgmpSnoopingScenarios
- nfv_tempest_plugin.tests.scenario.test_igmp_snooping_usecases.TestIgmpSnoopingScenarios.test_igmp_snooping_deployment

    Test that igmp snooping is configured properly in each br-int switch for each compute.  
    mcast_snooping_enable and mcast-snooping-disable-flood-unregistered must be enabled.

- nfv_tempest_plugin.tests.scenario.test_igmp_snooping_usecases.TestIgmpSnoopingScenarios.test_igmp_snooping

    Test igmp snooping.  
    Having 2 hypervisors and 3 vms in each hypervisor.  
    We configure a vm in each hypervisor to send a traffic to a different group.  
    We configure a different message for each group and different number of packets to be sent.  
    Then we configure 2 vms in each hypervisor subscribed to each group.  
    It is checking the following:
    - vms are properly subscribed
    - traffic in each interface in br-int
    - messages received in each vm and number of packets received

- nfv_tempest_plugin.tests.scenario.test_igmp_snooping_usecases.TestIgmpSnoopingScenarios.test_igmp_restart_ovs

    Test restart ovs.  
    Checks that multicast configuration is not lost after ovs restart.  
    Restart ovs and then execute test_igmp_snooping_deployment.

- nfv_tempest_plugin.tests.scenario.test_igmp_snooping_usecases.TestIgmpSnoopingScenarios.test_check_igmp_queries

    Test checks igmp queries arriving to the vms.  
    Check IGMP queries generated by a external switch arrives to the vms.  
    Tests https://bugzilla.redhat.com/show_bug.cgi?id=1933990

    Test checks if igmp queries generated by a external switch arrive to the vms.  
    At the time of creating this testcase, there is a bug and it does not arrive unless flooding is enabled.  
    https://bugzilla.redhat.com/show_bug.cgi?id=1933990  
    As a prerequisite, there must be a igmp querier configured in the switch.  
    It must be configured how long the testcase will wait to receive a message (tcpdump_timeout).  
    In a juniper switch, if it is not configured, default value is 180 seconds, so,  
    the default value for the testcase will be 200 to ensure that at least one packet is received.

- nfv_tempest_plugin.tests.scenario.test_igmp_snooping_usecases.TestIgmpSnoopingScenarios.test_check_igmp_reports

    Test checks that igmp reports generated a vm are able to arrive to a external switch.  
    Traffic will be captured in the ovs bridge in which it is connected  
    the nic connected to the external switch.  
    At the time of creating this testcase, there is a bug and messages will not  
    arrive unless flooding is enabled.  
    https://bugzilla.redhat.com/show_bug.cgi?id=1933734  
    It must configured the interface in which tcpdump will be executed in order to check if packets are arriving.

- nfv_tempest_plugin.tests.scenario.test_igmp_snooping_usecases.TestIgmpSnoopingScenarios.test_multicast_functionality

    Common test to test most of the igmp snooping scenarios.  
    Functionality:
    - create multicast traffic runners
    - create multicast listeners
    - check multicast group creation
    - calculate traffic in ech interface
    - check received traffic in each listener

### TestNfvOffload
- nfv_tempest_plugin.tests.scenario.test_nfv_offload.TestNfvOffload.test_offload_ovs_config

    Test checks ovs config for offload on all hypervisors.

- nfv_tempest_plugin.tests.scenario.test_nfv_offload.TestNfvOffload.test_offload_nic_eswitch_mode

    Check eswitch mode of nic for offload on all hypervisors.  

    **Note** - By default, offload nics are auto discovered.  
               But if the used would like to not perform the autodiscover and  
               provide the nics, it could be done by modifying the  
               CONF.nfv_plugin_options.offload_nics param in deployer-input file.

- nfv_tempest_plugin.tests.scenario.test_nfv_offload.TestNfvOffload.test_offload_ovs_flows

    Test checks OVS offloaded flows.  
    The following test deploy vms, on hw-offload computes.  
    It sends async ping and check offload flows exist in ovs.

### TestLiveMigrationScenarios
- nfv_tempest_plugin.tests.scenario.test_nfv_live_migration_usecases.TestLiveMigrationScenarios.test_live_migration_block

    The test boot an instance, checks availability  
    and migrates the instance and block storage to the next available hypervisor.

    **Note** - Make sure CONF.compute_feature_enabled.live_migration is True

- nfv_tempest_plugin.tests.scenario.test_nfv_live_migration_usecases.TestLiveMigrationScenarios.test_live_migration_shared

    The test boot an instance, checks availability  
    and migrates the instance using shared storage to the next available hypervisor.

    **Note** - Make sure CONF.compute_feature_enabled.live_migration is True

### TestHciScenarios
- nfv_tempest_plugin.tests.scenario.test_nfv_hci_usecases.TestHciScenarios.test_volume_in_hci_nfv_setup

    The HCI test boots an instance, attaches new volume with this instance,  
    connects to the instance using ssh, and writes the full disk.

- nfv_tempest_plugin.tests.scenario.test_nfv_hci_usecases.TestHciScenarios.test_boot_instance_with_volume_in_hci_nfv_setup

    The HCI test boots an instance with the volume,  
    connects to the instance using ssh, and writes the full disk.

- nfv_tempest_plugin.tests.scenario.test_nfv_hci_usecases.TestHciScenarios.test_volume_using_img_in_hci_nfv_setup

    The HCI test boots an instance,  
    attaches new volume which is created using image with this instance,  
    connects to the instance using ssh, and writes the full disk.

- nfv_tempest_plugin.tests.scenario.test_nfv_hci_usecases.TestHciScenarios.test_ceph_health_status_in_hci_nfv_setup

    The HCI test checks the ceph health status.

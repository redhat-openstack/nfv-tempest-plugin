Tempest integration tests for NFV based deployment
==================================================

The tempest-nfv-plugin contains various tempest tests for NFV based deployment.

### Documantation
For the proper documentation including installation, tests explanation and configuration, etc... refer to the `docs/` directory at the root of the repository.

Current available tests:
- tempest_nfv_plugintests.scenario.test_nfv_basic.TestNfvBasic.test_numa0_provider_network
- tempest_nfv_plugintests.scenario.test_nfv_basic.TestNfvBasic.test_numa1_provider_network
- tempest_nfv_plugintests.scenario.test_nfv_basic.TestNfvBasic.test_numamix_provider_network
- tempest_nfv_plugintests.scenario.test_nfv_basic.TestNfvBasic.test_packages_compute
- tempest_nfv_plugintests.scenario.test_nfv_basic.TestNfvBasic.test_mtu_ping_test
- tempest_nfv_plugintests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_min_queues_functionality
- tempest_nfv_plugintests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_equal_queues_functionality
- tempest_nfv_plugintests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_max_queues_functionality
- tempest_nfv_plugintests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_odd_queues_functionality
- tempest_nfv_plugintests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_live_migration_block
- tempest_nfv_plugin.tests.scenario.test_nfv_dpdk_usecases.TestDpdkScenarios.test_multicast

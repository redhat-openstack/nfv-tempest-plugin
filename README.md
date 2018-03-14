Tempest integration tests for NFV based deployment
==================================================

The tempest-nfv-plugin contains various tempest tests for NFV based deployment.

### Documantation
For the proper documentation including installation, tests explanation and configuration, etc... refer to the `docs/` directory at the root of the repository.

Current available tests:
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

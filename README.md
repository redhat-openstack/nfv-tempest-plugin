Tempest integration tests for NFV based deployment
==================================================

The tempest-nfv-plugin contains various tempest tests for NFV based deployment.

### Documantation
For the proper documentation including installation, tests explanation and configuration, etc... refer to the `docs/` directory at the root of the repository.

Current available tests:
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

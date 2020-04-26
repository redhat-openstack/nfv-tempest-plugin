# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest.common import waiters
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestNfvBasic(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestNfvBasic, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(TestNfvBasic, self).setUp()
        # pre setup creations and checks read from config files

    def _test_check_package_version(self, test_compute):
        """Check provided packages, service and tuned profile on the compute

        - If given - checks if packages are exist on hypervisor
        - If given - checks if the services are at active state
        - If given - checks the active state of the tuned-profile
        * The test demands test_compute list

        :param test_compute
        """
        self.assertTrue(self.test_setup_dict[test_compute],
                        "test requires check-compute-packages "
                        "list in external_config_file")
        hyper_kwargs = {'shell': '/home/stack/stackrc'}
        self.hypervisor_ip = self._get_hypervisor_ip_from_undercloud(
            **hyper_kwargs)[0]
        self.assertNotEmpty(self.hypervisor_ip,
                            "_get_hypervisor_ip_from_undercloud "
                            "returned empty ip list")
        test_result = []
        if 'package-names' in self.test_setup_dict[test_compute]:
            packages = self.test_setup_dict[test_compute]['package-names']
            if packages is not None:
                for package in packages:
                    cmd = "rpm -qa | grep {0}".format(package)
                    result = shell_utils.\
                        run_command_over_ssh(self.hypervisor_ip,
                                             cmd).split()
                    if result:
                        test_result += result

        LOG.info("Found the following packages: %s" % '\n'.join(test_result))
        del test_result[:]

        if 'service-names' in self.test_setup_dict[test_compute]:
            services = self.test_setup_dict[test_compute]['service-names']
            if services is not None:
                for service in services:
                    cmd = "systemctl is-active {0}".format(service)
                    result = shell_utils.\
                        run_command_over_ssh(self.hypervisor_ip,
                                             cmd).strip('\n')
                    if result != 'active':
                        test_result.append("The {0} service is not Active"
                                           .format(service))

        if 'tuned-profile' in self.test_setup_dict[test_compute]:
            tuned = self.test_setup_dict[test_compute]['tuned-profile']
            if tuned is not None:
                cmd = "sudo tuned-adm active | awk '{print $4}'"
                result = shell_utils.run_command_over_ssh(
                    self.hypervisor_ip, cmd).strip('\n')
                if result != tuned:
                    test_result.append("Tuned {0} profile is not Active"
                                       .format(tuned))

        kernel_args = ['nohz', 'nohz_full', 'rcu_nocbs', 'intel_pstate']
        check_grub_cmd = "sudo cat /proc/cmdline"
        result = shell_utils.\
            run_command_over_ssh(self.hypervisor_ip, check_grub_cmd)
        for arg in kernel_args:
            if arg not in result:
                test_result.append("Tuned not set in grub. Need to reboot?")

        test_result = '\n'.join(test_result)
        self.assertEmpty(test_result, test_result)

    def test_mtu_ping_test(self, test='test-ping-mtu', mtu=1973):
        """Test MTU by pinging instance gateway

        The test boots an instance with given args from external_config_file,
        connect to the instance using ssh, and ping with given MTU to GW.
        * This tests depend on MTU configured at running environment.

        :param test: Test name from the config file
        :param mtu: Size of the mtu to check
        """
        # TODO(skramaja): Need to check if it is possible to execute ping
        #                 inside the guest VM using network namespace
        self.assertTrue(self.fip, "Floating IP is required for mtu test")

        servers, key_pair = self.create_and_verify_resources(test=test)

        if 'mtu' in self.test_setup_dict[test]:
            mtu = self.test_setup_dict[test]['mtu']
            LOG.info('Set {} mtu for the test'.format(mtu))

        routers = self.os_admin.routers_client.list_routers()['routers']
        for router in routers:
            if router['external_gateway_info'] is not None:
                gateway = router['external_gateway_info'][
                    'external_fixed_ips'][0]['ip_address']
                break
        else:
            raise ValueError('The gateway of given network does not exists. '
                             'Please assign it and re-run.')

        ssh_source = self.get_remote_client(servers[0]['fip'],
                                            username=self.instance_user,
                                            private_key=key_pair[
                                                'private_key'])
        LOG.info('Execute ping test command')
        out = ssh_source.exec_command('ping -c 1 -M do -s %d %s' % (mtu,
                                                                    gateway))
        msg = "MTU Ping test failed - check your environment settings"
        self.assertTrue(out, msg)
        LOG.info('The {} test passed.'.format(test))

    def test_numa0_provider_network(self, test='numa0'):
        """Verify numa configuration on instance

        The test instance allocation on the selected numa cell.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = shell_utils.\
            run_command_over_ssh(servers[0]['hypervisor_ip'],
                                 command)
        self.assertTrue(int(result[0]) == 2)
        LOG.info('Check instance vcpu')
        self.match_vcpu_to_numa_node(servers[0], servers[0]['hypervisor_ip'],
                                     test[4:])
        LOG.info('The {} test passed.'.format(test))

    def test_numa1_provider_network(self, test='numa1'):
        """Verify numa configuration on instance

        The test instance allocation on the selected numa cell.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = shell_utils.\
            run_command_over_ssh(servers[0]['hypervisor_ip'],
                                 command)
        self.assertTrue(int(result[0]) == 2)
        LOG.info('Check instance vcpu')
        self.match_vcpu_to_numa_node(servers[0], servers[0]['hypervisor_ip'],
                                     test[4:])
        LOG.info('The {} test passed.'.format(test))

    def test_numamix_provider_network(self, test='numamix'):
        """Verify numa configuration on instance

        The test instance allocation on the selected numa cell.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = shell_utils.\
            run_command_over_ssh(servers[0]['hypervisor_ip'],
                                 command)
        self.assertTrue(int(result[0]) == 2)
        LOG.info('Check instance vcpu')
        self.match_vcpu_to_numa_node(servers[0], servers[0]['hypervisor_ip'],
                                     test[4:])
        LOG.info('The {} test passed.'.format(test))

    def test_packages_compute(self):
        self._test_check_package_version("check-compute-packages")

    def test_cold_migration(self, test='cold-migration'):
        """Test cold migration

        The test shuts down the instance, migrates it and brings it up to
        verify resize.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)

        LOG.info('Starting the cold migration.')
        self.os_admin.servers_client. \
            migrate_server(server_id=servers[0]['id'])
        waiters.wait_for_server_status(self.servers_client,
                                       servers[0]['id'], 'VERIFY_RESIZE')
        LOG.info('Confirm instance resize after the cold migration.')
        self.servers_client.confirm_resize_server(server_id=servers[0]['id'])
        LOG.info('Verify instance connectivity after the cold migration.')
        self.check_instance_connectivity(ip_addr=servers[0]['fip'],
                                         user=self.instance_user,
                                         key_pair=key_pair['private_key'])
        succeed = True

        msg = "Cold migration test id failing. Check your environment settings"
        self.assertTrue(succeed, msg)
        LOG.info('The cold migration test passed.')

    def test_emulatorpin(self, test='emulatorpin'):
        """Test emulatorpin on the instance vs nova configuration

        The test compares emulatorpin value from the dumpxml of the running
        instance vs values of the overcloud nova configuration

        Note! - The test suit only for RHOS version 14 and up, since the
                emulatorpin feature was implemented only in version 14.
        """

        servers, key_pair = self.create_and_verify_resources(test=test)

        conf = self.test_setup_dict['emulatorpin']['config_dict'][0]
        config_path = conf['config_path']
        check_section = conf['check_section']
        check_value = conf['check_value']

        for srv in servers:
            LOG.info('Test emulatorpin for the {} instance'.format(srv['fip']))
            return_value = self. \
                compare_emulatorpin_to_overcloud_config(srv,
                                                        srv['hypervisor_ip'],
                                                        config_path,
                                                        check_section,
                                                        check_value)
            self.assertTrue(return_value, 'The emulatorpin test failed. '
                                          'The values of the instance and '
                                          'nova does not match.')
        LOG.info('The {} test passed.'.format(test))

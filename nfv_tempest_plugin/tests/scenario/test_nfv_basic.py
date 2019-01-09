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

from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest.common import waiters
from tempest import config

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestNfvBasic(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestNfvBasic, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None
        self.availability_zone = None

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
        if 'availability-zone' in self.test_setup_dict[test_compute]:
            hyper_kwargs = {'shell': '/home/stack/stackrc',
                            'aggregation_name': self.availability_zone}
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
                    result = self._run_command_over_ssh(self.hypervisor_ip,
                                                        cmd)
                    if result is '':
                        test_result.append("Package {0} is not found"
                                           .format(package))

        if 'service-names' in self.test_setup_dict[test_compute]:
            services = self.test_setup_dict[test_compute]['service-names']
            if services is not None:
                for service in services:
                    cmd = "systemctl is-active {0}".format(service)
                    result = self._run_command_over_ssh(
                        self.hypervisor_ip, cmd).strip('\n')
                    if result != 'active':
                        test_result.append("The {0} service is not Active"
                                           .format(service))

        if 'tuned-profile' in self.test_setup_dict[test_compute]:
            tuned = self.test_setup_dict[test_compute]['tuned-profile']
            if tuned is not None:
                cmd = "sudo tuned-adm active | awk '{print $4}'"
                result = self._run_command_over_ssh(
                    self.hypervisor_ip, cmd).strip('\n')
                if result != tuned:
                    test_result.append("Tuned {0} profile is not Active"
                                       .format(tuned))

        kernel_args = ['nohz', 'nohz_full', 'rcu_nocbs', 'intel_pstate']
        check_grub_cmd = "sudo cat /proc/cmdline"
        result = self._run_command_over_ssh(self.hypervisor_ip, check_grub_cmd)
        for arg in kernel_args:
            if arg not in result:
                test_result.append("Tuned not set in grub. Need to reboot?")

        test_result = '\n'.join(test_result)
        self.assertEmpty(test_result, test_result)

    def _test_mtu_ping_gateway(self, test_setup_mtu, mtu=1973):
        """Test MTU by pinging instance gateway

        The test boots an instance with given args from external_config_file,
        connect to the instance using ssh, and ping with given MTU to GW.
        * This tests depend on MTU configured at running environment.

        :param test_setup_mtu
        :param mtu
        """

        servers, key_pair = \
            self.create_server_with_resources(test=test_setup_mtu)

        msg = "Timed out waiting for %s to become reachable" % \
              servers[0]['fip']

        if 'mtu' in self.test_setup_dict[test_setup_mtu]:
            mtu = self.test_setup_dict[test_setup_mtu]['mtu']

        self.assertTrue(self.ping_ip_address(servers[0]['fip']), msg)
        gateway = self.test_network_dict[self.test_network_dict[
            'public']]['gateway_ip']
        gw_msg = "The gateway of given network does not exists,".\
            join("please assign it and re-run.")
        self.assertTrue(gateway is not None, gw_msg)
        ssh_source = self.get_remote_client(servers[0]['fip'],
                                            private_key=key_pair[
                                                'private_key'])
        return ssh_source.exec_command('ping -c 1 -M do -s %d %s' % (mtu,
                                                                     gateway))

    def test_numa0_provider_network(self, test='numa0'):
        """Verify numa configuration on instance

        The test instance allocation on the selected numa cell.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh(servers[0]['hypervisor_ip'],
                                            command)
        self.assertTrue(int(result[0]) == 2)
        self._check_vcpu_from_dumpxml(servers[0], servers[0]['hypervisor_ip'],
                                      test[4:])

    def test_numa1_provider_network(self, test='numa1'):
        """Verify numa configuration on instance

        The test instance allocation on the selected numa cell.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh(servers[0]['hypervisor_ip'],
                                            command)
        self.assertTrue(int(result[0]) == 2)
        self._check_vcpu_from_dumpxml(servers[0], servers[0]['hypervisor_ip'],
                                      test[4:])

    def test_numamix_provider_network(self, test='numamix'):
        """Verify numa configuration on instance

        The test instance allocation on the selected numa cell.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh(servers[0]['hypervisor_ip'],
                                            command)
        self.assertTrue(int(result[0]) == 2)
        self._check_vcpu_from_dumpxml(servers[0], servers[0]['hypervisor_ip'],
                                      test[4:])

    def test_packages_compute(self):
        self._test_check_package_version("check-compute-packages")

    def test_mtu_ping_test(self):
        # TODO(skramaja): Need to check if it is possible to execute ping
        #                 inside the guest VM using network namespace
        self.assertTrue(self.fip, "Floating IP is required for mtu test")

        msg = "MTU Ping test failed - check your environment settings"
        self.assertTrue(self._test_mtu_ping_gateway("test-ping-mtu"), msg)

    def test_cold_migration(self, test='cold-migration'):
        """Test cold migration

        The test shuts down the instance, migrates it and brings it up to
        verify resize.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)

        self.os_admin.servers_client. \
            migrate_server(server_id=servers[0]['id'])
        waiters.wait_for_server_status(self.servers_client,
                                       servers[0]['id'], 'VERIFY_RESIZE')
        self.servers_client.confirm_resize_server(server_id=servers[0]['id'])
        msg = "Timed out waiting for %s to become reachable" % \
              servers[0]['fip']
        self.assertTrue(self.ping_ip_address(servers[0]['fip']), msg)
        self.assertTrue(self.get_remote_client(
            servers[0]['fip'], private_key=key_pair['private_key']))
        succeed = True

        msg = "Cold migration test id failing. Check your environment settings"
        self.assertTrue(succeed, msg)

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
            return_value = self. \
                compare_emulatorpin_to_overcloud_config(srv,
                                                        srv['hypervisor_ip'],
                                                        config_path,
                                                        check_section,
                                                        check_value)
            self.assertTrue(return_value, 'The emulatorpin test failed. '
                                          'The values of the instance and '
                                          'nova does not match.')

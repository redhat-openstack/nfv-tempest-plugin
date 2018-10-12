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

import re

from nfv_tempest_plugin.tests.scenario import baremetal_manager
from oslo_log import log as logging
from tempest import clients
from tempest.common import credentials_factory as common_creds
from tempest import config

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestNfvBasic(baremetal_manager.BareMetalManager):
    def __init__(self, *args, **kwargs):
        super(TestNfvBasic, self).__init__(*args, **kwargs)
        self.ip_address = None
        self.availability_zone = None
        self.cpuregex = re.compile('^[0-9]{1,2}$')
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id
        self.ssh_user = CONF.validation.image_ssh_user
        self.ssh_passwd = CONF.validation.image_ssh_password

    @classmethod
    def setup_credentials(cls):
        """Do not create network resources for these tests

        Using public network for ssh
        """
        cls.set_network_resources()
        super(TestNfvBasic, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(TestNfvBasic, self).setUp()
        # pre setup creations and checks read from config files

    def _test_numa_provider_network(self, test_setup_numa):
        """Verify numa configuration on test instance

        The test shows how to deploy Guest with existing networks..
        external_config.. networks leaf need only network names and port types
        per test setup flavor-id, image-id, availability zone
        The test identifies networks..
        create ports prepare port list and parse it to vm
        It relies on l3 provider network, no router
        consume test-setup
        numa_topology='numa0','numa1',numamix

        :param test_setup_numa
        """

        servers, key_pair = \
            self.create_server_with_resources(test=test_setup_numa)

        LOG.info("fip: %s, instance_id: %s", servers[0]['fip'],
                 servers[0]['id'])

        """
        Check CPU mapping for numa0
        """
        """
        self.ip_address = self._get_hypervisor_host_ip()
        w/a to my_ip address set in nova fir non_contolled network,
        need access from tester """
        host_ip = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc'})
        self.ip_address = host_ip[0]
        self.assertNotEmpty(self.ip_address,
                            "_get_hypervisor_ip_from_undercloud "
                            "returned empty ip list")
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh(self.ip_address, command)
        self.assertTrue(int(result[0]) == 2)

        """Run ping and verify ssh connection."""
        msg = "Timed out waiting for %s to become reachable" % \
              servers[0]['fip']
        self.assertTrue(self.ping_ip_address(servers[0]['fip']), msg)
        self.assertTrue(self.get_remote_client(
            servers[0]['fip'], private_key=key_pair['private_key']))
        self.ip_address = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc',
               'server_id': servers[0]['id']})[0]
        self._check_vcpu_with_xml(servers[0], self.ip_address,
                                  test_setup_numa[4:])

    def test_numa0_provider_network(self):
        self._test_numa_provider_network("numa0")

    def test_numa1_provider_network(self):
        self._test_numa_provider_network("numa1")

    def test_numamix_provider_network(self):
        self._test_numa_provider_network("numamix")

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
        if 'availability-zone' in self.test_setup_dict[test_compute]:
            self.availability_zone = \
                self.test_setup_dict[test_compute]['availability-zone']
            host_ip = self._get_hypervisor_ip_from_undercloud(
                **{'shell': '/home/stack/stackrc',
                   'aggregation_name': self.availability_zone})
            self.ip_address = host_ip[0]
        else:
            host_ip = self._get_hypervisor_ip_from_undercloud(
                **{'shell': '/home/stack/stackrc'})
            self.ip_address = host_ip[0]

        self.assertNotEmpty(self.ip_address,
                            "_get_hypervisor_ip_from_undercloud "
                            "returned empty ip list")

        test_result = []
        if 'package-names' in self.test_setup_dict[test_compute]:
            packages = self.test_setup_dict[test_compute]['package-names']
            if packages is not None:
                for package in packages:
                    cmd = "rpm -qa | grep {0}".format(package)
                    result = self._run_command_over_ssh(self.ip_address, cmd)
                    if result is '':
                        test_result.append("Package {0} is not found"
                                           .format(package))

        if 'service-names' in self.test_setup_dict[test_compute]:
            services = self.test_setup_dict[test_compute]['service-names']
            if services is not None:
                for service in services:
                    cmd = "systemctl is-active {0}".format(service)
                    result = self._run_command_over_ssh(
                        self.ip_address, cmd).strip('\n')
                    if result != 'active':
                        test_result.append("The {0} service is not Active"
                                           .format(service))

        if 'tuned-profile' in self.test_setup_dict[test_compute]:
            tuned = self.test_setup_dict[test_compute]['tuned-profile']
            if tuned is not None:
                cmd = "sudo tuned-adm active | awk '{print $4}'"
                result = self._run_command_over_ssh(
                    self.ip_address, cmd).strip('\n')
                if result != tuned:
                    test_result.append("Tuned {0} profile is not Active"
                                       .format(tuned))

        kernel_args = ['nohz', 'nohz_full', 'rcu_nocbs', 'intel_pstate']
        check_grub_cmd = "sudo cat /proc/cmdline"
        result = self._run_command_over_ssh(self.ip_address, check_grub_cmd)
        for arg in kernel_args:
            if arg not in result:
                test_result.append("Tuned not set in grub. Need to reboot?")

        test_result = '\n'.join(test_result)
        self.assertEmpty(test_result, test_result)

    def test_packages_compute(self):
        self._test_check_package_version("check-compute-packages")

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

    def test_mtu_ping_test(self):
        msg = "MTU Ping test failed - check your environment settings"
        self.assertTrue(self._test_mtu_ping_gateway("test-ping-mtu"), msg)

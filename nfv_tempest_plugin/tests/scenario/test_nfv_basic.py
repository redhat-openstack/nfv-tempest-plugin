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

from collections import namedtuple
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
import re
from tempest.common import waiters
from tempest import config
from tempest.lib import exceptions as lib_exc


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
                    result = self._run_command_over_ssh(self.hypervisor_ip,
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
        result = self._run_command_over_ssh(servers[0]['hypervisor_ip'],
                                            command)
        self.assertTrue(int(result[0]) == 2)
        LOG.info('Check instance vcpu')
        self._check_vcpu_from_dumpxml(servers[0], servers[0]['hypervisor_ip'],
                                      test[4:])
        LOG.info('The {} test passed.'.format(test))

    def test_numa1_provider_network(self, test='numa1'):
        """Verify numa configuration on instance

        The test instance allocation on the selected numa cell.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh(servers[0]['hypervisor_ip'],
                                            command)
        self.assertTrue(int(result[0]) == 2)
        LOG.info('Check instance vcpu')
        self._check_vcpu_from_dumpxml(servers[0], servers[0]['hypervisor_ip'],
                                      test[4:])
        LOG.info('The {} test passed.'.format(test))

    def test_numamix_provider_network(self, test='numamix'):
        """Verify numa configuration on instance

        The test instance allocation on the selected numa cell.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh(servers[0]['hypervisor_ip'],
                                            command)
        self.assertTrue(int(result[0]) == 2)
        LOG.info('Check instance vcpu')
        self._check_vcpu_from_dumpxml(servers[0], servers[0]['hypervisor_ip'],
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

    def test_volume_in_hci_nfv_setup(self, test='nfv_hci_basic_volume'):
        """Test attaches the volume to the instance and writes it.

        Also writing the content into the instance volume.

        :param test: Test name from the config file
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        volume_id = self.create_volume()
        attachment = self.attach_volume(servers[0], volume_id)
        self.assertTrue('device' in attachment)
        ssh_source = self.get_remote_client(servers[0]['fip'],
                                            username=self.instance_user,
                                            private_key=key_pair[
                                                'private_key'])
        LOG.info('Execute write test command')
        out = ssh_source.exec_command(
            'sudo dd if=/dev/zero of=/dev/vdb bs=4096k count=256 oflag=direct')
        self.assertEmpty(out)
        LOG.info('The {} test passed.'.format(test))

    def test_ovs_bond_connectivity(self, test='ovs_bond_connectivity'):
        """Test link aggregation for OVS bonds

        :param test: Test name from the config file
        """
        test_dict = self.test_setup_dict[test]
        if 'bond_interfaces' in test_dict:
            bond_dict = test_dict['bond_interfaces']
        else:
            raise ValueError('bond_interfaces is not defined in '
                             'bond_connectivity test')

        # Dictionary containing utilities to interact with supported modes
        bond_utils = {
            'bond_query_cmd': 'sudo ovs-appctl bond/show {}',
            'ovs_query_cmd': 'sudo ovs-vsctl show | grep {} -B100',
            're_filter': r'bond_mode:\s+.*',
            're_sub_filter': r'bond_mode:\s+(.*)',
            'bridge_re_filter':
                r'Bridge ".*"',
            'bridge_re_sub_filter':
                r'Bridge "(.*)"',
            'supported_modes': {
                'active-backup': {
                    'type': 'no_loadbalancing',
                    'active_slave_re_filter':
                        r'active slave mac:\s+.*',
                    'active_slave_sub_re_filter':
                        r'active slave mac:\s+.*\((.*)\)',
                    'interface_down_cmd':
                        'sudo ovs-ofctl mod-port {b} {i} down',
                    'interface_up_cmd':
                        'sudo ovs-ofctl mod-port {b} {i} up'
                }
            }
        }
        # Construct a namedtuple to be used to describe a bond
        bond = namedtuple('Bond', [
            'hypervisor',
            'interface',
            'type',
            'master_interface',
            'ovs_bridge',
            'networks',
            'ifup_cmd',
            'ifdown_cmd'
        ])
        # Initialize bonds list
        bonds = []
        # Retrieve all hypvervisors
        hypervisors = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')
        # Iterate over hypervisors
        for hypervisor in hypervisors:
            check_bond_cmd = bond_utils['bond_query_cmd']
            bond_mode_re_filter = bond_utils['re_filter']
            bond_mode_re_sub_filter = bond_utils['re_sub_filter']
            # Iterate over user supplied bond dict
            for bond_object in bond_dict:
                bond_interface = bond_object['interface']
                guest_networks = bond_object['guest_networks']
                # Query bond interface on hypervisor
                out = self._run_command_over_ssh(hypervisor,
                                                 check_bond_cmd
                                                 .format(bond_interface))
                msg = ("Bond '{b}' not present on hypervisor '{h}'"
                       .format(h=hypervisor, b=bond_interface))
                self.assertNotEmpty(out, msg)
                LOG.info("Bond '{b}' present on hypervisor '{h}'"
                         .format(h=hypervisor, b=bond_interface))
                re_result = re.search(bond_mode_re_filter, out)
                msg = "Could not find bonding mode from bond query output"
                self.assertIsNotNone(re_result, msg)
                re_bond_output = re_result.group(0)
                bond_mode = re.sub(bond_mode_re_sub_filter, r'\1',
                                   re_bond_output)
                if bond_mode not in bond_utils['supported_modes']:
                    raise ValueError('bond mode {} is not supported'
                                     .format(bond_mode))
                LOG.info("Bond '{b}' is set to mode '{m}'"
                         .format(b=bond_interface, m=bond_mode))
                bond_mode_type = \
                    bond_utils['supported_modes'][bond_mode]['type']
                # Execute logic based on bonding operation mode
                # Currently supporting only non loadbalancing bond modes
                if bond_mode_type == "no_loadbalancing":
                    re_result = re.search(bond_utils['supported_modes']
                                          [bond_mode]
                                          ['active_slave_re_filter'],
                                          out)
                    re_bond_output = re_result.group(0)
                    bond_master = re.sub(bond_utils['supported_modes']
                                         [bond_mode]
                                         ['active_slave_sub_re_filter'],
                                         r'\1', re_bond_output)
                    LOG.info("NIC '{m}' is set as master NIC in bond '{b}' on "
                             "hypervisor '{h}'".format(m=bond_master,
                                                       b=bond_interface,
                                                       h=hypervisor))
                else:
                    raise ValueError('Currenty only supporting bond modes '
                                     'that are not set to load balance '
                                     'traffic')

                cmd = bond_utils['ovs_query_cmd']
                # Fetch OVS general info
                out = self._run_command_over_ssh(hypervisor,
                                                 cmd.format(bond_master))
                ovs_bridge_re_filter = bond_utils['bridge_re_filter']
                ovs_bridge_re_sub_filter = bond_utils['bridge_re_sub_filter']
                # Construct interface up/down commands
                bond_if_up_cmd = \
                    (bond_utils['supported_modes'][bond_mode]
                     ['interface_up_cmd'])
                bond_if_down_cmd = \
                    (bond_utils['supported_modes'][bond_mode]
                     ['interface_down_cmd'])
                re_result = re.search(ovs_bridge_re_filter, out)
                ovs_bridge_output = re_result.group(0)
                ovs_user_bridge = \
                    re.sub(ovs_bridge_re_sub_filter, r'\1', ovs_bridge_output)
                # Apply required variables for interface commands
                bond_if_up_cmd = bond_if_up_cmd.format(b=ovs_user_bridge,
                                                       i=bond_master)
                bond_if_down_cmd = bond_if_down_cmd.format(b=ovs_user_bridge,
                                                           i=bond_master)

            # Initialize a namedtuple of current bond
            current_bond = bond(hypervisor, bond_interface, bond_mode,
                                bond_master, ovs_user_bridge,
                                guest_networks, bond_if_up_cmd,
                                bond_if_down_cmd)
            # Add bond interface to bonds list
            bonds.append(current_bond)
        # Create servers
        servers, key_pair = self.create_and_verify_resources(test=test,
                                                             num_servers=2)
        # Create OpenStack admin clients
        network_client = self.os_admin.networks_client
        subnet_client = self.os_admin.subnets_client
        # Overcloud username
        overcloud_username = CONF.nfv_plugin_options.overcloud_node_user
        # Overcloud private key
        overcloud_private_key = \
            open(CONF.nfv_plugin_options.overcloud_node_pkey_file).read()
        for server in servers:
            # Initialize helper variables
            failover_failed = False
            hypervisor_ip = server['hypervisor_ip']
            # Create SSH client to guest
            guest_ssh = \
                self.get_remote_client(server['fip'],
                                       username=self.instance_user,
                                       private_key=key_pair['private_key'])
            # Create SSH client to hypervisor hosting the guest
            hypervisor_ssh = \
                self.get_remote_client(hypervisor_ip,
                                       username=overcloud_username,
                                       private_key=overcloud_private_key)
            # Iterate over fetched bonds
            for bond in bonds:
                # If bond is present on hypervisor
                if bond.hypervisor == hypervisor_ip:
                    # Intialize helper variables
                    master_interface = bond.master_interface
                    bond_interface = bond.interface
                    # Iterate over supplied guest networks attached to bond
                    for net in guest_networks:
                        net_obj = (network_client.list_networks(name=net)
                                   ['networks'][0])
                        msg = "Failed to discover network '{}'".format(net)
                        self.assertNotEmpty(net_obj, msg)
                        net_id = net_obj['id']
                        subnet_obj = (subnet_client.list_subnets(
                                      network_id=net_id)['subnets'][0])
                        msg = ("Failed to discover subnets attached to "
                               "network '{}'".format(net))
                        self.assertNotEmpty(subnet_obj, msg)
                        subnet_gateway = subnet_obj['gateway_ip']
                        LOG.info("Default gateway for network '{n}' is set "
                                 "to '{g}'".format(n=net, g=subnet_gateway))
                        # Attempt to ping network's default gateway
                        try:
                            guest_ssh.icmp_check(subnet_gateway)
                        except lib_exc.SSHExecCommandFailed:
                            msg = ("Failed to ping networks '{n}' default "
                                   "gateway '{g}'".format(n=net,
                                                          g=subnet_gateway))
                            raise AssertionError(msg)
                        LOG.info("Initial ping is successful, will attempt "
                                 "to perform failover for bond '{b}' on "
                                 "hyperviosr '{h}'".format(b=bond_interface,
                                                           h=hypervisor_ip))
                        # Attempt to bring down master interface - failover
                        try:
                            hypervisor_ssh.exec_command(bond.ifdown_cmd)
                        except lib_exc.SSHExecCommandFailed:
                            msg = ("Failed to bring down interface '{i}' "
                                   "in bond '{b}' on hypervisor {h}"
                                   .format(i=master_interface,
                                           b=bond_interface,
                                           h=hypervisor_ip))
                            raise AssertionError(msg)
                        LOG.info("Performed failover in bond '{b}', "
                                 "interface '{i}' is no longer master on "
                                 "hypervisor '{h}'".format(b=bond_interface,
                                                           i=master_interface,
                                                           h=hypervisor_ip))
                        LOG.info("Will attempt to ping default gateway "
                                 "'{g}' on network '{n}'"
                                 .format(g=subnet_gateway, n=net))
                        # Attempt to ping network's default gateway
                        try:
                            guest_ssh.icmp_check(subnet_gateway)
                        except lib_exc.SSHExecCommandFailed:
                            LOG.info("Failed to ping networks '{n}' default "
                                     "gateway '{g}' post failover"
                                     .format(n=net, g=subnet_gateway))
                            failover_failed = True
                        finally:
                            # Attempt to bring up master interface
                            try:
                                hypervisor_ssh.exec_command(bond.ifup_cmd)
                            except lib_exc.SSHExecCommandFailed:
                                msg = ("Failed to bring up interface '{i} "
                                       "in bond '{b}' on hypervisor '{h}' ,"
                                       "check hypervisor for more details"
                                       .format(i=master_interface,
                                               b=bond_interface,
                                               h=hypervisor_ip))
                                raise AssertionError(msg)
                        self.assertFalse(failover_failed)
                        LOG.info("Failover scenario is successful for bond "
                                 "'{b}' on hypervisor '{h}'"
                                 .format(b=bond_interface, h=hypervisor_ip))

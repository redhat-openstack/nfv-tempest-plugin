# Copyright 2019 Red Hat, Inc.
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

import os
import random
import re
import time

from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestNfvOffload(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestNfvOffload, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(TestNfvOffload, self).setUp()

    def test_offload_ovs_config(self):
        """Check ovs config for offload on all hypervisors

        """
        # Command to check if hw-offload is enabled in OVS
        cmd = ("sudo ovs-vsctl get open_vswitch . "
               "other_config:hw-offload")
        # Retrieve all hypvervisors
        hypervisors = self._get_hypervisor_ip_from_undercloud()
        # Intialize results list
        result = []
        # Expected result is a list of dicts, each dict contains
        # a key which is hypervisor's IP and the value 'true'
        # Example:
        # [{192.0.60.1: 'true'}, {192.0.60.2: 'true'}]
        expected_result = [{ip: 'true'} for ip in hypervisors]
        for hypervisor in hypervisors:
            out = shell_utils.run_command_over_ssh(hypervisor, cmd)
            if out:
                # Strip newlines and remove double quotes
                output = out.rstrip().replace('"', '')
            # HW-Offload not enabled if no text returned
            else:
                output = 'false'
            LOG.info("Hypervisor '{h}' is OVS HW-offload "
                     "capable: '{r}'".format(h=hypervisor,
                                             r=output))
            result.append({hypervisor: output})
        msg = "Not all hypervisors have OVS HW-Offload enabled"
        self.assertCountEqual(expected_result, result, msg)

    def test_offload_nic_eswitch_mode(self):
        """Check eswitch mode of nic for offload on all hypervisors

        By default, offload nics are auto discovered.
        But if the used would like to not perform the autodiscover and
        provide the nics, it could be done by modifying the
        CONF.nfv_plugin_options.offload_nics param in deployer-input file.
        """
        LOG.info('Starting offload_nic_eswitch_mode test')
        # Retrieve all hypervisors
        hypervisors = self._get_hypervisor_ip_from_undercloud()
        offload_nics = CONF.nfv_plugin_options.offload_nics
        if not offload_nics:
            LOG.info('The offload nics are not provided. Detecting...')
            offload_nics = self.discover_hw_offload_nics(hypervisors)
        LOG.info('Test the following offload nics - {}'.format(offload_nics))
        # devlink cmd to retrieve switch mode of interface
        devlink_cmd = "sudo devlink dev eswitch show pci/{}"
        # Initialize results list
        result = []
        # Expected result is a list of dicts containing a dict of
        # hypervisor's IP, its offload nics as keys and the value 'true'
        # Example:
        # [{'192.0.160.1': [{'p6p1': 'true'}, {'p6p2': 'true'}]},
        #  {'192.0.160.2': [{'p6p1': 'true'}, {'p6p2': 'true'}]}]
        expected_result = [{ip: [{nic: 'true'} for nic, _ in nics.items()]}
                           for ip, nics in offload_nics.items()]
        for hypervisor, nics in offload_nics.items():
            dev_result = []
            # Check hw-offload config on hypervisor
            hyper_check = \
                'sudo ovs-vsctl get Open_vSwitch . other_config:hw-offload'
            hyper_offload_state = shell_utils.run_command_over_ssh(hypervisor,
                                                                   hyper_check)
            if not hyper_offload_state.strip() == '"true"':
                dev_result.append('No hw-offload on hypervisor')
                result.append({hypervisor: dev_result})
                LOG.info('No hw-offload on hypervisor {}'.format(hypervisor))
                continue
            LOG.info('Hw-offload configured on hyper - {}'.format(hypervisor))
            for nic, nic_options in nics.items():
                dev_query = shell_utils.run_command_over_ssh(
                    hypervisor, devlink_cmd.format(nic_options['bus-info']))
                if 'switchdev' in dev_query:
                    output = 'true'
                else:
                    output = 'false'
                LOG.info("Hypervisor '{h}' NIC '{n}' is in switchdev mode: {r}"
                         .format(h=hypervisor, n=nic, r=output))
                dev_result.append({nic: output})
            result.append({hypervisor: dev_result})
        msg = "Not all hypervisors contains nics in switchev mode"
        self.assertCountEqual(expected_result, result, msg)

    def test_offload_icmp_vlan(self, test='offload_icmp_vlan'):
        """Check ICMP traffic is offloaded in vlan network

        The following test deploy vms, on hw-offload computes.
        It sends async ping and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single packet por icmp
        reply/request. As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "icmp", "vlan")

    def test_offload_icmp_vxlan(self, test='offload_icmp_vxlan'):
        """Check ICMP traffic is offloaded in vxlan network

        The following test deploy vms, on hw-offload computes.
        It sends async ping and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single packet por icmp
        reply/request. As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "icmp", "vxlan")

    def test_offload_icmp_geneve(self, test='offload_icmp_geneve'):
        """Check ICMP traffic is offloaded in geneve network

        The following test deploy vms, on hw-offload computes.
        It sends async ping and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single packet por icmp
        reply/request. As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "icmp", "geneve")

    def test_offload_icmp_trunk_vlan(self, test='offload_icmp_trunk_vlan'):
        """Check ICMP traffic is offloaded in vlan trunk network

        The following test deploy vms, on hw-offload computes.
        It sends async ping and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single packet por icmp
        reply/request. As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "icmp", "trunk_vlan")

    def test_offload_icmp_transparent_vlan(
            self, test='offload_icmp_transparent_vlan'):
        """Check ICMP traffic is offloaded in transparent vlan network

        The following test deploy vms, on hw-offload computes.
        It sends async ping and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single packet por icmp
        reply/request. As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "icmp", "transparent_vlan")

    def test_offload_udp_vlan(self, test='offload_udp_vlan'):
        """Check UDP traffic is offloaded in vlan network

        The following test deploy vms, on hw-offload computes.
        It sends UDP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single UDP packet.
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "vlan")

    def test_offload_udp_vxlan(self, test='offload_udp_vxlan'):
        """Check UDP traffic is offloaded in vxlan network

        The following test deploy vms, on hw-offload computes.
        It sends UDP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single UDP packet.
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "vxlan")

    def test_offload_udp_geneve(self, test='offload_udp_geneve'):
        """Check UDP traffic is offloaded in geneve network

        The following test deploy vms, on hw-offload computes.
        It sends UDP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single UDP packet.
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "geneve")

    def test_offload_udp_trunk_vlan(self, test='offload_udp_trunk_vlan'):
        """Check UDP traffic is offloaded in vlan trunk network

        The following test deploy vms, on hw-offload computes.
        It sends UDP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single UDP packet.
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "trunk_vlan")

    def test_offload_udp_transparent_vlan(self,
                                          test='offload_udp_transparent_vlan'):
        """Check UDP traffic is offloaded in transparent vlan network

        The following test deploy vms, on hw-offload computes.
        It sends UDP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single UDP packet.
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "transparent_vlan")

    def test_offload_tcp_vlan(self, test='offload_tcp_vlan'):
        """Check TCP traffic is offloaded in vlan network

        The following test deploy vms, on hw-offload computes.
        It sends TCP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be 2 TCP packets (one per direction).
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "vlan")

    def test_offload_tcp_vxlan(self, test='offload_tcp_vxlan'):
        """Check TCP traffic is offloaded in vxlan network

        The following test deploy vms, on hw-offload computes.
        It sends TCP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be 2 TCP packets (one per direction).
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "vxlan")

    def test_offload_tcp_geneve(self, test='offload_tcp_geneve'):
        """Check TCP traffic is offloaded in geneve network

        The following test deploy vms, on hw-offload computes.
        It sends TCP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be 2 TCP packets (one per direction).
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "geneve")

    def test_offload_tcp_trunk_vlan(self, test='offload_tcp_trunk_vlan'):
        """Check TCP traffic is offloaded in vlan trunk network

        The following test deploy vms, on hw-offload computes.
        It sends TCP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be 2 TCP packets (one per direction).
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "trunk_vlan")

    def test_offload_tcp_transparent_vlan(self,
                                          test='offload_tcp_transparent_vlan'):
        """Check TCP traffic is offloaded in transparent vlan network

        The following test deploy vms, on hw-offload computes.
        It sends TCP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be 2 TCP packets (one per direction).
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "transparent_vlan")

    def filter_test_networks(self, test_networks, network_type):
        """filter test networks

        Only networks needed for the test will be created:
        * management network for fip
        * vlan networks for vlan testing
        * vxlan networks for vxlan testing
        * geneve networks for geneve testing
        * vlan trunk networks for vlan trunk testing
        * transparent vlan networks for transparent vlan testing

        :param test_networks: list of test networks
        :param network_type: network used (vlan, vxlan,
                             geneve, trunk_vlan, transparent_vlan)
        :return filtered network list
        """
        filtered_networks = []

        for network in test_networks:
            mgmt = False
            trunk_vlan = False
            trunk_vlan_parent = False
            transparent_vlan = False
            transparent_vlan_parent = False
            if 'mgmt' in network.keys() and network['mgmt']:
                mgmt = True
            if 'trunk_vlan_parent' in network.keys():
                if network['trunk_vlan_parent']:
                    trunk_vlan_parent = True
                else:
                    trunk_vlan = True
            if 'transparent_vlan_parent' in network.keys():
                if network['transparent_vlan_parent']:
                    transparent_vlan_parent = True
                else:
                    transparent_vlan = True

            select_network = False
            if mgmt:
                select_network = True
            elif ((network_type in ['vlan', 'vxlan', 'geneve'])
                  and not (trunk_vlan or transparent_vlan)
                  and network['network_type'] == network_type):
                select_network = True
            elif ((network_type == 'trunk_vlan')
                  and (trunk_vlan or trunk_vlan_parent)):
                select_network = True
            elif ((network_type == 'transparent_vlan')
                  and (transparent_vlan or transparent_vlan_parent)):
                select_network = True

            if select_network:
                if (network_type in ['vlan', 'vxlan',
                                     'geneve', 'transparent_vlan']):
                    network.pop('trunk_vlan', None)
                    network.pop('trunk_vlan_parent', None)
                if (network_type in ['vlan', 'vxlan',
                                     'geneve', 'trunk_vlan']):
                    network.pop('transparent_vlan', None)
                    network.pop('transparent_vlan_parent', None)
                filtered_networks.append(network)

        return filtered_networks

    def test_offload_udp_conntrack_vxlan(
            self, test='offload_udp_conntrack_vxlan'):
        """Check UDP traffic is offloaded in vxlan network with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends UDP traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "vxlan", True)

    def test_offload_udp_conntrack_vlan(
            self, test='offload_udp_conntrack_vlan'):
        """Check UDP traffic is offloaded in vlan network with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends UDP traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "vlan", True)

    def test_offload_udp_conntrack_geneve(
            self, test='offload_udp_conntrack_geneve'):
        """Check UDP traffic is offloaded in geneve network with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends UDP traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "geneve", True)

    def test_offload_udp_conntrack_trunk_vlan(
            self, test='ffload_udp_conntrack_trunk_vlan'):
        """Check UDP traffic is offloaded in vlan trunk net with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends UDP traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "trunk_vlan", True)

    def test_offload_udp_conntrack_transparent_vlan(
            self, test='offload_udp_conntrack_transparent_vlan'):
        """Check UDP traffic is offloaded in transp vlan net with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends UDP traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "udp", "transparent_vlan", True)

    def test_offload_tcp_conntrack_vxlan(
            self, test='offload_tcp_conntrack_vxlan'):
        """Check TCP traffic is offloaded in vxlan network with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends TCP traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "vxlan", True)

    def test_offload_tcp_conntrack_vlan(
            self, test='offload_tcp_conntrack_vlan'):
        """Check TCP traffic is offloaded in vlan network with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends TCP traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "vlan", True)

    def test_offload_tcp_conntrack_geneve(
            self, test='offload_tcp_conntrack_geneve'):
        """Check TCP traffic is offloaded in geneve network with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends TCP traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "geneve", True)

    def test_offload_tcp_conntrack_trunk_vlan(
            self, test='offload_tcp_conntrack_trunk_vlan'):
        """Check TCP traffic is offloaded in vlan trunk network with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends TCP traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "trunk_vlan", True)

    def test_offload_tcp_conntrack_transparent_vlan(
            self, test='offload_tcp_conntrack_transparent_vlan'):
        """Check TCP traffic is offloaded in transparent vlan network with sec groups

        The following test deploy vms, on hw-offload computes.
        Vms have security groups enabled.
        It sends Ttcp traffic and check conntrack table to check if flows
        are offloaded
        :param test: Test name from the external config file.
        """
        LOG.info('Start test_{} test.'.format(test))
        self.run_offload_testcase(test, "tcp", "transparent_vlan", True)

    def run_offload_testcase(self, test, protocol,
                             network_type, sec_groups=False):
        """Run offload testcase with different injection traffic

        This function will create resources needed to run offload
        testcases including test networks and vms. Then it will
        inject traffic (tcp, udp or icmp), it will check flows and
        traffic in representor port and it will report if the
        behaviour was as expected

        :param test: Test name from the external config file.
        :param protocol: Protocol to test (udp, tcp, icmp)
        :param network_type: network used (vlan, vxlan,
                             geneve, trunk_vlan, transparent_vlan)
        :param sec_groups: True/False
        """
        num_vms = int(CONF.nfv_plugin_options.offload_num_vms)
        offload_injection_time = int(
            CONF.nfv_plugin_options.offload_injection_time)
        tcpdump_time = int(CONF.nfv_plugin_options.tcpdump_time)
        aggregate_flavors = [int(flavor) for flavor in
                             CONF.nfv_plugin_options.aggregate_flavors]
        LOG.info('run_offload_testcase create {} vms'.format(num_vms))

        # only needed networks will be created
        full_test_network = self.external_config['test-networks']
        self.external_config['test-networks'] = \
            self.filter_test_networks(full_test_network, network_type)

        # Used host aggregation
        kw_test = dict()
        kw_test['num_servers'] = num_vms
        LOG.info('run_offload_testcase Using aggregate flavors {}'.
                 format(str(','.join(str(flavor)
                                     for flavor in aggregate_flavors))))
        if len(aggregate_flavors) > 0:
            kw_test['srv_details'] = {}
            for vm in range(num_vms):
                kw_test['srv_details'][vm] = dict()
                kw_test['srv_details'][vm]['flavor'] = \
                    aggregate_flavors[vm % len(aggregate_flavors)]

        servers, key_pair = self.create_and_verify_resources(
            test=test, **kw_test)

        if sec_groups and not self.sec_groups:
            raise ValueError("Security groups are required for this test")

        # Requiered at least 2 servers (server, client)
        # There may be more servers, in this case server 0 will be the iperf
        # server and server 1,2,3, ... will be the iperf client
        for server in servers:
            server['ssh_source'] = self.get_remote_client(
                server['fip'],
                username=self.instance_user,
                private_key=key_pair['private_key'])

        # install iperf
        server_command = "sudo yum install iperf3 -y || echo"
        server_command += ";sudo yum install iperf -y || echo"
        for server in servers:
            server['ssh_source'].exec_command(server_command)

        if sec_groups and protocol == 'udp':
            server_command = "sudo yum install python36 -y || echo"
            server_command += ";sudo pip3 install scapy  || echo"
            script_dir = os.path.dirname(__file__) + '/external_scripts/'
            for server in servers:
                server['ssh_source'].exec_command(server_command)
                self.copy_file_to_remote_host(
                    server['fip'],
                    key_pair['private_key'],
                    self.instance_user,
                    files='scapy_async_udp_sniff_send.py',
                    src_path=script_dir,
                    dst_path='/tmp/',
                    timeout=60)

        errors_found = []
        network_type_found = False
        # iterate servers
        for server in servers[1:]:
            # iterate networks
            for provider_network in server['provider_networks']:
                port = self.get_port_from_ip(provider_network.get(
                    'parent_ip_address',
                    provider_network['ip_address']))
                # check network type exists on the VM
                if 'provider:network_type' in provider_network:
                    if provider_network['provider:network_type']\
                        != network_type:
                        continue
                # make sure the network is offloaded
                if ('capabilities' not in port['binding:profile']
                    or 'switchdev' not in port['binding:profile']
                    ['capabilities']):
                    continue

                network_type_found = True

                # get network in the server in which ping is being executed
                source_network = \
                    next(item for item in servers[0]['provider_networks'] if
                         item["network_id"] == provider_network["network_id"])

                # pair with the server and network used for ping
                srv_pair = [{'server': servers[0], 'network': source_network},
                            {'server': server, 'network': provider_network}]

                # get vf from the mac address
                for srv_item in srv_pair:
                    network = srv_item['network']
                    srv_item['vf_nic'] = shell_utils.get_vf_from_mac(
                        network.get('parent_mac_address',
                                    network['mac_address']),
                        srv_item['server']['hypervisor_ip'])

                if sec_groups:
                    errors_found += self.check_conntrack(srv_pair, protocol)
                else:
                    errors_found += self.check_offload(srv_pair, protocol,
                                                       offload_injection_time,
                                                       tcpdump_time)

        self.assertTrue(network_type_found, "Network type {} not "
                                            "found".format(network_type))
        self.assertTrue(len(errors_found) == 0, "\n".join(errors_found))
        self.external_config['test-networks'] = full_test_network

    def check_offload(self, srv_pair, protocol, duration, tcpdump_time):
        """Check OVS offloaded flows and hw offload is working

        Two tests are done:
        - check offload is configured in the flows
        - check that there are no packets in the representor port. Only first
          packets must be present

        :param srv_pair: server/client data
        :param protocol: protocol to test (icmp, tcp, udp)
        :param duration: duration of the injection
        :param tcpdump_time: skip first seconds in tcpdump output
        :return checks: list with problems found
        """

        self.assertIn(protocol, ["udp", "tcp", "icmp"],
                      "Not supported protocol {}".format(protocol))

        errors = []
        # sleep several seconds so that flows generated checking provider
        # network connectivity during resource creation are removed. Timeout
        # for flows deletion is around 10 seconds
        flows_timeout = int(CONF.nfv_plugin_options.flows_timeout)
        time.sleep(flows_timeout)

        # execute tcpdump in representor port in both hypervisors
        iperf_port = random.randrange(8000, 9000)
        mac_addresses = [srv['network']['mac_address'] for srv in srv_pair]
        for srv_item in srv_pair:
            srv_item['tcpdump_file'] = shell_utils.tcpdump(
                server_ip=srv_item['server']['hypervisor_ip'],
                interface=srv_item['vf_nic'],
                duration=duration,
                macs=mac_addresses)

        # send traffic
        LOG.info('Sending traffic ({}) from {} to {}'.
                 format(protocol, srv_pair[0]['network']['ip_address'],
                        srv_pair[1]['network']['ip_address']))
        iperf_logs = []
        if protocol == "icmp":
            shell_utils.continuous_ping(
                srv_pair[1]['network']['ip_address'], duration=duration,
                ssh_client_local=srv_pair[0]['server']['ssh_source'])
        elif protocol in ["tcp", "udp"]:
            log = shell_utils.iperf_server(
                srv_pair[0]['network']['ip_address'],
                iperf_port, duration, protocol,
                srv_pair[0]['server']['ssh_source'])
            iperf_logs.append({'server': srv_pair[0]['server']['ssh_source'],
                               'log_file': log})
            log = shell_utils.iperf_client(
                srv_pair[0]['network']['ip_address'],
                iperf_port, duration, protocol,
                srv_pair[1]['server']['ssh_source'])
            iperf_logs.append({'server': srv_pair[1]['server']['ssh_source'],
                               'log_file': log})
            log = shell_utils.iperf_server(
                srv_pair[1]['network']['ip_address'],
                iperf_port, duration, protocol,
                srv_pair[1]['server']['ssh_source'])
            iperf_logs.append({'server': srv_pair[0]['server']['ssh_source'],
                               'log_file': log})
            log = shell_utils.iperf_client(
                srv_pair[1]['network']['ip_address'],
                iperf_port, duration, protocol,
                srv_pair[0]['server']['ssh_source'])
            iperf_logs.append({'server': srv_pair[1]['server']['ssh_source'],
                               'log_file': log})

        # Send traffic for a while, we need several packets
        # Only the first one should be captured by tcpdump
        time.sleep(duration)

        for srv_item in srv_pair:
            # check flows in both hypervisors
            offload_flows = shell_utils.get_offload_flows(
                srv_item['server']['hypervisor_ip'])
            network = srv_item['network']
            port = self.get_port_from_ip(network.get('parent_ip_address',
                                                     network['ip_address']))
            msg_header = "network_type {}, hypervisor {}, vm ip {} " \
                         "protocol {}.".\
                format(srv_item['network']['provider:network_type'],
                       srv_item['server']['hypervisor_ip'],
                       srv_item['network']['ip_address'],
                       protocol)
            if ('capabilities' not in port['binding:profile'] or 'switchdev'
                    not in port['binding:profile']['capabilities']):
                errors.append("{} Port does not have capabilities configured".
                              format(msg_header))
            if srv_item['network']['mac_address'] not in offload_flows:
                errors.append("{} mac address {} not in offload flows".
                              format(msg_header,
                                     srv_item['network']['mac_address']))
            if 'offloaded:yes, dp:tc' not in offload_flows:
                errors.append("{} 'offloaded:yes, dp:tc' missing in flows".
                              format(msg_header))

            # check tcpdump output. Only first packet should be going
            # through representor port. Once offload is working, there
            # should be no packet in representor port
            tcpdump_out = shell_utils.stop_tcpdump(
                srv_item['server']['hypervisor_ip'],
                srv_item['tcpdump_file'])

            tcpdump = ["", ""]
            tcpdump[0] = shell_utils.tcpdump_time_filter(
                tcpdump_out, end_time=tcpdump_time)
            tcpdump[1] = shell_utils.tcpdump_time_filter(
                tcpdump_out, start_time=tcpdump_time)

            if protocol == "icmp":
                icmp_requests = [0, 0]
                icmp_replies = [0, 0]
                icmp_requests[0] = tcpdump[0].count('ICMP echo request')
                icmp_requests[1] = tcpdump[1].count('ICMP echo request')
                icmp_replies[0] = tcpdump[0].count('ICMP echo reply')
                icmp_replies[1] = tcpdump[1].count('ICMP echo reply')
                # At least icmp request and icmp reply expected
                if icmp_requests[0] > 0 and icmp_requests[1] == 0 and \
                        icmp_replies[0] > 0 and icmp_replies[1] == 0:
                    pass
                else:
                    errors.append("{} Failed to check packets in representor "
                                  "port. Requests: {} (>0), {} (0), Replies"
                                  " {} (>0), {} (0)".format(msg_header,
                                                            icmp_requests[0],
                                                            icmp_requests[1],
                                                            icmp_replies[0],
                                                            icmp_replies[1]))
            err_udp = []
            if protocol == "udp":
                udp_packets = [0, 0]
                udp_packets[0] = tcpdump[0].count('UDP')
                udp_packets[1] = tcpdump[1].count('UDP')
                # At least one packet expected (single flow)
                if udp_packets[0] > 0 and udp_packets[1] == 0:
                    pass
                else:
                    err_udp.append("{} Failed to check packets in "
                                   "representor port. UDP packets: "
                                   "{} (>0), {} (0)".format(msg_header,
                                                            udp_packets[0],
                                                            udp_packets[1]))
            if protocol == "tcp" or len(err_udp) > 0:
                tcp_packets = [0, 0]
                tcp_packets[0] = tcpdump[0].count('IPv4')
                tcp_packets[1] = tcpdump[1].count('IPv4')
                # At least two packets expected (one per direction,
                # single flow)
                if tcp_packets[0] > 1 and tcp_packets[1] == 0:
                    if len(err_udp) > 0:
                        LOG.info('Same flow created for UPD/TCP. It is ok "'
                                 'according to BZ 2186488')
                    pass
                else:
                    if len(err_udp) > 0:
                        errors += err_udp
                    errors.append("{} Failed to check packets in representor "
                                  "port. TCP packets: {} (>1), {} (0)".
                                  format(msg_header,
                                         tcp_packets[0],
                                         tcp_packets[1]))

        for item in iperf_logs:
            shell_utils.stop_iperf(item['server'], item['log_file'])
        # sleep for a while to be sure that after stopping iperf,
        # there is no packet generated by iperf that may break
        # the following test
        time.sleep(10)

        return errors

    def check_conntrack(self, srv_pair, protocol):
        """Check OVS offloaded connection tracking is offloaded

        :param srv_pair: server/client data
        :param protocol: protocol to test (icmp, tcp, udp)
        :return checks: list with problems found
        """

        errors = []

        # execute tcpdump in representor port in both hypervisors
        traffic_port = random.randrange(8000, 9000)
        # If security group enabled create rules
        offload_sec_rules = [
            {
                'direction': 'ingress',
                'protocol': protocol,
            },
            {
                'direction': 'egress',
                'protocol': protocol,
            }
        ]
        # Apply security group if not ICMP
        for rule in offload_sec_rules:
            rule['port_range_min'] = rule['port_range_max'] = \
                traffic_port
        secgroup = \
            self.get_security_group_from_partial_string(
                group_name_string='tempest')
        # Allow port in security group
        self.add_security_group_rules(secgroup_id=secgroup['id'],
                                      rule_list=offload_sec_rules)
        # Flush connection tracking via OVS
        shell_utils.run_command_over_ssh(
            srv_pair[0]['server']['hypervisor_ip'],
            'sudo ovs-appctl dpctl/flush-conntrack')
        shell_utils.run_command_over_ssh(
            srv_pair[1]['server']['hypervisor_ip'],
            'sudo ovs-appctl dpctl/flush-conntrack')
        # If we are testing TCPm it is much easier to use iperf
        iperf_logs = []
        if protocol == 'tcp':
            log = shell_utils.iperf_server(
                srv_pair[0]['network']['ip_address'],
                traffic_port, 84600, 'tcp',
                srv_pair[0]['server']['ssh_source'])
            iperf_logs.append({'server': srv_pair[0]['server']['ssh_source'],
                               'log_file': log})
            log = shell_utils.iperf_client(
                srv_pair[0]['network']['ip_address'],
                traffic_port, 84600, 'tcp',
                srv_pair[1]['server']['ssh_source'])
            iperf_logs.append({'server': srv_pair[1]['server']['ssh_source'],
                               'log_file': log})
        # If we are testing UDP, it is much easier to use scapy
        elif protocol == 'udp':
            ip_address_first_vm = srv_pair[0]['network']['ip_address']
            ip_address_second_vm = srv_pair[1]['network']['ip_address']
            local_interface_first_vm = \
                srv_pair[0]['server']['ssh_source'].get_nic_name_by_ip(
                    ip_address_first_vm)
            local_interface_second_vm = \
                srv_pair[1]['server']['ssh_source'].get_nic_name_by_ip(
                    ip_address_second_vm)
            if not local_interface_first_vm and not local_interface_second_vm:
                raise ValueError('Failed to discover interfaces in VMs, ensure'
                                 ' IPv4 addresses are configured in all VMs.')
            cmd_first_vm = ("nohup sudo python3 "
                            "/tmp/scapy_async_udp_sniff_send.py"
                            " -s {iface} -d {ip} -p {l4_port}"
                            .format(iface=local_interface_first_vm,
                                    ip=ip_address_second_vm,
                                    l4_port=traffic_port))
            cmd_second_vm = ("nohup sudo python3 "
                             "/tmp/scapy_async_udp_sniff_send.py"
                             " -s {iface} -d {ip} -p {l4_port}"
                             .format(iface=local_interface_second_vm,
                                     ip=ip_address_first_vm,
                                     l4_port=traffic_port))
            srv_pair[0]['server']['ssh_source'].exec_command(
                cmd_first_vm + "&")
            srv_pair[1]['server']['ssh_source'].exec_command(
                cmd_second_vm + "&")
        for sv in srv_pair:
            errors += \
                self.check_conntrack_table(hyper=sv['server']['hypervisor_ip'],
                                           source=sv['network']['ip_address'],
                                           protocol=protocol,
                                           l4_port=traffic_port)

        for item in iperf_logs:
            shell_utils.stop_iperf(item['server'], item['log_file'])
        return errors

    def check_conntrack_table(self, hyper, source, protocol, l4_port):
        """Check connection tracking is offloaded

        Reads conntrack table to see if connection tracking is offloaded.
        :param hyper: hypervisor IP
        :param source: source IP
        :param protocol: protocol to test (tcp, udp)
        :param l4_port: transport protocol

        :return errors: list with errors found
        """
        errors = []
        conntrack_table_string = shell_utils.get_conntrack_table(hyper)
        regex = \
            re.compile(r'.*{pr}.*src={s_ip}.*sport={p}.*\[HW_OFFLOAD\].*'
                       .format(pr=protocol,
                               s_ip=source,
                               p=l4_port))
        test = regex.search(conntrack_table_string)
        if not test:
            errors.append("connection tracking for session protocol '{}' "
                          "with ip '{}' was not offloaded"
                          .format(protocol, source))
        return errors

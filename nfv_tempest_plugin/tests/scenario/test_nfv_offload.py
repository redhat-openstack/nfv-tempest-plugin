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

import random
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

    def test_offload_icmp_vlan_trunk(self, test='offload_icmp_vlan_trunk'):
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
        self.run_offload_testcase(test, "icmp", "vlan_trunk")

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

    def test_offload_udp_vlan_trunk(self, test='offload_udp_vlan_trunk'):
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
        self.run_offload_testcase(test, "udp", "vlan_trunk")

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

    def test_offload_tcp_vlan_trunk(self, test='offload_tcp_vlan_trunk'):
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
        self.run_offload_testcase(test, "tcp", "vlan_trunk")

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
                             geneve, vlan_trunk, transparent_vlan)
        :return filtered network list
        """
        filtered_networks = []

        for network in test_networks:
            if (('mgmt' in network.keys() and network['mgmt']) or
                    (network['network_type'] == network_type) or
                    (network_type == 'vlan_trunk' and
                     'trunk_vlan' in network.keys()) or
                    (network_type == 'transparent_vlan' and
                     'transparent_vlan' in network.keys())):
                filtered_networks.append(network)

        return filtered_networks

    def run_offload_testcase(self, test, protocol, network_type):
        """Run offload testcase with different injection traffic

        This function will create resources needed to run offload
        testcases including test networks and vms. Then it will
        inject traffic (tcp, udp or icmp), it will check flows and
        traffic in representor port and it will report if the
        behaviour was as expected

        :param test: Test name from the external config file.
        :param protocol: Protocol to test (udp, tcp, icmp)
        :param network_type: network used (vlan, vxlan,
                             geneve, vlan_trunk, transparent_vlan)
        """
        num_vms = int(CONF.nfv_plugin_options.offload_num_vms)
        offload_injection_time = int(
            CONF.nfv_plugin_options.offload_injection_time)
        tcpdump_time = int(CONF.nfv_plugin_options.tcpdump_time)
        LOG.info('test_offload_ovs_flows create {} vms'.format(num_vms))

        # only needed networks will be created
        full_test_network = self.external_config['test-networks']
        self.external_config['test-networks'] = \
            self.filter_test_networks(full_test_network, network_type)

        # Create servers
        servers, key_pair = self.create_and_verify_resources(
            test=test, num_servers=num_vms)

        # Requiered at least 2 servers (server, client)
        # There may be more servers, in this case server 0 will be the iperf
        # server and server 1,2,3, ... will be the iperf client
        for server in servers:
            server['ssh_source'] = self.get_remote_client(
                server['fip'],
                username=self.instance_user,
                private_key=key_pair['private_key'])

        errors_found = []
        network_type_found = False
        # iterate servers
        for server in servers[1:]:
            # iterate networks
            for provider_network in server['provider_networks']:

                if provider_network['provider:network_type'] != network_type:
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
            elif protocol == "udp":
                udp_packets = [0, 0]
                udp_packets[0] = tcpdump[0].count('UDP')
                udp_packets[1] = tcpdump[1].count('UDP')
                # At least one packet expected (single flow)
                if udp_packets[0] > 0 and udp_packets[1] == 0:
                    pass
                else:
                    errors.append("{} Failed to check packets in representor "
                                  "port. UDP packets: {} (>0), {} (0)".
                                  format(msg_header,
                                         udp_packets[0],
                                         udp_packets[1]))
            elif protocol == "tcp":
                tcp_packets = [0, 0]
                tcp_packets[0] = tcpdump[0].count('IPv4')
                tcp_packets[1] = tcpdump[1].count('IPv4')
                # At least two packets expected (one per direction,
                # single flow)
                if tcp_packets[0] > 1 and tcp_packets[1] == 0:
                    pass
                else:
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

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
        self.assertItemsEqual(expected_result, result, msg)

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
        self.assertItemsEqual(expected_result, result, msg)

    def test_offload_icmp(self, test='offload_icmp'):
        """Check ICMP traffic is offloaded

        The following test deploy vms, on hw-offload computes.
        It sends async ping and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single packet por icmp
        reply/request. As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_offload_icmp test.')
        self.run_offload_testcase(test, "icmp")

    def test_offload_udp(self, test='offload_udp'):
        """Check UDP traffic is offloaded

        The following test deploy vms, on hw-offload computes.
        It sends UDP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be a single UDP packet.
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_offload_udp test.')
        self.run_offload_testcase(test, "udp")

    def test_offload_tcp(self, test='offload_tcp'):
        """Check TCP traffic is offloaded

        The following test deploy vms, on hw-offload computes.
        It sends TCP traffic and check offload flows exist in ovs.
        It will also capture traffic in representor port in both
        hypervisors. There should be 2 TCP packets (one per direction).
        As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """
        LOG.info('Start test_offload_tcp test.')
        self.run_offload_testcase(test, "tcp")

    def run_offload_testcase(self, test, protocol):
        """Run offload testcase with different injection traffic

        This function will create resources needed to run offload
        testcases including test networks and vms. Then it will
        inject traffic (tcp, udp or icmp), it will check flows and
        traffic in representor port and it will report if the
        behaviour was as expected

        :param test: Test name from the external config file.
        :param protocol: Protocol to test (udp, tcp, icmp)
        """
        num_vms = int(CONF.nfv_plugin_options.offload_num_vms)
        offload_injection_time = int(
            CONF.nfv_plugin_options.offload_injection_time)
        LOG.info('test_offload_ovs_flows create {} vms'.format(num_vms))
        # Create servers
        servers, key_pair = self.create_and_verify_resources(
            test=test, num_servers=num_vms)

        # ssh connection to vm for executing ping (icmp)
        # or iperf server (tcp, upd)
        servers[0]['ssh_source'] = self.get_remote_client(
            servers[0]['fip'],
            username=self.instance_user,
            private_key=key_pair['private_key'])
        # ssh connection to vm for executing iperf client (tcp, upd)
        servers[1]['ssh_source'] = self.get_remote_client(
            servers[1]['fip'],
            username=self.instance_user,
            private_key=key_pair['private_key'])

        errors_found = []
        # iterate servers
        for server in servers[1:]:
            # iterate networks
            for provider_network in server['provider_networks']:

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
                                                   offload_injection_time)

        self.assertTrue(len(errors_found) == 0, "\n".join(errors_found))

    def check_offload(self, srv_pair, protocol, duration):
        """Check OVS offloaded flows and hw offload is working

        Two tests are done:
        - check offload is configured in the flows
        - check that there are no packets in the representor port. Only first
          packets must be present

        :param srv_pair: server/client data
        :param protocol: protocol to test (icmp, tcp, udp)
        :param duration: duration of the injection
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
            iperf_logs.append({'server': srv_pair[0]['network']['ip_address'],
                               'log_file': log})
            log = shell_utils.iperf_client(
                srv_pair[0]['network']['ip_address'],
                iperf_port, duration, protocol,
                srv_pair[1]['server']['ssh_source'])
            iperf_logs.append({'server': srv_pair[0]['network']['ip_address'],
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
                              format(msg_header, srv_item['network']['mac_address']))
            if 'offloaded:yes, dp:tc' not in offload_flows:
                errors.append("{} 'offloaded:yes, dp:tc' missing in flows".
                              format(msg_header))

            # check tcpdump output. Only first packet should be going
            # through representor port. Once offload is working, there
            # should be no packet in representor port
            tcpdump_out = shell_utils.stop_tcpdump(
                srv_item['server']['hypervisor_ip'],
                srv_item['tcpdump_file'])

            if protocol == "icmp":
                icmp_requests = tcpdump_out.count('ICMP echo request')
                icmp_replies = tcpdump_out.count('ICMP echo reply')
                if icmp_requests != 1 or icmp_replies != 1:
                    errors.append("{} There should be a single request/reply "
                                  "in representor port. Requests: "
                                  "{}, Replies: {}".format(msg_header,
                                                           icmp_requests,
                                                           icmp_replies))
            elif protocol == "udp":
                udp_packets = tcpdump_out.count('UDP')
                if udp_packets != 1:
                    errors.append("{} There should be a single UDP packet in "
                                  "representor port. {} packets found".
                                  format(msg_header, udp_packets))
            elif protocol == "tcp":
                tcp_packets = tcpdump_out.count('IPv4')
                if tcp_packets != 2:
                    errors.append("{} There should be two TCP packets in "
                                  "representor port. {} packets found".
                                  format(msg_header, tcp_packets))

        for item in iperf_logs:
            shell_utils.stop_iperf(item['server'], item['log_file'])

        return errors

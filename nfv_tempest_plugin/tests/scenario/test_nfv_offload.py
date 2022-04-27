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

    def test_offload_udp_with_conntrack(self, test='offload_udp_conn_track'):
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
        self.run_offload_testcase(test, "udp", True)

    def test_offload_tcp_with_conntrack(self, test='offload_tcp_conn_track'):
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
        self.run_offload_testcase(test, "tcp", True)

    def run_offload_testcase(self, test, protocol, conn_track=False):
        """Run offload testcase with different injection traffic

        This function will create resources needed to run offload
        testcases including test networks and vms. Then it will
        inject traffic (tcp, udp or icmp), it will check flows and
        traffic in representor port and it will report if the
        behaviour was as expected

        :param test: Test name from the external config file.
        :param protocol: Protocol to test (udp, tcp, icmp)
        :param conn_trac: Connection tracking support
        """
        num_vms = int(CONF.nfv_plugin_options.offload_num_vms)
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
                    srv_item['vf_nic'] = shell_utils.get_vf_from_mac(
                        srv_item['network']['mac_address'],
                        srv_item['server']['hypervisor_ip'])

                errors_found += self.check_offload(srv_pair, protocol,
                                                   nf_conntrack=conn_track)

        self.assertTrue(len(errors_found) == 0, "\n".join(errors_found))

    def check_offload(self, srv_pair, protocol, nf_conntrack=False):
        """Check OVS offloaded flows and hw offload is working

        Two tests are done:
        - check offload is configured in the flows
        - check that there are no packets in the representor port. Only first
          packets must be present

        Security group rules are also created based on randomized port

        :param srv_pair: server/client data
        :param protocol: protocol to test (icmp, tcp, udp)
        :param nf_conntrack: read connection tracking table
        :return checks: list with problems found
        """

        self.assertIn(protocol, ["udp", "tcp", "icmp"],
                      "Not supported protocol {}".format(protocol))

        packet_threshold_multiplier = float(
            CONF.nfv_plugin_options.offload_representor_port_threshold)
        errors = []
        # sleep several seconds so that flows generated checking provider
        # network connectivity during resource creation are removed. Timeout
        # for flows deletion is around 10 seconds
        flows_timeout = int(CONF.nfv_plugin_options.flows_timeout)
        time.sleep(flows_timeout)

        # We set the duration as high so we would have consistent flow of data
        traffic_duration = 9999999

        # execute tcpdump in representor port in both hypervisors
        iperf_port = random.randrange(8000, 9000)
        # If security group enabled create rules
        if self.sec_groups and protocol != 'icmp':
            print("Creating security group rules")
            offload_sec_rules = [
                {
                    'direction': 'ingress',
                    'protocol': protocol,
                    'remote_ip_prefix': '0.0.0.0/0'
                },
                {
                    'direction': 'egress',
                    'protocol': protocol,
                    'remote_ip_prefix': '0.0.0.0/0'
                }
            ]
            # Apply security group if not ICMP
            for rule in offload_sec_rules:
                rule['port_range_min'] = rule['port_range_max'] = \
                    iperf_port
            secgroup = \
                self.get_security_group_from_partial_string(
                        group_name_string='tempest')
            # Allow port in security group
            self.add_security_group_rules(secgroup_id=secgroup['id'],
                                          rule_list=offload_sec_rules)
        for srv_item in srv_pair:
            srv_item['tcpdump_file'] = shell_utils.tcpdump(
                srv_item['server']['hypervisor_ip'],
                srv_item['vf_nic'],
                protocol,
                traffic_duration,
                None if protocol == 'icmp' else iperf_port)

        # Delete all flows from hypervisor
        shell_utils.run_command_over_ssh(srv_item['server']['hypervisor_ip'],
                                         'sudo ovs-appctl dpctl/del-flows')

        # send traffic
        LOG.info('Sending traffic ({}) from {} to {}'.
                 format(protocol, srv_pair[0]['network']['ip_address'],
                        srv_pair[1]['network']['ip_address']))
        if protocol == "icmp":
            shell_utils.continuous_ping(
                srv_pair[1]['network']['ip_address'],
                duration=traffic_duration,
                ssh_client_local=srv_pair[0]['server']['ssh_source'])
        elif protocol in ["tcp", "udp"]:
            shell_utils.iperf_server(
               srv_pair[0]['network']['ip_address'],
               iperf_port, traffic_duration, protocol,
               srv_pair[0]['server']['ssh_source'])
            shell_utils.iperf_client(
               srv_pair[0]['network']['ip_address'],
               iperf_port, traffic_duration, protocol,
               srv_pair[1]['server']['ssh_source'])

        for srv_item in srv_pair:
            # check flows in both hypervisors
            offload_flows = shell_utils.get_offload_flows(
                srv_item['server']['hypervisor_ip'])
            port = self.get_port_from_ip(srv_item['network']['ip_address'])
            msg_header = "network_type {}, hypervisor {}, vm ip {} " \
                         "protocol {}.".\
                format(srv_item['network']['provider:network_type'],
                       srv_item['server']['hypervisor_ip'],
                       srv_item['network']['ip_address'],
                       protocol)
            print(offload_flows)
            # if ('capabilities' not in port['binding:profile'] or 'switchdev'
            #        not in port['binding:profile']['capabilities']):
            #    errors.append("{} Port does not have capabilities configured".
            #                  format(msg_header))
            # if port['mac_address'] not in offload_flows:
            #     errors.append("{} mac address {} not in offload flows".
            #                   format(msg_header, port['mac_address']))
            # if 'offloaded:yes, dp:tc' not in offload_flows:
            #     errors.append("{} 'offloaded:yes, dp:tc' missing in flows".
            #                   format(msg_header))

            # check tcpdump output, small amount of packets should be going
            # through representor port. Once offload is working, there
            # should be minimal packets in representor port
            tcpdump_out = shell_utils.stop_tcpdump(
                srv_item['server']['hypervisor_ip'],
                srv_item['tcpdump_file'])
            offload_flows_list = offload_flows.rstrip().split('\n')

            if protocol == "icmp":
                ovs_shorthand_protocol = '1'
                icmp_requests = tcpdump_out.count('ICMP echo request')
                icmp_replies = tcpdump_out.count('ICMP echo reply')
                if icmp_requests != 1 or icmp_replies != 1:
                    errors.append("{} There should be a single request/reply "
                                  "in representor port. Requests: "
                                  "{}, Replies: {}".format(msg_header,
                                                           icmp_requests,
                                                           icmp_replies))
            elif protocol == "udp":
                ovs_shorthand_protocol = '17'
                udp_packets = tcpdump_out.count('UDP')
                if udp_packets != 1:
                    errors.append("{} There should be a single UDP packet in "
                                  "representor port. {} packets found".
                                  format(msg_header, udp_packets))
            elif protocol == "tcp":
                ovs_shorthand_protocol = '6'
                tcp_packets = tcpdump_out.count('IPv4')
                if tcp_packets != 2:
                    errors.append("{} There should be two TCP packets in "
                                  "representor port. {} packets found".
                                  format(msg_header, tcp_packets))

            if nf_conntrack:
                conn_track_errors = self.check_conntrack_offload(
                    srv_item['server']['hypervisor_ip'],
                    port,
                    protocol,
                    iperf_port)
                errors += conn_track_errors

        return errors

    def parse_hardware_offload_flow(flow_string):
        """Constructs a tuple describing provided offload flow

        :param flow_string: offload flow string
        :retrun flow_tuple: tuple of flow
        """
        pass

    def check_conntrack_offload(self, hyper, vm_port, protocol, l4_port):
        """Check connection tracking is offloaded

        Reads conntrack table to see if connection tracking is offloaded.

        :param hyper: hypervisor IP
        :param vm_port: port object
        :param protocol: protocol to test (icmp, tcp, udp)
        :param l4_port: transport protocol
        :return checks: list with problems found
        """

        #import ipdb;ipdb.set_trace()
        errors = []
        source_ip = vm_port['fixed_ips'][0]['ip_address']
        conntrack_table_string = shell_utils.get_conntrack_table(hyper)
        regex = \
            re.compile(r'.*{pr}.*src={s_ip}.*sport={p}.*\[HW_OFFLOAD\].*'
                       .format(pr=protocol,
                               s_ip=source_ip,
                               p=l4_port))
        test = regex.search(conntrack_table_string)
        if not test:
            errors.append("connection tracking for session protocol '{}' "
                          "with ip '{}' was not offloaded"
                          .format(protocol, source_ip))
        else:
            print(test.string)
        return errors

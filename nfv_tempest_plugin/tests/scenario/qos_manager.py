# Copyright 2018 Red Hat, Inc.
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
import time

from enum import IntEnum
from math import ceil
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from oslo_log import log
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

CONF = config.CONF
LOG = log.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class QoSManagerMixin(object):
    class Servers(IntEnum):
        CLIENT_1 = 0
        CLIENT_2 = 1
        SERVER = 2

    # Unit conversion from iperf report to os qos units [10^6]
    KBYTES_TO_MBITS = 10 ** 6
    LOG_5102 = "/tmp/listen-5102.txt"
    LOG_5101 = "/tmp/listen-5101.txt"

    def create_network_qos_policy(self, namestart='qos-policy'):
        """Creates a network QoS policy"""
        qos_client = self.os_admin.qos_client
        result = qos_client.create_qos_policy(
            name=data_utils.rand_name(namestart))
        self.assertIsNotNone(result, 'Unable to create policy')
        qos_policy = result['policy']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        qos_client.delete_qos_policy,
                        qos_policy['id'])
        return qos_policy

    def create_min_bw_qos_rule(self, policy_id=None, min_kbps=None,
                               direction='egress'):
        """Creates a minimum bandwidth QoS rule

        NOTE: Not all kernel versions support minimum bandwidth for all
        NIC drivers.

        Only egress (guest --> outside) traffic is currently supported.

        :param policy_id
        :param min_kbps: Minimum kbps bandwidth to apply to rule
        :param direction: Traffic direction that the rule applies to
        """
        SUPPORTED_DIRECTIONS = 'egress'
        if not policy_id:
            self.assertNotEmpty(self.qos_policy_groups,
                                'Unable to create_min_bw_qos_rule '
                                'self.qos_policy_groups is Empty')
            policy_id = self.qos_policy_groups[0]['id']
        if direction not in SUPPORTED_DIRECTIONS:
            raise ValueError('{d} is not a supported direction, supported '
                             'directions: {s_p}'
                             .format(d=direction,
                                     s_p=SUPPORTED_DIRECTIONS.join(', ')))
        qos_min_bw_client = self.os_admin_v2.qos_minimum_bandwidth_rules_client
        result = qos_min_bw_client.create_minimum_bandwidth_rule(
            policy_id, **{'min_kbps': min_kbps, 'direction': direction})
        self.assertIsNotNone(result, 'Unable to create minimum bandwidth '
                                     'QoS rule')
        qos_rule = result['minimum_bandwidth_rule']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            qos_min_bw_client.delete_minimum_bandwidth_rule, policy_id,
            qos_rule['id'])

    def create_max_bw_qos_rule(self, policy_id=None, max_kbps=None,
                               max_burst_kbps=None,
                               direction='egress'):
        """Creates a maximum bandwidth QoS rule

        Only egress (guest --> outside) traffic is currently supported.

        :param policy_id
        :param max_kbps: Maximum kbps bandwidth to apply to rule
        :param max_burst_kbps: max burst bandwidth to apply to rule
        :param direction: Traffic direction that the rule applies to
        """

        SUPPORTED_DIRECTIONS = 'egress'
        if not policy_id:
            self.assertNotEmpty(self.qos_policy_groups,
                                'Unable to create_max_bw_qos_rule '
                                'self.qos_policy_groups is Empty')
            policy_id = self.qos_policy_groups[0]['id']
        if direction not in SUPPORTED_DIRECTIONS:
            raise ValueError('{d} is not a supported direction, supported '
                             'directions: {s_p}'
                             .format(d=direction,
                                     s_p=SUPPORTED_DIRECTIONS.join(', ')))
        bw_rules = {'direction': direction,
                    'max_kbps': max_kbps,
                    'max_burst_kbps': max_burst_kbps}
        qos_max_bw_client = self.os_admin_v2.qos_limit_bandwidth_rules_client
        result = qos_max_bw_client.create_limit_bandwidth_rule(policy_id,
                                                               **bw_rules)
        self.assertIsNotNone(result, 'Unable to create maximum bandwidth '
                                     'QoS rule')
        qos_rule = result['bandwidth_limit_rule']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            qos_max_bw_client.delete_limit_bandwidth_rule, policy_id,
            qos_rule['id'])

    def create_qos_policy_with_rules(self, use_default=True, **kwargs):
        """Create_qos_policy with rules

        :param kwargs:
            kwargs['max_kbps']: parameter indicates maximum qos requested
            kwargs['min_kbps']: parameter indicates minimum qos requested
        :param use_default: parameter use self.qos_policy_groups for the test
        """
        qos_policy_groups = \
            self.create_network_qos_policy()
        if use_default:
            self.qos_policy_groups = qos_policy_groups
            self.assertNotEmpty(self.qos_policy_groups,
                                'Unable to qos policy '
                                'self.qos_policy_groups is Empty')
        if 'min_kbps' in kwargs:
            # In some backends (when TC is used) it is needed to configure
            # max-bw(ceil) in order to be able to configure min-bw(rate)
            # we set max_rate 10% more than min rate for testing
            max_rate = int(kwargs['min_kbps'] * 1.1)
            self.create_max_bw_qos_rule(
                policy_id=qos_policy_groups['id'],
                max_kbps=max_rate, max_burst_kbps=max_rate)
            self.create_min_bw_qos_rule(
                policy_id=qos_policy_groups['id'],
                min_kbps=kwargs['min_kbps'])
            kwargs.pop('min_kbps')
        if 'max_kbps' in kwargs:
            self.create_max_bw_qos_rule(
                policy_id=qos_policy_groups['id'],
                **kwargs)
        return qos_policy_groups

    def check_qos_attached_to_guest(self, server, min_bw=False):
        """Check QoS attachment to guest

        This method checks if QoS is applied to an interface on hypervisor
        that is attached to guest

        :param server
        :param min_bw: Check for minimum bandwidth QoS
        """
        # Initialize parameters
        found_qos = False
        interface_data = shell_utils. \
            get_interfaces_from_overcloud_node(server['hypervisor_ip'])
        ports_client = self.os_admin.ports_client
        ports = ports_client.list_ports(device_id=server['id'])
        # Iterate over ports
        for port in ports['ports']:
            # If port has a QoS policy
            if port['qos_policy_id']:
                found_qos = True
                # Construct regular expression to locate port's MAC address
                re_string = r'.*{}.*'.format(port['mac_address'])
                line = re.search(re_string, interface_data)
                # Failed to locate MAC address on hypervisor
                if not line:
                    raise ValueError("Failed to locate interface with MAC "
                                     "'{}' on hypervisor"
                                     .format(port['mac_address']))
                line = line.group(0)
                # Check minimum bandwidth QoS
                if min_bw:
                    qos_min_bw_client = self.os_admin.qos_min_bw_client
                    min_qos_rule = \
                        qos_min_bw_client.list_minimum_bandwidth_rules(
                            port['qos_policy_id'])['minimum_bandwidth_rules']
                    # OpenStack API displays the size in Kbps
                    min_kbps = min_qos_rule[0]['min_kbps']
                    # Construct string to match Linux operating system
                    min_mbps = str(int(ceil(min_kbps / 1000)))
                    min_mbps = '{}Mbps'.format(min_mbps)
                    # Linux operating system displays the size in Mbps
                    qos = re.search(r'min_tx_rate \w+', line)
                    # Failed to locate min QoS
                    if not qos:
                        raise ValueError("Failed to dicover min QoS for "
                                         "interface with MAC '{}'"
                                         .format(port['mac_address']))
                    qos = qos.group(0)
                    # Filter QoS number
                    qos = qos.replace('min_tx_rate ', '')
                    self.assertEqual(min_mbps, qos)
        if not found_qos:
            raise ValueError('No QoS policies were applied to ports')

    def run_iperf_test(self, qos_policies=[], servers=[], key_pair=[],
                       network_id=None, vnic_type='normal'):
        """run_iperf_test

        This method receive server list, and prepare machines for iperf
        and run test commands in server and clients

        :param qos_policies qos policy created for servers
        :param servers servers list, at least 3
        :param key_pair servers key pairs
        :param network_id network_id to use
        :param vnic_type vnic_type to use
        """
        if not servers:
            servers = self.servers
        srv = QoSManagerMixin.Servers
        servers_ports_map = \
            [self.os_admin.ports_client.list_ports(
                device_id=server['id']) for server in servers]

        # Find machines ports based on type
        if network_id is None:
            tested_ports = [shell_utils.find_vm_interface(
                ports, vnic_type=vnic_type) for ports in servers_ports_map]
        else:
            tested_ports = [shell_utils.find_vm_interface_network_id(
                ports, network_id=network_id) for ports in servers_ports_map]

        # Bind to iperf server ip_addr
        ip_addr = tested_ports[srv.SERVER][1]
        # Set pors with QoS
        LOG.info('Update client ports with QoS policies...')
        # Assume server is the last server index 2,
        # In case one policy parsed, CLIENT_1 is the tested port
        [self.update_port(
            tested_ports[i][0],
            **{'qos_policy_id': qos_policies[i]['id']})
            for i in range((len(self.servers) - 1)
                           and len(qos_policies))]

        LOG.info('Run iperf server on server3...')
        ssh_dest = self.get_remote_client(servers[srv.SERVER]['fip'],
                                          username=self.instance_user,
                                          private_key=key_pair[
                                              'private_key'])
        # change mtu, workaround https://issues.redhat.com/browse/OSPRH-5356
        install_iperf_command = "sudo ip link set mtu 1400 eth0 || echo"
        install_iperf_command += ";sudo yum install iperf3 -y || echo"
        install_iperf_command += ";sudo yum install iperf -y || echo"
        ssh_dest.exec_command(install_iperf_command)

        LOG.info('Installing iperf on Server1...')
        ssh_source1 = self. \
            get_remote_client(servers[srv.CLIENT_1]['fip'],
                              username=self.instance_user,
                              private_key=key_pair['private_key'])
        ssh_source1.exec_command(install_iperf_command)
        LOG.info('Installing iperf on Server2...')
        ssh_source2 = self. \
            get_remote_client(servers[srv.CLIENT_2]['fip'],
                              username=self.instance_user,
                              private_key=key_pair['private_key'])
        ssh_source2.exec_command(install_iperf_command)

        LOG.info('Receive iperf traffic from Server3...')
        shell_utils.iperf_server(ip_addr, 5101, 90, "tcp", ssh_dest,
                                 QoSManagerMixin.LOG_5101)
        shell_utils.iperf_server(ip_addr, 5102, 90, "tcp", ssh_dest,
                                 QoSManagerMixin.LOG_5102)

        LOG.info('Send iperf traffic from Server1...')
        shell_utils.iperf_client(ip_addr, 5101, 60, "tcp", ssh_source1)
        LOG.info('Send iperf traffic from Server2...')
        shell_utils.iperf_client(ip_addr, 5102, 60, "tcp", ssh_source2)

        # wait for iperf to finish
        time.sleep(90)

    def collect_iperf_results(self, qos_rules_list=[],
                              servers=[], key_pair=[]):
        """collect_iperf_results

        This method receive server list, ssh to iperf server and collect
        iperf reports and compare it to QoS rules created for clients ports

        :param qos_rules_list qos rules list fpr tested ports
        :param servers servers list, at least 3
        :param key_pair servers key pairs
        """
        srv = QoSManagerMixin.Servers
        log_files = [QoSManagerMixin.LOG_5101, QoSManagerMixin.LOG_5102]

        LOG.info('Collect iperf logs from iperf server, server3...')

        # This format
        # [ID]    Interval        Transfer     Bitrate
        # [ 5]    0.00-11.77 sec  5.93 GBytes  4.32 Gbits/sec       receiver
        # or this other format
        # [ ID]    Interval        Transfer     Bitrate
        # [  5]    0.00-50.22 sec  53.5 GBytes  9.15 Gbits/sec       iperf3: interrupt - the server has terminated # noqa
        # receiver
        # or this format (no receiver tag)
        # [ ID] Interval       Transfer     Bandwidth
        # [  4]  0.0-60.0 sec  28.2 GBytes  4.04 Gbits/sec
        command = r"(grep -B 1 receiver {} || tail -1 {})"
        command += r" | grep  Gbits | awk '{print $7}'"
        # Receive result with number
        ssh_dest = self.get_remote_client(servers[srv.SERVER]['fip'],
                                          username=self.instance_user,
                                          private_key=key_pair[
                                              'private_key'])
        # Assert result
        for index in range(srv.SERVER):
            # If Default QoS, such as min_bw check only srv.CLIENT_1
            if len(self.qos_policy_groups) > 0 and index == srv.CLIENT_2:
                break
            rate = ssh_dest. \
                exec_command(command.replace('{}', log_files[index]))

            self.assertNotEmpty(
                rate, "Please check QoS definitions, iperf result for "
                "in file {} is empty or low".format(log_files[index]))

            qos_type = 'max_kbps'
            # In case of min_bw only one policy is set
            if 'min_kbps' in qos_rules_list[srv(index)]:
                qos_type = 'min_kbps'
            LOG.info('test_type {}, result_number {}, rate_limit {}'
                     .format(qos_type, float(rate),
                             qos_rules_list[srv(index)][qos_type]))
            self.calculate_deviation(test_type=qos_type,
                                     result_number=float(rate),
                                     rate_limit=qos_rules_list[
                                         srv(index)][qos_type])

    def calculate_deviation(self, test_type, rate_limit, result_number,
                            max_deviation_accepted=0.1):
        """Calculate deviation for a result number for a rate limit number

        Method supports two test types - max_kbps and min_kbps.
        For the max_kbps, the given number could be above the given rate limit
        within the accepted deviation number.
        For the min_kbps, the given number could be below the given rate limit
        within the accepted deviation number.

        :param test_type: One of two available test types - max_kbps/min_kbps
        :type test_type: str
        :param rate_limit: Limit rate for a given number. Depends on test type
        :type rate_limit: int
        :param result_number: A result number to calculate the deviation
        :type result_number: int
        :param max_deviation_accepted: Accepted deviation, defaults to 0.1
        :type max_deviation_accepted: float, optional
        """
        kbytes_to_mbits = QoSManagerMixin.KBYTES_TO_MBITS
        deviation = abs(result_number * kbytes_to_mbits / rate_limit - 1)
        err_msg = 'The number - {} deviates more than accepted deviation - {}'
        if test_type == "max_kbps" and (result_number * kbytes_to_mbits
                                        > rate_limit):
            self.assertLess(deviation, max_deviation_accepted,
                            err_msg.format(deviation, max_deviation_accepted))
        if test_type == "min_kbps" and (result_number * kbytes_to_mbits
                                        < rate_limit):
            self.assertLess(deviation, max_deviation_accepted,
                            err_msg.format(deviation, max_deviation_accepted))
        LOG.info('The test result number - {} with deviation - {}'
                 .format(result_number, deviation))
        return

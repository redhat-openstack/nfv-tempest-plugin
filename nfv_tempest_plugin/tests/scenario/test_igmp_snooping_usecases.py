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
from tempest import config

import json
import random
import string
import time

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestIgmpSnoopingScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestIgmpSnoopingScenarios, self).__init__(*args, **kwargs)
        self.instance = None
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestIgmpSnoopingScenarios, self).setUp()
        """ pre setup creations and checks read from config files """

    def test_deployment_igmp_snooping(self, test='deployment_igmp_snooping',
                                      hypervisor_ip=None):
        """Check that igmp snooping bonding is properly configure

        mcast_snooping_enable and mcast-snooping-disable-flood-unregistered
        configured in br-int
        """
        LOG.info('Starting deployment_igmp_snooping test.')

        if hypervisor_ip is None:
            hypervisor_ip = self._get_hypervisor_ip_from_undercloud(
                shell='/home/stack/stackrc')[0]
        cmd = 'sudo ovs-vsctl --format=json list bridge br-int'
        output = self._run_command_over_ssh(hypervisor_ip, cmd)
        # ovs command returns boolean in small letters
        ovs_data = json.loads(output)
        ovs_data_filtered = {}
        try:
            ovs_data_filtered['mcast_snooping_enable'] = \
                (ovs_data['data'][0]
                 [ovs_data['headings'].index('mcast_snooping_enable')])
            ovs_data_filtered['mcast-snooping-disable-flood-unregistered'] = \
                (dict(ovs_data['data'][0]
                      [ovs_data['headings'].index('other_config')][1])
                 ['mcast-snooping-disable-flood-unregistered'])
        except Exception:
            pass

        checks = {'mcast_snooping_enable': True,
                  'mcast-snooping-disable-flood-unregistered': 'true'}

        result = []
        diff_checks_cmd = set(checks.keys()) - set(ovs_data_filtered.keys())
        if len(diff_checks_cmd) > 0:
            result.append("Missing checks: {}. Check ovs commands "
                          "output".format(', '.join(diff_checks_cmd)))

        for check in checks:
            if check not in diff_checks_cmd:
                if ovs_data_filtered[check] != checks[check]:
                    result.append("Check failed: {}, Expected: {} - "
                                  "Found: {}".format(check,
                                                     checks[check],
                                                     ovs_data_filtered[check]))
        self.assertTrue(len(result) == 0, '. '.join(result))
        return True

    def test_igmp_snooping(self, test='igmp_snooping'):
        """Test igmp snooping

        Create 3 VMS on compute0 and 3 on compute1
        """
        LOG.info('Starting igmp_snooping test.')

        if self.external_resources_data is None:
            raise ValueError('External resource data is required for the test')

        servers, key_pair = self.create_and_verify_resources(test=test)
        if len(servers) != 3:
            raise ValueError('The test requires 3 instances.')

        errors = []

        # get the ports name used for sending/reciving multicast traffic
        # it will be a different port than the management one that will be
        # connected to a switch in which igmp snooping is configured
        port_list = self.get_ovs_port_names(servers)

        # groups to be used
        mcast_groups = [{'group': '239.0.0.1', 'port': '10000', 'tx_pkts': 200},
                        {'group': '238.0.0.5', 'port': '5000', 'tx_pkts': 300}]
        for group in mcast_groups:
            group['listeners'] = 0
            group['traffic-runners'] = 0
            group['rx_pkts'] = 0
            group['msg'] = ''.join(random.choice(string.ascii_lowercase)
                                   for i in range(20))
        # servers to be used
        servers[0]['mcast'] = [{'role' : 'traffic-runner', 'group': 0},
                               {'role' : 'listener', 'group': 1}]
        servers[1]['mcast'] = [{'role' : 'traffic-runner', 'group': 1},
                               {'role' : 'listener', 'group':0}]
        servers[2]['mcast'] = [{'role' : 'listener', 'group': 0},
                               {'role' : 'listener', 'group': 1}]

        # get ssh conection, calculate number of traffic runners/listeners
        for server in servers:
            server['ssh_source'] = self.get_remote_client(server['fip'],
                                                          username=self.instance_user,
                                                          private_key=key_pair[
                                                          'private_key'])
            for idx, role in enumerate(server['mcast']):
                role['mcast_output'] = '/tmp/output-{}'.format(idx)
                if role['role'] == 'traffic-runner':
                    mcast_groups[role['group']]['traffic-runners']+=1
                    mcast_groups[role['group']]['rx_pkts']+=mcast_groups[role['group']]['tx_pkts']
                elif role['role'] == 'listener':
                    mcast_groups[role['group']]['listeners']+=1
                LOG.info('Server {}: role {}, group: {}:{}, msg: {}'\
                    .format(server['fip'],
                            role['role'],
                            mcast_groups[role['group']]['group'],
                            mcast_groups[role['group']]['port'],
                            mcast_groups[role['group']]['msg']))

        # calculate traffic in each interface
        pkts_tolerance = 50
        for server in servers:
            server['tx_pkts'] = 0
            server['rx_pkts'] = 0
            for role in server['mcast']:
                if role['role'] == 'traffic-runner':
                    group = role['group']
                    server['tx_pkts']+=mcast_groups[group]['tx_pkts']
                elif role['role'] == 'listener':
                    group = role['group']
                    server['rx_pkts']+=mcast_groups[group]['rx_pkts']

        # kill multicast process if it exists
        kill_cmd = "pids=$(ps -e -o \"cmd:50 \" -o \"|%p\" | " \
            "awk -F '|' '$1 ~ /multicast/ { print $2}');" \
            "if [[ ! -z $pids ]];then sudo kill -9 $pids;fi;"
        for server in servers:
            server['ssh_source'].exec_command(kill_cmd)

        # start listeners
        for server in servers:
            for role in server['mcast']:
                if role['role'] == 'listener':
                    group = role['group']
                    receive_cmd = 'sudo python /usr/local/bin/multicast_traffic.py -r ' \
                                  '-g {0} -p {1} -c {2} > {3} 2>&1 &'.format(mcast_groups[group]['group'],
                                                                             mcast_groups[group]['port'],
                                                                             mcast_groups[group]['tx_pkts'],
                                                                             role['mcast_output'])
                    server['ssh_source'].exec_command(receive_cmd)

        # check groups are created
        for group in mcast_groups:
            groups = self.get_ovs_multicast_groups("br-int", group['group'])
            if len(groups) != group['listeners']:
                errors.append("Multicast groups not created properly: " +
                              "{} {}. ".format(mcast_groups[group]['group'],
                                               mcast_groups[group]['port']))
        # start servers
        stats_begin = self.get_ovs_interface_statistics(port_list)
        for server in servers:
            for role in server['mcast']:
                if role['role'] == 'traffic-runner':
                    group = role['group']
                    send_cmd = 'sudo python /usr/local/bin/multicast_traffic.py -s ' \
                               '-g {0} -p {1} -m {2} -c {3} > {4} 2>&1 &'.format(mcast_groups[role['group']]['group'],
                                                                                 mcast_groups[role['group']]['port'],
                                                                                 mcast_groups[role['group']]['msg'],
                                                                                 mcast_groups[role['group']]['tx_pkts'],
                                                                                 role['mcast_output'])
                    server['ssh_source'].exec_command(send_cmd)

        # sleep to be sure traffic has been sent
        time.sleep(3)
        stats_end = self.get_ovs_interface_statistics(port_list, stats_begin)

        # check groups has been removed
        for group in mcast_groups:
            for val in range(1, 5):
                groups = self.get_ovs_multicast_groups("br-int", group['group'])
                if len(groups) == 0:
                    break
                time.sleep(2)
            if len(groups) != 0:
                errors.append("Multicast groups not released properly: {} {}. " \
                    .format(group['group'],
                            group['port']))

        # check traffic in listener and traffic runner interfaces
        for server in servers:
            tx_pkts_mcast = stats_end[server['other_port']]['tx_packets']
            rx_pkts_mcast = stats_end[server['other_port']]['rx_packets']
            tx_pkts_mgmt = stats_end[server['mgmt_port']]['tx_packets']
            rx_pkts_mgmt = stats_end[server['mgmt_port']]['rx_packets']

            LOG.info('{} Multicast Traffic stats, tx_pkts: {}, rx_pkts {}'\
                .format(server['fip'],
                        tx_pkts_mcast,
                        rx_pkts_mcast))
            LOG.info('{} Management Traffic stats, tx_pkts: {}, rx_pkts {}.'\
                .format(server['fip'],
                        tx_pkts_mgmt,
                        rx_pkts_mgmt))
            if not (rx_pkts_mcast >= server['tx_pkts'] and
                    rx_pkts_mcast <= (server['tx_pkts'] + pkts_tolerance)):
                errors.append("No traffic in traffic runner {}: {}. ".format(
                    server['fip'],rx_pkts_mcast))
            if not (tx_pkts_mcast >= server['rx_pkts'] and
                    tx_pkts_mcast <= server['rx_pkts'] + pkts_tolerance):
                errors.append("No traffic in listener {}: {}. ".format(
                    server['fip'], tx_pkts_mcast))

        # check that messages were received properly
        for server in servers:
            for role in server['mcast']:
                if role['role'] == 'listener':
                    get_mcast_results = 'cat {} | sort | uniq -c'.format(role['mcast_output'])
                    LOG.info('Reading results from {} instance.'
                             .format(server['fip']))
                    output = server['ssh_source'].exec_command(get_mcast_results)
                    results = output.rstrip('\n').lstrip()
                    fail_results_msg = '{} unable to receive multicast ' \
                                       'traffic: {} '.format(server['fip'],
                                                             results)
                    if results != str(mcast_groups[role['group']]['rx_pkts']) + " " + mcast_groups[role['group']]['msg']:
                        errors.append(fail_results_msg)
                    else:
                        LOG.info('{} received multicast traffic.'
                                 .format(server['fip']))

        self.assertTrue(len(errors) == 0, '. '.join(errors))
        LOG.info('Listeners received multicast traffic')
        return True

    def test_restart_ovs(self, test='restart_ovs'):
        """Test restart_ovs

        Check that config is loaded properly
        """
        LOG.info('Starting restart_ovs test.')

        hypervisor_ip = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')[0]

        cmd = 'sudo systemctl restart openvswitch.service'
        self._run_command_over_ssh(hypervisor_ip, cmd)
        self.test_deployment_igmp_snooping(hypervisor_ip=hypervisor_ip)

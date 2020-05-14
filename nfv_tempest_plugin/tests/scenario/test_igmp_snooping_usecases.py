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
from tempest import config

import json
import random
import string

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestIgmpSnoopingScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestIgmpSnoopingScenarios, self).__init__(*args, **kwargs)

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestIgmpSnoopingScenarios, self).setUp()
        """ pre setup creations and checks read from config files """

    def test_igmp_snooping_deployment(self, test='igmp_snooping_deployment'):
        """Check that igmp snooping bonding is properly configure

        mcast_snooping_enable and mcast-snooping-disable-flood-unregistered
        configured in br-int
        """
        LOG.info('Starting {} test.'.format(test))

        hypervisors = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')

        result = []
        cmd = 'sudo ovs-vsctl --format=json list bridge br-int'
        checks = {'mcast_snooping_enable': True,
                  'mcast-snooping-disable-flood-unregistered': 'true'}

        for hypervisor_ip in hypervisors:
            output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
            # ovs command returns boolean in small letters
            ovs_data = json.loads(output)
            ovs_data_filt = {}
            try:
                ovs_data_filt['mcast_snooping_enable'] = \
                    (ovs_data['data'][0]
                     [ovs_data['headings'].index('mcast_snooping_enable')])
                ovs_data_filt['mcast-snooping-disable-flood-unregistered'] = \
                    (dict(ovs_data['data'][0]
                          [ovs_data['headings'].index('other_config')][1])
                     ['mcast-snooping-disable-flood-unregistered'])
            except Exception:
                pass

            diff_checks_cmd = (set(checks.keys())
                               - set(ovs_data_filt.keys()))
            if len(diff_checks_cmd) > 0:
                result.append("{}. Missing checks: {}. Check ovs cmd output"
                              .format(hypervisor_ip,
                                      ', '.join(diff_checks_cmd)))

            for check in checks:
                if check not in diff_checks_cmd:
                    if ovs_data_filt[check] != checks[check]:
                        msg = ("{}. Check failed: {}. Expected: {} - Found: {}"
                               .format(hypervisor_ip, check, checks[check],
                                       ovs_data_filt[check]))
                        result.append(msg)

        self.assertTrue(len(result) == 0, '. '.join(result))
        return True

    def test_igmp_snooping(self, test='igmp_snooping'):
        """Test igmp snooping

           Having 2 hypervisors and 3 vms in each hypervisor. We configure a vm
           in each hypervisor sending traffic to a different group. We
           configure a different message for each group and different number of
           packets to be sent.
           Then we configure 2 vms in each hypervisor subscribed to each group.
           It is checked the following:
           - vms are properly subscribed
           - traffic in each interface in br-int
           - messages received in each vm and number of packets received
        """
        LOG.info('Starting {} test.'.format(test))

        if self.external_resources_data is None:
            raise ValueError('External resource data is required for the test')

        igmp_dict = {}
        test_setup_dict = self.test_setup_dict[test]
        if 'config_dict' in test_setup_dict and \
           'igmp_config' in test_setup_dict['config_dict']:
            igmp_dict = test_setup_dict['config_dict']['igmp_config'][0]

        if 'mcast_groups' in igmp_dict.keys() and \
           len(igmp_dict['mcast_groups']) == 2:
            pass
        else:
            raise ValueError('The test requires 2 multicast groups in '
                             'configuration file.')

        servers, key_pair = self.create_and_verify_resources(test=test)
        hypervisors = dict([[server['hypervisor_ip'], []]
                           for server in servers])
        for index, server in enumerate(servers):
            hypervisors[server['hypervisor_ip']].append(index)

        if [len(hypervisors[hyp]) for hyp in hypervisors.keys()] != [3, 3]:
            raise ValueError('The test requires 2 hypervisors and 3 vms in '
                             'each hypervisor.')

        for group in igmp_dict['mcast_groups']:
            group['rx_pkts'] = 0  # to be calculated
            group['msg'] = ''.join(random.choice(string.ascii_lowercase)
                                   for i in range(group['pkt_size']))
        # servers to be used
        hyp_0 = list(hypervisors.items())[0][1]
        hyp_1 = list(hypervisors.items())[1][1]
        servers[hyp_0[0]]['mcast'] = [{'role': 'traffic-runner', 'group': 0}]
        servers[hyp_0[1]]['mcast'] = [{'role': 'listener', 'group': 0}]
        servers[hyp_0[2]]['mcast'] = [{'role': 'listener', 'group': 1}]
        servers[hyp_1[0]]['mcast'] = [{'role': 'traffic-runner', 'group': 1}]
        servers[hyp_1[1]]['mcast'] = [{'role': 'listener', 'group': 0}]
        servers[hyp_1[2]]['mcast'] = [{'role': 'listener', 'group': 1}]

        errors = self.test_multicast_functionality(servers,
                                                   key_pair,
                                                   igmp_dict['mcast_groups'],
                                                   igmp_dict['pkts_tolerance'])

        self.assertTrue(len(errors) == 0, '. '.join(errors))
        LOG.info('Listeners received multicast traffic')

    def test_igmp_restart_ovs(self, test='igmp_restart_ovs'):
        """Test restart ovs

        Check that multicast configuration is not lost after ovs restart.
        Restart ovs and then execute test_igmp_snooping_deployment
        """
        LOG.info('Starting {} test.'.format(test))

        hypervisor_ips = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')
        cmd = 'sudo systemctl restart openvswitch.service'
        for hyp in hypervisor_ips:
            shell_utils.run_command_over_ssh(hyp, cmd)
        self.test_igmp_snooping_deployment()

    def test_multicast_functionality(self, servers, key_pair, mcast_groups,
                                     pkts_tolerance):
        """common code to test most of the igmp snooping scenarios

        Functionality:
        - create multicast traffic runners
        - create multicast listeners
        - check multicast group creation
        - calculate traffic in ech interface
        - check received traffic in each listener
        param servers: list of servers
        param key_pair: key pair to connect to servers
        param mcast_groups: multicast groups to use
        param pkts_tolerance: tolerance for counting pkts in interfaces
        return a list with errors, or empty list if everything is ok
        """

        errors = []

        # get the ports name used for sending/reciving multicast traffic
        # it will be a different port than the management one that will be
        # connected to a switch in which igmp snooping is configured
        port_list = self.get_ovs_port_names(servers)

        # populate data
        hypervisors = {}
        for server in servers:
            server['ssh_source'] = self.get_remote_client(
                server['fip'],
                username=self.instance_user,
                private_key=key_pair['private_key'])
            hyper_ip = server['hypervisor_ip']
            if hyper_ip not in hypervisors.keys():
                hyp = []
                for group in mcast_groups:
                    hyp.append({'listeners': 0, 'traffic-runners': 0})
                hypervisors[hyper_ip] = hyp
            for idx, role in enumerate(server['mcast']):
                role['mcast_output'] = '/tmp/output-{}'.format(idx)
                group = role['group']
                if role['role'] == 'traffic-runner':
                    hypervisors[hyper_ip][group]['traffic-runners'] += 1
                    mcast_groups[group]['rx_pkts'] += (
                        mcast_groups[group]['tx_pkts'])
                elif role['role'] == 'listener':
                    hypervisors[hyper_ip][group]['listeners'] += 1
                LOG.info('Server {}: role {}, group: {}:{}, msg: {}'
                         .format(server['fip'],
                                 role['role'],
                                 mcast_groups[group]['ip'],
                                 mcast_groups[group]['port'],
                                 mcast_groups[group]['msg']))

        # calculate traffic in each interface
        for server in servers:
            server['tx_pkts'] = 0
            server['rx_pkts'] = 0
            for role in server['mcast']:
                if role['role'] == 'traffic-runner':
                    group = role['group']
                    server['tx_pkts'] += mcast_groups[group]['tx_pkts']
                elif role['role'] == 'listener':
                    group = role['group']
                    server['rx_pkts'] += mcast_groups[group]['rx_pkts']

        # kill multicast process if it exists
        cmd = "pids=$(ps -e -o \"cmd:50 \" -o \"|%p\" | " \
              "awk -F '|' '$1 ~ /multicast/ { print $2}');" \
              "if [[ ! -z $pids ]];then sudo kill -9 $pids;fi;"
        for server in servers:
            server['ssh_source'].exec_command(cmd)

        # start listeners
        for server in servers:
            for role in server['mcast']:
                if role['role'] == 'listener':
                    group = role['group']
                    cmd = 'sudo python /usr/local/bin/multicast_traffic.py ' \
                          '-r -g {0} -p {1} -c {2} > {3} 2>&1 &' \
                          .format(mcast_groups[group]['ip'],
                                  mcast_groups[group]['port'],
                                  mcast_groups[group]['tx_pkts'],
                                  role['mcast_output'])
                    server['ssh_source'].exec_command(cmd)

        # check groups are created
        for hyp in hypervisors.keys():
            groups = self.get_ovs_multicast_groups("br-int", hypervisor=hyp)
            for idx, group_info in enumerate(hypervisors[hyp]):
                num_listeners = len([grp for grp in groups if
                                    grp['GROUP'] == mcast_groups[idx]['ip']])
                if num_listeners != hypervisors[hyp][idx]['listeners']:
                    errors.append("Multicast groups not created properly: "
                                  "{} {}. ".format(mcast_groups[idx]['ip'],
                                                   mcast_groups[idx]['port']))

        # start servers
        stats_beg = {}
        stats_end = {}
        for hyp in hypervisors.keys():
            stats_beg[hyp] = self.get_ovs_interface_statistics(port_list[hyp],
                                                               hypervisor=hyp)
        for server in servers:
            for role in server['mcast']:
                if role['role'] == 'traffic-runner':
                    group = role['group']
                    cmd = 'sudo python /usr/local/bin/multicast_traffic.py ' \
                          '-s -g {0} -p {1} -m {2} -c {3} > {4} 2>&1 &' \
                          .format(mcast_groups[group]['ip'],
                                  mcast_groups[group]['port'],
                                  mcast_groups[group]['msg'],
                                  mcast_groups[group]['tx_pkts'],
                                  role['mcast_output'])
                    server['ssh_source'].exec_command(cmd)

        for hyp in hypervisors.keys():
            stats_end[hyp] = self.get_ovs_interface_statistics(port_list[hyp],
                                                               stats_beg[hyp],
                                                               hypervisor=hyp)

        # check groups has been removed
        for hyp in hypervisors.keys():
            groups = self.get_ovs_multicast_groups("br-int", hypervisor=hyp)
            for idx, group_info in enumerate(hypervisors[hyp]):
                num_listeners = len([grp for grp in groups if
                                    grp['GROUP'] == mcast_groups[idx]['ip']])
                if num_listeners != 0:
                    errors.append("Multicast groups not released properly: "
                                  "{} {}. ".format(mcast_groups[idx]['ip'],
                                                   mcast_groups[idx]['port']))

        # check traffic in listener and traffic runner interfaces
        for server in servers:
            stats = stats_end[server['hypervisor_ip']]
            tx_pkts_mcast = stats[server['other_port']]['tx_packets']
            rx_pkts_mcast = stats[server['other_port']]['rx_packets']
            tx_pkts_mgmt = stats[server['mgmt_port']]['tx_packets']
            rx_pkts_mgmt = stats[server['mgmt_port']]['rx_packets']

            LOG.info('{} Multicast Traffic stats, tx_pkts: {}, rx_pkts {}'
                     .format(server['fip'], tx_pkts_mcast, rx_pkts_mcast))
            LOG.info('{} Mgmt Traffic stats, tx_pkts: {}, rx_pkts {}.'
                     .format(server['fip'], tx_pkts_mgmt, rx_pkts_mgmt))
            if not (rx_pkts_mcast >= server['tx_pkts']
                    and rx_pkts_mcast <= (server['tx_pkts'] + pkts_tolerance)):
                errors.append("No traffic in traffic runner {}: {}. ".format(
                    server['fip'], rx_pkts_mcast))
            if not (tx_pkts_mcast >= server['rx_pkts']
                    and tx_pkts_mcast <= server['rx_pkts'] + pkts_tolerance):
                errors.append("No traffic in listener {}: {}. ".format(
                    server['fip'], tx_pkts_mcast))

        # check that messages were received properly
        for server in servers:
            for role in server['mcast']:
                if role['role'] == 'listener':
                    group = role['group']
                    get_mcast_results = ('cat {} | sort | uniq -c'
                                         .format(role['mcast_output']))
                    LOG.info('Reading results from {} instance.'
                             .format(server['fip']))
                    output = server['ssh_source'].exec_command(
                        get_mcast_results)
                    results = output.rstrip('\n').lstrip()
                    fail_results_msg = '{} unable to receive multicast ' \
                                       'traffic: {} '.format(server['fip'],
                                                             results)
                    if results != (str(mcast_groups[group]['rx_pkts'])
                                   + " " + mcast_groups[group]['msg']):
                        errors.append(fail_results_msg)
                    else:
                        LOG.info('{} received multicast traffic.'
                                 .format(server['fip']))

        return errors

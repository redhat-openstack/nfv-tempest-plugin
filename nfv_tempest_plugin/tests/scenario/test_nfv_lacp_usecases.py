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

import json
import time

from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestLacpScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestLacpScenarios, self).__init__(*args, **kwargs)
        self.instance = None
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestLacpScenarios, self).setUp()
        """ pre setup creations and checks read from config files """

    def test_deployment_lacp(self, hypervisor_ip=None):
        """Check that lacp bonding is properly configured

        The test uses the following configuration options example:
        bond_mode: 'balance-tcp'
        lacp_status: 'negotiated'
        lacp_time: 'fast'
        lacp_fallback_ab: 'true'

        The "bond_name" is auto discovered.
        """
        LOG.info('Starting deployment_lacp test.')

        if hypervisor_ip is None:
            hypervisor_ip = self._get_hypervisor_ip_from_undercloud()[0]

        lacp_config = json.loads(CONF.nfv_plugin_options.lacp_config)
        lacp_bond = self.retrieve_lacp_ovs_bond(hypervisor_ip)

        cmd = 'sudo ovs-appctl bond/show {0} | '\
              'egrep "^bond_mode|^lacp_status|^lacp_fallback_ab"; '\
              'sudo ovs-appctl lacp/show {0} | '\
              'egrep "lacp_time"'.format(lacp_bond['bond_name'])
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd) \
            .replace('\t', '').replace(' ', '').split('\n')
        bond_data = {}
        for i in range(len(output)):
            data = output[i].split(':')
            if len(data) == 2:
                bond_data[data[0]] = data[1]

        result = []
        checks = {'bond_mode', 'lacp_status', 'lacp_time', 'lacp_fallback_ab'}
        diff_checks_cmd = checks - set(bond_data.keys())
        diff_checks_cfg = checks - set(lacp_config.keys())
        if len(diff_checks_cmd) > 0:
            result.append("Missing checks: {}. Check ovs commands "
                          "output".format(', '.join(diff_checks_cmd)))

        if len(diff_checks_cmd) > 0:
            result.append("Missing checks: {}. Check testcase config "
                          "file".format(', '.join(diff_checks_cfg)))

        for check in checks:
            if check not in diff_checks_cmd and \
               check not in diff_checks_cfg:
                if bond_data[check] != lacp_config[check]:
                    result.append("Check failed: {}, Expected: {} - "
                                  "Found: {}".format(check,
                                                     lacp_config[check],
                                                     bond_data[check]))
        self.assertTrue(len(result) == 0, '. '.join(result))
        return True

    def test_balance_tcp(self, test='balance_tcp'):
        """Test balance-tcp traffic distribution

        The method boots two instances connected through a balance_tcp bond,
        runs traffic between them and checks that traffic goes through the
        right interface
        * 1 flow: all the traffic through the same interface,
          the other one is not used
        * 2 flows: 50% of the traffic in each interface
        * 3 flows: 66% in one interface, 33% in the other one

        The test uses "bond name" and "bond ports" as parameters.
        These options discovered automatically.
        """
        LOG.info('Starting balance_tcp test.')

        if self.external_resources_data is None:
            raise ValueError('External resource data is required for the test')

        servers, key_pair = self.create_and_verify_resources(test=test)
        if len(servers) != 2:
            raise ValueError('The test requires 2 instances.')

        servers[0]['role'] = 'traffic_runner'
        servers[1]['role'] = 'listener'

        tests = [{'desc': '1 flow', 'iperf_option': '-P 1',
                  'threshold_1': 0, 'threshold_2': 2},
                 {'desc': '2 flows', 'iperf_option': '-P 2',
                  'threshold_1': 99, 'threshold_2': 101},
                 {'desc': '3 flows', 'iperf_option': '-P 3',
                  'threshold_1': 49, 'threshold_2': 51}]

        lacp_bond = self.retrieve_lacp_ovs_bond()
        kill_cmd = '(if pgrep iperf; then sudo pkill iperf; fi;) ' \
                   '> /dev/null 2>&1'
        receive_cmd = '(if pgrep iperf; then sudo pkill iperf; fi;' \
                      ' sudo iperf -s -u) > /dev/null 2>&1 &'
        data_net = self.networks_client.list_networks(
            **{'provider:network_type': 'vlan',
               'router:external': False})['networks'][0]['name']
        srv = self.os_admin.servers_client.list_addresses(servers[1]['id'])
        server_network = [net for net in srv['addresses'].items()
                          if net[0] == data_net]
        self.assertEqual(len(server_network), 1,
                         "VM must have a port connected "
                         "to {}".format(data_net))
        server_addr = server_network[0][1][0]['addr']

        for test in tests:
            send_cmd = '(if pgrep iperf; then sudo pkill iperf; fi;' \
                       ' sudo iperf -c {} {} -u -t 1000) > /dev/null 2>&1 &' \
                       .format(server_addr, test['iperf_option'])
            for srv in servers:
                if 'role' in srv.keys():
                    cmd = send_cmd if 'traffic_runner' in srv['role'] \
                        else receive_cmd
                    LOG.info('Executing iperf on {} - {}: {}'
                             .format(srv['role'], srv['fip'], cmd))
                    ssh_source = self.get_remote_client(
                        srv['fip'], username=self.instance_user,
                        private_key=key_pair['private_key'])
                    ssh_source.exec_command(cmd)

            # it may take some time to balance the traffic properly, so I give
            # 10 tries  to stabilize, usually is stabilized between try 1 and 2
            for i in range(1, 10):
                stats_begin = self.get_ovs_interface_statistics(
                    lacp_bond['bond_ports'],
                    hypervisor=servers[0]['hypervisor_ip'])
                time.sleep(10)  # measured time
                stats_end = self.get_ovs_interface_statistics(
                    lacp_bond['bond_ports'], stats_begin,
                    servers[0]['hypervisor_ip'])
                tx_pks_1 = stats_end[lacp_bond['bond_ports'][0]]['tx_packets']
                tx_pks_2 = stats_end[lacp_bond['bond_ports'][1]]['tx_packets']
                tx_pkts_max = max(tx_pks_1, tx_pks_2)
                tx_pkts_min = min(tx_pks_1, tx_pks_2)
                tx_pks_rel = 100 * tx_pkts_min / tx_pkts_max
                LOG.info('test: {}, try: {}, pks_1: {}, pks_2: {}, '
                         'tx_packets_rel: {}, threshold_1: {}, '
                         'threshold_2: {}'.format(test['desc'], i, tx_pks_1,
                                                  tx_pks_2, tx_pks_rel,
                                                  test['threshold_1'],
                                                  test['threshold_2']))
                if test['threshold_2'] >= tx_pks_rel >= test['threshold_1']:
                    break

            msg = "Traffic not well balanced. Value {} not between the " \
                  "thresholds: {} and {}".format(tx_pks_rel,
                                                 test['threshold_1'],
                                                 test['threshold_2'])
            result = test['threshold_2'] >= tx_pks_rel >= test['threshold_1']
            self.assertTrue(result, msg)
        # Ensure that traffic is not being sent after the testcase finishes
        for srv in servers:
            if 'role' in srv.keys():
                LOG.info('Killing iperf on {} - {}: {}'
                         .format(srv['role'], srv['fip'], kill_cmd))
                ssh_source = self.get_remote_client(
                    srv['fip'], username=self.instance_user,
                    private_key=key_pair['private_key'])
                ssh_source.exec_command(kill_cmd)

    def test_restart_ovs(self, test='restart_ovs'):
        """Test restart_ovs

        Check that config is loaded properly
        """
        LOG.info('Starting restart_ovs test.')

        hypervisor_ip = self._get_hypervisor_ip_from_undercloud()[0]

        cmd = 'sudo systemctl restart openvswitch.service'
        shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        self.test_deployment_lacp(hypervisor_ip=hypervisor_ip)

        # Give time to have everything up after reboot so that other testcases
        # executed after this one do not fail
        time.sleep(60)

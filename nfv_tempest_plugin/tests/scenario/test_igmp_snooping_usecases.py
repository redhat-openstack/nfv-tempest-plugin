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
        """
        LOG.info('Starting deployment_igmp_snooping test.')

        if hypervisor_ip is None:
            hypervisor_ip = self._get_hypervisor_ip_from_undercloud(
                shell='/home/stack/stackrc')[0]
        cmd = 'sudo ovs-vsctl --format=json list bridge br-int'
        output = self._run_command_over_ssh(hypervisor_ip, cmd)
        #ovs command returns boolean in small letters
        ovs_data = json.loads(output)
        ovs_data_filtered = {}
        try:
            ovs_data_filtered['mcast_snooping_enable'] = ovs_data['data'][0][ovs_data['headings'].index('mcast_snooping_enable')]
            ovs_data_filtered['mcast-snooping-disable-flood-unregistered'] = dict(ovs_data['data'][0][ovs_data['headings'].index('other_config')][1])['mcast-snooping-disable-flood-unregistered']
        except:
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

        roles = { 'instance1' : 'traffic_runner',
                  'instance2' : 'listener',
                  'instance3' : 'listener'}

        for server in servers:
            if server['name'] in roles.keys():
                server['mcast_srv'] = roles[server['name']]

        mcast_group = '224.0.0.1'
        mcast_port = '10000'
        mcast_msg = 'mcast_pass'
        mcast_output = '/tmp/output'
        get_mcast_results = 'cat {}'.format(mcast_output)
        receive_cmd = 'sudo python /usr/local/bin/multicast_traffic.py -r ' \
                      '-g {0} -p {1} -c 1 > {2} &'.format(mcast_group,
                                                          mcast_port,
                                                          mcast_output)
        send_cmd = 'sudo python /usr/local/bin/multicast_traffic.py -s -g' \
                   ' {0} -p {1} -m {2} -c 1 > {3} &'.format(mcast_group,
                                                            mcast_port,
                                                            mcast_msg,
                                                            mcast_output)
        for role in [{'role':'traffic_runner', 'cmd':send_cmd},
                     {'role':'listener', 'cmd':receive_cmd}]:
            for srv in servers:
                if srv['mcast_srv'] == role['role']:
                    LOG.info('Executing multicast script on {} - {}.'
                             .format(srv['mcast_srv'], srv['fip']))
                    ssh_source = self.get_remote_client(srv['fip'],
                                                        username=self.instance_user,
                                                        private_key=key_pair[
                                                            'private_key'])
                    ssh_source.exec_command(role['cmd'])

        for receiver in servers:
            if ('listener1' in receiver['mcast_srv']) or \
                    ('listener2' in receiver['mcast_srv']):
                LOG.info('Reading results from {} - {} instance.'
                         .format(receiver['mcast_srv'], receiver['fip']))
                ssh_source = self.get_remote_client(receiver['fip'],
                                                    username=self.
                                                    instance_user,
                                                    private_key=key_pair[
                                                        'private_key'])
                output = ssh_source.exec_command(get_mcast_results)
                results = output.rstrip('\n')
                fail_results_msg = '{} - {} unable to receive multicast ' \
                                   'traffic.'.format(receiver['mcast_srv'],
                                                     receiver['fip'])
                self.assertEqual(results, mcast_msg, fail_results_msg)
                LOG.info('{} - {} received multicast traffic.'
                         .format(receiver['mcast_srv'], receiver['fip']))

        LOG.info('Both listener1 and listener2 received multicast traffic')
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

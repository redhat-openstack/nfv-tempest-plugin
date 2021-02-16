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

from json import loads

from nfv_tempest_plugin.tests.scenario import base_test
from nfv_tempest_plugin.tests.scenario.qos_manager import QoSManagerMixin
from oslo_log import log as logging
from tempest import config
import time

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestDpdkScenarios(base_test.BaseTest, QoSManagerMixin):
    def __init__(self, *args, **kwargs):
        super(TestDpdkScenarios, self).__init__(*args, **kwargs)
        self.instance = None
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id
        self.maxqueues = None

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestDpdkScenarios, self).setUp()

    def _test_queue_functionality(self, queues):
        """Checks DPDK queues functionality

        Booting number of instances with various number of cpus based on the
        setup queues number.
        """
        LOG.info('Prepare the queues functionality test')
        self.maxqueues = self.check_number_queues()

        extra_specs = {'extra_specs': {'hw:mem_page_size': str("large"),
                                       'hw:cpu_policy': str("dedicated")}}
        if queues == "min":
            queues = self.maxqueues - 2
        elif queues == "odd":
            queues = self.maxqueues - 1
        elif queues == 'max':
            queues = self.maxqueues + 2
        else:
            queues = self.maxqueues

        LOG.info('Create a flavor for the queues test.')
        queues_flavor = self.create_flavor(name='test-queues', vcpus=queues,
                                           **extra_specs)
        servers, key_pair = \
            self.create_server_with_resources(test='check-multiqueue-func',
                                              flavor=queues_flavor)

        LOG.info('Check connectivity to the queues instance.')
        self.check_instance_connectivity(ip_addr=servers[0]['fip'],
                                         user=self.instance_user,
                                         key_pair=key_pair['private_key'])
        LOG.info('The {} queues test passed.'.format(queues))
        return True

    def test_multicast(self, test='multicast'):
        """The method boots three instances, runs mcast traffic between them"""
        LOG.info('Starting multicast test.')
        servers, key_pair = \
            self.create_server_with_resources(test=test, num_servers=3,
                                              use_mgmt_only=True)

        # Add security group rules needed to allow multicast traffic
        rule_list = [{"protocol": "udp", "direction": "ingress"},
                     {"protocol": "udp", "direction": "egress"}]
        self.add_security_group_rules(rule_list,
                                      self.remote_ssh_sec_groups[0]['id'])

        servers[0]['mcast_srv'] = 'listener1'
        servers[1]['mcast_srv'] = 'listener2'
        servers[2]['mcast_srv'] = 'traffic_runner'
        LOG.info('Listener1 server - {}, '
                 'Listener2 server - {}, '
                 'Traffic_runner server - {}'.format(servers[0]['fip'],
                                                     servers[1]['fip'],
                                                     servers[2]['fip']))
        mcast_group = '224.0.0.1'
        mcast_port = '10000'
        mcast_msg = 'mcast_pass'
        mcast_output = '/tmp/output'
        get_mcast_results = 'cat {}'.format(mcast_output)
        receive_cmd = 'sudo python {0}/multicast_' \
                      'traffic.py -r -g {1} -p {2} -c 1 > {3} ' \
                      '&'.format(self.nfv_scripts_path, mcast_group,
                                 mcast_port, mcast_output)
        send_cmd = 'sleep 2;sudo python {0}/multicast_' \
                   'traffic.py -s -g {1} -p {2} -m {3} -c 1 > {4} ' \
                   '&'.format(self.nfv_scripts_path, mcast_group, mcast_port,
                              mcast_msg, mcast_output)
        for srv in servers:
            LOG.info('Executing multicast script on {} - {}.'
                     .format(srv['mcast_srv'], srv['fip']))
            ssh_source = self.get_remote_client(srv['fip'],
                                                username=self.instance_user,
                                                private_key=key_pair[
                                                    'private_key'])
            ssh_source.exec_command(send_cmd if 'traffic_runner' in
                                                srv['mcast_srv'] else
                                                receive_cmd)

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

    def test_min_queues_functionality(self):
        msg = "Could not create, ping or ssh to the instance with flavor " \
              "contains vcpus smaller than allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="min"), msg)

    def test_equal_queues_functionality(self):
        msg = "Could not create, ping or ssh to the instance with flavor " \
              "contains vcpus equal to allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="equal"), msg)

    def test_max_queues_functionality(self):
        msg = "Could not create, ping or ssh to the instance with flavor " \
              "contains vcpus max to allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="max"), msg)

    def test_odd_queues_functionality(self):
        msg = "Could not create, ping or ssh to the instance with flavor " \
              "contains odd number of vcpus"
        self.assertTrue(self._test_queue_functionality(queues="odd"), msg)

    def test_rx_tx(self, test='rx_tx'):
        """Test RX/TX on the instance vs nova configuration

        The test compares RX/TX value from the dumpxml of the running
        instance vs values of the overcloud nova configuration
        """

        servers, key_pair = self.create_and_verify_resources(test=test)

        check_section = 'libvirt'
        check_value = 'rx_queue_size,tx_queue_size'
        osp_release = self.get_osp_release()
        if osp_release >= 13:
            config_path = '/var/lib/config-data/puppet-generated/' \
                          'nova_libvirt/etc/nova/nova.conf'
        else:
            config_path = '/etc/nova/nova.conf'

        for srv in servers:
            LOG.info('Test RX/TX for the {} instance'.format(srv['fip']))
            return_value = self.\
                compare_rx_tx_to_overcloud_config(srv, srv['hypervisor_ip'],
                                                  config_path,
                                                  check_section,
                                                  check_value)
            self.assertTrue(return_value, 'The rx_tx test failed. '
                                          'The values of the instance and '
                                          'nova does not match.')
        LOG.info('The {} test passed.'.format(test))

    def test_dpdk_max_qos(self, test='dpdk_max_qos'):
        """Test DPDK MAX QoS functionality

        The test require [nfv_plugin_options ]
        use_neutron_api_v2 = true in tempest.config.
        Test also requires QoS neutron settings.
        The test deploy 3 vms. one iperf server receive traffic from
        two iperf clients, with max_qos defined run against iperf server.
        The test search for Traffic per second and compare against ports
        settings
        """
        LOG.info('Start dpdk Max QoS test.')

        kwargs = {}
        qos_rules = \
            loads(CONF.nfv_plugin_options.max_qos_rules)
        qos_rules_list = [x for x in qos_rules]
        sg_rules = [{"protocol": "tcp", "direction": "ingress",
                    "port_range_max": 5102, "port_range_min": 5101}]

        sg = self._create_security_group()
        self.add_security_group_rules(sg_rules, sg['id'])
        kwargs['security_groups'] = [{'name': sg['name'], 'id': sg['id']}]

        servers, key_pair = self.create_and_verify_resources(
            test=test, num_servers=3, use_mgmt_only=True, **kwargs)

        if len(servers) != 3:
            raise ValueError('The test requires 3 instances. Only {}'
                             ' exists'.format(len(servers)))

        # Max QoS configuration to server ports
        LOG.info('Create QoS Policies...')
        qos_policies = [self.create_qos_policy_with_rules(
            use_default=False, **i) for i in qos_rules_list]

        LOG.info('Running iperf')
        self.run_iperf_test(qos_policies, servers, key_pair,
                            vnic_type='normal')
        self.collect_iperf_results(qos_rules_list, servers, key_pair)

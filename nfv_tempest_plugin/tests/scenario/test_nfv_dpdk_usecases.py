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

import time

from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestDpdkScenarios(base_test.BaseTest):
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
        try:
            self.maxqueues = super(TestDpdkScenarios, self) \
                ._check_number_queues()
        except Exception:
            print("Hypervisor OVS not configured with MultiQueue")
        """ pre setup creations and checks read from config files """

    def _test_queue_functionality(self, queues):
        """Checks DPDK queues functionality

        Booting number of instances with various number of cpus based on the
        setup queues number.
        """

        msg = "Hypervisor OVS not configured with MultiQueue"
        self.assertIsNotNone(self.maxqueues, msg)

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

        queues_flavor = self.create_flavor(name='test-queues', vcpus=queues,
                                           **extra_specs)
        servers, key_pair = \
            self.create_server_with_resources(test='check-multiqueue-func',
                                              flavor=queues_flavor)

        msg = "%s instance is not reachable by ping" % servers[0]['fip']
        self.assertTrue(self.ping_ip_address(servers[0]['fip']), msg)
        self.assertTrue(self.get_remote_client(
            servers[0]['fip'], private_key=key_pair['private_key']))
        return True

    def _test_live_migration_block(self, test_setup_migration=None):
        """Method boots an instance and wait until ACTIVE state

        Migrates the instance to the next available hypervisor.
        """

        extra_specs = {'extra_specs': {'hw:mem_page_size': str("large")}}
        migration_flavor = self.create_flavor(name='live-migration', vcpus='2',
                                              **extra_specs)
        servers, key_pair = \
            self.create_server_with_resources(test=test_setup_migration,
                                              flavor=migration_flavor,
                                              use_mgmt_only=True)

        host = self.os_admin.servers_client.show_server(
            servers[0]['id'])['server']['OS-EXT-SRV-ATTR:hypervisor_hostname']
        """ Run ping before migration """
        msg = "Timed out waiting for %s to become reachable" % \
              servers[0]['fip']
        self.assertTrue(self.ping_ip_address(servers[0]['fip']), msg)
        """ Migrate server """
        self.os_admin.servers_client.live_migrate_server(
            server_id=servers[0]['id'], block_migration=True, host=None)
        """ Switch hypervisor id (compute-0 <=> compute-1) """
        count = 1
        if host.find('0') > 0:
            dest = list(host)
            dest[dest.index('0')] = '1'
            dest = ''.join(dest)
        else:
            dest = list(host)
            dest[dest.index('1')] = '0'
            dest = ''.join(dest)
        while count < 30:
            count += 1
            time.sleep(3)
            if dest == self\
                    .os_admin.servers_client.show_server(servers[0][
                    'id'])['server']['OS-EXT-SRV-ATTR:hypervisor_hostname']:
                """ Run ping after migration """
                self.assertTrue(self.ping_ip_address(servers[0]['fip']), msg)
                return True
        return False

    def test_multicast(self, test='multicast'):
        """The method boots three instances, runs mcast traffic between them"""
        LOG.info('Starting multicast test.')
        servers, key_pair = \
            self.create_server_with_resources(test=test, num_servers=3,
                                              use_mgmt_only=True,
                                              copy_file='tests_scripts/'
                                                        'multicast_traffic.py',
                                              copy_dest='/tmp/multicast_'
                                                        'traffic.py')
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
        receive_cmd = 'sudo python /tmp/multicast_traffic.py -r -g {0} -p ' \
                      '{1} -c 1 > {2} &'.format(mcast_group, mcast_port,
                                                mcast_output)
        send_cmd = 'sudo python /tmp/multicast_traffic.py -s -g {0} -p {1} ' \
                   '-m {2} -c 1 > {3} &'.format(mcast_group, mcast_port,
                                                mcast_msg, mcast_output)
        for srv in servers:
            LOG.info('Executing multicast script on {} - {}.'
                     .format(srv['mcast_srv'], srv['fip']))
            ssh_source = self.get_remote_client(srv['fip'],
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

    def test_live_migration_block(self):
        """Make sure CONF.compute_feature_enabled.live_migration is True"""
        msg = "Live migration Failed"
        self.assertTrue(self._test_live_migration_block(
            test_setup_migration="test_live_migration_basic"), msg)

    def test_rx_tx(self, test='rx_tx'):
        """Test RX/TX on the instance vs nova configuration

        The test compares RX/TX value from the dumpxml of the running
        instance vs values of the overcloud nova configuration

        Note! - The test suit only for RHOS version 14 and up, since the
                rx/tx feature was implemented only in version 14.
        """

        servers, key_pair = self.create_and_verify_resources(test=test)

        conf = self.test_setup_dict['rx_tx']['config_dict'][0]
        config_path = conf['config_path']
        check_section = conf['check_section']
        check_value = conf['check_value']

        for srv in servers:
            return_value = self.\
                compare_rx_tx_to_overcloud_config(srv, srv['hypervisor_ip'],
                                                  config_path,
                                                  check_section,
                                                  check_value)
            self.assertTrue(return_value, 'The rx_tx test failed. '
                                          'The values of the instance and '
                                          'nova does not match.')

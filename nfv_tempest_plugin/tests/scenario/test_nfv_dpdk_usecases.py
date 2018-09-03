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

import re
import time

from nfv_tempest_plugin.tests.scenario import baremetal_manager
from oslo_log import log as logging
from tempest import clients
from tempest.common import credentials_factory as common_creds
from tempest import config

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestDpdkScenarios(baremetal_manager.BareMetalManager):
    def __init__(self, *args, **kwargs):
        super(TestDpdkScenarios, self).__init__(*args, **kwargs)
        self.public_network = CONF.network.public_network_id
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.ssh_user = CONF.validation.image_ssh_user
        self.ssh_passwd = CONF.validation.image_ssh_password
        self.ip_address = None
        self.instance = None
        self.availability_zone = None
        self.maxqueues = None
        self.cpuregex = re.compile('^[0-9]{1,2}$')

    @classmethod
    def setup_credentials(cls):
        """Do not create network resources for these tests

        Using public network for ssh
        """
        cls.set_network_resources()
        super(TestDpdkScenarios, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestDpdkScenarios, self).setUp()
        try:
            self.maxqueues = super(TestDpdkScenarios, self)\
                ._check_number_queues()
        except Exception:
            print("Hypervisor OVS not configured with MultiQueue")
        """ pre setup creations and checks read from config files """

    def _test_queue_functionality(self, queues):
        """Checks DPDK queues functionality

        Booting number of instances with various number of cpus based on the
        setup queues number.
        """

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
        servers, fips, key_pair = \
            self.create_server_with_resources(test='check-multiqueue-func',
                                              flavor=queues_flavor)
        msg = "%s instance is not reachable by ping" % fips[0]['ip']
        self.assertTrue(self.ping_ip_address(fips[0]['ip']), msg)
        self.assertTrue(self.get_remote_client(
            fips[0]['ip'], private_key=key_pair['private_key']))
        return True

    def _test_live_migration_block(self, test_setup_migration=None):
        """Method boots an instance and wait until ACTIVE state

        Migrates the instance to the next available hypervisor.
        """

        self.assertTrue(test_setup_migration in self.test_setup_dict,
                        "Test requires {0} setup in "
                        "external_config_file".format(test_setup_migration))

        extra_specs = {'extra_specs': {'hw:mem_page_size': str("large")}}
        migration_flavor = self.create_flavor(name='live-migration', vcpus='2',
                                              **extra_specs)
        servers, fips, key_pair = \
            self.create_server_with_resources(test=test_setup_migration,
                                              flavor=migration_flavor)

        host = self.os_admin.servers_client.show_server(
            servers[0]['server']['id'])['server'][
            'OS-EXT-SRV-ATTR:hypervisor_hostname']

        """ Run ping before migration """
        msg = 'Timed out waiting for {} to become ' \
              'reachable'.format(fips[0]['ip'])
        self.assertTrue(self.ping_ip_address(fips[0]['ip']), msg)

        """ Migrate server """
        self.os_admin.servers_client.live_migrate_server(
            server_id=servers[0]['server']['id'], block_migration=True,
            disk_over_commit=True, host=None)

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
        while (count < 30):
            count = +1
            time.sleep(3)
            if (self.os_admin.servers_client.show_server(
                    servers[0]['server']['id'])['server'][
                    'OS-EXT-SRV-ATTR:hypervisor_hostname'] == dest):
                """ Run ping after migration """
                self.assertTrue(self.ping_ip_address(fips[0]['ip']), msg)
                return True
        return False

    def _test_multicast_traffic(self, test_multicast):
        """The method boots three instances, runs mcast traffic between them"""
        LOG.info('Starting multicast test.')

        self.assertTrue(test_multicast in self.test_setup_dict,
                        "Test requires {0} configuration "
                        "in external config file".format(test_multicast))

        servers, fips, key_pair = \
            self.create_server_with_resources(test=test_multicast,
                                              num_servers=3)
        traffic_runner = fips[0]['ip']
        listener1 = fips[1]['ip']
        listener2 = fips[2]['ip']
        listeners = [listener1, listener2]

        """
        Start multicast listeners
        """
        mcast_group = '224.1.1.1'
        mcast_port = '10000'
        mcast_msg = 'mcast_pass'
        mcast_output = '/tmp/output'
        get_mcast_results = 'cat {}'.format(mcast_output)
        for srv in listeners:
            LOG.info('Copy and execute multicast script to {}.'.format(srv))
            # The method is a temporary solution.
            # ToDo: Remove once config-drive will be implemented.
            copy = self.copy_file_to_remote_host(srv,
                                                 ssh_key=key_pair[
                                                     'private_key'],
                                                 files='mcast_receive.py',
                                                 src_path='tests_scripts',
                                                 dst_path='/tmp')
            LOG.info(copy)
            ssh_source = self.get_remote_client(srv,
                                                private_key=key_pair[
                                                    'private_key'])
            ssh_source.exec_command(
                'python /tmp/mcast_receive.py -g {0} -p {1} > {2} &'.format(
                    mcast_group, mcast_port, mcast_output))
        """
        Start multicast traffic runner
        """
        LOG.info('Copy and execute multicast script '
                 'to {}.'.format(traffic_runner))
        # The method is a temporary solution.
        # ToDo: Remove once config-drive will be implemented.
        copy = self.copy_file_to_remote_host(traffic_runner,
                                             ssh_key=key_pair[
                                                 'private_key'],
                                             files='mcast_send.py',
                                             src_path='tests_scripts',
                                             dst_path='/tmp')
        LOG.info(copy)
        ssh_source = self.get_remote_client(traffic_runner,
                                            private_key=key_pair[
                                                'private_key'])
        ssh_source.exec_command(
            'python /tmp/mcast_send.py -g {0} -p {1} -m {2}'.format(
                mcast_group, mcast_port, mcast_msg))
        """
        Reading the listeners output files
        """
        for srv in listeners:
            LOG.info('Reading results from {} instance.'.format(srv))
            ssh_source = self.get_remote_client(srv,
                                                private_key=key_pair[
                                                    'private_key'])
            output = ssh_source.exec_command(get_mcast_results)
            results = output.rstrip('\n')
            results_msg = '{} unable to receive multicast traffic.'.format(srv)
            self.assertEqual(results, mcast_msg, results_msg)
            LOG.info('{} received multicast traffic.'.format(srv))
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

    def test_multicast(self):
        msg = "Multicast test failed. Check log for more details."
        self.assertTrue(self._test_multicast_traffic("multicast"), msg)

# Copyright 2020 Red Hat, Inc.
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

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestLiveMigrationScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestLiveMigrationScenarios, self).__init__(*args, **kwargs)

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(TestLiveMigrationScenarios, self).setUp()
        # pre setup creations and checks read from config files

    def _perform_live_migration(self, server, key_pair,
                                use_block_migration=False):
        """Method boots an instance and wait until ACTIVE state

        Migrates the instance to the next available hypervisor.
        """

        host = self.os_admin.servers_client.show_server(
            server['id'])['server']['OS-EXT-SRV-ATTR:hypervisor_hostname']
        self.check_instance_connectivity(ip_addr=server['fip'],
                                         user=self.instance_user,
                                         key_pair=key_pair['private_key'])
        """ Migrate server """
        self.os_admin.servers_client.live_migrate_server(
            server_id=server['id'], block_migration=use_block_migration,
            host=None)
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
                    .os_admin.servers_client.show_server(server[
                    'id'])['server']['OS-EXT-SRV-ATTR:hypervisor_hostname']:
                """Verify connectivity after migration"""
                self.check_instance_connectivity(ip_addr=server['fip'],
                                                 user=self.instance_user,
                                                 key_pair=key_pair[
                                                     'private_key'])
                return True
        return False

    def test_live_migration_block(self, test='test_live_migration_block'):
        """Test live migration with block migration

        Make sure CONF.compute_feature_enabled.live_migration is True
        """
        msg = "live migration is not configured"
        self.assertTrue(CONF.compute_feature_enabled.live_migration, msg)
        msg = "Live migration Failed"
        servers, key_pair = \
            self.create_and_verify_resources(test=test, use_mgmt_only=True)
        self.assertTrue(self._perform_live_migration(
            servers[0], key_pair, use_block_migration=True), msg)

    def test_live_migration_shared(self, test='test_live_migration_shared'):
        """Test live migration with shared storage

        Make sure CONF.compute_feature_enabled.live_migration is True
        """
        msg = "live migration is not configured"
        self.assertTrue(CONF.compute_feature_enabled.live_migration, msg)
        msg = "Live migration Failed"
        servers, key_pair = \
            self.create_and_verify_resources(test=test, use_mgmt_only=True)
        self.assertTrue(self._perform_live_migration(servers[0], key_pair),
                        msg)

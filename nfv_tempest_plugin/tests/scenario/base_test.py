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

from nfv_tempest_plugin.tests.scenario import baremetal_manager
from oslo_log import log as logging
from tempest import clients
from tempest.common import credentials_factory as common_creds
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class BaseTest(baremetal_manager.BareMetalManager):
    def __init__(self, *args, **kwargs):
        super(BaseTest, self).__init__(*args, **kwargs)

    @classmethod
    def setup_credentials(cls):
        """Do not create network resources for these tests

        Using public network for ssh
        """
        cls.set_network_resources()
        super(BaseTest, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(BaseTest, self).setUp()
        # pre setup creations and checks read from config files

    def create_and_verify_resources(self, test=None, fip=None, **kwargs):
        """Create and verify resources method

        The create and verify resources method performs basic steps in order
        to prepare the environment for the actual test.
        Create all the resources and boot an instance.
        Verify ping and SSH connection to the instance.

        The method should be used by the tests as a starting point for
        environment preparation.

        :param test: Test name from the external config file.

        :return servers, key_pair
        """
        LOG.info('Starting the {} test'.format(test))
        if fip is None:
            fip = self.fip

        servers, key_pair = self.create_server_with_resources(test=test,
                                                              fip=fip,
                                                              **kwargs)

        for srv in servers:
            LOG.info('Instance details: fip: {}, instance_id: {}'.format(
                srv['fip'], srv['id']))

            srv['hypervisor_ip'] = self._get_hypervisor_ip_from_undercloud(
                **{'shell': '/home/stack/stackrc', 'server_id': srv['id']})[0]
            self.assertNotEmpty(srv['hypervisor_ip'],
                                "_get_hypervisor_ip_from_undercloud "
                                "returned empty ip list")

            LOG.info('Test {} instance connectivity.'.format(srv['fip']))
            if fip:
                msg = ("Timed out waiting for %s to become reachable" %
                       srv['fip'])
                self.assertTrue(self.ping_ip_address(srv['fip']), msg)
                self.assertTrue(self.get_remote_client(srv['fip'],
                                                       username=self.
                                                       instance_user,
                                                       private_key=key_pair[
                                                           'private_key']))
            else:
                LOG.info("FIP is disabled, ping %s using network namespaces" %
                         srv['fip'])
                ping = self.ping_via_network_namespace(srv['fip'],
                                                       srv['network_id'])
                self.assertTrue(ping)

        return servers, key_pair

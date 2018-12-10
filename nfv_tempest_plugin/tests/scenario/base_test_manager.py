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

LOG = logging.getLogger(__name__)
CONF = config.CONF


class BaseTestManager(baremetal_manager.BareMetalManager):
    def __init__(self, *args, **kwargs):
        super(BaseTestManager, self).__init__(*args, **kwargs)

    @classmethod
    def setup_credentials(cls):
        """Do not create network resources for these tests

        Using public network for ssh
        """
        cls.set_network_resources()
        super(BaseTestManager, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(BaseTestManager, self).setUp()
        # pre setup creations and checks read from config files

    def basic_test_base(self, test=None, **kwargs):
        """Basic test base method

        The basic test base method performs basic steps in order to prepare
        the environment for the actual test.
        Create all the resources and boot an instance.
        Verify ping and SSH connection to the instance.

        The method should be used by the tests as a starting point for
        environment preparation.

        :param test: Test name from the external config file.

        :return servers, key_pair
        """

        servers, key_pair = \
            self.create_server_with_resources(test=test, **kwargs)

        for srv in servers:
            LOG.info("fip: %s, instance_id: %s", srv['fip'], srv['id'])

            srv['hypervisor_ip'] = self._get_hypervisor_ip_from_undercloud(
                **{'shell': '/home/stack/stackrc', 'server_id': srv['id']})[0]
            self.assertNotEmpty(srv['hypervisor_ip'],
                                "_get_hypervisor_ip_from_undercloud "
                                "returned empty ip list")

            """Run ping and verify ssh connection"""
            msg = "Timed out waiting for %s to become reachable" % srv['fip']
            self.assertTrue(self.ping_ip_address(srv['fip']), msg)
            self.assertTrue(self.get_remote_client(srv['fip'],
                                                   private_key=key_pair[
                                                       'private_key']))

        return servers, key_pair

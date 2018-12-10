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


class TestSriovScenarios(baremetal_manager.BareMetalManager):
    def __init__(self, *args, **kwargs):
        super(TestSriovScenarios, self).__init__(*args, **kwargs)
        self.instance = None
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id

    @classmethod
    def setup_credentials(cls):
        """Do not create network resources for these tests

        Using public network for ssh
        """
        cls.set_network_resources()
        super(TestSriovScenarios, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestSriovScenarios, self).setUp()
        # pre setup creations and checks read from

    def test_sriov_trusted_vfs(self, test='trustedvfs'):
        """Verify trusted virtual functions

        """
        trusted_vfs_mac_addresses = []
        servers, key_pair = \
            self.create_server_with_resources(test=test)
        ports = self.ports_client.list_ports(device_id=servers[0]['id'])
        for port in ports['ports']:
            if 'trusted' in port['binding:profile'] and \
                port['binding:profile']['trusted']:
                    trusted_vfs_mac_addresses.append(port['mac_address'])
        self.assertNotEmpty(trusted_vfs_mac_addresses,
                            "No trusted VFs are attached to server")
        host = (self.os_admin.servers_client.show_server(servers[0]['id'])
                ['server']['OS-EXT-SRV-ATTR:hypervisor_hostname'].split('.')
                [0])
        host_ip = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc',
               'hyper_name': host})[0]
        for mac_address in trusted_vfs_mac_addresses:
            cmd = 'sudo ip link | grep {0}'.format(mac_address)
            result = self._run_command_over_ssh(host_ip, cmd)
            self.assertIn('trust on', result)
        return True

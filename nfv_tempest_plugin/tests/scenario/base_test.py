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

from importlib import import_module
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
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
    def get_client_manager(cls, credential_type=None, roles=None,
                           force_new=None):
        """Method, manages two client managers.

        Neutron tempest plugin ,maintain its own client.manager,
        it also save upstream manager w/ primary credential.
        This methos maintain nfv_tempest_plugin upstream client.manager
        and save neutron_tempest_plugin in class member
        """
        manager = super(BaseTest, cls).get_client_manager(
            credential_type=credential_type,
            roles=roles,
            force_new=force_new
        )
        """Apply dynamic package check to import nfv_tempest_plugin service
        Load packages only when use_neutron_api_v2 is set and
        neutron_tempest_plugin is installed
        """
        if CONF.nfv_plugin_options.use_neutron_api_v2 and \
                credential_type == 'admin':
            try:
                import_module('neutron_tempest_plugin')
                network_client_v2 = \
                    import_module('nfv_tempest_plugin.services'
                                  '.network_client_v2')
                cls.os_admin_v2 = \
                    network_client_v2.Manager(manager.credentials)
            except ImportError:
                LOG.info("Failed to load neutron_tempest_plugin, \
                         please check use_neutron_api_v2 set to False")
        return manager

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

    def verify_provider_networks(self, servers=None, key_pair=None):
        """Verifies provider networks attached to guest

        This functions attempts to verify all provider networks present
        inside guest.

        If multiple servers are created, guests will attempt to ping between
        themselves on each provider network.

        :param servers: List of servers created
        :param key-pair: Key pair used to authenticate with server
        """
        for server in servers:
            # Initialize a custom key inside server object
            server['provider_networks'] = []
            # Fetch all ports assigned to server
            ports =  \
                self.os_admin.ports_client.list_ports(device_id=server['id'])
            for port in ports['ports']:
                provider_dict = {
                    'network_id': port['network_id'],
                    'mac_address': port['mac_address'],
                    'ip_address': port['fixed_ips'][0]['ip_address']
                }
                server['provider_networks'].append(provider_dict)
            # Create an SSH connection to server
            ssh_client = self.get_remote_client(server['fip'],
                                                self.instance_user,
                                                key_pair['private_key'])
            shell_utils.\
                check_guest_interface_config(ssh_client,
                                             server['provider_networks'],
                                             server['name'])

        self.check_guest_provider_networks(servers, key_pair)

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
                self.check_instance_connectivity(ip_addr=srv['fip'],
                                                 user=self.instance_user,
                                                 key_pair=key_pair[
                                                     'private_key'])
            else:
                LOG.info("FIP is disabled, ping %s using network namespaces" %
                         srv['fip'])
                ping = self.ping_via_network_namespace(srv['fip'],
                                                       srv['network_id'])
                self.assertTrue(ping)

        # Verify provider networks only when requested and if FIP is assigned
        if self.test_all_provider_networks and fip:
            self.verify_provider_networks(servers, key_pair)

        return servers, key_pair

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

from __future__ import division  # Use Python3 divison in Python2

import os.path
import paramiko
import re

from nfv_tempest_plugin.tests.scenario import manager_utils
from oslo_log import log
from oslo_serialization import jsonutils
from tempest.api.compute import api_microversion_fixture
from tempest.common import waiters
from tempest import config
from tempest.lib.common import api_version_utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager
"""Python 2 and 3 support"""
from six.moves import StringIO


CONF = config.CONF
LOG = log.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class BareMetalManager(api_version_utils.BaseMicroversionTest,
                       manager.ScenarioTest,
                       manager_utils.ManagerMixin):
    """This class Interacts with BareMetal settings"""
    credentials = ['primary', 'admin']

    def __init__(self, *args, **kwargs):
        super(BareMetalManager, self).__init__(*args, **kwargs)
        self.public_network = CONF.network.public_network_id
        self.mgmt_network = None
        self.instance_user = CONF.nfv_plugin_options.instance_user
        self.instance_pass = CONF.nfv_plugin_options.instance_pass
        self.nfv_scripts_path = CONF.nfv_plugin_options.transfer_files_dest
        self.flavor_ref = CONF.compute.flavor_ref
        self.test_all_provider_networks = \
            CONF.nfv_plugin_options.test_all_provider_networks
        self.cpuregex = re.compile('^[0-9]{1,2}$')
        self.external_config = None
        self.test_setup_dict = {}
        self.remote_ssh_sec_groups = []
        self.remote_ssh_sec_groups_names = []
        self.qos_policy_groups = []
        self.servers = []
        self.test_network_dict = {}
        self.test_flavor_dict = {}
        self.test_instance_repo = {}
        self.user_data = {}
        self.user_data_b64 = ''
        self.fip = True
        self.external_resources_data = None

    @classmethod
    def setup_clients(cls):
        super(BareMetalManager, cls).setup_clients()
        cls.hypervisor_client = cls.manager.hypervisor_client
        cls.aggregates_client = cls.manager.aggregates_client
        cls.volumes_client = cls.os_primary.volumes_client_latest
        """
        security groups client
        floating ip client to support
        nova microversion>=2.36 changes
        """
        cls.security_groups_client = (
            cls.os_primary.security_groups_client)
        cls.security_group_rules_client = (
            cls.os_primary.security_group_rules_client)
        cls.floating_ips_client = (
            cls.os_primary.floating_ips_client)

    def setUp(self):
        """Check hypervisor configuration:

        SSH user and Private key/password definition [must].
        External config file exist [not a must].
        """
        super(BareMetalManager, self).setUp()
        self.assertIsNotNone(CONF.nfv_plugin_options.overcloud_node_user,
                             "Missing SSH user login in config")

        if CONF.nfv_plugin_options.overcloud_node_pkey_file:
            key_str = open(
                CONF.nfv_plugin_options.overcloud_node_pkey_file).read()
            CONF.nfv_plugin_options.overcloud_node_pkey_file_rsa = \
                paramiko.RSAKey.from_private_key(StringIO(key_str))
        else:
            self.assertIsNotNone(
                CONF.nfv_plugin_options.overcloud_node_pass,
                'Missing SSH password or key_file')
        if CONF.nfv_plugin_options.external_config_file:
            if os.path.exists(CONF.nfv_plugin_options.external_config_file):
                self.read_external_config_file()

        self.useFixture(api_microversion_fixture.APIMicroversionFixture(
            self.request_microversion))

        if CONF.nfv_plugin_options.external_resources_output_file:
            if os.path.exists(
                    CONF.nfv_plugin_options.external_resources_output_file):
                self._read_and_validate_external_resources_data_file()

        if CONF.nfv_plugin_options.quota_cores and \
                CONF.nfv_plugin_options.quota_ram:
            self.os_admin.quotas_client.update_quota_set(
                self.os_primary.tenants_client.tenant_id,
                cores=CONF.nfv_plugin_options.quota_cores,
                ram=CONF.nfv_plugin_options.quota_ram)

    @classmethod
    def resource_setup(cls):
        super(BareMetalManager, cls).resource_setup()
        cls.tenant_id = cls.manager.identity_client.tenant_id
        cls.request_microversion = (
            api_version_utils.select_request_microversion(
                cls.min_microversion,
                CONF.compute.min_microversion))

    @classmethod
    def setup_credentials(cls):
        super(BareMetalManager, cls).setup_credentials()

    def create_flavor(self, name='flavor', ram='2048', disk='20', vcpus='1',
                      **flavor_args):
        """The method creates flavor based on the args passed to the method.

        The flavor could be created with or without an extra specs.
        In case method call with empty parameters, default values will
        be used and default flavor will be created.

        :param name: Flavor name.
        :param ram: Flavor ram.
        :param disk: Flavor disk.
        :param vcpus: Flavor vcpus.
        :param flavor_args: Dict of parameters for the flavor that should be
                created.
        :return flavor_id: ID of the created flavor.
        """
        flavor = self.os_admin.flavors_client.create_flavor(name=name,
                                                            ram=ram,
                                                            disk=disk,
                                                            vcpus=vcpus)
        flavor_id = flavor['flavor']['id']
        if 'extra_specs' in flavor_args:
            extra_specs = flavor_args['extra_specs']
            if isinstance(flavor_args['extra_specs'], list):
                extra_specs = flavor_args['extra_specs'][0]
            self.os_admin.flavors_client.set_flavor_extra_spec(flavor_id,
                                                               **extra_specs)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.os_admin.flavors_client.delete_flavor, flavor_id)
        return flavor_id

    def create_volume(self, **volume_args):
        """The method creates volume based on the args passed to the method.

        In case method call with empty parameters, default values will
        be used and default volume will be created.

        :param volume_args: Dict of parameters for the volume that should be
        created
        :return volume_id: ID of the created volume.
        """
        if 'name' not in volume_args:
            volume_args['name'] = data_utils.rand_name('volume')
        if 'size' not in volume_args:
            volume_args['size'] = CONF.volume.volume_size
        volume = self.volumes_client.create_volume(**volume_args)['volume']
        self.addClassResourceCleanup(
            self.volumes_client.wait_for_resource_deletion, volume['id'])
        self.addClassResourceCleanup(test_utils.call_and_ignore_notfound_exc,
                                     self.volumes_client.delete_volume,
                                     volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')
        return volume

    def _detach_volume(self, server, volume):
        """Detaches a volume and ignores if not found or not in-use

        param server: Created server details
        param volume: Created volume details
        """
        try:
            volume = self.volumes_client.show_volume(volume['id'])['volume']
            if volume['status'] == 'in-use':
                self.servers_client.detach_volume(server['id'], volume['id'])
        except lib_exc.NotFound:
            pass

    def attach_volume(self, server, volume):
        """Attaches volume to server

        param server: Created server details
        param volume: Created volume details
        :return volume_attachment: Volume attachment information.
        """
        attach_args = dict(volumeId=volume['id'])
        attachment = self.servers_client.attach_volume(
            server['id'], **attach_args)['volumeAttachment']
        self.addCleanup(waiters.wait_for_volume_resource_status,
                        self.volumes_client, volume['id'], 'available')
        self.addCleanup(self._detach_volume, server, volume)
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'in-use')
        return attachment

    def create_and_set_availability_zone(self, zone_name=None, **kwargs):
        """Create availability zone with aggregation

        The method creates an aggregate and add the availability zone label
        :param zone_name: Availability zone name
        :param kwargs:
                aggr_name: The name of the aggregation to be created
                hyper_hosts: The list of the hypervisors to be attached
                aggr_meta: The metadata for the aggregation
        """
        if not zone_name:
            zone_name = data_utils.rand_name('availability-zone')
        aggr = self.create_and_set_aggregate(**kwargs)
        zone = self.aggregates_client.update_aggregate(
            aggregate_id=aggr['id'], availability_zone=zone_name)
        return zone['aggregate']

    def create_and_set_aggregate(self, hyper_hosts, aggr_name=None,
                                 aggr_meta=None):
        """Create aggregation and add an hypervisor to it

        :param hyper_hosts: The list of the hypervisors to be attached
        :param aggr_name: The name of the aggregation to be created
        :param aggr_meta: The metadata for the aggregation (optional)
        """
        if not aggr_name:
            aggr_name = data_utils.rand_name('aggregate')
        hyper_list = []
        for hyper in self.hypervisor_client.list_hypervisors()['hypervisors']:
            for host in hyper_hosts:
                if hyper['hypervisor_hostname'].split('.')[0] in host:
                    hyper_list.append(hyper['hypervisor_hostname'])
        if not hyper_list:
            raise ValueError('Provided host for the aggregate does not exist.')

        aggr = self.aggregates_client.create_aggregate(name=aggr_name)
        self.addCleanup(self.aggregates_client.delete_aggregate,
                        aggr['aggregate']['id'])
        if aggr_meta:
            meta_body = {aggr_meta.split('=')[0]: aggr_meta.split('=')[1]}
            self.aggregates_client.set_metadata(aggr['aggregate']['id'],
                                                metadata=meta_body)
        for host in hyper_list:
            self.aggregates_client.add_host(aggr['aggregate']['id'], host=host)
            self.addCleanup(self.aggregates_client.remove_host,
                            aggr['aggregate']['id'], host=host)
        return aggr['aggregate']

    def _list_aggregate(self, name=None):
        """Aggregation listing

        This Method lists aggregation based on name, and returns the
        aggregated hosts lists.
        TBD: Add support to return, hosts list
        TBD: Return None in case no aggregation found.

        :param name
        """
        host = None

        if not name:
            return host

        aggregate = self.aggregates_client.list_aggregates()['aggregates']
        #       Assertion check
        if aggregate:
            aggr_result = []
            for i in aggregate:
                if name in i['name']:
                    aggr_result.append(self.aggregates_client.
                                       show_aggregate(i['id'])['aggregate'])
            host = aggr_result[0]['hosts']
        return host

    def _create_test_networks(self):
        """Method reads test-networks attributes from external_config.yml

        The network will be created for tempest tenant.
        Do not use this method if the test
        need to run on pre-configured networks..
        see _detect_existing_networks() method
        """
        if len(self.external_config['test-networks']) > 0:
            self.test_network_dict.clear()
        mgmt_network = None
        for net in self.external_config['test-networks']:
            self.test_network_dict[net['name']] = \
                {'provider:physical_network': net['physical_network'],
                 'provider:network_type': net['network_type'],
                 'dhcp': net['enable_dhcp'],
                 'cidr': net['cidr'],
                 'pool_start': net['allocation_pool_start'],
                 'pool_end': net['allocation_pool_end'],
                 'gateway_ip': net['gateway_ip'],
                 'port_type': net['port_type'],
                 'ip_version': net['ip_version']}
            if 'segmentation_id' in net:
                self.test_network_dict[net['name']][
                    'provider:segmentation_id'] = net['segmentation_id']
            if 'sec_groups' in net:
                self.test_network_dict[net['name']]['sec_groups'] = \
                    net['sec_groups']
            if 'mgmt' in net and net['mgmt']:
                mgmt_network = net['name']
            if 'mgmt' in net and 'dns_nameservers' in net:
                self.test_network_dict[net['name']]['dns_nameservers'] = \
                    net['dns_nameservers']
            if ('tag' in net and (2.32 <= float(self.request_microversion)
                                  <= 2.36 or float(self.request_microversion)
                                  >= 2.42)):
                self.test_network_dict[net['name']]['tag'] = net['tag']
            if 'trusted_vf' in net and net['trusted_vf']:
                self.test_network_dict[net['name']]['trusted_vf'] = True
            if 'switchdev' in net and net['switchdev']:
                self.test_network_dict[net['name']]['switchdev'] = True
            if 'min_qos' in net and net['min_qos']:
                self.test_network_dict[net['name']]['min_qos'] = \
                    net['min_qos']
            if net.get('skip_srv_attach') and net['skip_srv_attach']:
                self.test_network_dict[net['name']]['skip_srv_attach'] = True
        network_kwargs = {}
        """
        Create network and subnets
        """
        for net_name, net_param in iter(self.test_network_dict.items()):
            network_kwargs.clear()
            network_kwargs['name'] = net_name
            if 'sec_groups' in net_param and not net_param['sec_groups']:
                network_kwargs['port_security_enabled'] = net_param[
                    'sec_groups']
            """Added this for VxLAN no need of physical network or segmentation
            """
            if 'provider:network_type' in net_param and \
                    (net_param['provider:network_type'] == 'vlan'
                     or net_param['provider:network_type'] == 'flat'):
                if 'provider:physical_network' in net_param:
                    network_kwargs['provider:physical_network'] =\
                        net_param['provider:physical_network']
                if 'provider:segmentation_id' in net_param:
                    network_kwargs['provider:segmentation_id'] =\
                        net_param['provider:segmentation_id']

            if 'provider:network_type' in net_param:
                network_kwargs['provider:network_type'] =\
                    net_param['provider:network_type']

            network_kwargs['tenant_id'] = self.networks_client.tenant_id
            result = self.os_admin.networks_client.create_network(
                **network_kwargs)
            network = result['network']
            self.assertEqual(network['name'], net_name)
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.os_admin.networks_client.delete_network,
                            network['id'])
            network_kwargs.clear()
            network_kwargs['network_id'] = network['id']
            self.test_network_dict[net_name]['net-id'] = network['id']
            network_kwargs['name'] = net_name + '_subnet'
            network_kwargs['ip_version'] = net_param['ip_version']
            if 'cidr' in net_param:
                network_kwargs['cidr'] = net_param['cidr']
            if 'gateway_ip' in net_param:
                network_kwargs['gateway_ip'] = net_param['gateway_ip']
            if 'dhcp' in net_param:
                network_kwargs['enable_dhcp'] = net_param['dhcp']
            if 'pool_start' in net_param:
                network_kwargs['allocation_pools'] = \
                    [{'start': net_param['pool_start'],
                      'end':net_param['pool_end']}]
            if 'dns_nameservers' in net_param:
                network_kwargs['dns_nameservers'] = \
                    net_param['dns_nameservers']

            result = self.subnets_client.create_subnet(**network_kwargs)
            subnet = result['subnet']
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.subnets_client.delete_subnet, subnet['id'])
            self.test_network_dict[net_name]['subnet-id'] = subnet['id']
        if mgmt_network is not None:
            self.mgmt_network = mgmt_network

    def _add_subnet_to_router(self, mgmt_subnet_only=False):
        """Add subnets of existing networks to the router

        The subnets attached to the router will get the ability for the
        instances to get dhcp allocations on the instance interfaces

        :param mgmt_subnet_only: Attach only mgmt network subnet to router
        """
        mgmt_net_name = self.mgmt_network
        mgmt_net = self.test_network_dict[mgmt_net_name]

        subnets = []
        if not mgmt_subnet_only:
            nets = self.os_admin.networks_client.list_networks()['networks']
            for net in nets:
                if not net['router:external'] \
                        and 'HA network tenant' not in net['name']:
                    subnets.append(net['subnets'][0])
        else:
            subnets.append(mgmt_net['subnet-id'])
        seen_routers = self.os_admin.routers_client.list_routers()['routers']
        self.assertEqual(len(seen_routers), 1,
                         "Test require 1 admin router. please check")
        for subnet in subnets:
            self.os_admin.routers_client.add_router_interface(
                seen_routers[0]['id'], subnet_id=subnet)
            self.addCleanup(self.os_admin.routers_client.
                            remove_router_interface, seen_routers[0]['id'],
                            subnet_id=subnet)

    def _detect_existing_networks(self):
        """Use method only when test require no network

        cls.set_network_resources()
        it run over external_config networks,
        verified against existing networks..
        in case all networks exist return True and fill self.test_networks
        lists.
        In case there is external router.. public network decided
        based on router_external=False and router is not None
        """
        self.assertIsNotNone(CONF.nfv_plugin_options.external_config_file,
                             'This test require missing external_config, '
                             'for this test')

        self.assertTrue(self.test_network_dict,
                        'No networks for test, please check '
                        'external_config_file')

        public_network = self.networks_client.list_networks(
            **{'router:external': True})['networks']

        """
        Check public network exist in networks.
        remove it from network list
        if  = 0 we create port on first network if = 1  public network exist
        and set next network as vm management network
        name must not be public, router exist and network external false
        """
        if len(public_network) == 0:
            self.mgmt_network = self.test_network_dict.keys()[0]

        elif len(public_network) == 1:
            self.mgmt_network = None
            remove_network = None
            for net_name, net_param in iter(self.test_network_dict.items()):
                if net_name != 'public' and 'router' in net_param \
                        and 'external' in net_param:
                    if not net_param['external']:
                        self.mgmt_network = net_name
                    else:
                        remove_network = net_name
            self.test_network_dict.pop(remove_network)

    def _create_ports_on_networks(self, num_ports=1, **kwargs):
        """Create ports on a test networks for instances

        The method will create a network ports as per test_network dict
        from the external config file.
        The ports creation will loop over the number of specified servers.
        This will allow to call the method once for all instances.

        The ID of the security groups used for the ports creation, removed
        from the kwargs for the later instance creation.
        Note:
        On port creation, tag with port type is set, except to external,
        This will help create_server_with_fip will select required ports
        based on test request filters.

        :param num_ports: The number of loops for ports creation
        :param kwargs
               set_qos: true/false set qos policy during port creation

        :return ports_list: A list of ports lists
        """
        # The "ports_list" holds lists of ports dicts per each instance.
        # Create the number of the nested lists according to the number of the
        # instances.
        ports_list = []
        [ports_list.append([]) for i in range(num_ports)]

        for net_name, net_param in iter(self.test_network_dict.items()):
            if 'skip_srv_attach' in net_param:
                continue
            create_port_body = {'binding:vnic_type': '',
                                'namestart': 'port-smoke',
                                'binding:profile': {}}
            if 'port_type' in net_param:
                create_port_body['binding:vnic_type'] = \
                    net_param['port_type']
                if self.remote_ssh_sec_groups and net_name == \
                        self.mgmt_network:
                    create_port_body['security_groups'] = \
                        [s['id'] for s in self.remote_ssh_sec_groups]
                if 'trusted_vf' in net_param and \
                        net_param['trusted_vf'] and \
                        net_param['port_type'] == 'direct':
                    create_port_body['binding:profile']['trusted'] = True
                if 'switchdev' in net_param and \
                        net_param['switchdev'] and \
                        net_param['port_type'] == 'direct':
                    create_port_body['binding:profile']['capabilities'] = \
                        ['switchdev']

                if len(create_port_body['binding:profile']) == 0:
                    del create_port_body['binding:profile']

                for port_index in range(num_ports):
                    port = self._create_port(network_id=net_param['net-id'],
                                             **create_port_body)
                    # No option to create port with QoS, due to neutron API
                    # Using update port
                    if 'min_qos' in net_param and \
                        net_param['min_qos'] and \
                        net_param['port_type'] == 'direct' and \
                        'set_qos' in kwargs:
                        port_name = data_utils.rand_name('port-min-qos')
                        port_args = {'name': port_name}
                        if kwargs['set_qos']:
                            port_args['qos_policy_id'] = \
                                self.qos_policy_groups['id']
                        self.update_port(port['id'], **port_args)
                    net_var = {'uuid': net_param['net-id'], 'port': port['id']}
                    if 'tag' in net_param:
                        net_var['tag'] = net_param['tag']
                    # Mark port type, as tag
                    else:
                        net_var['tag'] = "{}:{}".format(
                            net_param['port_type'],
                            net_param['provider:physical_network'])
                    # In order to proper map the FIP to the instance,
                    # management network needs to be first in the list of nets.
                    if net_var['tag'] == 'external':
                        ports_list[port_index].insert(0, net_var)
                    else:
                        ports_list[port_index].append(net_var)

        return ports_list

    def _create_port(self, network_id, client=None, namestart='port-quotatest',
                     **kwargs):
        """Port creation for instance

        This Method Overrides Manager::CreatePort to support direct and
        direct ph ports

        :param network_id
        :param client
        :param namestart
        :param kwargs
        """
        kwargs['admin_state_up'] = 'True'
        if not client:
            client = self.ports_client
        name = data_utils.rand_name(namestart)
        result = client.create_port(name=name, network_id=network_id, **kwargs)
        self.assertIsNotNone(result, 'Unable to allocate port')
        port = result['port']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.ports_client.delete_port, port['id'])
        return port

    def update_port(self, port_id, **kwargs):
        """update port

        The method, used to update port_body of port.
        kwargs patam should includ additional parameters to be set
        as per the following:
        https://docs.openstack.org/api-ref/network/v2/ \
                ?expanded=update-port-detail#update-port
        :param port_id
        :param kwargs
               qos_policy_id: id of policy to be attached to the port
        """
        ports_client = self.os_admin.ports_client
        ports_client.update_port(port_id, **kwargs)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            ports_client.update_port, port_id, qos_policy_id=None)

    def create_server(self, name=None, image_id=None, flavor=None,
                      validatable=False, srv_state=None,
                      wait_on_delete=True, clients=None, **kwargs):
        """This Method Overrides Manager::Createserver to support Gates needs

        :param validatable:
        :param clients:
        :param image_id:
        :param wait_on_delete:
        :param srv_state:
        :param flavor:
        :param name:
        """
        if 'key_name' not in kwargs:
            key_pair = self.create_keypair()
            kwargs['key_name'] = key_pair['name']

        net_id = []
        networks = []
        (CONF.compute_feature_enabled.config_drive
         and kwargs.update({'config_drive': True}))
        if 'networks' in kwargs:
            net_id = kwargs['networks']
            kwargs.pop('networks', None)
        else:
            networks = self.networks_client.list_networks(
                **{'router:external': False})['networks']

        for network in networks:
            net_id.append({'uuid': network['id']})

        server = super(BareMetalManager,
                       self).create_server(name=name,
                                           networks=net_id,
                                           image_id=image_id,
                                           flavor=flavor,
                                           wait_until=srv_state,
                                           **kwargs)
        self.servers.append(server)
        return server

    def create_server_with_fip(self, num_servers=1, use_mgmt_only=False,
                               fip=True, networks=None, srv_state='ACTIVE',
                               raise_on_error=True, **kwargs):
        """Create defined number of the instances with floating ip.

        :param num_servers: The number of servers to boot up.
        :param use_mgmt_only: Boot instances with mgmt net only.
        :param fip: Creation of the floating ip for the server.
        :param networks: List of networks/ports for the servers.
        :param srv_state: The state of the server to expect.
        :param raise_on_error: Raise as error on failed build of the server.
        :param kwargs:
                srv_details: Provide per server override options.
                             Supported options:
                                - flavor (flavor id)
                                - image (image id)
                                - ports_filter (comma separated port types)
                             For example:
                             srv_details = {0: {'flavor': <flavor_id>,
                                                'ports_filter':
                                                    '<port-type-a>,<port-type-b>'}
                                            1: {'flavor': <flavor_id>,
                                                'image': <image_id>}}

        :return: List of created servers
        """
        servers = []
        port = {}

        if not any(isinstance(el, list) for el in networks):
            raise ValueError('Network expect to be as a list of lists')

        override_details = None
        if kwargs.get('srv_details'):
            override_details = kwargs.pop('srv_details')
        for num in range(num_servers):
            kwargs['networks'] = networks[num]

            if override_details:
                if 'flavor' in override_details[num]:
                    kwargs['flavor'] = override_details[num]['flavor']
                if 'image' in override_details[num]:
                    kwargs['image_id'] = override_details[num]['image']
                if 'srv_state' in override_details[num]:
                    kwargs['srv_state'] = override_details[num]['srv_state']
                if 'ports_filter' in override_details[num]:
                    for net in kwargs['networks']:
                        if net['tag'] \
                                not in \
                                override_details[num]['ports_filter']:
                            if net['tag'].split(":")[0] \
                                    not in \
                                    override_details[num]['ports_filter']:
                                kwargs['networks'].remove(net)

            """ If this parameters exist, parse only mgmt network.
            Example live migration can't run with SRIOV ports attached"""
            if use_mgmt_only:
                del (kwargs['networks'][1:])

            LOG.info('Create instance - {}'.format(num + 1))
            servers.append(self.create_server(**kwargs))
        for num, server in enumerate(servers):
            waiters.wait_for_server_status(self.os_admin.servers_client,
                                           server['id'], srv_state,
                                           raise_on_error=raise_on_error)
            LOG.info('The instance - {} is in an {} state'.format(num + 1,
                     srv_state))
            if srv_state == 'ACTIVE':
                port = self.os_admin.ports_client.list_ports(device_id=server[
                    'id'], network_id=networks[num][0]['uuid'])['ports'][0]
            if fip and srv_state == 'ACTIVE':
                server['fip'] = \
                    self.create_floating_ip(server,
                                            port['id'],
                                            self.public_network)[
                        'floating_ip_address']
                LOG.info('The {} fip is allocated to the instance'.format(
                    server['fip']))
            elif srv_state == 'ACTIVE':
                server['fip'] = port['fixed_ips'][0]['ip_address']
                server['network_id'] = networks[num][0]['uuid']
                LOG.info('The {} fixed ip set for the instance'.format(
                    server['fip']))
        return servers

    def create_server_with_resources(self, num_servers=1, num_ports=None,
                                     test=None, **kwargs):
        """The method creates resources and call for the servers method

        The following resources are created:
        - Aggregation
        - Flavor creation / verification
        - Key pair
        - Security groups
        - Test networks
        - Networks ports
        - Cloud init preparation
        - Servers creation
        - Floating ip attachment to the servers
        - QoS attachments to port

        :param num_servers: The number of servers to boot up.
        :param num_ports: The number of ports to the created.
                          Default to (num_servers)
        :param test: Currently executed test. Provide test specific parameters.
        :param kwargs:
                set_qos: true/false create port with qos_policy
                availability_zone: Create and set availability zone
                    zone_name: Name of availability zone (optional)
                    aggr_name: Name of aggregate (optional)
                    hyper_hosts: The list of the hypervisors to be attached
                    aggr_meta: Metadata for aggregate (optional)

                    Example: {'availability_zone': {'hyper_hosts': 'compute0'}}

        :return servers, key_pair
        """
        LOG.info('Creating resources...')

        if num_ports is None:
            num_ports = num_servers

        # Check for the test config file. If not provided, load default.
        if test not in self.test_setup_dict:
            self.create_default_test_config(test)

        # In case resources created externally, set them.
        if self.external_resources_data is not None:
            servers, key_pair = self._organize_external_created_resources(test)
            LOG.info('The resources created by the external tool. '
                     'Continue to the test.')
            return servers, key_pair

        # Create and configure availability zone
        if kwargs.get('availability_zone'):
            avail_zone = kwargs.pop('availability_zone')
            kwargs['availability_zone'] = \
                self.create_and_set_availability_zone(
                    **avail_zone)['availability_zone']

        # Create and configure aggregation zone if specified
        if self.test_setup_dict[test]['aggregate'] is not None:
            aggr_hosts = self.test_setup_dict[test]['aggregate']['hosts']
            aggr_meta = self.test_setup_dict[test]['aggregate']['metadata']
            self.create_and_set_aggregate(test, aggr_hosts, aggr_meta)

        # Flavor creation
        if not kwargs.get('flavor'):
            flavor_check = self.check_flavor_existence(test)
            if flavor_check is False:
                flavor_name = self.test_setup_dict[test]['flavor']
                LOG.info('Flavor {} not found. Creating.'.format(flavor_name))
                try:
                    self.flavor_ref = self.create_flavor(
                        **self.test_flavor_dict[flavor_name])
                except KeyError as exc:
                    err_msg = "Unable to locate {} flavor details for " \
                              "the creation".format(exc)
                    raise Exception(err_msg)

            kwargs['flavor'] = self.flavor_ref

        LOG.info('Creating networks, keypair, security groups, router and '
                 'prepare cloud init.')
        # Key pair creation
        key_pair = self.create_keypair()
        kwargs['key_name'] = key_pair['name']

        # Network, subnet, router and security group creation
        self._create_test_networks()
        self._set_remote_ssh_sec_groups()
        if self.remote_ssh_sec_groups_names:
            kwargs['security_groups'] = self.remote_ssh_sec_groups_names
        ports_list = \
            self._create_ports_on_networks(num_ports=num_ports,
                                           **kwargs)
        # After port creation remove kwargs['set_qos']
        if 'set_qos' in kwargs:
            kwargs.pop('set_qos')
        router_exist = True
        if 'router' in self.test_setup_dict[test]:
            router_exist = self.test_setup_dict[test]['router']
        if router_exist:
            mgmt_subnet_only = False
            if kwargs.get('mgmt_subnet_only'):
                mgmt_subnet_only = True
                kwargs.pop('mgmt_subnet_only')
            self._add_subnet_to_router(mgmt_subnet_only)
        # Prepare cloudinit
        packages = None
        if 'package-names' in self.test_setup_dict[test].keys():
            packages = self.test_setup_dict[test]['package-names']
        kwargs['user_data'] = self._prepare_cloudinit_file(packages)
        servers = []
        if num_servers:
            servers = self.create_server_with_fip(num_servers=num_servers,
                                                  networks=ports_list,
                                                  **kwargs)
        return servers, key_pair

    def _set_remote_ssh_sec_groups(self):
        """Security group creation

        This method create security group except network marked with security
        groups == false in test_networks
        """
        """
        Create security groups [icmp,ssh] for Deployed Guest Image
        """
        mgmt_net = self.mgmt_network
        if not ('sec_groups' in self.test_network_dict[mgmt_net]
                and not self.test_network_dict[mgmt_net]['sec_groups']):
            security_group = self._create_security_group()
            self.remote_ssh_sec_groups_names = \
                [{'name': security_group['name']}]
            self.remote_ssh_sec_groups = [{'name': security_group['name'],
                                           'id': security_group['id']}]

    def _create_security_group(self):
        """Security group creation

        to conform changes in nova clients on microversions>=2.36
        Create security groups and call method create rules
        [icmp,ssh]
        """

        sg_name = data_utils.rand_name(self.__class__.__name__)
        sg_desc = sg_name + " description"
        client = self.security_groups_client
        secgroup = client.create_security_group(
            name=sg_name, description=sg_desc)['security_group']
        self.assertEqual(secgroup['name'], sg_name)
        self.assertEqual(secgroup['description'], sg_desc)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.security_groups_client.delete_security_group,
            secgroup['id'])

        # Add rules to the security group
        self._create_loginable_secgroup_rule(secgroup['id'])

        return secgroup

    def _create_loginable_secgroup_rule(self, secgroup_id=None):
        """Add secgroups rules

        To conform changes in nova clients on microversions>=2.36
        This method add sg rules with neutron client
        This method find default security group or specific one
        and add icmp and ssh rules
        """
        rule_list = \
            jsonutils.loads(CONF.nfv_plugin_options.login_security_group_rules)
        client = self.security_groups_client
        client_rules = self.security_group_rules_client
        if not secgroup_id:
            sgs = client.list_security_group['security_groups']
            for sg in sgs:
                if sg['name'] == 'default':
                    secgroup_id = sg['id']
                    break

        for rule in rule_list:
            direction = rule.pop('direction')
            client_rules.create_security_group_rule(
                direction=direction,
                security_group_id=secgroup_id,
                **rule)

    def create_floating_ip(self, server, mgmt_port_id, public_network_id):
        """Create floating ip to server

        To conform changes in nova clients on microversions>=2.36
        This method create fip with neutron client
        """
        fip_client = self.floating_ips_client
        floating_ip_args = {
            'floating_network_id': public_network_id,
            'port_id': mgmt_port_id,
            'tenant_id': server['tenant_id']
        }
        floating_ip = \
            fip_client.create_floatingip(**floating_ip_args)['floatingip']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        fip_client.delete_floatingip,
                        floating_ip['id'])
        return floating_ip

    def check_instance_connectivity(self, ip_addr, user, key_pair):
        """Check connectivity state of the instance

        The function will test the following protocols: ICMP, SSH

        :param ip_addr: The address of the instance
        :param user: Connection user
        :param key_pair: SSH key for the instance connection
        """
        msg = 'Timed out waiting for {} to become reachable'.format(ip_addr)
        self.assertTrue(self.ping_ip_address(ip_addr), msg)
        self.assertTrue(self.get_remote_client(ip_addr, user, key_pair), msg)

    def check_guest_provider_networks(self, servers, key_pair):
        """Check guest provider networks

        This function tests ICMP traffic on all provider networks
        between multiple servers.

        :param servers: List of servers to verify
        :param key-pair: Key pair used to authenticate with server
        """
        # In the current itteration, if only a single server is spawned
        # no pings will be performed.
        # TODO(vkhitrin): In the future, consider pinging default gateway
        if len(servers) == 1:
            LOG.info('Only one server was spawned, no neigbors to ping')
            return True

        for server in servers:
            # Copy servers list to a helper variable
            neighbor_servers = servers[:]
            # Initialize a list of neighbors IPs
            neighbors_ips = []
            # Remove current server from potential server neigbors list
            neighbor_servers.remove(server)
            # Retrieve neighbors IPs from their provier networks
            for neighbor_server in neighbor_servers:
                # Iterate over provider networks for current server and
                # neighbor servers and append potential IP to ping only if
                # both the neighbor and current server are attached to
                # same network
                # Currently it is inefficient to loop this way, consider
                # improving itteration logic
                for neighbor_network in neighbor_server['provider_networks']:
                    for server_network in server['provider_networks']:
                        if neighbor_network['network_id'] == \
                                server_network['network_id']:
                            neighbors_ips.append(
                                neighbor_network['ip_address'])

            ssh_client = self.get_remote_client(server['fip'],
                                                self.instance_user,
                                                key_pair['private_key'])

            hostname = server['name']
            for neighbors_ip in neighbors_ips:
                LOG.info("Guest '{h}' will attempt to "
                         "ping {i}".format(h=hostname, i=neighbors_ip))
                try:
                    ssh_client.icmp_check(neighbors_ip)
                except lib_exc.SSHExecCommandFailed:
                    msg = ("Guest '{h}' failed to ping "
                           "IP '{i}'".format(h=hostname, i=neighbors_ip))
                    raise AssertionError(msg)

                LOG.info("Guest '{h}' successfully was able to ping "
                         "IP '{i}'".format(h=hostname, i=neighbors_ip))

    def get_ovs_port_names(self, servers):
        """This method get ovs port names for each server

        for each server, this method will add mgmt_port and other_port
        values
        :param servers: server list
        return list of ports of each hypervisor
        """
        # get the ports name used for sending/reciving multicast traffic
        # it will be a different port than the management one that will be
        # connected to a switch in which igmp snooping is configured
        port_list = {}
        management_ips = []
        floating_ips = (self.os_admin.floating_ips_client.list_floatingips()
                        ['floatingips'])
        for floating_ip in floating_ips:
            management_ips.append(floating_ip['fixed_ip_address'])
        for server in servers:
            if server['hypervisor_ip'] not in port_list.keys():
                port_list[server['hypervisor_ip']] = []
            ports = self.os_admin.ports_client.list_ports(
                device_id=server['id'])['ports']
            for port in ports:
                ovs_port_name = (port['binding:vif_details']
                                 ['vhostuser_socket'].split('/')[-1])
                if port['fixed_ips'][0]['ip_address'] not in management_ips:
                    server['other_port'] = ovs_port_name
                else:
                    server['mgmt_port'] = ovs_port_name
                port_list[server['hypervisor_ip']].append(ovs_port_name)
        return port_list

    def create_default_test_config(self, test_name=None):
        """This method populate default test configs

        self.test_setup_dict is filled with defaults, if no configuration
        exist for test in network_config

        :param test_name: test_name
        """
        self.assertIsNotNone(test_name,
                             "Please supply mandatory param: test_name")
        if test_name not in self.test_setup_dict:
            self.test_setup_dict[test_name] = \
                {'flavor-id': self.flavor_ref,
                 'router': True, 'aggregate': None}

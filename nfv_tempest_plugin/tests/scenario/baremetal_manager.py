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

import ipaddress
import os.path
import paramiko
import re

from neutron_tempest_plugin.common import ip
from neutron_tempest_plugin.common import ssh
from nfv_tempest_plugin.services.os_clients import OsClients
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
        self.sec_groups = []
        self.sec_groups_names = []
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
            # trying to guess key type, RSA and ECDSA supported
            key_type = None
            for val in ["rsa", "ecdsa"]:
                try:
                    if val == "ecdsa":
                        CONF.nfv_plugin_options.\
                            overcloud_node_pkey_file_key_object = \
                            paramiko.ECDSAKey.\
                            from_private_key(StringIO(key_str))
                    else:
                        CONF.nfv_plugin_options.\
                            overcloud_node_pkey_file_key_object = \
                            paramiko.RSAKey.\
                            from_private_key(StringIO(key_str))
                    key_type = val
                    break
                except paramiko.ssh_exception.SSHException:
                    pass
            self.assertIsNotNone(key_type,
                                 "Unknown key type, "
                                 "only supported RSA and ECDSA")
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
                ram=CONF.nfv_plugin_options.quota_ram,
                instances=CONF.nfv_plugin_options.quota_instances)

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
        if 'imageRef' in volume_args:
            image_virtual_size = self.image_client.show_image(
                volume_args['imageRef'])['virtual_size']
            if image_virtual_size:
                volume_args['size'] = int(image_virtual_size / 1073741824) + 1
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

    def _create_network_trunks(self, trunk_list):
        """Create network trunks

        It creates networks trunks if defined in test networks

        :param trunk_list: dict with the trunks to be created
        """
        for server_trunk in trunk_list:
            for trunk_name, trunk_value in server_trunk.items():
                trunk = self.os_admin_v2.network_client.create_trunk(
                    parent_port_id=trunk_value['parent_port'],
                    subports=trunk_value['subports'])['trunk']
                self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                                self.os_admin_v2.network_client.delete_trunk,
                                trunk['id'])

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
            if 'trunk_vlan' in net and 'trunk_vlan_parent' in net:
                self.test_network_dict[net['name']]['trunk_vlan'] = \
                    net['trunk_vlan']
                self.test_network_dict[net['name']]['trunk_vlan_parent'] = \
                    net['trunk_vlan_parent']
            if 'transparent_vlan' in net and 'transparent_vlan_parent' in net:
                self.test_network_dict[net['name']]['transparent_vlan'] = \
                    net['transparent_vlan']
                self.test_network_dict[net['name']][
                    'transparent_vlan_parent'] = net[
                    'transparent_vlan_parent']
            if 'mtu' in net and net['mtu']:
                self.test_network_dict[net['name']]['mtu'] = \
                    int(net['mtu'])
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

            if 'mtu' in net_param:
                network_kwargs['mtu'] = net_param['mtu']

            if 'transparent_vlan' in net_param and \
                'transparent_vlan_parent' in net_param and \
                net_param['transparent_vlan_parent']:
                network_kwargs['vlan_transparent'] = True

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
                      'end': net_param['pool_end']}]
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
        self.assertGreater(len(seen_routers), 0,
                           "Test require at least admin router. please check")
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

        It will return vlan trunk and transparent vlan ports. These ports
        are usefull to create vlan interfaces inside vms

        :param num_ports: The number of loops for ports creation
        :param kwargs
               set_qos: true/false set qos policy during port creation

        :return ports_list: A list of ports lists used when creating vms.
        Contains regular ports and parent ports when using vlan trunk or
        vlan transparent. It does not contain child ports for vlan trunk
        or child ports por vlan transparent (which are not even created)
        :return trunk_ports: vlan trunk ports. It contains child ports for
        vlan trunk
        :return transparent_ports: transparent ports. It contains child ports
        for vlan transparent. These ports are not even created by neutron but
        this structure is useful to create vlans inside vms.
        """
        # The "ports_list" holds lists of ports dicts per each instance.
        # Create the number of the nested lists according to the number of the
        # instances.
        ports_list = []
        trunk_ports = []
        transparent_ports = []
        [ports_list.append([]) for i in range(num_ports)]
        [trunk_ports.append({}) for i in range(num_ports)]
        [transparent_ports.append({}) for i in range(num_ports)]

        # First managing child ports for transparent vlans. These ports are
        # not created by neutron.
        # list of ips available to assign in transparent vlans
        ips_available = {}
        for net_name, net_param in iter(self.test_network_dict.items()):
            if 'skip_srv_attach' in net_param:
                continue

            # When using network transparency, only for the parent
            # network it will be created a port
            transparent_enabled = False
            if 'transparent_vlan' in net_param and \
                    'transparent_vlan_parent' in net_param:
                transparent_enabled = True

                # create transparent structure if not created yet
                for port_index in range(num_ports):
                    if net_param['transparent_vlan'] not in \
                            transparent_ports[port_index].keys():
                        transparent_ports[port_index][net_param[
                            'transparent_vlan']] = {'subports': []}

            if transparent_enabled and \
                    not net_param['transparent_vlan_parent']:
                # get list of ips available to assign to transparent
                # interfaces
                if net_name not in ips_available:
                    start = ipaddress.ip_address(net_param['pool_start'])
                    end = ipaddress.ip_address(net_param['pool_end'])
                    ips_available[net_name] = \
                        [ip for ip in list(ipaddress.IPv4Network(
                            address=net_param['cidr'],
                            strict=False).hosts()) if ip > start and ip < end]

                # create transparent subports structure
                for port_index in range(num_ports):
                    # add subports
                    transparent = transparent_ports[port_index][
                        net_param['transparent_vlan']]
                    ip = "{}/{}".format(ips_available[net_name].pop(0),
                                        net_param['cidr'].split("/")[1])
                    subport = \
                        {'ip_address': ip,
                         'segmentation_id':
                             net_param['provider:segmentation_id'],
                         'segmentation_type': 'vlan'}
                    transparent['subports'].append(subport)

                # not created neutron port for child transparent ports
                continue

            # check if trunk vlan defined
            trunk_enabled = False
            trunk_parent = False
            if 'trunk_vlan' in net_param and 'trunk_vlan_parent' in net_param:
                trunk_enabled = True
                trunk_parent = net_param['trunk_vlan_parent']

            # create ports
            create_port_body = {'binding:vnic_type': '',
                                'namestart': 'port-smoke',
                                'binding:profile': {}}
            if 'port_type' in net_param:
                create_port_body['binding:vnic_type'] = \
                    net_param['port_type']
                if self.sec_groups and 'sec_groups' in net_param and \
                        net_param['sec_groups']:
                    create_port_body['security_groups'] = \
                        [s['id'] for s in self.sec_groups]
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

                    # ports_list will be the list of ports used when spawning
                    # vms when using trunk, child  ports must not be in the
                    # list when using transparency, no child port is created,
                    # so it will not be in the list
                    if not trunk_enabled or (trunk_enabled and trunk_parent):
                        # In order to proper map the FIP to the instance,
                        # management network needs to be first in the list
                        # of nets.
                        if net_var['tag'] == 'external':
                            ports_list[port_index].insert(0, net_var)
                        else:
                            ports_list[port_index].append(net_var)

                    # Add trunk parent port/subport if trunk vlan enabled
                    if trunk_enabled:
                        # create trunk structure if not created yet
                        if net_param['trunk_vlan'] not in \
                                trunk_ports[port_index].keys():
                            trunk_ports[port_index][net_param[
                                'trunk_vlan']] = {'subports': []}

                        # add parent port and subports
                        trunk = trunk_ports[port_index][net_param[
                            'trunk_vlan']]
                        if trunk_parent:
                            trunk['parent_port'] = port['id']
                        else:
                            subport = \
                                {'port_id': port['id'],
                                 'segmentation_id':
                                     net_param['provider:segmentation_id'],
                                 'segmentation_type': 'vlan'}
                            trunk['subports'].append(subport)

                    # Add transparent parent port if enabled
                    if transparent_enabled:
                        transparent_ports[port_index][net_param[
                            'transparent_vlan']]['parent_port'] = port['id']

        return ports_list, trunk_ports, transparent_ports

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
                    for net in kwargs['networks'][:]:
                        if net['tag'] \
                                not in \
                                override_details[num]['ports_filter'].\
                                split(","):
                            if net['tag'].split(":")[0] \
                                    not in \
                                    override_details[num]['ports_filter'].\
                                    split(","):
                                kwargs['networks'].remove(net)
                if 'availability_zone' in override_details[num]:
                    kwargs['availability_zone'] = \
                        override_details[num]['availability_zone']

            """ If this parameters exist, parse only mgmt network.
            Example live migration can't run with SRIOV ports attached"""
            if use_mgmt_only:
                del (kwargs['networks'][1:])

            LOG.info('Create instance - {}'.format(num + 1))
            server = self.create_server(**kwargs)
            servers.append(server)
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
            port_list_trunk = [{}]
            index = 1
            for port in \
                self.os_admin.ports_client.list_ports()['ports']:
                if 'trunk_details' in port:
                    port_list_trunk[0][f"trunk_{index}"] = \
                        {"subports": port['trunk_details']['sub_ports'],
                            "parent_port": port["id"]}
                    index += 1
            servers, key_pair = self._organize_external_created_resources(test)
            self._configure_external_vlan_trunk_vms(servers, key_pair,
                                                    port_list_trunk)
            LOG.info('The resources created by the external tool. '
                     'Continue to the test.')
            return servers, key_pair

        # Create and configure availability zone
        if kwargs.get('availability_zone'):
            avail_zone = kwargs.pop('availability_zone')
            kwargs['availability_zone'] = \
                self.create_and_set_availability_zone(
                    **avail_zone)['availability_zone']

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
        # Apply check if any network has sec-group true
        sec_groups_def = \
            [key for key, value
             in self.test_network_dict.items() if value['sec_groups']]
        if len(sec_groups_def) > 0:
            kwargs['security_groups'] = self._set_sec_groups(**kwargs)
            kwargs.pop('sg_rules', None)

        ports_list, port_list_trunk, port_list_transparent = \
            self._create_ports_on_networks(num_ports=num_ports,
                                           **kwargs)

        self._create_network_trunks(port_list_trunk)

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
            self._configure_vlan_trunk_vms(servers, key_pair,
                                           port_list_trunk)
            self._configure_vlan_transparent_vms(servers, key_pair,
                                                 port_list_transparent)

        return servers, key_pair

    def _configure_external_vlan_trunk_vms(self, servers,
                                           key_pair, port_list_trunk):
        """Configure vlan trunks in vms

        It will use ip commands through ssh to configure vlans inside vms

        :param servers: list with servers
        :param key_pair: key_pair to connect vms
        :port_list_trunk: list of trunk ports
        """
        # Exit if no truk ports
        if not port_list_trunk:
            return

        os_clients = OsClients()

        subnets = self.os_admin.subnets_client.list_subnets()['subnets']
        ports = self.os_admin.ports_client.list_ports()['ports']

        for os_server in os_clients.novaclient_overcloud.servers.list():
            for s in servers:
                if s['name'] == os_server.name:
                    nfv_server = s
                    break
            else:
                continue

            nfv_server['trunk_networks'] = []
            ssh_client = ssh.Client(host=nfv_server['fip'],
                                    username=self.instance_user,
                                    pkey=key_pair['private_key'])
            ip_command = ip.IPCommand(ssh_client=ssh_client)
            for trunk_values in port_list_trunk[0].values():
                # This is used to make sure all ports are related to the
                # server regardless of the order they are in the trunk dict
                for interface in os_clients.novaclient_overcloud.\
                    servers.interface_list(os_server):
                    if trunk_values['parent_port'] == interface.port_id:
                        parent_port = interface.__dict__
                        for subp in trunk_values['subports']:
                            child_port = [port for port in ports
                                          if port['id'] == subp['port_id']][0]
                            subnet_id = child_port['fixed_ips'][0]['subnet_id']
                            vlan_subnet = [subnet for subnet in subnets
                                           if subnet['id'] == subnet_id][0]
                            device = ip_command.configure_vlan_subport(
                                port=parent_port,
                                subport=child_port,
                                vlan_tag=subp['segmentation_id'],
                                subnets=[vlan_subnet])
                            ip_command.execute('link', 'set', 'address',
                                               child_port['mac_address'],
                                               'dev',
                                               device)

                        trunk_dict = {
                            'network_id':
                                child_port['network_id'],
                            'mac_address':
                                child_port['mac_address'],
                            'parent_mac_address':
                                parent_port['mac_addr'],
                            'ip_address':
                                child_port['fixed_ips'][0]['ip_address'],
                            'parent_ip_address':
                                parent_port['fixed_ips'][0]['ip_address'],
                            'provider:network_type':
                                'trunk_vlan'
                        }
                        nfv_server['trunk_networks'].append(trunk_dict)

    def _configure_vlan_trunk_vms(self, servers, key_pair, port_list_trunk):
        """Configure vlan trunks in vms

        It will use ip commands through ssh to configure vlans inside vms

        :param servers: list with servers
        :param key_pair: key_pair to connect vms
        :port_list_trunk: list of trunk ports
        """
        subnets = None
        ports = None
        for server_index, server in enumerate(servers):
            if len(port_list_trunk[server_index]) > 0:
                server['trunk_networks'] = []
                if subnets is None:
                    subnets = \
                        self.os_admin.subnets_client.list_subnets()['subnets']
                if ports is None:
                    ports = self.os_admin.ports_client.list_ports()['ports']
                ssh_client = ssh.Client(host=server['fip'],
                                        username=self.instance_user,
                                        pkey=key_pair['private_key'])
                ip_command = ip.IPCommand(ssh_client=ssh_client)
                for trunk_name, trunk_value in \
                        port_list_trunk[server_index].items():
                    parent_port = \
                        [port for port in ports
                         if port['id'] == trunk_value['parent_port']][0]
                    for subport in trunk_value['subports']:
                        child_port = [port for port in ports
                                      if port['id'] == subport['port_id']][0]
                        subnet_id = child_port['fixed_ips'][0]['subnet_id']
                        vlan_subnet = [subnet for subnet in subnets
                                       if subnet['id'] == subnet_id][0]
                        device = ip_command.configure_vlan_subport(
                            port=parent_port,
                            subport=child_port,
                            vlan_tag=subport['segmentation_id'],
                            subnets=[vlan_subnet])
                        ip_command.execute('link', 'set', 'address',
                                           child_port['mac_address'], 'dev',
                                           device)
                        trunk_dict = {
                            'network_id':
                                child_port['network_id'],
                            'mac_address':
                                child_port['mac_address'],
                            'parent_mac_address':
                                parent_port['mac_address'],
                            'ip_address':
                                child_port['fixed_ips'][0]['ip_address'],
                            'parent_ip_address':
                                parent_port['fixed_ips'][0]['ip_address'],
                            'provider:network_type':
                                'trunk_vlan'
                        }
                        server['trunk_networks'].append(trunk_dict)

    def _configure_vlan_transparent_vms(self, servers, key_pair,
                                        port_list_transparent):
        """Configure vlan transparent in vms

        It will use ip commands through ssh to configure vlans inside vms

        :param servers: list with servers
        :param key_pair: key_pair to connect vms
        :port_list_transparent: list of transparent ports
        """
        ports = None
        for server_index, server in enumerate(servers):
            if len(port_list_transparent[server_index]) > 0:
                server['transparent_networks'] = []
                if ports is None:
                    ports = self.os_admin.ports_client.list_ports()['ports']
                ssh_client = ssh.Client(host=server['fip'],
                                        username=self.instance_user,
                                        pkey=key_pair['private_key'])
                ip_command = ip.IPCommand(ssh_client=ssh_client)
                for transparent_name, transparent_value in \
                        port_list_transparent[server_index].items():
                    parent_port = \
                        [port for port in ports
                         if port['id'] == transparent_value['parent_port']][0]
                    for subport in transparent_value['subports']:
                        device = ip_command.configure_vlan_transparent(
                            port=parent_port,
                            vlan_tag=subport['segmentation_id'],
                            ip_addresses=[subport['ip_address']])
                        ip_link_output = ip_command.execute('link',
                                                            'show',
                                                            device).split(" ")
                        mac_address = ip_link_output[ip_link_output.index(
                            'link/ether') + 1]
                        # Reduce mtu for inserting vlan tag (4 bytes)
                        mtu = int(ip_link_output[ip_link_output.index(
                            'mtu') + 1]) - 4
                        ip_link_output = ip_command.execute('link',
                                                            'set',
                                                            device,
                                                            'mtu',
                                                            mtu)
                        LOG.info('Reduce MTU for transparent vlan interfaces '
                                 'in vm 4 bytes: {}'.format(mtu))
                        transp_dict = {
                            # set segmentation_id as network_id
                            'network_id':
                                subport['segmentation_id'],
                            'provider:network_type':
                                'transparent_vlan',
                            'mac_address':
                                mac_address,
                            'parent_mac_address':
                                parent_port['mac_address'],
                            'ip_address':
                                subport['ip_address'].split('/')[0],
                            'parent_ip_address':
                                parent_port['fixed_ips'][0]['ip_address']
                        }
                        server['transparent_networks'].append(transp_dict)
                        # set allowed-pairs when using security groups
                        if self.sec_groups:
                            all_addr_pairs = [
                                {'ip_address': subport['ip_address'],
                                 'mac_address': transp_dict['mac_address']}]
                            self.update_port(
                                parent_port['id'],
                                allowed_address_pairs=all_addr_pairs)

    def _set_sec_groups(self, **kwargs):
        """Creates a security group containing rules

        :param rules: a list containing dictionarys of rules
        :return: a list with security group names
        """
        if 'sg_rules' in kwargs:
            kwargs['sg_rules'].append(jsonutils.loads(
                CONF.nfv_plugin_options.login_security_group_rules))
        else:
            kwargs['sg_rules'] = \
                [jsonutils.loads(CONF.nfv_plugin_options.
                                 login_security_group_rules)]

        for group_rules in kwargs['sg_rules']:
            sg = self._create_security_group()
            self.add_security_group_rules(group_rules, sg['id'])
            self.sec_groups.append({'name': sg['name'], 'id': sg['id']})
            self.sec_groups_names.append({'name': sg['name']})

        return self.sec_groups_names

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

        return secgroup

    def add_security_group_rules(self, rule_list, secgroup_id=None):
        """Add secgroups rules

        To conform changes in nova clients on microversions>=2.36
        This method add sg rules with neutron client
        This method find default security group or specific one
        and specified rules
        # Add rules to the security group
        """
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
            secgrouprule = client_rules.create_security_group_rule(
                direction=direction,
                security_group_id=secgroup_id,
                **rule)
            self.addCleanup(
                test_utils.call_and_ignore_notfound_exc,
                client_rules.delete_security_group_rule,
                secgrouprule['security_group_rule']['id'])

    def get_security_group_from_partial_string(self, group_name_string):
        """Get security group based on partial string

        :param: group_name_string: group name string
        :return filtered_sec_group: filtered security group
        """
        client = self.security_groups_client
        all_sec_groups = client.list_security_groups()
        filtered_sec_group = \
            list(filter(lambda g: group_name_string in g['name'],
                        all_sec_groups['security_groups']))
        self.assertNotEmpty(filtered_sec_group,
                            "Failed to locate security group containing "
                            "string: {}".format(group_name_string))
        self.assertEqual(1,
                         len(filtered_sec_group),
                         "Returned more than one group: "
                         "{}".format(filtered_sec_group))
        return filtered_sec_group[0]

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

    def get_internal_port_from_fip(self, fip):
        """returns internal port data mapped to fip

        The function returns mapped port date to fip

        :param fip: fip address to resolve
        :return int_port: return port date
        """
        self.assertNotEmpty(fip, "fip is empty")
        fixed_ip = \
            self.os_admin.floating_ips_client.list_floatingips(
                floating_ip_address=fip)['floatingips'][0]['fixed_ip_address']
        return self.get_port_from_ip(fixed_ip)

    def get_port_from_ip(self, ip):
        """returns port from ip

        :param ip: ip address to resolve
        :return int_port: return port date
        """
        self.assertNotEmpty(ip, "ip is empty")
        int_port = self.os_admin.ports_client.list_ports(
            fixed_ips="ip_address=" + ip)['ports'][0]
        return int_port

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
                ping_cmd = \
                    "ping -c{0} -w{1} -s56 {2} || true".format("1",
                                                               "10",
                                                               neighbors_ip)
                ping_output = ssh_client.exec_command(ping_cmd)
                msg = ("Guest '{h}' failed to ping IP "
                       "'{i}'".format(h=hostname, i=neighbors_ip))
                # https://bugzilla.redhat.com/show_bug.cgi?id=1942053
                # Some packets could be lost in geneve networks while resolving
                # arp. This issue causes some testcases fail.
                # BZ has low priority. While it is fixed, we check that at
                # least some icmp packets arrive to destination. Some other
                # packets may have been lost
                self.assertNotIn("100% packet loss", ping_output, msg)
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
